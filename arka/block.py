
from __future__ import annotations
from typing import Literal
from struct import pack, pack_into, unpack_from, error as StructError
from arka.crypto import keccak_800, keccak_1600
from asyncio import gather


class AbstractElement(object):

    def __eq__(self, value: AbstractElement) -> bool:
        raise NotImplementedError()
    
    @property
    def size(self) -> int:
        raise NotImplementedError()
    
    def encode(self) -> bytes:
        raise NotImplementedError()
    
    @classmethod
    def decode(self, view: bytes | bytearray | memoryview) -> AbstractElement:
        raise NotImplementedError()


class Bytes(AbstractElement):

    def __init__(self,
        value: bytes | bytearray | memoryview,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise ValueError('invalid value type.')
            if len(value) != self.SIZE:
                raise ValueError('Invalid value size.')
        self.value = value if isinstance(value, bytes) else bytes(value)

    def __eq__(self, value) -> bool:
        if not isinstance(value, type(self)):
            return NotImplemented
        return self.value == value.value

    @property
    def size(self) -> int:
        return self.SIZE

    def encode(self) -> bytes:
        return self.value
       
    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Bytes:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid size when decoding.')
        value = view if len(view) == cls.SIZE else view[:cls.SIZE]
        value = value if isinstance(value, bytes) else bytes(value)
        return cls(value, _validate=False)


class SignerHash(Bytes):

    SIZE = 32


class SignerKey(Bytes):

    SIZE = 32

    async def hash(self) -> SignerHash:
        return SignerHash(await keccak_800(self.value))


class SignerList(AbstractElement):

    SIGNER_HASH = 0
    SIGNER_KEY = 1
    SIGNER_LIST = 2

    def __init__(self,
        signers: list[SignerList | SignerHash | SignerKey],
        threshold: int,
        _validate: bool = True
    ):
        if _validate:
            if len(signers) == 0 or len(signers) >= 0x8000:
                raise ValueError('Invalid signer list.')
            if threshold <= 0 or threshold > len(signers):
                raise ValueError('Invalid threshold.')
        self.signers = signers
        self.threshold = threshold

    def __eq__(self, value: SignerList) -> bool:
        if not isinstance(value, SignerList):
            return NotImplemented
        return (
            self.signers == value.signers
            and self.threshold == value.threshold
        )

    @property
    def size(self) -> int:
        n = 1 if len(self.signers) < 0x80 else 2
        n += 1 if self.threshold < 0x80 else 2
        n += (len(self.signers) + 3) // 4
        n += sum(s.size for s in self.signers)
        return n

    @property
    def keys(self) -> list[SignerKey]:
        key_count = 0
        values: list[bytes] = []
        unique: set[bytes] = set()
        output: list[SignerKey] = []
        for s in self.signers:
            match s:
                case SignerList():
                    values.extend([k.value for k in s.keys])
                    key_count += 1
                case SignerKey():
                    values.append(s.value)
                    key_count += 1
        if key_count < self.threshold:
            raise ValueError("SignerList keys does not meet threshold.")
        for k in values:
            if k not in unique:
                unique.add(k)
                output.append(SignerKey(k))
        return output

    @staticmethod
    async def _identity(x):
        return x

    async def hash(self) -> SignerHash:
        prefix = pack('<HH', len(self.signers), self.threshold)
        hashes: list[bytes] = []
        if not all(
            isinstance(x, (SignerHash, SignerKey, SignerList))
            for x in self.signers
        ):
            raise ValueError('Invalid signer type.')
        hashes: list[SignerHash] = await gather(*[
            s.hash()
            if isinstance(s, (SignerKey, SignerList))
            else self._identity(s)
            for s in self.signers
        ])
        preimage = b''.join([prefix] + [h.value for h in hashes])
        return SignerHash(await keccak_1600(preimage))

    def encode(self) -> bytes:
        n = len(self.signers)
        n = (n << 1) | (0 if n < 0x80 else 1)
        n = n.to_bytes((2 if n & 1 else 1), 'little')
        x = self.threshold
        x = (x << 1) | (0 if x < 0x80 else 1)
        x = x.to_bytes((2 if x & 1 else 1), 'little')
        types = bytearray((len(self.signers) + 3) // 4)
        encodings: list[bytes] = []
        for i, s in enumerate(self.signers):
            match s:
                case SignerHash():
                    t = self.SIGNER_HASH
                case SignerKey():
                    t = self.SIGNER_KEY
                case SignerList():
                    t = self.SIGNER_LIST
                case _:
                    raise ValueError('Invalid signer type.')
            types[i >> 2] |= t << ((i & 3) << 1)
            encodings.append(s.encode())
        return b''.join([n, x, types] + encodings)

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> SignerList:
        try:
            signers: list[SignerHash | SignerKey | SignerList] = []
            n = view[0]
            offset = 1
            if n & 1:
                n += view[offset] << 8
                offset += 1
            n >>= 1
            if not n:
                raise ValueError('Invalid signer list size.')
            x = view[offset]
            offset += 1
            if x & 1:
                x += view[offset] << 8
                offset += 1
            x >>= 1
            if not x or x > n:
                raise ValueError('Invalid threshold.')
            types = view[offset:offset + ((n + 3) >> 2)]
            offset += len(types)
            for i in range(n):
                match (types[i >> 2] >> ((i & 3) << 1)) & 3:
                    case cls.SIGNER_HASH:
                        signers.append(SignerHash.decode(view[offset:]))
                    case cls.SIGNER_KEY:
                        signers.append(SignerKey.decode(view[offset:]))
                    case cls.SIGNER_LIST:
                        signers.append(SignerList.decode(view[offset:]))
                    case _:
                        raise ValueError('Invalid signer type.')
                offset += signers[-1].size
        except IndexError as e:
            raise ValueError('Invalid size when decoding.')
        return SignerList(signers, x, _validate=False)


class UTXORefByIndex(AbstractElement):

    SIZE = 14

    def __init__(self, block: int, tx: int, output: int, _validate=True):
        if _validate:
            if block < 0 or block >= 0x1_0000_0000_0000_0000:
                raise ValueError('Invalid block number.')
            if tx < 0 or tx >= 0x1_0000_0000:
                raise ValueError('Invalid tx number.')
            if output < 0 or output >= 0x1_0000:
                raise ValueError('Invalid output number.')
        self.block, self.tx, self.output = block, tx, output

    def __eq__(self, value: UTXORefByIndex) -> bool:
        if not isinstance(value, UTXORefByIndex):
            return NotImplemented
        return (
            self.block == value.block
            and self.tx == value.tx
            and self.output == value.output
        )

    @property
    def size(self) -> int:
        return self.SIZE

    def encode(self) -> bytes:
        return pack('<QIH', self.block, self.tx, self.output)

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXORefByIndex:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid view size.')
        return cls(*unpack_from('<QIH', view, 0), _validate=False)


class TransactionHash(Bytes):

    SIZE = 32


class UTXORefByHash(AbstractElement):

    def __init__(self, tx_hash: TransactionHash, output: int, _validate: bool = True):
        if _validate:
            if not isinstance(tx_hash, TransactionHash):
                raise ValueError('Invalid tx_hash.')
            if output < 0 or output >= 0x1_0000:
                raise ValueError('Invalid output number.')
        self.tx_hash = tx_hash
        self.output = output

    def __eq__(self, value: UTXORefByHash) -> bool:
        if not isinstance(value, UTXORefByHash):
            return NotImplemented
        return (
            self.tx_hash == value.tx_hash
            and self.output == value.output
        )

    @property
    def size(self) -> int:
        return self.tx_hash.size + 2
    
    def encode(self) -> bytes:
        return self.tx_hash.encode() + pack('<H', self.output)

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXORefByHash:
        if len(view) < TransactionHash.SIZE + 2:
            raise ValueError('Invalid size when decoding.')
        tx_hash = TransactionHash.decode(view)
        output = unpack_from('<H', view, tx_hash.size)[0]
        return cls(tx_hash, output, _validate=False)


class TransactionElement(AbstractElement):

    def __init__(self,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if memo is not None:
                if (
                    not isinstance(memo, (bytes, bytearray, memoryview))
                    or len(memo) == 0
                    or len(memo) >= 0x1_0000
                ):
                    raise ValueError('Invalid memo.')
        self.memo = memo


    @staticmethod
    def _encode_mlen(
        memo: bytes | bytearray | memoryview | None
    ) -> bytes:
        if memo is None:
            return b''
        mlen = len(memo)
        if mlen == 0:
            raise ValueError('Invalid memo size')
        elif mlen < 0x100:
            return pack('<B', mlen)
        elif mlen < 0x1_0000:
            return pack('<H', mlen)
        else:
            raise ValueError('Invalid memo size')

    @classmethod
    def _decode_memo(
        cls, prefix: Literal[0, 1, 2], view: bytes | bytearray | memoryview
    ) -> bytes | None:
        try:
            match prefix:
                case 0:
                    return None
                case 1:
                    mlen = view[0]
                    if not mlen or len(view) < 1 + mlen:
                        raise IndexError()
                    return bytes(view[1:1+mlen])
                case 2:
                    mlen = unpack_from('<H', view, 0)[0]
                    if mlen < 0x100 or len(view) < 2 + mlen:
                        raise IndexError()
                    return bytes(view[2:2+mlen])
                case _:
                    raise IndexError()
        except (IndexError, StructError) as e:
            raise ValueError('Invalid memo size')


class TransactionInput(TransactionElement):

    SIGNER_KEY = 0
    SIGNER_LIST = 1
    SIGNER_NONE = 2

    def __init__(self,
        signer: SignerKey | SignerList | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if (
                signer is not None
                and not isinstance(signer, (SignerKey, SignerList))
            ):
                raise ValueError('Invalid signer.')
        super().__init__(memo, _validate=_validate)
        self.signer = signer

    @property
    def signers(self) -> list[SignerKey]:
        match self.signer:
            case SignerKey():
                return [self.signer]
            case SignerList():
                return self.signer.keys
            case _:
                raise ValueError('Invalid signer.')

    @classmethod
    def _encode_signer(
        cls, signer: SignerKey | SignerList
    ) -> tuple[Literal[0, 1], bytes]:
        match signer:
            case SignerKey():
                prefix = cls.SIGNER_KEY
            case SignerList():
                prefix = cls.SIGNER_LIST
            case _:
                raise ValueError('Invalid signer.')
        return prefix, signer.encode()

    @classmethod
    def _decode_signer(
        cls, prefix: Literal[0, 1], view: bytes | bytearray | memoryview
    ) -> SignerKey | SignerList:
        match prefix:
            case cls.SIGNER_KEY:
                return SignerKey.decode(view)
            case cls.SIGNER_LIST:
                return SignerList.decode(view)
            case _:
                raise ValueError('Invalid signer.')

    @classmethod
    def _encode_optional_signer(
        cls, signer: SignerKey | SignerList | None
    ) -> tuple[Literal[0, 1, 2], bytes]:
        match signer:
            case SignerKey():
                prefix = cls.SIGNER_KEY
            case SignerList():
                prefix = cls.SIGNER_LIST
            case None:
                prefix = cls.SIGNER_NONE
            case _:
                raise ValueError('Invalid signer.')
        return prefix, (signer.encode() if signer else b'')

    @classmethod
    def _decode_optional_signer(
        cls, prefix: Literal[0, 1, 2], view: bytes | bytearray | memoryview
    ) -> SignerKey | SignerList | None:
        match prefix:
            case cls.SIGNER_KEY:
                return SignerKey.decode(view)
            case cls.SIGNER_LIST:
                return SignerList.decode(view)
            case cls.SIGNER_NONE:
                return
            case _:
                raise ValueError('Invalid signer.')


class UTXOSpend(TransactionInput):

    UTXO_REF_BY_INDEX = 0
    UTXO_REF_BY_HASH = 1

    def __init__(self,
        utxo: UTXORefByIndex | UTXORefByHash,
        signer: SignerKey | SignerList | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(utxo, (UTXORefByIndex, UTXORefByHash)):
                raise ValueError('Invalid UTXO reference.')
        super().__init__(signer, memo, _validate=_validate)
        self.utxo = utxo

    def __eq__(self, value: UTXOSpend) -> bool:
        if not isinstance(value, UTXOSpend):
            return NotImplemented
        return (
            self.utxo == value.utxo
            and self.signer == value.signer
            and self.memo == value.memo
        )

    @property
    def size(self) -> int:
        n = 1 + self.utxo.size + (self.signer.size if self.signer else 0)
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        match self.utxo:
            case UTXORefByIndex():
                prefix = self.UTXO_REF_BY_INDEX
            case UTXORefByHash():
                prefix = self.UTXO_REF_BY_HASH
            case _:
                raise ValueError('Invalid UTXO reference.')
        _prefix, signer = self._encode_optional_signer(self.signer)
        prefix |= _prefix << 1
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 3
        return b''.join([
            pack('<B', prefix), self.utxo.encode(),
            signer, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXOSpend:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        match prefix & 1:
            case cls.UTXO_REF_BY_INDEX:
                utxo = UTXORefByIndex.decode(view[1:])
            case cls.UTXO_REF_BY_HASH:
                utxo = UTXORefByHash.decode(view[1:])
            case _:
                raise ValueError('Invalid UTXO reference.')
        prefix >>= 1
        offset = 1 + utxo.size
        signer = cls._decode_optional_signer(prefix & 3, view[offset:])
        prefix >>= 2
        offset += signer.size if signer else 0
        memo = cls._decode_memo(prefix & 3, view[offset:])
        return cls(utxo, signer, memo, _validate=False)


class BlockSpend(TransactionInput):

    def __init__(self,
        block: int,
        signer: SignerKey | SignerList | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if (
                not isinstance(block, int)
                or block < 0
                or block >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid block number.')
        super().__init__(signer, memo, _validate=_validate)
        self.block = block

    def __eq__(self, value: BlockSpend) -> bool:
        if not isinstance(value, type(self)):
            return NotImplemented
        return (
            self.block == value.block
            and self.signer == value.signer
            and self.memo == value.memo
        )

    @property
    def size(self) -> int:
        n = 9
        n += (self.signer.size if self.signer else 0)
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        prefix, signer = self._encode_optional_signer(self.signer)
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 2
        return b''.join([
            pack('<BQ', prefix, self.block),
            signer, mlen, self.memo
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> BlockSpend:
        if len(view) < 9:
            raise ValueError('Invalid size when decoding.')
        prefix, block = unpack_from('<BQ', view, 0)
        signer = cls._decode_optional_signer(prefix & 3, view[9:])
        prefix >>= 2
        offset = 9 + (signer.size if signer else 0)
        memo = cls._decode_memo(prefix & 3, view[offset:])
        return cls(block, signer, memo, _validate=False)


class PublisherSpend(BlockSpend):

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> PublisherSpend:
        x = BlockSpend.decode(view)
        return cls(x.block, x.signer, x.memo, _validate=False)


class ExecutiveSpend(BlockSpend):

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveSpend:
        x = BlockSpend.decode(view)
        return cls(x.block, x.signer, x.memo, _validate=False)


class ExecutiveSpawn(TransactionInput):

    def __init__(self,
        signer: SignerKey | SignerList,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate and signer is None:
            raise ValueError('Invalid signer.')
        super().__init__(signer, memo, _validate=_validate)

    def __eq__(self, value: ExecutiveSpawn) -> bool:
        if not isinstance(value, ExecutiveSpawn):
            return NotImplemented
        return self.signer == value.signer and self.memo == value.memo

    @property
    def size(self) -> int:
        n = 1 + self.signer.size
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n
    
    def encode(self) -> bytes:
        prefix, signer = self._encode_signer(self.signer)
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 1
        return b''.join([
            pack('<B', prefix), signer, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveSpawn:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        signer = cls._decode_signer(prefix & 1, view[1:])
        prefix >>= 1
        memo = cls._decode_memo(prefix & 3, view[1+signer.size:])
        return cls(signer, memo, _validate=False)


class AssetSpawn(TransactionInput):

    def __init__(self,
        signer: SignerKey | SignerList,
        memo: bytes | bytearray | memoryview | None = None,
        lock: bool = False,
        _validate: bool = True
    ):
        if _validate and not isinstance(lock, bool):
            raise ValueError('Invalid lock.')
        super().__init__(signer, memo, _validate=_validate)
        self.lock = lock

    def __eq__(self, value: AssetSpawn) -> bool:
        if not isinstance(value, AssetSpawn):
            return NotImplemented
        return (
            self.signer == value.signer
            and self.memo == value.memo
            and self.lock == value.lock
        )

    @property
    def size(self) -> int:
        n = 1 + self.signer.size
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n
    
    def encode(self) -> bytes:
        prefix, signer = self._encode_signer(self.signer)
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 1
        if isinstance(self.lock, bool):
            prefix |= int(self.lock) << 3
        else:
            raise ValueError('Invalid lock value.')
        return b''.join([
            pack('<B', prefix), signer, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> AssetSpawn:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        signer = cls._decode_signer(prefix & 1, view[1:])
        prefix >>= 1
        memo = cls._decode_memo(prefix & 3, view[1+signer.size:])
        prefix >>= 2
        lock = bool(prefix & 1)
        return cls(signer, memo, lock, _validate=False)


class TransactionOutput(TransactionElement):
    
    def __init__(self,
        units: int | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if (
                units is not None
                and (
                    not isinstance(units, int)
                    or units <= 0
                    or units >= 0x1_0000_0000_0000_0000
                )
            ):
                raise ValueError('Invalid units.')
        super().__init__(memo, _validate)
        self.units = units


class UTXOSpawn(TransactionOutput):

    SIGNER_KEY = 0
    SIGNER_HASH = 1
    SIGNER_NONE = 2

    def __init__(self,
        asset: SignerHash | None = None,
        signer: SignerHash | SignerKey | None = None,
        units: int | None = None,
        block_reward: int | None = None,
        exec_fund: int | None = None,
        utxo_fee: int | None = None,
        data_fee: int | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if asset is not None and not isinstance(asset, SignerHash):
                raise ValueError('Invalid asset identifier.')
            if (
                signer is not None
                and not isinstance(signer, (SignerKey, SignerHash))
            ):
                raise ValueError('Invalid signer.')
            if (
                block_reward is not None
                and (
                    not isinstance(block_reward, int)
                    or block_reward < 0
                    or block_reward >= 0x1_0000_0000_0000_0000
                )
            ):
                raise ValueError('Invalid block_reward.')
            if (
                exec_fund is not None
                and (
                    not isinstance(exec_fund, int)
                    or exec_fund < 0
                    or exec_fund >= 0x1_0000_0000_0000_0000
                )
            ):
                raise ValueError('Invalid exec_fund.')
            if (
                utxo_fee is not None
                and (
                    not isinstance(utxo_fee, int)
                    or utxo_fee < 0
                    or utxo_fee >= 0x1_0000_0000_0000_0000
                )
            ):
                raise ValueError('Invalid utxo_fee.')
            if (
                data_fee is not None
                and (
                    not isinstance(data_fee, int)
                    or data_fee < 0
                    or data_fee >= 0x1_0000_0000_0000_0000
                )
            ):
                raise ValueError('Invalid data_fee.')
        super().__init__(units, memo, _validate=_validate)
        self.asset = asset
        self.signer = signer
        self.block_reward = block_reward
        self.exec_fund = exec_fund
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee

    def __eq__(self, value: UTXOSpawn) -> bool:
        if not isinstance(value, UTXOSpawn):
            return NotImplemented
        return (
            self.asset == value.asset
            and self.signer == value.signer
            and self.units == value.units
            and self.block_reward == value.block_reward
            and self.exec_fund == value.exec_fund
            and self.utxo_fee == value.utxo_fee
            and self.data_fee == value.data_fee
            and self.memo == value.memo
        )

    @property
    def size(self) -> int:
        n = 2
        n += self.asset.size if self.asset else 0
        match self.signer:
            case None:
                pass
            case SignerHash() | SignerKey():
                n += self.signer.size
            case _:
                raise ValueError('Invalid signer.')
        n += 8 if self.units else 0
        n += 0 if self.block_reward is None else 8
        n += 0 if self.exec_fund is None else 8
        n += 0 if self.utxo_fee is None else 8
        n += 0 if self.data_fee is None else 8
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        prefix = 0
        asset = self.asset.encode() if self.asset else b''
        prefix |= 1 if asset else 0
        match self.signer:
            case SignerKey():
                signer = self.signer.encode()
                prefix |= self.SIGNER_KEY << 1
            case SignerHash():
                signer = self.signer.encode()
                prefix |= self.SIGNER_HASH << 1
            case None:
                signer = b''
                prefix |= self.SIGNER_NONE << 1
            case _:
                raise ValueError('Invalid signer.')
        units = pack('<Q', self.units) if self.units else b''
        prefix |= 8 if units else 0
        reward = b'' if self.block_reward is None else pack('<Q', self.block_reward)
        prefix |= 16 if reward else 0
        fund = b'' if self.exec_fund is None else pack('<Q', self.exec_fund)
        prefix |= 32 if fund else 0
        utxo_fee = b'' if self.utxo_fee is None else pack('<Q', self.utxo_fee)
        prefix |= 64 if utxo_fee else 0
        data_fee = b'' if self.data_fee is None else pack('<Q', self.data_fee)
        prefix |= 128 if data_fee else 0
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 8
        return b''.join([
            pack('<H', prefix), asset, signer, units, reward,
            fund, utxo_fee, data_fee, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXOSpawn:
        try:
            prefix = unpack_from('<H', view, 0)[0]
            offset = 2
            asset = SignerHash.decode(view[offset:]) if prefix & 1 else None
            offset += 0 if asset is None else asset.size
            prefix >>= 1
            match prefix & 3:
                case cls.SIGNER_NONE:
                    signer = None
                case cls.SIGNER_HASH:
                    signer = SignerHash.decode(view[offset:])
                case cls.SIGNER_KEY:
                    signer = SignerKey.decode(view[offset:])
                case _:
                    raise ValueError('Invalid signer.')
            offset += 0 if signer is None else signer.size
            prefix >>= 2
            units = unpack_from('<Q', view, offset)[0] if prefix & 1 else None
            if units == 0:
                raise ValueError('Invalid units.')
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            reward = unpack_from('<Q', view, offset)[0] if prefix & 1 else None
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            fund = unpack_from('<Q', view, offset)[0] if prefix & 1 else None
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            utxo_fee = unpack_from('<Q', view, offset)[0] if prefix & 1 else None
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            data_fee = unpack_from('<Q', view, offset)[0] if prefix & 1 else None
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(
                asset, signer, units, reward, fund,
                utxo_fee, data_fee, memo, _validate=False
            )
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class ExecutiveVote(TransactionOutput):
    
    def __init__(self,
        executive: SignerHash,
        units: int | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(executive, SignerHash):
                raise ValueError('Invalid executive identifier.')
        super().__init__(units, memo, _validate=_validate)
        self.executive = executive

    def __eq__(self, value: ExecutiveVote) -> bool:
        if not isinstance(value, ExecutiveVote):
            return NotImplemented
        return (
            self.executive == value.executive
            and self.units == value.units
            and self.memo == value.memo
        )

    @property
    def size(self) -> int:
        n = 1
        n += self.executive.size
        n += 8 if self.units else 0
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        prefix = 0
        executive = self.executive.encode()
        units = pack('<Q', self.units) if self.units else b''
        prefix |= 1 if units else 0
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 1
        return b''.join([
            pack('<B', prefix), executive, units, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveVote:
        try:
            prefix = view[0]
            offset = 1
            executive = SignerHash.decode(view[offset:])
            offset += executive.size
            units = unpack_from('<Q', view, offset)[0] if prefix & 1 else None
            if units == 0:
                raise ValueError('Invalid units.')
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(executive, units, memo, _validate=False)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class Signature(Bytes):

    SIZE = 64


class Transaction(AbstractElement):

    PUBLISHER_SPEND = 0
    EXECUTIVE_SPEND = 1
    UTXO_SPEND = 2
    ASSET_SPAWN = 3
    EXECUTIVE_SPAWN = 4

    UTXO_SPAWN = 0
    EXECUTIVE_VOTE = 1

    def __init__(self,
        inputs: list[
            PublisherSpend | ExecutiveSpend | UTXOSpend
            | AssetSpawn | ExecutiveSpawn
        ],
        outputs: list[UTXOSpawn | ExecutiveVote] = [],
        signatures: list[Signature] = [],
        _validate: bool = True
    ):
        if _validate:
            if not all(
                isinstance(x, (
                    PublisherSpend, ExecutiveSpend, UTXOSpend,
                    AssetSpawn, ExecutiveSpawn
                ))
                for x in inputs
            ):
                raise ValueError('Invalid inputs list.')
            if not all(
                isinstance(x, (UTXOSpawn, ExecutiveVote))
                for x in outputs
            ):
                raise ValueError('Invalid outputs list.')
            if not all(
                isinstance(x, Signature)
                for x in signatures
            ):
                raise ValueError('Invalid signatures list.')
        self.inputs = inputs
        self.outputs = outputs
        self.signatures = signatures

    def __eq__(self, value: Transaction) -> bool:
        if not isinstance(value, Transaction):
            return NotImplemented
        return (
            self.inputs == value.inputs
            and self.outputs == value.outputs
            and self.signatures == value.signatures
        )

    @property
    def signers(self) -> list[SignerKey]:
        keys: list[SignerKey] = [k for x in self.inputs for k in x.signers]
        unique: set[bytes] = set()
        output: list[SignerKey] = []
        for k in keys:
            if k.value not in unique:
                unique.add(k.value)
                output.append(k)
        return output

    @property
    def size(self) -> int:
        n = 6
        n += (len(self.inputs) + 1) >> 1
        n += (len(self.outputs) + 7) >> 3
        n += sum(x.size for x in self.inputs)
        n += sum(x.size for x in self.outputs)
        n += 64 * len(self.signatures)
        return n

    async def hash(self) -> TransactionHash:
        preimage = self.encode(include_signatures=False)
        return TransactionHash(await keccak_1600(preimage))

    def encode(self, include_signatures: bool = True) -> bytes:
        if include_signatures:
            if self._encoded:
                return self._encoded
            signatures = [x.encode() for x in self.signatures]
        else:
            signatures = []
        prefix = pack('<HHH', len(self.inputs), len(self.outputs), len(signatures))
        in_types = bytearray((len(self.inputs) + 1) >> 1)
        for i, x in enumerate(self.inputs):
            match x:
                case PublisherSpend():
                    in_types[i >> 1] |= self.PUBLISHER_SPEND << ((i & 1) << 2)
                case ExecutiveSpend():
                    in_types[i >> 1] |= self.EXECUTIVE_SPEND << ((i & 1) << 2)
                case UTXOSpend():
                    in_types[i >> 1] |= self.UTXO_SPEND << ((i & 1) << 2)
                case AssetSpawn():
                    in_types[i >> 1] |= self.ASSET_SPAWN << ((i & 1) << 2)
                case ExecutiveSpawn():
                    in_types[i >> 1] |= self.EXECUTIVE_SPAWN << ((i & 1) << 2)
                case _:
                    raise ValueError('Invalid input type.')
        inputs = [x.encode() for x in self.inputs]
        out_types = bytearray((len(self.outputs) + 7) >> 3)
        for i, x in enumerate(self.outputs):
            match x:
                case UTXOSpawn():
                    out_types[i >> 3] |= self.UTXO_SPAWN << (i & 7)
                case ExecutiveVote():
                    out_types[i >> 3] |= self.EXECUTIVE_VOTE << (i & 7)
                case _:
                    raise ValueError('Invalid output type.')
        outputs = [x.encode() for x in self.outputs]
        return b''.join(
            [prefix, in_types, out_types] + inputs + outputs + signatures
        )

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Transaction:
        try:
            ninputs, noutputs, nsignatures = unpack_from('<HHH', view, 0)
            offset = 6
            # Input types
            in_types_len = (ninputs + 1) >> 1
            if len(view) < offset + in_types_len:
                raise IndexError()
            in_types = view[offset:offset + in_types_len]
            offset += in_types_len
            # Output types
            out_types_len = (noutputs + 7) >> 3
            if len(view) < offset + out_types_len:
                raise IndexError()
            out_types = view[offset:offset + out_types_len]
            offset += out_types_len
            # Decode inputs
            inputs: list[
                PublisherSpend | ExecutiveSpend | UTXOSpend | AssetSpawn | ExecutiveSpawn
            ] = []
            for i in range(ninputs):
                match (in_types[i >> 1] >> ((i & 1) << 2)) & 7:
                    case cls.PUBLISHER_SPEND:
                        x = PublisherSpend.decode(view[offset:])
                    case cls.EXECUTIVE_SPEND:
                        x = ExecutiveSpend.decode(view[offset:])
                    case cls.UTXO_SPEND:
                        x = UTXOSpend.decode(view[offset:])
                    case cls.ASSET_SPAWN:
                        x = AssetSpawn.decode(view[offset:])
                    case cls.EXECUTIVE_SPAWN:
                        x = ExecutiveSpawn.decode(view[offset:])
                    case _:
                        raise ValueError('Invalid input type.')
                inputs.append(x)
                offset += x.size
            # Decode outputs
            outputs: list[UTXOSpawn | ExecutiveVote] = []
            for i in range(noutputs):
                match (out_types[i >> 3] >> (i & 7)) & 1:
                    case cls.UTXO_SPAWN:
                        x = UTXOSpawn.decode(view[offset:])
                    case cls.EXECUTIVE_VOTE:
                        x = ExecutiveVote.decode(view[offset:])
                outputs.append(x)
                offset += x.size
            # Decode signatures
            signatures: list[Signature] = []
            for i in range(nsignatures):
                if len(view) < offset + 64:
                    raise IndexError()
                x = Signature.decode(view[offset:])
                signatures.append(x)
                offset += x.size
            # Return Transaction
            return cls(inputs, outputs, signatures, _validate=False)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class BlockHeaderHash(Bytes):

    SIZE = 32


class BlockHash(Bytes):

    SIZE = 32


class TransactionListHash(Bytes):

    SIZE = 32


class Nonce(Bytes):

    SIZE = 32


class Parameters(AbstractElement):

    SIZE = 66

    TARGET_MAX = 255 * 2 ** 255

    def __init__(self,
        target: int,            # mint difficulty x * 2 ** y
        block_reward: int,      # units generated each block for publishers
        exec_fund: int,         # units generated each epoch for executives
        utxo_fee: int,          # decay of UTXOs per block as a fraction z / 2**64
        data_fee: int,          # units to destroy per byte in payment
        executive: SignerHash,  # identifier of elected executive
        _validate: bool = True
    ):
        if _validate:
            if (
                not isinstance(target, int)
                or target < 0
                or target > self.TARGET_MAX
            ):
                raise ValueError('Invalid target.')
            if (
                not isinstance(block_reward, int)
                or block_reward < 0
                or block_reward >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid block_reward.')
            if (
                not isinstance(exec_fund, int)
                or exec_fund < 0
                or exec_fund >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid exec_fund.')
            if (
                not isinstance(utxo_fee, int)
                or utxo_fee < 0
                or utxo_fee >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid utxo_fee.')
            if (
                not isinstance(data_fee, int)
                or data_fee < 0
                or data_fee >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid data_fee.')
            if not isinstance(executive, SignerHash):
                raise ValueError('Invalid executive identifier.')
        self.target = target
        self.block_reward = block_reward
        self.exec_fund = exec_fund
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee
        self.executive = executive

    def __eq__(self, value: Parameters) -> bool:
        if not isinstance(value, Parameters):
            return NotImplemented
        return (
            self.encode_target() == value.encode_target()
            and self.block_reward == value.block_reward
            and self.exec_fund == value.exec_fund
            and self.utxo_fee == value.utxo_fee
            and self.data_fee == value.data_fee
            and self.executive == value.executive
        )

    @property
    def size(self) -> int:
        return self.SIZE

    def encode_target(self) -> bytes:
        n = max(0, self.target.bit_length() - 8)
        x = self.target >> n
        return bytes([x, n])

    def encode(self) -> bytes:
        target = self.encode_target()
        ints = pack('<QQQQ', 
            self.block_reward, self.exec_fund, self.utxo_fee, self.data_fee
        )
        executive = self.executive.encode()
        return b''.join([target, ints, executive])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Parameters:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid view size.')
        target = view[0] * (1 << view[1])
        reward, fund, utxo_fee, data_fee = unpack_from('<QQQQ', view, 2)
        executive = SignerHash.decode(view[34:])
        return cls(target, reward, fund, utxo_fee, data_fee, executive, _validate=False)


class BlockHeader(AbstractElement):

    SIGNER_KEY = 0
    SIGNER_HASH = 1

    def __init__(self,
        id: int, timestamp: int, prev_block: BlockHash,
        publisher: SignerKey | SignerHash, ntxs: int | None = None,
        root_hash: TransactionListHash | None = None,
        parameters: Parameters | None = None, nonce: Nonce | None = None,
        _validate: bool = True
    ):
        if _validate:
            if (
                not isinstance(id, int)
                or id < 0
                or id >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid block id.')
            if (
                not isinstance(timestamp, int)
                or timestamp < 0
                or timestamp >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid timestamp.')
            if not isinstance(prev_block, BlockHash):
                raise ValueError('Invalid prev_block.')
            if not isinstance(publisher, (SignerKey, SignerHash)):
                raise ValueError('Invalid publisher.')
            if ntxs is None:
                if root_hash is not None:
                    raise ValueError('Invalid root_hash.')
            elif (
                not isinstance(ntxs, int)
                or ntxs <= 0
                or ntxs >= 0x1_0000_0000_0000_0000
            ):
                raise ValueError('Invalid ntxs.')
            if root_hash is None:
                if ntxs is not None:
                    raise ValueError('Invalid root_hash.')
            elif not isinstance(root_hash, TransactionListHash):
                raise ValueError('Invalid root_hash.')
            if parameters is not None and not isinstance(parameters, Parameters):
                raise ValueError('Invalid parameters.')
            if nonce is not None and not isinstance(nonce, Nonce):
                raise ValueError('Invalid nonce.')
        self.id = id
        self.timestamp = timestamp
        self.prev_block = prev_block
        self.publisher = publisher
        self.ntxs = ntxs
        self.root_hash = root_hash
        self.parameters = parameters
        self.nonce = nonce

    def __eq__(self, value: BlockHeader) -> bool:
        if not isinstance(value, BlockHeader):
            return NotImplemented
        return (
            self.id == value.id
            and self.timestamp == value.timestamp
            and self.prev_block == value.prev_block
            and self.publisher == value.publisher
            and self.ntxs == value.ntxs
            and self.root_hash == value.root_hash
            and self.parameters == value.parameters
            and self.nonce == value.nonce
        )

    @property
    def size(self) -> int:
        n = 17      # prefix[1] | id[8] | timestamp[8]
        n += self.prev_block.size
        n += self.publisher.size
        if self.ntxs:
            if self.root_hash is None:
                raise ValueError('Invalid root_hash')
            n += 4 + self.root_hash.size
        n += 0 if self.parameters is None else self.parameters.size
        n += 0 if self.nonce is None else self.nonce.size
        return n

    async def hash(self) -> BlockHeaderHash:
        return BlockHeaderHash(
            await keccak_1600(self.encode(include_nonce=False))
        )

    async def hash_nonce(self) -> BlockHash:
        if self.nonce is None:
            raise ValueError('Invalid nonce.')
        return BlockHash(
            await keccak_800(
                (await self.hash()).value + self.nonce.value
            )
        )

    def encode(self, include_nonce=True) -> bytes:
        prefix = 0
        id = pack('<Q', self.id)
        timestamp = pack('<Q', self.timestamp)
        prev_block = self.prev_block.encode()
        match self.publisher:
            case SignerKey():
                prefix |= self.SIGNER_KEY
            case SignerHash():
                prefix |= self.SIGNER_HASH
            case _:
                raise ValueError('Invalid publisher.')
        publisher = self.publisher.encode()
        if self.ntxs:
            prefix |= 2
            ntxs = pack('<I', self.ntxs)
            root_hash = self.root_hash.encode()
        else:
            ntxs = b''
            root_hash = b''
        parameters = b'' if self.parameters is None else self.parameters.encode()
        prefix |= 4 if parameters else 0
        if not include_nonce or self.nonce is None:
            nonce = b''
        else:
            nonce = self.nonce.encode()
            prefix |= 8
        prefix = pack('<B', prefix)
        return b''.join([
            prefix, id, timestamp, prev_block, publisher,
            ntxs, root_hash, parameters, nonce
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> BlockHeader:
        try:
            prefix = view[0]
            id, timestamp = unpack_from('<QQ', view, 1)
            prev_block = BlockHash.decode(view[17:])
            offset = 17 + prev_block.size
            match prefix & 1:
                case cls.SIGNER_KEY:
                    publisher = SignerKey.decode(view[offset:])
                case cls.SIGNER_HASH:
                    publisher = SignerHash.decode(view[offset:])
            offset += publisher.size
            if prefix & 2:
                ntxs = unpack_from('<I', view, offset)[0]
                if not ntxs:
                    raise ValueError('Invalid ntxs.')
                offset += 4
                root_hash = TransactionListHash.decode(view[offset:])
                offset += root_hash.size
            else:
                ntxs = None
                root_hash = None
            parameters = Parameters.decode(view[offset:]) if prefix & 4 else None
            offset += parameters.size if parameters else 0
            nonce = Nonce.decode(view[offset:]) if prefix & 8 else None
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')
        return cls(
            id, timestamp, prev_block, publisher,
            ntxs, root_hash, parameters, nonce, _validate=False
        )


class Block(AbstractElement):
    SIGNER_KEY = 0
    SIGNER_HASH = 1

    def __init__(self,
        header: BlockHeader,
        transactions: list[Transaction] = [],
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(header, BlockHeader):
                raise ValueError('Invalid block header.')
            if not all(isinstance(tx, Transaction) for tx in transactions):
                raise ValueError('Invalid transaction.')
        self.header = header
        self.transactions = transactions

    def __eq__(self, value: Block) -> bool:
        if not isinstance(value, Block):
            return NotImplemented
        return (
            self.header == value.header
            and self.transactions == value.transactions
        )

    @property
    def size(self) -> int:
        n = self.header.size
        n += sum(2 + tx.size for tx in self.transactions)
        return n

    async def hash_transactions(self, merkle: bool = False) -> TransactionListHash | None:
        if not self.transactions:
            return
        hashes = await gather(*[
            tx.hash() for tx in self.transactions
        ])
        if merkle:
            while len(hashes) > 1:
                if len(hashes) & 1:
                    hashes.append(hashes[-1])
                hashes = await gather(*[
                    keccak_1600(hashes[i].value + hashes[i + 1].value)
                    for i in range(0, len(hashes), 2)
                ])
            hash = hashes[0].value
        else:
            hash = await keccak_1600(b''.join(h.value for h in hashes))
        return TransactionListHash(hash)

    async def hash(self, update_header=False) -> BlockHash:
        h = await self.hash_transactions()
        if update_header:
            self.header.ntxs = len(self.transactions) or None
            self.header.root_hash = h
        elif self.header.ntxs != (len(self.transactions) or None):
            raise ValueError('Invalid header.ntxs.')
        elif self.header.root_hash != h:
            raise ValueError('Invalid header.root_hash.')
        return await self.header.hash_nonce()

    def encode(self) -> bytes:
        if len(self.transactions):
            if self.header.ntxs != len(self.transactions):
                raise ValueError('Invalid header.ntxs')
            if self.header.root_hash is None:
                raise ValueError('Invalid header.root_hash')
        else:
            if self.header.ntxs is not None:
                raise ValueError('Invalid header.ntxs')
            if self.header.root_hash is not None:
                raise ValueError('Invalid header.root_hash')
        header = self.header.encode()
        transactions: list[bytes] = []
        n = len(self.transactions)
        tx_lens = bytearray(2 * n)
        if n == 0:
            pass
        elif n < 0x1_0000_0000:
            for i, tx in enumerate(self.transactions):
                tx = tx.encode()
                m = len(tx)
                if m >= 0x1_0000:
                    raise ValueError('Invalid transaction size.')
                pack_into('<H', tx_lens, 2 * i, m)
                transactions.append(tx)
        else:
            raise ValueError('Invalid transactions list size.')
        return b''.join(
            [header, tx_lens] + transactions
        )

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Block:
        try:
            header = BlockHeader.decode(view)
            transactions: list[Transaction] = []
            if header.ntxs:
                offset = header.size
                end = offset + 2 * header.ntxs
                if len(view) < end:
                    raise IndexError()
                offsets = [end]
                for i in range(offset, end, 2):
                    end += unpack_from('<H', view, i)[0]
                    offsets.append(end)
                if len(view) < offsets[-1]:
                    raise IndexError()
                for i in range(header.ntxs):
                    s, e = offsets[i], offsets[i + 1]
                    tx = Transaction.decode(view[s:e])
                    if tx.size != (e - s):
                        raise ValueError('Invalid transaction size.')
                    transactions.append(tx)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')
        return cls(
            header, transactions, _validate=False
        )
