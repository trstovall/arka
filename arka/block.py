
from __future__ import annotations
from typing import Literal
from struct import pack, unpack_from, error as StructError
from arka.crypto import keccak_800, keccak_1600


class Parameters(object):

    SIZE = 66

    def __init__(self,
        target: int,            # mint difficulty x * 2 ** y
        block_reward: int,      # units generated each block for publishers
        exec_fund: int,         # units generated per epoch for executive spends
        utxo_fee: int,          # decay of UTXOs per block as a fraction z / 2**64
        data_fee: int,          # units to destroy per byte in payment
        executive: bytes        # account address of elected executive
    ):
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
        encoding = b''.join([target, ints, self.executive])
        if len(encoding) != self.SIZE:
            raise ValueError('Invalid size when encoding.')
        return encoding

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Parameters:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid size when decoding.')
        target = view[0] * (1 << view[1])
        reward, fund, utxo_fee, data_fee = unpack_from('<QQQQ', view, 2)
        exec = bytes(view[34:66])
        return cls(target, reward, fund, utxo_fee, data_fee, exec)


class SignerHash(object):

    SIZE = 32

    def __init__(self, hash: bytes):
        self.hash = hash

    def __eq__(self, value: SignerHash) -> bool:
        if not isinstance(value, SignerHash):
            return NotImplemented
        return self.hash == value.hash

    @property
    def size(self) -> int:
        return self.SIZE

    def encode(self) -> bytes:
        return self.hash
       
    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> SignerHash:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid size when decoding.')
        hash = view if len(view) == cls.SIZE else view[:cls.SIZE]
        hash = hash if isinstance(hash, bytes) else bytes(hash)
        return cls(hash)


class SignerKey(object):

    SIZE = 32

    def __init__(self, key: bytes):
        self.key = key

    def __eq__(self, value: SignerKey) -> bool:
        if not isinstance(value, SignerKey):
            return NotImplemented
        return self.key == value.key

    @property
    def size(self) -> int:
        return self.SIZE

    def encode(self) -> bytes:
        return self.key
       
    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> SignerKey:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid size when decoding.')
        key = view if len(view) == cls.SIZE else view[:cls.SIZE]
        key = key if isinstance(key, bytes) else bytes(key)
        return cls(key)

    async def hash(self) -> SignerHash:
        return SignerHash(await keccak_800(self.key))    


class SignerList(object):

    SIGNER_HASH = 0
    SIGNER_KEY = 1
    SIGNER_LIST = 2

    def __init__(self,
        signers: list[SignerList | SignerHash | SignerKey],
        threshold: int,
        _encoding: bytes | None = None
    ):
        if len(signers) <= 0 or len(signers) >= 0x8000:
            raise ValueError('Invalid signer list.')
        if threshold <= 0 or threshold > len(signers):
            raise ValueError('Invalid threshold.')
        self.signers = signers
        self.threshold = threshold
        self._encoding = _encoding

    def __eq__(self, value: SignerList) -> bool:
        if not isinstance(value, SignerList):
            return NotImplemented
        return (
            self.signers == value.signers
            and self.threshold == value.threshold
        )

    @property
    def size(self) -> int:
        if self._encoding:
            return len(self._encoding)
        n = 1 if len(self.signers) < 0x80 else 2
        n += 1 if self.threshold < 0x80 else 2
        n += (len(self.signers) + 3) // 4
        n += sum(s.size for s in self.signers)
        return n

    @property
    def keys(self) -> list[bytes]:
        key_count = 0
        values: list[bytes] = []
        output: list[bytes] = []
        unique: set[bytes] = set()
        for s in self.signers:
            match s:
                case SignerList():
                    values.extend(s.keys)
                    key_count += 1
                case SignerKey():
                    values.append(s.key)
                    key_count += 1
        if key_count < self.threshold:
            raise ValueError("SignerList keys does not meet threshold.")
        for k in values:
            if k not in unique:
                unique.add(k)
                output.append(k)
        return output

    async def hash(self) -> SignerHash:
        prefix = pack('<HH', len(self.signers), self.threshold)
        hashes: list[bytes] = []
        for i, s in enumerate(self.signers):
            match s:
                case SignerHash():
                    hashes.append(s.hash)
                case SignerKey() | SignerList():
                    hashes.append((await s.hash()).hash)
                case _:
                    raise ValueError('Invalid signer type.')
        preimage = b''.join([prefix] + hashes)
        return SignerHash(await keccak_1600(preimage))

    def encode(self) -> bytes:
        if self._encoding:
            return self._encoding
        n = len(self.signers)
        n = (n << 1) | (0 if n < 0x80 else 1)
        n = n.to_bytes(2 if n & 1 else 1, 'little')
        x = self.threshold
        x = (x << 1) | (0 if x < 0x80 else 1)
        x = x.to_bytes(2 if x & 1 else 1, 'little')
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
        self._encoding = b''.join([n, x, types] + encodings)
        return self._encoding

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
            x = view[offset]
            offset += 1
            if x & 1:
                x += view[offset] << 8
                offset += 1
            x >>= 1
            if not n or not x:
                raise ValueError('Decoded `SignerList` must not be empty.')
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
        encoding = bytes(view if len(view) == offset else view[:offset])
        return SignerList(signers, x, encoding)


class UTXORefByIndex(object):

    SIZE = 14

    def __init__(self, block: int, tx: int, output: int):
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
            raise ValueError('Invalid size when decoding.')
        return cls(*unpack_from('<QIH', view, 0))


class UTXORefByHash(object):

    SIZE = 34

    def __init__(self, tx_hash: bytes, output: int):
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
        return self.SIZE
    
    def encode(self) -> bytes:
        return self.tx_hash + pack('<H', self.output)

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXORefByHash:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid size when decoding.')
        tx_hash = bytes(view if len(view) == 32 else view[:32])
        return cls(tx_hash, *unpack_from('<H', view, 32))


class AbstractTXInput(object):

    SIGNER_KEY = 0
    SIGNER_LIST = 1
    SIGNER_NONE = 2

    @property
    def signers(self) -> list[bytes]:
        match self.signer:
            case SignerKey():
                return [self.signer.key]
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

    @classmethod
    def _encode_mlen(cls, memo: bytes) -> tuple[Literal[0, 1, 2], bytes]:
        prefix = 0
        mlen = len(memo)
        if mlen == 0:
            mlen = b''
        elif mlen < 0x100:
            mlen = pack('<B', mlen)
            prefix |= 1
        elif mlen < 0x10000:
            mlen = pack('<H', mlen)
            prefix |= 2
        else:
            raise ValueError('Invalid memo size')
        return prefix, mlen

    @classmethod
    def _decode_memo(
        cls, prefix: Literal[0, 1, 2], view: bytes | bytearray | memoryview
    ) -> bytes:
        try:
            match prefix:
                case 0:
                    return b''
                case 1:
                    mlen = view[0]
                    if len(view) < 1 + mlen:
                        raise IndexError()
                    return bytes(view[1:1+mlen])
                case 2:
                    mlen = unpack_from('<H', view, 0)[0]
                    if len(view) < 2 + mlen:
                        raise IndexError()
                    return bytes(view[2:2+mlen])
                case _:
                    raise IndexError()
        except (IndexError, StructError) as e:
            raise ValueError('Invalid memo size')


class BlockSpend(AbstractTXInput):

    def __init__(self,
        block: int,
        signer: SignerKey | SignerList | None = None,
        memo: bytes = b''
    ):
        self.block = block
        self.signer = signer
        self.memo = memo

    @property
    def size(self) -> int:
        n = 9
        n += (self.signer.size if self.signer else 0)
        prefix, mlen = self._encode_mlen(self.memo)
        n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        prefix, signer = self._encode_optional_signer(self.signer)
        _prefix, mlen = self._encode_mlen(self.memo)
        prefix |= _prefix << 2
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
        memo = cls._decode_memo(prefix & 3, view[9+signer.size:])
        return cls(block, signer, memo)


class PublisherSpend(BlockSpend):

    def __eq__(self, value: PublisherSpend) -> bool:
        if not isinstance(value, PublisherSpend):
            return NotImplemented
        return (
            self.block == value.block
            and self.signer == value.signer
            and self.memo == value.memo
        )

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> PublisherSpend:
        x = BlockSpend.decode(view)
        return cls(x.block, x.signer, x.memo)


class ExecutiveSpend(BlockSpend):

    def __eq__(self, value: ExecutiveSpend) -> bool:
        if not isinstance(value, ExecutiveSpend):
            return NotImplemented
        return (
            self.block == value.block
            and self.signer == value.signer
            and self.memo == value.memo
        )
    
    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveSpend:
        x = BlockSpend.decode(view)
        return cls(x.block, x.signer, x.memo)


class UTXOSpend(AbstractTXInput):

    UTXO_REF_BY_INDEX = 0
    UTXO_REF_BY_HASH = 1

    def __init__(self,
        utxo: UTXORefByIndex | UTXORefByHash,
        signer: SignerKey | SignerList | None = None,
        memo: bytes = b''
    ):
        self.utxo, self.signer, self.memo = utxo, signer, memo

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
        _prefix, mlen = self._encode_mlen(self.memo)
        prefix |= _prefix << 3
        return b''.join([
            pack('<B', prefix), self.utxo.encode(),
            signer, mlen, self.memo
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
        return cls(utxo, signer, memo)


class ExecutiveSpawn(AbstractTXInput):

    def __init__(self, signer: SignerKey | SignerList, memo: bytes = b''):
        self.signer, self.memo = signer, memo

    def __eq__(self, value: ExecutiveSpawn) -> bool:
        if not isinstance(value, ExecutiveSpawn):
            return NotImplemented
        return self.signer == value.signer and self.memo == value.memo

    @property
    def size(self) -> int:
        n = 1 + self.signer.size
        prefix, mlen = self._encode_mlen(self.memo)
        n += len(mlen) + len(self.memo)
        return n
    
    def encode(self) -> bytes:
        prefix, signer = self._encode_signer(self.signer)
        _prefix, mlen = self._encode_mlen(self.memo)
        prefix |= _prefix << 1
        return b''.join([
            pack('<B', prefix), signer, mlen, self.memo
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveSpawn:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        signer = cls._decode_signer(prefix & 1, view[1:])
        prefix >>= 1
        memo = cls._decode_memo(prefix & 3, view[1+signer.size:])
        return cls(signer, memo)


class AssetSpawn(AbstractTXInput):

    def __init__(self, signer: SignerKey | SignerList, memo: bytes = b'', lock: bool = False):
        self.signer, self.memo, self.lock = signer, memo, lock

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
        prefix, mlen = self._encode_mlen(self.memo)
        n += len(mlen) + len(self.memo)
        return n
    
    def encode(self) -> bytes:
        prefix, signer = self._encode_signer(self.signer)
        _prefix, mlen = self._encode_mlen(self.memo)
        prefix |= _prefix << 1
        if isinstance(self.lock, bool):
            prefix |= int(self.lock) << 3
        else:
            raise ValueError('Invalid lock value.')
        return b''.join([
            pack('<B', prefix), signer, mlen, self.memo
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
        return cls(signer, memo, lock)


class AbstractTXOutput(object):

    @classmethod
    def _encode_mlen(cls, memo: bytes) -> tuple[Literal[0, 1, 2], bytes]:
        prefix = 0
        mlen = len(memo)
        if mlen == 0:
            mlen = b''
        elif mlen < 0x100:
            mlen = pack('<B', mlen)
            prefix |= 1
        elif mlen < 0x10000:
            mlen = pack('<H', mlen)
            prefix |= 2
        else:
            raise ValueError('Invalid memo size')
        return prefix, mlen

    @classmethod
    def _decode_memo(
        cls, prefix: Literal[0, 1, 2], view: bytes | bytearray | memoryview
    ) -> bytes:
        try:
            match prefix:
                case 0:
                    return b''
                case 1:
                    mlen = view[0]
                    if len(view) < 1 + mlen:
                        raise IndexError()
                    return bytes(view[1:1+mlen])
                case 2:
                    mlen = unpack_from('<H', view, 0)[0]
                    if len(view) < 2 + mlen:
                        raise IndexError()
                    return bytes(view[2:2+mlen])
                case _:
                    raise IndexError()
        except (IndexError, StructError) as e:
            raise ValueError('Invalid memo size')


class UTXOSpawn(AbstractTXOutput):

    SIGNER_KEY = 0
    SIGNER_HASH = 1
    SIGNER_NONE = 2

    def __init__(self,
        asset: SignerHash | None = None,
        signer: SignerHash | SignerKey | None = None,
        units: int = 0,
        block_reward: int | None = None,
        exec_fund: int | None = None,
        utxo_fee: int | None = None,
        data_fee: int | None = None,
        memo: bytes = b''
    ):
        if signer is None and not units:
            raise ValueError('Burn amount must be non-zero.')
        self.asset = asset
        self.signer = signer
        self.units = units
        self.block_reward = block_reward
        self.exec_fund = exec_fund
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee
        self.memo = memo

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
        _, mlen = self._encode_mlen(self.memo)
        n += len(mlen) + len(self.memo)
        return n

    def encode(self, view: bytes | bytearray | memoryview) -> bytes:
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
        _prefix, mlen = self._encode_mlen(self.memo)
        prefix |= _prefix << 8
        n += len(mlen) + len(self.memo)
        return b''.join([
            pack('<H', prefix), asset, signer, units, reward,
            fund, utxo_fee, data_fee, mlen, self.memo
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
            units = unpack_from('<Q', view, offset)[0] if prefix & 1 else 0
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
                asset, signer, units, reward, fund, utxo_fee, data_fee, memo
            )
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class ExecutiveVote(AbstractTXOutput):
    
    def __init__(self, executive: SignerHash, units: int, memo: bytes):
        self.executive = executive
        self.units = units
        self.memo = memo

    @property
    def size(self) -> int:
        n = 1
        n += self.executive.size
        n += 8 if self.units else 0
        prefix, mlen = self._encode_mlen(self.memo)
        n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        prefix = 0
        executive = self.executive.encode()
        units = pack('<Q', self.units) if self.units else b''
        prefix |= 1 if units else 0
        _prefix, mlen = self._encode_mlen(self.memo)
        prefix |= _prefix << 1
        return b''.join([
            pack('<B', prefix), executive, units, mlen, self.memo
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveVote:
        try:
            prefix = view[0]
            offset = 1
            executive = SignerHash.decode(view[offset:])
            offset += executive.size
            units = unpack_from('<Q', view, offset) if prefix & 1 else 0
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(executive, units, memo)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class Transaction(object):

    PUBLISHER_SPEND = 0
    EXECUTIVE_SPEND = 1
    UTXO_SPEND = 2
    ASSET_SPAWN = 3
    EXECUTIVE_SPAWN = 4

    UTXO_SPAWN = 0
    EXECUTIVE_VOTE = 1

    def __init__(self,
        inputs: list[
            PublisherSpend | ExecutiveSpend | UTXOSpend | AssetSpawn | ExecutiveSpawn
        ],
        outputs: list[UTXOSpawn | ExecutiveVote],
        signatures: list[bytes] = [],
        _encoded: bytes = b''
    ):
        self.inputs = inputs
        self.outputs = outputs
        self.signatures = signatures
        self._encoded = _encoded
        self._digest: bytes | None = None

    @property
    def signers(self) -> list[bytes]:
        keys: list[bytes] = [k for x in self.inputs for k in x.signers]
        output: list[bytes] = []
        unique: set[bytes] = set()
        for k in keys:
            if k not in unique:
                output.append(k)
                unique.add(k)
        return output

    @property
    def size(self) -> int:
        if self._encoded:
            return len(self._encoded)
        n = 6
        n += (len(self.inputs) + 1) >> 1
        n += (len(self.outputs) + 7) >> 3
        n += sum(x.size for x in self.inputs)
        n += sum(x.size for x in self.outputs)
        n += 64 * len(self.signers)
        return n

    async def hash(self) -> bytes:
        if self._digest is None:
            if self._encoded:
                preimage = self._encoded[:-64 * len(self.signers)]
            else:
                preimage = self.encode(signatures=False)
            self._digest = await keccak_1600(preimage)
        return self._digest

    def encode(self, signatures: bool = True) -> bytes:
        if signatures and self._encoded:
            return self._encoded
        prefix = pack('<HHH', len(self.inputs), len(self.outputs), len(self.signers))
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
                    out_types[i >> 3] |= self.UTXO_SPAWN << (i & 3)
                case ExecutiveVote():
                    out_types[i >> 3] |= self.EXECUTIVE_VOTE << (i & 3)
                case _:
                    raise ValueError('Invalid output type.')
        outputs = [x.encode() for x in self.outputs]
        if signatures:
            if (
                len(self.signatures) != len(self.signers)
                or any(len(x) != 64 for x in self.signatures)
            ):
                raise ValueError('Invalid signatures.')
            encoded = b''.join(
                [prefix, in_types, out_types] + inputs + outputs + self.signatures
            )
            if len(encoded) >= 0x10000:
                raise ValueError('Invalid transaction size.')
            self._encoded = encoded
        else:
            encoded = b''.join([prefix, in_types, out_types] + inputs + outputs)
            if len(encoded) + 64 * len(self.signers) >= 0x10000:
                raise ValueError('Invalid transaction size.')
        return encoded

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Transaction:
        try:
            ninputs, noutputs, nsigners = unpack_from('<HHH', view, 0)
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
                match in_types[i >> 1] & 7:
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
            outputs = list[UTXOSpawn | ExecutiveVote] = []
            for i in range(noutputs):
                match out_types[i >> 3] & 1:
                    case cls.UTXO_SPAWN:
                        x = UTXOSpawn.decode(view[offset:])
                    case cls.EXECUTIVE_VOTE:
                        x = ExecutiveVote.decode(view[offset:])
                outputs.append(x)
                offset += x.size
            # Decode signatures
            signatures: list[bytes] = []
            for i in range(nsigners):
                if len(view) < offset + 64:
                    raise IndexError()
                signatures.append(bytes(view[offset:offset+64]))
                offset += 64
            # Return Transaction
            encoded = bytes(view if len(view) == offset else view[:offset])
            return cls(inputs, outputs, signatures, encoded)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class BlockHeader(object):

    def __init__(self, id: int, timestamp: int, prev_hash: bytes,
        uid: SignerHash, payments_digest: bytes,
        nonce: bytes, parameters: Parameters | None = None
    ):
        self.id = id
        self.timestamp = timestamp
        self.prev_hash = prev_hash
        self.uid = uid
        self.payments_digest = payments_digest
        self.nonce = nonce
        self.parameters = parameters

    @property
    def prehash(self) -> bytes:
        return keccak_1600(self.encode()[:-32])

    @property
    def digest(self) -> bytes:
        return keccak_800(self.prehash + self.nonce)

    def encode(self) -> bytearray:
        size = 128
        uid = self.uid.hash
        if self.parameters:
            parameters = self.parameters.encode()
            size += len(parameters)
        buffer = bytearray(size)
        view = memoryview(buffer)
        pack_into('<IQ', view, 0, self.id, self.timestamp)
        view[12:44] = self.prev_hash
        offset = 44
        view[offset:offset+len(uid)] = uid
        offset += len(uid)
        if self.parameters:
            view[offset:offset+len(parameters)] = parameters
            offset += len(parameters)
        view[offset:offset+32] = self.payments_digest
        offset += 32
        view[offset:offset+32] = self.nonce
        return buffer

    @classmethod
    def decode(cls, view: memoryview) -> tuple['BlockHeader', int]:
        if len(view) < 44:
            raise ValueError('`view` is too short to decode `BlockHeader`.')
        id, timestamp = unpack_from('<IQ', view, 0)
        prev_hash = bytes(view[12:44])
        offset = 44
        if len(view) < offset + 1:
            raise ValueError('`view` is too short to decode `BlockHeader`.')
        match view[offset] & 3:
            case SpenderEnum.SIGNER_HASH.value:
                uid, n = SignerHash.decode(view[offset:])
            case SpenderEnum.SIGNER_KEY.value:
                uid, n = SignerKey.decode(view[offset:])
                if uid.truncate:
                    raise ValueError('`BlockHeader` `SignerKey` must not be truncated.')
        offset += n
        if id % 10000 == 0:
            parameters, n = Parameters.decode(view[offset:])
            offset += n
        else:
            parameters = None
        if len(view) < offset + 64:
            raise ValueError('`view` is too short to decode `BlockHeader`.')
        payments_hash = bytes(view[offset:offset+32])
        nonce = bytes(view[offset+32:offset+64])
        offset += 64
        return cls(
            id, timestamp, prev_hash, uid, payments_hash, nonce, parameters
        ), offset


class Block(object):

    def __init__(self,
        id: int,                                # block number
        timestamp: int,                         # microseconds since UNIX epoch
        prev_hash: bytes,                       # hash digest of most recent block
        nonce: bytes,                           # nonce required to hash block to target difficulty
        uid: SignerHash | SignerKey,          # uid of block worker
        parameters: Parameters | None = None,   # epoch blocks publish network parameters
        payments: list[Payment] = []            # payment transactions to commit by this block
    ):
        self.id = id
        if id % 10000 and parameters is not None:
            raise ValueError('non-epoch blocks should not hold parameters.')
        self.timestamp = timestamp
        self.prev_hash = prev_hash
        self.uid = uid
        self.nonce = nonce
        self.parameters = parameters
        self.payments = payments
        self.payment_hashes = [x.digest for x in payments]

    @property
    def header(self) -> BlockHeader:
        payments_digest = keccak_1600(b''.join(self.payment_hashes))
        return BlockHeader(
            self.id, self.timestamp, self.prev_hash, self.uid,
            payments_digest, self.nonce, self.parameters
        )
