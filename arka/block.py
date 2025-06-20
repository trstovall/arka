
from __future__ import annotations
from typing import Literal
from struct import pack, pack_into, unpack_from, error as StructError
from arka.crypto import keccak_800, keccak_1600
from asyncio import gather


MAX_INT_BYTES = 15


def _encode_optional_int(x: int | None) -> bytes:
    if x:
        n = (x.bit_length() + 7) >> 3
        if n > MAX_INT_BYTES:
            raise ValueError('Invalid integer.')
        return x.to_bytes(n, 'little')
    elif x is None:
        return b''
    else:
        return b'\x00'


def _decode_optional_int(
    nbytes: int, view: bytes | bytearray | memoryview
) -> int | None:
    if not nbytes:
        return
    if len(view) < nbytes:
        raise ValueError('Invalid view size.')
    return int.from_bytes(view[:nbytes], 'little')


async def identity(x):
    return x


class AbstractElement(object):

    def __eq__(self, value: AbstractElement) -> bool:
        return isinstance(value, type(self))

    def __ne__(self, value: AbstractElement) -> bool:
        return not self.__eq__(value)
    
    def __hash__(self) -> int:
        return hash(self.encode())

    @property
    def size(self) -> int:
        return len(self.encode())
    
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

    def __eq__(self, value: Bytes) -> bool:
        return (
            super().__eq__(value)
            and self.value == value.value
        )

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
        return (
            super().__eq__(value)
            and self.signers == value.signers
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

    async def hash(self) -> SignerHash:
        prefix = pack('<HH', len(self.signers), self.threshold)
        hashes: list[bytes] = []
        if not all(
            isinstance(x, (SignerHash, SignerKey, SignerList))
            for x in self.signers
        ):
            raise ValueError('Invalid signer type.')
        hashes: list[SignerHash] = await gather(*[
            (
                s.hash()
                if isinstance(s, (SignerKey, SignerList))
                else identity(s)
            )
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


class SignerLocked(AbstractElement):

    SIGNER_HASH = 0
    SIGNER_LIST = 1

    def __init__(self,
        hash_lock: Nonce_32, hash_locked_signer: SignerList | SignerHash,
        time_lock: int, time_locked_signer: SignerList | SignerHash,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(hash_lock, Nonce_32):
                raise ValueError('Invalid hash_lock.')
            if not isinstance(hash_locked_signer, (SignerList, SignerHash)):
                raise ValueError('Invalid hash_locked_signer.')
            if not isinstance(time_lock, int) or time_lock < 0:
                raise ValueError('Invalid time_lock.')
            if not isinstance(time_locked_signer, (SignerList, SignerHash)):
                raise ValueError('Invalid time_locked_signer.')
        self.hash_lock = hash_lock
        self.hash_locked_signer = hash_locked_signer
        self.time_lock = time_lock
        self.time_locked_signer = time_locked_signer

    def __eq__(self, value: SignerLocked) -> bool:
        return (
            super().__eq__(value)
            and self.hash_lock == value.hash_lock
            and self.hash_locked_signer == value.hash_locked_signer
            and self.time_lock == value.time_lock
            and self.time_locked_signer == value.time_locked_signer
        )
    
    @property
    def size(self) -> int:
        n = 1
        n += self.hash_lock.size + self.hash_locked_signer.size
        n += 4 + self.time_locked_signer.size
        return n
    
    @property
    def keys(self) -> list[SignerKey]:
        if (
            isinstance(self.hash_locked_signer, SignerHash)
            and isinstance(self.time_locked_signer, SignerHash)
        ):
            raise ValueError('SignerLocked does not have keys.')
        keys: list[SignerKey] = []
        if isinstance(self.hash_locked_signer, SignerList):
            keys.extend(self.hash_locked_signer.keys)
        if isinstance(self.time_locked_signer, SignerList):
            keys.extend(self.time_locked_signer.keys)
        unique: set[bytes] = set()
        output: list[SignerKey] = []
        for k in keys:
            if k.value not in unique:
                unique.add(k.value)
                output.append(k)
        return output

    async def hash(self) -> SignerHash:
        match self.hash_locked_signer:
            case SignerHash():
                hash_lock = self.hash_lock.value
                hash_locked_signer = self.hash_locked_signer.value
            case SignerList():
                hash_lock = await keccak_800(self.hash_lock.value)
                hash_locked_signer = (await self.hash_locked_signer.hash()).value
            case _:
                raise ValueError('Invalid hash_locked_signer type.')
        time_lock = pack('<I', self.time_lock)
        match self.time_locked_signer:
            case SignerHash():
                time_locked_signer = self.time_locked_signer.value
            case SignerList():
                time_locked_signer = (await self.time_locked_signer.hash()).value
            case _:
                raise ValueError('Invalid time_locked_signer type.')
        preimage = b''.join([
            hash_lock, hash_locked_signer,
            time_lock, time_locked_signer
        ])
        return SignerHash(await keccak_1600(preimage))

    def encode(self) -> bytes:
        prefix = 0
        hash_lock = self.hash_lock.encode()
        match self.hash_locked_signer:
            case SignerHash():
                prefix = self.SIGNER_HASH
            case SignerList():
                prefix = self.SIGNER_LIST
            case _:
                raise ValueError('Invalid hash_locked_signer type.')
        hash_locked_signer = self.hash_locked_signer.encode()
        time_lock = pack('<I', self.time_lock)
        match self.time_locked_signer:
            case SignerHash():
                prefix |= self.SIGNER_HASH << 1
            case SignerList():
                prefix |= self.SIGNER_LIST << 1
            case _:
                raise ValueError('Invalid time_locked_signer type.')
        time_locked_signer = self.time_locked_signer.encode()
        return b''.join([
            pack('<B', prefix),
            hash_lock, hash_locked_signer,
            time_lock, time_locked_signer
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> SignerLocked:
        try:
            prefix = view[0]
            hash_lock = Nonce_32.decode(view[1:])
            offset = 1 + hash_lock.size
            match prefix & 1:
                case cls.SIGNER_HASH:
                    hash_locked_signer = SignerHash.decode(view[offset:])
                case cls.SIGNER_LIST:
                    hash_locked_signer = SignerList.decode(view[offset:])
                case _:
                    raise ValueError('Invalid hash_locked_signer type.')
            prefix >>= 1
            offset += hash_locked_signer.size
            time_lock = unpack_from('<I', view, offset)[0]
            offset += 4
            match prefix & 1:
                case cls.SIGNER_HASH:
                    time_locked_signer = SignerHash.decode(view[offset:])
                case cls.SIGNER_LIST:
                    time_locked_signer = SignerList.decode(view[offset:])
                case _:
                    raise ValueError('Invalid time_locked_signer type.')
            return cls(
                hash_lock, hash_locked_signer,
                time_lock, time_locked_signer,
                _validate=False
            )
        except (IndexError, StructError):
            raise ValueError('Invalid view size.')


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
        return (
            super().__eq__(value)
            and self.block == value.block
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
        return (
            super().__eq__(value)
            and self.tx_hash == value.tx_hash
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

    def __eq__(self, value: TransactionElement) -> bool:
        return (
            super().__eq__(value)
            and self.memo == value.memo
        )

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
    SIGNER_LOCKED = 2
    SIGNER_NONE = 3

    def __init__(self,
        signer: SignerKey | SignerList | SignerLocked | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if (
                signer is not None
                and not isinstance(signer, (SignerKey, SignerList, SignerLocked))
            ):
                raise ValueError('Invalid signer.')
        super().__init__(memo, _validate=_validate)
        self.signer = signer

    def __eq__(self, value: TransactionInput) -> bool:
        return (
            super().__eq__(value)
            and self.signer == value.signer
        )

    @property
    def keys(self) -> list[SignerKey]:
        match self.signer:
            case SignerKey():
                return [self.signer]
            case SignerList() | SignerLocked():
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
        cls, signer: SignerKey | SignerList | SignerLocked | None
    ) -> tuple[Literal[0, 1, 2, 3], bytes]:
        match signer:
            case SignerKey():
                prefix = cls.SIGNER_KEY
            case SignerList():
                prefix = cls.SIGNER_LIST
            case SignerLocked():
                prefix = cls.SIGNER_LOCKED
            case None:
                prefix = cls.SIGNER_NONE
            case _:
                raise ValueError('Invalid signer.')
        return prefix, (signer.encode() if signer else b'')

    @classmethod
    def _decode_optional_signer(
        cls, prefix: Literal[0, 1, 2, 3], view: bytes | bytearray | memoryview
    ) -> SignerKey | SignerList | SignerLocked | None:
        match prefix:
            case cls.SIGNER_KEY:
                return SignerKey.decode(view)
            case cls.SIGNER_LIST:
                return SignerList.decode(view)
            case cls.SIGNER_LOCKED:
                return SignerLocked.decode(view)
            case cls.SIGNER_NONE:
                return
            case _:
                raise ValueError('Invalid signer.')


class UTXOSpend(TransactionInput):

    UTXO_REF_BY_INDEX = 0
    UTXO_REF_BY_HASH = 1

    def __init__(self,
        utxo: UTXORefByIndex | UTXORefByHash,
        time_lock: int | None = None,
        signer: SignerKey | SignerList | SignerLocked | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(utxo, (UTXORefByIndex, UTXORefByHash)):
                raise ValueError('Invalid UTXO reference.')
            if time_lock is not None:
                if (
                    not isinstance(time_lock, int)
                    or time_lock <= 0
                    or time_lock >= 0x1_0000_0000
                ):
                    raise ValueError('Invalid time lock.')
        super().__init__(signer, memo, _validate=_validate)
        self.utxo = utxo
        self.time_lock = time_lock

    def __eq__(self, value: UTXOSpend) -> bool:
        return (
            super().__eq__(value)
            and self.utxo == value.utxo
            and self.time_lock == value.time_lock
        )

    @property
    def size(self) -> int:
        n = 1
        n += self.utxo.size
        n += 4 if self.time_lock is not None else 0
        n += (self.signer.size if self.signer else 0)
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
        shift = 1
        time_lock = b'' if self.time_lock is None else pack('<I', self.time_lock)
        prefix |= (1 << shift) if time_lock else 0
        shift += 1
        _prefix, signer = self._encode_optional_signer(self.signer)
        prefix |= _prefix << shift
        shift += 2
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << shift
        shift += 2
        return b''.join([
            pack('<B', prefix), self.utxo.encode(), time_lock,
            signer, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXOSpend:
        try:
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
            time_lock = unpack_from('<I', view, offset)[0] if prefix & 1 else None
            if time_lock == 0:
                raise ValueError('Invalid time lock.')
            prefix >>= 1
            offset += 4 if time_lock is not None else 0
            signer = cls._decode_optional_signer(prefix & 3, view[offset:])
            prefix >>= 2
            offset += signer.size if signer else 0
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(utxo, time_lock, signer, memo, _validate=False)
        except (IndexError, StructError):
            raise ValueError('Invalid view size.')


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
            if signer is not None:
                if not isinstance(signer, (SignerKey, SignerList)):
                    raise ValueError('Invalid signer.')
        super().__init__(signer, memo, _validate=_validate)
        self.block = block

    def __eq__(self, value: BlockSpend) -> bool:
        return (
            super().__eq__(value)
            and self.block == value.block
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


class Nonce_16(Bytes):

    SIZE = 16


class ExecutiveDefinition(TransactionInput):

    def __init__(self,
        executive: Nonce_16,
        signer: SignerKey | SignerList,
        new_signer: SignerHash | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(executive, Nonce_16):
                raise ValueError('Invalid executive identifier.')
            if not isinstance(signer, (SignerKey, SignerList)):
                raise ValueError('Invalid signer.')
            if (
                new_signer is not None
                and not isinstance(new_signer, SignerHash)
            ):
                raise ValueError('Invalid new_signer.')
        super().__init__(signer, memo, _validate=_validate)
        self.executive = executive
        self.new_signer = new_signer

    def __eq__(self, value: ExecutiveDefinition) -> bool:
        return (
            super().__eq__(value)
            and self.executive == value.executive
            and self.new_signer == value.new_signer
        )

    @property
    def size(self) -> int:
        n = 1           # prefix[1]
        n += self.executive.size
        n += self.signer.size if self.signer else 0
        n += self.new_signer.size if self.new_signer else 0
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n
    
    def encode(self) -> bytes:
        executive = self.executive.encode()
        prefix, signer = self._encode_signer(self.signer)
        shift = 1
        new_signer = self.new_signer.encode() if self.new_signer else b''
        prefix |= (1 << shift) if new_signer else 0
        shift += 1
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << shift
        return b''.join([
            pack('<B', prefix), executive, signer, new_signer, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveDefinition:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        executive = Nonce_16.decode(view[1:])
        offset = 1 + executive.size
        signer = cls._decode_signer(prefix & 1, view[offset:])
        prefix >>= 1
        offset += signer.size
        new_signer = SignerHash.decode(view[offset:]) if prefix & 1 else None
        prefix >>= 1
        offset += new_signer.size if new_signer else 0
        memo = cls._decode_memo(prefix & 3, view[offset:])
        return cls(executive, signer, new_signer, memo, _validate=False)


class AssetDefinition(TransactionInput):

    def __init__(self,
        asset: Nonce_16,
        signer: SignerKey | SignerList,
        new_signer: SignerHash | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        lock: bool = False,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(asset, Nonce_16):
                raise ValueError('Invalid asset identifier.')
            if not isinstance(signer, (SignerKey, SignerList)):
                raise ValueError('Invalid signer.')
            if (
                new_signer is not None
                and not isinstance(new_signer, SignerHash)
            ):
                raise ValueError('Invalid new_signer.')
            if not isinstance(lock, bool):
                raise ValueError('Invalid lock.')
        super().__init__(signer, memo, _validate=_validate)
        self.asset = asset
        self.new_signer = new_signer
        self.lock = lock

    def __eq__(self, value: AssetDefinition) -> bool:
        return (
            super().__eq__(value)
            and self.asset == value.asset
            and self.new_signer == value.new_signer
            and self.lock == value.lock
        )

    @property
    def size(self) -> int:
        n = 1
        n += self.asset.size
        n += self.signer.size
        n += self.new_signer.size if self.new_signer else 0
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n
    
    def encode(self) -> bytes:
        asset = self.asset.encode()
        prefix, signer = self._encode_signer(self.signer)
        shift = 1
        new_signer = self.new_signer.encode() if self.new_signer else b''
        prefix |= (1 << shift) if new_signer else 0
        shift += 1
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << shift
        shift += 2
        prefix |= int(self.lock) << shift
        return b''.join([
            pack('<B', prefix), asset, signer, new_signer, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> AssetDefinition:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        asset = Nonce_16.decode(view[1:])
        offset = 1 + asset.size
        signer = cls._decode_signer(prefix & 1, view[offset:])
        prefix >>= 1
        offset += signer.size
        new_signer = SignerHash.decode(view[offset:]) if prefix & 1 else None
        prefix >>= 1
        offset += new_signer.size if new_signer else 0
        memo = cls._decode_memo(prefix & 3, view[offset:])
        prefix >>= 2
        lock = bool(prefix & 1)
        return cls(asset, signer, new_signer, memo, lock, _validate=False)


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
                    or (units.bit_length() + 7) >> 3 > MAX_INT_BYTES
                )
            ):
                raise ValueError('Invalid units.')
        super().__init__(memo, _validate)
        self._units = units

    def __eq__(self, value: TransactionOutput) -> bool:
        return (
            super().__eq__(value)
            and self.units == value.units
        )

    @property
    def units(self) -> int | None:
        return self._units if self._units else None
    
    @units.setter
    def units(self, value: int | None) -> int | None:
        self._units = value if value else None
        return self._units


class ArkaUTXO(TransactionOutput):

    SIGNER_KEY = 0
    SIGNER_HASH = 1
    SIGNER_NONE = 2

    def __init__(self,
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
                    or (block_reward.bit_length() + 7) >> 3 > MAX_INT_BYTES
                )
            ):
                raise ValueError('Invalid block_reward.')
            if (
                exec_fund is not None
                and (
                    not isinstance(exec_fund, int)
                    or exec_fund < 0
                    or (exec_fund.bit_length() + 7) >> 3 > MAX_INT_BYTES
                )
            ):
                raise ValueError('Invalid exec_fund.')
            if (
                utxo_fee is not None
                and (
                    not isinstance(utxo_fee, int)
                    or utxo_fee < 0
                    or (utxo_fee.bit_length() + 7) >> 3 > MAX_INT_BYTES
                )
            ):
                raise ValueError('Invalid utxo_fee.')
            if (
                data_fee is not None
                and (
                    not isinstance(data_fee, int)
                    or data_fee < 0
                    or (data_fee.bit_length() + 7) >> 3 > MAX_INT_BYTES
                )
            ):
                raise ValueError('Invalid data_fee.')
        super().__init__(units, memo, _validate=_validate)
        self.signer = signer
        self.block_reward = block_reward
        self.exec_fund = exec_fund
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee

    def __eq__(self, value: ArkaUTXO) -> bool:
        return (
            super().__eq__(value)
            and self.signer == value.signer
            and self.block_reward == value.block_reward
            and self.exec_fund == value.exec_fund
            and self.utxo_fee == value.utxo_fee
            and self.data_fee == value.data_fee
        )

    @property
    def size(self) -> int:
        n = 3
        match self.signer:
            case None:
                pass
            case SignerHash() | SignerKey():
                n += self.signer.size
            case _:
                raise ValueError('Invalid signer.')
        if self.units:
            n += (self.units.bit_length() + 7) >> 3
        if self.block_reward:
            n += ((self.block_reward.bit_length() + 7) >> 3)
        else:
            n += 0 if self.block_reward is None else 1
        if self.exec_fund:
            n += ((self.exec_fund.bit_length() + 7) >> 3)
        else:
            n += 0 if self.exec_fund is None else 1
        if self.utxo_fee:
            n += ((self.utxo_fee.bit_length() + 7) >> 3)
        else:
            n += 0 if self.utxo_fee is None else 1
        if self.data_fee:
            n += ((self.data_fee.bit_length() + 7) >> 3)
        else:
            n += 0 if self.data_fee is None else 1
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo or b'')
        return n

    def encode(self) -> bytes:
        prefix = 0
        match self.signer:
            case SignerKey():
                signer = self.signer.encode()
                prefix |= self.SIGNER_KEY
            case SignerHash():
                signer = self.signer.encode()
                prefix |= self.SIGNER_HASH
            case None:
                signer = b''
                prefix |= self.SIGNER_NONE
            case _:
                raise ValueError('Invalid signer.')
        shift = 2
        units = _encode_optional_int(self.units)
        prefix |= len(units) << shift
        shift += 4
        reward = _encode_optional_int(self.block_reward)
        prefix |= len(reward) << shift
        shift += 4
        fund = _encode_optional_int(self.exec_fund)
        prefix |= len(fund) << shift
        shift += 4
        utxo_fee = _encode_optional_int(self.utxo_fee)
        prefix |= len(utxo_fee) << shift
        shift += 4
        data_fee = _encode_optional_int(self.data_fee)
        prefix |= len(data_fee) << shift
        shift += 4
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << shift
        shift += 2
        prefix = prefix.to_bytes(3, 'little')
        return b''.join([
            prefix, signer, units, reward, fund,
            utxo_fee, data_fee, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ArkaUTXO:
        try:
            if len(view) < 3:
                raise IndexError()
            prefix = int.from_bytes(view[:3], 'little')
            offset = 3
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
            nbytes = prefix & 15
            units = _decode_optional_int(nbytes, view[offset:])
            if units == 0:
                raise ValueError('Invalid units.')
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            reward = _decode_optional_int(nbytes, view[offset:])
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            fund = _decode_optional_int(nbytes, view[offset:])
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            utxo_fee = _decode_optional_int(nbytes, view[offset:])
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            data_fee = _decode_optional_int(nbytes, view[offset:])
            offset += nbytes
            prefix >>= 4
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(
                signer, units, reward, fund, utxo_fee,
                data_fee, memo, _validate=False
            )
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class AssetUTXO(TransactionOutput):

    SIGNER_KEY = 0
    SIGNER_HASH = 1
    SIGNER_NONE = 2

    def __init__(self,
        asset: Nonce_16,
        signer: SignerKey | SignerHash | None = None,
        units: int | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(asset, Nonce_16):
                raise ValueError('Invalid asset identifier.')
            if (
                signer is not None
                and not isinstance(signer, (SignerKey, SignerHash))
            ):
                raise ValueError('Invalid signer.')
        super().__init__(units, memo, _validate=_validate)
        self.asset = asset
        self.signer = signer
    
    def __eq__(self, value: AssetUTXO) -> bool:
        return (
            super().__eq__(value)
            and self.asset == value.asset
            and self.signer == value.signer
        )

    @property
    def size(self) -> int:
        n = 1
        n += self.asset.size
        n += self.signer.size if self.signer else 0
        if self.units:
            n += (self.units.bit_length() + 7) >> 3
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo or b'')
        return n

    def encode(self) -> bytes:
        prefix = 0
        asset = self.asset.encode()
        match self.signer:
            case SignerKey():
                signer = self.signer.encode()
                prefix |= self.SIGNER_KEY
            case SignerHash():
                signer = self.signer.encode()
                prefix |= self.SIGNER_HASH
            case None:
                signer = b''
                prefix |= self.SIGNER_NONE
            case _:
                raise ValueError('Invalid signer.')
        shift = 2
        units = _encode_optional_int(self.units)
        prefix |= len(units) << shift
        shift += 4
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << shift
        shift += 2
        return b''.join([
            pack('<B', prefix), asset, signer, units, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> AssetUTXO:
        try:
            prefix = view[0]
            offset = 1
            asset = Nonce_16.decode(view[offset:])
            offset += asset.size
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
            nbytes = prefix & 15
            units = _decode_optional_int(nbytes, view[offset:])
            if units == 0:
                raise ValueError('Invalid units.')
            offset += nbytes
            prefix >>= 4
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(asset, signer, units, memo, _validate=False)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class ExecutiveVote(TransactionOutput):
    
    def __init__(self,
        executive: Nonce_16,
        promote: bool = True,
        units: int | None = None,
        memo: bytes | bytearray | memoryview | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(executive, Nonce_16):
                raise ValueError('Invalid executive identifier.')
            if not isinstance(promote, bool):
                raise ValueError('Invalid promote flag.')
        super().__init__(units, memo, _validate=_validate)
        self.executive = executive
        self.promote = promote

    def __eq__(self, value: ExecutiveVote) -> bool:
        return (
            super().__eq__(value)
            and self.executive == value.executive
            and self.promote == value.promote
        )

    @property
    def size(self) -> int:
        n = 1       # prefix[1]
        n += self.executive.size
        n += ((self.units.bit_length() + 7) >> 3) if self.units else 0
        mlen = self._encode_mlen(self.memo)
        if mlen:
            n += len(mlen) + len(self.memo)
        return n

    def encode(self) -> bytes:
        prefix = 0
        executive = self.executive.encode()
        prefix |= 1 if self.promote else 0
        units = _encode_optional_int(self.units)
        prefix |= len(units) << 1
        mlen = self._encode_mlen(self.memo)
        prefix |= len(mlen) << 5
        return b''.join([
            pack('<B', prefix), executive, units, mlen, (self.memo or b'')
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveVote:
        try:
            prefix = view[0]
            offset = 1
            executive = Nonce_16.decode(view[offset:])
            offset += executive.size
            promote = bool(prefix & 1)
            prefix >>= 1
            nbytes = prefix & 15
            units = _decode_optional_int(nbytes, view[offset:])
            if units == 0:
                raise ValueError('Invalid units.')
            offset += nbytes
            prefix >>= 4
            memo = cls._decode_memo(prefix & 3, view[offset:])
            return cls(executive, promote, units, memo, _validate=False)
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

    ARKA_UTXO = 0
    ASSET_UTXO = 1
    EXECUTIVE_VOTE = 2

    def __init__(self,
        inputs: list[
            PublisherSpend | ExecutiveSpend | UTXOSpend
            | AssetDefinition | ExecutiveDefinition
        ],
        outputs: list[ArkaUTXO | AssetUTXO | ExecutiveVote] = [],
        signatures: list[Signature] = [],
        digest: TransactionHash | None = None,
        _validate: bool = True
    ):
        if _validate:
            if not all(
                isinstance(x, (
                    PublisherSpend, ExecutiveSpend, UTXOSpend,
                    AssetDefinition, ExecutiveDefinition
                ))
                for x in inputs
            ):
                raise ValueError('Invalid inputs list.')
            if not all(
                isinstance(x, (ArkaUTXO, AssetUTXO, ExecutiveVote))
                for x in outputs
            ):
                raise ValueError('Invalid outputs list.')
            if not all(
                isinstance(x, Signature)
                for x in signatures
            ):
                raise ValueError('Invalid signatures list.')
            if (
                digest is not None
                and not isinstance(digest, TransactionHash)
            ):
                raise ValueError('Invalid digest.')
        self.inputs = inputs
        self.outputs = outputs
        self.signatures = signatures
        self.digest = digest
        self._size: int | None = None

    def __eq__(self, value: Transaction) -> bool:
        return (
            super().__eq__(value)
            and self.inputs == value.inputs
            and self.outputs == value.outputs
            and self.signatures == value.signatures
        )

    @property
    def keys(self) -> list[SignerKey]:
        keys: list[SignerKey] = [k for x in self.inputs for k in x.keys]
        unique: set[bytes] = set()
        output: list[SignerKey] = []
        for k in keys:
            if k.value not in unique:
                unique.add(k.value)
                output.append(k)
        return output

    @property
    def size(self) -> int:
        if self._size is not None:
            return self._size
        n = 6
        n += (len(self.inputs) + 1) >> 1
        n += (len(self.outputs) + 3) >> 2
        n += sum(x.size for x in self.inputs)
        n += sum(x.size for x in self.outputs)
        n += Signature.SIZE * len(self.signatures)
        return n

    async def hash(self) -> TransactionHash:
        if self.digest is not None:
            return self.digest
        preimage = self.encode(include_signatures=False)
        return TransactionHash(await keccak_1600(preimage))

    def encode(self, include_signatures: bool = True) -> bytes:
        if include_signatures:
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
                case AssetDefinition():
                    in_types[i >> 1] |= self.ASSET_SPAWN << ((i & 1) << 2)
                case ExecutiveDefinition():
                    in_types[i >> 1] |= self.EXECUTIVE_SPAWN << ((i & 1) << 2)
                case _:
                    raise ValueError('Invalid input type.')
        inputs = [x.encode() for x in self.inputs]
        out_types = bytearray((len(self.outputs) + 3) >> 2)
        for i, x in enumerate(self.outputs):
            match x:
                case ArkaUTXO():
                    out_types[i >> 2] |= self.ARKA_UTXO << ((i & 3) << 1)
                case AssetUTXO():
                    out_types[i >> 2] |= self.ASSET_UTXO << ((i & 3) << 1)
                case ExecutiveVote():
                    out_types[i >> 2] |= self.EXECUTIVE_VOTE << ((i & 3) << 1)
                case _:
                    raise ValueError('Invalid output type.')
        outputs = [x.encode() for x in self.outputs]
        return b''.join(
            [prefix, in_types, out_types] + inputs + outputs + signatures
        )

    @classmethod
    def decode(cls,
        view: bytes | bytearray | memoryview,
        digest: TransactionHash | None = None
    ) -> Transaction:
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
            out_types_len = (noutputs + 3) >> 2
            if len(view) < offset + out_types_len:
                raise IndexError()
            out_types = view[offset:offset + out_types_len]
            offset += out_types_len
            # Decode inputs
            inputs: list[
                PublisherSpend | ExecutiveSpend | UTXOSpend | AssetDefinition | ExecutiveDefinition
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
                        x = AssetDefinition.decode(view[offset:])
                    case cls.EXECUTIVE_SPAWN:
                        x = ExecutiveDefinition.decode(view[offset:])
                    case _:
                        raise ValueError('Invalid Transaction input type.')
                inputs.append(x)
                offset += x.size
            # Decode outputs
            outputs: list[ArkaUTXO | AssetUTXO | ExecutiveVote] = []
            for i in range(noutputs):
                match (out_types[i >> 2] >> ((i & 3) << 1)) & 3:
                    case cls.ARKA_UTXO:
                        x = ArkaUTXO.decode(view[offset:])
                    case cls.ASSET_UTXO:
                        x = AssetUTXO.decode(view[offset:])
                    case cls.EXECUTIVE_VOTE:
                        x = ExecutiveVote.decode(view[offset:])
                    case _:
                        raise ValueError('Invalid Transaction output type.')
                outputs.append(x)
                offset += x.size
            # Decode signatures
            signatures: list[Signature] = []
            for i in range(nsignatures):
                x = Signature.decode(view[offset:])
                signatures.append(x)
                offset += x.size
            # Return Transaction
            return cls(inputs, outputs, signatures, digest, _validate=False)
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')


class BlockHeaderHash(Bytes):

    SIZE = 32


class BlockHash(Bytes):

    SIZE = 32


class TransactionListHash(Bytes):

    SIZE = 32


class Nonce_32(Bytes):

    SIZE = 32


class Parameters(AbstractElement):

    TARGET_MAX = 255 * 2 ** 255

    def __init__(self,
        target: int,            # mint difficulty x * 2 ** y
        block_reward: int,      # units generated each block for publishers
        exec_fund: int,         # units generated each epoch for executives
        utxo_fee: int,          # decay of UTXOs per block as a fraction z / 2**64
        data_fee: int,          # units to destroy per byte in payment
        executive: Nonce_16,    # identifier of elected executive
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
                or (block_reward.bit_length() + 7) >> 3 > MAX_INT_BYTES
            ):
                raise ValueError('Invalid block_reward.')
            if (
                not isinstance(exec_fund, int)
                or exec_fund < 0
                or (exec_fund.bit_length() + 7) >> 3 > MAX_INT_BYTES
            ):
                raise ValueError('Invalid exec_fund.')
            if (
                not isinstance(utxo_fee, int)
                or utxo_fee < 0
                or (utxo_fee.bit_length() + 7) >> 3 > MAX_INT_BYTES
            ):
                raise ValueError('Invalid utxo_fee.')
            if (
                not isinstance(data_fee, int)
                or data_fee < 0
                or (data_fee.bit_length() + 7) >> 3 > MAX_INT_BYTES
            ):
                raise ValueError('Invalid data_fee.')
            if not isinstance(executive, Nonce_16):
                raise ValueError('Invalid executive identifier.')
        self.target = target
        self.block_reward = block_reward
        self.exec_fund = exec_fund
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee
        self.executive = executive

    def __eq__(self, value: Parameters) -> bool:
        return (
            super().__eq__(value)
            and self.encode_target() == value.encode_target()
            and self.block_reward == value.block_reward
            and self.exec_fund == value.exec_fund
            and self.utxo_fee == value.utxo_fee
            and self.data_fee == value.data_fee
            and self.executive == value.executive
        )

    @property
    def size(self) -> int:
        n = 4       # prefix[2] | target[2] 
        n += (self.block_reward.bit_length() + 7) >> 3
        n += (self.exec_fund.bit_length() + 7) >> 3
        n += (self.utxo_fee.bit_length() + 7) >> 3
        n += (self.data_fee.bit_length() + 7) >> 3
        n += self.executive.size
        return n

    def encode_target(self) -> bytes:
        n = max(0, self.target.bit_length() - 8)
        x = self.target >> n
        return bytes([x, n])

    def encode(self) -> bytes:
        prefix = 0
        target = self.encode_target()
        reward = _encode_optional_int(self.block_reward or None)
        prefix |= len(reward)
        shift = 4
        fund = _encode_optional_int(self.exec_fund or None)
        prefix |= len(fund) << shift
        shift += 4
        utxo_fee = _encode_optional_int(self.utxo_fee or None)
        prefix |= len(utxo_fee) << shift
        shift += 4
        data_fee = _encode_optional_int(self.data_fee or None)
        prefix |= len(data_fee) << shift
        shift += 4
        executive = self.executive.encode()
        prefix = prefix.to_bytes(2, 'little')
        return b''.join([prefix, target, reward, fund, utxo_fee, data_fee, executive])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Parameters:
        try:
            prefix = unpack_from('<H', view, 0)[0]
            target = view[2] * (1 << view[3])
            offset = 4
            nbytes = prefix & 15
            reward = _decode_optional_int(nbytes, view[offset:])
            if reward == 0:
                raise ValueError('Invalid block_reward.')
            reward = reward or 0
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            fund = _decode_optional_int(nbytes, view[offset:])
            if fund == 0:
                raise ValueError('Invalid exec_fund.')
            fund = fund or 0
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            utxo_fee = _decode_optional_int(nbytes, view[offset:])
            if utxo_fee == 0:
                raise ValueError('Invalid utxo_fee.')
            utxo_fee = utxo_fee or 0
            offset += nbytes
            prefix >>= 4
            nbytes = prefix & 15
            data_fee = _decode_optional_int(nbytes, view[offset:])
            if data_fee == 0:
                raise ValueError('Invalid data_fee.')
            data_fee = data_fee or 0
            offset += nbytes
            prefix >>= 4
            executive = Nonce_16.decode(view[offset:])
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')
        return cls(target, reward, fund, utxo_fee, data_fee, executive, _validate=False)


class BlockHeader(AbstractElement):

    SIGNER_KEY = 0
    SIGNER_HASH = 1

    def __init__(self,
        id: int, timestamp: int, prev_block: BlockHash,
        publisher: SignerKey | SignerHash, ntxs: int | None = None,
        root_hash: TransactionListHash | None = None,
        parameters: Parameters | None = None, nonce: Nonce_32 | None = None,
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
                or ntxs >= 0x1_0000_0000
            ):
                raise ValueError('Invalid ntxs.')
            if root_hash is None:
                if ntxs is not None:
                    raise ValueError('Invalid root_hash.')
            elif not isinstance(root_hash, TransactionListHash):
                raise ValueError('Invalid root_hash.')
            if parameters is not None and not isinstance(parameters, Parameters):
                raise ValueError('Invalid parameters.')
            if nonce is not None and not isinstance(nonce, Nonce_32):
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
        return (
            super().__eq__(value)
            and self.id == value.id
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
            nonce = Nonce_32.decode(view[offset:]) if prefix & 8 else None
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
        return (
            super().__eq__(value)
            and self.header == value.header
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

    @staticmethod
    async def _decode_transaction(view: bytes | bytearray | memoryview) -> Transaction:
        tx = Transaction.decode(view)
        if tx.size != len(view):
            raise ValueError('Invalid transaction size.')
        tx.digest = await tx.hash()
        tx._size = len(view)
        return tx

    @classmethod
    async def decode(cls, view: bytes | bytearray | memoryview) -> Block:
        try:
            header = BlockHeader.decode(view)
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
                transactions: list[Transaction] = await gather(*[
                    cls._decode_transaction(view[offsets[i]:offsets[i + 1]])
                    for i in range(header.ntxs)
                ])
            else:
                transactions = []
        except (IndexError, StructError) as e:
            raise ValueError('Invalid view size.')
        return cls(
            header, transactions, _validate=False
        )


class BlockSummary(AbstractElement):

    def __init__(self,
        header: BlockHeader,
        ids: list[int] = [],
        _validate: bool = True
    ):
        if _validate:
            if not isinstance(header, BlockHeader):
                raise ValueError('Invalid block header.')
            if not isinstance(ids, list) or not all(
                isinstance(x, int) for x in ids
            ):
                raise ValueError('Invalid ids list.')
            if (header.ntxs or 0) != len(ids) or len(ids) > 0x1_0000_0000:
                raise ValueError('Invalid ids list.')
        self.header = header
        self.ids = ids

    def __eq__(self, value: BlockSummary) -> bool:
        return (
            super().__eq__(value)
            and self.header == value.header
            and self.ids == value.ids
        )
    
    @property
    def size(self) -> int:
        n = self.header.size
        if not self.header.ntxs:
            return n
        n += 1  # prefix[1]
        base = min(self.ids)
        n += (base.bit_length() + 7) >> 3
        if self.header.ntxs > 1:
            bound = max(self.ids) - base
            n += ((bound.bit_length() + 7) >> 3) * self.header.ntxs
        return n
    
    def encode(self) -> bytes:
        header = self.header.encode()
        if not self.header.ntxs:
            return header
        base = min(self.ids)
        prefix = (base + 7) >> 3
        if prefix > MAX_INT_BYTES:
            raise ValueError('Invalid ids list.')
        if self.header.ntxs == 1:
            base = base.to_bytes(prefix, 'little')
            prefix = prefix.to_bytes(1, 'little')
            return b''.join([header, prefix, base])
        # self.header.ntxs > 1
        bound = max(self.ids) - base
        nbytes = (bound.bit_length() + 7) >> 3
        if nbytes > MAX_INT_BYTES:
            raise ValueError('Invalid ids list.')
        prefix |= nbytes << 4
        ids = [(x - base).to_bytes(nbytes, 'little') for x in self.ids]
        base = base.to_bytes(prefix & 15, 'little')
        prefix = prefix.to_bytes(1, 'little')
        return b''.join([header, prefix, base] + ids)

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> BlockSummary:
        try:
            header = BlockHeader.decode(view)
            if not header.ntxs:
                return cls(header, [], _validate=False)
            offset = header.size
            prefix = view[offset]
            offset += 1
            end = offset + (prefix & 15)
            if len(view) < end:
                raise IndexError()
            base = int.from_bytes(view[offset:end], 'little')
            if header.ntxs == 1:
                return cls(header, [base], _validate=False)
            offset = end
            nbytes = prefix >> 4
            end = offset + nbytes * header.ntxs
            if len(view) < end:
                raise IndexError()
            ids: list[int] = [
                int.from_bytes(view[i:i + nbytes], 'little') + base
                for i in range(offset, end, nbytes)
            ]
            return cls(header, ids, _validate=False)
        except IndexError as e:
            raise ValueError('Invalid view size.')
