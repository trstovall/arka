
from __future__ import annotations

from struct import pack, unpack_from, Struct, error as StructError
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

    @property
    def signers(self) -> list[bytes]:
        match self.signer:
            case SignerKey():
                return [self.signer.key]
            case SignerList():
                return self.signer.keys
            case _:
                raise ValueError('Invalid signer.')


class PublisherSpend(AbstractTXInput):

    SIGNER_NONE = 0
    SIGNER_KEY = 1
    SIGNER_LIST = 2

    def __init__(self,
        block: int,
        signer: SignerKey | SignerList | None = None
    ):
        self.block, self.signer = block, signer
    
    def __eq__(self, value: PublisherSpend) -> bool:
        if not isinstance(value, PublisherSpend):
            return NotImplemented
        return self.block == value.block and self.signer == value.signer
    
    @property
    def size(self) -> int:
        return 8 + (self.signer.size if self.signer else 0)
    
    def encode(self) -> bytes:
        prefix = 0
        match self.signer:
            case None:
                prefix |= self.SIGNER_NONE
            case SignerKey():
                prefix |= self.SIGNER_KEY
            case SignerList():
                prefix |= self.SIGNER_LIST
            case _:
                raise ValueError('Invalid signer.')
        return b''.join([
            pack('<BQ', prefix, self.block),
            self.signer.encode() if self.signer else b''
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> PublisherSpend:
        if len(view) < 9:
            raise ValueError('Invalid size when decoding.')
        prefix, block = unpack_from('<BQ', view, 0)
        match prefix:
            case cls.SIGNER_NONE:
                signer = None
            case cls.SIGNER_KEY:
                signer = SignerKey.decode(view[9:])
            case cls.SIGNER_LIST:
                signer = SignerList.decode(view[9:])
            case _:
                raise ValueError('Invalid signer.')
        return cls(block, signer)


class ExecutiveSpend(PublisherSpend):

    def __eq__(self, value: ExecutiveSpend) -> bool:
        if not isinstance(value, ExecutiveSpend):
            return NotImplemented
        if self.block == value.block and self.signer == value.signer:
            return True
        return False
    
    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> ExecutiveSpend:
        x = PublisherSpend.decode(view)
        return cls(x.block, x.signer)


class UTXOSpend(AbstractTXInput):

    UTXO_REF_BY_INDEX = 0
    UTXO_REF_BY_HASH = 1

    SIGNER_NONE = 0
    SIGNER_KEY = 1
    SIGNER_LIST = 2

    def __init__(self,
        utxo: UTXORefByIndex | UTXORefByHash,
        signer: SignerKey | SignerList | None = None
    ):
        self.utxo, self.signer = utxo, signer

    def __eq__(self, value: UTXOSpend) -> bool:
        if not isinstance(value, UTXOSpend):
            return NotImplemented
        return (
            self.utxo == value.utxo
            and self.signer == value.signer
        )

    @property
    def size(self) -> int:
        return 1 + self.utxo.size + (self.signer.size if self.signer else 0)

    def encode(self) -> bytes:
        prefix = 0
        match self.utxo:
            case UTXORefByIndex():
                prefix |= self.UTXO_REF_BY_INDEX
            case UTXORefByHash():
                prefix |= self.UTXO_REF_BY_HASH
            case _:
                raise ValueError('Invalid UTXO reference.')
        match self.signer:
            case None:
                prefix |= self.SIGNER_NONE << 1
            case SignerKey():
                prefix |= self.SIGNER_KEY << 1
            case SignerList():
                prefix |= self.SIGNER_LIST << 1
            case _:
                raise ValueError('Invalid signer.')
        return b''.join([
            pack('<B', prefix),
            self.utxo.encode(),
            self.signer.encode() if self.signer else b''
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
        match prefix >> 1:
            case cls.SIGNER_NONE:
                signer = None
            case cls.SIGNER_KEY:
                signer = SignerKey.decode(view[1 + utxo.size:])
            case cls.SIGNER_LIST:
                signer = SignerList.decode(view[1 + utxo.size:])
            case _:
                raise ValueError('Invalid signer.')
        return cls(utxo, signer)


class AssetSpawn(AbstractTXInput):

    SIGNER_KEY = 0
    SIGNER_LIST = 1

    def __init__(self, signer: SignerKey | SignerList):
        self.signer = signer

    def __eq__(self, value: AssetSpawn) -> bool:
        if not isinstance(value, AssetSpawn):
            return NotImplemented
        return self.signer == value.signer

    @property
    def size(self) -> int:
        return 1 + self.signer.size
    
    def encode(self) -> bytes:
        prefix = 0
        match self.signer:
            case SignerKey():
                prefix |= self.SIGNER_KEY
            case SignerList():
                prefix |= self.SIGNER_LIST
            case _:
                raise ValueError('Invalid signer.')
        return b''.join([
            pack('<B', prefix), self.signer.encode()
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> AssetSpawn:
        if not view:
            raise ValueError('Invalid size when decoding.')
        prefix = view[0]
        match prefix:
            case cls.SIGNER_KEY:
                signer = SignerKey.decode(view[1:])
            case cls.SIGNER_LIST:
                signer = SignerList.decode(view[1:])
            case _:
                raise ValueError('Invalid signer.')
        return cls(signer)


class ExecutiveSpawn(AbstractTXInput):
    pass


class Vote(object):

    SIZE = 32
    FORMAT = Struct('<QQQQ')

    def __init__(self,
        block_reward: int,
        exec_fund: int,
        utxo_fee: int,
        data_fee: int
    ):
        self.block_reward = block_reward
        self.exec_fund = exec_fund
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee
    
    def __eq__(self, value: Vote) -> bool:
        if not isinstance(value, Vote):
            return NotImplemented
        return (
            self.block_reward == value.block_reward
            and self.exec_fund == value.exec_fund
            and self.utxo_fee == value.utxo_fee
            and self.data_fee == value.data_fee
        )
    
    @property
    def size(self) -> int:
        return self.SIZE

    def encode(self) -> bytes:
        return self.FORMAT.pack(
            self.block_reward, self.exec_fund, self.utxo_fee, self.data_fee
        )
    
    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> Vote:
        if len(view) < cls.SIZE:
            raise ValueError('Invalid size when decoding.')
        return cls(*cls.FORMAT.unpack_from(view, 0))


class AbstractTXOutput(object):

    @staticmethod
    def _encode_mlen(memo: bytes):
        prefix = 0
        mlen = len(self.memo)
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

    @staticmethod
    def _decode_memo(prefix: int, view: bytes | bytearray | memoryview) -> bytes:
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

    SIGNER_NONE = 0
    SIGNER_HASH = 1
    SIGNER_KEY = 2

    def __init__(self,
        asset: SignerHash | None = None         # Asset to spawn
        signer: SignerHash | SignerKey | None = None,
        units: int = 0,                         # 1 share = 10**6 units
        block_reward: int | None = None,
        exec_fund: int | None = None,
        utxo_fee: int | None = None,
        data_fee: int | None = None,
        memo: bytes = b''                       # raw data to add to blockchain
    ):
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
        n = 1
        n += self.asset.size if self.asset else 0
        match self.signer:
            case None:
                pass
            case SignerHash | SignerKey:
                n += self.signer.size
            case _:
                raise ValueError('Invalid signer.')
        n += 8 if self.units else 0
        n += 0 if self.block_reward is None else 8
        n += 0 if self.exec_fund is None else 8
        n += 0 if self.utxo_fee is None else 8
        n += 0 if self.data_fee is None else 8
        if len(self.memo) < 0x80:
            n += 1
        elif len(self.memo) < 0x4000:
            n += 2
        elif len(self.memo) < 0x200000:
            n += 3
        else:
            raise ValueError('Invalid memo size.')
        n += len(self.memo)
        return n

    def encode(self, view: bytes | bytearray | memoryview) -> bytes:
        prefix = 0
        asset = self.asset.encode() if self.asset else b''
        prefix |= 1 if asset else 0
        match self.signer:
            case None:
                signer = b''
            case SignerHash():
                signer = self.signer.encode()
                prefix |= 2
            case SignerKey():
                signer = self.signer.encode()
                prefix |= 4
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
        mlen = len(self.memo)
        if mlen < 0x80:
            mlen = (mlen << 1).to_bytes(1, 'little')
        elif mlen < 0x4000:
            mlen = ((mlen << 2) | 1).to_bytes(2, 'little')
        elif mlen < 0x200000:
            mlen = ((mlen << 3) | 3).to_bytes(3, 'little')
        else:
            raise ValueError('Invalid memo size.')
        return b''.join([
            pack('<B', prefix), asset, signer, units, reward,
            fund, utxo_fee, data_fee, mlen, self.memo
        ])

    @classmethod
    def decode(cls, view: bytes | bytearray | memoryview) -> UTXOSpawn:
        try:
            prefix, offset = view[0], 1
            asset = SignerHash.decode(view[offset:]) if prefix & 1 else None
            prefix >>= 1
            offset += 0 if asset is None else asset.size
            match prefix & 3:
                case cls.SIGNER_NONE:
                    signer = None
                case cls.SIGNER_HASH:
                    signer = SignerHash.decode(view[offset:])
                case cls.SIGNER_KEY:
                    signer = SignerKey.decode(view[offset:])
                case _:
                    raise ValueError('Invalid signer.')
            prefix >>= 2
            offset += 0 if signer is None else signer.size
            units = unpack_from('<Q', view, offset)[0] if prefix & 1 else 0
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            reward = unpack_from('<Q', view, offset)[0] if prefix & 1 else 0
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            fund = unpack_from('<Q', view, offset)[0] if prefix & 1 else 0
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            utxo_fee = unpack_from('<Q', view, offset)[0] if prefix & 1 else 0
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            data_fee = unpack_from('<Q', view, offset)[0] if prefix & 1 else 0
            offset += 8 if prefix & 1 else 0
            prefix >>= 1
            if view[offset] & 1:
                if view[offset] & 2:
                    if len(view) < offset + 3:
                        raise IndexError()
                    mlen = int.from_bytes(view[offset:offset+3], 'little') >> 2
                    offset += 3
                else:
                    if len(view) < offset + 2:
                        raise IndexError()
                    mlen = int.from_bytes(view[offset:offset+2], 'little') >> 2
                    offset += 2
            else:
                mlen = view[offset] >> 1
                offset += 1
            memo = bytes(view[offset:offset+mlen])
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
        n ÷= (2 + len(self.memo)) if self.memo else 0
        return n

    def encode(self) -> bytes:
        prefix = 0
        executive = self.executive.encode()
        units = pack('<Q', self.units) if self.units else b''
        prefix |= 1 if units else 0
        mlen = len(self.memo)
        if mlen == 0:
            mlen = b''
        elif mlen < 0x100:
            mlen = pack('<B', mlen)
            prefix |= 2
        elif mlen < 0x10000:
            mlen = pack('<H', mlen)
            prefix |= 4
        else:
            raise ValueError('Invalid memo size')
        return b''.join([
            pack('<B', prefix), executive, units, mlen, self.memo
        ])




class AssetLock(AbstractTXOutput):
    pass


class PaymentOutput(object):


    def encode(self) -> bytearray:
        flags, i = 0, 1
        if self.signer:
            flags += 1
            signer = self.signer.hash
            i += len(signer)
        if self.units:
            flags += 2
            i += 8
        if self.block_reward_vote is not None:
            flags += 4
            i += 8
        if self.utxo_fee_vote is not None:
            flags += 8
            i += 8
        if self.data_fee_vote is not None:
            flags += 16
            i += 8
        if self.memo:
            if len(self.memo) < 256:
                flags += 32
                i += 1
            elif len(self.memo) < 0x10000:
                flags += 64
                i += 2
            else:
                raise ValueError('`memo` too large to encode.')
            i += len(self.memo)
        buffer = bytearray(i)
        view = memoryview(buffer)
        view[0] = flags
        i = 1
        if self.signer:
            view[i:i+len(signer)] = signer
            i += len(signer)
        if self.units:
            pack_into('<Q', view, i, self.units)
            i += 8
        if self.block_reward_vote is not None:
            pack_into('<Q', view, i, self.block_reward_vote)
            i += 8
        if self.utxo_fee_vote is not None:
            pack_into('<Q', view, i, self.utxo_fee_vote)
            i += 8
        if self.data_fee_vote is not None:
            pack_into('<Q', view, i, self.data_fee_vote)
            i += 8
        if self.memo:
            if len(self.memo) < 256:
                view[i] = len(self.memo)
                i += 1
            else:
                pack_into('<H', view, i, len(self.memo))
                i += 2
            view[i:i+len(self.memo)] = self.memo
        return buffer

    @classmethod
    def decode(cls, view: memoryview) -> tuple['PaymentOutput', int]:
        if len(view) < 1:
            raise ValueError('`view` too short to decode `PaymentOutput`.')
        flags, i = view[0], 1
        # unpack signer
        if flags & 1:
            if len(view) < i + 20:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            signer = SignerHash(bytes(view[i:i+20]))
            i += 20
        else:
            signer = None
        # unpack units
        if flags & 2:
            if len(view) < i + 8:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            units = unpack_from('<Q', view, i)[0]
            i += 8
        else:
            units = None
        # unpack block_reward_vote
        if flags & 4:
            if len(view) < i + 8:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            block_reward_vote = unpack_from('<Q', view, i)[0]
            i += 8
        else:
            block_reward_vote = None
        # unpack utxo_fee_vote
        if flags & 8:
            if len(view) < i + 8:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            utxo_fee_vote = unpack_from('<Q', view, i)[0]
            i += 8
        else:
            utxo_fee_vote = None
        # unpack data_fee_vote
        if flags & 16:
            if len(view) < i + 8:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            data_fee_vote = unpack_from('<Q', view, i)[0]
            i += 8
        else:
            data_fee_vote = None
        # unpack memo
        if flags & 96 == 96:
            raise ValueError('Invalid `memo_len` flag encoded in `PaymentOutput`.')
        if flags & 32:
            if len(view) < i + 1:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            memo_len = view[i]
            i += 1
            if len(view) < i + memo_len:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            memo = view[i:i+memo_len]
            i += memo_len
        elif flags & 64:
            if len(view) < i + 2:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            memo_len = unpack_from('<H', view, i)
            i += 2
            if len(view) < i + memo_len:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            memo = view[i:i+memo_len]
            i += memo_len
        else:
            memo = None
        return cls(signer, units, block_reward_vote, utxo_fee_vote, data_fee_vote, memo), i


class Payment(object):

    def __init__(self,
        inputs: list[PaymentInput],
        outputs: list[PaymentOutput],
        signatures: list[bytes],
        encoded_buffer: bytearray | None = None
    ):
        self.inputs = inputs
        self.outputs = outputs
        self.signatures = signatures
        self.encoded_buffer = encoded_buffer
        self._digest = None

    @property
    def digest(self) -> bytes:
        if self._digest is None:
            if self.encoded_buffer is None:
                self.encoded_buffer = self.encode()
            self._digest = keccak_1600(self.encoded_buffer)
        return self._digest

    @property
    def digest_no_signatures(self) -> bytes:
        if self.encoded_buffer is None:
            self.encoded_buffer = self.encode()
        return keccak_1600(self.encoded_buffer[:-64*len(self.signatures)])

    def encode(self) -> bytearray:
        inputs = [x.encode() for x in self.inputs]
        inputs_size = sum(len(x) for x in inputs)
        outputs = [x.encode() for x in self.outputs]
        outputs_size = sum(len(x) for x in outputs)
        if any(len(x) != 64 for x in self.signatures):
            raise ValueError('Invalid signature length for `Payment`.')
        sigs_size = 64 * len(self.signatures)
        nbytes = 4 + inputs_size + outputs_size + sigs_size
        if nbytes >= 0x10000:
            raise ValueError('`Payment` encoding is too long.')
        buffer = bytearray(nbytes)
        view = memoryview(buffer)
        pack_into('<HH', view, 0, inputs_size, outputs_size)
        # encode inputs
        offset = 4
        for input in inputs:
            view[offset:offset+len(input)] = input
            offset += len(input)
        # encode outputs
        for output in outputs:
            view[offset:offset+len(output)] = output
            offset += len(output)
        # encode signatures
        for signature in self.signatures:
            view[offset:offset+64] = signature
            offset += 64
        return buffer
    
    @classmethod
    def decode(cls, view: memoryview) -> tuple['Payment', int]:
        if len(view) < 4:
            raise ValueError('`view` is too short to decode `Payment`.')
        inputs_size, outputs_size = unpack_from('<HH', view, 0)
        sigs_size = len(view) - 4 - inputs_size - outputs_size
        if sigs_size < 0 or sigs_size & 63:
            raise ValueError('Malformed signature block for `Payment`.')
        # decode inputs
        inputs: list[PaymentInput] = []
        offset = 4
        while offset < 4 + inputs_size:
            x, nbytes = PaymentInput.decode(view[offset:])
            inputs.append(x)
            offset += nbytes
        # decode outputs
        outputs: list[PaymentOutput] = []
        while offset < 4 + inputs_size + outputs_size:
            x, nbytes = PaymentOutput.decode(view[offset:])
            outputs.append(x)
            offset += nbytes
        # decode signatures
        signatures: list[bytes] = []
        while offset < len(view):
            signatures.append(bytes(view[offset:offset+64]))
            offset += 64
        return cls(inputs, outputs, signatures, bytearray(view[:offset])), offset


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
