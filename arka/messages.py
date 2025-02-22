
from struct import pack_into, unpack_from
from enum import IntEnum

from .crypto import keccak_800, keccak_1600



class Parameters(object):

    def __init__(self,
        target: int,            # mint difficulty x * 2 ** y
        block_reward: int,      # units generated each block
        utxo_fee: int,          # decay of UTXOs per block as a fraction z / 2**64
        data_fee: int,          # units to destroy per byte in payment
    ):
        self.target = target
        self.block_reward = block_reward
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee

    def encode(self) -> bytearray:
        buffer = bytearray(26)
        view = memoryview(buffer)
        view[1] = max(0, self.target.bit_length() - 8)
        view[0] = self.target >> view[1]
        pack_into('<QQQ', view, 2, self.block_reward, self.utxo_fee, self.data_fee)
        return buffer

    @classmethod
    def decode(cls, view: memoryview) -> tuple["Parameters", int]:
        try:
            target = view[0] * (1 << view[1])
            block_reward, utxo_fee, data_fee = unpack_from('<QQQ', view, 2)
        except IndexError as e:
            raise ValueError('`view` too short to decode `Parameters`.')
        return cls(target, block_reward, utxo_fee, data_fee), 26


class SpenderEnum(IntEnum):
    SPENDER_LIST = 0
    SPENDER_HASH = 1
    SPENDER_KEY = 2


class SpenderHash(object):

    def __init__(self, hash: bytes):
        self.hash = hash

    def encode(self) -> bytearray:
        buffer = bytearray(1 + len(self.hash))
        view = memoryview(buffer)
        view[0] = (len(self.hash) << 2) | SpenderEnum.SPENDER_HASH.value
        view[1:1+len(self.hash)] = self.hash
        return buffer
       
    @classmethod
    def decode(cls, view: memoryview) -> tuple["SpenderHash", int]:
        try:
            hash_len = view[0] >> 2
            if 16 <= hash_len <= 32:
                hash = bytes(view[1:1+hash_len])
            else:
                raise ValueError('Invalid hash length encoded for `SpenderHash`.')
            if len(hash) < hash_len:
                raise IndexError()
        except IndexError as e:
            raise ValueError('`view` too short to decode `SpenderHash`.')
        return cls(hash), 1 + hash_len


class SpenderKey(object):

    def __init__(self, key: bytes, truncate: int = 0):
        self.key = key
        self.truncate = truncate

    def hash(self) -> SpenderHash:
        if not self.truncate:
            raise ValueError('`SpenderKey` is not to be hashed.')
        return SpenderHash(keccak_800(self.key)[:self.truncate])
    
    def encode(self) -> bytearray:
        buffer = bytearray(33)
        view = memoryview(buffer)
        view[0] = (self.truncate << 2) | SpenderEnum.SPENDER_KEY.value
        view[1:33] = self.key
        return buffer

    @classmethod
    def decode(cls, view: memoryview) -> tuple["SpenderKey", int]:
        try:
            truncate = view[0] >> 2
            if truncate == 0 or 16 <= truncate <= 32:
                key = bytes(view[1:33])
            else:
                raise ValueError('Invalid `truncate` value encoded for `SpenderKey`.')
            if len(key) < 32:
                raise IndexError()
        except IndexError as e:
            raise ValueError('`view` too short to decode `SpenderKey`.')
        return cls(key, truncate), 33


class SpenderList(object):

    def __init__(self, spenders: list["SpenderList" | SpenderHash | SpenderKey],
            threshold: int, truncate: int = 16):
        self.spenders = spenders
        self.threshold = threshold
        self.truncate = truncate

    @property
    def keys(self) -> list[bytes]:
        key_count = 0
        values: list[bytes] = []
        output: list[bytes] = []
        unique: set[bytes] = set()
        for s in self.spenders:
            match s:
                case SpenderList():
                    values.extend(s.keys)
                    key_count += 1
                case SpenderKey():
                    values.append(s.key)
                    key_count += 1
        if key_count < self.threshold:
            raise ValueError("SpenderList keys does not meet threshold.")
        for k in values:
            if k not in unique:
                unique.add(k)
                output.append(k)
        return output

    def hash(self) -> SpenderHash:
        if not self.spenders or not self.threshold:
            raise ValueError("Cannot hash empty SpenderList.")
        prefix = bytearray(1
            + (1 if len(self.spenders) < 128 else 2)
            + (1 if self.threshold < 128 else 2)
        )
        prefix[0] = (self.truncate << 2) | SpenderEnum.SPENDER_LIST.value
        if len(self.spenders) < 128:
            prefix[1] = len(self.spenders) << 1
            i = 2
        else:
            prefix[1] = ((len(self.spenders) & 0x7f) << 1) | 1
            prefix[2] = (len(self.spenders) >> 7) & 0xff
            i = 3
        if self.threshold < 128:
            prefix[i] = self.threshold << 1
        else:
            prefix[i] = ((self.threshold & 0x7f) << 1) | 1
            prefix[i+1] = (self.threshold >> 7) & 0xff
        spenders: list[bytes] = []
        for s in self.spenders:
            match s:
                case SpenderHash():
                    spenders.append(s.hash)
                case SpenderKey() | SpenderList():
                    spenders.append(s.hash().hash)
        buffer = bytearray(len(prefix) + sum(len(s) for s in spenders))
        view = memoryview(buffer)
        i = 0
        view[i:i+len(prefix)] = prefix
        i += len(prefix)
        for s in spenders:
            view[i:i+len(s)] = s
            i += len(s)
        return SpenderHash(keccak_1600(buffer)[:self.truncate])

    def encode(self) -> bytearray:
        if not self.spenders or not self.threshold:
            raise ValueError("Cannot encode empty SpenderList.")
        prefix = bytearray(1
            + (1 if len(self.spenders) < 128 else 2)
            + (1 if self.threshold < 128 else 2)
        )
        prefix[0] = (self.truncate << 2) | SpenderEnum.SPENDER_LIST.value
        if len(self.spenders) < 128:
            prefix[1] = len(self.spenders) << 1
            i = 2
        else:
            prefix[1] = ((len(self.spenders) & 0x7f) << 1) | 1
            prefix[2] = (len(self.spenders) >> 7) & 0xff
            i = 3
        if self.threshold < 128:
            prefix[i] = self.threshold << 1
        else:
            prefix[i] = ((self.threshold & 0x7f) << 1) | 1
            prefix[i+1] = (self.threshold >> 7) & 0xff
        spenders = [s.encode() for s in self.spenders]
        buffer = bytearray(len(prefix) + sum(len(s) for s in spenders))
        view = memoryview(buffer)
        i = 0
        view[i:i+len(prefix)] = prefix
        i += len(prefix)
        for s in spenders:
            view[i:i+len(s)] = s
            i += len(s)
        return buffer

    @classmethod
    def decode(cls, view: memoryview) -> tuple["SpenderList", int]:
        try:
            spenders: list[SpenderHash | SpenderKey | SpenderList] = []
            truncate = view[0] >> 2
            if truncate < 16 or truncate > 32:
                raise ValueError('Invalid `truncate` value encoded for `SpenderList`.')
            nspenders = view[1]
            i = 2
            if nspenders & 1:
                nspenders += view[i] << 8
                i += 1
            nspenders >>= 1
            threshold = view[i]
            i += 1
            if threshold & 1:
                threshold += view[i] << 8
                i += 1
            threshold >>= 1
            if not nspenders or not threshold:
                raise ValueError('Decoded `SpenderList` must not be empty.')
            for j in range(nspenders):
                match view[i] & 3:
                    case SpenderEnum.SPENDER_HASH.value:
                        x, n = SpenderHash.decode(view[i:])
                    case SpenderEnum.SPENDER_KEY.value:
                        x, n = SpenderKey.decode(view[i:])
                    case SpenderEnum.SPENDER_LIST.value:
                        x, n = SpenderList.decode(view[i:])
                    case _:
                        raise ValueError('Invalid spender type encoded.')
                spenders.append(x)
                i += n
        except IndexError as e:
            raise ValueError('`view` too short to decode `SpenderList`.')
        return SpenderList(spenders, threshold, truncate), i


class UTXORefEnum(IntEnum):

    BY_INDEX = 0
    BY_HASH = 1


class UTXORefByIndex(object):

    def __init__(self, block: int, payment: int, output: int):
        self.block, self.payment, self.output = block, payment, output
    
    def encode(self) -> bytearray:
        buffer = bytearray(11)
        pack_into('<BIIH', buffer, 0,
            UTXORefEnum.BY_INDEX.value, self.block, self.payment, self.output
        )
        return buffer

    @classmethod
    def decode(cls, view) -> tuple['UTXORefByIndex', int]:
        if len(view) < 11:
            raise ValueError('`view` too short to decode `UTXORefByIndex`.')
        return cls(*unpack_from('<IIH', view, 1)), 11


class UTXORefByHash(object):

    def __init__(self, payment: bytes, output: int):
        self.payment, self.output = payment, output

    def encode(self) -> bytearray:
        buffer = bytearray(35)
        view = memoryview(buffer)
        view[0] = UTXORefEnum.BY_HASH.value
        view[1:33] = self.payment
        pack_into('<H', view, 33, self.output)
        return buffer

    @classmethod
    def decode(cls, view: memoryview) -> tuple["UTXORefByHash", int]:
        if len(view) < 35:
            raise ValueError('`view` too short to decode `UTXORefByHash`.')
        payment = bytes(view[1:33])
        output = unpack_from('<H', view, 33)[0]
        return cls(payment, output), 35


class PaymentInput(object):

    def __init__(self,
        utxo: UTXORefByIndex | UTXORefByHash, spender: SpenderKey | SpenderList
    ):
        self.utxo, self.spender = utxo, spender

    def encode(self) -> bytearray:
        return self.utxo.encode() + self.spender.encode()

    @classmethod
    def decode(cls, view: memoryview) -> tuple['PaymentInput', int]:
        if len(view) == 0:
            raise ValueError('`view` too short to decode `PaymentInput`.')
        match view[0]:
            case UTXORefEnum.BY_INDEX.value:
                utxo, i = UTXORefByIndex.decode(view)
            case UTXORefEnum.BY_HASH.value:
                utxo, i = UTXORefByHash.decode(view)
            case _:
                raise ValueError('Invalid `UTXORef*` type encoded in `view`.')
        if len(view) == i:
            raise ValueError('`view` too short to decode `PaymentInput`.')
        match view[i]:
            case SpenderEnum.SPENDER_KEY.value:
                spender, n = SpenderKey.decode(view[i:])
            case SpenderEnum.SPENDER_LIST.value:
                spender, n = SpenderList.decode(view[i:])
            case _:
                raise ValueError('Invalid `Spender*` type encoded in `view`.')
        return cls(utxo, spender), i + n


class Vote(object):

    def __init__(self,
        block_reward: int,
        utxo_fee: int,
        data_fee: int
    ):
        self.block_reward = block_reward
        self.utxo_fee = utxo_fee
        self.data_fee = data_fee

    def encode(self) -> bytearray:
        buffer = bytearray(24)
        pack_into('<QQQ', buffer, 0,
            self.block_reward, self.utxo_fee, self.data_fee
        )
        return buffer
    
    @classmethod
    def decode(cls, view: memoryview) -> tuple['Vote', int]:
        if len(view) < 24:
            raise ValueError('`view` too short to decode `Vote`.')
        return cls(*unpack_from('<QQQ', view, 0)), 24


class PaymentOutput(object):

    def __init__(self,
        spender: SpenderHash | SpenderKey | None,   # 16-32 bytes digest of receipient's public key
        units: int = 0,                             # 1 coin = 10**9 units
        vote: Vote | None = None,                   # adjustments to blockchain parameters
        memo: bytes | None = None                   # raw data to add to blockchain
    ):
        self.spender = spender
        self.units = units
        self.vote = vote
        self.memo = memo

    def encode(self) -> bytearray:
        flags, i = 0, 1
        if self.spender:
            flags += 1
            spender = self.spender.encode()
            i += len(spender)
        if self.units:
            flags += 2
            i += 8
        if self.vote:
            flags += 4
            vote = self.vote.encode()
            i += len(vote)
        if self.memo:
            if len(self.memo) < 256:
                flags += 8
                i += 1
            elif len(self.memo) < 0x10000:
                flags += 16
                i += 2
            else:
                raise ValueError('`memo` too large to encode.')
            i += len(self.memo)
        buffer = bytearray(i)
        view = memoryview(buffer)
        view[0] = flags
        i = 1
        if self.spender:
            view[i:i+len(spender)] = spender
            i += len(spender)
        if self.units:
            pack_into('<Q', view, i, self.units)
            i += 8
        if self.vote:
            view[i:i+len(vote)] = vote
            i += len(vote)
        if self.memo:
            if len(self.memo) < 256:
                view[i] = len(self.memo)
                i += 1
            else:
                pack_into('<H', view, i, len(self.memo))
                i += 2
            view[i:i+len(self.memo)] = self.memo
        return buffer


class Payment(object):

    def __init__(self,
        inputs: list[PaymentInput],
        outputs: list[PaymentOutput],
        signatures: list[bytes]
    ):
        self.inputs = inputs
        self.outputs = outputs
        self.signatures = signatures


class Block(object):

    def __init__(self,
        timestamp: int,                         # microseconds since UNIX epoch
        prev_hash: bytes,                       # hash digest of most recent block
        uid: SpenderHash | SpenderKey,          # uid of block worker
        nonce: bytes | None = None,             # nonce required to hash block to target difficulty
        parameters: Parameters | None = None,   # epoch blocks publish network parameters
        payments: list[Payment] = []            # payment transactions to commit by this block
    ):
        self.timestamp = timestamp
        self.prev_hash = prev_hash
        self.uid = uid
        self.nonce = nonce
        self.parameters = parameters
        self.payments = payments

    def header_prehash(self) -> bytes:
        if self.worker is None:
            raise Exception("No worker set for block.")
        data = b''.join([
            self.index_bytes,
            self.prev_block,
            self.prev_link,
            self.timestamp_bytes,
            self.total_work_bytes,
            self.worker
        ])
        return keccak_1600(data)
    
    def mint(self, limit: int = 1000, nonce: bytes | None = None) -> bytes | None:
        key = self.work_key
        target = self.parameters.target
        nonce = nonce or self.nonce or (b'\x00' * 32)
        base, exp = target
        len = (exp + 7) // 8
        for iteration in range(limit):
            digest = keccak_800(b''.join(key, target, nonce))
            if base >= digest[0]:
                exp_sum = sum(digest[i+1] << (8*i) for i in range(len))
                if not exp_sum % (1 << exp):
                    self.nonce = nonce
                    return digest
            new_nonce = sum(x << (8*i) for i,x in enumerate(nonce)) + 1
            nonce = bytes([
                (new_nonce >> (8*i)) % 0xff for i in range(len(nonce))
            ])
        self.nonce = nonce
        return None

    def digest(self) -> bytes | None:
        if not self.nonce:
            return None
        data = b''.join(
            self.work_key,
            self.parameters.target,
            self.nonce
        )
        digest = keccak_800(data)
        base, exp = self.parameters.target
        if base >= digest[0]:
            exp_sum = sum(digest[i+1] << (8*i) for i in range((exp + 7) // 8))
            if not exp_sum % (1 << exp):
                return digest
        return None

