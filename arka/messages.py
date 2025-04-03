
from __future__ import annotations

from struct import pack_into, unpack_from
from enum import IntEnum
from ._crypto import keccak_800, keccak_1600



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
        if len(view) < 26:
            raise ValueError('`view` too short to decode `Parameters`.')
        target = view[0] * (1 << view[1])
        block_reward, utxo_fee, data_fee = unpack_from('<QQQ', view, 2)
        return cls(target, block_reward, utxo_fee, data_fee), 26


class SpenderEnum(IntEnum):
    SPENDER_LIST = 0
    SPENDER_HASH = 1
    SPENDER_KEY = 2


class SpenderHash(object):

    def __init__(self, hash: bytes):
        self.hash = hash

    def encode(self) -> bytearray:
        return bytearray([SpenderEnum.SPENDER_HASH.value]) + self.hash
       
    @classmethod
    def decode(cls, view: memoryview) -> tuple["SpenderHash", int]:
        if len(view) < 21:
            raise ValueError('`view` too short to decode `SpenderHash`.')
        return cls(bytes(view[1:21])), 21


class SpenderKey(object):

    def __init__(self, key: bytes):
        self.key = key

    def hash(self) -> SpenderHash:
        return SpenderHash(keccak_800(self.key, 20))
    
    def encode(self) -> bytearray:
        return bytearray([SpenderEnum.SPENDER_KEY.value]) + self.key

    @classmethod
    def decode(cls, view: memoryview) -> tuple["SpenderKey", int]:
        if len(view) < 33:
            raise ValueError('`view` too short to decode `SpenderKey`.')
        return cls(bytes(view[1:33])), 33


class SpenderList(object):

    def __init__(self,
        spenders: list[SpenderList | SpenderHash | SpenderKey],
        threshold: int
    ):
        self.spenders = spenders
        self.threshold = threshold

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
        prefix[0] = SpenderEnum.SPENDER_LIST.value
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
        hashes: list[bytes] = []
        for s in self.spenders:
            match s:
                case SpenderHash():
                    hashes.append(s.hash)
                case SpenderKey() | SpenderList():
                    hashes.append(s.hash().hash)
        buffer = bytearray(len(prefix) + 20 * len(hashes))
        view = memoryview(buffer)
        i = 0
        view[i:i+len(prefix)] = prefix
        i += len(prefix)
        for h in hashes:
            view[i:i+len(h)] = h
            i += len(h)
        return SpenderHash(keccak_1600(buffer, 20))

    def encode(self) -> bytearray:
        if not self.spenders or not self.threshold:
            raise ValueError("Cannot encode empty SpenderList.")
        prefix = bytearray(1
            + (1 if len(self.spenders) < 128 else 2)
            + (1 if self.threshold < 128 else 2)
        )
        prefix[0] = SpenderEnum.SPENDER_LIST.value
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
                match view[i]:
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
        return SpenderList(spenders, threshold), i


class UTXORefByIndex(object):

    def __init__(self, block: int, payment: int, output: int):
        self.block, self.payment, self.output = block, payment, output
    
    def encode(self) -> bytearray:
        buffer = bytearray(10)
        pack_into('<IIH', buffer, 0,
            self.block, self.payment, self.output
        )
        return buffer

    @classmethod
    def decode(cls, view) -> tuple['UTXORefByIndex', int]:
        if len(view) < 10:
            raise ValueError('`view` too short to decode `UTXORefByIndex`.')
        return cls(*unpack_from('<IIH', view, 0)), 10


class PaymentInput(object):

    def __init__(self,
        utxo: UTXORefByIndex, spender: SpenderKey | SpenderList
    ):
        self.utxo, self.spender = utxo, spender

    def encode(self) -> bytearray:
        return self.utxo.encode() + self.spender.encode()

    @classmethod
    def decode(cls, view: memoryview) -> tuple['PaymentInput', int]:
        utxo, i = UTXORefByIndex.decode(view)
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
        spender: SpenderHash | None,            # 16-32 bytes digest of receipient's public key
        units: int = 0,                         # 1 coin = 10**9 units
        block_reward_vote: int | None = None,   # adjustment to block_reward
        utxo_fee_vote: int | None = None,       # adjustment to utxo_fee
        data_fee_vote: int | None = None,       # adjustment to data_fee
        memo: bytes | None = None               # raw data to add to blockchain
    ):
        self.spender = spender
        self.units = units
        self.block_reward_vote = block_reward_vote
        self.utxo_fee_vote = utxo_fee_vote
        self.data_fee_vote = data_fee_vote
        self.memo = memo

    def encode(self) -> bytearray:
        flags, i = 0, 1
        if self.spender:
            flags += 1
            spender = self.spender.hash
            i += len(spender)
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
        if self.spender:
            view[i:i+len(spender)] = spender
            i += len(spender)
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
        # unpack spender
        if flags & 1:
            if len(view) < i + 20:
                raise ValueError('`view` too short to decode `PaymentOutput`.')
            spender = SpenderHash(bytes(view[i:i+20]))
            i += 20
        else:
            spender = None
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
        return cls(spender, units, block_reward_vote, utxo_fee_vote, data_fee_vote, memo), i


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
        uid: SpenderHash, payments_digest: bytes,
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
            case SpenderEnum.SPENDER_HASH.value:
                uid, n = SpenderHash.decode(view[offset:])
            case SpenderEnum.SPENDER_KEY.value:
                uid, n = SpenderKey.decode(view[offset:])
                if uid.truncate:
                    raise ValueError('`BlockHeader` `SpenderKey` must not be truncated.')
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
        uid: SpenderHash | SpenderKey,          # uid of block worker
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
