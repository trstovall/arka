# arka.block data reference

Compact declarations for [arka/block.py](../arka/block.py).
See [block.md](block.md) for byte layouts, constraints, and implementation exceptions.

The signatures describe construction, not executable function definitions.
Aliases below are documentation shorthand. Internal validation arguments,
comparison methods, and repeated codec methods are omitted.

## Byte values

Each type wraps `value: bytes` and accepts `bytes | bytearray | memoryview`.
Mutable input is copied to immutable bytes.

| Size | Types |
| ---: | --- |
| 16 | `Nonce_16` |
| 32 | `Nonce_32`, `SignerKey`, `SignerHash`, `TransactionHash`, `TransactionListHash`, `BlockHeaderHash`, `BlockHash` |
| 64 | `Signature` |

## Signers and references

```python
Buffer = bytes | bytearray | memoryview
Memo = Buffer | None
Signer = SignerKey | SignerList | SignerLocked
Recipient = SignerKey | SignerHash

SignerList(signers: list[SignerList | SignerHash | SignerKey], threshold: int)
SignerLocked(
    hash_lock: Nonce_32, hash_locked_signer: SignerList | SignerHash,
    time_lock: int, time_locked_signer: SignerList | SignerHash,
)

UTXORefByIndex(block: int, tx: int, output: int)
UTXORefByHash(tx_hash: TransactionHash, output: int)
```

## Transaction inputs

```python
UTXOSpend(
    utxo: UTXORefByIndex | UTXORefByHash,
    time_lock: int | None = None,
    signer: Signer | None = None, memo: Memo = None,
)
PublisherSpend(
    block: int, signer: SignerKey | SignerList | None = None, memo: Memo = None,
)
ExecutiveSpend(
    block: int, signer: SignerKey | SignerList | None = None, memo: Memo = None,
)
ExecutiveDefinition(
    executive: Nonce_16, signer: SignerKey | SignerList,
    new_signer: SignerHash | None = None, memo: Memo = None,
)
AssetDefinition(
    asset: Nonce_16, signer: SignerKey | SignerList,
    new_signer: SignerHash | None = None, memo: Memo = None, lock: bool = False,
)
```

## Transaction outputs

```python
ArkaUTXO(
    signer: Recipient | None = None, units: int | None = None,
    block_reward: int | None = None, exec_fund: int | None = None,
    utxo_fee: int | None = None, data_fee: int | None = None, memo: Memo = None,
)
AssetUTXO(
    asset: Nonce_16, signer: Recipient | None = None,
    units: int | None = None, memo: Memo = None,
)
ExecutiveVote(
    executive: Nonce_16, promote: bool = True,
    units: int | None = None, memo: Memo = None,
)
```

## Transactions and blocks

```python
Input = PublisherSpend | ExecutiveSpend | UTXOSpend | AssetDefinition | ExecutiveDefinition
Output = ArkaUTXO | AssetUTXO | ExecutiveVote

Transaction(
    inputs: list[Input] | None = None,
    outputs: list[Output] | None = None,
    signatures: list[Signature] | None = None,
    digest: TransactionHash | None = None,
)
TransactionList(transactions: list[Transaction] | None = None)

Parameters(
    target: int, block_reward: int, exec_fund: int,
    utxo_fee: int, data_fee: int, executive: Nonce_16,
)
BlockHeader(
    id: int, timestamp: int, prev_block: BlockHash, publisher: Recipient,
    ntxs: int | None = None, root_hash: TransactionListHash | None = None,
    parameters: Parameters | None = None, nonce: Nonce_32 | None = None,
)
Block(header: BlockHeader, transactions: TransactionList)
BlockSummary(header: BlockHeader, ids: list[int] = [])
```

Constructor names identify stored fields. Transaction and transaction-list
arguments of `None` become empty lists. `BlockSummary.ids` retains the source's
literal default. Base types are `AbstractElement`, `Bytes`, `TransactionElement`,
`TransactionInput`, `BlockSpend`, and `TransactionOutput`; the records above are
the concrete data definitions.

## Shared operations

For concrete type `T`, `size: int` describes its encoded byte length.

```python
def encode(self) -> bytes: ...

@classmethod
def decode(cls, view: Buffer) -> T: ...
```

Exceptions and additional operations:

| Type | Signature |
| --- | --- |
| `Transaction` | `encode(include_signatures: bool = True) -> bytes` |
| `Transaction` | `decode(view: Buffer, digest: TransactionHash | None = None) -> Transaction` |
| `BlockHeader` | `encode(include_nonce: bool = True) -> bytes` |
| `TransactionList` | `async decode(view: Buffer) -> TransactionList` |
| `Block` | `async decode(view: Buffer) -> Block` |
| `Parameters` | `encode_target() -> bytes` |
| `SignerKey`, `SignerList`, `SignerLocked` | `async hash() -> SignerHash` |
| `Transaction` | `async hash() -> TransactionHash` |
| `TransactionList` | `async hash(merkle: bool = True) -> TransactionListHash | None` |
| `BlockHeader` | `async hash() -> BlockHeaderHash` |
| `BlockHeader` | `async hash_nonce() -> BlockHash` |
| `Block` | `async hash(update_header: bool = False) -> BlockHash` |

`keys: list[SignerKey]` is available on signer lists, locked signers, transaction
inputs, and transactions. It preserves first occurrence and removes duplicate
key bytes; missing signers or insufficient thresholds can raise an error.
Stored lists expose ordered data; `TransactionList` has no `__iter__` method.

## Invocation forms

Finite nested expressions illustrate composition; they define no algorithms.
Here `view: Buffer`, `key_bytes: bytes` has length 32, and `tx: Transaction`.

```python
SignerList([SignerKey(key_bytes)], threshold=1).encode()
Transaction.decode(tx.encode())
await TransactionList([Transaction.decode(view)]).hash()
(await Block.decode(view)).transactions.transactions
```

Encoded bytes are immutable. Decoded byte fields own their data; object fields
and lists remain mutable. Cached transaction sizes and digests assume unchanged
represented data. Cryptographic `.hash()` is distinct from Python `hash()`;
see `block.md` for current hashability and constructor memo-ownership limitations.

## Example: one UTXO transfer

This block contains one transaction spending output `(100, 0, 0)` and creating
one output of 1,000 units. It includes one signer, one signature, and a block
nonce. Memos, votes, time locks, and epoch parameters are absent.

Repeated-byte keys, hashes, signature, and nonce are illustrative payloads;
they do not establish authorization or valid proof of work. The transaction
root is computed from the actual example transaction. The expression containing
`await` belongs in an asynchronous context.

```python
from arka.block import (
    ArkaUTXO, Block, BlockHash, BlockHeader, Nonce_32, Signature,
    SignerHash, SignerKey, Transaction, TransactionList,
    UTXORefByIndex, UTXOSpend,
)

prev_block = BlockHash(bytes.fromhex('33' * 32))

publisher = SignerKey(bytes.fromhex('11' * 32))

nonce = Nonce_32(bytes.fromhex('55' * 32))

transfer = Transaction(
    inputs=[UTXOSpend(
        utxo=UTXORefByIndex(block=100, tx=0, output=0),
        signer=SignerKey(bytes.fromhex('11' * 32)),
    )],
    outputs=[ArkaUTXO(
        signer=SignerHash(bytes.fromhex('22' * 32)),
        units=1_000,
    )],
    signatures=[Signature(bytes.fromhex('44' * 64))],
)

transactions = TransactionList([transfer])

txs_hash = await transactions.hash()

example = Block(
    header=BlockHeader(
        id=101,
        timestamp=1_700_000_000_000_000,
        prev_block=prev_block,
        publisher=publisher,
        ntxs=1,
        root_hash=txs_hash,
        nonce=nonce,
    ),
    transactions=transactions,
)

encoded: bytes = example.encode()
```

### Byte map

Offsets below are zero-based and inclusive. Hex bytes appear in wire order.
`xx × N` means the byte `xx` repeated `N` times. `R` denotes the computed
32-byte root, not a literal placeholder written into the encoding.

| Offsets | Bytes | Meaning |
| --- | --- | --- |
| 0 | `0a` | Header prefix |
| 1–8 | `65 00 00 00 00 00 00 00` | Block ID 101 |
| 9–16 | `00 40 1e 18 24 0a 06 00` | Timestamp 1,700,000,000,000,000 |
| 17–48 | `33 × 32` | Previous block hash |
| 49–80 | `11 × 32` | Publisher key |
| 81–84 | `01 00 00 00` | One transaction |
| 85–116 | `R` | Transaction root |
| 117–148 | `55 × 32` | Nonce |
| 149–150 | `9c 00` | Transaction byte length: 156 |
| 151–152 | `01 00` | One input |
| 153–154 | `01 00` | One output |
| 155–156 | `01 00` | One signature |
| 157 | `02` | Input type table: UTXO spend |
| 158 | `00` | Output type table: Arka UTXO |
| 159 | `00` | UTXO-spend prefix |
| 160–167 | `64 00 00 00 00 00 00 00` | Referenced block 100 |
| 168–171 | `00 00 00 00` | Referenced transaction 0 |
| 172–173 | `00 00` | Referenced output 0 |
| 174–205 | `11 × 32` | Input signer key |
| 206–208 | `09 00 00` | Arka-UTXO prefix |
| 209–240 | `22 × 32` | Recipient signer hash |
| 241–242 | `e8 03` | 1,000 units |
| 243–306 | `44 × 64` | Signature |

Total: **307 bytes** = 149-byte header + 2-byte length table + 156-byte
transaction. The transaction consists of 6 count bytes, 2 type-table bytes,
a 47-byte input, a 37-byte output, and a 64-byte signature.

### Prefix bits

Bit 0 is the least significant bit. Binary byte displays run from bit 7 to
bit 0; multi-byte prefixes are interpreted as little-endian integers.

| Offset | Binary | Bit interpretation |
| --- | --- | --- |
| 0 | `00001010` | `[0]=0`: publisher key; `[1]=1`: count/root present; `[2]=0`: no parameters; `[3]=1`: nonce present; `[4:7]=0`: unused |
| 157 | `00000010` | `[0:3]=0010`: input tag 2 (`UTXOSpend`); `[4:7]=0000`: unused second slot |
| 158 | `00000000` | `[0:1]=00`: output tag 0 (`ArkaUTXO`); `[2:7]=0`: unused slots |
| 159 | `00000000` | `[0]=0`: index reference; `[1]=0`: no time lock; `[2:3]=00`: signer key; `[4:5]=00`: no memo; `[6:7]=0`: unused |

The output prefix at offsets 206–208 is `00001001 00000000 00000000` in
wire-byte order, or integer `0x000009`:

| Prefix bits | Value | Meaning |
| --- | --- | --- |
| `[0:1]` | `01` | Recipient is `SignerHash` |
| `[2:5]` | `0010` | Units occupy two bytes |
| `[6:9]` | `0000` | No block-reward vote |
| `[10:13]` | `0000` | No executive-fund vote |
| `[14:17]` | `0000` | No UTXO-fee vote |
| `[18:21]` | `0000` | No data-fee vote |
| `[22:23]` | `00` | No memo length or payload |

Every bit outside these prefixes belongs to an integer or opaque payload:
integer byte `j` contributes its unsigned value times `256^j`. Thus
`9c 00 = 156`, and `e8 03 = 232 + 3*256 = 1000`. Opaque bytes have no codec
subfields: `11`, `22`, `33`, `44`, and `55` correspond respectively to
`00010001`, `00100010`, `00110011`, `01000100`, and `01010101`. Root and signature
bits are retained verbatim, without byte-order conversion. There are no
separators, padding bytes, or terminators.

### Root and decoding boundaries

For this singleton list, `R` is the transaction digest itself, with no extra
Merkle-parent hash. Its preimage is the 92-byte unsigned transaction: the first
six bytes are `01 00 01 00 00 00`, followed by the type tables, input, and output.
The 64 signature bytes are omitted. Consequently, `R = K1600(preimage)`.
The root's numeric bytes depend on that computation and are intentionally
symbolic in the map above.

Decoding reads the header through offset 148, obtains the transaction count,
then reads `9c 00` and decodes exactly bytes 151–306 as one transaction.
Its counts and type tags determine each nested record. Absent fields consume
zero bytes; fixed byte wrappers consume their declared sizes. Block decoding
caches the resulting transaction size (156) and digest (`R`).
