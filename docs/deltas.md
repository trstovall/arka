# Indexed, reversible delta lists

This document proposes a storage representation for translating accepted blocks
into ordered, chunked database changes. It is a design specification, not an
implemented interface in [chain.py](../arka/chain.py).

[block.1.md](block.1.md) defines the block codecs and hashes;
[block.2.md](block.2.md) provides the concrete data definitions and example
transfer; [chain.1.md](chain.1.md) describes the existing delta classes.
The storage framing below is new and does not change the block wire format.

## Translation model

A block contains instructions and new outputs. The database supplies the records
those instructions consume or replace. Translation therefore depends on both:

`Translate(parent_state, block) = ordered_delta_list`

Each delta is a before/after change:

`Delta(collection, key, old_bytes | absent, new_bytes | absent)`

| Before | After | Change |
| --- | --- | --- |
| Absent | Value | Insert |
| Value | Absent | Delete |
| Value A | Value B | Replace |

Absence is distinct from an empty value or a numeric zero. Equal before/after
values and two absent values are omitted. Snapshots are immutable byte strings,
not references to mutable `block.py` objects. A delta records the exact previous
stored bytes so reversal restores the previous representation as well as its value.

Application requires the current record to equal `old_bytes`; it then installs
`new_bytes`, or removes the record when the new value is absent. Reversal requires
the current record to equal `new_bytes` and restores `old_bytes`. A mismatch is a
state conflict and must abort the application unit.

## From transactions to deltas

Translation operates against a private working state initially equal to the
parent state. Transactions are considered in block order. Each transaction is
validated against that working state, and its successful changes become visible
to subsequent transactions. Rejected transactions invalidate block translation;
no partial result becomes the active database state.

The following ordering is part of this proposal:

1. Pre-transaction effects required by the chain's validation rules.
2. For each transaction: input effects in input order, output effects in output
   order, then transaction lookup-index changes.
3. Post-transaction effects, including applicable reward, fund, parameter, and
   expiration changes.
4. The chain-tip change, last.

This order does not establish new monetary or authorization rules. In particular,
new reward records must not become spendable earlier than consensus permits.
A transaction validates all of its effects before adding them to the working
state. Duplicate spends and conflicting replacements must be rejected rather
than made valid by overlapping old snapshots.

| Block element | Delta translation |
| --- | --- |
| `PublisherSpend` | Look up its block reward; capture and remove the consumed record |
| `ExecutiveSpend` | Look up its executive fund; capture and remove the consumed record |
| `UTXOSpend` | Resolve its reference; capture and remove the ARKA or asset UTXO |
| `ExecutiveDefinition` | Capture any prior definition; install the validated resulting definition |
| `AssetDefinition` | Capture any prior definition; install the validated resulting definition |
| `ArkaUTXO` output | Insert at `(block.header.id, transaction_position, output_position)` |
| `AssetUTXO` output | Insert at the same positional form in the asset collection |
| `ExecutiveVote` output | Capture and replace the record determined by the vote-state rule |
| Header and active parameters | Produce applicable reward, fund, parameter, and tip changes |

Definitions and votes require their actual consensus transition rules; blindly
copying an input or overwriting an executive's vote record is not a substitute.
`chain.py` does not yet define vote aggregation or all block-level effects.
A translator must report unsupported effects rather than publish an incomplete
list as the reversible change for a whole block.

A hash-based UTXO reference is normalized through the transaction-position index
before forming the UTXO delta key. A transaction alone cannot supply its eventual
positional output keys: block height and transaction position are also required.

All authoritative state affected by acceptance must be covered, including lookup
indexes and the chain tip. A derived cache may instead be invalidated and rebuilt
if it is explicitly excluded from authoritative state. Immutable archived blocks
and delta chunks need not be deleted when a block is disconnected.

## Serialized delta records

All integers below are unsigned and little-endian. `U[n]` occupies `n` bytes;
`B[n]` is exactly `n` bytes; `||` denotes concatenation. No alignment padding
is present. Length limits are checked before allocation or slicing.

```text
record =
    collection: U[1]
 || presence:   U[1]
 || key_len:    U[2]
 || old_len:    U[4]
 || new_len:    U[4]
 || key:        B[key_len]
 || old:        B[old_len]
 || new:        B[new_len]
```

Presence bit 0 denotes an old value; bit 1 denotes a new value. Bits 2–7 are
zero. An absent value has length zero; a present value may have length zero
only if its collection codec permits an empty value. Thus flags `01`, `02`,
and `03` mean deletion, insertion, and replacement respectively.

`record_size = 12 + key_len + old_len + new_len`

Each decoder consumes its complete bounded record slice. Unknown collection
tags, reserved bits, inconsistent lengths, and surplus bytes are rejected.
There is no implicit Python object hash or pickle representation.

### Version 1 collection registry

The numeric tags below are proposed storage tags, not transaction type tags.

| Tag | Collection | Key bytes | Value bytes |
| ---: | --- | --- | --- |
| 1 | Publisher rewards | `U[8](height)` | Publisher tag `U[1]` (`0=key`, `1=hash`), 32 publisher bytes, `U[15](units)` |
| 2 | Executive funds | `U[8](height)` | `U[15](units)` |
| 3 | ARKA UTXOs | `UTXORefByIndex.encode()` (14 bytes) | `ArkaUTXO.encode()` |
| 4 | Asset UTXOs | `UTXORefByIndex.encode()` (14 bytes) | `AssetUTXO.encode()` |
| 5 | Executive definitions | 16 identifier bytes | `ExecutiveDefinition.encode()` |
| 6 | Asset definitions | 16 identifier bytes | `AssetDefinition.encode()` |
| 7 | Executive votes | 16 executive identifier bytes | `ExecutiveVote.encode()` |
| 8 | Transaction positions | 32 transaction-hash bytes | `U[8](height) || U[4](transaction_position)` |
| 9 | Epoch parameters | `U[8](epoch)` | `Parameters.encode()` |
| 10 | Active tip | One byte `00` | `U[8](height) || B[32](block_hash)` |

Tags 1–7 correspond to the delta classes in `chain.py`; tags 8–10 extend that
model to cover supporting state. Tag 7 describes the currently declared
identifier-keyed record shape, not an aggregation policy. A different vote schema
requires a registry revision. Conflicting transaction-hash index entries require
an explicit uniqueness policy; they must not silently overwrite another position.

New values use canonical codecs. Before-images are copied from stored bytes.
When reading a value, the collection determines its type and the entire value
slice must be consumed. Canonicality and existing codec limitations remain as
described in `block.1.md`; this framing does not repair those implementations.

## Chunk framing

A chunk is a finite consecutive segment of one block's delta list. Records never
straddle chunks. The envelope contains offsets for direct access in either order:

```text
chunk =
    magic:        B[4] = ASCII "ADLT"
 || version:      U[2] = 1
 || flags:        U[2] = 0
 || record_count: U[4] = N
 || payload_len:  U[8] = P
 || offsets:      U[8] repeated N+1 times
 || payload:      B[P]
 || checksum:     B[32]
```

Offsets are relative to the start of `payload`. `offset[0]=0`,
`offset[N]=P`, and every consecutive pair is strictly increasing. Record `i`
is exactly `payload[offset[i]:offset[i+1]]`. The checksum is the project's
32-byte `keccak_1600` digest of all preceding chunk bytes, including the offsets.

`chunk_size = 20 + 8*(N+1) + P + 32`

A chunk must contain at least one record. An empty list has zero chunks. Normal
chunks are packed greedily in delta order up to a configured total encoded-byte
budget (for example, 1 MiB). A record that cannot fit by itself occupies one
oversized chunk, subject to a separate hard record-size limit; exceeding that
limit fails translation. These limits are recorded as storage configuration,
not consensus rules. Rechunking preserves the ordered delta sequence.

A transaction may span chunks. Chunk boundaries are storage boundaries, not
validation, commit, or rollback boundaries.

## Index and block manifest

Each block has a manifest with the following logical fields. The manifest's
physical encoding is outside the chunk format above and must be versioned by
the chosen storage backend.

```text
BlockManifest:
    format_version
    block_height, block_hash, parent_block_hash
    delta_count
    chunks: ordered (locator, byte_length, checksum, first_ordinal, record_count)
    transactions: ordered (transaction_position, transaction_hash, start, stop)
    pre_effects:  [start, stop)
    post_effects: [start, stop)
    tip_effects:  [start, stop)
```

All ranges use global delta ordinals, zero-based with an exclusive end.
Transaction ranges may be empty. Together the phase and transaction ranges
partition the complete list in order. Chunk ordinal ranges also partition the
same list, independently of transaction boundaries.

| Index | Lookup result |
| --- | --- |
| Block hash | Manifest for that specific block, including disconnected forks |
| Active height | Active block hash at that height |
| `(block_hash, transaction_position)` | Transaction's global delta range |
| `(block_hash, delta_ordinal)` | Chunk descriptor and local record number |
| Optional `(collection, key)` history | Ordered `(block_hash, delta_ordinal)` references |

For ordinal `g` in a chunk beginning at `f`, the local record number is `g-f`.
Its physical start is `chunk_start + 20 + 8*(N+1) + offset[g-f]`.
The next offset determines its length. Locators and checksums bind reads to the
intended chunk. Manifest totals, contiguous ranges, lengths, and checksums must
be verified before applying a block. Checksums detect corruption; trusted parent
state and validation establish correctness.

Height alone is not a fork-safe identity. Transaction hashes likewise do not
replace the enclosing block identity for archive indexing. Archive indexes
locate retained data; active-chain indexes change atomically with connection or
disconnection of the block.

## Forward application and reversal

Connecting a block requires that the active tip match its manifest's parent.
Apply deltas in increasing ordinal order, checking every before-image. Publish
the new tip and active-height mapping only with successful completion of the
whole block. The tip delta must agree with the manifest identities.

Disconnecting requires that the active tip be that block. Read chunks in reverse
order and records within each chunk in reverse order. For each record, check
its after-image and restore its before-image. Restore the parent tip and active
indexes with the same atomic visibility guarantee.

This reverse traversal needs no alternate delta representation and no reexecution
of transaction validation. Undo data is already present. Reading a transaction
range independently is useful for inspection, but undoing it in isolation may
violate later dependencies and is not generally permitted.

Immutable chunk writes must be durable before their manifest is published.
A database transaction or recovery journal must make state changes and active
index publication atomic. A crash must expose either the complete parent state
or complete child state, never a partly applied chunk sequence. Unpublished
chunks may be garbage-collected. The persistence backend implementing these
guarantees is not selected by this proposal.

## Example 1: one input and one output

Use the transfer from `block.2.md`: block 101 spends `(100,0,0)` and creates
`(101,0,0)`. For illustration, the database's old output contains 1,100 units,
no memo or votes, and signer hash `aa` repeated 32 times. The new output contains
1,000 units with signer hash `22` repeated 32 times. Both serialize to 37 bytes.
The difference is illustrative; actual fees and signatures require validation.

```text
D0 = ARKA[(100,0,0)]: old_output -> absent
D1 = ARKA[(101,0,0)]: absent -> new_output
```

Exact record layouts, with hexadecimal bytes and `xx*32` denoting repetition:

```text
D0:
  03 01 0e 00 25 00 00 00 00 00 00 00   # tag, flags, key/old/new lengths
  64 00 00 00 00 00 00 00 00 00 00 00 00 00  # (100,0,0)
  09 00 00 aa*32 4c 04                   # old ArkaUTXO: 1100 units

D1:
  03 02 0e 00 00 00 00 00 25 00 00 00
  65 00 00 00 00 00 00 00 00 00 00 00 00 00  # (101,0,0)
  09 00 00 22*32 e8 03                   # new ArkaUTXO: 1000 units
```

Each record occupies `12+14+37=63` bytes. Packed together, `N=2`, `P=126`,
offsets are `[0,63,126]`, and total chunk size is `20+24+126+32=202` bytes.
The payload begins at chunk byte 44: D0 occupies `[44,107)`, D1 `[107,170)`,
and the checksum `[170,202)`.

With a demonstration chunk budget of 160 bytes, each record instead occupies its
own 131-byte chunk (`20+16+63+32`). Their first ordinals are 0 and 1, each with
offsets `[0,63]`. A transaction range `[0,2)` spans both chunks without changing
its semantics. A practical budget would ordinarily keep these records together.

Forward application removes the old UTXO and inserts the new one. Reverse
application removes `(101,0,0)` first, then restores the exact 1,100-unit value
at `(100,0,0)`. These two records are only the UTXO portion; a complete block list
also includes applicable index, reward, and tip changes.

## Example 2: dependent transactions and reverse order

If consensus permits a later transaction in a block to spend an earlier output,
its deltas observe the earlier transaction's working-state changes:

```text
Transaction 0, range [0,2):
    D0: A = old_A -> absent
    D1: B = absent -> value_B
Transaction 1, range [2,4):
    D2: B = value_B -> absent
    D3: C = absent -> value_C
```

Reverse order is `D3, D2, D1, D0`: remove C, restore B, remove B, restore A.
Applying inverse D1 before inverse D2 would expect B to exist when it is absent.
Consequently, swapping snapshots without reversing sequence order is incorrect.
Even though B is absent at both block boundaries, retaining D1 and D2 preserves
transaction attribution and intermediate-state validation.

## Implementation work implied by this specification

The repository still needs a translator, canonical delta codecs, chunk writer
and reader, manifest/index storage, and atomic apply/undo operations. Existing
`Chain` stubs do not supply these facilities. `BlockRewardUpdate` also needs to
retain its `old` and `new` fields before it can serve as a translation record.
Unspecified consensus effects must be completed independently of storage framing.

Round-trip record/chunk tests, index-boundary tests, corruption rejection,
repeated-key reversal, and interrupted-commit recovery are the essential checks
for an implementation. The defining state property is:

`Undo(Apply(parent_state, deltas), deltas) = parent_state`

It applies to all authoritative state covered by the block, not only UTXO rows.
