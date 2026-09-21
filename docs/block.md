# Block encoding, encapsulation, hashing, and iteration

This document describes [arka/block.py](../arka/block.py) and its calls to
[arka/crypto.py](../arka/crypto.py). It specifies canonical byte layouts with
finite sequences, tagged alternatives, integer constraints, and structural
relations. The notation is declarative and non-Turing-complete: repetition is
bounded by an encoded count or finite input extent; nesting is over finite,
acyclic values; Merkle reduction has a strictly decreasing sequence length.
There are no executable statements, general recursion, or user-defined programs.

The format describes representation. Successful decoding does not establish
signature validity, authorization, an unspent balance, or valid proof of work.
Implementation exceptions to the representation contract are listed at the end.

## Notation and primitive domains

| Notation | Meaning |
| --- | --- |
| `U[n](x)` | Unsigned integer `x` in exactly `n` bytes, little-endian; `0 <= x < 256^n` |
| `B[n]` | Exactly `n` uninterpreted bytes |
| `empty` | The zero-length byte sequence |
| `A || B` | Concatenation in the stated order |
| `E(x)` | Canonical serialized bytes of value `x` |
| `D_T(b)` | Decoding a value of type `T` from the beginning of byte sequence `b` |
| `size(x)` | Byte length of the full canonical representation |
| `p[a:b]` | Inclusive bit positions `a` through `b` of integer prefix `p`; bit zero is least significant |
| `field?flag` | The field when `flag = 1`; otherwise `empty` |
| `Concat(sequence)` | Ordered concatenation of a finite sequence; empty input yields `empty` |
| `width(x)` | Least `n >= 0` such that `x < 256^n`; `width(0) = 0` |
| `K800(b)`, `K1600(b)` | The corresponding project Keccak function with its default 32-byte output |

Every multi-byte integer, including a multi-byte prefix, is little-endian.
There is no alignment padding, global version field, or global object tag.
The enclosing field or type table determines the interpretation of a payload.
Unassigned prefix bits and unused type-table slots are zero in canonical output.

`K800` and `K1600` name the project functions, not interchangeable standard-library
SHA-3 operations. Their numeric suffixes identify the underlying permutation;
both return 32 bytes in this module.

### Fixed-size byte values

| Type | Size |
| --- | ---: |
| `SignerHash`, `SignerKey`, `TransactionHash` | 32 |
| `BlockHeaderHash`, `BlockHash`, `TransactionListHash` | 32 |
| `Nonce_32` | 32 |
| `Nonce_16` | 16 |
| `Signature` | 64 |

For each fixed-size type, `E(x) = x.value`. The type is not encoded inside the
bytes. A decoder requires at least the fixed size and reads only that prefix.

### Optional integers

The enclosing prefix supplies a four-bit byte count `n`, in `0..15`.

| Value | `n` | Payload |
| --- | ---: | --- |
| Absent (`None`) | 0 | `empty` |
| Zero | 1 | `00` |
| Positive `x` | `width(x)` | `U[n](x)` |

The maximum represented positive value is `2^120 - 1`. Negative values are
outside the domain. Present `units` values must be positive. Optional vote
parameters may be zero. Required parameter amounts use the separate zero rule
specified under `Parameters`.

### Memo fields

The enclosing prefix supplies the memo-length width `m`.

| `m` | Meaning | Memo field |
| ---: | --- | --- |
| 0 | Absent memo | `empty` |
| 1 | `1 <= L <= 255` | `U[1](L) || B[L]` |
| 2 | `256 <= L <= 65535` | `U[2](L) || B[L]` |
| 3 | Invalid | No representation |

A present, empty memo is invalid. Memo bytes are opaque; the codec does not
interpret or execute them. `Memo(m)` below denotes both the length and payload.

## Signer representations

### SignerList

Let `N` be the number of children and `T` the threshold, with
`1 <= T <= N <= 32767`. The compact count relation is:

| Domain | `Count(x)` |
| --- | --- |
| `1 <= x < 128` | `U[1](2*x)` |
| `128 <= x <= 32767` | `U[2](2*x + 1)` |

The low bit selects the width; the remaining bits contain the count.

`E(list) = Count(N) || Count(T) || types || Concat(E(children))`

`types` has `ceil(N/4)` bytes. Child `i` occupies two bits beginning at
`2*(i mod 4)` in byte `floor(i/4)`.

| Tag | Child |
| ---: | --- |
| 0 | `SignerHash` |
| 1 | `SignerKey` |
| 2 | Nested `SignerList` |
| 3 | Invalid |

Children retain list order. A nested list occupies its complete encoding;
there is no separate child-length table.

### SignerLocked

`E(x) = U[1](p) || E(hash_lock) || E(hash_locked_signer) || U[4](time_lock) || E(time_locked_signer)`

`hash_lock` is `Nonce_32`. Each signer is either `SignerHash` or `SignerList`.
Bit 0 selects the hash-locked signer; bit 1 selects the time-locked signer.
For either selector, `0 = SignerHash`, `1 = SignerList`.
The serialized time lock is an unsigned 32-bit integer.

### Context-dependent signer tags

| Context | Tags |
| --- | --- |
| Required definition signer | `0 = SignerKey`, `1 = SignerList` |
| Optional input signer | `0 = SignerKey`, `1 = SignerList`, `2 = SignerLocked`, `3 = absent` |
| Output signer | `0 = SignerKey`, `1 = SignerHash`, `2 = absent`, `3 = invalid` |
| Header publisher | `0 = SignerKey`, `1 = SignerHash` |

An absent signer contributes no payload bytes. `BlockSpend` constructors restrict
present signers to a key or list, although their shared optional-signer decoder
also recognizes the locked tag.

## Transaction input layouts

### UTXO references

| Type | Layout | Size |
| --- | --- | ---: |
| `UTXORefByIndex` | `U[8](block) || U[4](tx) || U[2](output)` | 14 |
| `UTXORefByHash` | `E(tx_hash) || U[2](output)` | 34 |

### Input records

All input prefixes below occupy one byte. A named signer payload is selected
by the corresponding prefix bits.

| Record | Payload following prefix |
| --- | --- |
| `UTXOSpend` | `E(utxo) || U[4](time_lock)?present || E(signer) || Memo(m)` |
| `PublisherSpend`, `ExecutiveSpend` | `U[8](block) || E(signer) || Memo(m)` |
| `ExecutiveDefinition` | `E(executive) || E(signer) || E(new_signer)?present || Memo(m)` |
| `AssetDefinition` | `E(asset) || E(signer) || E(new_signer)?present || Memo(m)` |

`executive` and `asset` are `Nonce_16`; `new_signer` is `SignerHash`.

| Record | Prefix bit allocation |
| --- | --- |
| `UTXOSpend` | `[0]`: reference tag (`0 = index`, `1 = hash`); `[1]`: time-lock presence; `[2:3]`: optional signer; `[4:5]`: `m` |
| `PublisherSpend`, `ExecutiveSpend` | `[0:1]`: optional signer; `[2:3]`: `m` |
| `ExecutiveDefinition` | `[0]`: required signer; `[1]`: new-signer presence; `[2:3]`: `m` |
| `AssetDefinition` | Same as executive definition; `[4]`: Boolean `lock` |

A present `UTXOSpend.time_lock` lies in `1..2^32-1`. The asset lock has no
additional payload. Publisher and executive spends have identical payload
layouts; their enclosing transaction tags distinguish them.

## Transaction output layouts

| Record | Prefix size | Payload following prefix |
| --- | ---: | --- |
| `ArkaUTXO` | 3 | `E(signer) || units || block_reward || exec_fund || utxo_fee || data_fee || Memo(m)` |
| `AssetUTXO` | 1 | `E(asset) || E(signer) || units || Memo(m)` |
| `ExecutiveVote` | 1 | `E(executive) || units || Memo(m)` |

Integer payload widths are supplied by the prefix. Asset and executive
identifiers are `Nonce_16`.

| Record | Prefix bit allocation |
| --- | --- |
| `ArkaUTXO` | `[0:1]`: output signer; `[2:5]`: units width; `[6:9]`: reward width; `[10:13]`: fund width; `[14:17]`: UTXO-fee width; `[18:21]`: data-fee width; `[22:23]`: `m` |
| `AssetUTXO` | `[0:1]`: output signer; `[2:5]`: units width; `[6:7]`: `m` |
| `ExecutiveVote` | `[0]`: Boolean `promote`; `[1:4]`: units width; `[5:6]`: `m` |

## Transaction and transaction-list envelopes

For input count `I`, output count `O`, and signature count `S`:

`E(tx) = U[2](I) || U[2](O) || U[2](S) || input_types || output_types || Concat(E(inputs)) || Concat(E(outputs)) || Concat(E(signatures))`

Each count lies in `0..65535`. `input_types` has `ceil(I/2)` bytes;
`output_types` has `ceil(O/4)` bytes. Both tables precede all record payloads.
Input `i` occupies the four-bit slot starting at `4*(i mod 2)` in byte
`floor(i/2)`. Output `i` occupies the two-bit slot starting at `2*(i mod 4)`
in byte `floor(i/4)`.

| Input tag | Record | Output tag | Record |
| ---: | --- | ---: | --- |
| 0 | `PublisherSpend` | 0 | `ArkaUTXO` |
| 1 | `ExecutiveSpend` | 1 | `AssetUTXO` |
| 2 | `UTXOSpend` | 2 | `ExecutiveVote` |
| 3 | `AssetDefinition` | 3 | Invalid |
| 4 | `ExecutiveDefinition` | | |

Other canonical input tags are invalid. Signatures have no type table and each
occupies 64 bytes. Signature count is independently represented; this codec
does not enforce correspondence between signatures and keys.

`size(tx) = 6 + ceil(I/2) + ceil(O/4) + sum(size(inputs)) + sum(size(outputs)) + 64*S`

The unsigned transaction representation, `E_unsigned(tx)`, has `S = 0` and no
signature payload. All other fields retain their ordinary encoding.

`E(TransactionList) = Concat(E(transactions))`

A standalone transaction list contains no count or length table. Its supplied
buffer is its complete extent. It is empty exactly when that extent is empty.

## Parameters and block header

### Parameters

`E(parameters) = U[2](p) || U[1](mantissa) || U[1](exponent) || block_reward || exec_fund || utxo_fee || data_fee || E(executive)`

Prefix nibbles `[0:3]`, `[4:7]`, `[8:11]`, and `[12:15]` contain the respective
amount widths. These required amounts use width zero for numeric zero; positive
amounts use their minimal widths, at most 15. A nonempty zero amount is rejected
by the decoder. `executive` is `Nonce_16`.

The target relations are:

`exponent = max(0, bit_length(target) - 8)`

`mantissa = floor(target / 2^exponent)`

`decoded_target = mantissa * 2^exponent`

The admitted constructor domain is `0..255*2^255`. Exact value inversion requires
`target = decoded_target`; arbitrary integers in that domain may be rounded
down by encoding. Canonical target bytes are those produced by the relations
above from their decoded value. `Parameters.__eq__` compares encoded targets,
so objects with different numeric targets can nevertheless compare equal when
those targets have the same compact representation.

### BlockHeader

`E(header) = U[1](p) || U[8](id) || U[8](timestamp) || E(prev_block) || E(publisher) || transaction_fields || E(parameters)?parameters_present || E(nonce)?nonce_present`

| Prefix bit | Meaning |
| ---: | --- |
| 0 | Publisher tag |
| 1 | Transaction fields present |
| 2 | Parameters present |
| 3 | Nonce present |

`prev_block` is `BlockHash`; `nonce` is `Nonce_32`.
When transaction fields are present, they are
`U[4](ntxs) || E(root_hash)`, with `1 <= ntxs <= 2^32-1` and
`root_hash: TransactionListHash`. Otherwise both fields are absent and both
object attributes are `None`. The minimal header size is 81 bytes.
The codec assigns no additional interpretation to the timestamp integer.

`E_without_nonce(header)` omits the nonce payload and clears prefix bit 3.
It is not simply a full header with its last 32 bytes removed.

## Block and summary envelopes

### Block

Let `N` be `header.ntxs`, treating absence as zero, and let `L[i]` be the
encoded length of transaction `i`.

`E(block) = E(header) || Concat(U[2](L[i]), 0 <= i < N) || Concat(E(tx[i]), 0 <= i < N)`

The length table precedes all transactions. Each `L[i] < 65536`.
The header count equals the transaction-list length. A nonempty block requires
a root hash; an empty block has neither a count nor a root-hash field.
Encoding checks presence and count, but does not recompute the root hash.

`size(block) = size(header) + 2*N + sum(L[i])`

With `H = size(header)`, transaction offsets satisfy:

`offset[i] = H + 2*N + sum(L[j], 0 <= j < i)`

Transaction `i` occupies exactly `[offset[i], offset[i] + L[i])`.
Decoding requires every slice to be available and its decoded transaction size
to equal the declared length. Bytes after the last declared transaction are
outside the decoded block and may remain in the supplied buffer.

### BlockSummary

A summary contains a header and an ordered sequence of integer IDs, whose count
equals the header transaction count. IDs replace transaction bodies; the codec
does not define their external lookup semantics.

| Count | Canonical layout |
| --- | --- |
| `N = 0` | `E(header)` |
| `N = 1` | `E(header) || U[1](b) || U[b](base)` |
| `N > 1` | `E(header) || U[1](b + 16*d) || U[b](base) || Concat(U[d](id[i] - base), 0 <= i < N)` |

Here `base = min(ids)`, `b = width(base)`, and
`d = width(max(ids) - base)`. IDs are nonnegative and `b,d <= 15`.
Zero-width base or delta fields contribute no bytes. If all IDs are equal,
`d = 0` and every reconstructed ID equals `base`. Input order is retained.
This describes the inverse format contract; the current implementation has the
summary exceptions recorded below.

## Decoding and encapsulation contract

For a canonical value `x` and its canonical bytes `b = E(x)`:

`D_type(x)(E(x)) = x`

`E(D_type(x)(b)) = b`

Equality here concerns represented fields. Cached sizes and digests are not
wire fields. Exact numeric-field recovery is restricted to representable targets;
Python parameter equality instead uses compact-target equivalence. Byte
inversion is restricted to canonical encodings. It does not assert that every byte string accepted by a
permissive decoder re-encodes unchanged.

Single-value decoders operate on a buffer prefix. For an allowed trailing
sequence `r`, their contract is `D_T(b || r) = D_T(b)`, with consumed length
`size(D_T(b)) = length(b)`. A standalone `TransactionList.decode` instead treats
the entire supplied buffer as a transaction stream; arbitrary trailing data is
not ignored. No public decoder returns a separate consumed-length value.

The accepted input containers are `bytes`, `bytearray`, and byte-oriented
`memoryview`. Encoded results are immutable `bytes`. Fixed-size byte wrappers
copy mutable input into `bytes`; decoded memos are also copied into `bytes`.
Source-buffer mutation after completed decoding therefore does not change
retained byte fields. A caller must keep an input buffer stable during decoding,
including across asynchronous suspension points.

The intended ownership contract extends to constructor-supplied byte streams:
retained values are independent of mutable source buffers. The current memo
constructor exception is identified below. Object fields and Python lists are
mutable and are not generally defensively copied. Their use assumes exclusive
ownership and no changes affecting a cached representation.

`Transaction.decode` may receive a supplied `digest`; it does not verify that
digest against the decoded content. Ordinary decoding does not populate the size
cache. Block decoding computes each transaction digest and stores both that
digest and its exact slice length. `Transaction.hash()` and `Transaction.size`
subsequently use these values when present. Cache validity requires the relevant
represented fields to remain unchanged; there is no automatic invalidation.

## Hash relations

All digest payloads below are 32 bytes. Hash type wrappers are not part of the
preimage. No additional domain-separation tags are added by these methods.

### Signers

Define `S(x)` over a finite signer tree:

| Signer | Digest payload `S(x)` |
| --- | --- |
| `SignerHash` | Existing `value` |
| `SignerKey` | `K800(value)` |
| `SignerList` | `K1600(U[2](N) || U[2](T) || Concat(S(children)))` |

List hashing uses fixed-width counts rather than the compact wire counts and
omits the wire type table. Substitution of a child by its corresponding
`SignerHash` preserves the parent digest.

For `SignerLocked`, let `A` be the hash-locked signer and `B` the time-locked
signer. Define `lock_digest = hash_lock.value` when `A` is a hash, and
`lock_digest = K800(hash_lock.value)` when `A` is a list.

`locked_digest = K1600(lock_digest || S(A) || U[4](time_lock) || S(B))`

The result is wrapped in `SignerHash`. The hash-lock transformation depends on
the representation of `A`.

### Transactions and lists

`transaction_digest = K1600(E_unsigned(tx))`, wrapped in `TransactionHash`.

A supplied or cached digest takes precedence over computation. Signature bytes
and the original nonzero signature count are excluded from this digest.

For list leaves `h[i] = transaction_digest(tx[i])`, an empty list has no digest
(`None`). In flat mode, a nonempty list has digest `K1600(Concat(h))`.
In Merkle mode, which is the default, define finite levels:

`level[0] = h`

`length(level[k+1]) = ceil(length(level[k])/2)`

`level[k+1][j] = K1600(level[k][2*j] || level[k][min(2*j+1, length(level[k])-1)])`

The root is the sole element of the first singleton level and is wrapped in
`TransactionListHash`. An odd final node is paired with itself. A single leaf is
returned without an additional hash. For `N >= 1`, reduction requires
`ceil(log2(N))` levels after the leaves. Flat and Merkle digests are distinct
conventions; the wire format carries no mode tag.

### Headers and blocks

`header_digest = K1600(E_without_nonce(header))`, wrapped in `BlockHeaderHash`.

`block_digest = K800(header_digest || nonce.value)`, wrapped in `BlockHash`.

The nonce is required for `hash_nonce()`. A block hash commits to the header's
root field rather than directly hashing the block length table and bodies.
`Block.hash()` computes the default Merkle root and verifies the header count
and root. With `update_header=True`, it replaces those two fields before
computing the block digest. It does not verify signatures or a work target.

### Python hashability

Python `hash(x)` and asynchronous `x.hash()` have separate meanings.
`AbstractElement.__hash__` expresses `hash(E(x))`, a Python hash-table value,
not a persistent cryptographic identifier. Appropriate value objects used as
set members or dictionary keys require equality-compatible Python hashes and
stable represented state during membership. Current subclass behavior is noted
below; the presence of the base method alone does not establish hashability.

## Finite iteration and ordering

| Operation | Iteration extent and order |
| --- | --- |
| Signer serialization and hashing | Child order; structural descent into finite nested lists |
| Transaction serialization | Input order, then output order, then signature order |
| Transaction decoding | Counts bound each sequence; each next offset follows the previous encoded extent |
| Standalone list decoding | Consecutive transactions until the supplied extent is exhausted; each transaction consumes at least six bytes |
| Block decoding | Exactly the header count of slices specified by the length table |
| Summary decoding | Exactly the header count of IDs, retaining their original order |
| Merkle reduction | Adjacent pairs in each finite level; repeated last node for odd length |

`SignerList.keys` traverses children in order. Each direct key contributes one
to its threshold count; each successfully expanded child list contributes one;
a hash-only child contributes zero. Every visited child list must itself yield
keys. The count must meet the current list's threshold. Flattened keys are
then deduplicated by byte value while preserving first occurrence. This count
is taken before deduplication and is not a count of distinct keys.

`SignerLocked.keys` concatenates the keys of the hash-locked list, if present,
then those of the time-locked list, if present, with stable deduplication. Two
hash-only branches produce an error. `TransactionInput.keys` exposes its
signer's keys and raises an error for no signer; `Transaction.keys` concatenates
input keys in input order and applies the same stable deduplication. These
operations enumerate represented keys; they do not evaluate lock conditions.

`TransactionList` has no Python `__iter__` method. Its stored sequence is
`transactions`; a block exposes that sequence as `block.transactions.transactions`.

Hash coroutines are submitted together through `gather`. The crypto wrappers
submit C operations to an executor, and the C hashing functions release the GIL.
Independent operations within a batch can therefore run in parallel, subject to
executor capacity. Gathered results retain input order. Merkle levels depend on
preceding levels and cannot be evaluated independently. Block transaction
slices can be decoded and hashed concurrently; within a slice, parsing retains
field order. Scheduling does not alter any byte or digest relation above.

## Current implementation exceptions

The following observations describe the implementation inspected for this
document. They distinguish the canonical contract from accepted input and
runtime behavior; they do not define alternative canonical encodings.

- Several decoders ignore reserved bits or accept nonminimal integer widths.
  `SignerList.decode` accepts nonminimal compact counts, and transaction input
  decoding masks only three bits of each four-bit slot. Consequently, acceptance
  alone does not establish byte-for-byte canonicality. Nested offset accounting
  uses reconstructed sizes and assumes canonical widths.
- Parameter targets lose low bits unless exactly representable by the compact
  target relation. Thus unrestricted constructor values do not satisfy exact
  numeric-field inversion, although equality compares their encoded targets.
- `TransactionElement.__init__` retains its memo argument directly. Mutable
  constructor memos therefore do not yet satisfy the stated ownership contract,
  although decoded memos and fixed-size byte wrappers do.
- Concrete classes override equality without explicitly restoring the base
  `__hash__`; Python consequently makes those classes unhashable. Cryptographic
  `.hash()` methods remain separate and available where defined.
- `Block.size` multiplies `header.ntxs` directly; an empty block uses `None` and
  therefore does not currently satisfy the size equation.
- `BlockSummary.encode` computes base width as `ceil(base/8)` rather than
  `width(base)`. Its decoder also uses a zero range step for multiple equal IDs.
  These cases do not implement the summary inverse contract above.
- `BlockSpend.encode` passes an absent memo directly to byte concatenation.
  A memo-free publisher or executive spend therefore currently fails encoding.

The contract tests reside in [tests/test_block.py](../tests/test_block.py).
