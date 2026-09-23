# Database design using arka.files

The database has three persistent parts:

1. A sequential log of serialized blocks.
2. A persistent dictionary representing the current UTXO set.
3. A sequential log of serialized block deltas.

[files.py](../arka/files.py) supplies `AsyncPersistentLog` and
`AsyncPersistentDictionary` as building blocks. [block.py](../arka/block.py)
supplies block and record codecs; [chain.py](../arka/chain.py) supplies the
initial delta types. This document describes how to assemble them. The complete
database implementation does not yet exist.

The block layouts are described in [block.1.md](block.1.md), with examples in
[block.2.md](block.2.md). [deltas.md](deltas.md) proposes delta framing. The
unique-key model here supersedes that proposal's assumption that a block may
contain repeated changes to the same key.

## Persistent representation

| Logical part | Container | Suggested files | Stored value |
| --- | --- | --- | --- |
| Blocks | `AsyncPersistentLog` | `blocks.offsets`, `blocks.values` | One block envelope containing `Block.encode()` |
| Current state | `AsyncPersistentDictionary` | `utxo.keys`, `utxo.values` | Canonical state key mapped to immutable record bytes |
| Block deltas | `AsyncPersistentLog` | `deltas.offsets`, `deltas.values` | One envelope containing the complete delta list for a block |

Three parts therefore mean six physical files with the current containers.
Log indexes remain zero-based, without prefix pruning. If genesis is entry zero,
block height equals entry index. Both logs must describe the same active prefix.
Fork archival and old-prefix pruning are separate extensions.

The state dictionary is the materialized result of applying the logged deltas.
It can be rebuilt from a defined empty pre-genesis state and the complete delta
log. Genesis must have its own complete delta entry; otherwise a separately
defined base snapshot is required.

Strictly interpreted, a UTXO dictionary stores only unspent outputs. The existing
chain model also needs rewards, funds, definitions, and votes. To retain exactly
three persistent parts, use namespaces in this same dictionary for those live
state records, or explicitly derive them from the logs. The recommended choice
is a namespaced state dictionary, still named `utxo` for its primary purpose.
No authoritative mutable collection may be omitted from undo information.

### Keys and values

A database key is a stable, typed identifier, not a Python hash:

`key_identity = (delta_type, reference)`

`key_bytes = U[1](delta_type) || canonical_reference_bytes`

`delta_type` is a small unsigned integer identifying the update type. The
one-byte encoding and numeric assignments are the proposed registry in
`deltas.md`. Keys are indexed first by delta type, then by the reference within
that type. A flat persistent dictionary represents this same identity with the
concatenated bytes above; a nested in-memory index may use
`index[delta_type][reference_bytes]`.

For a positional UTXO, the reference is the 14-byte
`UTXORefByIndex.encode()`. Definition references are 16-byte identifiers;
reward and fund references are block heights encoded as unsigned 8-byte integers.
A delta-type tag distinguishes otherwise identical references from different
update types. A UTXO position must still resolve unambiguously to its output type;
separate namespaces must not permit two live output types at the same position.

Values are immutable serialized records. Block-derived records use their
`encode()` methods; chain-only reward and fund records need codecs, as proposed
in `deltas.md`. Log entries and delta records retain original keys, even though
the dictionary itself stores only salted key digests.

Block hashes, heights, transaction positions, and optional hash-to-position
indexes can be reconstructed from the block log. Keep those indexes in memory
initially; they are accelerators rather than a fourth persistent state structure.
The active tip is derived from the committed log prefix, not a separate mutable
UTXO record.

## Deltas with unique keys

For a block at height `h`, define:

`D[h] = { key: (old_bytes | absent, new_bytes | absent) }`

Each key occurs at most once in this block's complete delta list. A replacement
is one delta containing both values, not a deletion and insertion under the same
key. Insertion has no old value; deletion has no new value. Absence differs from
empty bytes. Identical before/after values may be omitted.

Forward application checks `state[key] = old` and installs `new`.
Reverse application checks `state[key] = new` and installs `old`.
These are consistency checks, not substitutes for signature and consensus checks.

Uniqueness applies across transactions and block-generated effects, using the
full `(delta_type, reference)` identity. Two references with the same bytes but
different delta types are distinct keys. Duplicate-key detection occurs before conversion to a Python
`dict`; otherwise later entries could silently replace earlier ones.

Because the entries touch distinct keys, their assignments commute within one
block after validation. Reversal does not require reversing their internal order,
although reverse traversal remains convenient for reading chunks. Blocks must
still be reverted in reverse chain order because different blocks may share keys.

This strict model rejects two transactions spending the same UTXO, two independent
updates to the same definition, and a transaction spending an output created by
another transaction in the candidate block. The latter would insert and remove
the same key. Do not silently merge such dependent transactions into a net delta:
that would change the admission model and conceal the conflict.

Aggregate state, such as vote totals, needs an explicit treatment. Multiple votes
cannot independently emit the same aggregate key. Either represent contributions
under distinct keys or let a block-level reduction produce one validated aggregate
delta. The current vote classes do not resolve this schema decision. Reserve keys
for generated effects, or include them in the final uniqueness check.

## Pending transactions form the next block candidate

Pending transactions are not speculative writes to the persistent dictionary.
Maintain a bounded in-memory candidate attached to a particular parent tip:

```text
Candidate:
    parent_height, parent_hash
    ordered_transactions
    transaction_deltas
    reserved_keys: key -> owning transaction
    validation read dependencies
    candidate height and parameter context
```

Every admitted transaction is expected to be included in the next locally
constructed block. It is not merely a member of a larger pool from which a
subset is selected later. Admission must account for candidate block limits and
all required block-level effects. This is a construction policy, not a guarantee
that a peer's winning block will include the same transactions.

Admission has the following logical steps:

1. Read a coherent committed parent state and determine next-height parameters.
2. Validate the transaction and derive immutable before/after snapshots.
3. Reject duplicate delta keys within the transaction.
4. Check each before-image against the parent state and require its write keys
   to be disjoint from already reserved candidate keys.
5. Check read dependencies and candidate resource limits.
6. Atomically reserve its keys and publish both transaction and delta list into
   the candidate.

Uniqueness of writes alone does not ensure validity. One transaction may read a
definition or authorization record another changes. Record validation read sets;
reject conflicting write/read dependencies unless the consensus rules explicitly
specify parent-state reads, and revalidate the finalized block. Read-only sharing
is not itself a conflict. A chain-tip change invalidates the context of all
pending checks.

A candidate reservation lock protects the check-and-reserve step. Expensive
hashing or signature checks may run outside that lock against a captured tip,
but publication must verify that the tip and reservations have not changed.
No persistent dictionary writes occur during this process.

### Assigning output positions

A new output's final key requires the candidate height, transaction position,
and output position. Candidate admission can use an append-only transaction
order and reserve those positional keys immediately. Admission after a removal,
reordering, or parent-tip change must rebuild the candidate's positional deltas
and reservations. Another option is provisional transaction-hash-based identities
in memory, resolved to positional keys only at finalization.

Neither option changes the persisted positional delta key format. The candidate
must never publish a final block with stale provisional references.

## Append and revert

At a stable database boundary, for log length `n`:

`len(blocks) = len(deltas) = n`

`state = Apply(D[0], ..., D[n-1], empty_state)`

Finalization freezes transaction order, validates the complete block, adds its
generated effects, and checks uniqueness across the complete delta list. Deltas
must correspond to the exact encoded block, not merely a matching transaction
count. A received block is translated independently; local pending deltas may be
reused only after matching the block, parent context, and final positions.

The logical append is:

```text
blocks.append(serialized_block)
deltas.append(serialized_delta_list)
state.install_all_new_values(delta_list)
```

The logical revert is:

```text
state.restore_all_old_values(last_delta_list)
blocks.remove_last_entry()
deltas.remove_last_entry()
```

These equations express state effects, not a crash-safe physical write order.
A database-wide writer lock and the recovery ordering below are required.
Keep readers from observing a partially applied dictionary. A process-local
`asyncio.Lock` is sufficient only if the process is the sole database owner;
multiple processes require ownership enforcement as well.

After append or revert, discard the old candidate context. Remove transactions
included in the new tip and reconsider remaining transactions against the new
parent. Reverted transactions may be reconsidered, but are not automatically
valid or conflict-free in the rebuilt candidate.

## Log envelopes, chunks, and recovery

Use one outer entry per block in each log. A block envelope carries a format
version, height, block hash, parent hash, payload length, serialized block, and
checksum. A delta envelope repeats the identity fields and contains record count,
chunk lengths/offsets, and the checksummed chunks proposed in `deltas.md`.
Include explicit self-framing lengths so interrupted tails can be distinguished
from complete entries. A finalized binary envelope specification remains to be
implemented.

The existing log offsets provide block-level lookup. Chunk offsets provide
record-level access within the delta entry; the simplest implementation reads
that whole entry first. This avoids a separate persistent manifest. Optional
transaction-to-delta ranges can live in the delta envelope. Stable serialization
order may be transaction order followed by generated effects, since uniqueness
removes repeated-key ordering dependencies.

A practical initial recovery strategy treats the complete matching prefix of the
two logs as authoritative and rebuilds the dictionary after an unclean shutdown.
The recovery protocol requires durable writes and strict framing validation:

- **Append:** durably write the complete block entry first, then the matching
  delta entry. That complete pair is the recovery commit point. Materialize the
  dictionary before publishing the new tip to live readers or acknowledging
  success. A crash after the pair is durable may commit a block whose caller
  never received an acknowledgement; retries must identify the block hash.
- **Revert:** retain the last delta in memory, durably shorten the delta log
  first, then shorten the block log. Restore the old dictionary values before
  publishing the parent state. Recovery treats the unmatched block suffix as
  uncommitted. Do not destroy both copies of undo information before a recovery
  path exists.
- **Restart:** find the valid, identity-matching paired prefix, discard only
  interrupted/unmatched tails, and reconstruct the dictionary from that prefix.
  Corruption within previously committed history is an error, not permission
  to silently discard history.

With unique keys, a healthy partial dictionary application can also be completed
idempotently: each affected record must match either its old or new image. This
is insufficient for torn hash-table entries or interrupted resize operations;
full reconstruction is the safe initial fallback.

The paired-prefix approach avoids a fourth semantic data store. It still requires
careful tail publication: checksummed framing, synchronized file lengths, ordered
`fsync` operations, and directory synchronization where file creation or replacement
requires it. Crash-safe append/truncate may require redundant metadata or generation
markers inside the log's own storage. The current methods do not provide these
guarantees merely by returning successfully.

Compaction is optional maintenance, not part of a block commit. Retain the logs
if they are the reconstruction source. Dictionary reconstruction or compaction
may write temporary files and install a verified replacement while the database
is closed; those files remain part of the same dictionary component.

## Mapping to the current async interfaces

After correct file initialization, the relevant calls are:

```python
blocks = await AsyncPersistentLog.create(block_offsets, block_values)
deltas = await AsyncPersistentLog.create(delta_offsets, delta_values)
utxo = await AsyncPersistentDictionary.create(utxo_keys, utxo_values)

old = await utxo.get(key, None)
await utxo.__setitem__(key, new_bytes)
await utxo.__delitem__(key)
await blocks.append(block_envelope)
await deltas.append(delta_envelope)
last_delta = await deltas[-1]
count = await blocks.__len__()
await blocks.truncate(end=count - 1)
```

These are API forms, not an executable commit sequence. Python's normal `len`,
`in`, assignment, and deletion syntax does not await asynchronous special methods;
call those methods explicitly. `get` distinguishes missing keys using `None`.
`update` performs repeated sets, not a database transaction. Log `truncate`
keeps the range `[start,end)`; use only end truncation with `start_index=0` for
this initial design.

## Required corrections in files.py

The source is a useful starting point, but its atomicity claims exceed the
implemented guarantees. The following issues affect this database directly:

| Area | Observed implementation | Required work |
| --- | --- | --- |
| Fresh initialization | Constructors open files with `r+b` before `_initialize` can create them; precreating empty files skips initialization by existence checks | Create and initialize valid headers/tables before opening handle pools; distinguish fresh, empty, and corrupt storage |
| Durability | Writes and truncations call `flush()` but not `os.fsync()` | Add explicit durability barriers and a tested publication/recovery protocol |
| Concurrent append | `seek` to EOF and write occur without an internal writer lock; `append` also performs blocking I/O on the event loop | Serialize writers and move blocking operations to the executor |
| Dictionary reopen | `_load_state` derives the probing mask from item count rather than persisted table capacity | Derive mask from the validated power-of-two physical table size; resizing can leave capacity different from the count heuristic |
| Dictionary mutations | Value append, slot update, count update, and resize are separate writes | Do not treat a set/delete as atomic; recover or rebuild interrupted mutations |
| Resize | The old table is truncated before replacement is complete | Use recoverable replacement or rebuild from the logs after interruption |
| Value lengths | Slot lengths are unsigned 16-bit, but the length is packed after appending data | Reject values above 65,535 bytes before any write, or version the storage to support larger records |
| Prefix log truncation | Offsets are shifted and `start_index` is also advanced; readers add that index again | Fix the indexing model before enabling prefix pruning |
| Log compaction | New files must already exist; caches are changed without switching processors to the new files | Implement explicit creation, verified installation, and handle replacement |
| Deletion batch | `difference_update` is annotated as a list but requires a set | Align the interface; preserve strict missing-record checks for normal undo/apply |
| Handle lifetime | Cancellation may release a handle while executor work continues; `close` closes only currently queued handles | Drain in-flight work before releasing/reusing handles or closing storage |

Validate log pointer monotonicity, exact read/write lengths, checksums, file bounds,
and header consistency. The dictionary's 22-byte salted key digest is a lookup
fingerprint: original keys are not retained for collision comparison or enumeration.
For exact key identity, store original keys with records and compare them, or
explicitly adopt the probabilistic collision assumption. Rebuild from delta keys,
not by attempting to recover original keys from dictionary slots.

Dictionary replacements append new value bytes; deletion marks a slot and leaves
old values behind. Reversion therefore restores logical state without restoring
previous file sizes. Space reclamation requires a separate rebuild/compaction.

## Examples

### Distinct spends

At tip 100, state contains `A=1100` and `B=700` units. Candidate block 101 admits:

```text
T0: A -> absent; absent -> C(1000), key C=(101,0,0)
T1: B -> absent; absent -> D(600),  key D=(101,1,0)
```

The four keys `{A,C,B,D}` are distinct. Both transactions belong to the candidate;
its size reservation includes both. Amount differences are illustrative and need
to satisfy actual fee rules. Appending records the block and all four deltas,
then exposes C and D in place of A and B. Reverting restores the exact serialized
A and B values and removes C and D. Internal restore order is immaterial.

### Conflicting admission

A third transaction spending A conflicts with T0's reservation and is rejected
from this candidate. A transaction spending C also conflicts: C is created by
T0 and is not in the committed parent state. It must wait for a later block under
this model. Two updates to the same asset definition are likewise conflicting,
even if their UTXO inputs differ.

### Crash between persistent parts

Suppose both logs contain 101 entries (genesis through height 100). A new block
entry is durable, but its delta entry is incomplete. Recovery retains 101 paired
entries and discards the incomplete height-101 tail. If both entries are complete
and durable but the dictionary was only partly updated, recovery retains 102
entries and rebuilds state through height 101. Dictionary file length is never
used to infer the committed block height.

## Implementation sequence

First repair and test container initialization, reopen behavior, writer exclusion,
and exact bounds. Next implement canonical state keys and delta/envelope codecs,
then a single-writer database facade with append, revert, and full replay recovery.
Add candidate admission with atomic key reservation and read-dependency checks.
Only then optimize recovery, chunk reads, compaction, and parallel validation.

Essential tests include append/revert identity, reopen after resize, duplicate-key
rejection, candidate rebasing, output-position reassignment, and interrupted writes
at every persistence boundary. The central invariant remains:

`revert(append(state, block, deltas)) = state`

The equality concerns the complete logical database state, not identical physical
file bytes. Unique delta keys make the state transition simple; the log and
recovery layer makes that transition persistent.
