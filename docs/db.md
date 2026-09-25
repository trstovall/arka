# Database design using arka.files

The database has five chain stores and four parameter vote stores:

1. `db/blocks`: a sequential log of completed serialized blocks.
2. `db/utxos`: a persistent dictionary of unclaimed transaction outputs.
3. `db/deltas`: a sequential log of UTXO updates partitioned by block.
4. `db/pow`: a sequential log of POW records from those block headers.
5. `db/vote_deltas`: a sequential log of transaction-derived vote updates, partitioned by block.
6. `db/block_reward`, `db/exec_fund`, `db/utxo_fee`, and `db/data_fee`: materialized vote state for each governed parameter.

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

| Database | Container | Contents |
| --- | --- | --- |
| `db/blocks` | `AsyncPersistentLog` | One completed block envelope per height |
| `db/utxos` | `AsyncPersistentDictionary` | Typed UTXO reference mapped to unclaimed output bytes |
| `db/deltas` | `AsyncPersistentLog` | One complete UTXO delta envelope per block |
| `db/pow` | `AsyncPersistentLog` | One 96-byte `POW.encode()` payload per block header |

Log and UTXO stores use `index` and `values`; parameter stores use `manifest` and `values`:

```text
db/
    blocks/{index,values}
    utxos/{index,values}
    deltas/{index,values}
    pow/{index,values}
    vote_deltas/{index,values}
    block_reward/{manifest,values}
    exec_fund/{manifest,values}
    utxo_fee/{manifest,values}
    data_fee/{manifest,values}
```

For a persistent log, `index` is the offsets file. For the persistent dictionary,
`index` is the hash-table keys file. These names require no container-format
change: `files.py` accepts both backing paths as arguments. The nine stores use eighteen backing files. Parameter manifest semantics are described below.

Log indexes remain zero-based, without prefix pruning. Genesis is entry zero;
height equals log index. At every published state all four logs have the same
length, and the dictionary represents exactly that prefix. A block's POW is
retained in its header and duplicated in `db/pow` for direct chain lookup.

For a nonempty canonical database:

`tip_height = len(pow_log) - 1`

`tip_hash = POW.decode(pow_log[tip_height]).final_hash`

The final hash's 32 payload bytes identify the tip. Empty stores represent the
pre-genesis state and have no tip. The application must compare digest bytes
across `Nonce_32` and `BlockHash` wrappers, whose Python equality is type-sensitive.

At each height, the POW log value must equal the completed block header's POW.
Its initial hash must equal the header hash excluding POW, and its final hash
must equal `keccak_800(initial_hash || nonce)`. Each non-genesis header's
`prev_block` equals the preceding POW's final hash. These hash relations alone
do not validate difficulty or transaction state.

The UTXO dictionary can be rebuilt from the complete delta log and a defined
empty pre-genesis state. Genesis therefore requires a complete delta entry.
Keep `db/utxos` restricted to unclaimed outputs: derive definitions, parameters,
rewards, funds, and executive-selection context from the completed block prefix into branch-local
indexes until their persistence is explicitly specified. The general delta
registry in `deltas.md` is broader than this UTXO log. Non-UTXO context must be
restored or rebuilt whenever the branch changes; a UTXO rollback alone is not
sufficient validation state.

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
`UTXORefByIndex.encode()`. Only UTXO update types are persisted in this
dictionary; other delta types belong to the broader chain model.
A delta-type tag distinguishes otherwise identical references from different
update types. A UTXO position must still resolve unambiguously to its output type;
separate namespaces must not permit two live output types at the same position.

Values are immutable serialized outputs using their `encode()` methods.
Non-UTXO records from the broader `deltas.md` proposal remain derived validation
context in this design. Log entries and delta records retain original keys, even though
the dictionary itself stores only salted key digests.

Block hashes, heights, transaction positions, and optional hash-to-position
indexes can be reconstructed from the block log. Keep those indexes in memory
initially; they are branch-local accelerators, not additional persistent stores.
The active tip is the final hash of the last canonical POW, not a mutable UTXO record.

## Vote persistence and parameter stores

Vote deltas are extracted while translating transactions. They include removals
of votes carried by consumed outputs and additions from new outputs; a spend's
old contributions come from the recorded parent state, not merely its input bytes.
Persist one entry per completed block in `db/vote_deltas`, including an empty
entry when no votes change. Each entry identifies the block height, block hash,
and parent hash and retains source transaction/output attribution and exact
before/after contribution values.

Contained vote deltas in the UTXO model and the extracted vote log describe the
same effects. They must agree, and the effects are applied once through the vote
log. Do not both apply nested votes and independently replay their extracted
copies. See [deltas.md](deltas.md) for contribution types and reversal semantics.

| Governed parameter | Manifest path | Values path |
| --- | --- | --- |
| `block_reward` | `db/block_reward/manifest` | `db/block_reward/values` |
| `exec_fund` | `db/exec_fund/manifest` | `db/exec_fund/values` |
| `utxo_fee` | `db/utxo_fee/manifest` | `db/utxo_fee/values` |
| `data_fee` | `db/data_fee/manifest` | `db/data_fee/values` |

Each parameter store represents its live voting contributions, not merely the
currently selected parameter number. Route a delta by its small integer vote
type; preserve source-reference identity and the distinction between no vote
and a proposal of zero. Multiple sources can propose the same amount without
colliding. Executive voting is a different domain and must not be routed into
one of these four parameter stores; its materialization remains separately defined.

The manifest identifies the stored contribution records and any derived aggregate
state needed for selection. Its exact binary layout is not yet implemented.
A minimal implementation can use `AsyncPersistentDictionary.create(manifest_path,
values_path)`: the file named `manifest` then uses that class's hash-table format,
with source references as keys and proposal/weight records as values. This is an
implementation option, not a claim that `files.py` already implements a sorted
vote manifest or parameter selector. Its missing original-key enumeration means
aggregates must be maintained during replay, reconstructed from the vote log,
or supported by a later manifest implementation.

Each store can be reconstructed by replaying its routed changes from
`db/vote_deltas` through the published POW height. No store may expose votes from
an unpublished block. Undo restores captured old contributions, then restores or
rebuilds derived totals. Auxiliary fork databases copy or reconstruct all four
stores and roll them back with the UTXO state. Parameter selection uses the
branch-local stores at the consensus-defined epoch boundary.

These stores and the vote log belong to the same commit, recovery, and generation
publication unit as the original four databases. A fully validated fork cannot
be promoted with parameter manifests from another branch. Pending votes remain
in memory until their transactions are accepted into a completed block.

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

`len(blocks) = len(deltas) = len(vote_deltas) = len(pow_log) = n`

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
vote_deltas.append(serialized_vote_delta_list)
state.install_all_new_values(delta_list)
parameter_stores.install_all_new_votes(vote_delta_list)
pow_log.append(completed_block.header.pow.encode())
```

The logical revert is:

```text
state.restore_all_old_values(last_delta_list)
parameter_stores.restore_all_old_votes(last_vote_delta_list)
blocks.remove_last_entry()
deltas.remove_last_entry()
vote_deltas.remove_last_entry()
pow_log.remove_last_entry()
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

`db/pow` publication follows full block validation. A longer branch is never
installed by merely extending or rewriting canonical POW entries: the matching
blocks, UTXO state, both delta logs, and parameter vote state must be installed together. Missing candidate
blocks, incomplete validation, or an invalid suffix leave canonical `db/pow`
unchanged.

For an ordinary append under the database writer lock, durably write the block
and both delta entries, apply the UTXO and parameter vote changes, then durably publish the POW entry last.
Only then expose the new tip. If interrupted before POW publication, the block
and delta tails are unpublished and state is rebuilt to the old POW prefix.
If publication completed, recovery rebuilds through the new prefix. Validate
POW/header/UTXO-delta/vote-delta identity and checksums; a published POW with missing or corrupt
supporting data is an error, not permission to silently discard history.

This requires recoverable log-tail publication, not just `flush()`. The current
`files.py` does not supply that guarantee. Framing/checksums, ordered `fsync`,
and torn-tail handling must be added. Use the generation scheme below for
multi-block reversion and fork adoption: it avoids destructive changes to
canonical files while replacement state is being prepared.

## Auxiliary databases and fork validation

A competing branch may descend from a canonical POW at height `a` below tip
height `h`. Locate the ancestor by its final-hash bytes, then check its height;
height alone does not identify a branch. A temporary hash-to-height map can be
rebuilt by scanning canonical `db/pow`. If the parent is not known, obtain the
missing ancestry before constructing an auxiliary database.

Each auxiliary database has its own nine stores and records its source generation,
source tip, and ancestor `(height, final_hash)`. It starts from a coherent copy
of canonical state, rolled back to the ancestor. A branch is then validated
forward from that point, with its own UTXO dictionary, vote stores, delta logs, POW log, derived indexes,
and parameter context. Candidate peer deltas are never trusted: derive deltas
from validated blocks against this local branch state.

### Simplest implementation: copy, roll back, validate

1. Acquire the canonical database writer lock, drain outstanding I/O, and flush
   and synchronize all backing files. Copy all eighteen files to an auxiliary
   generation directory while writes remain excluded. Release the lock only
   after the copy represents one coherent tip. Independent read handles do not
   create a filesystem snapshot.
2. Open fresh container instances for the copies. For heights `h` down through
   `a+1`, read the local delta entry, check its after-images, and restore its
   before-images, and undo the corresponding vote deltas in the four copied parameter stores. Truncate the copied block, UTXO-delta, vote-delta, and POW logs to `a+1`
   entries. Rebuild non-UTXO validation context and hash-to-position indexes for
   that retained prefix. Verify its tip equals the chosen ancestor.
3. Validate competing blocks consecutively at heights `a+1`, `a+2`, and onward.
   Check height and parent linkage, both POW hash relations, the applicable work
   target, transaction root and signatures, balances and fees, lock/definition
   rules, and unique delta keys. Validation uses this branch's epoch parameters.
   Only completed blocks are appended to the auxiliary stores.
4. If any block fails, reject that branch without touching canonical stores.
   An incomplete or not-yet-longer branch may remain auxiliary, subject to
   resource limits; it cannot be promoted.
5. When the entire proposed suffix is valid and strictly longer than the current
   canonical chain, prepare its generation for atomic publication as described
   below. Recheck length against the current tip under the writer lock.

Here “longer” means strictly greater validated tip height, as specified by this
design. An equal-height branch does not replace canonical state. This is an
explicit selection rule; replacing it with cumulative work would require a
separate consensus decision. Validating proof difficulty remains mandatory.

Copying costs disk space and time proportional to the snapshot; rollback costs
work proportional to the detached suffix. It is nevertheless the simplest
implementation with mutable file-backed dictionaries: ordinary filesystem
copies isolate all writes and avoid a new overlay implementation. Do not use
hard links for these copies; modifying a linked dictionary would modify the
canonical files. Filesystem copy-on-write clones are an optional optimization
only where their isolation semantics are established.

An alternative builds the auxiliary dictionary by replaying deltas from genesis
to the ancestor. This avoids copying dead dictionary values and does not need
original-key enumeration from `AsyncPersistentDictionary`, but costs a prefix
replay. Persistent overlays would need a pinned immutable base, tombstones,
branch-aware lookups, and a promotion/materialization strategy. They are a later
optimization, not required for the initial implementation.

### Publishing a validated branch as one generation

Do not overwrite eighteen canonical files individually. Keep all nine stores in
one generation directory and identify the active generation through a small
`CURRENT` metadata file:

```text
chain/
    CURRENT                    # Identifier of the published generation
    generations/
        canonical-001/db/    # All nine stores listed above
        candidate-002/db/    # Independent copies of the same nine stores
```

`CURRENT` is storage-selection metadata, not an additional chain database or an
independent tip. The tip remains the last POW final hash within its selected
generation. Promotion proceeds under the canonical writer lock:

1. Recheck that the auxiliary suffix is fully validated, its ancestor is still
   on the current canonical chain, and its tip is strictly higher than the
   current tip. If the ancestor was detached, reevaluate against a valid common
   ancestor before promotion; do not rely on the old snapshot height alone.
2. Verify equal log lengths, POW/header identities, and materialized state.
   Synchronize all auxiliary files and required directory metadata.
3. Write a new temporary `CURRENT` file, synchronize it, and atomically replace
   `CURRENT` using the platform's supported same-filesystem replacement and
   durability protocol. Rebind the application's database facade to fresh
   handles for that generation before allowing new operations.
4. Invalidate old candidate transactions and tip-dependent caches, rebuild
   reservations, and reconsider detached transactions against the new tip.
   Retain the previous generation until in-flight readers release it and any
   desired rollback window has passed.

Readers pin one generation for an entire operation. They must never combine an
old UTXO handle with a new POW handle. Canonical growth during auxiliary
validation is allowed: append-only growth retaining the ancestor does not alter
the already validated branch, but it may make that branch no longer longer.
Promotion then waits or declines rather than replacing a higher current tip.

After a crash, `CURRENT` selects either the old or new complete generation;
unpublished auxiliaries cannot become canonical merely because they contain
more POW records. Validate the selected generation before serving it. Atomic
replacement and power-loss durability are separate guarantees and must be tested
on the deployment platform. End-tail recovery is still needed for ordinary
appends within the selected generation.

Canonical explicit reversion can use the same copy-and-rollback mechanism, then
publish that completed generation under the writer lock. It is an administrative
operation, not automatic adoption of a shorter branch. Garbage collection and
compaction operate only on unpinned generations and never remove data needed by
a validating branch.

## Mapping to the current async interfaces

After correct file initialization, the relevant calls are shown below. Paths are relative to the selected generation root; auxiliary generations use the same layout:

```python
blocks = await AsyncPersistentLog.create("db/blocks/index", "db/blocks/values")
deltas = await AsyncPersistentLog.create("db/deltas/index", "db/deltas/values")
pow_log = await AsyncPersistentLog.create("db/pow/index", "db/pow/values")
vote_deltas = await AsyncPersistentLog.create("db/vote_deltas/index", "db/vote_deltas/values")
utxo = await AsyncPersistentDictionary.create("db/utxos/index", "db/utxos/values")

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

Suppose the four canonical logs contain 101 entries (genesis through height
100). New block, UTXO-delta, and vote-delta entries are durable but no POW entry is published.
Recovery retains height 100 and rebuilds the dictionary to that prefix. If the
matching POW entry is durably published, recovery retains height 101. The
UTXO dictionary's physical length never determines the canonical tip.

### A longer branch from an earlier POW

Canonical state ends at height 100 with final hash `H100`. A peer supplies
blocks 98–102 whose block 98 points to the canonical height-97 POW hash `H97`.
Copy the canonical databases and undo deltas 100, 99, and 98 in the copy.
The auxiliary log lengths become 98, retaining heights 0–97. Validate and append
all five competing blocks using the auxiliary state. Canonical `db/pow` still
ends at `H100` throughout this work.

If block 101 on that branch is invalid, nothing is promoted, even if the peer
advertised a height-102 proof. If all five blocks are valid and canonical state
still ends below 102, publish the auxiliary generation. Its `db/pow` contains
103 entries, and its last final hash becomes the canonical tip. If canonical
state advanced to 102 meanwhile, the branch is not strictly longer and waits.

## Implementation sequence

First repair and test container initialization, reopen behavior, writer exclusion,
and exact bounds. Next implement canonical state keys and delta/envelope codecs,
then a nine-store, single-writer database facade with POW-last append and replay recovery.
Add candidate admission with atomic key reservation and read-dependency checks.
Implement coherent snapshots, auxiliary rollback, full branch validation, and atomic generation publication before optimizing copy cost or parallel validation.

Essential tests include append/revert identity, reopen after resize, duplicate-key
rejection, candidate rebasing, output-position reassignment, and interrupted writes
at every persistence boundary. Add invalid-fork isolation, canonical-growth races, hash-based ancestor lookup, and crash-during-promotion tests. The central invariant remains:

`revert(append(state, block, deltas)) = state`

The equality concerns the complete logical database state, not identical physical
file bytes. Unique delta keys make the state transition simple; the log and
recovery layer makes that transition persistent.

## Addendum: weighted medians from sorted epoch bins

Aggregate votes into epoch bins and sort each bin by proposed value. Maintain
each bin's weight below, equal to, and above the global median. This replaces
the augmented-tree proposal with sequential records, sorted arrays, and a small
manifest. It fits the append-oriented file containers and avoids maintaining a
persistent search tree on every UTXO change.

### Voting window and publication

Let `E = 10000`. Epoch `e`, for `e >= 1`, uses votes from block heights:

`[E*e - E, E*e) = [E*(e-1), E*e)`

These are exactly the previous 10,000 blocks, ending at `E*e-1`. Multiplication
by `e` is intended here; `10000**e` denotes exponentiation and does not produce
successive fixed-length epochs. Genesis supplies the initial parameter values.
Epoch `e` publishes and activates its parameters at height `E*e` using the
completed state through `E*e-1`. Votes in block `E*e` belong to the next window
and cannot change the parameters validating that block.

For each parameter, a vote's source is an `ArkaUTXO`, its proposal is the
corresponding field, and its weight is the output's positive `units` value.
`None` means no vote; zero is a valid proposal. Each field receives the full
UTXO weight independently. Spending an ARKA output removes its recorded votes;
creating one inserts its votes. A partial transfer removes the entire spent
output's contribution and adds those of the new outputs, including change.

Combining this window with the existing spend-removes-votes rule gives the
following eligibility definition: a source contributes to a publication only
if it was created within that publication's window and remains unspent at its
cutoff. This is a snapshot of eligible live contributions, not a time integral
of balances. A different interpretation, such as counting every historical vote
even after its UTXO is spent, would conflict with the deletion rule and requires
an explicit consensus change.

An older output remaining unspent is still in the UTXO database but is outside
the new voting window. Spending it removes its live contribution from its origin
bin; it does not subtract from the current window's total. A published epoch
snapshot is immutable: subsequent spends never revise past parameter decisions.
Reorganizations select the appropriate branch's snapshots instead.

### Bin and file layout

Use one logical bin per source-creation epoch for each parameter. Large bins
may have several sorted runs or file chunks. Physical chunks do not define vote
eligibility; source height and the publication window do.

```text
db/<parameter>/values
    append-only contribution changes grouped by source epoch
    sorted, aggregated runs for each epoch bin
    optional source lists for popular proposal values
    sealed publication snapshots

db/<parameter>/manifest
    format version, parameter type, generation
    applied block height/hash and vote-log position
    bin descriptors and committed values extent
    current window and total eligible weight
    median cache and per-bin partition positions
    epoch publication descriptors
```

A sorted bin aggregates all live votes for an exact proposal:

```text
SortedBin:
    source_epoch, generation
    run location, length, checksum
    sorted entries: (proposal, total_weight, cumulative_weight)
    optional membership-list locations
    live_source_count, distinct_proposal_count, total_weight
```

Proposal values are sorted numerically, not by their little-endian byte strings.
Identical proposals share one entry; popular proposals can retain chunked source
lists for attribution. The median uses their total weight, never the number of
members. Do not approximate values by range midpoints.

A source map associates each contribution's UTXO reference with its proposal,
weight, and creation epoch. Initially it can be in memory, reconstructed from
`db/vote_deltas` and verified against UTXO before-images. A persistent source
index is optional when replay cost warrants it. Membership-list history is not
itself a live electorate: deletions must be resolved before aggregating weights.

Each completed block supplies one extracted vote-delta entry, including empty
lists. Apply each effect once, even if its originating UTXO delta also contains
it. Group changes by parameter, source epoch, and proposal; combine their signed
weight adjustments after validating each source. Reject aggregate underflow.
The immutable vote log retains the individual source-level records for rollback.

For the initial implementation, update an in-memory map of proposal totals and
mark affected bins dirty. Persist contribution changes sequentially. Sort the
map and produce cumulative sums when an exact median is requested, and always
at publication. This avoids rewriting a sorted array for every transaction.
Larger implementations can append small sorted runs and merge them periodically;
a query must include unmerged changes and must not count superseded runs twice.

### Weighted median and per-bin positions

For the eligible bins, let `W` be their total weight. Use exact integer sums;
aggregates can exceed the size of one UTXO amount. A proposed deterministic tie
rule is the lower weighted median:

`rank = (W + 1) // 2`

The median is the first proposal whose cumulative eligible weight reaches
`rank`. For an even electorate divided exactly between two proposals this selects
the lower proposal, not their average. With `W=0`, there is no median; the proposed
fallback retains the previously effective parameter. Tie and empty-electorate
rules still require consensus agreement.

For cached global median `m`, each eligible bin records:

```text
MedianPartition:
    bin_generation
    first entry >= m, first entry > m
    weight_below_m, weight_equal_m, weight_above_m
```

Binary searches and cumulative weights obtain these values from a sorted bin.
Sum the below and equal weights across eligible bins to obtain `L` and `Q`.
The cached proposal remains the exact median precisely when:

`Q > 0 and L < rank <= L + Q`

A change below, at, or above `m` updates the corresponding partition total and
`W`. An insertion or deletion may move the median in either direction. If the
inequality fails, mark the cached median invalid and compute a replacement before
returning an exact query or publishing parameters. It is acceptable to postpone
this computation while processing a block batch; it is not acceptable to expose
a dirty cache as the median.

There are two straightforward exact selection methods:

- With one consolidated eligible epoch bin, binary-search its cumulative weights
  for `rank`. This is the ordinary case for the aligned 10,000-block window.
- With several nonoverlapping runs or bins, merge their sorted proposal sequences,
  combining equal proposals and accumulating weights until reaching `rank`.
  A sorted-run heap avoids loading all proposals at once. As a later optimization,
  search the numeric proposal domain using the sum of per-bin cumulative-weight
  queries; the stored proposal domain is bounded to 120 bits.

Do not take a median of bin medians: bins have different weights and distributions.
After finding `m`, refresh every participating bin's partition and record the
run generation and entry location containing the selected proposal. A rewrite
or merge invalidates physical entry positions even if the numerical median is
unchanged. Every cache must identify its window and bin generations.

### Epoch publication and durability

At cutoff `E*e-1`, finish applying that block's UTXO and vote deltas. Consolidate
the eligible bin, compute the exact median, and write an immutable descriptor:

```text
Publication:
    parameter_type, epoch=e, activation_height=E*e
    source_window=[E*(e-1), E*e)
    cutoff_block_hash, snapshot_generation
    sorted_run locations and checksums
    total_weight, median proposal/location | absent
    effective_parameter_value
```

All four parameter publications share the cutoff block and activation height.
Persist their values and manifest generations before publishing the block whose
acceptance depends on them. Header parameter fields must agree with these
branch-local decisions. Difficulty and executive selection are outside these
four parameter-vote stores.

Keep the live bin cache separate from sealed publications. A new epoch starts a
new eligibility window; the prior median is not automatically the new window's
live median. Retain older chunks for unspent source tracking, replay, snapshots,
and forks. Merely crossing an epoch boundary does not authorize deletion of old
chunks. Reclaim them only when no retained generation or recovery path needs them.

`AsyncFileProcessor` can support sequential runs and small manifest reads/writes;
`files.py` does not yet implement this manifest or selector. Use checksummed,
versioned records, exact length checks, and generation-tagged manifest updates.
Synchronize newly written values before publishing their manifest locations.
The database-wide commit protocol still binds the four parameter stores to the
UTXO state, both delta logs, and published POW prefix. A file flush alone does
not establish power-loss durability.

### Rollback and auxiliary branches

Undo restores the exact source proposals and units recorded in the vote log,
updates the affected origin bins, and invalidates their sorted-run and median
caches. Re-sort only the dirty bins needed for the restored window. Restore the
publication descriptors belonging to the restored cutoff hash, or regenerate
them from the correct branch's retained source data.

Auxiliary databases own isolated manifests and mutable bins. They may share only
pinned immutable runs through a deliberately implemented snapshot mechanism;
ordinary independent file copies remain the simplest first implementation.
Canonical and auxiliary branches can have different medians for the same epoch.
Neither source epoch nor activation height replaces cutoff hash as branch identity.

### Example and implementation cost

Suppose the eligible epoch bin contains proposals `10:40`, `20:30`, and `30:30`,
where the second number is total live UTXO weight. Then `W=100`, `rank=50`, and
the median is 20. Its partition is `(below=40, equal=30, above=30)`.
Spending the source supplying 30 weight at proposal 20 leaves `W=70`, `rank=35`;
the cached median fails the inequality and selection returns 10. Adding a new
eligible output with 60 weight at proposal 30 gives `10:40, 30:90`; the median
becomes 30. An equally large output created before the window contributes nothing
to this publication, even if it remains unspent.

For a bin containing `k` distinct proposals, rebuilding its sorted aggregate costs
`O(k log k)` sorting and `O(k)` prefix-sum work; selection from the consolidated
array takes `O(log k)`. Map updates and dirty marking avoid repeated full sorts.
This is simpler to implement than a persistent augmented tree and is a good
initial choice when exact publication occurs once per epoch. Its actual speed
advantage depends on distinct-value count, deletion volume, merge frequency,
and demand for exact within-epoch medians; benchmark those workloads before
adding more complex indexing.

Tests should cover window endpoints, old-output spends, explicit zero votes,
equal-half ties, empty windows, popular proposals, dirty caches, multiple-run
selection, rollback across an epoch boundary, and branch-specific publication.
