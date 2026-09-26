# Awaitable database workers

This document proposes an implementation of the storage model in [db.md](db.md)
using queue-driven, awaitable classes. Record codecs come from
[block.py](../arka/block.py); delta semantics are described in
[deltas.md](deltas.md). The file containers are supplied by
[files.py](../arka/files.py). The worker classes and messaging protocol below
are new interfaces to implement.

## Ownership and topology

Create one worker for each database within a selected generation. Each worker
owns its file handles, caches, an input queue, and the right to mutate that
store. It consumes requests from its input queue and emits lookup requests,
replies, and lifecycle events to an output queue.

| Worker | Owned directory | Backend |
| --- | --- | --- |
| `BlocksDB` | `db/blocks` | Persistent log: `index`, `values` |
| `UTXOsDB` | `db/utxos` | Persistent dictionary: `index`, `values` |
| `DeltasDB` | `db/deltas` | Persistent log: `index`, `values` |
| `POWDB` | `db/pow` | Persistent log: `index`, `values` |
| `VoteDeltasDB` | `db/vote_deltas` | Persistent log: `index`, `values` |
| `ParameterDB("block_reward")` | `db/block_reward` | Sorted epoch bins: `manifest`, `values` |
| `ParameterDB("exec_fund")` | `db/exec_fund` | Sorted epoch bins: `manifest`, `values` |
| `ParameterDB("utxo_fee")` | `db/utxo_fee` | Sorted epoch bins: `manifest`, `values` |
| `ParameterDB("data_fee")` | `db/data_fee` | Sorted epoch bins: `manifest`, `values` |

A `DatabaseCoordinator` owns the worker group, routes output messages, admits
requests against a coherent database view, and sequences cross-store commits.
It is not another persistent database. Each worker address includes a generation
identifier and store name. Auxiliary forks have independent groups and addresses;
a lookup from a fork must never fall back to a canonical worker implicitly.

The simplest topology uses a private bounded input queue per worker and one
shared output queue continuously drained by the coordinator. Workers do not
call each other's methods or manipulate each other's files. The same protocol
can later support separate processes, but initially ordinary `asyncio.Queue`
instances and immutable messages are sufficient.

## Awaitable lifecycle

Awaiting a worker initializes its backend and returns that worker. It does not
enter an infinite request loop or consume the caller's reply stream.

```python
class DatabaseWorker:
    def __init__(
        self, root: Path, address: StoreAddress,
        inbox: asyncio.Queue[Request | Reply | Stop],
        outbox: asyncio.Queue[Lookup | Reply | Event],
    ) -> None: ...

    def __await__(self) -> Generator[Any, None, Self]: ...
    async def open(self) -> Self: ...
    async def serve(self) -> None: ...
    async def close(self) -> None: ...
```

`__await__` delegates to an initialization coroutine that returns `self`.
`open()` is idempotent and shares one initialization task when called concurrently.
It validates the generation path and file headers and finishes recovery before
reporting readiness. The coordinator starts exactly one supervised `serve()` task
per ready worker. Do not delegate directly to a backend initializer that returns
`None`; `await worker` must preserve the documented result type.

A conceptual setup is:

```python
outbox = asyncio.Queue(maxsize=256)
worker = await UTXOsDB(
    root=generation_root,
    address=StoreAddress(generation="g1", store="utxos"),
    inbox=asyncio.Queue(maxsize=64),
    outbox=outbox,
)
service_task = asyncio.create_task(worker.serve())
```

This is illustrative API usage, not a complete runnable service. A router must
already be draining the output queue, and task supervision and shutdown must be
installed. Derived classes use the common constructor; `ParameterDB` additionally
accepts one of the four permitted parameter names.

## Message protocol

Use typed immutable records with a finite operation enum and validated payload
schemas. Never send arbitrary callable objects or dynamically evaluate operation
strings. Domain values crossing queues should be immutable encoded bytes or
frozen scalar records; avoid sharing mutable `block.py` objects and caches.

```text
StoreAddress = (generation_id, store_name)
View         = (generation_id, published_height, published_final_hash)

Request:
    request_id, destination, reply_to
    operation, payload, view
    batch_id | absent

Lookup:
    request_id, parent_request_id
    source, destination, operation, payload, view
    batch_id | absent

Reply:
    request_id, source, destination, view
    result | error

Event:
    source, kind, details
```

Lookup IDs are distinct from their parent request ID. Replies preserve the ID
of the specific request they answer. The initiating worker maps lookup IDs to
the suspended parent operation. A parent sends one terminal reply after all
required lookups finish or one fails. Error replies use codes such as
`NOT_FOUND`, `INVALID_REQUEST`, `STALE_VIEW`, `STATE_CONFLICT`, `CORRUPT_DATA`,
and `IO_ERROR`; diagnostic text must not replace a typed status.

During ordinary operation, each accepted request produces one terminal reply.
Process crashes can prevent delivery, so this is not an exactly-once transport.
Mutation retries require a stable batch ID and payload identity checked against
persisted block/delta identities. A reused ID with different data is a conflict.
A caller timeout does not prove that a write was cancelled or never committed.

Public reads name the published view. Internal preparation reads name the
coordinator's batch and are permitted only under its exclusive transaction gate.
Workers reject stale generations and inappropriate views. Multi-store requests
remain pinned to one view until their terminal reply; the coordinator prevents
a writer or generation swap from changing that view in mid-operation.

## Dispatch without lookup deadlocks

A worker must continue consuming its inbox while an operation awaits an external
lookup reply. Otherwise that reply sits behind the waiting operation forever.
Implement a small mailbox dispatcher with pending-operation state:

1. Validate a request and run its local step, or register a bounded operation task.
2. If it needs external data, register the lookup ID before emitting `Lookup`.
   Suspend the operation, not the mailbox dispatcher.
3. The dispatcher recognizes incoming replies and resolves their pending lookup.
4. Resume the local step and eventually emit the parent reply.

Writes within a store remain serialized. Avoid holding a store mutation lock
while awaiting another worker: gather required external inputs first, then
recheck local preconditions under the batch/view gate before mutating. The
coordinator controls the dependency order; workers cannot initiate arbitrary
cyclic mutation chains. The initial dependency graph is acyclic:

```text
UTXO hash-reference lookup -> BlocksDB transaction-position lookup
ParameterDB rebuild       -> VoteDeltasDB range reads
DeltasDB recovery checks   -> BlocksDB identity lookup
POWDB identity checks     -> BlocksDB header lookup
```

Do not make the reverse worker depend on the originating pending request.
The coordinator can supply known identities directly to avoid unnecessary
lookups in commit paths.

Bound the number of pending requests and lookup chains as well as queue sizes.
The router must not await a blocked worker's full inbox while ignoring all
other output: use independent bounded delivery tasks or per-destination buffers.
Reserve capacity or priority for replies and shutdown messages. These controls
prevent full request queues from blocking the responses needed to drain them.
`task_done()` records mailbox consumption; `queue.join()` is not proof that a
suspended operation or durable commit has completed.

## Database-specific operations

### BlocksDB

Operations include `GET_BLOCK(height)`, `GET_HEADER(height)`,
`FIND_TRANSACTION(hash)`, `APPEND_BLOCK(batch, bytes)`, `TRUNCATE_TO(count)`,
`LENGTH`, and `SYNC`. Reads use log offsets; append stores a completed block
bound to the batch's height, parent, and POW identity. Transaction-position
indexes can be reconstructed from the completed block prefix and retained in
memory. A returned position identifies the branch view as well as the height.

The worker enforces serialization and log consistency. It does not independently
perform all consensus validation; only the coordinator's validated batch may
request canonical writes.

### UTXOsDB

Operations include `GET_BY_INDEX(ref)`, `GET_BY_HASH(ref)`,
`CHECK_DELTAS(batch)`, `APPLY_DELTAS(batch)`, and `UNDO_DELTAS(batch)`.
For a hash-based reference, emit a `BlocksDB.FIND_TRANSACTION` lookup, retain
the output position, and then perform the positional dictionary read. Resolve
the record's output type before forming the typed delta key.

A check verifies unique delta keys and exact before-images without writing.
Application installs the new bytes; undo verifies after-images and restores old
bytes. Vote changes are returned or supplied as part of the validated batch;
this worker does not independently update parameter stores. That would bypass
the coordinator and risk applying extracted votes twice.

### DeltasDB and VoteDeltasDB

Both are block-partitioned log workers with `GET(height)`, `READ_RANGE(start,stop)`,
`APPEND(batch, envelope)`, `TRUNCATE_TO(count)`, `LENGTH`, and `SYNC`.
Both append an entry for every block, including an empty delta list. Envelopes
bind height, parent hash, block hash, counts, and checksums. Reversal retains
before-images; it does not derive them from present database state.

`DeltasDB` stores UTXO changes. `VoteDeltasDB` stores the extracted contribution
changes, with parameter type, source reference, proposal, old/new units, and
source-creation epoch. The coordinator verifies their correspondence to the
transactions and spent outputs before append. Range replies are bounded or
paged rather than copying an unbounded log suffix into one queue message.

### POWDB

Operations include `GET(height)`, `TIP`, `FIND_FINAL_HASH(hash)`,
`APPEND_POW(batch, bytes)`, `TRUNCATE_TO(count)`, `LENGTH`, and `SYNC`.
`TIP` returns height and the last POW's `final_hash: BlockHash`; an empty log has
no tip. A rebuildable final-hash index locates common ancestors.

POW/header identity and hash linkage must agree. Difficulty and full transaction
validation are prerequisites supplied by the validation layer. The coordinator
permits canonical POW publication only after supporting stores are durable.
A peer's claimed longer POW sequence cannot publish itself through this worker.

### ParameterDB

Instantiate the same class four times, each restricted to its named parameter.
It owns the sorted epoch bins, proposal totals, source map, median partitions,
and manifest/publication descriptors described in `db.md`.

Operations include:

| Operation | Result or effect |
| --- | --- |
| `CHECK_VOTES(batch)` | Validate source identities and before-images |
| `APPLY_VOTES(batch)` | Add/remove UTXO weights in origin-epoch bins; mark changed bins dirty |
| `UNDO_VOTES(batch)` | Restore previous contributions and invalidate affected caches |
| `MEDIAN(window)` | Return exact median, total weight, and matching cache generation; sort/merge dirty bins first |
| `PREPARE_EPOCH(epoch, cutoff)` | Compute and persist an unpublished publication descriptor |
| `GET_PUBLICATION(epoch)` | Return the decision visible in the requested published view |
| `REBUILD(cutoff)` | Obtain bounded vote-log ranges through lookup messages and replay this parameter's changes |
| `SYNC` | Complete the required backend durability barrier |

A spend removes the vote weight of the consumed ARKA output; an insertion adds
its new output weight. Explicit zero proposals are distinct from missing votes.
All four instances use the same epoch cutoff and branch identity. For epoch `e`,
the publication window is `[10000*(e-1), 10000*e)` under the current documented
window convention. Requests cannot substitute an unrelated live median for a
sealed epoch publication. Empty-electorate and tie rules must match consensus.

Neither `AsyncPersistentDictionary` nor `AsyncPersistentLog` implements this
ordered parameter manifest. Implement its runs and descriptors on
`AsyncFileProcessor`, with the fixes and synchronization guarantees required by
`db.md`. Median computation may initially use a replayed in-memory aggregate
and sorted snapshots; the queue API need not change when its storage evolves.

## Coordinating a block commit

A `BlockBatch` carries the parent view, completed block bytes, exact UTXO deltas,
extracted vote deltas, proposed POW bytes, and publication effects. It is immutable
once validation succeeds. The coordinator takes the exclusive database gate,
rechecks its parent tip, and performs this dependency sequence:

1. Ask UTXOsDB and the four ParameterDB instances to check the batch's before-images.
   All checks must succeed before any authoritative mutation.
2. Append block, UTXO-delta, and vote-delta envelopes to their log workers and
   obtain durability acknowledgements.
3. Apply UTXO updates and route votes to the four parameter workers. Prepare any
   required epoch publications. Synchronize their data and manifests.
4. Publish and synchronize the POW entry last, then advance the public view and
   answer the original commit request.

Independent checks or store-local writes may run concurrently within a phase;
phase dependencies must be respected. No public read observes intermediate
states. A successful ordinary reply and a durable `SYNC` reply are distinct
unless the operation contract explicitly combines them.

If a mutation phase fails, fail the batch, stop exposing the affected group,
and recover it to the committed POW prefix before admitting more work. An error
reply does not roll back earlier file writes. Queue ordering and one writer per
store do not provide multi-file crash atomicity; the log publication and recovery
protocol in `db.md` remains mandatory.

## Auxiliary groups and reversion

Create an auxiliary group using its own generation root and queues. Copy a
coherent canonical snapshot or reconstruct it from logs, then undo the detached
suffix in decreasing height. Undo both UTXO and vote deltas, restore parameter
publications, and shorten all four logs consistently. Rebuild branch-local
lookup indexes. Canonical workers remain untouched.

Feed competing blocks into this group through the same validation and batch
protocol. After the whole suffix is valid, the coordinator compares its tip with
the current canonical tip, rechecks the ancestor, and publishes the generation
only when the branch qualifies. Route new requests to the new group after the
atomic generation switch. Existing operations either finish pinned to the old
generation or receive an explicit stale-view error; never silently reroute an
outstanding lookup into a different branch.

## Examples of queue exchanges

### Resolve an unclaimed output by transaction hash

```text
caller -> UTXOsDB.in:
    Request id=41, GET_BY_HASH(tx_hash, output=2), view=g1/H100
UTXOsDB.out -> coordinator -> BlocksDB.in:
    Lookup id=42, parent=41, FIND_TRANSACTION(tx_hash), view=g1/H100
BlocksDB.out -> coordinator -> UTXOsDB.in:
    Reply id=42, result=(height=98, transaction_position=3), view=g1/H100
UTXOsDB.out -> coordinator -> caller:
    Reply id=41, result=encoded_output | NOT_FOUND, view=g1/H100
```

The worker reads positional output `(98,3,2)` locally after reply 42. Failure
to find the transaction ends request 41 without a dictionary read. The coordinator
pins the view for the entire exchange.

### Spend and replace a parameter vote

```text
Validated batch B101:
    UTXO A: old_A -> absent
    UTXO B: absent -> new_B
    block_reward vote A: (proposal=100, weight=1100) -> absent
    block_reward vote B: absent -> (proposal=120, weight=1000)

coordinator -> VoteDeltasDB: APPEND(B101, extracted vote list)
coordinator -> UTXOsDB: APPLY_DELTAS(B101)
coordinator -> ParameterDB(block_reward): APPLY_VOTES(B101)
```

These messages occur in their prescribed commit phases. The parameter worker
updates A's origin bin and B's origin bin, then invalidates or refreshes its median
cache. A later `MEDIAN` reply includes the exact eligible result, not necessarily
120. Other parameter workers advance their applied-block identity even when their
routed lists are empty. An epoch publication waits for all four workers at the
same cutoff.

## Shutdown, recovery, and implementation order

On shutdown, stop admission, keep the router running, settle or explicitly fail
pending requests, drain lookup chains and executor work, synchronize committed
state, then close the backends and finish service tasks. An urgent cancellation
must not return a file handle to a pool while its executor operation still runs.
On startup, validate the selected generation and recover stores to one POW prefix
before workers accept public requests.

Start with the message types, correlation router, supervised worker lifecycle,
and sequential handlers. Wrap the existing log and dictionary backends, then add
ParameterDB and the exclusive coordinator gate. Implement durability and recovery
before enabling canonical mutation. Existing `files.py` initialization, flush,
resize, and handle-lifetime issues described in `db.md` still require correction.

Test out-of-order lookup replies, duplicate IDs, stale generations, missing
records, full queues, cancellation, worker failure, epoch barriers, commit-phase
faults, and fork promotion during live requests. A test that merely receives a
queue reply does not establish that the database is durable or coherent.

## Implementation notes: concurrent canonical and branch candidates

A candidate consists of a completed chain view plus pending transactions intended
for its next block. The canonical candidate and a competing branch candidate are
independent instances of this state machine. Both remain active and validate
incoming transactions while the competing branch is reconstructed and extended.
Rolling back for branch validation means rolling back the auxiliary instance of
canonical state, never temporarily rolling back the live canonical database.

Until a competing candidate's fully validated tip surpasses the current canonical
tip, canonical transaction admission, queries, block construction, and completed
block acceptance continue normally. The branch's advertised height or received
POW suffix is not its validated height. An equal-height branch does not trigger
promotion under the selection rule in `db.md`.

### Candidate-local state and locks

```text
CandidateState:
    candidate_id, generation_id
    role: canonical | auxiliary
    phase: reconstructing | validating | ready | failed | retired
    completed_view: height, final_hash, revision
    worker_group: nine database workers
    pending_transactions and immutable transaction bytes
    reserved_delta_keys and validation read dependencies
    per-transaction validation results and assigned output positions
    incoming_transaction_cursor
    promotion_eligibility
```

Each candidate has its own coordinator gate, reservation lock, queues, request
IDs, caches, derived indexes, and parameter publications. The existing
"exclusive database gate" is exclusive to that candidate's worker group; it
must not serialize canonical work behind branch replay or branch commits.
A separate short-lived selection lock protects the identity of the canonical
candidate during promotion. It is not held during cryptographic checks,
reconstruction, or ordinary branch extension.

Every request, lookup, and reply carries candidate identity in addition to its
generation and view. A revision changes whenever that candidate advances or
rebases. The transaction bytes may be shared because they are immutable; UTXO
lookups, deltas, votes, median caches, and admission decisions are candidate-local.
The same positional reference on two branches can designate different outputs.

### Obtain an ancestor view without blocking canonical work

A full eight- or eighteen-file copy under the canonical writer lock pauses
canonical mutation for the duration of the copy. It is therefore unsuitable as
the default snapshot mechanism for this non-interruption requirement. There are
two implementation choices:

- **Replay retained immutable history:** capture a common ancestor height/hash
  and pin the matching completed block and delta ranges. Build auxiliary stores
  from genesis or a verified checkpoint through that ancestor while canonical
  appends continue. Completed log entries in the pinned prefix must be immutable;
  compaction, truncation, and generation deletion cannot invalidate them.
- **Use an established isolated snapshot:** pin a previously sealed generation
  or a filesystem snapshot with guaranteed isolation, then roll its auxiliary
  state back to the ancestor. A brief barrier may establish the snapshot identity,
  but copying the entire live mutable dictionary must not occur under that barrier.

Replay is the simplest portable starting point with the current containers.
Workers issue bounded range reads against captured prefix extents, excluding
newly appended tails. Reconstruct UTXOs and all four parameter stores, and rebuild
branch-local transaction indexes and publication context. Do not read the live
canonical dictionary as if it were a historical snapshot.

If a snapshot at height `h` is used, undo heights `h` down through `a+1` in the
auxiliary stores only, where `a` is the ancestor. The resulting completed view
must equal the ancestor's final hash before branch blocks are validated. A
reconstructing candidate can queue incoming transactions, but cannot declare them
valid before it has a coherent state. Its admission starts as soon as that state
is ready, concurrently with further canonical operation.

### Fan out every transaction to both candidates

Use a transaction ingress service with a monotonically increasing ingress
sequence. Each incoming transaction is stored once as immutable bytes and sent
to both candidate inboxes with separate request IDs:

```text
TransactionEnvelope:
    ingress_sequence, transaction_identity, encoded_transaction

ValidateForCandidate:
    candidate_id, request_id, ingress_sequence
    expected_view_revision, encoded_transaction
```

Do not use competing consumers on a single transaction queue: that distributes
transactions between candidates rather than delivering each transaction to both.
The ingress router explicitly fans out each envelope. Track a delivery cursor
and backlog per candidate. A candidate created later replays the retained pending
transaction set and catches up from the captured cursor, with identity-based
deduplication to cover overlap with live delivery.

Canonical delivery does not await branch validation or a full branch inbox.
Use independent bounded delivery tasks and a retained ingress backlog, with
per-candidate acknowledgements and limits. If resources are exhausted, explicitly
pause or abandon the auxiliary candidate and release its pins; do not silently
drop branch deliveries while claiming that it has processed all transactions.
Bounded resources cannot support unlimited lagging candidates without a policy.

Ingress deduplication must account for signed payload bytes: transaction hashes
exclude signatures, so two submissions with one transaction hash need not contain
the same signature material. Share parsing or cryptographic computations only
when their complete inputs match. State-dependent signer resolution, balances,
fees, and vote effects are still checked separately on each candidate.

### Independent validation outcomes

A transaction can be accepted on one candidate and rejected on the other. It may
spend an output already claimed on one branch, refer to an output absent from the
other, or encounter different epoch parameters. Return candidate-qualified results:

```text
ValidationResult:
    transaction_identity, candidate_id, completed_view_revision
    status: accepted | invalid | conflict | missing_dependency | stale
    reason
```

An auxiliary rejection must not evict an accepted canonical transaction. A
canonical rejection must not prevent independent branch validation. Pending-set
membership, unique delta-key reservations, resource budgets, and next-block
output positions are maintained independently. Within each candidate all admitted
transactions remain intended for that candidate's next block.

Validation captures a completed view, performs lookups and checks, and rechecks
that revision under the candidate admission lock before reserving keys. If the
candidate advanced meanwhile, mark the result stale and retry against its new
view. Do not publish stale deltas just because the transaction bytes are unchanged.
Deterministic ingress order can resolve local reservation conflicts; it is not
a substitute for block consensus rules.

### Advancing a branch while transactions arrive

Process branch blocks sequentially against their own parent views. Transaction
validation tasks may run between commits or concurrently against a pinned stable
view. A branch-local commit gate prevents them from observing partial UTXO or
vote application, without affecting the canonical candidate's gate.

After each branch block commits, remove included transactions from that branch's
pending set, invalidate stale reservations, and revalidate remaining transactions.
Recompute next-block output positions and vote deltas where their context changed.
Perform the same process independently whenever the canonical tip advances.
Candidate transactions do not get inserted into downloaded completed blocks;
they are candidates for a subsequent block built on the resulting tip.

If a peer supplies a long suffix, promotion may occur at a completed, fully
validated prefix that already surpasses canonical height, provided every block
through that proposed promotion tip is validated. An unvalidated remaining suffix
cannot contribute to the length comparison and remains unaccepted. If the
promotion proposal instead names the entire received suffix, all of it must first
be validated.

### Promotion barrier and continued transaction delivery

Once the branch has a qualifying validated tip:

1. Prepare and synchronize its complete generation without holding the canonical
   selection lock. Verify that its parameter publications and all four logs agree
   with its completed view.
2. Acquire the selection lock and briefly gate canonical commits and the branch's
   own commits. Compare both current completed tips, not their earlier snapshots.
   Recheck ancestry and validation status. If canonical growth has caught up,
   release the gates and continue validating; do not force promotion.
3. Publish the selected generation using the durable `CURRENT` protocol. Switch
   canonical routing as one operation, then release the gates. No partial store
   combination becomes canonical.
4. Preserve branch-local admissions that still match the promoted completed view.
   Independently reconsider canonical-only pending transactions and transactions
   from detached blocks; do not copy their old deltas or reservations.

Ingress continues to record transactions during this brief publication barrier.
Candidate-specific cursors ensure that every retained envelope is delivered
exactly as needed after routing changes. A result already in flight remains
associated with its original candidate and revision; it is never relabeled as
an acceptance by the newly canonical candidate. Reads already pinned to the old
generation may complete with that view identified, subject to retention policy.

This allows a short synchronization point for atomic promotion, not a canonical
pause for the duration of branch validation. The old canonical candidate can
remain an auxiliary instance if retained for further branch work, or be drained
and retired. Worker groups and ingress cursors must be updated consistently with
that decision.

### Scheduling and failure isolation

Give canonical requests a reserved processing budget and bound branch replay,
range reads, sorting, and cryptographic concurrency. Separate executor capacity
or admission semaphores prevent branch work from saturating every thread used by
canonical operations. CPU-heavy Python sorting must not monopolize the event loop;
use an appropriate executor or bounded work batches. Snapshot/replay I/O also
needs throttling on a shared disk.

A corrupt or invalid branch transitions to `failed`; outstanding branch requests
receive explicit failure or retirement replies, and canonical work continues.
A failure during the atomic publication step invokes database recovery, not
optimistic routing to whichever group replied first. Group shutdown drains its
own pending lookups and file operations before removing snapshots or queued data.

### Example and verification

Canonical tip C100 and branch tip B97 share ancestor 97. Auxiliary reconstruction
and validation of B98, B99, and B100 proceed while canonical transactions and
blocks continue. Transaction T spending an ancestor output is sent to both:
canonical state may reject it because C99 spent that output, while B100 accepts
it. Neither result changes the other's pending set.

If B101 is fully valid and canonical still ends at C100, B101 can be promoted.
If canonical advanced to C102, B101 remains auxiliary and continues receiving
transactions. B103 qualifies only after B102 and B103 are fully validated and
canonical still ends below height 103. A claimed B104 proof with missing blocks
cannot affect the comparison.

Tests should demonstrate continued canonical commits during slow replay, delivery
to both candidates, divergent validation outcomes, stale-view retries, bounded
branch backlogs, independent reservations, epoch-specific vote medians, and
promotion races with canonical growth. Inject failures before and after generation
publication and verify that canonical POW never advertises an unvalidated branch.
