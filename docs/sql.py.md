# SQLite database layer and broker integration

This document defines the interface implemented in [arka/sql.py](../arka/sql.py)
and the adapter required to connect it to [arka/broker.py](../arka/broker.py).
SQLite replaces the proposed `files.py` containers for this implementation.
Earlier persistence layouts in [db.md](db.md) and worker descriptions in
[db.2.md](db.2.md) remain design background, not the SQL filesystem layout.

The SQL layer currently implements a persistent map, a canonical chain table,
live parameter votes, precomputed medians, epoch publications, and one queue-driven
coordinator. Consensus translation is supplied through a `Parser` protocol.
Broker subscription, durable communication journaling, outbound events, pending
transaction reservations are not implemented by `sql.py`. One persistent auxiliary
branch is supported through sparse `aux_*` tables and a validated atomic transfer.
Its lifecycle and broker integration are specified below.

## Ownership and execution

`Database(path)` owns one SQLite connection and one dedicated executor thread.
Awaiting the database opens it; an async context manager opens and closes it.
Parent directories are created for file-backed databases. `:memory:` is supported.
File-backed connections request WAL mode and `synchronous=FULL`.

Connection creation, SQL execution, and closing run on the same thread through
`_call`. This preserves SQLite's default `check_same_thread=True`. Repeated
`asyncio.to_thread()` calls would use the shared executor and could run on different
threads. An asyncio lock additionally protects whole operations and transactions;
thread affinity alone would not prevent transaction interleaving.

Cancellation does not stop SQL already executing. `_call` shields and drains the
operation before propagating cancellation so cleanup cannot race it. A cancelled
commit may already have succeeded. Neither timeout nor missing response proves
that a mutation was rolled back.

One coordinator processes requests in FIFO order. Parsing occurs while holding
the database lock and a `BEGIN IMMEDIATE` transaction. This provides a coherent
read/write context, including against another SQLite writer, but long parsing
holds the writer reservation. The current coordinator does not parallelize
validation. Auxiliary staging interleaves with canonical requests; selected-path
validation uses a deliberate transfer barrier.

## Persistent schema

| Table | Columns | Meaning |
| --- | --- | --- |
| `map` | `key BLOB PRIMARY KEY NOT NULL`, `value BLOB NOT NULL` | Persistent typed-key state |
| `chain` | `id INTEGER PRIMARY KEY`, `header BLOB NOT NULL`, `block BLOB NOT NULL`, `deltas BLOB NOT NULL` | One canonical block and its reversible changes per height |
| `votes` | `parameter TEXT`, `source BLOB`, `epoch INTEGER`, `contribution BLOB` | Live per-output parameter votes; primary key `(parameter, source)` |
| `vote_medians` | `parameter TEXT`, `epoch INTEGER`, `median BLOB NULL`, `total_weight TEXT` | Prepared selection per source epoch; primary key `(parameter, epoch)` |
| `parameter_publications` | `height INTEGER`, `parameter TEXT`, `value BLOB` | Published monetary values; primary key `(height, parameter)` |

All vote/publication columns except `median` are non-null. The map and vote-related
tables use `WITHOUT ROWID`. `votes_epoch(parameter, epoch)` indexes contribution
selection. Map keys and values and chain byte columns have SQL blob-type checks;
chain IDs have a nonnegative check. SQLite integer IDs are signed 64-bit even
though the block codec admits unsigned 64-bit heights.

The map's key includes the logical delta-type namespace chosen by the parser.
The SQL layer treats it as opaque bytes. Missing keys differ from present empty
blobs. There is no independent `pow` table: the stored header contains POW, and
its `final_hash` identifies the completed tip. Headers and full blocks are both
stored to support representation-specific reads.

`chain` contains the active path, not a fork archive. Reverting removes its last
row. The table does not implement the bounded queue, retired-body buffer, or
checkpoint reclamation described in [block_queue.md](block_queue.md).

## Public storage interface

```python
database = await Database(path)

await database.get(key, default=None)
await database.__getitem__(key)
await database.__setitem__(key, value)
await database.__delitem__(key)
await database.__contains__(key)
await database.__len__()
await database.update(items)
await database.difference_update(keys)

await database.tip()                 # ChainRecord | None
await database.block(height)         # ChainRecord | None
await database.median(parameter_name)  # int | None
await database.parameters(height)    # dict[str, int]
await database.close()
```

Async special methods require explicit awaiting; ordinary assignment, `len`, and
`in` syntax do not await them. `update` uses one `executemany` upsert batch.
`difference_update` deduplicates keys, executes one deletion batch, and checks
the affected count. Any missing key aborts the complete deletion transaction.

Direct map writes are for standalone use or controlled initialization. They do
not generate chain deltas or update vote tables. During chain operation, changes
must pass through the coordinator to preserve reversal and vote consistency.

`ChainRecord(id, header, block, deltas)` is an immutable record of encoded bytes.
The public API does not expose arbitrary SQL execution. Separate public reads
are separately locked; they do not constitute a pinned multi-read snapshot.

## Deltas and serialization

```python
Delta(key: bytes, old: bytes | None, new: bytes | None,
      votes: tuple[VoteDelta, ...] = ())

Vote(proposal: int, weight: int, height: int)
VoteDelta(parameter: str, source: bytes,
          old: Vote | None, new: Vote | None)
```

Delta byte fields and vote source bytes are copied into immutable bytes. `None`
means absence. Apply requires the stored value to equal `old`; reversal requires
it to equal `new`. Map keys must be unique in a serialized batch. Vote identities
`(parameter, source)` must also be unique across that batch. A mismatch raises
`StateConflict` and rolls back all writes in the coordinator's transaction.

The chain's `deltas` column uses the SQL module's versioned format, not the chunk
format proposed in [deltas.md](deltas.md):

```text
list = "ASQL" || version:u8 || count:u32 || records
field = length:u32 || payload[length]
record_v1 = field(key) || field(old) || field(new)
record_v2 = record_v1 || nested_length:u32 || nested_vote_list
```

Integers are little-endian. Field length `0xffffffff` denotes absence with no
payload; keys cannot be absent. Present empty blobs have length zero. A nested
vote list is a version 1 list whose key is a one-byte parameter index followed
by source bytes. Parameter indices follow `block_reward`, `exec_fund`, `utxo_fee`,
`data_fee`. Its old/new fields hold vote encodings or absence.

A vote occupies 38 bytes: creation height in 8 bytes, proposal in 15 bytes, and
weight in 15 bytes. Proposals may be zero; weights must be positive. Both fit
120 bits. Vote-bearing batches use version 2, including empty nested lists for
non-voting records. Version 1 remains readable. Decoding rejects truncation,
unknown versions, invalid nested tags, duplicate identities, and surplus bytes.
This format has no separate per-record checksum or chunk index.

## Parser and queue protocol

The parser is a required injected dependency:

```python
async def parse_transaction(encoded: bytes, view: ReadView,
                            height: int, position: int) -> Iterable[Delta]: ...
async def parse_block(encoded: bytes, view: ReadView) -> Iterable[Delta]: ...
```

It owns signatures, authorization, balances, fees, rewards, work-target rules,
UTXO reference resolution, retirement, and complete vote derivation. A block
parser must validate the whole block and return every authoritative change.
`chain.py` stubs are not a complete implementation of this protocol.

`ReadView` provides `get`, `tip`, `median`, and `parameters` in the request's
transaction. It expires when the request finishes. Parser callbacks must use
this view rather than reentering public database methods or
`Coordinator.median`, which would wait on the lock already held by the request.

```python
Request(id: str, operation: str, payload: bytes = b'', position: int = 0)
Response(id: str, result=None, error: str | None = None,
         detail: str | None = None)
```

The supported operation strings and effects are:

| Operation | Processing | Successful result | Persistence |
| --- | --- | --- | --- |
| `transaction` | Parse at next height and supplied transaction position; check effects by temporary application | Tuple of deltas | Roll back |
| `candidate` | Decode a next block, check linkage/commitments, parse and temporarily apply all effects | Tuple of deltas | Roll back |
| `commit` | Perform the same checks and reparse against current state; insert chain row | Committed `ChainRecord` | Commit |
| `revert` | Restore tip deltas in reverse; remove chain row and its publications | Removed `ChainRecord` | Commit |
| `stop` | Finish service after preceding requests | `None` | No mutation |

Candidate and commit paths require exact re-encoding, next sequential height,
parent POW final-hash linkage, matching transaction count/root, and both POW hash
commitments. These checks do not establish work-target validity; the parser must
do that independently. Initial height is zero; genesis policy belongs to the parser.

Errors become responses containing the exception class name and message. IDs
correlate responses but are not durable deduplication keys. A repeated commit
normally conflicts with the next-height requirement. A successful transaction
request does not reserve its keys, append it to a pending block, or promise future
acceptance. Likewise, `candidate` means a trial next block on this canonical tip,
not arbitrary auxiliary-branch validation.

The service awaits output queue capacity. A caller must continuously drain
responses; a full response queue stops subsequent request processing. During
ordinary operation each request receives one response. Cancellation or process
failure can interrupt delivery. Stop and await the service before closing storage.

## Votes, cached selection, and epoch timing

An ARKA UTXO contributes its full balance independently to each non-absent vote
field. Spending or retiring it removes the exact recorded contributions. The
parser attaches these changes to the parent UTXO delta. Asset UTXOs do not vote
for these four parameters. SQL does not infer contributions from opaque map bytes
or verify that parser-supplied weights match an output; that is a parser contract.

The source epoch is `creation_height // 10000`. At epoch block height `H`, where
`H > 0` and `H % 10000 == 0`, eligible votes are sources created in `[H-10000,H)`
and still live through `H-1`. Later spending does not rewrite past publications.

During application or reversal, changed source epochs are collected. Each affected
parameter/epoch bin is scanned once, proposals are aggregated and numerically
sorted, and the cache is written in the same SQL transaction. Python integers
hold exact totals beyond SQLite's signed 64-bit range; totals are persisted as
decimal text. Individual proposals and published values use 15-byte blobs.

For total eligible weight `W`, selection uses rank `(W+1)//2` and the first proposal
whose cumulative weight reaches that rank. Exact half-weight ties select the lower
proposal. With no live contributions, `median(name)` returns `None`; publication
then retains the previously published value.

`Database.median` and `Coordinator.median` perform cache lookups, not vote scans or
sorting. They select the source epoch containing the current committed tip, so
at tip `H-1` the result is ready for publication at `H`. After committing `H`,
the default query concerns the new source epoch, not the sealed prior publication.
Use `parameters(height)` for effective published values.

Publication occurs logically before applying the epoch block's own deltas. All
four proposed header values must match the parent-state cache or empty-electorate
fallback. A non-genesis epoch block must contain parameters. The SQL fixture path
permits genesis without parameters, but production genesis validation must provide
the bootstrap context. Unknown parameter names are rejected.

| Block height | Monetary context |
| --- | --- |
| `H-1` | Completes the source window and prepares medians |
| Epoch block `H` | Uses incoming context; publishes four values from the completed window |
| `H+1` through `H+10000` | Uses the publication from `H` |
| Epoch block `H+10000` | Still uses the publication from `H`, while publishing the following period |

This activation rule supersedes earlier descriptions that activate new monetary
values in the publishing block itself. Difficulty is already determined for `H`
from incoming chain context. A miner cannot choose its validation difficulty by
putting a new target in `H`'s header. The four monetary vote tables neither compute
nor persist the difficulty schedule; the parser remains responsible for it.

`parameters(height)` currently selects the latest stored publication preceding
the requested height, with a genesis special case. It returns an empty dictionary
when none exists and does not prove that a future height or publication is available.
Callers must constrain queries to the validated chain context.

## Broker boundary and required adapter

The proposed communication path is:

```text
network -> broker journal -> adapter -> SQL request queue
                                         coordinator -> parser / SQLite
network <- broker journal <- adapter <- SQL response queue
```

`sql.py` does not import or subscribe to `broker.py`. An adapter must translate
between peer events and SQL requests. Existing broker events carry mutable block
objects and peer-local identifiers; encode payloads into owned bytes at admission
and retain the peer/session mapping separately.

| Broker input | Adapter responsibility | SQL interaction |
| --- | --- | --- |
| `PeerTransactionsPublished` | Resolve peer/session IDs and request missing bodies | No automatic write |
| `PeerTransactionsResponded` | Match requested hashes and establish candidate position/context | `transaction` for canonical evaluation |
| `PeerBlocksPublished` | Compare identity/ancestry and schedule required data | No automatic commit |
| `PeerBlocksResponded` | Distinguish headers/summaries/full bodies; assemble a selected next block | Full block `candidate` or locally authorized `commit` |
| `PeerTransactionsRequested` | Resolve the session mapping and locate retained bodies | Read service/index still required |
| `PeerBlocksRequested` | Read the requested representation and identify unavailable heights | `Database.block(height)` plus decoding/response assembly |
| Connection/subscription events | Maintain peer availability and outgoing subscriptions | No chain mutation |

POW-chain and extended-function event classes in [broker.1.md](broker.1.md) remain
proposals. A peer advertisement never directly authorizes `commit` or `revert`.
Only canonical scheduling may issue those mutations. Ahead auxiliary paths use
the explicit `aux_fork` and `aux_stage` operations below. The adapter selects a
path for `aux_transfer`; peer events do not directly authorize that transition.

The adapter maintains a pending mapping from SQL request ID to journal message,
peer/session, requested content identity, and expected canonical context. One
response dispatcher routes each result to its owner. Since SQL responses do not
currently include a view revision, pending transaction acceptance needs additional
context checks and reservations before it can be announced as admitted.

Successful commit responses may produce proposed `DatabaseBlockCommitted`,
`DatabaseCanonicalTipChanged`, and, at epoch boundaries,
`DatabaseParametersPublished` events. Only after admission or commitment may the
corresponding outbound announcements be emitted. Candidate parsing is not a
committed-tip event. Revert results describe removal and must not announce that
removed block as newly accepted. Internal delta bytes need not be sent to peers.

### Reliability and the commit/event gap

The current broker dispatches synchronously by exact event class, uses
`put_nowait`, and silently skips full subscriber queues. It has no durable journal,
acknowledgement, request correlation, or replay cursor. Subscribing to
`AbstractBrokerEvent` does not receive its subclasses. Consequently, the existing
broker alone cannot guarantee delivery to the SQL queue.

The integration must journal admitted communication before dispatch, preserve
backpressure through retained records, and track consumer progress as described
in `broker.1.md`. SQLite's WAL is a database recovery mechanism, not this command
journal. SQL request IDs likewise do not provide exactly-once execution.

A block may commit before its response or broker event is recorded. Implement
an outbox in the same SQLite transaction as the chain change, or an equivalent
recoverable publication protocol, before claiming reliable commit announcements.
An outbox is not part of the current schema. Stable event IDs and retry records
must distinguish an already committed request from a conflicting new request;
blindly retrying a commit after timeout is insufficient.

## Lifecycle example

The parser below is an application-supplied complete implementation; the example
does not construct a permissive placeholder validator.

```python
async def run_database(parser: Parser, encoded_block: bytes):
    requests = asyncio.Queue(maxsize=64)
    responses = asyncio.Queue(maxsize=64)
    async with Database("db/chain.sqlite") as database:
        coordinator = Coordinator(database, parser, requests, responses)
        service = asyncio.create_task(coordinator.serve())
        try:
            await requests.put(Request("block-1", "commit", encoded_block))
            response = await responses.get()
            # The adapter correlates, journals, and routes this response.
            await requests.put(Request("shutdown", "stop"))
            stopped = await responses.get()
            await service
            return response
        finally:
            if not service.done():
                service.cancel()
                await asyncio.gather(service, return_exceptions=True)
```

Production response dispatch is continuous and keyed by request ID, rather than
assuming that the next response belongs to a particular caller.

## Recovery, migration, and verification

Map changes, vote contributions, median caches, publications, and the chain row
share one SQL transaction. Candidate/transaction evaluation rolls it back;
commit publishes it; revert restores before-images and removes the detached
publication. Reversal recomputes affected caches before committing.

Opening an existing database creates missing tables but does not backfill votes
omitted from version 1 historical deltas. Such a chain needs replay through a
vote-aware parser before its electorate is complete. There is no general schema
migration registry or automatic state reconstruction from blocks in this module.

[test_sql.py](../tests/test_sql.py) covers map batches, persistence, coordinator
commits, conflicts, reversal, and cancellation. [test_sql_votes.py](../tests/test_sql_votes.py)
covers vote codecs, large weights, cached reads, epoch activation, empty-window
fallback, rollback, and reopen. These are component tests with fixture parsers,
not evidence of complete consensus validation or broker integration.

Further integration tests must cover journal-before-dispatch, full subscriber
queues, peer reconnection, response correlation, a crash after SQL commit but
before announcement, retry identity, pending transaction conflicts, and canonical
transition recovery. The bounded queue still requires SQL-specific implementation
and tests before use.

## Auxiliary tables and canonical transfer

The database maintains one auxiliary candidate at a time, identified by its
parent-linked POW path. Heights locate rows; they do not replace hashes as branch
identity. Supporting several candidates requires table namespacing and is not
implemented.

| Table | Role |
| --- | --- |
| `aux_map` | Sparse ancestor values and tombstones |
| `aux_chain` | Overrides masking the detached canonical suffix and preserving shared history |
| `aux_votes` | Source-contribution overrides for all four parameters |
| `aux_vote_medians` | Recomputed or preserved ancestor bin caches |
| `aux_parameter_publications` | Ancestor publication overrides |
| `aux_state` | Singleton ancestor height and active capture flag |
| `aux_pending` | Ordered candidate headers and full block bytes awaiting selected validation |

The first five tables have their canonical table's logical columns and primary
key plus `deleted INTEGER NOT NULL DEFAULT 0`. Companion `aux_view_<table>` views
return nondeleted overrides and canonical rows with no override. Missing entries
fall through; tombstones return absence. Unchanged data stays shared, rather than
being copied into a second database. These views are internal SQL infrastructure.

### Reconstruct and preserve the ancestor

`aux_fork` verifies that the ancestor is retained, then reverses canonical deltas
from the tip down to that ancestor into the sparse tables in one transaction.
It hides detached chain rows and publications. Older rollback changes overwrite
later reverse-replay results when establishing the ancestor's exact value.

Canonical write triggers capture each key's pre-write state only if it has no
auxiliary override. New canonical keys receive tombstones. Existing overrides
remain unchanged. Capture handles insertion, update, deletion, and upsert, so
canonical advancement or reversion cannot leak into ancestor reads. This state
survives reopening. Space grows with changed keys and retained suffix data, not
with the entire untouched database.

```python
await database.aux_get(key, default=None)
await database.aux_tip()
await database.aux_block(height)
await database.aux_median(parameter_name)
await database.aux_parameters(height)
```

These methods expose the reconstructed ancestor, not hypothetical state at the
unvalidated staged tip. Missing suffix blocks cannot fall back to another path's
canonical suffix. Queries raise `StateConflict` when no auxiliary branch exists.

### Queue lifecycle

`Request` has an optional `ancestor: int | None` field. Auxiliary requests share
the existing FIFO queues and correlated response protocol.

| Operation | Input | Effect and result |
| --- | --- | --- |
| `aux_fork` | `ancestor=A` | Reconstruct A; return `None`; reject an already active auxiliary branch |
| `aux_stage` | Encoded block payload | Append the next contiguous candidate block; return `None` |
| `aux_transfer` | No payload | Validate and install a strictly taller candidate; return its committed tip `ChainRecord` |
| `aux_discard` | No payload | Clear auxiliary state without changing canonical data; return `None` |

Staging checks exact encoding, sequential height, parent linkage, count/root, and
POW hash commitments. It does not invoke the consensus parser or admit pending
transactions. Target difficulty and state validation wait for transfer. Canonical
processing continues between staging requests. Complete bodies currently arrive
in parent order; out-of-order buffering and advertised POW inventory belong to
the adapter.

For `A -> C1` and `A -> B -> C2`:

```python
await requests.put(Request("fork-A", "aux_fork", ancestor=A_height))
# Check each correlated response before depending on its operation.
await requests.put(Request("stage-B", "aux_stage", encoded_B))
await requests.put(Request("stage-C2", "aux_stage", encoded_C2))
await requests.put(Request("select-C2", "aux_transfer"))
```

The adapter must not advertise C2 as accepted merely because it was staged. If
canonical growth catches up, transfer rejects it until its staged height again
exceeds the current canonical height. Comparison is by height, not cumulative work.

### Selected validation and installation

Transfer holds the coordinator lock and one SQLite write transaction. It checks
that the staged tip exceeds canonical, then validates each block in parent order
against the reconstructed ancestor. The parser generates fresh trusted deltas;
later blocks see earlier accepted effects within that transaction. Votes, cached
medians, and epoch publications use this selected path's context.

This is the single selected canonical validator, not independent auxiliary
transaction admission. Incoming requests queue during the barrier. Public reads
through this Database also wait on its lock; the API does not expose a separate
pinned read service during transfer.

After every block succeeds, installation disables capture, replaces only the
canonical keys represented by overrides, applies tombstones, and clears the
auxiliary tables. All five canonical tables change in one commit. Ordinary tip
reversal then uses the new path's stored deltas.

Failure before commit restores both the old canonical state and the pre-transfer
ancestor/staged path. The adapter can explicitly discard an invalid candidate.
Invalidity classification and descendant pruning are not automatic. Cancellation
during commit requires checking the resulting state: the commit may have finished.

### Broker events and tests

Staging may produce a proposed `DatabaseCandidateUpdated` event. Only successful
transfer permits an accepted canonical-tip or POW announcement. Failed transfer
produces a failure response, not a tip announcement. Auxiliary queue requests are
not a durable broker journal; the commit/event outbox requirement still applies.

[test_sql_aux.py](../tests/test_sql_aux.py) covers repeated-key rollback,
tombstones, canonical growth and upserts, ancestor votes, reopen, staging without
consensus calls, failed transfer, successful installation, epoch publications,
and subsequent reversal. Crash injection, multiple candidates, resource/pruning
budgets, and retired-history recovery remain further work.
