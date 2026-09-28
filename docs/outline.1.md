# Database development outline and test plan

This document indexes every other document currently in `docs/` and translates
its database requirements into a test-driven implementation plan. It is the
entry point for developing the missing database components, not a declaration
that the proposed interfaces or tests already exist. This file itself provides
the cross-document outline, precedence rules, acceptance cases, and delivery order.

Requirement IDs below are stable references for future test names and review.
Tests should cite an ID and its source document. A behavioral requirement can
have several tests; a proposed class name or file layout is not evidence that
an implementation is complete.

## Reading rules and design precedence

The documents contain both source observations and evolving proposals. Use the
following rules before turning prose into assertions:

| Subject | Governing design and treatment of earlier text |
| --- | --- |
| Candidate ownership and validation | [forks.md](forks.md) supersedes copied auxiliary databases and independent auxiliary validators in `db.md` and `db.2.md`. Auxiliary work stages data and proposed deltas; only the selected canonical context validates. |
| Ancestor reconstruction | [db.3.md](db.3.md) supplies sparse keyed overlays, fenced logs, and parameter-view composition under the rules in `forks.md`. |
| Retirement | [block_queue.md](block_queue.md) requires retirement deltas after transaction deltas and ordinary reverse replay; earlier retire-before descriptions are obsolete. |
| Within-block conflicts | [db.md](db.md) requires unique complete `(delta_type, reference)` keys. The dependent-transaction example in `deltas.md` illustrates general reversal, not permitted same-block admission under this policy. |
| Voting storage | The sorted epoch-bin addendum in [db.md](db.md) governs the four parameter stores. Its copied auxiliary-store suggestion is superseded by `forks.md` and `db.3.md`. |
| POW representation | Current `block.py` and `tests/test_pow.py` use a 96-byte POW and `BlockHash` final hash. The nonce-only headers and byte offsets in `block.1.md` and `block.2.md` need revision before becoming current golden fixtures. |
| Journal vocabulary | [broker.1.md](broker.1.md) distinguishes implemented `Peer*` notifications from proposed coordinator events and reliable journal behavior. |

Source observations are dated diagnostics, not desired behavior. In particular,
do not write a regression test requiring a documented bug to persist. Recheck
the implementation before recording an issue as unresolved. Proposed consensus
choices remain explicit test parameters until settled; see the decision register.

## Per-document outline and acceptance requirements

### 1. [block.1.md](block.1.md): encoding and value contracts

**Outline:** primitive byte and integer domains; signer forms; input/output
layouts; transaction/list framing; parameters, headers, blocks, and summaries;
decoding ownership; cryptographic hashes versus Python hashes; bounded iteration;
implementation exceptions.

**Database role:** supplies immutable record bytes, stable references, identities,
and bounded decoding for stored blocks and before-images.

- **CODEC-01:** Canonical representable values round-trip through encoding and
  decoding; size agrees with consumed bytes. Exercise nested values, empty
  lists, optional zero versus absence, and compact-target equivalence.
- **CODEC-02:** Mutating caller-owned byte buffers after construction or decode
  cannot alter retained byte fields. Do not mutate object fields behind caches.
- **CODEC-03:** Appropriate dictionary/set key values have equality-compatible
  Python hashes; persistent keys use explicit codecs, never Python `hash()`.
- **CODEC-04:** Transaction digests exclude signatures; Merkle roots cover empty,
  singleton, odd, and even lists while preserving order. Block count/root
  mismatches are rejected at validation.
- **CODEC-05:** POW initial hash equals the header digest with POW omitted;
  final hash equals `keccak_800(initial_hash + nonce)` and is a `BlockHash`.
  Tampering with either commitment fails. This does not establish work-target
  or full block validity.

Extend existing `tests/test_block.py` and `tests/test_pow.py` where appropriate.
Distinguish prefix decoders from exact bounded database-record decoders; permissive
decoding alone does not establish canonical byte identity.

### 2. [block.2.md](block.2.md): compact data reference and example

**Outline:** typed byte wrappers; signers and references; transaction inputs and
outputs; transactions and blocks; shared methods; declarative invocation forms;
one-transfer example with byte offsets, prefix bits, and hash boundaries.

**Database role:** a readable fixture vocabulary for constructing blocks and
tracking their positional outputs.

- **EXAMPLE-01:** Replace the legacy nonce example with the current POW interface
  before pinning its encoded bytes or offsets in tests. Independently check field
  widths, transaction lengths, and hash preimages.
- **EXAMPLE-02:** A transfer fixture names its parent UTXO, containing block height,
  transaction position, and output position. Translation must fetch the old value;
  that value cannot be recovered from the spend instruction alone.
- **EXAMPLE-03:** Distinguish codec-only placeholder signatures from valid signed
  fixtures. Full validation tests require valid signatures and applicable POW.

### 3. [chain.1.md](chain.1.md): state records and translation boundary

**Outline:** before/after delta relation; reward, fund, UTXO, definition, and
executive-vote records; input dispatch; hash-to-position resolution; output and
header effects; transfer example; validation, parameters, and source stubs.

**Database role:** maps `block.py` data to logical collections and identifies the
lookup and validation work missing from `chain.py`.

- **CHAIN-01:** Every supported update retains `ref`, `old`, and `new`; insertion,
  removal, and replacement distinguish absence from zero or empty bytes.
- **CHAIN-02:** Input dispatch resolves the correct collection and reports
  unsupported inputs explicitly. Positional and hash references resolve to the
  same output in a coherent view; unavailable references cannot be spent.
- **CHAIN-03:** Output keys use final block/transaction/output positions. Reward,
  fund, and definition effects follow their specified rules; unsupported effects
  fail translation rather than disappear from a supposedly complete batch.
- **CHAIN-04:** Genesis parameters are available at initialization; later epochs
  resolve the correct publication and branch context. A fresh chain exposes a
  defined state rather than uninitialized height/hash fields.

### 4. [deltas.md](deltas.md): indexed serialized changes

**Outline:** block-to-delta translation; small-integer type namespaces; immutable
before/after snapshots; nested vote effects; extracted vote log; version 1 base
records and version 2 composite records; checksummed chunks; manifests and
indexes; ordered application/reversal; byte and transaction examples.

- **DELTA-01:** Typed keys distinguish equal reference bytes in different
  collections. Apply checks the old bytes; undo checks the new bytes. Conflicts
  leave the application unit unpublished. Undo restores exact stored bytes.
- **DELTA-02:** Versioned record codecs distinguish absent and present-empty
  values, reject unknown tags/reserved bits/truncation/surplus bytes, and validate
  lengths before allocation. Version 1 cannot silently accept nested votes.
- **DELTA-03:** Chunk offsets bound complete records; count, final offset, payload
  length, checksum, and manifest ranges agree. Corrupt chunks fail before state
  publication. Empty delta lists have no chunks.
- **DELTA-04:** Rechunking preserves ordered deltas; reverse traversal crosses
  chunk boundaries correctly. Exercise exact budgets, an oversized permitted
  record, and rejection above the hard record limit.
- **DELTA-05:** Block/hash/transaction/ordinal indexes locate the intended records
  on divergent paths. Same height does not imply same block identity.
- **DELTA-06:** Each ARKA output contributes its full units independently to each
  non-absent parameter vote; spending removes the recorded contributions. Zero
  proposals remain votes. Nested effects and the extracted vote log agree and
  are applied exactly once, including empty per-block vote entries.

The byte registry and manifest codec are proposals. Finalize their versioned
definitions before making their exact encodings compatibility commitments.

### 5. [db.md](db.md): persistence, admission, commits, and voting

**Outline:** store layout and typed keys; vote persistence; unique delta keys;
pending next-block transactions; positional assignment; append/revert; recovery;
historical copied-fork proposal; `files.py` mapping and defects; examples;
sorted epoch bins, weighted medians, cached partitions, and epoch publication.

| Logical store | Files | Main responsibility |
| --- | --- | --- |
| Completed blocks | `db/blocks/{index,values}` | Immutable block bytes and active sequence |
| Unclaimed outputs | `db/utxos/{index,values}` | Typed persistent dictionary |
| Block changes | `db/deltas/{index,values}` | Block-partitioned reversible changes |
| Accepted POW | `db/pow/{index,values}` | Completed canonical proofs and tip identity |
| Vote changes | `db/vote_deltas/{index,values}` | Extracted block-partitioned contributions |
| Each voting parameter | `db/<parameter>/{manifest,values}` | Epoch bins, cached selection, sealed publications |

The four parameters are `block_reward`, `exec_fund`, `utxo_fee`, and `data_fee`.

- **STORE-01:** Fresh creation, reopen, empty valid storage, and corrupt storage
  have distinct outcomes. Log reads preserve absolute positions through prefix
  removal, tail rollback, compaction, and reopen.
- **STORE-02:** Dictionary inserts/replacements/deletes survive reopen and resize;
  probing uses physical capacity. Validate value-size limits before writing.
  Define exact-key collision handling before claiming exact key identity.
- **STORE-03:** Concurrent append cannot overlap records. Cancellation cannot
  recycle a handle still used by executor work; close drains in-flight work.
  Fault injection covers partial writes, resize, and compaction installation.
- **ADMIT-01:** Pending admission changes only the next-block candidate. Reserve
  complete typed keys atomically, rejecting double spends, duplicate effects,
  and same-block create/spend dependencies under the strict uniqueness policy.
- **ADMIT-02:** Validate read dependencies and block capacity as well as write
  uniqueness. Reordering, removal, or parent changes rebuild positions and
  reservations; concurrent validation cannot publish against a stale tip.
- **COMMIT-01:** Block, UTXO, both delta logs, parameter state, and POW describe one
  published view. Append then revert restores logical state and identities, not
  necessarily physical file sizes. Logs include empty per-block partitions.
- **COMMIT-02:** Restart after each durable write boundary exposes either the
  complete parent or complete child. Replayed batch IDs are idempotent; reuse
  with different payloads fails. No partial dictionary or POW tip is visible.
- **VOTE-01:** Epoch `e` uses live sources created in
  `[10000*(e-1), 10000*e)` at its cutoff. Test both endpoints, spent sources,
  older live sources, and later spends that cannot revise sealed publications.
- **VOTE-02:** Sort proposals numerically; aggregate exact weights, not voter
  counts or bin medians. Compare selection against an independent sorted
  reference calculation, including popular proposals and totals wider than
  individual output amounts.
- **VOTE-03:** Dirty bins and merged runs invalidate stale cache locations. Exact
  queries include outstanding changes; cache identity includes window and
  generation. Reject weight underflow and duplicate source application.
- **VOTE-04:** All four publications share cutoff hash and activation height.
  Rollback across an epoch boundary restores source weights and matching
  publications; proposed tie/empty-window policies remain explicit parameters.

After queue pruning, reconstruction starts from a retained checkpoint plus its
delta suffix. Do not turn the early empty-state replay equation into an assertion
that discarded history remains reconstructible.

### 6. [db.2.md](db.2.md): awaitable workers and coordinator

**Outline:** per-store ownership; initialization and service lifecycle; typed
request/lookup/reply/event queues; nonblocking mailbox dispatch; database-specific
operations; coordinated commits; recovery/shutdown; historical dual-validator
concurrency addendum.

- **WORKER-01:** Awaiting initialization returns the worker; concurrent opens are
  idempotent. Serving has one owner and shutdown resolves or explicitly fails
  outstanding requests before storage closes.
- **WORKER-02:** Nested lookups have distinct correlated IDs; a suspended request
  does not prevent its reply from being consumed. Each ordinary request has one
  terminal result, including lookup failure and stale-view errors.
- **WORKER-03:** Mutations serialize; multi-store reads remain pinned. Queue
  saturation on one destination does not stop unrelated replies or canonical
  work. Bound pending tasks as well as mailbox sizes.
- **WORKER-04:** Retries use persisted batch identity; caller timeout alone cannot
  mean a mutation failed. Test a late reply and a commit preceding a timeout.

Keep the worker protocol; replace copied worker groups and independent auxiliary
admission from the older addendum with the overlay and transition requirements
below. Internal lookups are not automatically public network journal messages.

### 7. [db.3.md](db.3.md): reverse replay and layered database views

**Outline:** representations for each store; keyed reverse replay; preserving
the base during canonical growth; fenced log prefixes; vote-bin overlays and
publications; forward extension; retention limits; adapters; C1/C2 worked case.

- **OVERLAY-01:** Distinguish missing override, stored value, tombstone, and
  unresolved construction. Only a missing override falls through to the base.
  Reversing `10 -> 20 -> 30` produces 10, not the first encountered value 20.
- **OVERLAY-02:** Pin the base or capture pre-write values under a revision gate.
  Subsequent canonical insertion/deletion cannot leak into the ancestor view.
  Test writes during reconstruction and generation replacement.
- **OVERLAY-03:** All four logs fence the shared prefix at the ancestor. Missing
  auxiliary suffix data must not fall back to another branch's canonical suffix.
- **OVERLAY-04:** Parameter overlays merge source changes and recompute eligible
  aggregates; selecting one median manifest by first-look fallback is invalid.
- **OVERLAY-05:** For `A -> C1` and `A -> B -> C2`, apply trusted reverse `d1` to
  reconstruct A, then proposed forward `d2` only to its complete frontier. Reads
  follow forward override, rollback override, coherent base. Incomplete C2 data
  cannot be presented as a complete or validated C2 state.

### 8. [forks.md](forks.md): POW candidates and canonical transitions

**Outline:** identity and advertising; ahead/lagging retention; canonical-only
validation; sparse extensions; ancestor reconstruction; staged forward changes;
vote context; path selection and installation; reconvergence and pruning.

- **FORK-01:** Merge observations of the same POW path; do not merge distinct
  paths merely because height, transactions, or balances match. Headers establish
  parent linkage; bare POW order is insufficient.
- **FORK-02:** A longer observed path remains auxiliary while bodies arrive.
  Canonical transaction admission continues; auxiliary staging neither mutates
  canonical stores nor announces acceptance nor runs independent admission.
- **FORK-03:** Retain ahead candidates unless known invalid; prune significantly
  lagging ones under configured policy. Missing data is not invalidity. Shared
  prefix resources remain until their last dependent view releases them.
- **FORK-04:** Selection enters a canonical validation barrier. Queue incoming
  transactions, validate the selected history in parent order, and publish only
  a complete successful transition. Invalid paths preserve the old accepted view;
  successful transitions revalidate queued transactions against the new tip.
- **FORK-05:** Crash during detach/install recovers a coherent accepted generation
  across all stores. Proposed auxiliary deltas are verified, never installed as
  trusted changes merely because their POW tip is higher.

### 9. [block_queue.md](block_queue.md): bounded history and retirement

**Outline:** 200-epoch capacity; converting retired outputs into deletion deltas;
one combined transaction/retirement list; full-queue reversal; worked example;
bounded retired bodies; vote effects; indexing and recovery horizons.

- **QUEUE-01:** Capacity is 2,000,000 blocks. First retirement occurs when height
  2,000,000 is accepted with genesis at zero. Check production constants and use
  an injectable small capacity to exercise the same boundary behavior cheaply.
- **QUEUE-02:** Enumerate retiring outputs and delete only those still live after
  transaction effects. Already spent outputs produce no retirement delta; votes
  are removed once. Store `transaction_deltas || retirement_deltas`.
- **QUEUE-03:** Undo restores retired outputs before undoing transactions and
  restores both front and tail bounds of a full queue. Reuse ordinary delta undo,
  including overlays; require no separate retired-output lookup table.
- **QUEUE-04:** Bound retired bodies near the configured 100-block allowance,
  including peer-driven pins. Re-retirement on a new path recomputes live-output
  deletions. Body eviction does not imply that retained state deltas are unusable,
  or that original block bytes can be reconstructed from them.
- **QUEUE-05:** Retirement outside the current voting window cannot reduce its
  electorate or revise sealed parameters. Checkpoints, undo retention, pinned
  views, and reclamation preserve the declared reconstruction horizon.

### 10. [broker.1.md](broker.1.md): journaled network/database boundary

**Outline:** existing synchronous exact-type pub/sub and peer events; coordinator
distribution; envelopes and roles; proposed database events; durable journal;
delivery/replay; transaction and slow-branch examples; implementation sequence.

- **BROKER-01:** Accepted boundary messages are durably recorded before dispatch.
  Full queues defer reliable delivery; journal failure cannot silently forward an
  unrecorded command. Logging cannot depend on a base-class subscription.
- **BROKER-02:** `Database*Requested`, `Responded`, and `Published` route outward;
  `Peer*` reports route inward. Session-scoped IDs, correlation, candidate, and
  view identities survive serialization and reconnect handling.
- **BROKER-03:** Immutable journal payloads preserve meaning despite subsequent
  caller mutation. Replay cursors and stable IDs prevent duplicate state effects;
  transport completion remains distinct from peer acknowledgement and commit.
- **BROKER-04:** Evaluation, staging, commit, tip, parameter, and retirement events
  have distinct meanings. Commit facts occur after coherent publication; recovery
  closes the commit/event crash gap. Only accepted canonical state is advertised.
- **BROKER-05:** Test unavailable bodies, partial bounded POW responses, explicit
  failure replies, and registered extended-function I/O correlation. Journal
  events cannot substitute for before-images in the delta logs.

## Decisions to settle before freezing tests

| Decision | Impact on the test contract |
| --- | --- |
| Median tie and empty electorate | Lower median and retaining the previous value are proposed, not settled consensus. Keep fixtures explicit until adopted. |
| Expiry-boundary spending | Decide whether transactions may spend an output in its retirement block. Either way retirement must not delete it twice. |
| Rewards, funds, executive votes, definitions, fees, and work target | Complete consensus rules before asserting full-block acceptance; codec/UTXO tests cannot stand in for them. |
| Transaction hash-to-position index | Define persistence, duplicate-hash policy, rollback, and pruning. Do not infer a complete index from an interface stub. |
| Delta registries and manifest/envelope codecs | Version the proposed tags, limits, exact encodings, and unsupported-version behavior. |
| Commit and recovery protocol | Select commit markers/checkpoints and durability barriers before defining physical crash points. Reader-visible atomicity is already required. |
| Retirement versus generated metadata ordering | Specify where reward/parameter/tip metadata lies relative to the retirement suffix; preserve transaction-before-retirement and atomic tip publication. |
| Retention and peer policy | Set lag thresholds, retired-body/pin limits, journal retention, and the minimum reconstructible ancestor; unavailable history is not an invalid chain. |
| Persistent dictionary key identity | Retain original keys for comparison or explicitly document the collision assumption; tests must reflect the chosen guarantee. |

Resolve decisions in their owning documents and update this outline before
implementing tests that would otherwise invent protocol behavior.

## TDD delivery order and evidence

The following test modules are proposed additions, not existing coverage claims.
Existing tests are `test_block.py`, `test_pow.py`, `test_crypto.py`, and
`test_net.py`. No database tests were run as part of this outline.

| Stage | Proposed tests | Requirements and completion evidence |
| --- | --- | --- |
| 1. Fixtures and storage | Existing block/POW tests; `test_files.py` | CODEC, EXAMPLE, STORE: deterministic fixtures, reopen, indexing, cancellation, and recoverable file operations |
| 2. Changes and translation | `test_deltas.py`, `test_chain.py` | CHAIN, DELTA: immutable reversible effects, exact framing, corruption rejection, and positional lookup |
| 3. Canonical database | `test_database.py` | ADMIT, COMMIT: conflict-safe candidate, append/revert, synchronized stores, idempotent restart |
| 4. Voting | `test_parameter_db.py` | VOTE and DELTA-06: exact reference medians, cutoff publications, rollback, cache invalidation |
| 5. Queued workers and journal | `test_db_workers.py`, `test_broker.py` | WORKER, BROKER: correlated progress under backpressure, durable delivery, no duplicate effects |
| 6. Views and branch transition | `test_db_overlays.py`, `test_forks.py` | OVERLAY, FORK: preserved ancestor views, slow auxiliary supply, canonical barrier, failed/successful recovery |
| 7. Bounded history | `test_block_queue.py` | QUEUE: retirement suffix, full-window reversal, body limits, checkpoint and overlay interaction |

For each stage, write a failing observable contract test, implement the smallest
complete behavior, then run its related regression tests. Use a simple in-memory
reference state to compare persistent apply/undo results; do not calculate expected
results by calling the implementation under test. Compare exact logical records,
published identities, queue bounds, and vote contributions, not only record counts.

Use controlled queues and synchronization barriers for concurrency tests rather
than timing sleeps. Use temporary directories and explicit crash/fault points for
recovery tests; flush-only mocks cannot establish power-loss durability. Integration
hash/signature tests use the locally built `arka.crypto` and `arka._crypto` modules.
Small capacities and epoch lengths may exercise algorithms, while separate checks
assert the production 2,000,000-block and 10,000-block constants.

The final integration scenario starts with a committed voting UTXO, admits and
commits a transfer, crosses an epoch and retirement boundary, collects a longer
auxiliary path while canonical admission continues, then selects and validates
that path. Inject failures during publication and reopen. At every stable point,
all stores and journaled commit facts must identify the same accepted state;
reversal must restore the previous logical state within the retained undo horizon.
