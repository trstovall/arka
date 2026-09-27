# Forks, subchain candidates, and delayed validation

A peer may advertise a POW chain longer than the local canonical chain while
supplying the corresponding headers, transactions, and validation data slowly.
The node must keep validating transactions and building its current next-block
candidate while independently reconstructing and validating the alternative.
A report of acceptance by another peer is a reason to request data, not a local
acceptance decision.

This design extends [db.md](db.md) and the queue-driven workers in
[db.2.md](db.2.md). It follows their current selection rule: a strictly longer
fully validated chain may replace canonical state; equal length does not suffice.
Difficulty validation remains mandatory. Substituting cumulative work for height
would be a separate consensus change.

## What can reconverge?

There are three distinct possibilities:

| Situation | Interpretation |
| --- | --- |
| Nodes initially follow different chains, then adopt the same validated branch | Consensus reconvergence: their canonical choices become equal |
| Candidate descriptions overlap on an identical parent-linked prefix | Candidate deduplication: store and validate that shared prefix once |
| Different histories later contain similar transactions or produce similar balances | Content or state similarity, not a merger of chain ancestry |

In `block.py`, a header hash includes `prev_block`, and the POW final hash commits
to that header hash and its nonce. A block has exactly one parent hash. Two
histories that diverged at an ancestor cannot normally acquire an identical
later hash-linked block: its parent commitment would have to identify both
histories. This would require a hash collision or a protocol change introducing
multiple parents. A descendant of one branch cannot simply be appended to the
other as an ancestry join.

The useful form of reconvergence is therefore selection of one branch, followed
by revalidation of pending transactions from both sides against that branch.
Identical transaction hashes or apparent UTXO balances do not justify merging
branch databases. Output positions, votes, epoch publications, and POW ancestry
can still differ.

## Candidates form a tree of possible extensions

Distinguish the following objects:

- A **completed view** is a fully validated database state ending at a particular
  height and POW final hash.
- A **local next-block candidate** contains transactions admitted for the next
  block on one completed view. Until finalized, its contents may change.
- A **reported block candidate** is a proposed block from a peer, identified by
  its parent and claimed POW, with some required data possibly missing.
- A **subchain candidate** is an ordered path of reported block candidates from
  a known ancestor. Its validated prefix may be shorter than its advertised path.

Several block candidates can share a parent and then form alternative multi-block
paths. Represent them as a parent-linked candidate tree, not as one mutable list
that changes the canonical chain whenever another POW arrives. Shared, completely
validated prefixes may share immutable data. Only coherent validated views may
serve as parents for authoritative transaction-state validation.

A candidate record should include:

```text
BlockCandidate:
    parent_final_hash, claimed_final_hash, claimed_height
    POW bytes | missing
    header bytes | missing
    transaction data and missing-data inventory
    supplying peers
    status and validation error | absent

BranchCandidate:
    candidate_id, common_ancestor
    advertised_tip
    highest_linkage_checked_tip
    fully_validated_tip
    ordered candidate path
    auxiliary worker group | not yet ready
    pending transaction set and ingress cursor
```

A POW record by itself contains no parent or height. The peer's ordering and
height claims are provisional until headers bind those records to an ancestry.
Moreover, valid hash linkage is not the same as an acceptable target, a correct
transaction root, or valid state transitions.

`final_hash` can be a discovery index but is not sufficient for accepting arbitrary
supplied bytes as identical validation input. In particular, transaction hashes
exclude signatures. Retain and validate the actual signed payloads; reject or
investigate conflicting representations rather than allowing a claimed hash to
overwrite already validated data.

## Three independent progress frontiers

For each alternative path track separately:

1. **Advertised frontier:** the highest block the peer claims to possess.
2. **Header/POW frontier:** the contiguous prefix whose supplied headers and POW
   links have been checked to the extent allowed by known parameters.
3. **Fully validated frontier:** the contiguous prefix whose complete blocks and
   state effects have passed all validation against the branch state.

Only the third frontier is eligible for canonical selection. If voting on the
branch determines an epoch target or other parameter, checks needing that context
must wait for validated ancestry; they cannot be marked complete using the other
branch's parameters.

A block may move through:

```text
announced -> collecting -> parent-ready -> validating -> validated
                                        -> invalid
```

Data collection for later blocks can proceed while earlier blocks are validated.
Cheap bounded structural checks and independent signature computations may run
in advance, but a descendant cannot become fully state-validated before its
parent. Out-of-order arrivals enter the cache, not canonical storage.

## Keep the canonical candidate running

The canonical worker group continues to serve reads, validate incoming
transactions, reserve unique delta keys, assemble its next block, and accept
completed canonical extensions. It has its own queues, commit gate, database
handles, and candidate revision. Branch reconstruction uses separate resources.

At a known ancestor, construct the alternative view by replaying pinned immutable
history or by rolling back an isolated snapshot. Undo UTXO deltas and vote deltas,
restore the four parameter stores/publications, and rebuild branch-local indexes.
Never roll back the live canonical dictionary as a temporary way to validate a
peer's branch. A long file copy under the canonical writer lock would also defeat
the non-interruption goal; prefer replay or a suitable isolated snapshot.

Give each ready branch its own next-block candidate in addition to its reported
subchain. Its incoming transactions are checked against its fully validated tip,
not against a later advertised block whose state is unknown. Whenever that tip
advances, included transactions are removed and remaining admissions are rebased.
Speculative results for an incomplete future state cannot reserve authoritative
keys or be reported as final acceptance.

Full branch replay must not occupy the canonical request loop. Bound auxiliary
I/O, sorting, cryptographic work, and outstanding lookups. Reserve processing
capacity for canonical requests. A stalled or failed branch can be paused or
retired without stopping canonical operation.

## Deliver transactions to both candidates

A single ingress service retains immutable transaction bytes and assigns ingress
sequence numbers. It explicitly fans out each transaction to both the canonical
candidate and every admitted auxiliary candidate. Multiple consumers of one queue
would divide the transactions between candidates rather than validate them on both.

Maintain independent delivery cursors and backlogs. A reconstructing branch queues
or later replays transactions until its state is ready. The canonical route never
waits for a slow auxiliary inbox. Resource exhaustion requires a visible branch
pause/retirement policy, not unlimited memory growth or silent loss of delivery.

Each candidate produces a result qualified by candidate ID, generation, tip hash,
and revision. The same transaction can be:

- Accepted on both branches, with different positional output keys.
- Accepted on one and rejected on the other because an input is spent or absent.
- Valid in isolation but excluded by another pending transaction's reserved key.
- Stale because its candidate advanced during validation.

Admission and rejection remain local to that candidate. Publish successful
reservations only after rechecking its captured revision. Shared parsing and
cryptographic caches are useful only when their complete inputs agree; balances,
authorization lookups, parameters, vote effects, and final deltas remain branch-local.
The unique-key-per-block rule continues to prohibit conflicting spends and
same-candidate spends of newly created outputs.

## Process the peer's longer path incrementally

1. Locate the last common ancestor by verified final-hash ancestry. If unknown,
   request missing headers/ancestry while continuing canonical operations.
2. Register the alternative candidate path and bounded missing-data inventory.
   Request the earliest gap first, with bounded prefetch of descendants.
3. Build a coherent auxiliary view at the ancestor. Pin required history against
   truncation and compaction until reconstruction finishes.
4. As each complete parent-ready block arrives, validate its header/POW relation,
   difficulty, root, signatures, balances, vote changes, and epoch rules. Derive
   deltas locally rather than trusting peer-provided state updates.
5. Commit successful blocks to the auxiliary group using the same UTXO, vote-log,
   parameter-store, and POW-last protocol. Rebase that candidate's pending set.
6. Compare its new fully validated frontier to the current canonical tip.
   Keep it auxiliary unless it has become strictly longer.

A peer's slow response does not block the above steps on other candidates. Data
can be requested from another peer by verified block/transaction identity. Failure
of one block invalidates its descendant path until that invalid ancestry is
replaced; it does not invalidate sibling candidates. If two peer reports describe
the same validated ancestry and payloads, deduplicate the reports and share the
work rather than maintaining redundant databases.

## Promotion is a short publication event

The node need not wait for every block the peer advertised. A contiguous fully
validated prefix can be promoted once its tip surpasses canonical state; any
remaining advertised suffix is still pending. Nothing after the proposed promotion
tip contributes to the length comparison.

Prepare and synchronize the auxiliary generation first. At publication, briefly
hold the selection lock and gate commits in both groups. Recheck their current
heights, ancestor relation, and validation status. If canonical growth has caught
up, resume both without switching. Otherwise atomically select the completed
auxiliary generation and update routing. Canonical `db/pow` changes only as part
of this complete state publication.

The barrier covers generation selection, not branch downloading or validation.
Ingress continues to retain transactions while routing changes. In-flight replies
remain labeled with their original view. Pinned old-generation reads may finish;
new canonical requests use the promoted generation. Never combine a new POW tip
with old UTXOs or old vote manifests.

Reconsider canonical-only pending transactions and detached-block transactions
against the promoted tip. Do not blindly concatenate pending sets or copy old
reservations/deltas. A transaction already accepted on the promoted candidate
may retain that admission only if its revision and next-block position still
match. Rebuilding a local next-block candidate is the practical reconvergence of
transaction processing, after consensus reconverges on one completed history.

## Example: a slow longer-chain report

```text
                         C98 -- C99 -- C100 -- C101 ...  canonical activity
                        /
common ancestor H97 ----+
                        \
                         B98 -- B99 -- B100 -- B101 -- B102 -- B103
                               reported alternative, data arriving slowly
```

Initially canonical tip is C100. The peer advertises B103 but supplies only B98.
The node validates B98 on an auxiliary H97 view. C100 remains canonical, and its
candidate C101 continues accepting transactions. The B98 candidate separately
validates the same incoming transactions for a possible next block on B98.

B99 and B100 then arrive. They extend the auxiliary state, but its validated
height is not greater than C100. Meanwhile the local chain may complete C101.
If the peer next supplies B102 before B101, retain B102 but do not skip B101.
When B101 arrives, validate B101 and then B102. If canonical still ends at C101,
B102 now qualifies for promotion even though B103 remains unavailable. If
canonical already reached C102, keep validating without switching on a tie.

A transaction T spending an output consumed in C99 but still live on B102 is
rejected by the canonical candidate and accepted by the auxiliary candidate.
Promotion can make the B102 result relevant to canonical admission; the earlier
C99-based rejection does not globally blacklist T. Conversely a transaction
accepted on C101 may become invalid after promotion and must be reconsidered.

No physical ancestry join occurs at B102. The node switches from one history to
the other; peers subsequently choosing the same history have reconverged.

## Implementation and verification priorities

Implement a candidate registry, missing-data scheduler, independent worker groups,
transaction fan-out with per-candidate cursors, and a small canonical selector.
Prefer one auxiliary group per actively validated path initially; share immutable
prefix data rather than mutable dictionaries. Limit admitted paths, orphan blocks,
prefetch depth, and retained generations so a peer's claims cannot exhaust storage
or starve canonical validation.

Test delayed and out-of-order blocks, missing ancestry, invalid intermediate
blocks, epoch crossings, divergent transaction outcomes, canonical growth during
validation, and promotion after only a validated advertised prefix. Verify that
stalled branches do not delay canonical admission or commits, and that a crash
at promotion selects one complete recoverable generation. A longer announcement
must never alone advance canonical POW or evict the current candidate's pending
transactions.
