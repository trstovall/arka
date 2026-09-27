# POW-chain candidates and auxiliary delta extensions

Candidates are identified by their POW chains. The canonical chain is the chain
selected for validation and normal transaction processing. Peers advertise their
canonical chain; observing a longer POW chain does not, by itself, make that
chain canonical locally or authorize advertising it as locally accepted.

This document replaces the earlier model of independently validated auxiliary
chains with copied databases. In this model, validation occurs only in the
canonical context. Auxiliary candidates retain POW ancestry, supplied data, and
compact state-change extensions. They do not run independent transaction
admission or duplicate the canonical database. Where [db.md](db.md) or
[db.2.md](db.2.md) describes copied auxiliary stores or transaction fan-out to
independent branch validators, this document supersedes that behavior.

## Identity, observation, and advertising

A POW chain consists of an ordered, parent-linked sequence of proofs associated
with block headers. The tip's `final_hash` identifies that path once its ancestry
is known. Height is useful for comparison but is not candidate identity: two
candidates may have the same height and different final hashes.

A candidate records:

```text
Candidate:
    POW tip height and final_hash
    known parent-linked POW path
    common ancestor height and final_hash
    supplied headers and transaction data
    missing-data ranges
    per-block change descriptions
    UTXO extension relative to the ancestor
    status: incomplete | retained | selected | invalid | discarded
```

POW alone contains neither transaction state nor the parent identifier; headers
supply the parent commitments. A bare ordered list of proofs is therefore a
claim until linked to its headers. It cannot provide the UTXO changes without
associated transaction data.

A peer's announcement describes that peer's canonical chain. It may identify a
chain that is merely auxiliary at this node. A node may observe or retrieve a
longer auxiliary chain without advertising it as its own canonical chain.
Retrieval and responses to explicit requests must preserve this distinction;
providing candidate data is not an announcement of canonical acceptance.

Merge peer observations of the same POW ancestry into one candidate. Keep peer
availability and response progress separately from candidate identity. Do not
create a second candidate merely because another peer announces the same tip.

## Retention policy

Compare candidates with the current canonical POW tip:

- Retain an auxiliary candidate whose POW tip is beyond canonical, unless part
  of its ancestry is known invalid. Incomplete supporting data means pending
  retrieval, not invalidity.
- Do not maintain an auxiliary chain significantly behind canonical. Define a
  configurable lag threshold for this pruning policy; no numeric threshold is
  specified here.
- Equal-height and near-behind candidates may be retained within that policy.
  They do not displace canonical solely because they were received later.

Reevaluate lag whenever the canonical tip advances. If a block is established
invalid, candidates descending through it cannot be selected. Shared ancestors
and sibling paths do not become invalid by association.

Candidate retention need not mean keeping all payloads in RAM. Keep the identity,
ancestry, missing-data inventory, and extension metadata while staging larger
payloads to bounded disk storage. Slow delivery must not turn an ahead candidate
into an invalid one or cause canonical processing to wait for it. Resource limits
may throttle retrieval and construction; they must not silently substitute a
"discard every slow ahead chain" policy for the retention rule above.

## Canonical-only validation

Only the canonical context validates transactions, checks state-dependent
consensus conditions, and admits transactions for its next block. Incoming
transactions go to that context once. Auxiliary candidates do not maintain their
own independently accepted pending sets or reserve canonical UTXO keys.

An auxiliary candidate can collect and decode data, identify referenced outputs,
and calculate proposed insertions/deletions. Such bookkeeping does not assert
that its signatures, balances, vote effects, parameters, or blocks are valid.
Malformed encodings can be rejected during collection; state-dependent validity
must not be inferred from successfully constructing an extension.

Keep the distinction explicit:

```text
observed POW length != complete supporting data != canonical validation
```

A longer observation is a candidate for selection, not an automatic replacement
of canonical state. While its supporting data is missing, the current canonical
chain continues transaction validation, block construction, and normal advertising.
An extension with unresolved references is incomplete, not a validated state.

When the selection policy chooses another path, move validation to that canonical
context through a controlled transition. There is still only one canonical
validation context, not a background validator for every retained candidate.
Previously admitted transactions must be reconsidered if their parent view changes.

## An empty extension, not an empty blockchain

For a fork at ancestor A, initialize an empty UTXO extension `E_A`. This is an
empty map of changes since A, not a claim that A had no unclaimed outputs.
Unmodified records remain in the ancestor view and need not be copied.

For each typed UTXO key, distinguish three extension states:

| Extension state | Lookup meaning |
| --- | --- |
| No entry | Read the UTXO from the ancestor view |
| Stored output bytes | Return the inserted or replaced output |
| Tombstone | The output was removed after the ancestor; return absent |

A deletion marker is essential. Removing an entry from an ordinary dictionary
would instead reveal the ancestor's old output again. Empty bytes must not be
used ambiguously as both a tombstone and a valid encoded value.

```text
lookup(candidate, key) =
    absent                         if extension[key] is a tombstone
    extension[key].new             if extension contains a live value
    lookup(ancestor_view, key)      otherwise
```

Key identity remains `(delta_type, reference)` with the small integer delta-type
tag. The extension captures only keys affected between the forking POW and the
candidate tip. Proposed changes are processed in block and transaction order.
A missing source that cannot yet be resolved is tracked explicitly; it must not
silently become a zero balance or an absent-before-image insertion.

## Obtaining the ancestor view without a database copy

The current canonical dictionary may differ from its ancestor's dictionary.
Falling through directly to current state would return incorrect results for
keys changed on the canonical suffix. Use its existing reverse deltas to build
a sparse rollback view or resolve affected keys lazily.

For captured canonical tip C and ancestor A:

```text
R_A = empty rollback map
for each canonical block from C down to A+1:
    for each UTXO delta in that block:
        R_A[key] = that delta's old value, or a tombstone for old absence
```

Repeated keys across blocks are overwritten in this reverse traversal so their
final value is the value at A. Then:

```text
ancestor_lookup(key) =
    R_A[key]                       if key is present in R_A
    captured_canonical_lookup(key) otherwise
```

The full candidate view is `extension -> rollback view -> captured canonical`.
Both maps are sparse; neither is a full copy of the UTXO dictionary. Canonical
suffix deltas may be shared across candidates that have the same ancestor and
captured base view.

The base must remain coherent while canonical processing continues. One simple
implementation tags lookups with a canonical revision and retries if a commit
races a read. Under the canonical commit gate, each affected ancestor view records
the earliest pre-change value for a newly touched key before that key is mutated;
existing ancestor overrides remain unchanged. This preserves the fixed ancestor
view without freezing the entire dictionary. Alternatively, use a versioned read
view or replay the relevant retained deltas for on-demand historical lookups.
Generation replacement requires rebinding or rebuilding these rollback views;
a stale file handle is not a historical snapshot.

Pin the history needed to resolve each retained ancestor. Background compaction
or pruning must not remove it while a candidate depends on it. This is retention
of shared history, not a duplicate database per candidate.

## From the ancestor to the candidate tip

Maintain both per-block delta descriptions and a compact net extension:

- An insertion records its proposed new bytes under the output's positional key.
- A spend records a tombstone and captures or resolves the source's previous value.
- A replacement records one ancestor-relative before-image and the latest proposed
  after-image.
- Creation followed by spending in a later block can cancel from the net extension
  when both the ancestor and resulting state are absent at that key.

Retain the per-block records even when net effects cancel. They are needed for
canonical validation, reconstruction, vote lifetime, and undo. Net-state equality
cannot establish valid intermediate transactions. The unique-key rule applies
within a block; repeated changes across different blocks remain possible.

A practical entry is:

```text
ExtensionEntry:
    key
    ancestor_value | absent | unresolved
    proposed_tip_value | absent | unresolved
    source block references
```

Only after the necessary body data is supplied can the extension cover the whole
path. Track a data-complete extension frontier separately from the advertised POW
tip. Later block data may be buffered while earlier gaps remain unresolved.

### Example

Ancestor A contains outputs X and Y. The canonical suffix spends X and creates Z.
The competing suffix instead spends Y and creates W:

```text
canonical dictionary: {Y, Z}
rollback view to A:    {X: old_X, Z: tombstone}
candidate extension:  {Y: tombstone, W: new_W}
```

Candidate lookups return X from the rollback view, suppress Y through the
extension, suppress Z through the rollback view, and return W from the extension.
All other keys fall through to the coherent canonical base. The auxiliary state
requires only the changes, not a second copy of every unclaimed output.

## Votes and other branch context

UTXO vote changes remain attached to the output changes and are extracted into
candidate-local proposed vote deltas. Do not apply these to canonical parameter
manifests during auxiliary construction. Parameter context must be reconstructible
from the ancestor's publication and the candidate's proposed history when that
path is selected for canonical validation.

Epoch medians cannot be derived from net UTXO differences alone if intermediate
cutoffs matter. Retain the per-block vote history, source epochs, and cutoff
identities. Auxiliary bookkeeping may cache sparse aggregate adjustments, but
it must not label them as validated publications. The same distinction applies
to definitions, rewards, and any derived indexes used by validation.

This removes the requirement for nine independently writable database copies per
auxiliary candidate. Persist candidate headers, bodies, and delta extensions as
needed; canonical `db/*` remains the authoritative materialized database.

## Selecting and installing another canonical path

Do not install the unvalidated net extension directly. The distinction between
selecting a path for validation and publishing completed canonical state must
be reflected in the coordinator:

1. Choose an eligible candidate with sufficient supporting data; recheck its
   POW ancestry and comparison with the current canonical tip.
2. Enter a canonical transition. Pin the previous accepted state for recovery
   and queries; freeze publication of new completed blocks while the selected
   path is processed. Retain incoming transactions in the ingress queue.
3. Use the sparse ancestor view and proposed extension data as inputs to the
   single canonical validator. Validate each block in parent order and produce
   trusted deltas; computed auxiliary deltas are hints to verify, not authority.
4. If any block is invalid, mark its dependent candidate paths invalid and restore
   the previous canonical validation context. No invalid suffix is published.
5. On success, durably undo the detached canonical suffix and apply the newly
   validated suffix under a recovery protocol. Publish the corresponding block,
   UTXO, delta, vote, parameter, and POW state consistently. Revalidate queued
   transactions against the new completed tip.

The old completed tip may continue serving pinned reads during the transition,
but no incomplete or unvalidated tip is advertised as accepted canonical state.
Staging changes in an extension until validation finishes prevents destructive
rollback from exposing half-built state. Durable installation still needs a
journal or equivalent atomic publication mechanism; sparse overlays alone do
not supply crash recovery.

Canonical-only validation means that validation of a newly selected history and
validation of new transactions in the old context cannot both continue as
independent authoritative validators. This design keeps normal processing active
through observation, retrieval, and extension construction; the actual canonical
transition has a deliberate validation barrier. Incoming transactions are retained
and subsequently checked, rather than falsely reported as accepted in both states.

## Reconvergence and pruning

Different POW histories cannot normally join at an identical descendant block:
a block commits to one parent. Reconvergence means peers select the same canonical
POW path, or multiple observations are recognized as descriptions of that same
path. Similar balances, cancelled net deltas, or matching transactions are not
proof that different POW histories have merged.

After canonical advancement or replacement, recompute retained candidates'
common ancestors and lag. Reuse immutable shared prefixes, rebase sparse ancestor
views as necessary, and discard significantly behind candidates. Ahead candidates
remain available unless known invalid. A discarded candidate's private extension
can be deleted only after no retained descendant or pending operation needs it.

## Implementation priorities

Implement a POW-path candidate registry, missing-data tracking, sparse ancestor
views, tombstone-aware extensions, and explicit separation of proposed versus
validated deltas. Keep one canonical admission/validation pipeline and advertise
only completed canonical state. Add canonical transition recovery before allowing
untrusted extensions to influence persisted state.

Tests should cover shared POW observations, delayed bodies, above-tip retention,
lag pruning, tombstone fallthrough, repeated-key changes across blocks, canonical
base mutations during ancestor reads, vote cutoff reconstruction, invalid selected
paths, and crash recovery during installation. A central invariant is that
auxiliary bookkeeping never mutates or advertises the canonical database.
