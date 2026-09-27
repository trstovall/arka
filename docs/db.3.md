# Database overlays: db1, db2, and reverse replay

`db1` is the canonical database collection. `db2` is an initially empty set of
sparse overrides describing an earlier view of that collection. Reverse-playing
the canonical delta suffix into `db2` can reconstruct ancestor state without
copying unchanged records. Lookups consult `db2` first and use `db1` only when
there is no override.

This document analyzes that behavior for every store in [db.md](db.md), using
the candidate rules in [forks.md](forks.md). Auxiliary construction is bookkeeping,
not independent consensus validation. Only the selected canonical context performs
validation. The overlay adapters described here are proposed additions to
[files.py](../arka/files.py), not features of its existing containers.

## One view, several representations

Let `C` be the captured canonical tip and `A` the requested ancestor. Reverse
replay processes heights `C, C-1, ..., A+1`. The ancestor block itself is retained.
Every store participating in the view must agree on the ancestor's height/hash,
base generation, and reconstruction status.

| Store | How db2 represents the ancestor | Subsequent branch extension |
| --- | --- | --- |
| `db/utxos` | Keyed before-images and explicit deletion markers | Proposed output values and deletions |
| `db/blocks` | Shared immutable prefix ending at A | Private suffix of supplied block records |
| `db/deltas` | Shared delta prefix ending at A | Private, explicitly proposed per-block deltas |
| `db/pow` | Shared POW prefix ending at A | Private observed POW suffix with completeness status |
| `db/vote_deltas` | Shared vote-delta prefix ending at A | Private extracted vote-change suffix |
| `db/block_reward` | Source-contribution overrides and adjusted epoch bins | Proposed changes to reward votes |
| `db/exec_fund` | Source-contribution overrides and adjusted epoch bins | Proposed changes to executive-fund votes |
| `db/utxo_fee` | Source-contribution overrides and adjusted epoch bins | Proposed changes to UTXO-fee votes |
| `db/data_fee` | Source-contribution overrides and adjusted epoch bins | Proposed changes to data-fee votes |

Keyed records support first-look fallback directly. Logs need an explicit logical
length fence. Median manifests need merged aggregates and newly computed caches;
blindly selecting one manifest and falling back to the other is incorrect.

## Keyed reverse replay

Each delta supplies `(key, old, new)`, with absence distinct from an encoded value.
For each delta in reverse chronological order, db2 stores its old state:

```text
old present -> db2[key] = VALUE(old_bytes)
old absent  -> db2[key] = TOMBSTONE
```

An earlier delta overwrites a later reverse-replay result for the same key.
Within a block the keys are unique; different blocks can modify the same key.
The resulting override is the state at A, not the state immediately before the
most recent change.

Three states are required:

```text
no db2 entry      -> consult db1
VALUE(bytes)     -> return those bytes
TOMBSTONE        -> return absent; do not consult db1
```

Removing an override is not deleting a visible record: it reveals the base again.
A possible private overlay codec is byte `00` for a tombstone and `01 || payload`
for a stored value. A missing dictionary entry remains the only fallback signal.
This codec is distinct from ordinary UTXO encoding. An unresolved lookup during
construction must have separate status and must not be treated as absence.

Replay can verify each delta's after-image against the current logical rollback
view before installing its before-image. This detects mismatched base state or
wrong-branch delta records. Such consistency checks do not establish transaction
validity. Publish the overlay as an ancestor view only after the whole required
suffix has been reconstructed.

### UTXO example

```text
At A:       X=10, Y=20
A+1:        delete X; insert Z=30
A+2:        replace Y=20 with Y=25
At C=db1:   Y=25, Z=30
```

Reverse replay creates `db2={Y:VALUE(20), Z:TOMBSTONE, X:VALUE(10)}`.
The merged view is X=10, Y=20, with Z absent. Untouched UTXOs consume no overlay
space. Each key includes its small integer delta type and canonical reference.

If a key changes `10 -> 20 -> 30`, reverse replay writes 20 and then 10; retaining
only the first before-image encountered would give the wrong ancestor value.

## Preserve the base while canonical state advances

An overlay constructed against C is not automatically correct after db1 changes.
A new insertion in db1 would leak into ancestor reads unless db2 masks it; a new
deletion could destroy a value the ancestor still needs.

There are two valid strategies:

1. Pin an immutable/versioned base view at C and retain its storage until the
   overlay is released.
2. Keep using mutable canonical db1, but preserve ancestor-visible values before
   each canonical write through a coordinated copy-on-write observer.

For the second strategy, before changing key `k`, install the current pre-write
value in every affected ancestor overlay that has no entry for `k`. Install a
tombstone if it is currently absent. Existing overrides remain unchanged. The
capture and canonical write must be ordered under the same gate; lookups either
hold that gate or detect a revision change and retry the complete lookup.

This "capture only if missing" rule applies to **new canonical writes after the
base was captured**, not to initial reverse replay, which must overwrite entries.
During asynchronous overlay construction, preserve new-write captures separately
from rollback overrides or synchronize their merge. Rollback history has precedence
when it establishes an earlier value at A. Register the observer at the same
revision barrier used to capture C, so no intervening write is missed.

On canonical generation replacement, retain the old base or rebuild/rebind the
ancestor view. An unchanged filename is not an unchanged database generation.
Multiple overlays can share a common versioned base or ancestor layer to avoid
capturing the same before-image repeatedly.

## Sequential logs: fence the shared prefix

An ancestor log view has a prefix fence at height A. A branch view adds only its
own suffix after that fence:

```text
read(height):
    below retained first height -> retired/unavailable
    at or below A              -> read pinned shared prefix
    above A and in own suffix  -> read own suffix
    otherwise                  -> missing/out of range
```

Never fall back to canonical entries above A. They belong to the other branch,
even when the auxiliary suffix has not arrived yet. A fence hides the entire
canonical suffix without creating one tombstone per log entry. Absolute heights
must be mapped through retained queue bounds, not assumed to equal physical slots.

Ordinary canonical appends do not change the pinned prefix. Canonical truncation,
compaction, or retirement must retain or relocate pinned prefix data safely.
`AsyncPersistentLog` lacks this shared-prefix adapter; calling its `truncate`
on the canonical log would change canonical state and defeats the overlay design.

### Blocks

The block view shares completed blocks through A and stores supplied branch blocks
privately. Missing bodies remain missing even if a POW exists at that height.
UTXO deltas cannot reconstruct original block bytes, signatures, or memos.
Shared blocks therefore require retained block storage or verified retrieval.
Height and parent/hash checks bind supplied bodies to the candidate path.

### UTXO delta log

Read canonical suffix deltas to construct the rollback layer, but do not include
that suffix in the branch's logical delta log. Preserve the common prefix and
attach proposed branch delta entries with explicit unvalidated status. Keep their
per-block boundaries even if net state effects cancel in the overlay.

A net extension is useful for lookup; it is not a replacement for the history
needed to validate intermediate blocks, reverse individual blocks, or reconstruct
retirement effects. Trusted deltas replace or confirm proposed entries only when
the path is processed by the canonical validator.

### POW log

The ancestor POW view ends at A's final hash. A candidate attaches its observed
POW path, never the canonical path above A. The candidate's observed tip, body-data
frontier, and completed canonical tip are different properties. Reading a candidate
POW tip must not update canonical `db/pow` or produce an accepted-tip announcement.

Candidates are indexed by POW ancestry/final hash, not merely height. POW records
cannot reconstruct missing transaction state. They must be linked to headers and
associated with the correct candidate before use.

### Vote delta log

The vote log follows the same shared-prefix/private-suffix structure, with one
entry per block, including empty lists. Reverse its canonical suffix into the
parameter contribution overlays. Retain source-creation epochs and exact old/new
weights. Extracted votes and nested UTXO vote records describe the same effects;
apply them once, not once from each representation.

The UTXO and vote rollback layers must reach A together before exposing the
combined view. A correct UTXO overlay paired with tip-C parameter votes is not
a correct ancestor database.

## Four parameter databases

For each parameter, reverse the matching contribution deltas into a source-keyed
overlay. A live source record contains its proposal, positive UTXO weight, and
creation epoch. A source tombstone suppresses a contribution in the base. All
four stores obey the same algorithm, routed by their parameter vote types:

| Store | Proposal field on ArkaUTXO |
| --- | --- |
| `db/block_reward` | `block_reward` |
| `db/exec_fund` | `exec_fund` |
| `db/utxo_fee` | `utxo_fee` |
| `db/data_fee` | `data_fee` |

An absent field contributes nothing; an explicit zero proposal still has weight.
Reverse removal restores the original UTXO units rather than recomputing weight
from later parameter values.

### Merging bins instead of replacing manifests

The base manifest summarizes sorted origin-epoch bins. An overlay retains sparse
signed adjustments to each `(origin_epoch, proposal)` bin as well as the source
records needed to check membership:

`view_weight(epoch, proposal) = base_weight(epoch, proposal) + adjustment(epoch, proposal)`

In undoing a change, subtract its new contribution if present and add its old
contribution if present. A replacement can move weight between proposal values
or change the amount. The combined weight must never be negative. Source overrides
prevent counting a replaced record both in the base and overlay.

An overlay map of absolute aggregate values can work instead, but cannot be mixed
with signed adjustments under one lookup rule. Choose and version the representation.
When db1 continues changing, the contribution captures must also preserve these
ancestor aggregate values, or queries must use a pinned base bin generation.
Updating source overrides alone while reading newly changed base totals is incorrect.

Median queries merge the base's sorted proposal entries with the sparse adjustment
entries, combine equal proposals, and remove zero-total bins. Use the eligible
window for the requested view and recompute cumulative weights. The median of
this merged distribution is not the median of the two databases' cached medians.

Cache the result with ancestor/candidate identity, window, base generation, and
overlay revision. A base leaf offset from another generation is not a valid median
location. A private overlay manifest can reference immutable base runs plus its
own adjustments; it need not duplicate the entire parameter values file.

### Epoch publications

For epoch e the documented window is `[10000*(e-1),10000*e)`, with the live-source
eligibility rule in `db.md`. Publication descriptors are branch- and cutoff-hash
specific. Share a sealed descriptor only if its cutoff belongs to the shared
history. Suppress later canonical publications and reconstruct the selected
branch's decision from its own vote history when canonical validation requires it.

Store proposed auxiliary calculations separately from validated publications.
Identical epoch numbers are not sufficient for fallback. An ancestor view cannot
reuse a future canonical publication merely because its parameter value happens
to match. Per-block vote history is needed even if the net UTXO extension is empty.

## Forward branch extension and installation

A useful three-layer composition is:

`candidate_view = forward_extension -> ancestor_rollback_overlay -> coherent_db1`

The forward extension begins empty, records proposed branch changes, and uses the
same value/tombstone rules. It can be combined physically with the rollback overlay,
but keeping separate layers simplifies rebasing and preserves shared ancestor state.
Log suffixes and parameter adjustments carry matching candidate revisions.

The combined view is not a commit. Before selection, it is a reconstruction of
proposed effects; signature, balance, POW, and parameter validation are not implied.
When another path is selected for canonical validation, validate it sequentially
and produce trusted changes before installing it. Do not write every db2 entry
back to db1 blindly: rollback entries describe the ancestor, and net overlays may
omit required intermediate effects and publication history.

Installation must consistently update the four logs, UTXO state, parameter stores,
queue bounds, and published POW tip using the recovery protocol. Private overlay
pages can be discarded after installation only when no pinned reader or retained
candidate depends on them.

## Retirement and reconstruction limits

The active block queue retains 2,000,000 blocks as described in
[block_queue.md](block_queue.md). Canonical retirement is another mutation for
overlay purposes: capture live records before deletion if an ancestor view needs
them, including their vote contributions. Log-prefix retirement must respect pins
or provide a verified checkpoint/retrieval path.

A sparse map does not recover information already erased before the overlay was
registered. If the required delta suffix, block prefix, or vote history is missing,
construction remains unresolved until that history is obtained. A checkpoint
plus deltas may reconstruct state, but it does not necessarily reconstruct the
original block log payloads. Ahead-candidate retention does not remove these
availability requirements.

## Practical adapter interfaces

Add view adapters above the existing storage classes rather than modifying every
consumer to manually probe two databases:

```text
OverlayDictionary:
    lookup(key, view) -> value | absent | unresolved
    set_override(key, value)
    mask(key)
    capture_before_base_write(key, old)

PrefixSuffixLog:
    read(absolute_height, view)
    shared_end_height
    private_suffix and completeness bounds

ParameterOverlay:
    source_lookup(reference, view)
    apply_reverse_vote(delta)
    merged_sorted_bins(window, view)
    median(window, view)
```

Route requests through the coordinator/worker queues in `db.2.md` with explicit
view IDs. Physical `db2` storage can be an in-memory map with spill files or a
persistent dictionary using a tombstone envelope. The current dictionary's
16-bit value length must account for envelope overhead; it cannot accept an
arbitrarily large output or overlay record. Do not confuse its internal deleted
hash-table slot marker with an application-level tombstone: deleting a slot
makes a key missing and would wrongly enable fallback.

Overlay persistence needs metadata identifying the base, ancestor, replay cursor,
and completion flag. After an interrupted construction, resume only against the
same reconstructible base or discard and rebuild the overlay. A complete-marker
write is not proof of cross-store durability without the synchronization and
journal protocol described in `db.md`.

## Complexity and checks

Reverse reconstruction reads the detached suffix's deltas and stores at most one
final override per touched key, plus per-block history references. It avoids
copying untouched UTXOs. Shared-prefix logs require only bounds and private suffix
storage. Parameter overlays store changed sources and proposal totals but may
need a merged scan to compute an exact median. Long forks can touch most state;
sparse storage is an optimization, not a fixed upper bound on fork memory.

Verify the following properties against a fully replayed reference database:

- Ancestor lookups match after inserts, deletes, replacements, and repeated-key
  changes across blocks.
- Tombstones prevent fallback; removing an override restores fallback deliberately.
- Canonical writes during construction or lookup cannot change the ancestor result.
- No log read leaks canonical suffix entries into an incomplete branch.
- All four merged parameter distributions and publication cutoffs match replay.
- Retirement, compaction, crashes, and generation changes preserve or explicitly
  invalidate pinned views rather than silently changing their meaning.

The central rule is: db2 contains differences, while the view adapter defines
what absence, bounds, and fallback mean for each database. That distinction makes
the scheme correct for both UTXO lookups and the wider database collection.

## Two candidates: validated C1 and a longer, incomplete C2

Consider canonical candidate C1 and auxiliary candidate C2. Interpreting
`ancestor` as the immediate parent in this example:

```text
       C1          height h+1, canonical and fully validated
      /
A ---+
      \
       B --- C2    heights h+1 and h+2, longer observed POW path
```

`parent(C1)=A` and `parent(parent(C2))=A`. C2 is receiving transaction data for
its proposed blocks. Its POW height exceeds C1's, but this does not establish a
validated state at C2. The peer's claimed acceptance and this node's canonical
acceptance are separate facts.

Let the two delta sequences be:

```text
d1 = inverse changes from C1 back to A
d2 = proposed forward changes from A through B to C2
```

These are ordered transformations, not an unordered union of records. `d1`
uses the trusted before-images from C1's accepted delta log. `d2` is initially
incomplete and becomes data-complete only when the required transactions and
source records have been obtained. It remains proposed until canonical validation.

### State composition

For canonical state `S1`:

`S_A = Apply(S1, d1)`

`S2_proposed = Apply(Apply(S1, d1), d2)`

Construct neither expression by modifying S1 in place. Reverse-play d1 into an
empty rollback overlay R, then forward-play the available d2 into a separate
extension F. Lookup precedence is:

`F -> R -> db1`

R expresses changes needed to recover A from C1. F expresses changes after A
on the alternative path. The already described value/tombstone/fallback rules
apply independently at each layer. A forward tombstone suppresses a value
restored by R; a forward value can replace a rollback tombstone. Combining both
layers into one physical map is possible, but composition must preserve that
precedence and retain the per-block history separately.

For logs, the same relation is a shared prefix through A followed by B and C2.
C1's log entry is excluded from the candidate view, not used as fallback for B
at the same height. POW entries may be available before block or delta entries;
that availability does not fill missing transaction data.

### Concrete UTXO example

Suppose A has X=10 and Y=20, with all other example keys absent:

```text
C1 changes:  delete X; insert Z=9
B changes:   delete Y; insert W=19
C2 changes:  delete W; insert V=18
```

Amounts are illustrative; acceptance still requires applicable fee and signature
checks. W is spent in a later block, so this example does not violate the
unique-key rule within a block.

```text
db1 at C1:   {Y=20, Z=9}
R from d1:   {X=VALUE(10), Z=TOMBSTONE}
F after B:   {Y=TOMBSTONE, W=VALUE(19)}
F after C2:  {Y=TOMBSTONE, V=VALUE(18)}
```

In the final net F, W's insertion and later deletion cancel because W was absent
at A. Its absence must be established before this cancellation is performed.
B and C2's individual deltas still retain W's history. The proposed merged view
contains X=10 and V=18, with Y, Z, and W absent. C1 remains unchanged throughout.

Notice that C2 cannot be applied directly to db1: C1 consumed X, whereas the
alternative path leaves it live. Reversing d1 is necessary even when d2 appears
to touch different keys. The composition reconciles the complete fork difference,
not merely the peer's latest block.

### Receiving transactions incrementally

Maintain three separate pieces of progress for C2:

- Its observed POW tip is C2 at height h+2.
- Its contiguous data-complete delta prefix may end at A, B, or C2.
- Its canonical-validation status is not implied by either frontier.

If B's transaction data is complete but C2's is not, F can expose a proposed
view through B with that frontier explicitly attached. It must not label that
view as the state at C2. A missing C2 transaction might spend any currently visible
output or add another one; an absent entry in an incomplete F is not proof that
the key survives at the advertised tip.

If C2's data arrives before B's, retain it by block identity and transaction
position. Do not resolve a spend of W as permanently invalid because W has not
yet been reconstructed. Its dependency is unresolved. Missing branch data must
not cause fallback to C1's same-height transaction or output.

As bodies arrive, check their association with the reported headers and inventory,
record dependencies, and derive proposed changes in parent order. These collection
and consistency steps do not authorize an auxiliary transaction-admission stream.
Under the canonical-only validation rule, incoming unrelated transactions continue
to be validated against C1 while C2 is auxiliary.

### Transition from proposal to canonical validation

C2's greater observed height justifies retaining it and retrieving the missing
data. C1 remains the advertised completed canonical tip during this process.
Before selecting C2 for validation, require enough complete supporting history
to evaluate the chosen path from A. The proposal must not substitute its own
unverified before-images for records resolved from A and earlier branch blocks.

When selected, the single canonical validator evaluates B and then C2 using
`R -> db1` as the ancestor view and verified forward changes as it advances.
It checks signatures, balances, roots, POW/difficulty, uniqueness, vote effects,
and epoch rules. F can accelerate lookups and expose proposed differences, but
its contents must be confirmed or replaced by those verified changes.

If B or C2 fails, discard that invalid path's proposed acceptance and retain C1's
completed database. If both succeed and the branch still qualifies against the
current canonical tip, install the trusted composition and publish C2 consistently.
The completed canonical announcement changes only after that installation.

This model does not simultaneously validate C1's new transactions and C2's blocks
as two independent canonical contexts. Canonical transaction processing continues
while C2 data is gathered; the selected-path validation transition uses the barrier
described in `forks.md`, retaining incoming transactions for subsequent validation.

### Canonical growth during C2 collection

If C1 advances to C1', the observed comparison must be repeated. C2 may now tie
or trail the current tip and is retained or pruned according to the candidate
policy. Its original h+2 claim cannot override newer canonical progress.

The ancestor view must still be A. Either keep a pinned db1 at C1 or maintain R
against live canonical writes as described earlier. Conceptually the new rollback
sequence is the inverse C1'-to-C1 suffix followed by d1. Do not simply attach d1
to the new base without preserving intervening before-images. F still describes
the A-to-C2 path and can be reused when its source dependencies remain unchanged.

### Votes, medians, and retirement

Apply the same reverse/forward composition to source vote records: undo C1's
vote changes, then add B and C2's changes, preserving source epochs and weights.
The four parameter views are derived from those merged contributions, not from
C1's current median cache. A publication boundary between A and C2 requires the
alternative branch's per-block vote history; cancelling W from the net UTXO map
must not erase its possible contribution at an intermediate cutoff.

If either path advances the bounded block queue, its d1 or d2 also contains the
corresponding UTXO-retirement effects and logical queue bounds. Reversing C1 must
restore records it retired when needed at A; advancing through C2 must apply the
alternative path's retirement rules. This requires retained undo history even
when the active queue has discarded the original block bytes.

The useful outcome is a compact candidate description: shared history through A,
trusted reverse changes d1, proposed forward changes d2, and explicit completeness
and validation status. It captures the alternative state without duplicating the
canonical databases or treating a longer POW announcement as accepted state.
