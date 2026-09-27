# Bounded block queue and retirement

The canonical block queue retains at most **200 epochs**, with **10,000 blocks
per epoch**, for a capacity of **2,000,000 blocks**. Once full, accepting another
block retires the oldest retained block and any still-unclaimed UTXOs originating
in it. Retirement changes live state; it is not merely deletion of historical
block bytes.

This document extends [db.md](db.md), [deltas.md](deltas.md), and
[forks.md](forks.md). It describes the required behavior, not completed code.
`chain.py` has an unimplemented `expire` method. `consensus.py` currently uses
`52 * 4 = 208` epochs; that constant does not implement the 200-epoch limit here.

## Queue bounds

Let `C = 2_000_000` and `H` be the completed canonical tip height, with genesis
at height zero. The active queue contains:

`first_height = max(0, H - C + 1)`

`retained_heights = [first_height, H + 1)`

`count = min(H + 1, C)`

| Tip height | Retained heights, inclusive | Count | Newly retired height |
| ---: | --- | ---: | --- |
| 1,999,998 | 0–1,999,998 | 1,999,999 | None |
| 1,999,999 | 0–1,999,999 | 2,000,000 | None |
| 2,000,000 | 1–2,000,000 | 2,000,000 | 0 |
| 2,000,001 | 2–2,000,001 | 2,000,000 | 1 |

The initial fill retires nothing. Thereafter the queue advances one block at a
time, not an entire epoch every 10,000 blocks. Absolute block heights never
reset when the oldest entry is removed.

## UTXO retirement

A UTXO's origin is its positional reference `(block, transaction, output)`.
Retiring height `r` removes every live output whose origin block is `r`,
regardless of its balance or how long its owner intended to retain it. Already
spent outputs require no deletion. Outputs created by later transactions remain
live even if their value ultimately came from a retired block.

Use the retiring block's output list to enumerate possible keys, then look up
the corresponding live records. Alternatively maintain a block-to-live-output
index. The persistent dictionary cannot recover original keys from its salted
key fingerprints, so retirement must not depend on enumerating those fingerprints
as if they were UTXO references.

For every remaining output, capture an ordinary deletion delta:

```text
RetirementDelta:
    delta_type = ARKA_UTXO or ASSET_UTXO
    reference = (retiring_height, transaction_position, output_position)
    old = exact live output bytes
    new = absent
```

Both ARKA and asset UTXOs retire. Removing a UTXO does not automatically remove
an asset definition, executive definition, or another non-UTXO state record;
those require their own explicit lifetime rules. Reward/fund expiration is also
not implied merely by naming this a UTXO-retirement operation.

## Ordering at the retention boundary

Retirement is caused by advancing the canonical queue, and belongs to the same
atomic state transition as the newly accepted block. A deterministic boundary
rule is required so nodes agree whether an oldest-block output can be spent in
the block that retires it.

The recommended rule is **retire before validating the new block's inputs**.
For proposed height `h`, any reference below `max(0, h-C+1)` is outside the live
window and cannot be spent. Compute the retirement effects in the private
validation view before checking transactions; do not mutate published state until
the whole block succeeds. If this block is rejected, no retirement takes effect.
This ordering is a proposed consensus detail accompanying the capacity rule.

A transaction previously admitted against the old tip can consequently become
ineligible at the boundary. Candidate admission should already use the next
block's retention bounds, and final block validation must recheck them. An
explicit spend and retirement must not emit duplicate deletion keys for the
same block transition.

After validation, commit the new block, its transaction and retirement deltas,
vote effects, queue bounds, and POW tip as one consistent state. Append-first
physical staging may temporarily use extra disk space; the published logical
queue must never exceed capacity.

## Vote effects

Retiring an ARKA UTXO removes the votes attached to its balance just as spending
it does. Capture those removals in the containing UTXO delta and the extracted
entry in `db/vote_deltas`, and apply them exactly once to the relevant parameter
stores. Preserve source reference, proposal, and old weight for reversal.

Under the previous-10,000-block publication window in `db.md`, outputs retiring
after 2,000,000 blocks are already outside the current electorate. Their removal
therefore does not subtract weight from the current window's median. It removes
any remaining live-source records in their origin bins. Previously sealed epoch
publications remain unchanged. If an old bin has already been safely discarded,
cleanup must recognize that representation rather than manufacture a negative
vote total or count the vote twice.

## Partitioning deltas and indexing logs

Store retirement effects with the block that caused them, not by rewriting the
retired block's historical delta entry. For example, the delta list at height
2,000,000 includes deletions of still-live outputs from height zero. Its reverse
restores those exact outputs if that queue advancement is undone.

Each log needs explicit logical bounds:

```text
QueueState:
    first_height
    count
    tip_height, tip_final_hash
    predecessor_final_hash of first_height, or genesis marker
```

A request for absolute height `h` maps to slot `h-first_height` only when
`first_height <= h <= tip_height`. Earlier heights return a distinct retired/
unavailable result, not an accidental lookup of another block. The canonical tip
remains the final hash of the last retained POW. Retain the predecessor hash at
the front boundary to identify ancestry without pretending it supplies the
retired predecessor's full state.

Blocks, POWs, UTXO deltas, and vote deltas remain associated by absolute height
and block identity. They may share a logical active window while undo/checkpoint
storage temporarily retains older bytes. Such bytes are recovery history, not
additional active queue entries.

`AsyncPersistentLog` needs a corrected prefix-retirement implementation before
being used here: its current prefix truncation shifts offsets while also advancing
`start_index`, and readers add that index again. Define one consistent translation
from absolute height to physical offset. Do not simply call that existing method
for every retirement and assume the bounds remain valid.

For a simple implementation, retain append-only data segments with a logical
front offset, then compact retired segments in batches. Rewriting the entire
2,000,000-entry offset table for each accepted block is unnecessary. Epoch-sized
segments fit the retention unit, but a partially retired first segment still
requires a per-block logical boundary. Chunk reclamation follows reader and
candidate pins.

## Reversal and recovery

Undoing an accepted boundary block must reverse both its ordinary transaction
changes and its retirement changes. It must also restore the former queue front.
Once a block is physically erased, its bytes cannot be recreated from a UTXO
before-image alone. Keep the retired front entry in an undo segment or pinned
archive until the supported rollback interval permits its deletion, or require
retrieval and verification of that historical data before such a reversal.

Retained deltas alone cannot rebuild current state from an empty dictionary once
the genesis-era delta prefix has been discarded. Maintain a verified rolling
checkpoint immediately before the oldest replayable delta, or retain an archival
replay source. The checkpoint must bind its height/hash, UTXO state, parameter
publication context, and other required validation state. Advance it using the
retiring historical delta before discarding that delta, with a recoverable
checkpoint-publication protocol.

After a crash, recover one committed tip, front boundary, and matching state.
Never expose a shortened queue with unretired UTXOs, or delete the only undo
records before their corresponding state/checkpoint publication is durable.
Filesystem deletion and compaction are later reclamation steps, not the commit
point for retirement.

## Auxiliary candidates

The sparse extensions in `forks.md` must include retirement effects caused by
their proposed tip heights. A candidate extending beyond canonical may have a
later logical front, and its view must hide expired outputs even if they remain
in canonical state. These are proposed tombstones until canonical validation
establishes the transition's validity.

Canonical front advancement must preserve historical lookups pinned by retained
candidates or rebuild them from a verified checkpoint and retained deltas. A
candidate whose fork predates available history cannot be reconstructed from the
retained block queue alone. It needs a trustworthy reconstruction source or must
remain unresolved; a POW chain is not a replacement for missing state data.
Being ahead does not eliminate this data requirement, and missing history is not
itself evidence that the candidate is invalid.

The 200-epoch bound governs the active block queue, not an unconditional bound on
all recovery, checkpoint, or candidate staging storage. If a strict total-disk
limit is also required, history availability and deep-fork handling need a
separate explicit policy.

## Example

At height 1,999,999, the queue is full. Genesis output A remains unclaimed, while
genesis output B was spent long ago. Proposed block 2,000,000 retires height zero.
Its private view removes A and its attached votes; B causes no deletion. A
transaction in the proposed block cannot claim A under the recommended ordering.

After successful commit, the queue covers heights 1–2,000,000, A is absent, and
the new block's delta entry contains A's exact before-image. If the block is
reverted while the necessary history is retained, A and the former queue front
are restored. The previously spent B remains absent.

Tests should cover the first retirement, each off-by-one boundary, ARKA and asset
outputs, already-spent sources, rejected boundary blocks, vote cleanup, next-block
admission, rollback, absolute-height lookups, checkpoint replay, and auxiliary
extensions crossing different front boundaries.
