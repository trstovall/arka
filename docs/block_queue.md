# Bounded block queue and reversible retirement

The canonical block queue retains **200 epochs of 10,000 blocks**, or
**2,000,000 blocks**. Once full, accepting a block retires the oldest block and
any of its outputs still unclaimed after the new block's transactions.

Retirement is represented by ordinary reversible deltas appended to the end of
that block's transaction deltas. Reversal uses the same delta replay mechanism;
it does not construct a separate retirement lookup table or special receipt map.
Retired block bodies are kept temporarily in a bounded buffer, approximately
100 blocks for untrusted-peer handling.

This describes the intended implementation. `chain.py` still has an unimplemented
`expire` method, and `consensus.py` currently uses 208 rather than 200 epochs.
Related designs are in [db.md](db.md), [deltas.md](deltas.md), and
[db.3.md](db.3.md). The ordering here supersedes the earlier recommendation to
apply retirement before the accepting block's transaction deltas.

## Queue bounds

With capacity `C=2_000_000`, genesis at height zero, and completed tip H:

`first_height = max(0, H-C+1)`

`retained_heights = [first_height, H+1)`

`count = min(H+1, C)`

| Completed tip | Retained heights, inclusive | Newly retired block |
| ---: | --- | --- |
| 1,999,998 | 0–1,999,998 | None |
| 1,999,999 | 0–1,999,999 | None; queue just filled |
| 2,000,000 | 1–2,000,000 | 0 |
| 2,000,001 | 2–2,000,001 | 1 |

Retirement advances one block per append, not one whole epoch at a time. Heights
and positional output references are never renumbered.

## Convert the retiring block to deletion deltas

For new height h at capacity, retiring height is `r=h-C`. Enumerate the retiring
block's transaction outputs using their original transaction and output positions.
Only outputs are needed for this conversion; inputs and signatures need not be
revalidated merely to retire state.

For each ARKA or asset output reference, look up its live value in the private
state **after** applying the accepting block's transaction deltas:

- If present, emit its normal typed UTXO delta with the exact live bytes as `old`
  and absence as `new`.
- If already spent, emit nothing.
- Attach/extract any associated vote removals using the same mechanism as an
  ordinary spend.

```text
retirement_delta = UTXOUpdate(
    ref=(retiring_height, transaction_position, output_position),
    old=live_output,
    new=absent,
)
```

Retiring a block does not reapply or reverse that old block's original transaction
deltas. It constructs new deletion deltas for outputs that remain live now.
Definitions, rewards, funds, and other non-UTXO records require explicit lifetime
rules; they are not removed simply because their original block retires.

A transaction that consumes an output from the retiring block leaves no live
record for retirement to delete again. This preserves unique delta keys within
the accepting block. Whether a boundary-block spend is otherwise permitted is a
consensus eligibility rule; retirement ordering itself must not produce a second
delete or introduce a separate undocumented rejection rule.

## One list, one reversal path

Let T[h] be the accepting block's transaction deltas and R[h] its generated
retirement deltas. Store:

`D[h] = T[h] || R[h]`

The vote-delta partition likewise includes transaction effects followed by any
remaining retirement vote removals. Persist both partitions with the identity
of block h, including empty retirement suffixes. Chunk boundaries may divide the
list but do not change its semantic order or commit boundary.

Forward application follows D[h]. Reverse application visits D[h] backward and
swaps old/new:

```text
forward:  transaction effects -> retirement effects
reverse:  restore retired outputs -> undo transaction effects
```

There is no special lookup needed to undo retirement. Each deletion already
contains the output bytes and vote before-images necessary to restore it. A
retirement-start ordinal may be recorded for inspection, but correctness does
not depend on a second table of retired outputs.

Conversion and validation take place in a private working view. A rejected block
causes no published transaction changes or retirement. The ordinary database
commit protocol publishes the complete deltas, UTXO/vote state, queue bounds,
and POW tip consistently before obsolete bytes are reclaimed.

## Reversing a full queue

Before accepting h, the full queue spans `[r,h)`. Afterward it spans `[r+1,h+1)`.
Undoing h restores `[r,h)`, rather than simply shortening the queue to C-1 entries:

1. Reverse D[h], restoring retirement deletions and then undoing transactions.
2. Remove h from the active tail and restore the former front block r from the
   retired-block buffer when its body is available.
3. Restore the prior queue bounds, tip, ancestry boundary, and matching log views
   in the same recoverable transition.

Queue metadata and block identity are still required. They describe ordering and
availability, not an additional UTXO lookup table. Reverse-playing D[h] into a
sparse ancestor overlay works unchanged: retirement deletions restore their old
values just as ordinary spend deltas do.

### Example

At full capacity, output A from height zero is live, output B from height zero
was spent previously, and output X from height zero is spent by new block
2,000,000, producing Y. The combined list contains:

```text
transaction deltas:  X -> absent; absent -> Y
retirement deltas:   A -> absent
```

B is absent already; X is absent after transaction application. Neither receives
a retirement delta. Reverse replay restores A, removes Y, and restores X. B stays
absent. Restoring the height-zero block at the queue front returns the logical
window to 0–1,999,999. No retirement-specific lookup table is built.

## Bounded retired-block buffer

Maintain a recent retired-block buffer with a configurable maximum of approximately
100 blocks for untrusted-peer handling. Retain absolute height and block/POW
identity with each body. Canonical bodies removed from the front are already
validated; the limit bounds history retained to service untrusted peer-driven
reorganization work, not permission to trust arbitrary peer-supplied bodies.

This buffer is outside the 2,000,000-entry active queue. It enables short backward
queue shifts and provides the output inventory if a restored front block retires
again on a different path. Recompute retirement deletions against that path's
live state; do not blindly reuse the earlier suffix when different transactions
may have spent different outputs.

At steady state, evict the oldest buffered body when the configured limit is
exceeded, subject to an explicit bounded pin policy. A peer must not bypass the
limit by opening many candidates that pin every old block. Limit or defer such
operations, retrieve verified history when needed, or report unavailable data.
Missing history is not by itself evidence that an ahead POW candidate is invalid.

The body-buffer horizon and delta undo horizon are distinct. A retained delta can
restore UTXO state after the corresponding original body has been evicted, but
cannot reconstruct inputs, signatures, or the complete original block bytes.
Reversal that requires those bodies must retrieve them or expose explicit body
unavailability. Never advertise an output inventory as a complete block.

## Votes and parameter state

ARKA retirement deletes the votes attached to the output's full recorded balance.
Log these removals in the accepting block's vote-delta entry and apply them once.
Reverse replay restores the exact old contribution; it must not recompute old
weight from later parameters.

Under the previous-10,000-block publication window, a UTXO retiring after
2,000,000 blocks is outside the current electorate. Its removal cleans up any
remaining origin-bin source state without subtracting from the current window
or changing sealed epoch publications. If old materialized bins have already been
reclaimed, the representation must account for that without fabricating negative
weights. Retained deltas still describe the reversible logical effect.

## Log indexing, recovery, and retention limits

Logs must distinguish absolute heights from physical positions. At a retained
front f, logical slot for h is `h-f`; requests below f return retired/unavailable
unless served through the retired-block buffer or an explicit historical view.
The current `AsyncPersistentLog` prefix-truncation implementation needs correction
before use: it both shifts offsets and advances an index readers add again.
Use logical front advancement and batched segment reclamation rather than moving
the whole offset table on every block.

Before removing a body, complete output enumeration and persist its generated
retirement deltas as part of the accepting transition. Preserve undo information
through the supported rollback horizon. Retirement cannot be reversed if both
its before-images and any reconstruction source have been erased.

Once old delta prefixes are discarded, replay from an empty UTXO database is no
longer sufficient. Retain a verified checkpoint before the oldest replayable
transition, or an archival reconstruction source. Advancing and publishing that
checkpoint must be recoverable before deleting its source history.

A crash must recover either the old queue/state or the complete accepted new
queue/state. Buffer movement, log truncation, and physical deletion must not
remove the only recovery source mid-commit. Auxiliary overlays include the same
retirement suffixes and must pin or reconstruct the history they use within the
configured resource policy.

Tests should cover initial fill, first retirement, empty retirement suffixes,
already-spent outputs, transaction/retirement key uniqueness, full-queue reverse
replay, repeated rollback/re-extension, vote restoration, buffer overflow, missing
old bodies, and interrupted commits. The defining property is that ordinary
transaction-delta reversal also reverses retirement.
