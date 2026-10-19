# Persistent critbit trees and Windows

[arka/critbit.py](../arka/critbit.py) defines immutable node records, copy-on-write
tree algorithms, augmented selection, batch patches, and capped sequence Windows.
Its logical operations return unpublished roots. [arka/db.py](../arka/db.py)
provides concrete codecs and an initial mmap-backed store; the persistence classes
declared inside `critbit.py` remain design interfaces, not completed disk storage.

## Nodes and references

An `Offset` is a file-relative node address. Zero represents an empty tree.
`Leaf(key, value, summary)` owns the key/value bytes supplied through tree updates.
`Branch(bit, left, right, summary)` routes by a critical bit, numbered from the
most significant bit of the first key byte. Branch bit positions increase along
each path. Keys have a fixed positive byte width within a tree; values have
variable length. Absent values differ from present empty bytes.

`NodeStore.read(offset)` loads a node; `allocate(node)` stages a new immutable
node and returns its address. Allocation is not publication or durability.
Updating a tree copies changed paths and shares unchanged subtrees. Old roots
continue to identify their exact old contents until released by their owners.

| Kind | Leaf augmentation | Internal augmentation | Uses |
| --- | --- | --- | --- |
| `MAP` | None | None | Executive/asset definitions, ARKA/asset UTXOs, `tx_refs`, Window records |
| `SUM` | Nonnegative integer weight | Sum of child weights | Parameter proposal selection |
| `MAX` | `ExecutiveRank(balance, updated, key)` | Greatest `(balance, updated)` and winning key | Executive election |

The registry includes `block_reward`, `exec_fund`, `utxo_fee`, `data_fee`, and
`bond_rate` SUM trees. Parameter proposal keys must preserve numeric order,
normally fixed-width unsigned big-endian encoding. Executive identifiers are
publisher-chosen; they need no relationship to executive balances.

`tx_refs` is an ordinary map from transaction hash to `(block_id, transaction_id)`
for transactions with `hash_ref=True`. Transaction policy and domain encoding
belong to the coordinator/codecs, not generic tree operations.

## Updates and queries

```python
tree = Critbit(store, kind, key_bytes)
value = tree.get(root, key)           # bytes | None
next_root = tree.update(root, items, remove=keys)
next_root = tree.update_difference(root, keys)
```

`update` is the primary per-block interface. `items` is a mapping or iterable of
key/value pairs. Ordinary values may be bytes; augmented values use
`Update(value, weight=...)` or `Update(value, balance=..., updated=...)`.
Amounts replace prior amounts; they are not increments. Inputs are copied and
validated. Duplicate upserts, duplicate removals, overlapping sets, and missing
removal keys are errors. Empty patches return the original root.

The patch uses an in-memory staging arena. Intermediate paths are discarded;
only nodes reachable from the final tree are allocated in the backing store.
Input errors leave the old root intact without backing allocations. A storage
failure while persisting the final nodes may leave unpublished allocations;
the transactional backend owns recovery and reclamation.

`put` and `delete` remain available for individual changes. Each returns a new
root. `delete` raises `KeyError` for absence. Large block patches should use the
batch interface to avoid persisting every intermediate path.

`select(root, rank)` selects a leaf by one-based cumulative SUM weight. It chooses
the left child when the rank is within its weight, otherwise subtracts that
weight and chooses the right child. `median` uses rank `(total+1)//2`; an empty
or zero-weight electorate returns `None`. Exact half-weight ties select the lower
proposal. Selection is by key order, not value-byte order.

`maximum` returns the cached executive rank or `None` for an empty tree. Promotion
and demotion change balance; ties prefer the greatest update position
`(block_id, transaction_id, output_id)`. Identifier order is not a tie breaker.
The implementation rejects an ambiguous equal winning rank for distinct keys.
Consensus must guarantee the intended update-position identity. Signed balances
are representable, but consensus decides whether negative balances are allowed.

## Window representation

`Window` wraps a MAP critbit tree with eight-byte unsigned big-endian sequence
keys. Each key maps an absolute record index to immutable variable-length bytes.
The normal active capacity is 2,000,000 records: 200 epochs of 10,000 blocks.

```python
WindowVersion(tree_root=0, start=0, end=0)
WindowRoot(tree_root=0, start=0, end=0, predecessors=())
window = Window(tree, capacity=2_000_000, delete_after=100)
root = window.empty()
root = window.advance(root, encoded_genesis)
record = window.get(root, 0)
root = window.rollback(root, blocks=1)
```

All bounds are half-open: the active interval is `[start, end)` and `size=end-start`.
Every index in that interval must have a record. Indices are never renumbered.
An out-of-window read raises `IndexError`; a missing in-window key signals invalid
state. An empty byte string is a valid record.

| State | Interval | Size |
| --- | --- | ---: |
| Empty | `[0,0)` | 0 |
| Genesis added at index 0 | `[0,1)` | 1 |
| Capacity reached | `[0,2_000_000)` | 2,000,000 |
| Record 2,000,000 added | `[1,2_000_001)` | 2,000,000 |

`advance(root, record)` calls `_advance_end` to insert at the current end and
then `_advance_start` to remove records exceeding capacity. Both helpers operate
within one staging arena, so only the final reachable nodes are persisted. The
returned root is still unpublished. One advance corresponds to one block/version.

`rollback(root, blocks)` selects a retained ancestor and calls `_rollback_start`
and `_rollback_end`. It restores the ancestor tree as well as its boundaries;
changing numerical bounds alone would not restore the correct records. The private
intermediate descriptors are not readable or publishable Windows. Rollback performs
no node allocation. Zero steps returns the same root; unavailable history is an error.

### Retention and branching

`delete_after` counts rollback steps, not per-record age. A WindowRoot retains its
current version plus up to `delete_after` predecessor versions, oldest first.
Predecessors are plain WindowVersion records with no recursively embedded history.
The initial empty version participates, so genesis can be rolled back when retained.
With zero retention, no predecessor can be selected through `rollback`.

For example, a capacity-three window after five appends has interval `[2,5)`.
With `delete_after=2`, it retains predecessors `[0,3)` and `[1,4)`. Rolling back
two steps restores `[0,3)`, including the original records at indices 0 and 1.
The old current root continues to read records 2 through 4 if another owner keeps it.

Rollback drops detached future versions from the returned predecessor list.
Appending to the restored root creates a branch: the new record at that absolute
index does not modify the old branch's record. Independently retained roots remain
valid. Repeated rollback cannot cross the oldest retained ancestor.

Exceeding capacity deletes the oldest key from the new tree immediately. Older
roots retain that record until their histories or external pins are released.
Exceeding `delete_after` removes the oldest predecessor from the returned root's
history; it does not physically erase nodes. Garbage collection must account for
every canonical, auxiliary, historical, and reader root. The current append-only
store does not yet reclaim unreachable records.

## Batch durability and persistence boundary

Trees and Windows do not commit themselves. A database block transaction must
publish all map roots and complete WindowRoot descriptors together, including
retained histories and identities. Flush new nodes and allocation metadata first,
then durably publish one root-set manifest, then acknowledge or announce commitment.
Rollback is itself a new durable publication selecting older versions.

`MappedTreeFile`, `RootManifest`, `FileState`, and `TransactionalBackend` in
`critbit.py` describe this contract. The concrete `db.py` backend currently
journals bare critbit roots, not Window bounds/history. Window checkpoint encoding,
manifest integration, and recovery therefore remain required work before a Window
can serve as a durable block log. Merely writing its nodes through a disk NodeStore
does not persist its interval or rollback history.

Each tree file is intended to reside at `~/.arka/db/<name>.bin` and contain its own
allocation tracking. References are offsets, never process addresses. Recovery
must expose a complete old or new database generation, never mixed tree roots.
Uncertain commit outcomes require recovery and identity checks before retry or
reclamation. Power-outage guarantees require platform-specific synchronization
and fault testing, not only logical tree tests.

## Defragmentation and replacement files

```python
new_root = tree.defrag(root, replacement_store)
new_window_root = window.defrag(window_root, replacement_store)
```

Both operations copy into a separate replacement store and return remapped roots;
neither changes the source tree, flushes files, or installs a replacement manifest.
The destination must have the same kind/key width and should be freshly created.
Construct a new Critbit/Window around that store to read the returned roots.

Traversal is left-first depth-first **postorder**, so children are allocated before
their parents. This matches the append-only node codec's backward-offset rule.
It groups subtrees in file order rather than historical update order. Caching
benefits depend on access patterns and must be measured; breadth-first placement
could be preferable for some lookup workloads.

A relocation map records source offset to replacement offset. Shared nodes are
copied once. When copying several retained roots, pass the same mapping as the
`relocations=` argument. Each mapping belongs exclusively to one source-file and
destination-file pair. Do not reuse it across files or after abandoning a failed
replacement. Zero roots require no allocation. Augmentations and values are
preserved, with child references remapped to the new offsets.

Window defrag starts with the oldest retained predecessor and proceeds forward
through the current version. Already relocated subtrees are reused; only new
records and changed paths are copied for each later root. This patches the copied
node graph forward without replaying transaction effects or copying the whole
window for every version. The returned WindowRoot retains the same interval and
rollback history, now referencing the replacement file.

Traversal uses memory proportional to path depth, but the default Python
relocation dictionary grows with the reachable node count. For billions of nodes,
provide an external-memory `MutableMapping` implementation; none is supplied here.
The destination's bounded mmap cache does not bound this relocation metadata.

Safe installation belongs to the database coordinator:

1. Pin the source generation and every root that must survive, including branches
   and readers. Freeze writers, or arrange explicit catch-up before publication.
2. Copy retained roots into a separately identified replacement file. For a Window,
   also preserve its bounds and complete retained-root descriptor.
3. Flush and synchronize the replacement and its allocation metadata. Verify the
   remapped roots before publishing them.
4. Durably publish one manifest containing the replacement file identity and all
   remapped roots. Switch new readers only after that commit.
5. Keep the old file until old readers/roots are released. Then reclaim it with the
   necessary filesystem durability barriers.

A filename rename by itself is insufficient: offsets and file identities changed,
and mapped readers may still refer to the old file. The current db.py manifest
replays historical file identities and has no replacement-generation checkpoint
mechanism. It therefore still needs coordinated swap/recovery support before
installing a defragmented live database. On copy failure, the source remains valid;
discard the unfinished replacement and its relocation session.

## Scale and verification

A critbit tree with N leaves has N-1 internal branches. Window indexing therefore
has more metadata than a page packing many sequence descriptors. Its benefit is
reuse of copy-on-write allocation and root management. Keep the Window interface
independent so a paged sequence index could replace it if profiling warrants it.
Batch staging consumes memory proportional to affected paths; no operation should
materialize the complete billion-record database in Python. Retained root history
is bounded by `delete_after`, though retained node volume depends on changes.

[test_critbit.py](../tests/test_critbit.py) verifies map updates, retained roots,
augmentation, and batch staging. [test_window.py](../tests/test_window.py) covers
capacity, root retention, genesis/empty state, rollback, branching, and failed
advance. Small capacities exercise the boundary algorithm; defaults separately
assert 2,000,000 active records and 100 rollback steps. These tests do not establish
Window manifest durability or garbage-collection safety.
