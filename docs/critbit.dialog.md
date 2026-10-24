
Following a discussion with ChatGPT, I am going to use a persistent augmented critbit tree to serve as the primary primitive to the database backend.

...

That fits both typed byte keys and weighted vote selection. The tree’s augmentation can maintain subtree vote weights, allowing median lookup by descending toward the target cumulative weight.

For this design, I’d use:

- Immutable nodes with copy-on-write paths, so canonical and auxiliary states share unchanged subtrees.
- Persistent root references for snapshots and rollback.
- An atomic root manifest that publishes all related database roots together.
- Order-preserving vote keys, such as fixed-width big-endian proposals, rather than the existing little-endian serialization.

The important distinction is between a critbit tree over arbitrary keys and one ordered by proposal value: weighted median selection requires the latter.

This replaces SQLite’s storage role while allowing the coordinator, parser, and broker interfaces to remain. The next document should define node encoding, augmentation, root publication, recovery, and reclamation before implementation.

---

The weighted median selection uses nodes which are augmented with the sum of the child weights.  So, the critbit tree indexes keys, and the augmentation indexes values.

...

Yes. The critbit structure indexes keys; each internal node stores the sum of its children’s weights.

For weighted selection at rank `r`, inspect the left subtree’s weight `L`:

- If `r ≤ L`, descend left.
- Otherwise, descend right with rank `r − L`.

The augmentation therefore selects by cumulative weight **in key order**. For a weighted median of proposals, keys must preserve proposal order, and leaf weights represent the aggregate UTXO balance voting for each proposal.

---

For executive voting, the balance is spent to promote or demote an executive by that amount.  Each epoch, the MAX by executive balance is selected as the epoch executive.  Keys are identifiers chosen by the Executive publisher.  Balances are chosen by voters.  Nodes in the tree are augmented by the MAX of the child nodes.

...

Yes. Executive selection uses a **maximum augmentation**, independent of identifier ordering.

- Each leaf maps a publisher-chosen executive identifier to its accumulated balance: promotions add the amount spent; demotions subtract it.
- Each internal node stores the maximum balance of its children.
- The root exposes the winning balance. Following children with that maximum locates the executive selected for the epoch.
- Updating a balance recomputes maxima along its path to the root.

Unlike weighted-median selection, identifiers need no relationship to balances. Consensus must define tie-breaking and whether demotions can produce negative balances.

---

To break ties, the most recently updated leaf that matches the maximum is tracked and selected.  Update ordering is standardized by greatest (block id, transaction id, output id) which can be implemented by updating a separate maximum accumulator each block.

...

Then each leaf’s selection rank is:

`(executive_balance, last_update_position)`

where `last_update_position = (block_id, transaction_id, output_id)`. Each internal node retains the lexicographic maximum rank and its executive identifier. The root selects the highest balance, breaking ties by the greatest update position.

A separate per-block accumulator can track update ordering, but it cannot alone maintain the global winner: if the current winner is demoted, an untouched executive may become maximal. Recomputing the tree’s augmentation along changed paths handles that case.

---

The critbit trees associated with ExecutiveDefinition, AssetDefinition, ArkaUTXO, and AssetUTXO are simple maps and do not need augmented nodes.

...

Understood. The trees share the persistent critbit structure, with augmentation determined by their purpose:

| Tree | Leaf value | Internal-node augmentation |
|---|---|---|
| ExecutiveDefinition | Executive definition | None |
| AssetDefinition | Asset definition | None |
| ArkaUTXO | Unspent ARKA output | None |
| AssetUTXO | Unspent asset output | None |
| Parameter votes | Weight for a proposal | Sum of child weights |
| Executive votes | Balance and last-update position | Maximum `(balance, update_position)` |

The four ordinary maps require only key lookup, insertion, replacement, and deletion; their internal nodes carry routing information alone.

---

Transactions that are tagged with hash\_ref=True have their transaction hash mapped to (block id, transaction id) in an additional ordinary map.

...

Add an unaugmented transaction-reference tree:

`TransactionHash → (block_id, transaction_id)`

Only transactions with `hash_ref=True` create entries. A hash-based UTXO reference resolves through this map, retaining its output ID to form `(block_id, transaction_id, output_id)`.

These entries must follow the same commit and rollback lifecycle as their containing blocks.

---

The backing database files are \~/.arka/db/\*.bin and memory mapped.  Allocation tracking is included within each file that contains each tree.

...

Each persistent critbit tree has its own memory-mapped file at `~/.arka/db/<tree>.bin`, containing:

- Tree metadata and root reference.
- Internal nodes and leaf records.
- Allocation metadata for that file.

Persistent references should use file-relative offsets, so remapping does not invalidate them. Allocation and reclamation must preserve nodes reachable from retained canonical or auxiliary roots.

---

Sketch implementation in arka/critbit.py

...

Added [arka/critbit.py](arka/critbit.py) with copy-on-write map operations, sum-based weighted selection, and executive maximum selection with update-position tie-breaking.

Outlined per-file allocation tracking, mmap storage, and atomic root publication. Those persistence interfaces remain explicitly unimplemented.

**3 logical algorithm tests passed.**

---

Updates are batched and must be transactional, durable, and recoverable after power outage.

...

Updated [arka/critbit.py](arka/critbit.py) with transactional batch interfaces and a power-loss recovery protocol: private roots, synchronized tree files, one durable manifest commit, and acknowledgement afterward.

Defined allocator recovery, retry identity, and crash-test requirements. These remain explicit implementation contracts; the sketch does not yet provide durable storage.

---

Update critbit.py Critbit to have update and update\_difference methods to allow a batch patch.  This is the primary update method since it is updated with each one minute block.  The singular methods may be useful in the future.

...

Added to [arka/critbit.py](arka/critbit.py):

- `update(root, items, remove=())` for combined block patches.
- `update_difference(root, keys)` for batch deletion.
- `Update` records for weighted and executive values.

Batches stage changes in memory and allocate only final reachable nodes. Original roots remain intact; durable publication still belongs to the transactional backend.

Single-key methods remain available. **6 tests passed.**

---

Flesh out codecs for the different node types and node stores based on codecs in block.py.  Write this to db.py.  Include a database coordinator and a discussion on allocation algorithm options.  Plan for billions of records.

...

Added [arka/db.py](arka/db.py) with:

- Versioned MAP, SUM, and MAX node codecs and `block.py` value adapters.
- Bounded-window mmap storage with per-file allocation checkpoints.
- Transactional root-set journaling and an async queue coordinator.
- Allocation tradeoffs and capacity planning for billions of records.

**14 tests passed.** Reclamation, journal compaction, and Windows power-loss qualification remain unfinished.

---

I am considering how to handle deltas for chain rollbacks.  Could I just keep a tree root for each block and truncate?

...

Yes. With immutable copy-on-write nodes, you can retain a **complete set of tree roots for each block** and roll back by selecting an earlier set. You do not need inverse deltas merely to restore tree state.

Each block’s checkpoint should include its identity, parent, all tree roots, and any associated log boundaries. Publish rollback as a **new durable manifest generation** pointing to the ancestor checkpoint, so recovery sees the rollback consistently.

“Truncate” needs two distinctions:

- **Logical truncation:** remove the detached suffix from the canonical chain and restore its ancestor roots. This is straightforward.
- **Physical truncation:** shorten backing files only when their discarded tails contain nothing reachable from any retained root—including auxiliary branches and readers. Otherwise, defer reclamation.

For a fork, start the candidate from the ancestor’s root set while canonical processing continues. Unchanged nodes remain shared.

Deltas may still help with inspection, replay, or effects outside the trees, but become optional for rollback if **every authoritative state change is covered by the checkpoint**. The current `db.py` retains root records in its journal, but still needs an explicit checkpoint-selection/rollback API.

---

The critbit tree is sufficient to replace the AsyncPersistentDictionary, but we need a series structure to store sequential data like blocks, headers, etc. including the allocation and copy on write.  A better AsyncPersistentLog.

...

A **persistent paged sequence** would complement the critbit maps well.

Use a copy-on-write radix tree indexed by absolute sequence number:

- **Leaf pages** hold record descriptors: file offset and byte length.
- **Internal pages** hold child offsets.
- **Record extents** hold immutable variable-length bytes, such as blocks.
- **A sequence root** records the index-tree root and retained interval `[first, stop)`.

This gives the operations needed for the chain:

| Operation | Behavior |
|---|---|
| Append batch | Write records, replace affected index pages, return a new root |
| Read by height | Descend through the index to its record descriptor |
| Truncate tail | Return a root with a smaller `stop` |
| Retire prefix | Advance `first`, preserving absolute heights |
| Fork | Share an ancestor root, then append a private suffix |
| Roll back | Restore a retained sequence root |

A partial final page must be copied before appending. After tail truncation, subsequent appends must replace descriptors at those positions rather than expose the detached suffix.

Each sequence file—such as `blocks.bin` or `headers.bin`—would contain its own allocation tracking, index pages, and record extents. Truncation is logical; physical space is reclaimed only when no retained root or reader references it.

The database manifest should publish **map roots and sequence roots together per block**. That makes a rollback restore both UTXO state and chain history atomically, without replaying inverse deltas.

I’d keep this as a separate `PersistentSeries` primitive, sharing the allocator and commit machinery with the critbit stores.

---

Truncate tail and retire prefix are similar operations but sound very different.

...

Agreed. Use symmetric names:

- `truncate_start(first)` removes entries before `first`.
- `truncate_end(stop)` removes entries at or after `stop`.

Both return a new root describing the retained interval `[first, stop)`, preserve absolute indices, and defer physical reclamation until no retained root references the removed data.

“Retirement” and “rollback” describe why the database changes those bounds, rather than different storage operations.

---

Also, rollback\_start, rollback\_end, rollback, and advance.

...

Then `Window` can expose symmetric boundary operations:

| Method | Effect |
|---|---|
| `advance_start` | Move start forward, excluding older records |
| `advance_end` | Append records, moving end forward |
| `advance` | Advance both boundaries in one batch |
| `rollback_start` | Restore an earlier start and its retained records |
| `rollback_end` | Restore an earlier end, excluding newer records |
| `rollback` | Restore both boundaries from a retained Window version |

Each operation returns a new root for `[start, end)`. Rollback must preserve the selected version’s record identities, not merely change numerical bounds; restoration requires retained data.

---

Window\.advance and Window\.rollback return the appropriate root after calling the appropriate
```python
Window._[rollback|advance]_[start|end]
```

...

Yes. The public methods coordinate the boundary changes:

```python
Window.advance(...) -> WindowRoot
Window.rollback(...) -> WindowRoot
```

They call the appropriate private helpers:

```python
Window._advance_start(...)
Window._advance_end(...)
Window._rollback_start(...)
Window._rollback_end(...)
```

Each public call returns one resulting `WindowRoot(tree_root, start, end)`. Intermediate roots remain unpublished; the database coordinator commits the final root with the other structures in the batch.

---

The Window begins empty.  Then a genesis block (index 0) is added and Window size is 1.  This grows to `2_000_000` blocks (200 epochs) capped.  Then block 2\_000\_000 is added, so advance(record\_2M) returns a root with 2\_000\_000 records ([1, 2\_000\_000]).  Record N remains until garbage collected determined by a delete\_after parameter.  So delete\_after=100 would delete record N when Window(start=a, end=b) for `a == N + delete_after` is added.

...

Understood. `Window` separates its **active bounds** from **retained records awaiting deletion**.

Using half-open bounds:

- Empty: `[0, 0)`.
- After genesis: `[0, 1)`.
- At capacity: `[0, 2_000_000)`.
- After adding record `2_000_000`: `[1, 2_000_001)`—still 2,000,000 active records.

On `advance(record)`, append at `end`, then move `start` as needed to enforce capacity.

With `delete_after=100`, record `N` remains retained after leaving the active window. When the new root has `start == N + 100`, remove its key from that new tree version.

That deletion makes its storage eligible for garbage collection; physical reclamation still waits until no retained root or reader references it. The returned root therefore describes 2,000,000 **active** records, while its underlying tree may temporarily contain additional retained records.

---

The delete\_after parameter controls the number of window roots retained (the last N == delete\_after).  This allows rolling back at most delete\_after blocks.

...

Understood—`delete_after` controls **root-history retention**, not a per-record expiration delay. Records become reclaimable only when unreachable from every retained root or reader.

To allow rollback by up to `delete_after` blocks, retain the **current root plus `delete_after` predecessor roots**. Keeping only `delete_after` roots total would allow at most `delete_after - 1` rollback steps.

---

Add Window to critbit.py and document critbit.py in docs/critbit.md

...

Added `Window` to [arka/critbit.py](arka/critbit.py), with capped advance, retained-root rollback, and branch-safe records.

Created [docs/critbit.md](docs/critbit.md) covering trees, augmentation, batch updates, Window semantics, and persistence boundaries.

**10 tests passed.** Persisting Window bounds and history in the database manifest remains unfinished.

---

The critbit trees become fragmented and randomly oriented.  The backing file can be defragmented and ordered by depth first traversal and copy to a replacement file improving caching then swapped.  For Window, start with the oldest retained root and patch forward.  Add a defrag method to Critbit and Window and document.

...

Added `Critbit.defrag()` and `Window.defrag()` in [arka/critbit.py](arka/critbit.py). They copy nodes in depth-first order, preserve sharing, and remap roots. Window processes retained versions oldest-first.

Documented usage, scaling, and safe file replacement in [docs/critbit.md](docs/critbit.md).

**23 tests passed**, including mmap reopen. Live file swapping remains coordinator work.

---

critbit.md describes Window representation as wrapping a MAP critbit tree.  But all trees need to be windowed.  The window is just the last `delete_after` tree root generations.  Rollback past `delete_after` roots is prevented.

...

Understood. `Window` should manage **root-generation history for every tree kind**—MAP, SUM, and MAX—not represent a sequence of records.

- Each committed block adds one root generation, even if that tree’s root is unchanged.
- Retain the current generation plus `delete_after` predecessors.
- Rollback selects a retained generation; deeper rollback is rejected.
- Publish all trees’ generations together so rollback restores one coherent database state.

The 2,000,000-block cap and absolute record indices belong to the block sequence, separately from root retention. The current `Window` implementation and documentation conflate those responsibilities and need to be revised.

---

The blocks themselves are the deltas to the tree structures.  Candidate block processing threads should greedily seek the next block and should prevent rolling back past `delete_after`.  They maintain a 2M + 1 block rolling window of block chain plus candidate.  While `delete_after` controls root retension, the 2\_000\_000 constant is hard-coded.

...

Understood. These are separate limits:

- **Tree history:** Every tree retains its current root plus `delete_after` predecessor generations. Rollback beyond that retained history is prohibited.
- **Block history:** Candidate processing maintains a hard-coded rolling window of **2,000,000 chain blocks plus one candidate block**.
- **Processing:** Each candidate worker greedily obtains the next available block and derives the next tree roots from it. A block supplies the transition instructions; retained roots supply rollback, without inverse-delta replay.
- **Publication:** A completed block’s roots across all trees form one coherent generation.

Replaying a block still requires its parent state to resolve spends and other referenced values. The block alone is not a standalone before/after state snapshot.

