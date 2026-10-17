
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

