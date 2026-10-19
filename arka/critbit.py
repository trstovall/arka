"""Implementation sketch for memory-mapped persistent critbit trees.

Each tree owns ~/.arka/db/<name>.bin, including its allocation metadata.
References are file-relative offsets; zero denotes an empty root. Nodes are
immutable: an update allocates a leaf and the changed path, returning a new
root. Canonical and auxiliary views retain different roots in the same files.

The tree algorithms below define the logical implementation. MappedTreeFile and
RootManifest intentionally leave the on-disk codec, allocator and crash recovery
unimplemented. This is not yet a replacement for sql.py.

Proposed file regions (versioned, exact binary widths still to be specified):
    superblocks A/B: magic, version, tree kind, generation, allocation extent,
                    allocator metadata pointer, checksum
    allocation metadata: allocated/free extents and deferred retirements
    node arena: immutable leaf and branch records addressed by offset

Commit order: write nodes and allocation metadata; flush mappings and synchronize
files; atomically publish one manifest referencing all tree roots. Recover from
the last valid manifest. A per-file root alone cannot publish a multi-tree block.
Do not reuse nodes reachable from canonical, auxiliary, historical, or reader
roots. Reclaim abandoned allocations only after reachability/recovery checks.

Updates are transactional batches, not separately published tree mutations.
Readers pin one committed generation covering every tree. A batch builds private
roots and allocator generations under a single database writer gate. An error
aborts the complete batch; no partial root set becomes visible. Durable commit
must finish before returning success or emitting a broker commit event.

Required power-loss protocol (not implemented by this sketch):
  1. Reserve fresh extents without altering live nodes or the committed allocator
     snapshot. Write copy-on-write nodes, summaries and allocator metadata.
  2. Flush modified mappings, then synchronize every participating backing file,
     including file growth. An mmap flush alone is not the durability contract.
  3. Append a framed, checksummed commit record to a database-wide manifest.bin:
     batch identity, parent/new generation, block identity, complete root sets,
     file identities, durable extents and allocator roots. Synchronize this file.
     Synchronize directory metadata when required for newly created files.
  4. Make the generation visible and acknowledge. Per-tree superblocks are hints;
     they cannot independently decide which multi-tree batch committed.

Recovery validates the manifest's committed prefix and all referenced file bounds
and metadata. An incomplete final record is an uncommitted tail. Corruption inside
committed history is an error, not permission to silently discard acknowledged
blocks. Replay the last complete commit, ignoring unpublished roots/allocations.
Never reuse extents until recovery and retained-root reachability prove them free.
If a commit becomes durable before its response is delivered, a retry with the
same batch identity must report that result; conflicting reuse must be rejected.

Fault-injection tests must interrupt every write/flush/publication boundary,
simulate torn final records and allocator updates, and reopen all files. Recovery
must expose a complete old or new generation, never mixed roots. These guarantees
require an actual disk format and platform durability implementation; the logical
algorithms and interfaces here alone do not provide power-outage recovery.

Fixed-width keys are required within each tree. Parameter proposals use unsigned
big-endian keys so bit order equals numeric order. Other keys follow their domain
codec. Executive selection is by stored balance, not identifier ordering.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Protocol


DB_HOME = Path('~/.arka/db').expanduser()
Offset = int
Position = tuple[int, int, int]  # block id, transaction id, output id


class Kind(Enum):
    MAP = 'map'
    SUM = 'sum'
    MAX = 'max'


TREE_KINDS = {
    'executive_definitions': Kind.MAP,
    'asset_definitions': Kind.MAP,
    'arka_utxos': Kind.MAP,
    'asset_utxos': Kind.MAP,
    'tx_refs': Kind.MAP,        # hash_ref=True only: hash -> (block, tx)
    'block_reward': Kind.SUM,
    'exec_fund': Kind.SUM,
    'utxo_fee': Kind.SUM,
    'data_fee': Kind.SUM,
    'bond_rate': Kind.SUM,
    'executive_votes': Kind.MAX,
}


@dataclass(frozen=True)
class ExecutiveRank:
    balance: int
    updated: Position
    key: bytes  # Winning executive identifier, for selection without another walk.


Summary = int | ExecutiveRank | None


@dataclass(frozen=True)
class Leaf:
    key: bytes
    value: bytes
    summary: Summary = None


@dataclass(frozen=True)
class Branch:
    bit: int  # Zero-based, most significant bit first; increases down a path.
    left: Offset
    right: Offset
    summary: Summary = None


Node = Leaf | Branch


@dataclass(frozen=True)
class Update:
    """Replacement value and augmentation for one key in a block patch."""

    value: bytes
    weight: int | None = None
    balance: int | None = None
    updated: Position | None = None


class _PatchStore:
    """Stage intermediate nodes in memory; persist only the final reachable DAG."""

    def __init__(self, base: NodeStore):
        self.base = base
        self.nodes: dict[Offset, Node] = {}

    def read(self, offset: Offset) -> Node:
        return self.nodes[offset] if offset < 0 else self.base.read(offset)

    def allocate(self, node: Node) -> Offset:
        offset = -len(self.nodes) - 1
        self.nodes[offset] = node
        return offset

    def persist(self, root: Offset) -> Offset:
        translated = {0: 0}
        pending = [(root, False)]
        while pending:
            offset, visited = pending.pop()
            if offset >= 0 or offset in translated:
                continue
            node = self.nodes[offset]
            if isinstance(node, Branch):
                if not visited:
                    pending.extend(((offset, True), (node.right, False), (node.left, False)))
                    continue
                node = Branch(node.bit, translated.get(node.left, node.left),
                              translated.get(node.right, node.right), node.summary)
            translated[offset] = self.base.allocate(node)
        return translated.get(root, root)


class NodeStore(Protocol):
    def read(self, offset: Offset) -> Node: ...
    def allocate(self, node: Node) -> Offset:
        """Stage an immutable node; allocation alone does not imply durability."""
        ...


class MappedTreeFile:
    """Planned mmap-backed NodeStore; one owner serializes mutation per file.

    On open, verify kind/key width, generations, extents and record boundaries.
    Ordinary branches encode only critical bit and child offsets, with no
    augmentation payload. SUM/MAX records add their respective summaries.
    Weight sums must not be limited to the width of one UTXO's balance.

    Growth must coordinate readers before resizing/remapping; retain offsets,
    never exported memoryviews or process addresses, across remaps. Allocation
    bookkeeping must be durable before a root can expose newly allocated nodes.
    Blocking mapping/flush operations belong on the backend's owning executor.
    """

    def __init__(self, path: Path, kind: Kind, key_bytes: int):
        self.path, self.kind, self.key_bytes = path, kind, key_bytes

    def open(self) -> MappedTreeFile:
        raise NotImplementedError('Specify and implement mmap file format/recovery')

    def read(self, offset: Offset) -> Node:
        raise NotImplementedError('Decode a bounded, validated node record')

    def allocate(self, node: Node) -> Offset:
        raise NotImplementedError('Allocate and track a copy-on-write node')

    def flush(self) -> None:
        raise NotImplementedError('Flush mapping and synchronize backing file')

    def reclaim(self, retained_roots: tuple[Offset, ...]) -> None:
        raise NotImplementedError('Reclaim only unreachable, unpinned allocations')

    def close(self) -> None:
        raise NotImplementedError('Drain readers, release mapping and file handle')


class RootManifest(Protocol):
    def publish(self, expected_generation: int, roots: Mapping[str, Offset]) -> int:
        """Durably publish all roots together after flushing their tree files.

        Compare the expected generation to prevent publishing against a stale
        tip. Include block identity and every retained root in the eventual
        manifest format. Return the new generation; publication is not a plain
        series of independent per-tree assignments.
        """
        ...


@dataclass(frozen=True)
class FileState:
    """One file's prepared state referenced by a durable batch commit.

    file_id distinguishes file replacement from offset reuse. allocator_root
    refers to allocation tracking inside this same tree file. durable_extent
    bounds every referenced record; it is not permission to reclaim older roots.
    """

    file_id: bytes
    root: Offset
    allocator_root: Offset
    durable_extent: int


class TransactionalBackend(Protocol):
    """Required persistence boundary; implementations must enforce these effects.

    begin captures a complete generation and admits one writer. Tree operations
    subsequently allocate within that batch. commit includes unchanged files and
    the retained canonical/auxiliary/history root sets in its manifest record.
    Implementations must freeze caller mappings before accepting them.
    """

    def begin(self, batch_id: bytes, expected_generation: int) -> None: ...

    def commit(self, batch_id: bytes, block_hash: bytes,
               files: Mapping[str, FileState],
               retained_roots: Mapping[str, Mapping[str, Offset]]) -> int:
        """Flush prepared files, durably publish one commit, then return generation.

        Failure during final synchronization can leave the outcome uncertain;
        recover and query the batch identity before retrying or reclaiming data.
        """
        ...

    def abort(self, batch_id: bytes) -> None:
        """Discard an unpublished batch; never undo an already durable commit."""
        ...

    def recover(self) -> int:
        """Restore the last complete committed generation before admitting work."""
        ...


class Critbit:
    """Copy-on-write algorithms over a validated NodeStore.

    Methods return roots without publishing or freeing the previous version.
    A block coordinator batches updates to private roots, then publishes them
    together. Rollback selects retained roots; auxiliary branches start from
    the ancestor roots. This primitive does not validate transactions or votes.
    """

    def __init__(self, store: NodeStore, kind: Kind, key_bytes: int):
        if key_bytes <= 0:
            raise ValueError('Keys must have a positive fixed width')
        self.store, self.kind, self.key_bytes = store, kind, key_bytes

    def _key(self, key: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError('Expected key bytes')
        key = bytes(key)
        if len(key) != self.key_bytes:
            raise ValueError('Incorrect key width')
        return key

    @staticmethod
    def _direction(key: bytes, bit: int) -> int:
        return (key[bit // 8] >> (7 - bit % 8)) & 1

    def _path(self, root: Offset, key: bytes):
        path = []
        while root:
            node = self.store.read(root)
            if isinstance(node, Leaf):
                return path, node
            direction = self._direction(key, node.bit)
            path.append((node, direction))
            root = node.right if direction else node.left
        return path, None

    def get(self, root: Offset, key: bytes) -> bytes | None:
        key = self._key(key)
        _, leaf = self._path(root, key)
        return leaf.value if leaf is not None and leaf.key == key else None

    def update(self, root: Offset,
               items: Mapping[bytes, bytes | Update] | Iterable[tuple[bytes, bytes | Update]],
               *, remove: Iterable[bytes] = ()) -> Offset:
        """Primary per-block patch: upsert items and remove keys as one root change.

        Ordinary map items may be bytes; augmented items use Update(value,
        weight=...) or Update(value, balance=..., updated=...). Values replace
        current values; weights/balances are absolute, not increments. Input
        order does not define executive recency: the explicit position does.

        Reject duplicate upserts, duplicate removals, overlapping sets and missing
        removal keys. Empty patches return the original root. Validate and stage
        the entire patch before allocating persistent nodes. Intermediate paths
        are kept in memory; only nodes reachable from the final root are written.
        Unchanged subtrees remain shared with the original root.

        No root is published here. The caller's transactional backend must flush
        and publish this root with the other trees in the one-minute block batch.
        Allocation failure can leave unpublished nodes for backend abort/recovery;
        the original root remains intact. This is not a durable commit by itself.
        """
        replacements = {}
        for key, value in items.items() if isinstance(items, Mapping) else items:
            key = self._key(key)
            if key in replacements:
                raise ValueError('Duplicate update key')
            value = value if isinstance(value, Update) else Update(value)
            if not isinstance(value.value, (bytes, bytearray, memoryview)):
                raise TypeError('Expected value bytes')
            replacements[key] = Update(bytes(value.value), value.weight, value.balance,
                                       None if value.updated is None else tuple(value.updated))
        removals = set()
        for key in remove:
            key = self._key(key)
            if key in removals or key in replacements:
                raise ValueError('Duplicate or overlapping removal key')
            removals.add(key)
        if not replacements and not removals:
            return root
        staged = _PatchStore(self.store)
        tree = Critbit(staged, self.kind, self.key_bytes)
        # Remove replaced leaves too, avoiding transient executive rank clashes
        # when valid final ranks move between leaves in a single atomic patch.
        for key in sorted(removals | replacements.keys()):
            if tree.get(root, key) is not None:
                root = tree.delete(root, key)
            elif key in removals:
                raise KeyError(key)
        for key, value in sorted(replacements.items()):
            root = tree.put(root, key, value.value, weight=value.weight,
                            balance=value.balance, updated=value.updated)
        return staged.persist(root)

    def update_difference(self, root: Offset, keys: Iterable[bytes]) -> Offset:
        """Remove a batch of existing keys; return one unpublished replacement root.

        For a combined insertion/replacement/deletion patch, use
        update(root, items, remove=keys) so both sets are staged together.
        """
        return self.update(root, (), remove=keys)

    def _branch(self, bit: int, left: Offset, right: Offset) -> Offset:
        summary = None
        if self.kind != Kind.MAP:
            a, b = self.store.read(left).summary, self.store.read(right).summary
            if self.kind == Kind.SUM:
                summary = a + b
            else:
                # Exact rank ties between distinct executives are not silently
                # broken by identifier order: output positions must be unique.
                if (a.balance, a.updated) == (b.balance, b.updated) and a.key != b.key:
                    raise ValueError('Ambiguous executive update position')
                summary = max((a, b), key=lambda rank: (rank.balance, rank.updated))
        return self.store.allocate(Branch(bit, left, right, summary))

    def _rebuild(self, path, child: Offset) -> Offset:
        for parent, direction in reversed(path):
            child = self._branch(parent.bit, parent.left if direction else child,
                                 child if direction else parent.right)
        return child

    def put(self, root: Offset, key: bytes, value: bytes, *,
            weight: int | None = None, balance: int | None = None,
            updated: Position | None = None) -> Offset:
        key = self._key(key)
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError('Expected value bytes')
        summary = None
        if self.kind == Kind.SUM:
            if type(weight) is not int or weight < 0 or balance is not None or updated is not None:
                raise ValueError('SUM leaves require a nonnegative integer weight')
            summary = weight
        elif self.kind == Kind.MAX:
            if (type(balance) is not int or updated is None or len(updated) != 3
                    or any(type(i) is not int or i < 0 for i in updated) or weight is not None):
                raise ValueError('MAX leaves require balance and output position')
            # Signed balances are representable here; consensus decides whether
            # demotions below zero are permitted.
            summary = ExecutiveRank(balance, tuple(updated), key)
        elif weight is not None or balance is not None or updated is not None:
            raise ValueError('Ordinary maps have no augmentation')
        path, old = self._path(root, key)
        child = self.store.allocate(Leaf(key, bytes(value), summary))
        if old is None:
            return child
        if old.key == key:
            return self._rebuild(path, child)
        difference = int.from_bytes(key, 'big') ^ int.from_bytes(old.key, 'big')
        bit = self.key_bytes * 8 - difference.bit_length()
        split = 0
        subtree = root
        while split < len(path) and path[split][0].bit < bit:
            parent, direction = path[split]
            subtree = parent.right if direction else parent.left
            split += 1
        if self._direction(key, bit):
            child = self._branch(bit, subtree, child)
        else:
            child = self._branch(bit, child, subtree)
        return self._rebuild(path[:split], child)

    def delete(self, root: Offset, key: bytes) -> Offset:
        key = self._key(key)
        path, leaf = self._path(root, key)
        if leaf is None or leaf.key != key:
            raise KeyError(key)
        if not path:
            return 0
        parent, direction = path.pop()
        return self._rebuild(path, parent.left if direction else parent.right)

    def select(self, root: Offset, rank: int) -> Leaf:
        """Select the leaf containing a one-based cumulative weight rank."""
        if self.kind != Kind.SUM:
            raise TypeError('Weighted selection requires a SUM tree')
        if not root or not 1 <= rank <= self.store.read(root).summary:
            raise ValueError('Rank outside total weight')
        node = self.store.read(root)
        while isinstance(node, Branch):
            left = self.store.read(node.left)
            if rank <= left.summary:
                node = left
            else:
                rank -= left.summary
                node = self.store.read(node.right)
        return node

    def median(self, root: Offset) -> Leaf | None:
        """Lower weighted median; empty or zero total weight has no median."""
        if self.kind != Kind.SUM:
            raise TypeError('Median requires a SUM tree')
        total = self.store.read(root).summary if root else 0
        return self.select(root, (total + 1) // 2) if total else None

    def maximum(self, root: Offset) -> ExecutiveRank | None:
        """Highest balance, then greatest (block, transaction, output) position."""
        if self.kind != Kind.MAX:
            raise TypeError('Executive selection requires a MAX tree')
        return self.store.read(root).summary if root else None

    def defrag(self, root: Offset, destination: NodeStore, *,
               relocations: MutableMapping[Offset, Offset] | None = None) -> Offset:
        """Copy reachable nodes in left-first depth-first postorder.

        Return a root in destination; this tree and all source roots stay intact.
        Children are allocated before parents, as required by the append-only
        db.py codec. Each shared node is copied once per relocation session.
        Supply the same mapping to copy additional retained roots from the SAME
        source file into the SAME destination. Start with an empty mapping and
        fresh replacement store; never reuse it after discarding that store.

        Traversal memory is bounded by tree depth, but the default relocation
        dictionary is O(reachable nodes). At billions of records supply an
        external-memory MutableMapping. Source offsets are not globally unique:
        mappings must not be shared between different source/destination pairs.

        This method neither flushes nor swaps files. The owner pins source roots,
        copies every retained version, synchronizes the destination, and commits
        a manifest binding new file identity and remapped roots before switching
        readers. On failure discard the replacement and relocation session.
        """
        if destination is self.store:
            raise ValueError('Defrag requires a separate replacement store')
        source_path = getattr(self.store, 'path', None)
        target_path = getattr(destination, 'path', None)
        if source_path is not None and target_path is not None:
            if Path(source_path).resolve() == Path(target_path).resolve():
                raise ValueError('Defrag cannot overwrite its source file')
        codec = getattr(destination, 'codec', None)
        if codec is not None and (codec.kind != self.kind or codec.key_bytes != self.key_bytes):
            raise ValueError('Replacement store has a different schema')
        moved = {} if relocations is None else relocations
        if not root:
            return 0
        pending = [(root, None)]
        visiting = set()
        while pending:
            offset, parent = pending.pop()
            if offset in moved:
                continue
            if parent is not None:
                node = Branch(parent.bit, moved[parent.left], moved[parent.right], parent.summary)
                moved[offset] = destination.allocate(node)
                visiting.remove(offset)
                continue
            if offset in visiting:
                raise ValueError('Cyclic source tree')
            node = self.store.read(offset)
            if isinstance(node, Leaf):
                moved[offset] = destination.allocate(node)
            else:
                visiting.add(offset)
                pending.extend(((offset, node), (node.right, None), (node.left, None)))
        return moved[root]


@dataclass(frozen=True)
class WindowVersion:
    """One sequence version: absolute interval [start, end) and its tree root."""

    tree_root: Offset = 0
    start: int = 0
    end: int = 0

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class WindowRoot(WindowVersion):
    """Current version plus oldest-to-newest rollback predecessors.

    Predecessors are plain versions, not recursive history objects. Persist this
    complete descriptor with the database manifest, not merely tree_root.
    """

    predecessors: tuple[WindowVersion, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, 'predecessors', tuple(self.predecessors))


class Window:
    """Capped persistent sequence over an ordinary 64-bit-key critbit map.

    advance(root, record) adds one record/block and returns an unpublished root.
    rollback(root, blocks) selects a retained ancestor and drops detached future
    versions from the returned history. Both leave their input root untouched.
    delete_after counts rollback steps: keep current plus that many predecessors.
    A caller retaining another root explicitly pins its data independently.

    Keys are absolute indices encoded as eight-byte unsigned big-endian integers.
    Advancing past capacity removes the oldest key from the new tree, but its
    bytes remain reachable from older roots. Neither operation frees storage.
    Root descriptors/history still require transactional persistence by the owner.
    """

    def __init__(self, tree: Critbit, capacity: int = 2_000_000,
                 delete_after: int = 100):
        if tree.kind != Kind.MAP or tree.key_bytes != 8:
            raise ValueError('Window requires an ordinary map with eight-byte keys')
        if type(capacity) is not int or capacity <= 0:
            raise ValueError('Capacity must be positive')
        if type(delete_after) is not int or delete_after < 0:
            raise ValueError('delete_after must be nonnegative')
        self.tree, self.capacity, self.delete_after = tree, capacity, delete_after

    @staticmethod
    def empty() -> WindowRoot:
        return WindowRoot()

    def _validate(self, root: WindowRoot):
        versions = (*root.predecessors, WindowVersion(root.tree_root, root.start, root.end))
        if len(root.predecessors) > self.delete_after:
            raise ValueError('History exceeds retention limit')
        for version in versions:
            if (not 0 <= version.start <= version.end <= 2**64
                    or version.size > self.capacity
                    or version.start != max(0, version.end - self.capacity)
                    or (version.tree_root == 0) != (version.size == 0)):
                raise ValueError('Invalid Window version')
        if any(b.end != a.end + 1 for a, b in zip(versions, versions[1:])):
            raise ValueError('Window history must contain consecutive versions')

    def get(self, root: WindowRoot, index: int) -> bytes:
        self._validate(root)
        if type(index) is not int or not root.start <= index < root.end:
            raise IndexError(index)
        result = self.tree.get(root.tree_root, index.to_bytes(8, 'big'))
        if result is None:
            raise ValueError('Missing record inside Window interval')
        return result

    def _advance_end(self, version: WindowVersion, record: bytes,
                     tree: Critbit) -> WindowVersion:
        if version.end >= 2**64:
            raise OverflowError('Window sequence number exhausted')
        root = tree.put(version.tree_root, version.end.to_bytes(8, 'big'), record)
        return WindowVersion(root, version.start, version.end + 1)

    def _advance_start(self, version: WindowVersion, tree: Critbit) -> WindowVersion:
        start = max(version.start, version.end - self.capacity)
        root = version.tree_root
        for index in range(version.start, start):
            root = tree.delete(root, index.to_bytes(8, 'big'))
        return WindowVersion(root, start, version.end)

    def advance(self, root: WindowRoot, record: bytes) -> WindowRoot:
        self._validate(root)
        # Both boundary changes share one staging arena. Only the final tree's
        # reachable nodes are allocated in the backing store.
        staged = _PatchStore(self.tree.store)
        tree = Critbit(staged, Kind.MAP, 8)
        version = self._advance_start(self._advance_end(root, record, tree), tree)
        history = (*root.predecessors, WindowVersion(root.tree_root, root.start, root.end))
        history = history[-self.delete_after:] if self.delete_after else ()
        return WindowRoot(staged.persist(version.tree_root), version.start, version.end, history)

    @staticmethod
    def _rollback_start(current: WindowVersion, ancestor: WindowVersion) -> WindowVersion:
        # Private intermediate descriptor; not a readable or publishable window.
        # The ancestor tree restores the actual old prefix, not just its index.
        return WindowVersion(ancestor.tree_root, ancestor.start, current.end)

    @staticmethod
    def _rollback_end(current: WindowVersion, ancestor: WindowVersion) -> WindowVersion:
        return WindowVersion(current.tree_root, current.start, ancestor.end)

    def rollback(self, root: WindowRoot, blocks: int = 1) -> WindowRoot:
        self._validate(root)
        if type(blocks) is not int or not 0 <= blocks <= len(root.predecessors):
            raise ValueError('Rollback exceeds retained history')
        if blocks == 0:
            return root
        ancestor = root.predecessors[-blocks]
        version = self._rollback_end(self._rollback_start(root, ancestor), ancestor)
        return WindowRoot(version.tree_root, version.start, version.end,
                          root.predecessors[:-blocks])

    def defrag(self, root: WindowRoot, destination: NodeStore, *,
               relocations: MutableMapping[Offset, Offset] | None = None) -> WindowRoot:
        """Copy the oldest retained version first, then patch forward by sharing.

        Later versions reuse already relocated subtrees; only their new paths
        and records are copied. No transaction replay or reconstruction of missing
        history is needed. Return all remapped bounds/history in one descriptor.
        Read it through a Window wrapping destination, not through this Window.
        External branch/reader roots require copying too or pinning the old file.
        See Critbit.defrag for manifest publication and mapping-size requirements.
        """
        self._validate(root)
        moved = {} if relocations is None else relocations
        versions = []
        for version in (*root.predecessors, root):
            copied = self.tree.defrag(version.tree_root, destination, relocations=moved)
            versions.append(WindowVersion(copied, version.start, version.end))
        current = versions[-1]
        return WindowRoot(current.tree_root, current.start, current.end, tuple(versions[:-1]))
