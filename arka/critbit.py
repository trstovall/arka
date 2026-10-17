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

Fixed-width keys are required within each tree. Parameter proposals use unsigned
big-endian keys so bit order equals numeric order. Other keys follow their domain
codec. Executive selection is by stored balance, not identifier ordering.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol


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
    'transaction_refs': Kind.MAP,  # hash_ref=True only: hash -> (block, tx)
    'block_reward': Kind.SUM,
    'exec_fund': Kind.SUM,
    'utxo_fee': Kind.SUM,
    'data_fee': Kind.SUM,
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


class NodeStore(Protocol):
    def read(self, offset: Offset) -> Node: ...
    def allocate(self, node: Node) -> Offset:
        """Persist an immutable node in this file's tracked allocation arena."""
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
