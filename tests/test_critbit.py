"""Logical sketch tests; these do not establish on-disk durability."""

import random
import pytest

from arka.critbit import Critbit, Kind, Update


class Store:
    def __init__(self):
        self.nodes = {}

    def read(self, offset):
        return self.nodes[offset]

    def allocate(self, node):
        offset = len(self.nodes) + 1
        self.nodes[offset] = node
        return offset


def test_map_paths_and_retained_roots():
    tree = Critbit(Store(), Kind.MAP, 2)
    keys = list(range(100))
    random.Random(42).shuffle(keys)
    root = 0
    for key in keys:
        root = tree.put(root, key.to_bytes(2, 'big'), bytes([key]))
    retained = root
    for key in keys:
        assert tree.get(root, key.to_bytes(2, 'big')) == bytes([key])
        root = tree.delete(root, key.to_bytes(2, 'big'))
        assert tree.get(root, key.to_bytes(2, 'big')) is None
        assert tree.get(retained, key.to_bytes(2, 'big')) == bytes([key])
    assert root == 0


def test_weighted_selection_and_replacement():
    tree = Critbit(Store(), Kind.SUM, 1)
    root = 0
    for proposal, weight in ((30, 30), (10, 40), (20, 30)):
        root = tree.put(root, bytes([proposal]), b'', weight=weight)
    assert tree.median(root).key == bytes([20])
    assert tree.select(root, 40).key == bytes([10])
    changed = tree.put(root, bytes([20]), b'', weight=0)
    assert tree.median(changed).key == bytes([10])
    assert tree.median(root).key == bytes([20])


def test_executive_tie_and_winner_demotion():
    tree = Critbit(Store(), Kind.MAX, 1)
    root = tree.put(0, b'a', b'', balance=20, updated=(1, 0, 0))
    root = tree.put(root, b'b', b'', balance=20, updated=(1, 0, 1))
    assert tree.maximum(root).key == b'b'
    changed = tree.put(root, b'b', b'', balance=10, updated=(2, 0, 0))
    assert tree.maximum(changed).key == b'a'
    assert tree.maximum(root).key == b'b'


def test_batch_patch_retains_root_and_writes_only_final_nodes():
    store = Store()
    tree = Critbit(store, Kind.MAP, 1)
    root = tree.update(0, {bytes([i]): bytes([i]) for i in range(100)})
    assert len(store.nodes) == 199  # Final leaves and branches, no intermediate paths.
    changed = tree.update(root, {b'\x00': b'new', b'\xff': b''}, remove=[b'\x01'])
    assert tree.get(root, b'\x00') == b'\x00'
    assert tree.get(changed, b'\x00') == b'new'
    assert tree.get(changed, b'\x01') is None
    assert tree.get(changed, b'\xff') == b''
    assert tree.update(root, {}) == root
    assert tree.update_difference(root, []) == root
    assert tree.update_difference(root, (bytes([i]) for i in range(100))) == 0


def test_invalid_patch_allocates_nothing():
    store = Store()
    tree = Critbit(store, Kind.SUM, 1)
    root = tree.update(0, {b'a': Update(b'', weight=10)})
    count = len(store.nodes)
    with pytest.raises(ValueError):
        tree.update(root, {b'b': Update(b'', weight=-1)}, remove=[b'a'])
    with pytest.raises(KeyError):
        tree.update_difference(root, [b'a', b'z'])
    with pytest.raises(ValueError):
        tree.update(root, [(b'a', b''), (b'a', b'')])
    with pytest.raises(ValueError):
        tree.update(root, {b'a': Update(b'', weight=3)}, remove=[b'a'])
    assert len(store.nodes) == count
    assert tree.median(root).key == b'a'


def test_augmented_batch_selection():
    tree = Critbit(Store(), Kind.SUM, 1)
    root = tree.update(0, {b'a': Update(b'', weight=40), b'b': Update(b'', weight=30),
                           b'c': Update(b'', weight=30)})
    assert tree.median(root).key == b'b'
    changed = tree.update(root, {b'c': Update(b'', weight=90)}, remove=[b'b'])
    assert tree.median(changed).key == b'c'
    maximum = Critbit(Store(), Kind.MAX, 1)
    root = maximum.update(0, {b'a': Update(b'', balance=10, updated=(1, 0, 0)),
                              b'b': Update(b'', balance=10, updated=(1, 0, 1))})
    changed = maximum.update(root, {b'a': Update(b'', balance=10, updated=(1, 0, 1)),
                                    b'b': Update(b'', balance=10, updated=(1, 0, 0))})
    assert maximum.maximum(root).key == b'b'
    assert maximum.maximum(changed).key == b'a'


@pytest.mark.parametrize('kind', [Kind.MAP, Kind.SUM, Kind.MAX])
def test_defrag_retains_augmentation_and_shares_roots(kind):
    store, destination = Store(), Store()
    tree = Critbit(store, kind, 1)
    def value(number):
        if kind == Kind.SUM:
            return Update(bytes([number]), weight=number)
        if kind == Kind.MAX:
            return Update(bytes([number]), balance=number, updated=(1, number, 0))
        return bytes([number])
    root = tree.update(0, {b'a': value(1), b'b': value(2)})
    later = tree.update(root, {b'c': value(3)})
    moved = {}
    first = tree.defrag(root, destination, relocations=moved)
    second = tree.defrag(later, destination, relocations=moved)
    copy = Critbit(destination, kind, 1)
    assert copy.get(first, b'c') is None
    assert copy.get(second, b'c') == b'\3'
    assert copy.get(first, b'a') == tree.get(root, b'a')
    assert destination.read(second).summary == store.read(later).summary
    count = len(destination.nodes)
    assert tree.defrag(later, destination, relocations=moved) == second
    assert len(destination.nodes) == count
    from arka.critbit import Branch
    for offset, node in destination.nodes.items():
        if isinstance(node, Branch):
            assert node.left < offset and node.right < offset
    with pytest.raises(ValueError):
        tree.defrag(root, store)
