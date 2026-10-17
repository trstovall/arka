"""Logical sketch tests; these do not establish on-disk durability."""

import random

from arka.critbit import Critbit, Kind


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
