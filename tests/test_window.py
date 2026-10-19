import pytest

from arka.critbit import Critbit, Kind, Window
from test_critbit import Store


def test_capped_window_rollback_and_branch():
    store = Store()
    window = Window(Critbit(store, Kind.MAP, 8), capacity=3, delete_after=2)
    root = window.empty()
    for index in range(5):
        root = window.advance(root, bytes([index]))
    assert (root.start, root.end, root.size) == (2, 5, 3)
    assert len(root.predecessors) == 2
    assert window.tree.get(root.tree_root, (0).to_bytes(8, 'big')) is None
    with pytest.raises(IndexError):
        window.get(root, 1)
    before = len(store.nodes)
    ancestor = window.rollback(root, 2)
    assert len(store.nodes) == before
    assert (ancestor.start, ancestor.end) == (0, 3)
    assert [window.get(ancestor, i) for i in range(3)] == [b'\0', b'\1', b'\2']
    fork = window.advance(ancestor, b'fork')
    assert window.get(fork, 3) == b'fork'
    assert window.get(root, 3) == b'\3'
    assert window.rollback(fork).tree_root == ancestor.tree_root
    with pytest.raises(ValueError):
        window.rollback(root, 3)


def test_empty_genesis_and_no_history():
    window = Window(Critbit(Store(), Kind.MAP, 8), capacity=1, delete_after=0)
    empty = window.empty()
    genesis = window.advance(empty, b'')
    assert (genesis.start, genesis.end, genesis.size) == (0, 1, 1)
    assert window.get(genesis, 0) == b''
    assert not genesis.predecessors
    with pytest.raises(ValueError):
        window.rollback(genesis)
    assert window.rollback(genesis, 0) is genesis
    new = window.advance(genesis, b'next')
    assert (new.start, new.end) == (1, 2)
    assert window.get(genesis, 0) == b''


def test_failure_leaves_root_and_store_unchanged():
    store = Store()
    window = Window(Critbit(store, Kind.MAP, 8), capacity=2, delete_after=1)
    root = window.advance(window.empty(), b'genesis')
    count = len(store.nodes)
    with pytest.raises(TypeError):
        window.advance(root, 12)
    assert len(store.nodes) == count
    assert window.rollback(root) == window.empty()


def test_window_defaults():
    window = Window(Critbit(Store(), Kind.MAP, 8))
    assert window.capacity == 2_000_000
    assert window.delete_after == 100


def test_window_defrag_copies_oldest_first_and_retains_rollback():
    source, destination = Store(), Store()
    window = Window(Critbit(source, Kind.MAP, 8), capacity=3, delete_after=2)
    root = window.empty()
    for i in range(10):
        root = window.advance(root, bytes([i]))
    moved = {}
    compact = window.defrag(root, destination, relocations=moved)
    replacement = Window(Critbit(destination, Kind.MAP, 8), capacity=3, delete_after=2)
    assert len(destination.nodes) < len(source.nodes)
    assert moved[root.predecessors[0].tree_root] < compact.tree_root
    for steps in range(3):
        old = window.rollback(root, steps)
        new = replacement.rollback(compact, steps)
        assert (new.start, new.end) == (old.start, old.end)
        for i in range(old.start, old.end):
            assert replacement.get(new, i) == window.get(old, i)
