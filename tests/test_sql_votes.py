"""Exact cached voting, publication boundaries and atomic reversal."""

import asyncio

import pytest

from arka import block, sql
from test_sql import encoded_block


def parameters(value):
    return block.Parameters(0, value, value, value, value, block.Nonce_16(bytes(16)))


def output(key, proposal, weight, height):
    return sql.Delta(key, None, b'output', tuple(
        sql.VoteDelta(name, key, None, sql.Vote(proposal, weight, height))
        for name in sql.PARAMETERS))


def spend(delta):
    return sql.Delta(delta.key, delta.new, None, tuple(
        sql.VoteDelta(v.parameter, v.source, v.new, None) for v in delta.votes))


def test_vote_codec_and_bounds():
    changes = (output(b'x', 0, 2**119, 0), output(b'y', 2**119, 1, 10000))
    encoded = sql.encode_deltas(changes)
    assert encoded[:5] == b'ASQL\x02'
    assert sql.decode_deltas(encoded) == changes
    for end in range(len(encoded)):
        with pytest.raises(ValueError):
            sql.decode_deltas(encoded[:end])
    with pytest.raises(sql.StateConflict):
        sql.encode_deltas((changes[0], sql.Delta(b'other', None, b'', changes[0].votes)))
    with pytest.raises(ValueError):
        sql.VoteDelta('target', b'x', None, sql.Vote(1, 1, 0))
    with pytest.raises(ValueError):
        output(b'x', 0, 0, 0)


def test_epoch_cache_publication_and_undo(tmp_path, monkeypatch):
    monkeypatch.setattr(sql, 'BLOCKS_IN_EPOCH', 2)

    async def scenario():
        low = output(b'low', 0, 2**119, 0)
        high = output(b'high', 90, 2**119, 0)
        # Old-bin spends must not affect the new bin's electorate. Publications
        # are frozen before the epoch block's own deltas are applied.
        changes = {0: (low, high), 1: (),
                   2: (spend(low), output(b'new', 70, 1, 2))}

        class Parser:
            async def parse_block(self, encoded, view):
                height = (await block.Block.decode(encoded)).header.id
                if height == 2:
                    assert await view.median('block_reward') == 0
                    assert (await view.parameters(2))['block_reward'] == 5
                return changes[height]

        path = tmp_path / 'votes.sqlite'
        async with sql.Database(path) as db:
            coordinator = sql.Coordinator(db, Parser(), asyncio.Queue(), asyncio.Queue())
            genesis, parent = await encoded_block(0, parameters=parameters(5))
            await coordinator._handle(sql.Request('0', 'commit', genesis))
            for name in sql.PARAMETERS:
                assert await coordinator.median(name) == 0  # Lower half-weight tie.
            before, parent = await encoded_block(1, parent)
            await coordinator._handle(sql.Request('1', 'commit', before))
            bad, _ = await encoded_block(2, parent, parameters(90))
            with pytest.raises(sql.StateConflict):
                await coordinator._handle(sql.Request('bad', 'commit', bad))
            assert (await db.tip()).id == 1
            epoch, _ = await encoded_block(2, parent, parameters(0))
            await coordinator._handle(sql.Request('candidate', 'candidate', epoch))
            assert await db.median('block_reward') == 0
            assert await db.parameters(3) == dict.fromkeys(sql.PARAMETERS, 5)
            await coordinator._handle(sql.Request('epoch', 'commit', epoch))
            assert await db.parameters(2) == dict.fromkeys(sql.PARAMETERS, 5)
            assert await db.parameters(3) == dict.fromkeys(sql.PARAMETERS, 0)
            assert await db.parameters(4) == dict.fromkeys(sql.PARAMETERS, 0)
            assert await db.median('block_reward') == 70
            # Queries read persisted cache rows, not the contribution table.
            statements = []
            await db._call(db._connection.set_trace_callback, statements.append)
            assert await db.median('block_reward') == 70
            assert not any('FROM votes ' in query for query in statements)
            await db._call(db._connection.set_trace_callback, None)
        async with sql.Database(path) as db:
            assert await db.median('block_reward') == 70
            coordinator = sql.Coordinator(db, Parser(), asyncio.Queue(), asyncio.Queue())
            await coordinator._handle(sql.Request('undo', 'revert'))
            assert await db.median('block_reward') == 0
            assert await db.parameters(3) == dict.fromkeys(sql.PARAMETERS, 5)
            await coordinator._handle(sql.Request('undo1', 'revert'))
            await coordinator._handle(sql.Request('undo0', 'revert'))
            assert await db.median('block_reward') is None
            assert await db.parameters(1) == {}
    asyncio.run(scenario())


def test_empty_epoch_fallback_and_vote_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr(sql, 'BLOCKS_IN_EPOCH', 2)

    async def scenario():
        class Parser:
            conflict = False

            async def parse_block(self, encoded, view):
                if self.conflict:
                    return (sql.Delta(b'bad', None, b'value', (
                        sql.VoteDelta('data_fee', b'missing', sql.Vote(4, 1, 0), None),)),)
                return ()

        parser = Parser()
        async with sql.Database(tmp_path / 'empty.sqlite') as db:
            coordinator = sql.Coordinator(db, parser, asyncio.Queue(), asyncio.Queue())
            parent = None
            for height in range(3):
                encoded, next_parent = await encoded_block(
                    height, parent, parameters(5) if height % 2 == 0 else None)
                if height == 2:
                    parser.conflict = True
                    with pytest.raises(sql.StateConflict):
                        await coordinator._handle(sql.Request('bad', 'commit', encoded))
                    assert await db.get(b'bad') is None
                    assert (await db.tip()).id == 1
                    parser.conflict = False
                await coordinator._handle(sql.Request(str(height), 'commit', encoded))
                parent = next_parent
            assert await db.median('data_fee') is None
            assert await db.parameters(3) == dict.fromkeys(sql.PARAMETERS, 5)
            with pytest.raises(ValueError):
                await coordinator.median('target')
    asyncio.run(scenario())
