import asyncio

import pytest

from arka import block, sql
from test_sql import encoded_block
from test_sql_votes import output


def test_auxiliary_transfer_isolation_and_reopen(tmp_path):
    async def scenario():
        class Parser:
            fail = False
            calls = 0

            async def parse_block(self, data, view):
                self.calls += 1
                header = (await block.Block.decode(data)).header
                if self.fail and header.id == 3:
                    raise ValueError('Invalid selected block')
                old = await view.get(b'balance')
                return (sql.Delta(b'balance', old, header.timestamp.to_bytes(8, 'little')),
                        output(str(header.id).encode(), header.timestamp, 10, header.id))

        async def branch_block(height, parent, timestamp):
            from arka.crypto import keccak_800
            data, _ = await encoded_block(height, parent)
            value = await block.Block.decode(data)
            value.header.timestamp = timestamp
            initial = (await value.header.hash()).value
            value.header.pow = block.POW(block.Nonce_32(initial), block.Nonce_32(bytes(32)),
                block.BlockHash(await keccak_800(initial + bytes(32))))
            return value.encode(), value.header.pow.final_hash

        path = tmp_path / 'fork.sqlite'
        parser = Parser()
        async with sql.Database(path) as db:
            coordinator = sql.Coordinator(db, parser, asyncio.Queue(), asyncio.Queue())
            genesis, ancestor_hash = await encoded_block(0)
            await coordinator._handle(sql.Request('g', 'commit', genesis))
            canonical, canonical_hash = await branch_block(1, ancestor_hash, 10)
            await coordinator._handle(sql.Request('c', 'commit', canonical))
            await coordinator._handle(sql.Request('fork', 'aux_fork', ancestor=0))
            assert await db.aux_get(b'balance') == bytes(8)
            assert await db.aux_get(b'1') is None  # Canonical suffix is masked.
            assert await db.aux_median('block_reward') == 0
            assert (await db.aux_tip()).id == 0
            assert await db.aux_block(1) is None
            calls = parser.calls
            parent = ancestor_hash
            for height in (1, 2, 3):
                data, parent = await branch_block(height, parent, 20 + height)
                await coordinator._handle(sql.Request(str(height), 'aux_stage', data))
            assert parser.calls == calls  # Staging does not run consensus.
            canonical2, _ = await branch_block(2, canonical_hash, 11)
            await coordinator._handle(sql.Request('c2', 'commit', canonical2))
            assert await db.aux_get(b'2') is None
            # Untouched-at-fork key later inserted and then updated stays absent.
            await db.update({b'later': b'first'})
            await db.update({b'later': b'second'})
            assert await db.aux_get(b'later') is None
            parser.fail = True
            with pytest.raises(ValueError):
                await coordinator._handle(sql.Request('fail', 'aux_transfer'))
            assert (await db.tip()).id == 2
            assert await db.get(b'balance') == (11).to_bytes(8, 'little')
            assert await db.aux_get(b'balance') == bytes(8)
        async with sql.Database(path) as db:
            coordinator = sql.Coordinator(db, parser, asyncio.Queue(), asyncio.Queue())
            assert await db.aux_get(b'balance') == bytes(8)
            parser.fail = False
            result = await coordinator._handle(sql.Request('transfer', 'aux_transfer'))
            assert result.id == 3
            assert await db.get(b'balance') == (23).to_bytes(8, 'little')
            assert await db.get(b'later') is None
            assert await db.median('block_reward') == 21
            with pytest.raises(sql.StateConflict):
                await db.aux_get(b'balance')
            await coordinator._handle(sql.Request('revert', 'revert'))
            assert await db.get(b'balance') == (22).to_bytes(8, 'little')
            assert await db.median('block_reward') == 21
    asyncio.run(scenario())


def test_aux_epoch_publication_transfer(tmp_path, monkeypatch):
    from test_sql_votes import parameters
    monkeypatch.setattr(sql, 'BLOCKS_IN_EPOCH', 2)

    async def scenario():
        class Parser:
            async def parse_block(self, data, view):
                height = (await block.Block.decode(data)).header.id
                return (output(b'vote', 7, 10, 0),) if height == 0 else ()

        async with sql.Database(tmp_path / 'epoch.sqlite') as db:
            coordinator = sql.Coordinator(db, Parser(), asyncio.Queue(), asyncio.Queue())
            genesis, parent = await encoded_block(0, parameters=parameters(5))
            await coordinator._handle(sql.Request('g', 'commit', genesis))
            await coordinator._handle(sql.Request('fork', 'aux_fork', ancestor=0))
            for height in (1, 2):
                data, parent = await encoded_block(height, parent, parameters(7) if height == 2 else None)
                await coordinator._handle(sql.Request(str(height), 'aux_stage', data))
            assert await db.aux_parameters(1) == dict.fromkeys(sql.PARAMETERS, 5)
            await coordinator._handle(sql.Request('transfer', 'aux_transfer'))
            assert await db.parameters(3) == dict.fromkeys(sql.PARAMETERS, 7)
            await coordinator._handle(sql.Request('undo', 'revert'))
            assert await db.parameters(3) == dict.fromkeys(sql.PARAMETERS, 5)
            assert await db.median('block_reward') == 7
    asyncio.run(scenario())


def test_canonical_upsert_preserves_ancestor_value(tmp_path):
    async def scenario():
        from test_sql import FixtureParser
        async with sql.Database(tmp_path / 'capture.sqlite') as db:
            coordinator = sql.Coordinator(db, FixtureParser(), asyncio.Queue(), asyncio.Queue())
            genesis, parent = await encoded_block(0)
            await coordinator._handle(sql.Request('g', 'commit', genesis))
            await db.update({b'untouched': b'ancestor'})
            await coordinator._handle(sql.Request('fork', 'aux_fork', ancestor=0))
            await db.update({b'untouched': b'new'})
            assert await db.aux_get(b'untouched') == b'ancestor'
            await db.difference_update([b'untouched'])
            assert await db.aux_get(b'untouched') == b'ancestor'
            with pytest.raises(sql.StateConflict):
                await coordinator._handle(sql.Request('empty', 'aux_transfer'))
            await coordinator._handle(sql.Request('discard', 'aux_discard'))
            assert await db.get(b'untouched') is None
    asyncio.run(scenario())
