"""Persistence and queue contracts; the fixture parser is not consensus."""

import asyncio

import pytest

from arka.sql import (Coordinator, Database, Delta, Request, StateConflict,
                      decode_deltas, encode_deltas)


def test_delta_codec():
    source = bytearray(b'old')
    records = (Delta(b'key', source, b''), Delta(b'other', None, b'new'))
    source[:] = b'bad'
    encoded = encode_deltas(records)
    assert decode_deltas(encoded) == records
    assert records[0].old == b'old'
    for malformed in (encoded[:-1], encoded + b'x', b'ASQL\x02' + encoded[5:]):
        with pytest.raises(ValueError):
            decode_deltas(malformed)
    with pytest.raises(StateConflict):
        encode_deltas((records[0], records[0]))


def test_map_reopen(tmp_path):
    async def scenario():
        path = tmp_path / 'nested' / 'state.sqlite'
        async with Database(path) as db:
            await db.__setitem__(b'empty', b'')
            await db.__setitem__(b'key', b'old')
            await db.__setitem__(b'key', b'new')
            assert await db.__contains__(b'empty')
            assert await db.__len__() == 2
        async with Database(path) as db:
            assert await db[b'key'] == b'new'
            assert await db[b'empty'] == b''
            await db.__delitem__(b'key')
            with pytest.raises(KeyError):
                await db[b'key']
            assert await db.get(b'missing', b'default') == b'default'
            await db.update({b'a': b'one', b'b': b'two'})
            with pytest.raises(KeyError):
                await db.difference_update([b'a', b'not-present'])
            assert await db.get(b'a') == b'one'
            await db.difference_update([b'a', b'b'])
            assert await db.__len__() == 1
    asyncio.run(scenario())


async def encoded_block(height, parent=None):
    from arka import block
    from arka.crypto import keccak_800
    header = block.BlockHeader(height, height, parent or block.BlockHash(bytes(32)),
                               block.SignerKey(bytes(32)))
    initial = (await header.hash()).value
    nonce = bytes(32)
    header.pow = block.POW(block.Nonce_32(initial), block.Nonce_32(nonce),
                           block.BlockHash(await keccak_800(initial + nonce)))
    value = block.Block(header, block.TransactionList([]))
    return value.encode(), header.pow.final_hash


class FixtureParser:
    def __init__(self):
        self.calls = 0
        self.conflict = False
        self.view = None

    async def parse_block(self, encoded, view):
        self.calls += 1
        self.view = view
        old = await view.get(b'utxo')
        records = [Delta(b'utxo', old, str(self.calls).encode())]
        if self.conflict:
            records.append(Delta(b'missing', b'not-present', None))
        return records

    async def parse_transaction(self, encoded, view, height, position):
        return [Delta(b'tx', await view.get(b'tx'), encoded)]


def test_queue_commit_conflict_revert_reopen(tmp_path):
    async def scenario():
        path = tmp_path / 'chain.sqlite'
        db = await Database(path)
        parser = FixtureParser()
        requests, responses = asyncio.Queue(), asyncio.Queue()
        worker = Coordinator(db, parser, requests, responses)
        task = asyncio.create_task(worker.serve())

        async def ask(operation, payload=b''):
            await requests.put(Request(operation, operation, payload))
            reply = await asyncio.wait_for(responses.get(), 5)
            assert reply.id == operation
            return reply

        genesis, parent = await encoded_block(0)
        child, _ = await encoded_block(1, parent)
        try:
            reply = await ask('transaction', b'body')
            assert reply.result == (Delta(b'tx', None, b'body'),)
            assert await db.get(b'tx') is None
            reply = await ask('candidate', genesis)
            assert reply.error is None
            assert await db.tip() is None
            assert await db.get(b'utxo') is None
            with pytest.raises(RuntimeError):
                await parser.view.get(b'utxo')
            reply = await ask('commit', genesis)
            assert reply.error is None
            assert parser.calls == 2  # Commit reparses, rather than trusting candidate.
            assert await db.get(b'utxo') == b'2'
            assert (await db.block(0)).block == genesis
            assert (await ask('commit', genesis)).error == 'StateConflict'

            parser.conflict = True
            assert (await ask('commit', child)).error == 'StateConflict'
            assert await db.get(b'utxo') == b'2'  # First write rolled back too.
            assert (await db.tip()).id == 0
            parser.conflict = False
            assert (await ask('commit', child)).error is None
            assert (await ask('revert')).result.id == 1
            assert await db.get(b'utxo') == b'2'
            assert (await db.tip()).id == 0
            assert (await ask('unknown')).error == 'ValueError'
            assert (await ask('stop')).error is None
            await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await db.close()
        async with Database(path) as reopened:
            assert (await reopened.tip()).block == genesis
            assert await reopened.get(b'utxo') == b'2'
    asyncio.run(scenario())


def test_parser_cancellation_rolls_back_and_releases_lock(tmp_path):
    async def scenario():
        entered = asyncio.Event()

        class WaitingParser(FixtureParser):
            async def parse_transaction(self, *args):
                entered.set()
                await asyncio.Event().wait()

        async with Database(tmp_path / 'cancel.sqlite') as db:
            requests, responses = asyncio.Queue(), asyncio.Queue()
            coordinator = Coordinator(db, WaitingParser(), requests, responses)
            task = asyncio.create_task(coordinator.serve())
            await requests.put(Request('wait', 'transaction', b'body'))
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await db.__setitem__(b'after', b'usable')
            assert await db.get(b'after') == b'usable'
            # A new request can begin a transaction after the cancelled parser.
            coordinator.parser = FixtureParser()
            result = await coordinator._handle(Request('next', 'transaction', b'value'))
            assert result == (Delta(b'tx', None, b'value'),)
    asyncio.run(scenario())
