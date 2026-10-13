"""SQLite storage and a serialized, queue-driven database coordinator.

``database = await Database(path)`` exposes a bytes-to-bytes map. Pass an
async Parser to Coordinator and run ``serve()`` as a task. Requests carry
encoded blocks/transactions, so mutable codec caches never cross queues.

The parser owns consensus validation and complete delta derivation (including
votes, rewards and retirement). This module supplies persistence, not consensus.
Commit reparses the block inside the same SQL transaction that installs it.

ARKA output deltas carry VoteDelta records for block_reward, exec_fund, utxo_fee
and data_fee. Each insertion uses the output's full units and creation height;
a spend/retirement records the same contribution as its before-image. The parser
must derive these from the actual UTXO, not peer-supplied vote claims. Sources
created in the previous 10,000-block epoch and still live at its cutoff vote for
the next publication. Asset outputs do not contribute to these four parameters.

The votes table stores live contributions; vote_medians stores exact cached
lower medians by source epoch. A changed bin is recomputed during delta apply,
before commit, using Python integer sums (SQLite integers are only 64 bits).
This initial implementation scans/sorts affected bins once per batch. Public
median(name), including Coordinator.median(name), only reads the cache. Parsers
use await view.median(name) inside their existing transaction.

At epoch height H, cached parent-state medians are checked against the published
header values before applying H's transactions. With no eligible votes, retain
the preceding publication. Values published at H govern H+1 through H+10,000;
H uses the incoming context. Difficulty is independently known before H's new
parameters and must be validated by the parser from incoming chain context.
parameter_publications stores only the four monetary values, not difficulty.
All vote/cache/publication writes roll back with map and chain writes.

Existing ASQL version 1 deltas remain readable; vote-bearing deltas use version
2 with nested before-images. Creating the new tables does not reconstruct votes
omitted from historical version 1 data: an existing populated chain needs replay
through a vote-aware parser before its electorate can be considered complete.
"""

from __future__ import annotations

import asyncio
import sqlite3
import struct
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Protocol

BLOCKS_IN_EPOCH = 10_000
PARAMETERS = ('block_reward', 'exec_fund', 'utxo_fee', 'data_fee')

# Trusted SQL identifiers used by the sparse auxiliary adapter.
_TABLES = {
    'map': ('key value', 'key'),
    'chain': ('id header block deltas', 'id'),
    'votes': ('parameter source epoch contribution', 'parameter source'),
    'vote_medians': ('parameter epoch median total_weight', 'parameter epoch'),
    'parameter_publications': ('height parameter value', 'height parameter'),
}


@dataclass(frozen=True)
class Vote:
    """One live output's proposal, full UTXO weight and creation height."""

    proposal: int
    weight: int
    height: int

    def encode(self) -> bytes:
        if not 0 <= self.proposal < 2**120 or not 0 < self.weight < 2**120:
            raise ValueError('Invalid vote proposal or weight')
        return (self.height.to_bytes(8, 'little') + self.proposal.to_bytes(15, 'little')
                + self.weight.to_bytes(15, 'little'))

    @classmethod
    def decode(cls, data: bytes) -> Vote:
        if len(data) != 38:
            raise ValueError('Invalid vote encoding')
        value = cls(int.from_bytes(data[8:23], 'little'),
                    int.from_bytes(data[23:], 'little'), int.from_bytes(data[:8], 'little'))
        value.encode()
        return value


@dataclass(frozen=True)
class VoteDelta:
    parameter: str
    source: bytes
    old: Vote | None
    new: Vote | None

    def __post_init__(self):
        if self.parameter not in PARAMETERS:
            raise ValueError('Unknown voting parameter')
        object.__setattr__(self, 'source', _blob(self.source))
        for vote in (self.old, self.new):
            if vote is not None:
                vote.encode()


class StateConflict(ValueError):
    """A delta or block does not extend the current stored state."""


def _blob(value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError('Expected a byte stream')
    return bytes(value)


@dataclass(frozen=True)
class Delta:
    """Key includes its type prefix; None means absent, not empty bytes."""

    key: bytes
    old: bytes | None
    new: bytes | None
    votes: tuple[VoteDelta, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, 'votes', tuple(self.votes))
        for name in ('key', 'old', 'new'):
            value = getattr(self, name)
            if value is not None or name == 'key':
                object.__setattr__(self, name, _blob(value))


def encode_deltas(deltas: Iterable[Delta]) -> bytes:
    """Versioned SQL blob format; independent of docs/deltas.md chunk framing."""
    records = tuple(deltas)
    version = 2 if any(delta.votes for delta in records) else 1
    parts = [b'ASQL' + bytes([version]), struct.pack('<I', len(records))]
    keys = set()
    vote_keys = set()
    for delta in records:
        if delta.key in keys:
            raise StateConflict('Duplicate delta key')
        keys.add(delta.key)
        for value in (delta.key, delta.old, delta.new):
            if value is not None and len(value) >= 0xffffffff:
                raise ValueError('Delta field too large')
            parts.append(struct.pack('<I', 0xffffffff if value is None else len(value)))
            if value is not None:
                parts.append(value)
        if version == 2:
            nested = []
            for vote in delta.votes:
                key = bytes([PARAMETERS.index(vote.parameter)]) + vote.source
                if key in vote_keys:
                    raise StateConflict('Duplicate vote source')
                vote_keys.add(key)
                nested.append(Delta(key, None if vote.old is None else vote.old.encode(),
                                    None if vote.new is None else vote.new.encode()))
            encoded = encode_deltas(nested)
            parts.extend((struct.pack('<I', len(encoded)), encoded))
    return b''.join(parts)


def decode_deltas(data: bytes) -> tuple[Delta, ...]:
    data = _blob(data)
    if len(data) < 9 or data[:4] != b'ASQL' or data[4] not in (1, 2):
        raise ValueError('Invalid delta format')
    count = struct.unpack_from('<I', data, 5)[0]
    if count > (len(data) - 9) // 12:
        raise ValueError('Truncated delta list')
    offset = 9
    records = []
    for _ in range(count):
        values = []
        for field in range(3):
            if offset + 4 > len(data):
                raise ValueError('Truncated delta length')
            size = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            if size == 0xffffffff:
                if field == 0:
                    raise ValueError('Absent delta key')
                values.append(None)
            else:
                if size > len(data) - offset:
                    raise ValueError('Truncated delta value')
                values.append(data[offset:offset + size])
                offset += size
        votes = []
        if data[4] == 2:
            if offset + 4 > len(data):
                raise ValueError('Truncated vote list')
            size = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            nested = data[offset:offset + size]
            if len(nested) != size or nested[:5] != b'ASQL\x01':
                raise ValueError('Invalid nested vote list')
            for item in decode_deltas(nested):
                if not item.key or item.key[0] >= len(PARAMETERS):
                    raise ValueError('Invalid parameter tag')
                votes.append(VoteDelta(PARAMETERS[item.key[0]], item.key[1:],
                                       None if item.old is None else Vote.decode(item.old),
                                       None if item.new is None else Vote.decode(item.new)))
            offset += size
        records.append(Delta(*values, tuple(votes)))
    if offset != len(data):
        raise ValueError('Trailing delta bytes')
    result = tuple(records)
    encode_deltas(result)  # Also enforce unique keys on input.
    return result


@dataclass(frozen=True)
class ChainRecord:
    id: int
    header: bytes
    block: bytes
    deltas: bytes


class ReadView:
    """Read-only parser view, valid only during its request transaction.

    Parsers must use this view instead of reentering Database methods, which
    would wait on the coordinator's transaction lock.
    """

    def __init__(self, database: Database):
        self._database = database
        self._active = True

    async def get(self, key: bytes, default=None):
        self._check()
        value = await self._database._call(self._database._get, _blob(key))
        return default if value is None else value

    async def tip(self) -> ChainRecord | None:
        self._check()
        return await self._database._call(self._database._tip)

    async def median(self, parameter_name: str) -> int | None:
        """Read the precomputed current source-epoch median without rescanning votes."""
        self._check()
        return await self._database._call(self._database._median, parameter_name)

    async def parameters(self, height: int) -> dict[str, int]:
        """Published monetary parameters effective for the specified block."""
        self._check()
        return await self._database._call(self._database._parameters, height)

    def _check(self):
        if not self._active:
            raise RuntimeError('Read view has expired')


class Parser(Protocol):
    async def parse_transaction(self, encoded: bytes, view: ReadView,
                                height: int, position: int) -> Iterable[Delta]:
        """Validate and derive complete effects using final output positions."""
        ...

    async def parse_block(self, encoded: bytes, view: ReadView) -> Iterable[Delta]:
        """Validate all consensus rules and derive every block effect.

        Attach source VoteDelta records to ARKA insertions/spends/retirement.
        Use incoming difficulty for an epoch block, never its own proposed
        header target. view.parameters(height) supplies incoming monetary values;
        view.median(name) supplies the prepared publication proposal separately.
        """
        ...


class Database:
    """One SQLite connection owned by a dedicated executor thread.

    SQL and filesystem work run off the event loop. WAL with FULL synchronization
    supplies atomic map/chain commits. Direct map methods are for standalone map
    use/bootstrap; coordinated chain writes must use Coordinator.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='arka-sql')
        self._lock = asyncio.Lock()
        self._connection = None
        self._closed = False
        self._auxiliary = False

    def __await__(self):
        return self.open().__await__()

    async def _call(self, function, *args):
        """Run connection work on its owning thread and drain it on cancellation.

        The dedicated single-worker executor creates, uses, and closes the
        connection on the same thread, preserving SQLite's default
        check_same_thread=True. asyncio.to_thread() uses the shared executor;
        successive calls can use different threads even under an asyncio lock.
        The lock protects whole transactions, while this executor supplies
        thread affinity for individual operations.

        Cancelling an await does not stop SQL already running in a thread.
        Shield the future and wait for completion before propagating cancellation
        so callers cannot release the transaction lock or begin cleanup while
        that operation is still running. Plain to_thread() would need equivalent
        cancellation handling as well as a different connection ownership policy.
        Completion here does not imply rollback: a cancelled commit may already
        have succeeded.
        """
        future = asyncio.get_running_loop().run_in_executor(self._executor, function, *args)
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            # Finish the SQL operation before releasing its transaction/lock.
            while not future.done():
                try:
                    await asyncio.shield(future)
                except asyncio.CancelledError:
                    continue
            if not future.cancelled():
                future.exception()
            raise

    def _open(self):
        if self.path != ':memory:':
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            str(Path(self.path).expanduser()) if self.path != ':memory:' else self.path,
            isolation_level=None
        )
        try:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA synchronous=FULL')
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS map (
                    key BLOB PRIMARY KEY NOT NULL CHECK(typeof(key) = 'blob'),
                    value BLOB NOT NULL CHECK(typeof(value) = 'blob')
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS chain (
                    id INTEGER PRIMARY KEY CHECK(id >= 0),
                    header BLOB NOT NULL CHECK(typeof(header) = 'blob'),
                    block BLOB NOT NULL CHECK(typeof(block) = 'blob'),
                    deltas BLOB NOT NULL CHECK(typeof(deltas) = 'blob')
                );
                CREATE TABLE IF NOT EXISTS votes (
                    parameter TEXT NOT NULL,
                    source BLOB NOT NULL,
                    epoch INTEGER NOT NULL,
                    contribution BLOB NOT NULL,
                    PRIMARY KEY(parameter, source)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS votes_epoch ON votes(parameter, epoch);
                CREATE TABLE IF NOT EXISTS vote_medians (
                    parameter TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    median BLOB,
                    total_weight TEXT NOT NULL,
                    PRIMARY KEY(parameter, epoch)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS parameter_publications (
                    height INTEGER NOT NULL,
                    parameter TEXT NOT NULL,
                    value BLOB NOT NULL,
                    PRIMARY KEY(height, parameter)
                ) WITHOUT ROWID;
            ''')
            self._create_auxiliary_schema(connection)
        except BaseException:
            connection.close()
            raise
        self._connection = connection

    async def open(self):
        async with self._lock:
            if self._closed:
                raise RuntimeError('Database is closed')
            if self._connection is None:
                await self._call(self._open)
        return self

    def _execute(self, statement, parameters=()):
        if self._connection is None:
            raise RuntimeError('Database is not open')
        if self._auxiliary:
            return self._aux_execute(statement, parameters)
        return self._connection.execute(statement, parameters)

    @staticmethod
    def _create_auxiliary_schema(connection):
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS aux_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                ancestor INTEGER NOT NULL, active INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS aux_pending (
                id INTEGER PRIMARY KEY, header BLOB NOT NULL, block BLOB NOT NULL
            );
        ''')
        for table, (fields, identity) in _TABLES.items():
            columns, keys = fields.split(), identity.split()
            info = {row[1]: row[2] for row in connection.execute(f'PRAGMA table_info({table})')}
            declarations = ','.join(f'{name} {info[name]}' for name in columns)
            key_list = ','.join(keys)
            connection.execute(f'CREATE TABLE IF NOT EXISTS aux_{table} ('
                               f'{declarations}, deleted INTEGER NOT NULL DEFAULT 0, '
                               f'PRIMARY KEY({key_list})) WITHOUT ROWID')
            matches = ' AND '.join(f'a.{key}=b.{key}' for key in keys)
            connection.execute(f'CREATE VIEW IF NOT EXISTS aux_view_{table} AS '
                               f'SELECT {",".join("b." + c for c in columns)} FROM {table} b '
                               f'WHERE NOT EXISTS (SELECT 1 FROM aux_{table} a WHERE {matches}) '
                               f'UNION ALL SELECT {",".join(columns)} FROM aux_{table} WHERE deleted=0')
            # Capture a canonical key's pre-write state only if this ancestor
            # overlay has not already established an override for it.
            for operation in ('INSERT', 'UPDATE', 'DELETE'):
                source = 'NEW' if operation == 'INSERT' else 'OLD'
                values = ','.join(f'{source}.{c}' for c in columns)
                deleted = int(operation == 'INSERT')
                absent = 'NOT EXISTS(SELECT 1 FROM aux_' + table + ' WHERE ' + ' AND '.join(
                    f'{key}={source}.{key}' for key in keys) + ')'
                capture_existing = ''
                if operation == 'INSERT':
                    # SQLite runs BEFORE INSERT even when UPSERT takes its
                    # UPDATE path. Preserve the existing row before tombstoning.
                    predicate = ' AND '.join(f'{key}=NEW.{key}' for key in keys)
                    capture_existing = (
                        f'INSERT OR IGNORE INTO aux_{table} ({fields.replace(" ", ",")},deleted) '
                        f'SELECT {fields.replace(" ", ",")},0 FROM {table} WHERE {predicate} AND {absent}; ')
                connection.execute(f'CREATE TRIGGER IF NOT EXISTS aux_capture_{table}_{operation} '
                                   f'BEFORE {operation} ON {table} '
                                   'WHEN EXISTS(SELECT 1 FROM aux_state WHERE active=1) BEGIN '
                                   + capture_existing +
                                   f'INSERT OR IGNORE INTO aux_{table} ({fields.replace(" ", ",")},deleted) '
                                   f'SELECT {values},{deleted} WHERE {absent}; END')

    def _aux_execute(self, statement, parameters):
        """Route this module's fixed SQL vocabulary to sparse auxiliary tables.

        This is not an arbitrary SQL rewriting API. Public callers never supply
        SQL, and schema/control statements continue to address their own tables.
        """
        connection = self._connection
        if statement.startswith('SELECT'):
            for table in _TABLES:
                statement = re.sub(r'\bFROM ' + table + r'\b', 'FROM aux_view_' + table, statement)
        elif statement.startswith('INSERT INTO '):
            match = re.match(r'INSERT INTO (\w+)(\([^)]*\))? VALUES', statement)
            if match and match[1] in _TABLES:
                table = match[1]
                columns = match[2] or '(' + _TABLES[table][0].replace(' ', ',') + ')'
                # Replacing a tombstone resets deleted to its default zero.
                statement = ('INSERT OR REPLACE INTO aux_' + table + columns + ' VALUES'
                             + statement[match.end():].split(' ON CONFLICT')[0])
        elif statement.startswith('DELETE FROM '):
            match = re.match(r'DELETE FROM (\w+)(.*)', statement)
            if match and match[1] in _TABLES:
                table, suffix = match[1], match[2]
                columns = _TABLES[table][0].replace(' ', ',')
                return connection.execute(
                    f'INSERT OR REPLACE INTO aux_{table} ({columns},deleted) '
                    f'SELECT {columns},1 FROM aux_view_{table}{suffix}', parameters)
        return connection.execute(statement, parameters)

    def _many(self, statement, rows):
        if self._auxiliary:
            for row in rows:
                self._execute(statement, row)
        else:
            self._connection.executemany(statement, rows)

    def _require_auxiliary(self):
        row = self._connection.execute('SELECT ancestor FROM aux_state WHERE active=1').fetchone()
        if row is None:
            raise StateConflict('No auxiliary branch')
        return row[0]

    def _clear_auxiliary(self):
        self._connection.execute('DELETE FROM aux_state')
        for table in _TABLES:
            self._connection.execute(f'DELETE FROM aux_{table}')
        self._connection.execute('DELETE FROM aux_pending')

    def _fork_auxiliary(self, ancestor):
        if self._connection.execute('SELECT 1 FROM aux_state').fetchone():
            raise StateConflict('Discard the existing auxiliary branch first')
        if self._execute('SELECT id FROM chain WHERE id=?', (ancestor,)).fetchone() is None:
            raise StateConflict('Ancestor is not retained')
        self._connection.execute('INSERT INTO aux_state VALUES(1,?,1)', (ancestor,))
        self._auxiliary = True
        try:
            while (tip := self._tip()).id > ancestor:
                self._apply(decode_deltas(tip.deltas), True)
                self._execute('DELETE FROM chain WHERE id=?', (tip.id,))
                self._execute('DELETE FROM parameter_publications WHERE height=?', (tip.id,))
        finally:
            self._auxiliary = False

    def _install_auxiliary(self):
        # Disable capture while replacing canonical state with the selected view.
        self._connection.execute('UPDATE aux_state SET active=0')
        for table, (fields, identity) in _TABLES.items():
            columns = fields.replace(' ', ',')
            matches = ' AND '.join(f'a.{key}={table}.{key}' for key in identity.split())
            self._connection.execute(f'DELETE FROM {table} WHERE EXISTS '
                                     f'(SELECT 1 FROM aux_{table} a WHERE {matches})')
            self._connection.execute(f'INSERT INTO {table} ({columns}) '
                                     f'SELECT {columns} FROM aux_{table} WHERE deleted=0')
        self._clear_auxiliary()

    async def aux_get(self, key: bytes, default=None):
        """Read the stable ancestor view; staged blocks are not validated state."""
        async with self._lock:
            await self._call(self._require_auxiliary)
            self._auxiliary = True
            try:
                value = await self._call(self._get, _blob(key))
                return default if value is None else value
            finally:
                self._auxiliary = False

    async def aux_median(self, parameter_name: str) -> int | None:
        async with self._lock:
            await self._call(self._require_auxiliary)
            self._auxiliary = True
            try:
                return await self._call(self._median, parameter_name)
            finally:
                self._auxiliary = False

    async def aux_tip(self) -> ChainRecord:
        """Return the reconstructed ancestor tip, not the unvalidated staged tip."""
        async with self._lock:
            await self._call(self._require_auxiliary)
            self._auxiliary = True
            try:
                return await self._call(self._tip)
            finally:
                self._auxiliary = False

    async def aux_block(self, height: int) -> ChainRecord | None:
        async with self._lock:
            await self._call(self._require_auxiliary)
            row = await self._call(lambda: self._connection.execute(
                'SELECT id,header,block,deltas FROM aux_view_chain WHERE id=?', (height,)).fetchone())
            return None if row is None else ChainRecord(*row)

    async def aux_parameters(self, height: int) -> dict[str, int]:
        async with self._lock:
            await self._call(self._require_auxiliary)
            self._auxiliary = True
            try:
                return await self._call(self._parameters, height)
            finally:
                self._auxiliary = False

    def _get(self, key):
        row = self._execute('SELECT value FROM map WHERE key=?', (key,)).fetchone()
        return None if row is None else row[0]

    async def get(self, key: bytes, default=None):
        async with self._lock:
            value = await self._call(self._get, _blob(key))
            return default if value is None else value

    async def __getitem__(self, key: bytes) -> bytes:
        value = await self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    async def __setitem__(self, key: bytes, value: bytes):
        key, value = _blob(key), _blob(value)
        async with self._lock:
            await self._call(self._put, key, value)

    def _put(self, key, value):
        self._execute('INSERT INTO map(key,value) VALUES(?,?) '
                      'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))

    def _delete(self, key):
        if self._execute('DELETE FROM map WHERE key=?', (key,)).rowcount == 0:
            raise KeyError(key)

    async def __delitem__(self, key: bytes):
        async with self._lock:
            await self._call(self._delete, _blob(key))

    async def __contains__(self, key: bytes) -> bool:
        return await self.get(key) is not None

    def _batch(self, items, keys):
        self._execute('BEGIN IMMEDIATE')
        try:
            if items:
                self._connection.executemany(
                    'INSERT INTO map(key,value) VALUES(?,?) '
                    'ON CONFLICT(key) DO UPDATE SET value=excluded.value', items)
            if keys:
                cursor = self._connection.executemany(
                    'DELETE FROM map WHERE key=?', ((key,) for key in keys))
                # difference_update deduplicates keys before submitting the batch.
                if cursor.rowcount != len(keys):
                    raise KeyError('One or more batch keys are missing')
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    async def update(self, items: dict[bytes, bytes]):
        """Atomically insert or replace map entries."""
        snapshot = tuple((_blob(key), _blob(value)) for key, value in items.items())
        async with self._lock:
            await self._call(self._batch, snapshot, ())

    async def difference_update(self, keys: Iterable[bytes]):
        """Atomically remove keys; any missing key aborts the whole batch."""
        snapshot = tuple(dict.fromkeys(_blob(key) for key in keys))
        async with self._lock:
            await self._call(self._batch, (), snapshot)

    async def __len__(self) -> int:
        async with self._lock:
            return await self._call(lambda: self._execute('SELECT count(*) FROM map').fetchone()[0])

    def _tip(self):
        row = self._execute('SELECT id,header,block,deltas FROM chain ORDER BY id DESC LIMIT 1').fetchone()
        return None if row is None else ChainRecord(*row)

    async def tip(self) -> ChainRecord | None:
        async with self._lock:
            return await self._call(self._tip)

    async def block(self, height: int) -> ChainRecord | None:
        def read():
            row = self._execute('SELECT id,header,block,deltas FROM chain WHERE id=?', (height,)).fetchone()
            return None if row is None else ChainRecord(*row)
        async with self._lock:
            return await self._call(read)

    def _apply(self, deltas, reverse=False):
        dirty = set()
        for delta in reversed(deltas) if reverse else deltas:
            old, new = (delta.new, delta.old) if reverse else (delta.old, delta.new)
            if self._get(delta.key) != old:
                raise StateConflict('Delta before-image mismatch')
            if new is None:
                self._execute('DELETE FROM map WHERE key=?', (delta.key,))
            else:
                self._put(delta.key, new)
            for change in delta.votes:
                before, after = (change.new, change.old) if reverse else (change.old, change.new)
                row = self._execute('SELECT contribution FROM votes WHERE parameter=? AND source=?',
                                    (change.parameter, change.source)).fetchone()
                if (None if row is None else row[0]) != (None if before is None else before.encode()):
                    raise StateConflict('Vote before-image mismatch')
                for vote in (before, after):
                    if vote is not None:
                        dirty.add((change.parameter, vote.height // BLOCKS_IN_EPOCH))
                if after is None:
                    self._execute('DELETE FROM votes WHERE parameter=? AND source=?',
                                  (change.parameter, change.source))
                else:
                    self._execute('INSERT INTO votes VALUES(?,?,?,?) '
                                  'ON CONFLICT(parameter,source) DO UPDATE SET '
                                  'epoch=excluded.epoch, contribution=excluded.contribution',
                                  (change.parameter, change.source,
                                   after.height // BLOCKS_IN_EPOCH, after.encode()))
        # Pay selection cost during state preparation, never in median() or
        # epoch publication. SQLite INTEGER/SUM cannot hold 120-bit amounts.
        for parameter, epoch in dirty:
            totals = {}
            for (encoded,) in self._execute(
                    'SELECT contribution FROM votes WHERE parameter=? AND epoch=?', (parameter, epoch)):
                vote = Vote.decode(encoded)
                totals[vote.proposal] = totals.get(vote.proposal, 0) + vote.weight
            weight = sum(totals.values())
            rank, cumulative, median = (weight + 1) // 2, 0, None
            for proposal in sorted(totals):
                cumulative += totals[proposal]
                if cumulative >= rank:
                    median = proposal.to_bytes(15, 'little')
                    break
            self._execute('INSERT INTO vote_medians VALUES(?,?,?,?) '
                          'ON CONFLICT(parameter,epoch) DO UPDATE SET '
                          'median=excluded.median,total_weight=excluded.total_weight',
                          (parameter, epoch, median, str(weight)))

    def _median(self, parameter_name):
        if parameter_name not in PARAMETERS:
            raise ValueError('Unknown voting parameter')
        height = self._execute('SELECT max(id) FROM chain').fetchone()[0]
        epoch = 0 if height is None else height // BLOCKS_IN_EPOCH
        row = self._execute('SELECT median FROM vote_medians WHERE parameter=? AND epoch=?',
                            (parameter_name, epoch)).fetchone()
        return None if row is None or row[0] is None else int.from_bytes(row[0], 'little')

    async def median(self, parameter_name: str) -> int | None:
        """Cached lower weighted median; None means no eligible live votes.

        Votes are weighted by full UTXO units. Sources belong to their creation
        epoch; spending removes them. The previous epoch's cache is ready at its
        final block, before the next epoch block is parsed. Exact ties select
        the lower proposal. No sort or vote-table scan occurs in this method.
        """
        async with self._lock:
            return await self._call(self._median, parameter_name)

    def _parameters(self, height):
        # Epoch block H publishes for H+1 through H+10,000 inclusive. Genesis
        # supplies bootstrap parameters. In particular H uses incoming context.
        cutoff = max(0, height - 1)
        row = self._execute('SELECT max(height) FROM parameter_publications WHERE height<=?',
                            (cutoff,)).fetchone()
        if row[0] is None:
            return {}
        return {name: int.from_bytes(value, 'little') for name, value in self._execute(
            'SELECT parameter,value FROM parameter_publications WHERE height=?', (row[0],))}

    async def parameters(self, height: int) -> dict[str, int]:
        async with self._lock:
            return await self._call(self._parameters, height)

    def _publish_parameters(self, header):
        if header.id % BLOCKS_IN_EPOCH:
            return
        if header.parameters is None:
            if header.id:
                raise ValueError('Epoch block must publish parameters')
            return  # Codec-only bootstrap fixtures may omit genesis parameters.
        previous = self._parameters(header.id)
        entries = []
        for name in PARAMETERS:
            value = getattr(header.parameters, name)
            if header.id:
                expected = self._median(name)
                if expected is None:
                    expected = previous.get(name)
                if expected is None or value != expected:
                    raise StateConflict('Published parameter differs from prepared median')
            entries.append((header.id, name, value.to_bytes(15, 'little')))
        self._many('INSERT INTO parameter_publications VALUES(?,?,?)', entries)

    async def close(self):
        async with self._lock:
            if self._closed:
                return
            if self._connection is not None:
                await self._call(self._connection.close)
                self._connection = None
            self._closed = True
            self._executor.shutdown(wait=False)

    async def __aenter__(self):
        return await self.open()

    async def __aexit__(self, *exc):
        await self.close()


@dataclass(frozen=True)
class Request:
    id: str
    operation: Literal['transaction', 'candidate', 'commit', 'revert', 'stop',
                       'aux_fork', 'aux_stage', 'aux_transfer', 'aux_discard']
    payload: bytes = b''
    position: int = 0
    ancestor: int | None = None

    def __post_init__(self):
        object.__setattr__(self, 'payload', _blob(self.payload))


@dataclass(frozen=True)
class Response:
    id: str
    result: tuple[Delta, ...] | ChainRecord | None = None
    error: str | None = None
    detail: str | None = None


class Coordinator:
    """FIFO coordinator; one response per request, including stop and errors.

    Queue sizes are caller-controlled. Await stop's response and serve() before
    closing the database. Request IDs correlate replies, not durable retry IDs.
    Repeated commit of an already stored block is a conflict, not a new append.
    """

    def __init__(self, database: Database, parser: Parser,
                 requests: asyncio.Queue[Request], responses: asyncio.Queue[Response]):
        self.database, self.parser = database, parser
        self.requests, self.responses = requests, responses
        self._serving = False

    async def median(self, parameter_name: str) -> int | None:
        """Public query; parser callbacks use view.median() to avoid reentrancy."""
        return await self.database.median(parameter_name)

    async def _prepare_block(self, payload, view):
        from arka import block
        db = self.database
        tip = await view.tip()
        height = 0 if tip is None else tip.id + 1
        candidate = await block.Block.decode(payload)
        if candidate.encode() != payload:
            raise ValueError('Noncanonical or surplus block bytes')
        if candidate.header.id != height:
            raise StateConflict('Block does not extend tip height')
        if tip is not None:
            parent = block.BlockHeader.decode(tip.header)
            if parent.pow is None or candidate.header.prev_block != parent.pow.final_hash:
                raise StateConflict('Block does not extend tip hash')
        await candidate.hash()
        deltas = tuple(await self.parser.parse_block(payload, view))
        encoded = encode_deltas(deltas)
        await db._call(db._publish_parameters, candidate.header)
        await db._call(db._apply, deltas)
        return ChainRecord(height, candidate.header.encode(), payload, encoded), deltas

    async def _aux_handle(self, request, view):
        from arka import block
        db = self.database
        if request.operation == 'aux_fork':
            if request.ancestor is None:
                raise ValueError('Ancestor height is required')
            await db._call(db._fork_auxiliary, request.ancestor)
            return None
        if request.operation == 'aux_discard':
            await db._call(db._clear_auxiliary)
            return None
        ancestor = await db._call(db._require_auxiliary)
        if request.operation == 'aux_stage':
            candidate = await block.Block.decode(request.payload)
            if candidate.encode() != request.payload:
                raise ValueError('Noncanonical candidate bytes')
            row = await db._call(lambda: db._connection.execute(
                'SELECT id,header FROM aux_pending ORDER BY id DESC LIMIT 1').fetchone())
            if row is None:
                row = await db._call(lambda: db._connection.execute(
                    'SELECT id,header FROM aux_view_chain WHERE id=?', (ancestor,)).fetchone())
            parent = block.BlockHeader.decode(row[1])
            if candidate.header.id != row[0] + 1 or candidate.header.prev_block != parent.pow.final_hash:
                raise StateConflict('Candidate does not extend staged POW path')
            await candidate.hash()  # Commitments only; no independent consensus validator.
            await db._call(db._execute, 'INSERT INTO aux_pending VALUES(?,?,?)',
                           (candidate.header.id, candidate.header.encode(), request.payload))
            return None
        canonical = await view.tip()
        staged = await db._call(lambda: db._connection.execute(
            'SELECT id,block FROM aux_pending ORDER BY id').fetchall())
        if not staged or canonical is None or staged[-1][0] <= canonical.id:
            raise StateConflict('Candidate must surpass the current canonical tip')
        # One selected validation context. The lock/transaction is the transfer
        # barrier: incoming requests wait; failures retain the old accepted tip.
        db._auxiliary = True
        try:
            for _, payload in staged:
                result, _ = await self._prepare_block(payload, view)
                await db._call(db._execute, 'INSERT INTO chain(id,header,block,deltas) VALUES(?,?,?,?)',
                               (result.id, result.header, result.block, result.deltas))
        finally:
            db._auxiliary = False
        await db._call(db._install_auxiliary)
        return result

    async def _handle(self, request: Request):
        db = self.database
        auxiliary = request.operation in ('aux_fork', 'aux_stage', 'aux_transfer', 'aux_discard')
        if request.operation not in ('transaction', 'candidate', 'commit', 'revert') and not auxiliary:
            raise ValueError('Unknown operation')
        async with db._lock:
            # Reserve the writer before parser reads, including against other
            # SQLite connections. Candidates roll back without changing state.
            view = ReadView(db)
            try:
                await db._call(db._execute, 'BEGIN IMMEDIATE')
                if auxiliary:
                    result = await self._aux_handle(request, view)
                    await db._call(db._execute, 'COMMIT')
                    return result
                tip = await view.tip()
                height = 0 if tip is None else tip.id + 1
                if request.operation == 'revert':
                    if tip is None:
                        raise StateConflict('Empty chain')
                    await db._call(db._apply, decode_deltas(tip.deltas), True)
                    await db._call(db._execute, 'DELETE FROM chain WHERE id=?', (tip.id,))
                    await db._call(db._execute, 'DELETE FROM parameter_publications WHERE height=?', (tip.id,))
                    result = tip
                elif request.operation == 'transaction':
                    if request.position < 0:
                        raise ValueError('Negative transaction position')
                    result = tuple(await self.parser.parse_transaction(
                        request.payload, view, height, request.position))
                    encode_deltas(result)
                    await db._call(db._apply, result)
                else:
                    record, deltas = await self._prepare_block(request.payload, view)
                    if request.operation == 'commit':
                        result = record
                        await db._call(db._execute,
                                       'INSERT INTO chain(id,header,block,deltas) VALUES(?,?,?,?)',
                                       (result.id, result.header, result.block, result.deltas))
                    else:
                        result = deltas
                await db._call(db._execute, 'COMMIT' if request.operation in ('commit', 'revert') else 'ROLLBACK')
                return result
            finally:
                view._active = False
                # Covers parser errors, conflicts, and cancellation after writes.
                await db._call(lambda: db._connection.rollback() if db._connection.in_transaction else None)

    async def serve(self):
        if self._serving:
            raise RuntimeError('Coordinator already serving')
        self._serving = True
        try:
            await self.database.open()
            while True:
                request = await self.requests.get()
                try:
                    try:
                        result = None if request.operation == 'stop' else await self._handle(request)
                        response = Response(request.id, result)
                    except Exception as exc:
                        response = Response(request.id, error=type(exc).__name__, detail=str(exc))
                    await self.responses.put(response)
                    if request.operation == 'stop':
                        return
                finally:
                    self.requests.task_done()
        finally:
            self._serving = False
