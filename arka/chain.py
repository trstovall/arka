
import sqlite3
from pathlib import Path


class PaymentLink(object):

    id: int
    time_ms: int
    prev_link: bytes
    prev_run: bytes
    prev_epoch: bytes


class BlockLink(object):

    worker: bytes
    difficulty: tuple[int, int]
    nonce: bytes


class Chain(object):

    def __init__(self, path: str | Path = '~/.arka/chain.db'):

        path: Path = (path if isinstance(path, Path) else Path(path)).expanduser()
        parent: Path = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.cur = self.db.cursor()
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                digest BLOB,
                is_block BOOLEAN,
                index INTEGER,
                prev_link INTEGER,
                prev_block INTEGER,
                link BLOB
            );
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_links_id ON links(id);
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_links_digest ON links(digest);
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            workstamps (
                digest BLOB
            );
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_workstamps_digest ON workstamps(digest);
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            outputs (
                epoch           INTEGER,
                digest          BLOB,
                units           BLOB,
                block_reward    INTEGER,
                data_fee        INTEGER,
                stamp_reward    INTEGER,
                block_expiry    INTEGER
            );
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_outputs_digest ON outputs(digest);
        """)

    @property
    def last_block(self):
        pass

    @property
    def last_link(self):
        pass


class PaymentPool(object):
    pass
