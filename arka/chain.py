
import sqlite3
from pathlib import Path

from .tx import BlockLink

class Chain(object):

    def __init__(self, path: str | Path = '~/.arka/chain.db'):

        path: Path = (path if isinstance(path, Path) else Path(path)).expanduser()
        parent: Path = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.cur = self.db.cursor()
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            forks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fork_epoch  INTEGER,
                fork_block  INTEGER,
                last_epoch  INTEGER,
                last_block  INTEGER,
                last_link   INTEGER,
                total_work  BLOB
            );
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            block_links (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                index       INTEGER,
                timestamp   INTEGER,
                epoch       INTEGER,
                prev_block  INTEGER,
                prev_link   INTEGER,
                worker      BLOB,
                nonce       BLOB,
                digest      BLOB
            );
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_block_links_id ON block_links(id);
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_block_links_digest ON block_links(digest);
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            epochs (
                block_id        INTEGER,
                index           INTEGER,
                prev_epoch      INTEGER,
                digest          BLOB,
                target          BLOB,
                block_reward    BLOB,
                stamp_reward    BLOB,
                data_fee        BLOB,
                expiry          INTEGER
            );
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_epochs_id ON epochs(id);
        """)
        self.cur.execute("""
            CREATE INDEX IF NOT EXISTS
            UNIQUE idx_epochs_digest ON epochs(digest);
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
    def last_epoch(self) -> int:
        if not hasattr(self, "_last_epoch"):
            self.cur.execute("""
                SELECT 
            """)

    @property
    def last_block(self):
        pass

    @property
    def last_link(self):
        pass

    def forge_block(self) -> BlockLink:


    def add_block(self, block: BlockLink) -> bool:
        pass


class PaymentPool(object):
    pass
