
import sqlite3
from pathlib import Path

from .tx import WorkBlock, PaymentBlock

class Chain(object):

    forks = {}

    def __init__(self, 
        path: str | Path = '~/.arka/chain.db',
        parent: "Chain" | None = None
    ):
        self.path: Path = (path if isinstance(path, Path) else Path(path)).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.cur = self.db.cursor()
        self.parent = parent
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            params (
                id          INTEGER,
                values      BLOB
            );
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            blocks (
                id          INTEGER,
                timestamp   INTEGER,
                digest      BLOB,
                data        BLOB
            );
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            work_blocks (
                id          INTEGER,
                block_id    INTEGER
            );
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            outputs (
                id          BLOB,
                address     BLOB,
                units       BLOB,
                block_id    INTEGER,
                spent_id    INTEGER
            );
        """)
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            workstamps (
                id          BLOB,
                block_id    INTEGER
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

    @property
    def last_block(self):
        pass

    def forge_work_block(self, worker: bytes | None = None) -> WorkBlock:
        pass

    def force_payment_block(self, payments: list[Payment] = []) -> PaymentBlock:
        pass

    def add_block(self, block: WorkBlock | PaymentBlock) -> bool:
        pass


class PaymentPool(object):
    pass
