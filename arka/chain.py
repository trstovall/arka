
import sqlite3
from pathlib import Path

from .tx import WorkBlock, PaymentBlock

class Chain(object):

    forks = {}

    def __init__(self, 
        path: str | Path = '~/.arka/chain.db'
    ):
        self.path: Path = (path if isinstance(path, Path) else Path(path)).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.cur = self.db.cursor()
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS
            blocks (
                id          INTEGER,
                digest      BLOB,
                data        BLOB
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

    @property
    def last_block(self):
        pass

    def prepare_block(self, worker: bytes | None = None) -> WorkBlock:
        pass

    def add_block(self, block: Block) -> bool:
        pass


class PaymentPool(object):
    pass
