
from pathlib import Path
from arka import block
from arka import broker


class AbstractDeltaItem(object):
    pass


class Chain(object):

    forks = {}

    def __init__(self,
        broker: broker.Broker,
        path: str | Path = '~/.arka/',
        mode: int = 0o700
    ):
        self.broker = broker
        self.path: Path = (
            path if isinstance(path, Path) else Path(path)
        ).expanduser()
        self.path.mkdir(mode=mode, parents=True, exist_ok=True)

    async def accept(self, block: block.Block) -> bool:
        pass

    async def expire(self, block: int) -> bool:
        pass

    async def validate(self, tx: block.Transaction) -> list[AbstractDeltaItem]:
        pass

    async def parameters(self, block: int | None = None) -> block.Parameters:
        pass

    async def checkpoint(self, block: int) -> bool:
        pass

    async def fork(self, block: int) -> block.Block:
        pass

    async def hash(self) -> block.BlockHash:
        pass

    async def utxo(self,
        ref: block.UTXORefByIndex | block.UTXORefByHash
    ) -> block.UTXOSpawn | None:
        pass

    async def signer(self,
        ref: block.UTXORefByIndex | block.UTXORefByHash
    ) -> block.SignerKey | None:
        pass
