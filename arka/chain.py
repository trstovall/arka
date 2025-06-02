
from pathlib import Path
from arka import block
from arka import broker


class AbstractDeltaItem(object):
    pass


class BlockReward(object):

    def __init__(self,
        publisher: block.SignerKey | block.SignerHash,
        units: int
    ):
        self.publisher = publisher
        self.units = units


class BlockRewardUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: int,
        old: BlockReward | None = None,
        new: BlockReward | None = None
    ):
        self.ref = ref
        old = old
        new = new


class ExecutiveFund(object):
    def __init__(self, units: int):
        self.units = units


class ExecutiveFundUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: int,
        old: ExecutiveFund | None = None,
        new: ExecutiveFund | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class ArkaUTXOReference(block.UTXORefByIndex):
    pass


class ArkaUTXOUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: ArkaUTXOReference,
        old: block.ArkaUTXO | None = None,
        new: block.ArkaUTXO | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class AssetUTXOReference(block.UTXORefByIndex):
    pass


class AssetUTXOUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: AssetUTXOReference,
        old: block.AssetUTXO | None = None,
        new: block.AssetUTXO | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class ExecutiveDefinitionReference(block.Nonce_16):
    pass


class ExecutiveDefinitionUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: ExecutiveDefinitionReference,
        old: block.ExecutiveSpawn | None = None,
        new: block.ExecutiveSpawn | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class AssetDefinitionReference(block.Nonce_16):
    pass


class AssetDefinitionUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: AssetDefinitionReference,
        old: block.AssetSpawn | None = None,
        new: block.AssetSpawn | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


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

    async def block_reward(self, block: int) -> BlockReward | None:
        """
        Get the block reward for a given block height.
        """
        pass

    async def executive_fund(self, block: int) -> ExecutiveFund | None:
        """
        Get the executive fund for a given block height.
        """
        pass

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
