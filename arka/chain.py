
from pathlib import Path
from arka import block
from arka import genesis


BLOCKS_IN_EPOCH = 10_000


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


class ArkaUTXOUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: block.UTXORefByIndex,
        old: block.ArkaUTXO | None = None,
        new: block.ArkaUTXO | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class AssetUTXOUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: block.UTXORefByIndex,
        old: block.AssetUTXO | None = None,
        new: block.AssetUTXO | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class ExecutiveDefinitionUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: block.Nonce_16,
        old: block.ExecutiveDefinition | None = None,
        new: block.ExecutiveDefinition | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class AssetDefinitionUpdate(AbstractDeltaItem):

    def __init__(self,
        ref: block.Nonce_16,
        old: block.AssetDefinition | None = None,
        new: block.AssetDefinition | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class ExecutiveVoteUpdate(AbstractDeltaItem):
    def __init__(self,
        ref: block.Nonce_16,
        old: block.ExecutiveVote | None = None,
        new: block.ExecutiveVote | None = None
    ):
        self.ref = ref
        self.old = old
        self.new = new


class Chain(object):

    forks = {}

    def __init__(self,
        home: str | Path = '~/.arka/chain',
        mode: int = 0o700
    ):
        self.home: Path = (
            home if isinstance(home, Path) else Path(home)
        ).expanduser()
        self.home.mkdir(mode=mode, parents=True, exist_ok=True)

    @property
    def height(self) -> int:
        """
        Get the current height of the chain.
        """
        # This should be implemented to return the current block height.
        # For now, we return 0 as a placeholder.
        return self._height
    
    @property
    def state(self) -> tuple[int, block.BlockHash]:
        return self._height, self._hash

    async def transaction_input_delta(self,
        input: block.PublisherSpend | block.ExecutiveSpend
            | block.UTXOSpend | block.ExecutiveDefinition | block.AssetDefinition
    ) -> BlockRewardUpdate | ExecutiveFundUpdate | ArkaUTXOUpdate \
        | AssetUTXOUpdate | ExecutiveDefinitionUpdate | AssetDefinitionUpdate:
        """
        Get the delta item for a transaction input.
        """
        match input:
            case block.PublisherSpend():
                return await self.publisher_spend(input)
            case block.ExecutiveSpend():
                return await self.executive_spend(input)
            case block.UTXOSpend():
                return await self.utxo_spend(input)
            case block.ExecutiveDefinition():
                return await self.executive_definition(input)
            case block.AssetDefinition():
                return await self.asset_definition(input)

    async def publisher_spend(self, input: block.PublisherSpend) -> BlockRewardUpdate:
        """
        Get the delta item for a PublisherSpend transaction input.
        """
        pass

    async def executive_spend(self, input: block.ExecutiveSpend) -> ExecutiveFundUpdate:
        """
        Get the delta item for an ExecutiveSpend transaction input.
        """
        pass

    async def utxo_spend(self, input: block.UTXOSpend) -> ArkaUTXOUpdate | AssetUTXOUpdate:
        """
        Get the delta item for a UTXOSpend transaction input.
        """
        pass

    async def executive_definition(self, input: block.ExecutiveDefinition) -> ExecutiveDefinitionUpdate:
        """
        Get the delta item for an ExecutiveDefinition transaction input.
        """
        pass

    async def asset_definition(self, input: block.AssetDefinition) -> AssetDefinitionUpdate:
        """
        Get the delta item for an AssetDefinition transaction input.
        """
        pass

    async def block_reward(self, ref: int) -> BlockReward | None:
        """
        Get the block reward for a given block height.
        """
        pass

    async def executive_fund(self, ref: int) -> ExecutiveFund | None:
        """
        Get the executive fund for a given block height.
        """
        pass

    async def utxo_by_index(self,
        ref: block.UTXORefByIndex
    ) -> block.ArkaUTXO | block.AssetUTXO | None:
        """
        Get the UTXO for a given reference by index.
        """
        pass

    async def utxo_by_hash_to_index(
        self,
        ref: block.UTXORefByHash
    ) -> block.UTXORefByIndex | None:
        """
        Map the UTXO reference by hash to reference by index.
        """
        pass

    async def accept(self, block: block.Block) -> bool:
        pass

    async def expire(self, block: int) -> bool:
        pass

    async def validate(self, tx: block.Transaction) -> list[AbstractDeltaItem]:
        pass

    async def parameters(self, height: int | None = None) -> block.Parameters | None:
        """
        Get the parameters for a given block height.
        If no block is specified, return the latest parameters.
        """
        if height is None:
            height = self.height
        epoch = height // BLOCKS_IN_EPOCH
        if epoch == 0:
            return genesis.GENESIS.header.parameters
        else:
            raise NotImplementedError(
                "Parameters for epochs other than 0 are not implemented."
            )

    async def checkpoint(self, block: int) -> bool:
        pass

    async def fork(self, block: int) -> block.Block:
        pass

    async def hash(self) -> block.BlockHash:
        pass

    async def signer(self,
        ref: block.UTXORefByIndex | block.UTXORefByHash
    ) -> block.SignerKey | None:
        pass
