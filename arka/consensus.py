
from arka import block
from arka import broker
from arka import chain
from arka import crypto

import asyncio


class ConsensusError(Exception):
    """
    Base class for all consensus-related errors.
    """
    pass


class Consensus(object):
    """
    The consensus engine for the Arka blockchain.
    """
    def __init__(self,
        broker: broker.Broker,
        chain: chain.Chain,
        loop: asyncio.AbstractEventLoop | None = None
    ):
        self.broker = broker
        self.chain = chain
        self.loop = loop or asyncio.get_running_loop()

    async def validate_transaction(self,
        tx: block.Transaction,
        height: int
    ) -> list[chain.AbstractDeltaItem] | None:
        """
        Validate a transaction against the current state of the chain.
        """
        keys: list[crypto.Verifier] = [
            crypto.Verifier(k.value) for k in tx.keys
        ]
        if not keys or len(keys) != len(tx.signatures):
            raise ConsensusError('Invalid number of keys or signatures.')
        verified = await asyncio.gather(*[
            k.verify(s.value, tx.digest.value)
            for k, s in zip(keys, tx.signatures)
        ])
        if not all(verified):
            raise ConsensusError('Invalid signatures in transaction.')
        params = await self.chain.parameters(height)
        delta: list[chain.AbstractDeltaItem] = []
        assets: dict[block.Nonce_16 | None, int | None] = {
            None: -(params.data_fee * (tx.size + 2))
        }
        inputs: list[block.TransactionInput] = []
        for input in tx.inputs:
            match input:
                case block.PublisherSpend():
                    reward = await self.chain.block_reward(input.block)
                    if reward is None:
                        raise ConsensusError(
                            f'No block reward for block {input.block}.'
                        )
                    if input.signer is None:
                        if not isinstance(reward.publisher, block.SignerKey):
                            raise ConsensusError(
                                f'Invalid PublisherSpend().signer.'
                            )
                        input = block.PublisherSpend(
                            block=input.block,
                            signer=reward.publisher
                        )
                    elif (
                        isinstance(input.signer, block.SignerKey)
                        and isinstance(reward.publisher, block.SignerKey)
                        and not input.signer == reward.publisher
                    ):
                        raise ConsensusError(
                            f'Invalid PublisherSpend().signer.'
                        )
                    elif input.signer.hash() != reward.publisher:
                        raise ConsensusError(
                            f'Invalid PublisherSpend().signer hash.'
                        )
                    inputs.append(input)
                    delta.append(
                        chain.BlockRewardUpdate(
                            ref=input.block,
                            old=reward
                        )
                    )
                    assets[None] += reward.units - params.utxo_fee * (height - input.block)
                case block.ExecutiveSpend():
                    fund = await self.chain.executive_fund(input.block)
                    if fund is None:
                        raise ConsensusError(
                            f'No ExecutiveFund for block {input.block}.'
                        )
                    if input.signer is None:
                        if not isinstance(params.executive, block.SignerKey):
                            raise ConsensusError(
                                f'Invalid ExecutiveSpend().signer.'
                            )
                        input = block.ExecutiveSpend(
                            block=input.block,
                            signer=params.executive
                        )
                    elif (
                        isinstance(input.signer, block.SignerKey)
                        and isinstance(params.executive, block.SignerKey)
                        and not input.signer == params.executive
                    ):
                        raise ConsensusError(
                            f'Invalid ExecutiveSpend().signer.'
                        )
                    elif input.signer.hash() != params.executive:
                        raise ConsensusError(
                            f'Invalid ExecutiveSpend().signer hash.'
                        )
                    inputs.append(input)
                    delta.append(
                        chain.ExecutiveFundUpdate(
                            ref=input.block,
                            old=fund
                        )
                    )
                    assets[None] += fund.units - params.utxo_fee * (height - input.block)
                case block.UTXOSpend():
                    pass
                case block.AssetSpawn():
                    pass
                case block.ExecutiveSpawn():
                    pass
                case _:
                    return
        for output in tx.outputs:
            match output:
                case block.ArkaUTXO():
                    pass
                case block.AssetUTXO():
                    pass
                case block.ExecutiveVote():
                    pass
                case _:
                    return