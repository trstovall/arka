
from arka import block
from arka import broker
from arka import chain
from arka import crypto

import asyncio


UTXO_FEE_DIVISOR = 2 ** 64
BLOCKS_IN_EPOCH = 10_000  # 1 minute blocks, EPOCH ~ 6.94 days
EPOCHS_IN_CHAIN = 52 * 4  # 52 weeks per year, 4 years history
BLOCKS_IN_CHAIN = BLOCKS_IN_EPOCH * EPOCHS_IN_CHAIN


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
        broker_: broker.Broker,
        chain: chain.Chain,
        loop: asyncio.AbstractEventLoop | None = None
    ):
        self.broker = broker_
        self.chain = chain
        self.loop = loop or asyncio.get_running_loop()
        self.msg_q = asyncio.Queue()
        self.forks: dict[broker.Address, dict[int, block.BlockHash]] = {}
        self.handlers: dict[broker.Address, tuple[asyncio.Task, asyncio.Queue]] = {}
        self.handler: asyncio.Task = self.loop.create_task(self.run())


    async def run(self) -> None:
        tips: dict[broker.Address, tuple[int, block.BlockHash]] = {}
        forks: dict[int, dict[block.BlockHash, set[broker.Address]]] = {}
        subchains: dict[
            tuple[block.BlockHash, block.BlockHash], list[block.BlockHash]
        ] = {}
        headers: dict[block.BlockHash, block.BlockHeader] = {}
        blocks: dict[block.BlockHash, block.Block] = {}
        subs = {
            broker.PeerConnected, broker.PeerDisconnected,
            broker.PeerBlocksPublished, broker.PeerTransactionsPublished,
            broker.PeerBlocksSubscribed, broker.PeerTransactionsSubscribed,
            broker.PeerBlocksUnsubscribed, broker.PeerTransactionsUnsubscribed,
            broker.PeerBlocksRequested, broker.PeerTransactionsRequested,
            broker.PeerBlocksResponded, broker.PeerTransactionsResponded,
        }
        for sub in subs:
            self.broker.sub(sub, self.msg_q)
        try:
            while True:
                match await self.msg_q.get():
                    case broker.PeerConnected() as msg:
                        q = asyncio.Queue()
                        t = self.loop.create_task(self.handle_fork(msg.addr, q))
                        self.handlers[msg.addr] = (t, q)
                        t, q = None, None
                    case broker.PeerDisconnected() as msg:
                        handler = self.handlers.pop(msg.addr, None)
                        if handler:
                            handler[0].cancel()
                            await handler[0]
                            del handler
                    case broker.PeerTransactionsSubscribed() as msg:
                        print(f'Transactions subscribed: {msg.addr}')
                    case broker.PeerTransactionsUnsubscribed() as msg:
                        print(f'Transactions unsubscribed: {msg.addr}')
                    case broker.PeerTransactionsPublished() as msg:
                        print(f'Transactions published: {msg.addr}, {msg.tx_hashes}')
                    case broker.PeerTransactionsRequested() as msg:
                        print(f'Transactions requested: {msg.addr}, {msg.ids}')
                    case broker.PeerTransactionsResponded() as msg:
                        print(f'Transactions responded: {msg.addr}, {msg.txs}')
                    case broker.PeerBlocksSubscribed() as msg:
                        print(f'Blocks subscribed: {msg.addr}')
                    case broker.PeerBlocksUnsubscribed() as msg:
                        print(f'Blocks unsubscribed: {msg.addr}')
                    case (
                        broker.PeerBlocksPublished()
                        | broker.PeerBlocksRequested()
                        | broker.PeerBlocksResponded()
                     ) as msg:
                        handler = self.handlers.get(msg.addr)
                        if handler:
                            await handler[1].put(msg)
        finally:
            for sub in subs:
                self.broker.unsub(sub, self.msg_q)

    async def handle_fork(self, peer: broker.Address, msg_q: asyncio.Queue) -> None:
        root: int | None = None
        tip: int | None = None
        hashes: dict[int, block.BlockHash] = {}
        headers: dict[int, block.BlockHeader] = {}
        unlinked: set[int] = set()
        not_validated: set[int] = set()
        try:
            while True:
                match await msg_q.get():
                    case broker.PeerBlocksPublished() as msg:
                        if msg.id > self.chain.state[0] + BLOCKS_IN_CHAIN:
                            # Too many blocks in chain, ignore.
                            continue
                        if tip is None or msg.id > tip:

                            tip = msg.id
                            hashes[msg.id] = msg.hash
        finally:
            pass

    async def transaction_delta(self,
        tx: block.Transaction,
        height: int
    ) -> tuple[list[chain.AbstractDeltaItem], list[chain.AbstractDeltaItem]]:
        """
        Validate a transaction against the current state of the chain.
        """
        params = await self.chain.parameters(height)
        if params is None:
            raise ValueError(
                f'No parameters for height {height}.'
            )
        deltas = await asyncio.gather(*[
            self.chain.transaction_input_delta(input)
            for input in tx.inputs
        ])
        keys: list[block.SignerKey] = []
        assets: dict[block.Nonce_16 | None, int | None] = {
            None: -(params.data_fee * (tx.size + 2))
        }
        for delta, input in zip(deltas, tx.inputs):
            match delta:
                case chain.ArkaUTXOUpdate() | chain.AssetUTXOUpdate():
                    if delta.old is None:
                        raise ConsensusError(
                            'Invalid UTXOSpend.'
                        )
                    if isinstance(delta.old.signer, block.SignerKey):
                        if input.signer is None:
                            keys.append(delta.old.signer)
                        elif (
                            isinstance(input.signer, block.SignerKey)
                            and input.signer == delta.old.signer
                        ):
                            keys.append(input.signer)
                        else:
                            raise ConsensusError(
                                'Invalid UTXOSpend signer.'
                            )
                    elif isinstance(delta.old.signer, block.SignerHash):
                        if isinstance(input.signer, block.SignerKey):
                            if (await input.signer.hash()) == delta.old.signer:
                                keys.append(input.signer)
                            else:
                                raise ConsensusError(
                                    'Invalid UTXOSpend signer hash.'
                                )
                        elif isinstance(input.signer, block.SignerList):
                            if (await input.signer.hash()) == delta.old.signer:
                                keys.extend(input.signer.keys)
                            else:
                                raise ConsensusError(
                                    'Invalid UTXOSpend signer hash.'
                                )
                        else:
                            raise ConsensusError(
                                'Invalid UTXOSpend signer.'
                            )
                    else:
                        raise ConsensusError(
                            'Invalid UTXOSpend.'
                        )
                    if delta.ref.block > height:
                        raise ConsensusError(
                            'Invalid UTXOSpend().utxo.'
                        )
                    if isinstance(delta, chain.ArkaUTXOUpdate):
                        assets[None] += (
                            delta.old.units
                            - ((params.utxo_fee * (height - delta.ref.block)) // UTXO_FEE_DIVISOR)
                        )
                    else:
                        balance = assets.get(delta.old.asset, 0)
                        if balance is not None:
                            assets[delta.old.asset] = balance + delta.old.units
                case chain.BlockRewardUpdate():
                    if delta.old is None:
                        raise ConsensusError(
                            'Invalid PublisherSpend.'
                        )
                    if isinstance(delta.old.publisher, block.SignerKey):
                        if input.signer is None:
                            keys.append(delta.old.publisher)
                        elif (
                            isinstance(input.signer, block.SignerKey)
                            and input.signer == delta.old.publisher
                        ):
                            keys.append(input.signer)
                        else:
                            raise ConsensusError(
                                'Invalid PublisherSpend signer.'
                            )
                    elif isinstance(delta.old.publisher, block.SignerHash):
                        if isinstance(input.signer, block.SignerKey):
                            if (await input.signer.hash()) == delta.old.publisher:
                                keys.append(input.signer)
                            else:
                                raise ConsensusError(
                                    'Invalid PublisherSpend signer hash.'
                                )
                        elif isinstance(input.signer, block.SignerList):
                            if (await input.signer.hash()) == delta.old.publisher:
                                keys.extend(input.signer.keys)
                            else:
                                raise ConsensusError(
                                    'Invalid PublisherSpend signer hash.'
                                )
                        else:
                            raise ConsensusError(
                                'Invalid PublisherSpend signer.'
                            )
                    else:
                        raise ConsensusError(
                            'Invalid PublisherSpend.'
                        )
                    assets[None] += (
                        delta.old.units
                        - ((params.utxo_fee * (height - delta.ref)) // UTXO_FEE_DIVISOR)
                    )
                case chain.ExecutiveFundUpdate():
                    if delta.old is None:
                        raise ConsensusError(
                            'Invalid ExecutiveSpend.'
                        )
                    if isinstance(params.executive, block.SignerKey):
                        if input.signer is None:
                            keys.append(params.executive)
                        elif (
                            isinstance(input.signer, block.SignerKey)
                            and input.signer == params.executive
                        ):
                            keys.append(params.executive)
                        else:
                            raise ConsensusError(
                                'Invalid ExecutiveSpend signer.'
                            )
                    elif isinstance(params.executive, block.SignerHash):
                        if isinstance(input.signer, block.SignerKey):
                            if (await input.signer.hash()) == params.executive:
                                keys.append(params.executive)
                            else:
                                raise ConsensusError(
                                    'Invalid ExecutiveSpend signer hash.'
                                )
                        elif isinstance(input.signer, block.SignerList):
                            if (await input.signer.hash()) == params.executive:
                                keys.extend(input.signer.keys)
                            else:
                                raise ConsensusError(
                                    'Invalid ExecutiveSpend signer hash.'
                                )
                        else:
                            raise ConsensusError(
                                'Invalid ExecutiveSpend signer.'
                            )
                    else:
                        raise ConsensusError(
                            'Invalid ExecutiveSpend.'
                        )
                    assets[None] += (
                        delta.old.units
                        - ((params.utxo_fee * (height - delta.ref)) // UTXO_FEE_DIVISOR)
                    )
                case chain.ExecutiveDefinitionUpdate() | chain.AssetDefinitionUpdate():
                    if delta.old is None:
                        if isinstance(input.signer, block.SignerKey):
                            keys.append(input.signer)
                        elif isinstance(input.signer, block.SignerList):
                            keys.extend(input.signer.keys)
                        else:
                            raise ConsensusError(
                                'Invalid TransactionInput signer.'
                            )
                    elif isinstance(input.signer, block.SignerKey):
                        if delta.old.new_signer is None:
                            if input.signer != delta.old.signer:
                                raise ConsensusError(
                                    'Invalid TransactionInput signer.'
                                )
                        else:
                            if (await input.signer.hash()) != delta.old.new_signer:
                                raise ConsensusError(
                                    'Invalid TransactionInput signer.'
                                )
                        keys.append(input.signer)
                    elif isinstance(input.signer, block.SignerList):
                        if delta.old.new_signer is None:
                            if input.signer != delta.old.signer:
                                raise ConsensusError(
                                    'Invalid TransactionInput signer.'
                                )
                        else:
                            if (await input.signer.hash()) != delta.old.new_signer:
                                raise ConsensusError(
                                    'Invalid TransactionInput signer.'
                                )
                        keys.extend(input.signer.keys)
                    if isinstance(input, block.AssetDefinition):
                        if delta.old is None or not delta.old.lock:
                            assets[input.asset] = None
                case _:
                    raise ConsensusError('Invalid transaction input type.')
        unique: set[block.SignerKey] = set()
        verifiers: list[crypto.Verifier] = []
        for key in keys:
            if key not in unique:
                unique.add(key)
                verifiers.append(crypto.Verifier(key.value))
        if not verifiers or len(verifiers) != len(tx.signatures):
            raise ConsensusError('Invalid number of verifiers or signatures.')
        verified = await asyncio.gather(*[
            v.verify(s.value, tx.digest.value)
            for v, s in zip(verifiers, tx.signatures)
        ])
        if not all(verified):
            raise ConsensusError('Invalid signatures in transaction.')
        for output in tx.outputs:
            match output:
                case block.ArkaUTXO():
                    pass
                case block.AssetUTXO():
                    pass
                case block.ExecutiveVote():
                    pass
                case _:
                    raise ConsensusError(
                        'Invalid transaction output type.'
                    )
