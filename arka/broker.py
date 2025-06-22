"""
``` python
import asyncio
from arka.broker import (
    Broker, PeerConnected, PeerDisconnected, Address
)
async def subscriber(name: str, broker: Broker):
    queue = asyncio.Queue(maxsize=5)
    broker.sub(PeerConnected, queue)
    broker.sub(PeerDisconnected, queue)
    while True:
        event = await queue.get()
        match event:
            case PeerConnected() | PeerDisconnected():
                print(f"Subscriber {name} received event:  {type(event)} {event.addr}")
            case None:
                break

async def publisher(broker: Broker):
    await asyncio.sleep(1)
    broker.pub(PeerConnected(("127.0.0.1", 8080)))
    await asyncio.sleep(1)
    broker.pub(PeerDisconnected(("192.168.1.1", 9999)))

async def main():
    broker = Broker()
    # Start two subscribers
    asyncio.create_task(subscriber("A", broker))
    asyncio.create_task(subscriber("B", broker))
    # Start publisher
    await publisher(broker)

if __name__ == "__main__":
    asyncio.run(main())

```
"""


import asyncio
from typing import Literal
from arka import block


Address = tuple[str, int]


class AbstractBroker(object):
    pass


class AbstractBrokerEvent(object):
    pass


class PeerConnected(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerDisconnected(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerTransactionsSubscribed(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerTransactionsUnsubscribed(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerTransactionsPublished(AbstractBrokerEvent):
    def __init__(self, addr: Address, tx_hashes: dict[int, block.TransactionHash]):
        self.addr = addr
        self.tx_hashes = tx_hashes


class PeerTransactionsRequested(AbstractBrokerEvent):

    def __init__(self, addr: Address, ids: set[int]):
        self.addr = addr
        self.ids = ids


class PeerTransactionsResponded(AbstractBrokerEvent):

    def __init__(self, addr: Address, txs: dict[int, block.Transaction]):
        self.addr = addr
        self.txs = txs


class PeerBlocksSubscribed(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerBlocksUnsubscribed(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerBlocksPublished(AbstractBrokerEvent):
    def __init__(self, addr: Address, id: int, hash: block.BlockHash):
        self.addr = addr
        self.id = id
        self.hash = hash


class PeerBlocksRequested(AbstractBrokerEvent):

    def __init__(self, addr: Address, ids: set[int], mode: Literal['HEADER', 'SUMMARY', 'BLOCK']):
        self.addr = addr
        self.ids = ids
        self.mode = mode


class PeerBlocksResponded(AbstractBrokerEvent):

    def __init__(self,
        addr: Address,
        blocks: list[block.Block] | list[block.BlockHeader] | list[block.BlockSummary],
        mode: Literal['HEADER', 'SUMMARY', 'BLOCK']
    ):
        self.addr = addr
        self.blocks = blocks
        self.mode = mode


class Broker(AbstractBroker):

    def __init__(self):
        self.subs: dict[type[AbstractBrokerEvent], set[asyncio.Queue]] = {}
        self._empty = set()
    
    def sub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue):
        self.subs.setdefault(event, set()).add(queue)
    
    def unsub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue):
        self.subs.setdefault(event, set()).discard(queue)
    
    def pub(self, event: AbstractBrokerEvent):
        x: list[asyncio.Queue] = list(self.subs.get(type(event), self._empty))
        for q in x:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # If the queue is full, we skip this subscriber
                continue
