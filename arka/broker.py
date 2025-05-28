"""
``` python
import asyncio
from arka.broker import Broker, PeerConnected, Address

async def subscriber(name: str, broker: Broker):
    queue = asyncio.Queue(maxsize=5)
    broker.sub(PeerConnected, queue)
    while True:
        event = await queue.get()
        print(f"Subscriber {name} received: {event.addr}")

async def publisher(broker: Broker):
    await asyncio.sleep(1)
    await broker.pub(PeerConnected(("127.0.0.1", 8080)))
    await asyncio.sleep(1)
    await broker.pub(PeerConnected(("192.168.1.1", 9999)))

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

import asyncio


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


class Broker(AbstractBroker):

    def __init__(self):
        self.subs: dict[type[AbstractBrokerEvent], set[asyncio.Queue]] = {}
        self._empty = set()
    
    def sub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue):
        self.subs.setdefault(event, set()).add(queue)
    
    def unsub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue):
        self.subs.setdefault(event, set()).discard(queue)
    
    async def pub(self, event: AbstractBrokerEvent):
        x: list[asyncio.Queue] = list(self.subs.get(type(event), self._empty)):
        if not x:
            return
        await asyncio.gather(*[q.put(event) for q in x])
