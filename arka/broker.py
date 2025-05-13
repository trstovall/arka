
import asyncio


Address = tuple[str, int]


class AbstractBrokerEvent(object):
    pass


class PeerConnected(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class PeerDisconnected(AbstractBrokerEvent):

    def __init__(self, addr: Address):
        self.addr = addr


class Broker(object):

    def __init__(self):
        self.subs: dict[AbstractBrokerEvent, set[asyncio.Queue]] = {}
        self._empty = set()
    
    def sub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue):
        self.subs.setdefault(event, set()).add(queue)
    
    def unsub(self, event: type[AbstractBrokerEvent], queue: asyncio.Queue):
        self.subs.setdefault(event, set()).discard(queue)
    
    async def pub(self, event: AbstractBrokerEvent):
        for q in self.subs.get(type(event), self._empty):
            await q.put(event)
