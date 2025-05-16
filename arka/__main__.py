
import asyncio
from arka import net, broker

async def main():
    b = broker.Broker()
    q = asyncio.Queue()
    b.sub(broker.PeerConnected, q)
    b.sub(broker.PeerDisconnected, q)
    bs = [('2600:1900:4000:2958::', 4700)]
    m = net.Mesh(('::', 0), b, bs)
    await m.start()
    print(f'Running at {m.transport.get_extra_info("sockname")[:2]}')
    while True:
        match await q.get():
            case broker.PeerConnected() as e:
                print(f'{e.addr} CONNECTED!')
            case broker.PeerDisconnected() as e:
                print(f'{e.addr} DISCONNECTED!')


asyncio.run(main())

