#!/usr/bin/env python3
"""Watch Bitcoin addresses for new activity via the mempool.space WebSocket API.

Usage:
    pip install websockets
    python ws_track.py addresses.txt

This pushes events (new transactions, confirmations) after you subscribe.
It does NOT return current balances. Message names below are from memory of the
mempool.space WebSocket API - check their docs if nothing arrives.
"""
import asyncio
import json
import sys
import balance
import websockets

URL = "wss://mempool.space/api/v1/ws"


async def main(path):
    with open(path, encoding="utf-8") as f:
        addrs = list(dict.fromkeys(l.strip() for l in f if l.strip() and not l.startswith("#")))
    print(addrs)
    f1 = open("result-val.tx", "a")
    for addr in addrs:
        current_balance = balance.get_balance(addr)
        if current_balance > 0.0:
            print(current_balance)
            f1.write(addr + "\n")
    f1.close()
    # addrs = ('1KuJRPSinvkHW4VEtYTnm6v9WyqvkbhAgt')
    # async with websockets.connect(URL) as ws:
    #     await ws.send(json.dumps({"track-addresses": addrs}))
    #     print(f"Subscribed to {len(addrs)} addresses. Waiting for activity (Ctrl+C to stop)...")
    #     async for message in ws:
    #         data = json.loads(message)
    #         if "address-transactions" in data or "block-transactions" in data:
    #             print(json.dumps(data, indent=2))


if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     sys.exit("usage: python ws_track.py addresses.txt")
    m_path = 'list_256.txt'
    # asyncio.run(main(sys.argv[1]))
    asyncio.run(main(m_path))