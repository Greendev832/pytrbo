from web3 import Web3
import time
from collections import defaultdict

INFURA_URL = "https://mainnet.infura.io/v3/7795ed39279a4da4b5ec9b6f3efb09f5"
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

START_BLOCK = w3.eth.block_number - 2000  # scan last ~2000 blocks

wallet_stats = defaultdict(lambda: {
    "tx_count": 0,
    "total_value": 0,
    "first_seen": None,
    "last_seen": None
})

def process_tx(tx):
    if not tx["from"]:
        return

    wallet = tx["from"]

    value_eth = w3.from_wei(tx["value"], "ether")

    stats = wallet_stats[wallet]

    stats["tx_count"] += 1
    stats["total_value"] += float(value_eth)
    stats["last_seen"] = tx["blockNumber"]

    if not stats["first_seen"]:
        stats["first_seen"] = tx["blockNumber"]

def scan_blocks():
    global START_BLOCK

    latest = w3.eth.block_number

    print(f"Scanning from {START_BLOCK} → {latest}")

    for block_num in range(START_BLOCK, latest + 1):
        block = w3.eth.get_block(block_num, full_transactions=True)
        for tx in block.transactions:
            print(tx["hash"].hex(), tx["from"], tx["to"], tx["value"])
            process_tx(tx)

        START_BLOCK = block_num

while True:
    try:
        scan_blocks()
        time.sleep(5)

        print("Top active wallets:")

        sorted_wallets = sorted(
            wallet_stats.items(),
            key=lambda x: x[1]["tx_count"],
            reverse=True
        )[:10]

        for w, s in sorted_wallets:
            print(w, s)

    except Exception as e:
        print("Error:", e)
        time.sleep(5)