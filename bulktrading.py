import requests
import time

RPC_URL = "https://mainnet.infura.io/v3/e3a37fd57e33410eb7f4cfa8c84f3349"

CHUNK_SIZE = 100
MAX_RETRIES = 3


def chunked(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def fetch_batch(addresses):
    payload = [
        {
            "jsonrpc": "2.0",
            "id": i,
            "method": "eth_getBalance",
            "params": [addr, "latest"]
        }
        for i, addr in enumerate(addresses)
    ]

    for attempt in range(MAX_RETRIES):
        try:
            res = requests.post(RPC_URL, json=payload, timeout=5)
            res.raise_for_status()
            data = res.json()

            results = {}
            for item in data:
                idx = item["id"]
                addr = addresses[idx]

                if "result" in item:
                    results[addr] = int(item["result"], 16) / 1e18
                else:
                    results[addr] = None

            return results

        except Exception as e:
            print(f"Retry {attempt+1} failed:", e)
            time.sleep(0.5)

    return {addr: None for addr in addresses}


def get_balances(addresses):
    final = {}

    for chunk in chunked(addresses, CHUNK_SIZE):
        result = fetch_batch(chunk)
        final.update(result)

    return final


# --- usage ---
if __name__ == "__main__":
    addresses = [
        "0x0000000000000000000000000000000000000000",
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    ]

    balances = get_balances(addresses)

    for addr, bal in balances.items():
        print(addr, bal, "ETH")