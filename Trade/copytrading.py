import json
import time
from web3 import Web3

# --- CONFIG ---
WSS_URL = "wss://mainnet.infura.io/ws/v3/YOUR_API_KEY"

MY_WALLET = Web3.to_checksum_address("0xYOUR")
PRIVATE_KEY = "YOUR_PRIVATE_KEY"

# Track multiple wallets
TARGET_WALLETS = {
    Web3.to_checksum_address("0xWALLET1"): {"ratio": 0.2},
    Web3.to_checksum_address("0xWALLET2"): {"ratio": 0.1},
    Web3.to_checksum_address("0xWALLET3"): {"ratio": 0.3},
}

UNISWAP_ROUTER = Web3.to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")

w3 = Web3(Web3.WebsocketProvider(WSS_URL))

ROUTER_ABI = json.loads("""
[
  {
    "name": "swapExactETHForTokens",
    "type": "function",
    "inputs": [
      {"name": "amountOutMin", "type": "uint256"},
      {"name": "path", "type": "address[]"},
      {"name": "to", "type": "address"},
      {"name": "deadline", "type": "uint256"}
    ],
    "outputs": []
  }
]
""")

router = w3.eth.contract(address=UNISWAP_ROUTER, abi=ROUTER_ABI)

# --- HELPERS ---

def send_copy_trade(value, path, ratio):
    nonce = w3.eth.get_transaction_count(MY_WALLET)

    tx = router.functions.swapExactETHForTokens(
        0,
        path,
        MY_WALLET,
        int(time.time()) + 60
    ).build_transaction({
        'from': MY_WALLET,
        'value': int(value * ratio),
        'gas': 300000,
        'gasPrice': w3.eth.gas_price,
        'nonce': nonce,
    })

    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    print(f"✅ Copied trade: {tx_hash.hex()}")

# --- MAIN LOOP ---

def run():
    print("🚀 Multi-wallet tracking started...")
    pending_filter = w3.eth.filter('pending')

    while True:
        try:
            for tx_hash in pending_filter.get_new_entries():
                tx = w3.eth.get_transaction(tx_hash)

                if not tx or not tx['to']:
                    continue

                sender = tx['from']

                # Check if tx from tracked wallets
                if sender not in TARGET_WALLETS:
                    continue

                config = TARGET_WALLETS[sender]
                ratio = config["ratio"]

                print(f"🎯 {sender} triggered trade")

                if tx['to'].lower() == UNISWAP_ROUTER.lower():
                    try:
                        func, params = router.decode_function_input(tx['input'])

                        if func.fn_name == "swapExactETHForTokens":
                            print(f"🔁 Copying trade from {sender}")

                            path = params['path']
                            value = tx['value']

                            send_copy_trade(value, path, ratio)

                    except Exception as e:
                        print("Decode failed:", e)

        except Exception as e:
            print("Error:", e)
            time.sleep(2)

if __name__ == "__main__":
    run()