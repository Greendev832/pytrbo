from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://Mainnet.infura.io/v3/07b5e3368fdb472580a5b9b3c8dc953c"))

def find_shared_r(tx_hashes):
    r_map = {} # {r_value: [tx_hash1, tx_hash2, ...]}
    
    for tx_hash in tx_hashes:
        tx = w3.eth.get_transaction(tx_hash)
        r_val = tx['r'].hex()
        
        if r_val in r_map:
            r_map[r_val].append(tx_hash)
            print(f"[!] Collision Detected!")
            print(f"Shared R: {r_val}")
            print(f"Transactions: {r_map[r_val]}")
        else:
            r_map[r_val] = [tx_hash]
            
    return r_map