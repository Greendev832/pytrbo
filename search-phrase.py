import hashlib
import base58
import time
import requests
import json
import ecdsa # Required for Secp256k1 derivation

# --- AUDIT CONFIGURATION ---
# Current Time: 02:56 AM CDT, Tuesday, June 9, 2026
# Optimized for 2012-2013 Brainwallet Recovery

# The "High-Probability" 2012-2013 Era Dictionary
# AUDIT_PHRASES = [
#     "correct horse battery staple", "bitcoin", "satoshi", "nakamoto",
#     "password", "12345678", "qwertyuiop", "bitcoin is king",
#     "to the moon", "blockchain", "vires in numeris", "end the fed",
#     "chancellor on brink of second bailout", "genesis block",
#     "the times 03/jan/2009", "cypherpunk", "privacy is a human right"
# ]

AUDIT_PHRASES = [
    "liberty or death", "don't tread on me", "aaron swartz", "julian assange",
"free ross ulbricht", "silk road", "the white paper", "peer to peer",
"decentralize everything", "non aggression principle", "who is john galt"
]


QUICKNODE_URL = "https://indulgent-fluent-fog.btc.quiknode.pro/57aa2423c013b6d13f1dc4d41d4f959e95962cf2"

def get_balance_quicknode(address):
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'SovereignAuditor/12.4 (Macintosh; M2 Mac)',
        'Accept': 'application/json'
    }

    # Strict JSON-RPC 2.0 formatting
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getaddressbalance", # This is the standard QuickNode Indexed method
        "params": [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" # No nested list, just the string
        ]
    }
    try:
        response = requests.post(QUICKNODE_URL, headers=headers, data=json.dumps(payload), timeout=60)
        if response.status_code == 200:
            result = response.json().get('result', {})
            print(response.json())
            # Return balance in BTC
            return result.get('balance', 0) / 100_000_000
        elif response.status_code == 404:
            return "Error: 404 (Check URL/Method)"
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return f"RPC Failure: {str(e)}"


# --- STANDALONE BRAINWALLET AUDITOR v11.1 ---
# Current Time: 03:11 AM CDT, Tuesday, June 9, 2026
# Fully Integrated Phrase -> Key -> WIF -> Address

def get_address(pub_bytes):
    """Derives a Legacy P2PKH Address (starts with '1') from Public Key bytes."""
    sha256_h = hashlib.sha256(pub_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_h).digest()
    vh = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    return base58.b58encode(vh + checksum).decode('utf-8')

def to_wif(p_bytes, compressed=False):
    """Converts raw private key bytes to WIF (Wallet Import Format)."""
    extended = b'\x80' + p_bytes
    if compressed: extended += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode('utf-8')

def audit_phrase(phrase):
    # 1. Private Key (SHA256 of the phrase)
    priv_bytes = hashlib.sha256(phrase.encode('utf-8')).digest()
    
    # 2. Derive Public Keys using Secp256k1 curve
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    
    # Uncompressed PubKey (Standard 2012)
    pub_uncompressed = b'\x04' + vk.to_string()
    
    # Compressed PubKey (Standard 2013)
    pub_compressed = vk.to_string(encoding="compressed")

    return {
        "phrase": phrase,
        "wif_2012": to_wif(priv_bytes, compressed=False),
        "addr_2012": get_address(pub_uncompressed),
        "wif_2013": to_wif(priv_bytes, compressed=True),
        "addr_2013": get_address(pub_compressed)
    }

def get_balance_blockchain_info(address):
    """
    Fetches the balance of a Bitcoin address using the Blockchain.info API.
    Free tier allows for occasional lookups. For bulk, use a local node.
    """
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
    try:
        response = requests.get(url, timeout=10)
        print(response)
        if response.status_code == 200:
            data = response.json()
            # Balance is returned in Satoshis (1 BTC = 100,000,000 Satoshis)
            satoshis = data.get('final_balance', 0)
            btc = satoshis / 100_000_000
            tx_count = data.get('n_tx', 0)
            return {
                "address": address,
                "balance_btc": btc,
                "total_received": data.get('total_received', 0) / 100_000_000,
                "tx_count": tx_count
            }
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_balances_batch(address_list):
    """Checks up to 100 addresses in a single request."""
    addrs = "|".join(address_list)
    url = f"https://blockchain.info/balance?active={addrs}"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return {addr: (val['final_balance'] / 100_000_000) for addr, val in data.items()}
    except Exception as e:
        print(str(e))
        return None
    
def get_balance_multi_api(address):
    """
    Checks Bitcoin balance by rotating through multiple public APIs.
    Bypasses individual 400/429 errors automatically.
    """
    # 08:41 AM Provider List
    apis = [
        {"name": "Blockstream", "url": f"https://blockstream.info/api/address/{address}", "type": "esplora"},
        {"name": "Mempool.space", "url": f"https://mempool.space/api/address/{address}", "type": "esplora"},
        {"name": "BlockCypher", "url": f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance", "type": "blockcypher"},
    ]

    for api in apis:
        try:
            response = requests.get(api["url"], timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if api["type"] == "esplora":
                    stats = data.get('chain_stats', {})
                    confirmed_bal = (stats.get('funded_txo_sum', 0) - stats.get('spent_txo_sum', 0)) / 100_000_000

                    m_stats = data.get('mempool_stats', {})
                    mempool_bal = m_stats.get('funded_txo_sum', 0) - m_stats.get('spent_txo_sum', 0)
                    balance = confirmed_bal + mempool_bal
                else:
                    balance = data.get('balance', 0) / 100_000_000
                
                return balance
        except Exception:
            continue # Try next API in list
            
    return 0.0

if __name__ == "__main__":
    print(f"--- Brainwallet Audit Log: {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
    res2012 = get_balance_multi_api('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    print(res2012)
    
    for phrase in AUDIT_PHRASES:
        data = audit_phrase(phrase)
        # print(data)
        print(f"Phrase: {data['phrase']}")
        # print(f"  > 2012 WIF: {data['wif_2012']}")
        res2012 = get_balance_multi_api(data['addr_2012'])
        print(f"Address: {data['addr_2012']}, {res2012}")
        res2013 = get_balance_multi_api(data['addr_2013'])

        # print(f"  > 2013 WIF: {data['wif_2013']}")
        print(f"Address: {data['addr_2013']}, {res2013}")
        time.sleep(0.5)