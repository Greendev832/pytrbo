import hashlib
import base58
import time
import requests
import subprocess
import json
import ecdsa # Required for Secp256k1 derivation
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from bitcoinutils.transactions import Transaction
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
import binascii

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

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

RPC_USER = "ace"
RPC_PASS = "browser"

QUICKNODE_URL = "https://indulgent-fluent-fog.btc.quiknode.pro/57aa2423c013b6d13f1dc4d41d4f959e95962cf2"

def call_cli(command):
    """Executes bitcoin-cli with RPC credentials and parses the result."""
    cmd = ["bitcoin-cli", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}", *command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600) # Long timeout for scanning
        print(result)
        if result.returncode == 0:
            raw = result.stdout.strip()
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start != -1 and end != 0:
                return json.loads(raw[start:end])
            return raw
    except Exception as e:
        print(str(e))
        pass
    return None

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

# def verify_all_standards(private_key_int):
#     """
#     Exhaustive verification of ALL possible 2012-2013 address formats.
#     Includes: Uncompressed, Compressed, and Hybrid sign configurations.
#     """
#     try:
#         # 1. Standardize the integer to be within the SECP256k1 field
#         pk_clean = int(private_key_int) % N
#         # pk_clean = int(private_key_int)
#         if pk_clean == 0: return False
        
#         # 2. CRITICAL: Pad the hex string to exactly 64 characters (32 bytes)
#         # This prevents the "Length of string" error
#         pk_hex = hex(pk_clean)[2:].zfill(64)
#         pk_bytes = binascii.unhexlify(pk_hex)
        
#         # 3. Import as Signing Key
#         from ecdsa import SigningKey
#         sk = SigningKey.from_string(pk_bytes, curve=SECP256k1)
#         vk = sk.get_verifying_key()
        
#         # 4. Generate the candidates based on 2012/2013 standards
#         # Uncompressed (Legacy 2012): 0x04 + 64 bytes of X,Y
#         uncompressed_pub = b'\x04' + vk.to_string() 
#         # Compressed (Legacy 2013): 0x02/0x03 + 32 bytes of X
#         compressed_pub = vk.to_string(encoding="compressed")
        
#         for pubkey in [uncompressed_pub, compressed_pub]:
#             # SHA256 -> RIPEMD160
#             sha = hashlib.sha256(pubkey).digest()
#             h = hashlib.new('ripemd160', sha).digest()
#             # Add Network Byte (Mainnet = 0x00)
#             net = b'\x00' + h
#             # Double SHA256 Checksum
#             check = hashlib.sha256(hashlib.sha256(net).digest()).digest()[:4]
#             # Base58
#             addr = base58.b58encode(net + check).decode()
#             res2012 = get_balance_multi_api(addr)
#             print(addr)
#             print(res2012)
#     except Exception as e:
#         print(str(e))
#         # Silently skip candidates that fail to parse
#         # return False
#     # return False

def verify_all_standards(private_key_int):
    """
    Exhaustive verification of 2012-2013 standards.
    Outputs both the Address and the corresponding Private Key (WIF).
    """
    try:
        # 1. Standardize and Pad
        pk_clean = int(private_key_int) % N
        if pk_clean == 0: return False
        
        pk_hex = hex(pk_clean)[2:].zfill(64)
        pk_bytes = binascii.unhexlify(pk_hex)
        
        # 2. Derive Verifying Key
        sk = SigningKey.from_string(pk_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # 3. Define Standards: (Label, PubKeyBytes, is_compressed)
        standards = [
            ("Legacy Uncompressed (2012)", b'\x04' + vk.to_string(), False),
            ("Legacy Compressed (2013)", vk.to_string(encoding="compressed"), True)
        ]
        
        for label, pubkey, is_compressed in standards:
            # --- PART A: Generate Address ---
            sha = hashlib.sha256(pubkey).digest()
            h = hashlib.new('ripemd160', sha).digest()
            net_addr = b'\x00' + h
            check_addr = hashlib.sha256(hashlib.sha256(net_addr).digest()).digest()[:4]
            addr = base58.b58encode(net_addr + check_addr).decode()
            
            # --- PART B: Generate WIF (Private Key) ---
            # Prefix 0x80 for Mainnet
            if is_compressed:
                # Compressed WIF adds a 0x01 suffix to the private key bytes
                raw_wif = b'\x80' + pk_bytes + b'\x01'
            else:
                raw_wif = b'\x80' + pk_bytes
                
            check_wif = hashlib.sha256(hashlib.sha256(raw_wif).digest()).digest()[:4]
            wif = base58.b58encode(raw_wif + check_wif).decode()

            # --- PART C: Output ---
            print(f"--- {label} ---")
            print(f"Address: {addr}")
            print(f"WIF Key: {wif}")

            # tx_data = call_cli(["scantxoutset", 'start', f'[{{"desc":"addr({addr})"}}]'])
            # print(tx_data['total_amount'])

            # # Call your balance API
            # if tx_data['total_amount'] > 0.0:
            #     balance = get_balance_multi_api(addr)
            #     print(f"Balance: {balance}")
            #     if balance > 0.0:
            #         return True
            
            print("-" * 30)

    except Exception as e:
        print(f"Error: {str(e)}")
    return False


if __name__ == "__main__":
    print(f"--- Brainwallet Audit Log: {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
    verify_all_standards("83028330920203733122359012694059835179187558478082245005773143407281055445935")
    # res2012 = get_balance_multi_api('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    # print(res2012)
    
    # for phrase in AUDIT_PHRASES:
    #     data = audit_phrase(phrase)
    #     # print(data)
    #     print(f"Phrase: {data['phrase']}")
    #     # print(f"  > 2012 WIF: {data['wif_2012']}")
    #     res2012 = get_balance_multi_api(data['addr_2012'])
    #     print(f"Address: {data['addr_2012']}, {res2012}")
    #     res2013 = get_balance_multi_api(data['addr_2013'])

    #     # print(f"  > 2013 WIF: {data['wif_2013']}")
    #     print(f"Address: {data['addr_2013']}, {res2013}")
    #     time.sleep(0.5)
    # address = '1BQEJpcMjuYWJV1jCEA8pajGexQ9WBBtSb'
    # tx_data = call_cli(["scantxoutset", 'start', f'[{{"desc":"addr({address})"}}]'])
    # print(tx_data)

    key = 2 ** 248
    # idx = 263 #Tab = 1
    # while (True):
    #    res = verify_all_standards(key+idx)
    #    print(idx)
    #    if res:
    #        break
    #    idx += 1

    # idx = 0
    # while (True):
    #    res = verify_all_standards(key-idx)
    #    print(idx)
    #    if res:
    #        break
    #    idx += 1
    #    time.sleep(1)

    # key = N // 2
    # verify_all_standards(key+456137891358)