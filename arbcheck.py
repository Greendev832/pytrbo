import sys
import os
import cryptocheck
from sage.all import Matrix, ZZ, vector, QQ
from web3 import Web3
from eth_utils import keccak, to_bytes
import rlp
from eth_keys import keys
from eth_utils import decode_hex

# 1. Setup Connection (Using a public Arbitrum RPC)
RPC_URL = "https://arb1.arbitrum.io/rpc" # You can replace with your own provider

n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
middleN = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0

w3 = Web3(Web3.HTTPProvider(RPC_URL))

def get_signature_data(tx_hash):
    try:
        # Fetch transaction details
        tx = w3.eth.get_transaction(tx_hash)
        
        # Extract r, s, v
        r = tx['r'].hex()
        s = tx['s'].hex()
        v = tx['v']
        
        # Prepare the transaction dictionary to reconstruct the hash (z)
        # We need the unsigned version to find what was actually signed
        tx_dict = {
            'nonce': tx['nonce'],
            'gasPrice': tx['gasPrice'],
            'gas': tx['gas'],
            'to': tx['to'],
            'value': tx['value'],
            'data': tx['input'],
            'chainId': tx.get('chainId', 42161)
        }
        
        # Handle EIP-1559 transactions (maxFeePerGas)
        if 'maxFeePerGas' in tx:
            tx_dict['maxFeePerGas'] = tx['maxFeePerGas']
            tx_dict['maxPriorityFeePerGas'] = tx['maxPriorityFeePerGas']
            del tx_dict['gasPrice']

        unsigned_tx = serializable_unsigned_transaction_from_dict(tx_dict)
        z = unsigned_tx.hash().hex()

        print(f"--- Data for Tx: {tx_hash} ---")
        print(f"z (Message Hash): {z}")
        print(f"r: {r}")
        print(f"s: {s}")
        print(f"v: {v}")
        print("-" * 30)
        
        return z, r, s

    except Exception as e:
        print(f"Error: {e}")
        return None
    
def getAddress(srckey):
    raw_key = srckey.replace("0x", "")
    if len(raw_key) % 2 != 0:
        raw_key = "0" + raw_key

    priv_key_hex = "0x" + raw_key
    priv_key_bytes = decode_hex(priv_key_hex)
    priv_key_obj = keys.PrivateKey(priv_key_bytes)
    pub_key_obj = priv_key_obj.public_key
    print(f"Derived Address: {pub_key_obj.to_checksum_address()}")
    return pub_key_obj.to_checksum_address()

def manual_z_calculation(tx_hash):
    try:
        tx = w3.eth.get_transaction(tx_hash)        
        # 1. Get raw r, s, v
        r = tx['r'].hex()
        s = tx['s'].hex()
        v = tx['v']        
        # 2. Reconstruct the Type 2 (EIP-1559) Transaction payload for hashing
        # Format: 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, destination, amount, data, access_list])
        print(tx['chainId'])
        def clean_hex(val):
            if not val: return b''
            if isinstance(val, bytes): return val
            return to_bytes(hexstr=val)
    
        tx_list = [
            tx['chainId'],
            tx['nonce'],
            tx['maxPriorityFeePerGas'],
            tx['maxFeePerGas'],
            tx['gas'],
            clean_hex(tx['to']),
            tx['value'],
            clean_hex(tx['input']),
            tx.get('accessList', [])
        ]
        
        # Encode with RLP and prepend the Type 2 byte (0x02)
        encoded_tx = b'\x02' + rlp.encode(tx_list)
        
        # The hash of this is 'z'
        z = keccak(encoded_tx).hex()

        print(f"--- MANUAL EXTRACTION SUCCESS ---")
        print(f"z: {z}")
        print(f"r: {r}")
        print(f"s: {s}")
        print(f"v: {v}")
        
        r = int(r, 16)
        s = int(s, 16)
        z = int(z, 16)

        return z, r, s

    except Exception as e:
        print(f"Manual Hash Error: {e}")
        print("\nFallback: If RLP failed, here is the raw signature data:")
        print(f"Raw R: {tx['r'].hex()}")
        print(f"Raw S: {tx['s'].hex()}")

def check_single_sig(s):
    # SageMath Recovery Script
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    # Modular inverse of s
    s_inv = pow(s, -1, n)
    
    # We are testing if the nonce k has a significant bias.
    # To perform a Hidden Number Problem (HNP) attack, 
    # we ideally need a second signature from the same address.
    print("Checking signature for common vulnerabilities...")
    
    # Check if s is low-s normalized (EIP-2)
    if s > n // 2:
        print("Note: High-s value detected. Normalizing...")
        s_norm = n - s
    else:
        print("Signature is already low-s normalized.")

def check_possible(z1, r1, s1, z2, r2, s2):
    
    # Calculate t and u for each signature
    # t = (r * s^-1) mod n
    # u = (-z * s^-1) mod n
    s1_inv = pow(s1, -1, n)
    s2_inv = pow(s2, -1, n)
    
    t1 = (r1 * s1_inv) % n
    u1 = (z1 * s1_inv) % n
    
    t2 = (r2 * s2_inv) % n
    u2 = (z2 * s2_inv) % n
    
    # We transform the problem to: d*T + U = K (mod n)
    # where T = (t1 - t2) and U = (u1 - u2)
    T = (t1 - t2) % n
    U = (u1 - u2) % n
    
    # Construct the 2x2 LLL Matrix
    # This checks for "small" differences in nonces
    M = Matrix(ZZ, [
        [n, 0],
        [T, 1]
    ])
    
    print("Running LLL algorithm...")
    L = M.LLL()
    
    for row in L:
        # Potential private key candidate
        potential_d = (row[0] - U) * pow(T, -1, n) % n
        if potential_d != 0:
            getAddress(hex(potential_d))
            # print(f"\n[!] Possible Private Key Found: {hex(potential_d)}")

def run_lattice(z1, r1, s1, z2, r2, s2):
    # Calculate modular values
    s1_inv = pow(s1, -1, n)
    s2_inv = pow(s2, -1, n)
    
    t1 = (r1 * s1_inv) % n
    u1 = (z1 * s1_inv) % n
    
    t2 = (r2 * s2_inv) % n
    u2 = (z2 * s2_inv) % n
    
    # Hidden Number Problem formulation
    # We look for d such that: (t1*d - u1) - (t2*d - u2) is small
    T = (t1 - t2) % n
    U = (u2 - u1) % n
    
    # Constructing the Matrix for LLL
    # This matrix assumes the nonces share a bias in the most significant bits
    # Shift represents the expected bit-length of the nonce (256 - bias)
    #MSB->
    shift = 2**128 
    M = Matrix(ZZ, [
        [n, 0, 0],
        [T, 1, 0],
        [U, 0, shift]
    ])

    #LSB->
    # M = Matrix(ZZ, [[2**128 * n, 0, 0], [2**128 * T, 1, 0], [2**128 * U, 0, n]])
    
    print("Computing LLL...")
    L = M.LLL()
    
    found = False
    for row in L:
        # Candidate for the Private Key d
        # d = (k1 - u1) * t1^-1 mod n
        # Since row[1] represents a candidate for (k1 - k2), we test the relationship
        potential_k1 = abs(row[0])
        if potential_k1 == 0: continue
        
        # Solving for d: d = (k - u) * t^-1 mod n
        d = ((potential_k1 + u1) * pow(t1, -1, n)) % n
        
        # Validation: Check if d * G yields the expected address (simplified as d > 0)
        if d > 10**10: 
            # print(f"\n[!] ALERT: Possible Private Key Found!")
            # print(f"Hex: {hex(d)}")
            # print(f"Dec: {d}")
            print(len(hex(d)))
            getAddress(hex(d))
            found = True
            # break
            
    if not found:
        print("LLL finished. No short vector found with current bias settings.")
        print("Tip: If the nonces have a smaller bias, try changing 'shift' to 2**160 or 2**20")

def solve_lattice(z1, r1, s1, z2, r2, s2):
    # Modular inverses
    s1_inv = pow(s1, -1, n)
    s2_inv = pow(s2, -1, n)
    
    t1 = (r1 * s1_inv) % n
    u1 = (z1 * s1_inv) % n
    t2 = (r2 * s2_inv) % n
    u2 = (z2 * s2_inv) % n
    
    T = (t1 - t2) % n
    U = (u2 - u1) % n
    
    # We test for Most Significant Bit (MSB) bias
    # Common leak sizes: 128 bits, 160 bits
    for bias_bits in [128, 160, 192]:
        B = 2^bias_bits
        M = Matrix(ZZ, [
            [n, 0, 0],
            [T, 1, 0],
            [U, 0, B]
        ])
        
        L = M.LLL()
        for row in L:
            # Check for the key candidate
            for sign in [1, -1]:
                k_diff = abs(row[0])
                if k_diff == 0: continue
                
                # Formula for d: d = (k - u) * t^-1 mod n
                d = ((k_diff * sign + u1 - u2) * pow(t1 - t2, -1, n)) % n
                
                if d > 0 and d < n:
                    # Final check: Verify d produces r1
                    # (Requires ECPublicKey math, but we check bit length first)
                    if d.bit_length() > 200:
                        print(len(hex(d)))
                        getAddress(hex(d))
                        # print(f"HEX: {hex(d)}")
                        # return True
    return False

def solve(z1, r1, s1, z2, r2, s2):
    # Modular inverses
    s1_inv = pow(s1, -1, n)
    s2_inv = pow(s2, -1, n)
    
    t1 = (r1 * s1_inv) % n
    u1 = (z1 * s1_inv) % n
    t2 = (r2 * s2_inv) % n
    u2 = (z2 * s2_inv) % n
    
    T = (t1 - t2) % n
    U = (u2 - u1) % n
    
    # Check for Most Significant Bit (MSB) bias
    # We test common leak sizes used in older or flawed signing libs
    for bias in [2^128, 2^160, 2^192]:
        print(f"Testing bias: {bias.bit_length()} bits...")
        M = Matrix(ZZ, [[n, 0, 0], [T, 1, 0], [U, 0, bias]])
        L = M.LLL()
        
        for row in L:
            for sign in [1, -1]:
                k_candidate = (row[0] * sign) % n
                if k_candidate == 0: continue
                
                # Formula: d = (k_candidate - u1) * t1^-1 mod n
                d = ((k_candidate + u1) * pow(t1, -1, n)) % n
                # d = ((k_candidate - u1) * pow(t1, -1, n)) % n
                
                # If d is the key, it will satisfy the second signature relationship
                if (d * t2 - u2) % n < bias:
                    print(len(hex(d)))
                    print(getAddress(hex(d)))
                    # print(f"Hex: {hex(d)}")
                    # return True
    return False

def solve_two_lattice(z1, r1, s1, z2, r2, s2):
    s1_inv = pow(s1, -1, n)
    s2_inv = pow(s2, -1, n)
    t1, u1 = (r1 * s1_inv) % n, (z1 * s1_inv) % n
    t2, u2 = (r2 * s2_inv) % n, (z2 * s2_inv) % n
    T, U = (t1 - t2) % n, (u2 - u1) % n

    # 1. TEST MSB BIAS (Top Bits)
    print("Strategy 1: Testing MSB Bias...")
    for bias in [2^128, 2^160, 2^192]:
        M = Matrix(ZZ, [[n, 0, 0], [T, 1, 0], [U, 0, bias]])
        for row in M.LLL():
            d = ((abs(row[0]) + u1) * pow(t1, -1, n)) % n
            if d > 0 and d < n and d.bit_length() > 200:
                print(getAddress(hex(d)))

    # 2. TEST LSB BIAS (Bottom Bits)
    print("Strategy 2: Testing LSB Bias...")
    # LSB requires shifting the weights to the bottom of the matrix
    for shift in [2^8, 2^16, 2^32]:
        M = Matrix(ZZ, [[n * shift, 0, 0], [T * shift, 1, 0], [U * shift, 0, n]])
        for row in M.LLL():
            d = ((row[1] * pow(T, -1, n)) - U * pow(T, -1, n)) % n
            if d > 0 and d < n and d.bit_length() > 200:
                print(getAddress(hex(d)))

    print("No key found with current bias models.")

def getSignatures(txhashes):
    sigs = []
    for txhash in txhashes:
        z, r, s = manual_z_calculation(txhash)
        sigs.append({'z': z, 'r': r, 's': s})
    return sigs

def solve_multi_hnp(signatures, addr):
    m = len(signatures)
    # Target bit-leakage (start with 128 bits)
    B = 2^128 
    
    # Calculate t_i and u_i
    ts = []
    us = []
    for sig in signatures:
        s_inv = pow(sig['s'], -1, n)
        ts.append((sig['r'] * s_inv) % n)
        us.append((sig['z'] * s_inv) % n)
        
    # Construct the lattice matrix
    # Rows: m+1, Columns: m+1
    matrix_rows = []
    for i in range(m):
        row = [0] * (m + 1)
        row[i] = n
        matrix_rows.append(row)
        
    # The bias relation row
    last_row = [0] * (m + 1)
    for i in range(m):
        last_row[i] = ts[i]
    last_row[m] = B / n # Weighting factor
    matrix_rows.append(last_row)
    
    # The constant terms row
    const_row = [0] * (m + 1)
    for i in range(m):
        const_row[i] = us[i]
    # matrix_rows.append(const_row) # Variation for certain HNP solvers

    M = Matrix(ZZ, matrix_rows)
    print(f"Running LLL on {m} signatures...")
    L = M.LLL()
    
    # Check vectors for key candidate
    for row in L:
        potential_k = abs(row[0])
        if potential_k == 0: continue
        d = ((potential_k + us[0]) * pow(ts[0], -1, n)) % n
        if d.bit_length() > 200:
            print(getAddress(hex(d)))
            # return True
    return False

def multi_solve(signatures):
    m = len(signatures)
    # Testing different leak sizes (from 8 bits to 128 bits)
    # The 'X' value represents the maximum size of the random nonce k
    for leak_bits in [128, 160, 200, 64]:
        X = 2^(256 - leak_bits) 
        print(f"Testing for {leak_bits}-bit bias (Max k = {X.bit_length()} bits)...")
        
        # Calculate t_i and u_i
        ts = []
        us = []
        for sig in signatures:
            s_inv = pow(sig['s'], -1, n)
            ts.append((sig['r'] * s_inv) % n)
            us.append((sig['z'] * s_inv) % n)
            
        # Matrix Construction (m+1 x m+1)
        # Using the embedding technique to find the private key d
        M = Matrix(ZZ, m + 1, m + 1)
        for i in range(m - 1):
            M[i, i] = n
            
        # Relationships between signatures
        # (t_i * d - u_i) - (t_m * d - u_m) = k_i - k_m
        for i in range(m - 1):
            M[m - 1, i] = (ts[i] * pow(ts[m-1], -1, n)) % n
            
        M[m - 1, m - 1] = 1 # Weight for the key relationship
        M[m, m] = X # Weight for the bias target
        
        # Embedding the constant terms (u_i)
        for i in range(m - 1):
            diff_u = (us[i] - us[m-1] * ts[i] * pow(ts[m-1], -1, n)) % n
            M[m, i] = diff_u

        L = M.LLL()
        
        for row in L:
            # Check the candidate in the second to last column
            # This represents the potential private key d
            for sign in [1, -1]:
                d_candidate = (row[m-1] * sign) % n
                if d_candidate < 100: continue # Skip trivial vectors
                
                # Check if this d satisfies the first signature
                if d_candidate.bit_length() > 200:
                    print(getAddress(hex(d_candidate)))

def run_diff(z1, r1, s1, z2, r2, s2):
    s1_inv = pow(s1, -1, n)
    s2_inv = pow(s2, -1, n)
    
    t1 = (r1 * s1_inv) % n
    u1 = (z1 * s1_inv) % n
    t2 = (r2 * s2_inv) % n
    u2 = (z2 * s2_inv) % n
    
    # We are looking for a small 'd' (private key) and small 'k' differences
    # Construction: [n, 0], [t1-t2, 1]
    T = (t1 - t2) % n
    U = (u2 - u1) % n
    
    # Testing for small differences between k1 and k2
    # We use a 2x2 matrix with a target 'U'
    for shift in [2^64, 2^128, 2^160]:
        M = Matrix(ZZ, [[n, 0], [T, shift]])
        target = vector(ZZ, [U, 0])
        
        # Solving the Closest Vector Problem (CVP)
        L = M.LLL()
        for row in L:
            # Check the candidate
            d = (U * pow(T, -1, n)) % n
            if d.bit_length() > 200:
                print(getAddress(hex(d)))
                # return True
    return False

if __name__ == "__main__":
    # Usage: sage -python script.py 0xYourTxHash
    # myAddress = "0xf584F8728B874a6a5c7A8d4d387C9aae9172D621"
    # txHashes = [
    #     "0x20a276aa6d4add5d5254de82528f7ec3461902a0ec8089401384c5b28e3a8e90",
    #     "0x0838ae66e88ad3f7b21fa4be6ef87d5887f5878f449e6bfae850df8677a5f328",
    #     "0xbcbd84c7a1e2ebccd075924ee060848b16532bb616449317c42021c515ca987d"
    # ]
    # sigs = getSignatures(txHashes)
    # multi_solve(sigs)
    z1,r1,s1 = manual_z_calculation("0x4c35be4635647fc39bcb8d7fdeffd760b03e9a4d1af4b4cdcc43ca30eb9e5969")
    z2,r2,s2 = manual_z_calculation("0x20022e8fc4b471500f28d5d97f9b82825fbcab22544540ba36f2655a09b74cc6")
    solve_two_lattice(z1, r1, s1, z2, r2, s2)
    # print(cryptocheck.verify_z(z2, r2, s2, 0, myAddress))
    # getAddress("0x50ba2625495e6bac51bfa010cc9295859858683b3f610075331131d3094e518")
    # check_single_sig(s)
    # if len(sys.argv) > 1:
    #     get_signature_data(sys.argv[1])
    # else:
    #     print("Please provide a Transaction Hash.")