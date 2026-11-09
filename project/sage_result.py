import sys
from ecdsa import SigningKey, SECP256k1
from ecdsa.numbertheory import inverse_mod
from sage.all import Matrix, ZZ, vector, QQ, RealField, RR, log, EllipticCurve, GF, inverse_mod, Integer, power_mod
from fpylll import IntegerMatrix, GSO, BKZ, LLL, FPLLL, Enumeration
import json

# --- SECP256K1 CURVE ORDER CONSTANT ---
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def get_k(z_hex, r_hex, s_hex, d_hex):
    # n is the order of the SECP256k1 curve
    n = SECP256k1.order
    
    # Convert hex values to integers
    z = int(z_hex, 16)
    r = int(r_hex, 16)
    s = int(s_hex, 16)
    d = int(d_hex, 16)
    
    # Calculate k = (z + r*d) * inv(s) mod n
    s_inv = inverse_mod(s, n)
    k = ((z + r * d) * s_inv) % n
    
    return k

def verify_key_affine_coordinates(potential_x, target_pubkey_x_hex, target_pubkey_y_hex):
    """
    Direct integer coordinate check to guarantee SageMath evaluates the point match 
    without falling into string-formatting or header prefix traps.
    """
    try:
        if potential_x <= 0 or potential_x >= Q: 
            return False
            
        # Reconstruct the private key object from the candidate scalar
        priv_key = SigningKey.from_secret_num(int(potential_x), curve=SECP256k1)
        pub_key = priv_key.verifying_key
        
        # Extract direct coordinate integers from the generated public point object
        point = pub_key.pubkey.point
        derived_x = int(point.x())
        derived_y = int(point.y())
        
        # Convert target hex parameters straight to integers for an exact numerical check
        target_x_int = int(target_pubkey_x_hex, 16)
        target_y_int = int(target_pubkey_y_hex, 16)
        
        return (derived_x == target_x_int) and (derived_y == target_y_int)
    except:
        return False

def run_17_input_centered_lattice(signatures_list, target_pubkey_x_hex, target_pubkey_y_hex):
    """
    Sign-Agnostic Centered Lattice Matrix Solver.
    Uses 17 inputs to cancel out all browser engine variants, timestamps, and mouse noise.
    """
    m = len(signatures_list) # Must be exactly 17
    if m < 17:
        print(f"[-] Warning: You supplied {m} inputs. This lattice is optimized for exactly 17.")
        
    dim = m + 2              # 19 x 19 Matrix
    M = Matrix(ZZ, dim, dim)
    
    # 1. Populate the diagonal modular matrix constraints
    for i in range(m):
        M[i, i] = Q
        
    # 2. Populate the row linking your shared private key variable 'x'
    for i in range(m):
        t_i, u_i = signatures_list[i]
        M[m, i] = t_i
    M[m, m] = 1
    
    # 3. Apply the Sign-Agnostic Centering Shift Transformation
    # Shifting the constant offset matrix profile by adding half the curve order (Q // 2)
    # forces both positive and negative nonces into an identical short vector tracking length.
    for i in range(m):
        t_i, u_i = signatures_list[i]
        M[m+1, i] = (u_i + (Q // 2)) % Q   
        
    # Set the precise geometric bounding weights across the final columns
    M[m, m] = 0
    M[m+1, m+1] = Q // 2 

    print(f"[*] Constructing corrected {dim}x{dim} Sign-Agnostic Matrix...")
    print("[*] Running maximum mathematical reduction pass...")
    
    # Pre-reduce with LLL to clean the basis geometry
    M_reduced = M.LLL()
    
    # Set block size equal to the dimensions for an unconstrained, exhaustive vector space sweep
    M_reduced.BKZ(block_size=19)
    
    print("[+] Reduction complete. Evaluating output basis for key extraction...")
    print("-" * 75)
    
    for row_index, row in enumerate(M_reduced):
        candidate_x = row[m]
        if candidate_x == 0: 
            continue
            
        # Test standard positive orientation
        pos_key = candidate_x % Q
        if verify_key_affine_coordinates(pos_key, target_pubkey_x_hex, target_pubkey_y_hex):
            print("\n" + "="*75)
            print(f"[🎯🎯🎯 LATTICE SUCCESS: PRIVATE KEY RECOVERED]")
            print(f"[+] Output Row Index:            {row_index}")
            print(f"[+] Recovered Private Key (Hex): {hex(pos_key)}")
            print("="*75 + "\n")
            return pos_key
            
        # Test negative/inverted geometric reflection track
        neg_key = (-candidate_x) % Q
        if verify_key_affine_coordinates(neg_key, target_pubkey_x_hex, target_pubkey_y_hex):
            print("\n" + "="*75)
            print(f"[🎯🎯🎯 LATTICE SUCCESS: PRIVATE KEY RECOVERED]")
            print(f"[+] Output Row Index:            {row_index} (Flipped Translation)")
            print(f"[+] Recovered Private Key (Hex): {hex(neg_key)}")
            print("="*75 + "\n")
            return neg_key
            
    print("[-] Lattice finished. Key not found.")
    print("[!] Ensure that all 17 inputs belong strictly to the SAME reused public key address.")
    print("[!] Ensure your 'z' hashes were derived uniquely for each input index from the full raw hex.")
    return None


def get_words():
    wordsList = []
    if wordsList == []:
        content_string = ""
        
        with open("../report/CTUU-total-3.txt", "r") as f:
        # with open("./report/KP7b-total-2.txt", "r") as f:
            content_string = f.read()
        
        wordsList = content_string.split("\n")
        
    return wordsList

def get_t_u(sig):
    z, r, s = int(sig['z'], 16), int(sig['r'], 16), int(sig['s'], 16)
    s_inv = pow(s, -1, N)
    t_i = (r * s_inv) % N
    u_i = (z * s_inv) % N # Known prefix is 0
    return (t_i, u_i)

# =====================================================================
# LIVE DATA CONFIGURATION BLOCK
# =====================================================================
if __name__ == "__main__":
    result = []
    my_data = []
    totalCnt = 0
    # allHistory = get_full_history(address)
    # result, r_du, totalCnt = extract_rsz_data(allHistory, address)

    words = get_words()
    for word in words:
        if not word:
            continue
        result.append(json.loads(word))

    for res in result[11:28]:
        t, u = get_t_u(res)
        my_data.append((t, u))

    data = result[11:28]
    print(data[0]['vid'], ' ',data[-1]['vid'])
    


    
    # 1. PASTE YOUR 17 EXTRACTED DATA PAIRS HERE (From Index 0 up to Index 16)
    # Ensure they remain formatted as clean tuples: (t_constant, u_constant)
    # my_data = [
    #     (0x0, 0x0), # Input Index 0 -> Replace with real t and u hex values
    #     (0x0, 0x0), # Input Index 1
    #     (0x0, 0x0), # Input Index 2
    #     (0x0, 0x0), # Input Index 3
    #     (0x0, 0x0), # Input Index 4
    #     (0x0, 0x0), # Input Index 5
    #     (0x0, 0x0), # Input Index 6
    #     (0x0, 0x0), # Input Index 7
    #     (0x0, 0x0), # Input Index 8
    #     (0x0, 0x0), # Input Index 9
    #     (0x0, 0x0), # Input Index 10
    #     (0x0, 0x0), # Input Index 11
    #     (0x0, 0x0), # Input Index 12
    #     (0x0, 0x0), # Input Index 13
    #     (0x0, 0x0), # Input Index 14
    #     (0x0, 0x0), # Input Index 15
    #     (0x0, 0x0)  # Input Index 16
    # ]
    
    # 2. CRITICAL CONFIGURATION: Input your real target public key coordinates here
    # Strip away the leading '04' entirely from your real 130-character uncompressed public key.
    # The next 64 characters are the X coordinate, and the final 64 characters are the Y coordinate.
    PUBKEY_X_COORDINATE = "0ab0cc178d88300001d14ef832b1c5a33d2c75c4f27e2e4680cd51647d1983b5" 
    PUBKEY_Y_COORDINATE = "78df37e18b1910447220f337676eb7d85f39ab875f4a2dc6e7a482e27e4452e9" 
    
    if my_data[0] == (0x0, 0x0) or PUBKEY_X_COORDINATE == "PASTE_YOUR_ACTUAL_64_CHARACTER_X_COORDINATE_HERE":
        print("[!] Input Data Flag Missing: Edit this script file to insert your real constants.")
        sys.exit(1)
        
    # run_17_input_centered_lattice(my_data, PUBKEY_X_COORDINATE, PUBKEY_Y_COORDINATE)
    r = '6afea407b5f8c244fa1af04ee516a1c8688b3831e33e6a344e879812f5a256a0'
    s = '30d03e07954b6ddf5b00ac09268be977d7b286b62a63348bcd55e1df23794234'
    z = '3d91d50eef6bad18e306b8d1018c8cb7bcd6ed876697ce5d46b8c3809f6794c1' 
    d = '15'
    print(get_k(z,r,s,d))
