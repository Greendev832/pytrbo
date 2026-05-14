# SageMath script for ECDSA Private Key Recovery via LLL
from sage.all import *

# SECP256k1 Curve Order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_hnp_with_lll(sigs, bias_bits):
    """
    sigs: list of (e, r, s) tuples
    bias_bits: number of known zero bits at the start of the nonce k
    """
    num_sigs = len(sigs)
    
    # We build a matrix of size (m+2) x (m+2)
    # The bias defines the target range for the vector
    B = 2^(256 - bias_bits)
    
    # Create the Lattice Matrix
    matrix = Matrix(QQ, num_sigs + 2, num_sigs + 2)
    
    for i in range(num_sigs):
        e, r, s = sigs[i]
        # Relationship: k_i = (e + r*d) / s  mod N
        # Target: s*k_i - r*d = e  mod N
        t = (int(r, 16) * pow(int(s, 16), -1, N)) % N
        u = (int(e, 16) * pow(int(s, 16), -1, N)) % N
        
        matrix[i, i] = N
        matrix[num_sigs, i] = t
        matrix[num_sigs + 1, i] = u
        
    matrix[num_sigs, num_sigs] = B / N
    matrix[num_sigs + 1, num_sigs + 1] = B

    # Run LLL Algorithm
    print("[*] Running LLL reduction...")
    reduced_matrix = matrix.LLL()
    
    # Extract the private key from the reduced basis
    for row in reduced_matrix:
        potential_d = (row[num_sigs] * N / B) % N
        if potential_d != 0:
            return hex(int(potential_d))
    
    return None

# --- Usage Example ---
# sigs = [(e1, r1, s1), (e2, r2, s2), ... (en, rn, sn)]
# private_key = solve_hnp_with_lll(sigs, 8) 