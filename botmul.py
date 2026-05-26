from sage.all import *

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_hnp_with_lll(sigs, bias_bits):
    """
    sigs: list of (e, r, s) tuples
    bias_bits: number of known zero bits at the start of the nonce k
    """
    num_sigs = len(sigs)
    
    B = 2^(256 - bias_bits)
    
    matrix = Matrix(QQ, num_sigs + 2, num_sigs + 2)
    
    for i in range(num_sigs):
        e, r, s = sigs[i]
        t = (int(r, 16) * pow(int(s, 16), -1, N)) % N
        u = (int(e, 16) * pow(int(s, 16), -1, N)) % N
        
        matrix[i, i] = N
        matrix[num_sigs, i] = t
        matrix[num_sigs + 1, i] = u
        
    matrix[num_sigs, num_sigs] = B / N
    matrix[num_sigs + 1, num_sigs + 1] = B

    print("[*] Running LLL reduction...")
    reduced_matrix = matrix.LLL()
    
    for row in reduced_matrix:
        potential_d = (row[num_sigs] * N / B) % N
        if potential_d != 0:
            return hex(int(potential_d))
    
    return None
