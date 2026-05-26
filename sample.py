# Tuesday, May 19, 2026 | 03:09 AM - Nonce Reuse Check
def check_for_nonce_reuse(sigs):
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # Look for any two signatures with the same 'r'
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            r1, s1, h1 = sigs[i]
            r2, s2, h2 = sigs[j]
            
            if r1 == r2 and s1 != s2:
                print(f"!!! NONCE REUSE DETECTED !!!")
                # Algebra: x = (h1*s2 - h2*s1) / (r*(s1 - s2))
                num = (h1 * s2 - h2 * s1) % n
                den = (r1 * (s1 - s2)) % n
                potential_key = (num * pow(den, -1, n)) % n
                return hex(potential_key)
    return None