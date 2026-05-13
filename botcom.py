from eth_utils import decode_hex

# SECP256k1 Curve Order (n)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def solve_bot_key(e1_hex, s1_hex, e2_hex, s2_hex, r_hex):
    # Convert hex to integers
    e1 = int(e1_hex, 16)
    s1 = int(s1_hex, 16)
    e2 = int(e2_hex, 16)
    s2 = int(s2_hex, 16)
    r = int(r_hex, 16)

    # 1. Calculate the shared nonce (k)
    # k = (e1 - e2) / (s1 - s2) % N
    numerator = (e1 - e2) % N
    denominator = pow(s1 - s2, -1, N) # Modular inverse
    k = (numerator * denominator) % N

    # 2. Calculate the Private Key (d)
    # d = ((s * k) - e) / r % N
    # We can use either (e1, s1) or (e2, s2)
    d = (((s1 * k) - e1) * pow(r, -1, N)) % N

    return hex(d)

# Example data from your previous extraction:
tx1 = {
    "e": "0x...", # Message hash of Tx 1
    "s": "0x...", # S value of Tx 1
}
tx2 = {
    "e": "0x...", # Message hash of Tx 2
    "s": "0x...", # S value of Tx 2
}
shared_r = "0x..." # The R value that was the same in both

pri = solve_bot_key(tx1['e'], tx1['s'], tx2['e'], tx2['s'], shared_r)
print(f"Successfully recovered Bot PRI Key: {pri}")
with open("2.txt", "a") as file:
    file.write(pri+"\n")