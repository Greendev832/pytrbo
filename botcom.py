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
    "e": "1bed1ee683857338849300118556c82ac69273444411c401ee152afbb5f06041", # Message hash of Tx 1
    "s": "0x75ca6c77c594fb1ee76bd44c9c8492018f93320c95e0c49a5fe8aee047fa0097", # S value of Tx 1
}
tx2 = {
    "e": "acccc3d776a34cc0d5dcfcb2cbbb3c56b9ab3da4f3244387f52324f198315657", # Message hash of Tx 2
    "s": "0x31206512f26ee8737760c765ece0e2c76597e5d9c4b35b2d4283426b0ebd365b", # S value of Tx 2
}
shared_r = "0x6196a9d338caee0f355bad480197586f67440896628bb02f733b2eee81b22625" # The R value that was the same in both

pri = solve_bot_key(tx1['e'], tx1['s'], tx2['e'], tx2['s'], shared_r)

with open("2.txt", "a") as file:
    file.write(pri+"\n")