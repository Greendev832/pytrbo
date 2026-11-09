def compress_pubkey(pubkey_str: str) -> str:
    # 1. Clean string (strip whitespace/0x prefix)
    s = pubkey_str.strip().lower()
    if s.startswith("0x"):
        s = s[2:]

    # 2. Extract X (chars 2 to 66) and the very last char of Y
    x_hex = s[2:66]
    last_char = s[-1]

    # 3. If last hex char is even -> '02', if odd -> '03'
    prefix = "02" if last_char in "02468ace" else "03"

    return prefix + x_hex


# --- Example usage ---
uncompressed_str = "0498fc8809ab38b853f54ade5a5a0d4a41245707644eb921c9d4af244a67d75d60cee9f2eed075afb16cba9f94f239b10ffe041ef9ebd81f15ba9863dc6b19826c"

compressed_str = compress_pubkey(uncompressed_str)

print("Result:", compressed_str)
# Output: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798