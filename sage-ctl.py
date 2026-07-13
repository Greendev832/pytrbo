import hashlib
import ecdsa
import base58
import bech32
import os
import customset

def number_to_bitcoin_address(n):
    # 1. Private Key: Convert number to 32-byte hex
    private_key_bytes = n.to_bytes(32, byteorder='big')
    
    # 2. Public Key: Generate using secp256k1 curve
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    # Use uncompressed format (0x04 prefix)
    public_key = b'\x04' + vk.to_string()
    
    # 3. Hashing: SHA-256 followed by RIPEMD-160 (HASH160)
    sha256_pub = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed_pub = ripemd160.digest()
    
    # 4. Add Network Byte: 0x00 for Mainnet
    network_byte = b'\x00' + hashed_pub
    
    # 5. Checksum: Double SHA-256, take first 4 bytes
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    
    # 6. Base58 Check Encoding
    binary_address = network_byte + checksum
    bitcoin_address = base58.b58encode(binary_address)
    
    return bitcoin_address.decode('utf-8')

def number_to_segwit_address(n):
    # 1. Private Key: Convert number to 32-byte hex
    private_key_bytes = n.to_bytes(32, byteorder='big')
    
    # 2. Public Key: Generate using secp256k1 (COMPRESSED)
    # Modern wallets use compressed keys (33 bytes) starting with 0x02 or 0x03
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key_bytes = vk.to_string()
    
    # Determine prefix (0x02 for even Y, 0x03 for odd Y)
    if public_key_bytes[-1] % 2 == 0:
        compressed_pubkey = b'\x02' + public_key_bytes[:32]
    else:
        compressed_pubkey = b'\x03' + public_key_bytes[:32]
        
    # 3. HASH160: SHA-256 followed by RIPEMD-160
    sha256_pub = hashlib.sha256(compressed_pubkey).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    witness_program = ripemd160.digest()
    
    # 4. Bech32 Encoding: bc1q + encoded witness program
    # 0 is the witness version
    five_bit_words = bech32.convertbits(witness_program, 8, 5)
    modern_address = bech32.bech32_encode('bc', [0] + five_bit_words)
    
    return modern_address

def generate_modern_bitcoin(n):
    # 1. Private Key (32-byte hex)
    pk_bytes = n.to_bytes(32, byteorder='big')
    
    # 2. WIF (Modern/Compressed) - Use this to import into wallets
    prefix_pk = b'\x80' + pk_bytes + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(prefix_pk).digest()).digest()[:4]
    wif = base58.b58encode(prefix_pk + checksum).decode('utf-8')

    # 3. Compressed Public Key
    sk = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_bytes = vk.to_string()
    compressed_pub = (b'\x02' if pub_bytes[-1] % 2 == 0 else b'\x03') + pub_bytes[:32]

    # 4. Modern Address (Bech32 / SegWit)
    sha256_pub = hashlib.sha256(compressed_pub).digest()
    h160 = hashlib.new('ripemd160', sha256_pub).digest()
    bech32_addr = bech32.bech32_encode('bc', [0] + bech32.convertbits(h160, 8, 5))

    print(f"Number:         {n}")
    print(f"Private Key:    {pk_bytes.hex()}")
    print(f"WIF (to import): {wif}")
    print(f"Modern Address: {bech32_addr}")

def generate_2012_uncompressed_suite(n):
    # 1. Private Key (Raw Hex)
    pk_bytes = n.to_bytes(32, byteorder='big')
    pk_hex = pk_bytes.hex()
    
    # 2. Uncompressed WIF (Private Key for Importing)
    # Format: [Network Byte 0x80] + [32-byte Private Key]
    # NOTE: There is NO 0x01 suffix for uncompressed keys.
    vh = b'\x80' + pk_bytes
    checksum = hashlib.sha256(hashlib.sha256(vh).digest()).digest()[:4]
    wif = base58.b58encode(vh + checksum).decode('utf-8')

    # 3. Uncompressed Public Key (Starting with 04)
    sk = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pubkey = b'\x04' + vk.to_string()

    # 4. Legacy Address (Starting with 1)
    sha_pub = hashlib.sha256(pubkey).digest()
    h160 = hashlib.new('ripemd160', sha_pub).digest()
    addr_vh = b'\x00' + h160
    addr_checksum = hashlib.sha256(hashlib.sha256(addr_vh).digest()).digest()[:4]
    address = base58.b58encode(addr_vh + addr_checksum).decode('utf-8')

    print(f"--- 2012 UNCOMPRESSED DATA (Number: {n}) ---")
    print(f"Private Key (Hex):   {pk_hex}")
    print(f"WIF (starts with 5): {wif}")
    print(f"Public Key (starts with 04):")
    print(f"{pubkey.hex()}")
    print(f"Legacy Address (starts with 1): {address}")
    print("-" * 45)
    return pk_hex, wif, pubkey.hex(), address



if __name__ == "__main__":
    # Example: Generate address from the number 1
    my_number = 123456333
    temp = 0
    customset.set_num(my_number)
    my_number = customset.get_num()
    # print(f"Number: {my_number}")
    print(f"Bitcoin Address: {number_to_bitcoin_address(my_number)}")
    print(f"Bitcoin Address: {number_to_segwit_address(my_number)}")
    generate_modern_bitcoin(my_number)
    pkey, owif, opub, oaddr = generate_2012_uncompressed_suite(my_number)
    # customset.setK(owif)
    print(owif)
    print(opub)
    print(oaddr)