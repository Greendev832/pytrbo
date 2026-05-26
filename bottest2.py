from web3 import Web3
from eth_keys import keys
from eth_utils import keccak
import rlp

# Connection
RPC_URL = "https://Mainnet.infura.io/v3/70eacff3195c4af6af76fe8171529091"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def extract_params_type2(tx_hash):
    # 1. Fetch transaction
    tx = w3.eth.get_transaction(tx_hash)

    if tx.get('type') == 2 or tx.get('type') == '0x2':
        return {"type": 1}
    # 2. Extract Signature Components
    r_val = int(tx['r'].hex(), 16)
    s_val = int(tx['s'].hex(), 16)
    
    # Normalize v: Type 2 expects 0 or 1. 
    # If the provider returns 27 or 28, we subtract 27.
    v_val = tx['v']
    if v_val >= 27:
        v_val -= 27

    # 3. Reconstruct EIP-1559 Transaction Fields
    # Use bytes() for HexBytes and w3.to_bytes for addresses
    to_address = w3.to_bytes(hexstr=tx['to']) if tx['to'] else b''
    input_data = bytes(tx['input'])

    unsigned_fields = [
        tx['chainId'],
        tx['nonce'],
        tx['maxPriorityFeePerGas'],
        tx['maxFeePerGas'],
        tx['gas'],
        to_address,
        tx['value'],
        input_data,
        tx['accessList'] 
    ]

    # 4. Generate Message Hash (e)
    # The 0x02 prefix is mandatory for EIP-1559 (Type 2)
    encoded_payload = b'\x02' + rlp.encode(unsigned_fields)
    e_hash = keccak(encoded_payload)

    # 5. Recover Public Key (gx)
    signature = keys.Signature(vrs=(v_val, r_val, s_val))
    public_key = signature.recover_public_key_from_msg_hash(e_hash)

    # Extract gx (first 32 bytes of public key)
    gx = hex(int.from_bytes(public_key.to_bytes()[:32], 'big'))

    return {
        "gx": gx,
        "r": hex(r_val),
        "s": hex(s_val),
        "e": e_hash.hex(),
        "type": tx.get('type'),
        # "type": "EIP-1559 (Type 2)"
    }

# Example execution
# target_tx = "0xc2a713951e7762cc4498c5caef8fef4f0edb0fb19af78eacdc7fda8926dd68da"
# target_tx = "0x26018141258e3a4a321993bd8833016f3f6e94f2f4043aba32b9181a98a1cb2c"
# results = extract_params_type2(target_tx)

# print(f"Transaction Type: {results['type']}")
# print(f"gx: {results['gx']}")
# print(f"r: {results['r']}")
# print(f"s: {results['s']}")
# print(f"e: {results['e']}")