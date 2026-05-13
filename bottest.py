from web3 import Web3
from eth_keys import keys
from eth_utils import keccak, to_bytes
import rlp

# 1. Setup Connection
# Note: Using your provided Infura URL
RPC_URL = "https://Mainnet.infura.io/v3/70eacff3195c4af6af76fe8171529091"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def extract_params(tx_hash):
    # 2. Get the Transaction details
    tx = w3.eth.get_transaction(tx_hash)
    
    # 3. Extract r, s, and v
    # Using .hex() on HexBytes and handling potential integer types
    r_val = tx['r'].hex()
    s_val = tx['s'].hex()
    v_val = tx['v']
    
    # 4. Reconstruct the Message Hash (e)
    # Different transaction types require different hashing structures
    
    # Handle EIP-1559 (Type 2) - Very common in May 2026
    if tx.get('type') == 2 or tx.get('type') == '0x2':
        unsigned_fields = [
            tx['chainId'],
            tx['nonce'],
            tx['maxPriorityFeePerGas'],
            tx['maxFeePerGas'],
            tx['gas'],
            to_bytes(hexstr=tx['to']) if tx['to'] else b'',
            tx['value'],
            tx['input'],
            [] # Access list
        ]
        # EIP-1559 requires a type prefix (0x02) before hashing
        encoded_raw = b'\x02' + rlp.encode(unsigned_fields)
        v_standard = v_val # In Type 2, v is already 0 or 1
        
    # Handle Legacy / EIP-155 (Type 0)
    else:
        chain_id = tx.get('chainId', 1)
        unsigned_fields = [
            tx['nonce'],
            tx['gasPrice'],
            tx['gas'],
            to_bytes(hexstr=tx['to']) if tx['to'] else b'',
            tx['value'],
            tx['input'],
            chain_id, 0, 0
        ]
        encoded_raw = rlp.encode(unsigned_fields)
        # Normalize V for Legacy
        if v_val >= 37:
            v_standard = (v_val - 35 - 2 * chain_id) % 2
        elif v_val in [27, 28]:
            v_standard = v_val - 27
        else:
            v_standard = v_val

    e_hash = keccak(encoded_raw)

    # 5. Recover Public Key
    try:
        signature = keys.Signature(vrs=(v_standard, int(r_val, 16), int(s_val, 16)))
        public_key = signature.recover_public_key_from_msg_hash(e_hash)
        
        # gx is the first 32 bytes (x-coord)
        gx = hex(int.from_bytes(public_key.to_bytes()[:32], 'big'))
        
        return {
            "gx": gx,
            "r": r_val,
            "s": s_val,
            "e": e_hash.hex(),
            "type": tx.get('type', 'Legacy')
        }
    except Exception as err:
        return {"error": str(err), "v_standard": v_standard}

# Example usage
target_hash = "0xc2a713951e7762cc4498c5caef8fef4f0edb0fb19af78eacdc7fda8926dd68da"
params = extract_params(target_hash)

if "error" in params:
    print(f"Error: {params['error']} (V-Standard calculated: {params.get('v_standard')})")
else:
    print(f"Transaction Type: {params['type']}")
    print(f"gx: {params['gx']}")
    print(f"r: {params['r']}")
    print(f"s: {params['s']}")
    print(f"e: {params['e']}")