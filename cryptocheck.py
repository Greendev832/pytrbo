from eth_account.messages import _hash_eip191_message
from eth_account import Account
from eth_utils import to_checksum_address, keccak
import requests
from web3 import Web3


def verify_z(z_int, r_int, s_int, v_int, tarAddress):
    # Replace with your first tuple's data
    z_bytes = z_int.to_bytes(32, 'big')
    # Note: For recoverHash, v MUST be 0, 1, 27, or 28
    # If your RPC gave you 37, use: v = 37 - (2 * chainId + 35)
    try:
        # 1. Ensure z_bytes is exactly 32 bytes
        # 2. Most 2026 libraries expect v to be 0, 1, 27, or 28
        recovered_addr = Account._recover_hash(z_bytes, vrs=(v_int, r_int, s_int))
        print(f"Recovered Address: {recovered_addr}")
        if recovered_addr.lower() == tarAddress.lower():
            return True
        return False
    except Exception as e:
        print(str(e))
        # Alternative for specific Web3.py v7 environments
        # Manually reconstruct the signature as a 65-byte hex string
        # signature = r (32) + s (32) + v (1)
        sig_hex = hex(r_int)[2:].zfill(64) + hex(s_int)[2:].zfill(64) + hex(v_int)[2:].zfill(2)
        recovered_addr = Account._recover_hash(z_bytes, signature=sig_hex)


def get_live_signatures(address):
    """Phase 1: Real-time Signature Harvesting"""
    ETHERSCAN_KEY = "CI3EABWI86DGFJ8PICBKRD6XSFQPPNMG3Z"
    # api = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=desc&apikey={CONFIG['ETHERSCAN_KEY']}"
    w3 = Web3(Web3.HTTPProvider('https://attentive-wispy-owl.quiknode.pro/1bd932de9bb976cfe86a9ecd58675fd575d6d9f1'))
    
    api = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={address}&sort=desc&apikey={ETHERSCAN_KEY}"
    txs = requests.get(api).json().get('result', [])

    rLists = {}
    zVerifiedCnt = 0
    sigs = []    
    print(len(txs))

    for tx_data in txs:
        tx = w3.eth.get_transaction(tx_data['hash'])
        if tx['from'].lower() == address.lower():
            print(tx_data['hash'])
            nonce = tx['nonce']
            if nonce not in rLists.keys():
                rLists[nonce] = 1
            else:
                rLists[nonce] +=1 
                print("found")
                return


def check_for_guardian(address):
    # We check for common Guardian implementation signatures
    # (e.g., ERC-4337 or Gnosis Safe modules)
    code = w3.eth.get_code(address).hex()
    
    if code == '0x':
        print("This is a standard EOA. No Guardian contract is active.")
        return False
    
    # Check for 'getGuardians' or 'isGuardian' function selectors
    # 0x47cc0364 is a common 'getGuardians' selector
    if "47cc0364" in code:
        print("!!! Guardian Contract Detected !!!")
        # You can now query the contract to see WHO the guardians are
        return True
    return False

def main():
    verify_z(48333156036955130009426611177018940389265082121994774383175722037397674612490, 12546732647094510677632207048210978426257670358699086187669203276350606214254, 25096162647676615178305257222335981281631480687385349420646519278073842821108, 1, "0xf584F8728B874a6a5c7A8d4d387C9aae9172D621")
    # get_live_signatures("0x264bd8291fAE1D75DB2c5F573b07faA6715997B5")

main()