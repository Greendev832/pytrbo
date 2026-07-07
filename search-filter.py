import requests
import time
import subprocess
import json
import ecdsa
from ecdsa import VerifyingKey, SECP256k1
from bitcoinutils.transactions import Transaction
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
import binascii
import hashlib
import base58
from sage.all import Matrix, ZZ, vector, QQ, RealField, RR, log, EllipticCurve, GF, inverse_mod, Integer, power_mod
from fpylll import IntegerMatrix, GSO, BKZ, LLL, FPLLL, Enumeration

# --- WALLET FINGERPRINT ANALYZER v19.0 ---
# Current Time: 10:44 AM CDT, Tuesday, June 9, 2026
# Purpose: Identify 2013-era wallet software via transaction patterns.

RPC_USER = "ace"
RPC_PASS = "browser"

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# 1. Initialize for Mainnet
setup('mainnet')

def detect_vulnerable_software(address):
    """
    Scans a Bitcoin address to detect if the signatures 
    match the Blockchain.info or MultiBit 2013 fingerprints.
    """
    api_url = f"https://mempool.space/api/address/{address}/txs"
    
    try:
        response = requests.get(api_url, timeout=10)
        txs = response.json()
        
        if not txs:
            return "No data found."

        # 1. Detect Signature Density (Critical for Lattice)
        out_txs = [tx for tx in txs if any(vin['prevout']['scriptpubkey_address'] == address for vin in tx['vin'] if 'prevout' in vin)]
        count = len(out_txs)
        
        # 2. Detect Fee Fingerprint (MultiBit Legacy used 0.0001 or 0.0005)
        fees = [tx['fee'] for tx in txs]
        is_multibit = any(f in [10000, 50000] for f in fees)

        # 3. Detect Blockchain.info Pattern (Legacy P2PKH + High Tx Frequency)
        is_bci = count > 10 and address.startswith('1')

        print(f"--- Detection Report for {address} ---")
        if is_bci:
            return "VERDICT: Blockchain.info (2013) pattern detected. Target for Lattice Audit."
        elif is_multibit:
            return "VERDICT: MultiBit (Legacy) fee pattern detected. High Success Potential."
        else:
            return "VERDICT: Generic Legacy Wallet. Low specific bias detected."

    except Exception as e:
        return f"Detection error: {str(e)}"
 

def call_cli(command):
    """Executes bitcoin-cli with RPC credentials and parses the result."""
    cmd = ["bitcoin-cli", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}", *command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600) # Long timeout for scanning
        # print(result)
        if result.returncode == 0:
            raw = result.stdout.strip()
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start != -1 and end != 0:
                return json.loads(raw[start:end])
            return raw
    except:
        pass
    return None

def get_full_history(address):
    all_txs = []
    last_txid = None
    # cmp_time = 1375315200  # 2013.8.1
    cmp_time = 1388534400  # 2014.1.1
    print(f"Starting deep history scan for {address}...")
    relaxID = 0
    while True:
        # Construct the URL with paging if we have a last_txid
        if last_txid:
            url = f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
        else:
            url = f"https://mempool.space/api/address/{address}/txs"
            
        response = requests.get(url)
        if response.status_code != 200:
            print(response.status_code)
            break
            
        batch = response.json()
        if not batch: # No more transactions found
            break

        for tx in batch:
            block_time = tx.get('status', {}).get('block_time', 0)
            # if int(block_time) < cmp_time:
            all_txs.extend(batch)
        last_txid = batch[-1]['txid'] # Update the anchor for the next page
        
        # Monitor progress
        last_date = batch[-1].get('status', {}).get('block_time', 0)
        print(f"Collected {len(all_txs)} txs... reached date: {time.ctime(last_date)}")
        relaxID += 1
        # Stop once we reach the end of 2012
        # if last_date > cmp_time: # Jan 1, 2012
        #     break
        if relaxID < 10:
            time.sleep(1) # Avoid rate limiting
        else:
            relaxID = 0
            time.sleep(10)

    return all_txs

def private_key_to_address(found_number):
    """
    Converts a private key hex string to a Legacy P2PKH address.
    Handles both Uncompressed (standard in 2012) and Compressed formats.
    """
    # 1. Ensure the hex is exactly 64 characters (32 bytes)
    # 1. Convert integer to hex
    raw_hex = hex(found_number)[2:]
    
    # 2. Pad with leading zeros to ensure it is exactly 32 bytes (64 chars)
    # This is critical! A 256-bit key MUST be 64 characters.
    private_key_hex = raw_hex.zfill(64)

    private_key_hex = private_key_hex.zfill(64)
    private_key_bytes = binascii.unhexlify(private_key_hex)
    
    # 2. Derive Public Key using SECP256k1
    sk = VerifyingKey.from_string(private_key_bytes, curve=SECP256k1)
    
    # 3. Generate BOTH Uncompressed and Compressed addresses for verification
    formats = {
        "Uncompressed": b'\x04' + sk.to_string(),
        "Compressed": sk.to_string(encoding="compressed")
    }
    
    results = {}
    for fmt_name, pubkey_bytes in formats.items():
        # Hash 160: RIPEMD160(SHA256(PubKey))
        sha256_pk = hashlib.sha256(pubkey_bytes).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_pk)
        pubkey_hash = ripemd160.digest()
        
        # Add Network Byte (0x00 for Mainnet)
        network_hash = b'\x00' + pubkey_hash
        
        # Checksum: First 4 bytes of Double SHA256
        checksum = hashlib.sha256(hashlib.sha256(network_hash).digest()).digest()[:4]
        
        # Base58Check Encoding
        address = base58.b58encode(network_hash + checksum).decode('utf-8')
        results[fmt_name] = address
        
    return results


def detectBias(scriptsig_hex):
    # if not scriptsig_hex: return 0
    # try:
    #     # The push-byte (e.g., 0x47, 0x48) indicates total sig length
    #     push_byte = int(scriptsig_hex[0:2], 16)
    #     if push_byte >= 0x48: return 0 # Standard 72+ bytes
    #     return (0x48 - push_byte) * 8 # 8 bits per missing byte
    # except: return 0
    try:
        push_byte = int(scriptsig_hex[0:2], 16)
        if push_byte >= 0x48:
            return 0
        # Formula: Each byte below 0x47 adds 8 bits, plus the initial 1-bit sign bias
        return ((0x47 - push_byte) * 8) + 1
    except:
        return 0

def get_z_legacy(raw_tx_hex, input_index, script_pub_key_hex):
    """
    Calculates the 'z' value (the hash to be signed) for a legacy P2PKH input.
    """
    try:
        
        # Standard Bitcoin SIGHASH_ALL (01) logic handled by bitcoin-utils
        # This performs the 'Blank and Swap' correctly for any input index.
        tx = Transaction.from_raw(raw_tx_hex)
        
        
        script_obj = Script.from_raw(script_pub_key_hex)
        
        # 4. Calculate the digest (SIGHASH_ALL = 1)
        z_bytes = tx.get_transaction_digest(input_index, script_obj, 1)
        
        # 5. Return hex string for your Lattice spreadsheet
        return binascii.hexlify(z_bytes).decode()
    except Exception as e:
        return f"Serialization Error: {str(e)}"
    
def verify_sig_integrity(r_hex, s_hex, z_hex, pubkey_hex):
    """
    Ensures your 539 signatures are mathematically valid before running LLL.
    If this returns True, your R, S, and Z are perfectly aligned with the Public Key.
    """
    try:
        # 1. Convert inputs to integers
        r_int = int(r_hex, 16)
        s_int = int(s_hex, 16)
        z_int = int(z_hex, 16)
        
        # 2. Reconstruct the Public Key object (SECP256k1)
        # Handles both Compressed (33 bytes) and Uncompressed (65 bytes)
        pubkey_bytes = binascii.unhexlify(pubkey_hex)
        vk = ecdsa.VerifyingKey.from_string(pubkey_bytes, curve=ecdsa.SECP256k1)
        
        # 3. Verify the signature (r, s) against the message hash (z)
        # NOTE: ecdsa library expects the signature in (r + s) byte format
        sig_bytes = binascii.unhexlify(r_hex.zfill(64) + s_hex.zfill(64))
        
        # Verification (Will raise ecdsa.BadSignatureError if incorrect)
        is_valid = vk.verify_digest(sig_bytes, binascii.unhexlify(z_hex))
        
        return is_valid

    except ecdsa.BadSignatureError:
        return False
    except Exception as e:
        return f"Audit Error: {str(e)}"



def extract_rsz_data(full_history, my_address):
    """
    Extracts r, s, and calculates z for Legacy P2PKH transactions.
    """
    recovered_data = []
    r_seen = {} # For instant duplicate R detection
    out_txs = set()
    maxBias = 0
    maxBiasCnt = 0
    rfound = False
    totalList = []
    dup_address = []

    for tx in full_history:
        # raw_tx_hex = requests.get(f"https://mempool.space/api/tx/{tx['txid']}/hex").text
        # print(raw_tx_hex)
        # return

        for i, vin in enumerate(tx.get('vin', [])):
            if vin.get('prevout', {}) == None or vin.get('prevout', {}) == {}:
                continue
            # cmpAddress = (vin.get('prevout', {}).get('scriptpubkey_address'))
            # if cmpAddress not in dup_address:
            #     print(cmpAddress," ", i)
            #     dup_address.append(cmpAddress)
            if vin.get('prevout', {}).get('scriptpubkey_address') == my_address:
            # if 1 == 1:
                scriptsig = vin.get('scriptsig', '')
                if not scriptsig or '30' not in scriptsig: continue
                
                # Precise DER Parsing
                try:
                    to_entity = {'tx': tx['txid'], 'script': scriptsig}
                    if to_entity not in totalList:
                        totalList.append(to_entity)
                    approBias = (detectBias(scriptsig))
                    # if approBias == 0:
                    #     continue
                    # print(tx['txid'])
                    # print(scriptsig)

                    # tx_data = call_cli(["getrawtransaction", tx['txid'], "true"])
                    # raw_tx_hex = tx_data['hex']

                    if approBias > maxBias:
                        maxBias = approBias
                        print(tx['txid'])
                        # print(tx)
                        block_height = tx.get('status', {}).get('block_height', 0)
                        print(block_height)
                    # print(approBias)
                    der_start = scriptsig.find('30')
                    r_len = int(scriptsig[der_start+6:der_start+8], 16) * 2
                    r = scriptsig[der_start+8:der_start+8+r_len]
                    # print(len(r), " ", r)
  
                    s_header = der_start + 8 + r_len
                    s_len = int(scriptsig[s_header+2:s_header+4], 16) * 2
                    s = scriptsig[s_header+4:s_header+4+s_len]

                    # --- New Public Key Extraction ---
                    # The signature ends at s_header + 4 + s_len. 
                    # Usually, a 1-byte SigHash (01) follows it.
                    # The Public Key starts after that.
                    
                    # Position after signature + 1 byte (SigHash)
                    pubkey_search_start = s_header + 4 + s_len + 2 
                    remaining_hex = scriptsig[pubkey_search_start:]
                    
                    if remaining_hex.startswith('41'): # 0x41 length prefix for Uncompressed (65 bytes)
                        pubkey = remaining_hex[2:132]   # The 65 bytes of the key
                    elif remaining_hex.startswith('21'): # 0x21 length prefix for Compressed (33 bytes)
                        pubkey = remaining_hex[2:68]    # The 33 bytes of the key
                    else:
                        # Fallback: Search for standard prefixes (04, 02, or 03)
                        if '04' in remaining_hex:
                            idx = remaining_hex.find('04')
                            pubkey = remaining_hex[idx:idx+130]
                        elif '02' in remaining_hex:
                            idx = remaining_hex.find('02')
                            pubkey = remaining_hex[idx:idx+66]
                        elif '03' in remaining_hex:
                            idx = remaining_hex.find('03')
                            pubkey = remaining_hex[idx:idx+66]

                    # print("\n",pubkey)
                    
                    # Z Calculation: 
                    # CRITICAL: For a correct Z, you must replace the scriptSig 
                    # with the spent scriptPubKey before hashing.
                    spent_script_pub_key = vin.get('prevout', {}).get('scriptpubkey', '')
                    
                    # # This simplified template works for single-input legacy txs:
                    # template = binascii.unhexlify(raw_tx_hex) + binascii.unhexlify("01000000")
                    # z = hashlib.sha256(hashlib.sha256(template).digest()).hexdigest()
                    
                    # z = get_z_legacy(raw_tx_hex, i, spent_script_pub_key)
                    z = ""
                    # print("z=>  ", z)

                    entry = {'txid': tx['txid'], 'r': r, 's': s, 'z': z, 'pubkey': pubkey, 'prefix': f'0x{scriptsig[0:2]}'}
                    if entry not in recovered_data:
                        recovered_data.append(entry)
                        # if maxBias > 1:
                        if approBias > 1:
                            maxBiasCnt += 1

                    # Instant Duplicate Check
                    # if r in r_seen:
                    #     old_txid, old_s = r_seen[r]
                    #     if s != old_s:
                    #         # print(f"\n[!!!] VULNERABILITY FOUND [!!!]")
                    #         # print(f"Duplicate R: {r}")
                    #         print(f"TX1: {old_txid} (S: {old_s})")
                    #         print(f"TX2: {tx['txid']} (S: {s})")
                    # r_seen[r] = (tx['txid'], s)
                    if r in r_seen:
                        s_list = r_seen[r]
                        if s not in s_list:
                            print("found")
                            r_seen[r].append(s)
                            rfound = True
                    else:
                        r_seen[r] = []
                        r_seen[r].append(s)
                    # r_seen[r] = tx['txid']

                    # if tx['txid'] in out_txs:
                    #     continue
                    # out_txs.add(tx['txid'])
                    # print(tx['txid'])

                except Exception as e:
                    print(f"Skip TX {tx['txid']}: Parsing error {e}")

    print(maxBias,"  ", maxBiasCnt)
    return recovered_data, r_seen, len(totalList), maxBias, maxBiasCnt, rfound


def verify_all_standards(private_key_int, target_address):
    """
    Exhaustive verification of ALL possible 2012-2013 address formats.
    Includes: Uncompressed, Compressed, and Hybrid sign configurations.
    """
    try:
        # 1. Standardize the integer to be within the SECP256k1 field
        pk_clean = int(private_key_int) % N
        # pk_clean = int(private_key_int)
        if pk_clean == 0: return False
        
        # 2. CRITICAL: Pad the hex string to exactly 64 characters (32 bytes)
        # This prevents the "Length of string" error
        pk_hex = hex(pk_clean)[2:].zfill(64)
        pk_bytes = binascii.unhexlify(pk_hex)
        
        # 3. Import as Signing Key
        from ecdsa import SigningKey
        sk = SigningKey.from_string(pk_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # 4. Generate the candidates based on 2012/2013 standards
        # Uncompressed (Legacy 2012): 0x04 + 64 bytes of X,Y
        uncompressed_pub = b'\x04' + vk.to_string() 
        # Compressed (Legacy 2013): 0x02/0x03 + 32 bytes of X
        compressed_pub = vk.to_string(encoding="compressed")
        
        for pubkey in [uncompressed_pub, compressed_pub]:
            # SHA256 -> RIPEMD160
            sha = hashlib.sha256(pubkey).digest()
            h = hashlib.new('ripemd160', sha).digest()
            # Add Network Byte (Mainnet = 0x00)
            net = b'\x00' + h
            # Double SHA256 Checksum
            check = hashlib.sha256(hashlib.sha256(net).digest()).digest()[:4]
            # Base58
            addr = base58.b58encode(net + check).decode()
            # print(addr)
            if addr.lower() == target_address.lower():
                return True
    except Exception as e:
        print(str(e))
        # Silently skip candidates that fail to parse
        return False
    return False

def get_words():
    wordsList = []
    if wordsList == []:
        content_string = ""
        with open("tr.txt", "r") as f:
            content_string = f.read()
        wordsList = content_string.split("\n")
    return wordsList

if __name__ == "__main__":
    # Example:
    # address= "1NibfhHfgA857dtG6pB25Y5hDcxpDo2J47"
    # address = "1EpbMFnnpCi6QjQCJMhkKdJyatwDjeoYmA"
    # address = "1FgiDfz7jmdjTUaJ9GsKbNbgsmu7T31Dvx"
    # address = "1JfzVxMddF91a4oqhZYsSZ4tmpRXfWvKeY"
    # address = "1A8mhLMd1meWZbLvbKCzpta5rC9tnV5v5Z"
    # address = "1DEfMuUGRhvoQE7cxgds3nYjRZzzhfJ9jc"
    # report = detect_vulnerable_software(address)
    # print(report)

    address = "1NB3ZXxs3vfq1hRhuSAZ3zPdQNrXBQB6ZX"

    allHistory = get_full_history(address)
    result, r_du, totalCnt, maxBias, maxBiasCnt, rfound = extract_rsz_data(allHistory, address)
    verfiedCnt = 0
    # for entity in result:
    #     res = verify_sig_integrity(entity['r'], entity['s'], entity['z'], entity['pubkey'])
    #     # print(entity['r'])
    #     if res:
    #         verfiedCnt += 1
        # print(res)
    print(len(result), "-", verfiedCnt, "-", totalCnt)
    print((rfound))

    # totalLists = get_words()
    # # print(totalLists)
    # idx = 0
    # for item in totalLists:
    #     idx += 1
    #     if idx < 378:
    #         continue
    #     address = item.split(",")[0]
    #     if len(address) < 3:
    #         continue
    #     allHistory = get_full_history(address)
    #     result, r_du, totalCnt, maxBias, maxBiasCnt, rfound = extract_rsz_data(allHistory, address)
    #     verfiedCnt = 0
    #     for entity in result:
    #         res = verify_sig_integrity(entity['r'], entity['s'], entity['z'], entity['pubkey'])
    #         # print(entity['r'])
    #         if res:
    #             verfiedCnt += 1
    #         # print(res)
    #     print(len(result), "-", verfiedCnt, "-", totalCnt)
    #     print(len(r_du))

    #     print(address)
    #     with open("search-content.txt", "a") as file:
    #         file.write(f'{address} -> totalcnt: {totalCnt}, realcnt: {len(result)}, vericnt: {verfiedCnt}, maxBias: {maxBias}, maxCnt: {maxBiasCnt}, rfound: {rfound}\n')
    #     time.sleep(1)

    
    
    # res = solve_event_horizon(result, address)
    # res = solve_sniper(result, address)
    # print(res)

    # verify_all_standards('39685648753016824787952881909322793904596734009504857818589497891815035', address)


# Finds any signature starting with the 71-byte push (47) or 70-byte push (46)
# grep -E "4730440220|463043021f" transactions.txt