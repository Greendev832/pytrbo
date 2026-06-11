import requests
import time
import subprocess
import json
import ecdsa
from bitcoinutils.transactions import Transaction
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
import binascii

# --- WALLET FINGERPRINT ANALYZER v19.0 ---
# Current Time: 10:44 AM CDT, Tuesday, June 9, 2026
# Purpose: Identify 2013-era wallet software via transaction patterns.

RPC_USER = "ace"
RPC_PASS = "browser"

def analyze_wallet_fingerprint(address):
    """
    Analyzes transaction patterns to identify likely 2013-era wallet software.
    Checks for fee structures, change address logic, and signature types.
    """
    api_url = f"https://mempool.space/api/address/{address}/txs"
    
    try:
        response = requests.get(api_url, timeout=10)
        txs = response.json()
        
        if not txs:
            return "No transactions found for this address."

        # Analysis Metrics
        avg_fee = sum(tx['fee'] for tx in txs) / len(txs)
        has_multisig = any('p2sh' in tx.get('status', {}) for tx in txs)
        
        print(f"--- 2013 Fingerprint Report: {address} ---")
        print(f"Average Fee: {avg_fee} sat")

        # Identification Logic (Historical 2013 Behavioral Profiles)
        if avg_fee == 10000 or avg_fee == 50000:
            software = "MultiBit (Legacy) - Highly likely based on fixed fee."
        elif len(txs) > 1 and any(len(tx['vout']) > 2 for tx in txs):
            software = "Bitcoin Core (Bitcoin-Qt) - Complex change logic detected."
        elif has_multisig:
            software = "Early Armory or Shared Wallet Service."
        else:
            software = "Blockchain.info (Web/Mobile) or generic script."

        return {
            "address": address,
            "likely_software": software,
            "audit_priority": "High" if "MultiBit" in software or "Blockchain.info" in software else "Medium"
        }

    except Exception as e:
        return f"Scan failed: {str(e)}"

def detect_bit_bias(address):
    """
    Upgraded auditor that looks for actual mathematical bias (Leading Zeros)
    in signature R-values, identifying 2013-era RNG flaws.
    """
    api_url = f"https://mempool.space/api/address/{address}/txs"
    
    try:
        response = requests.get(api_url, timeout=10)
        txs = response.json()
        
        bias_hits = 0
        total_sigs = 0
        
        print(f"--- Mathematical Audit: {address} ---")

        for tx in txs:
            for vin in tx.get('vin', []):
                # Analyze signatures from the target address
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    scriptsig = vin.get('scriptsig', '')
                    
                    # 2026 AUDIT LOGIC: Extract R-value from DER signature
                    # DER format usually: 304[len]02[r_len][r_value]...
                    if len(scriptsig) > 70 and scriptsig.startswith('30'):
                        total_sigs += 1
                        # The R-value starts after the '02' tag (usually at index 8)
                        r_value = scriptsig[8:72]
                        
                        # CHECK FOR MSB BIAS (The Android Bug Fingerprint)
                        # If the first byte is '00', it's an 8-bit bias.
                        if r_value.startswith('00'):
                            bias_hits += 1
        
        if total_sigs == 0: return "No outgoing signatures found."

        bias_ratio = (bias_hits / total_sigs) * 100
        
        # VERDICT ENGINE
        print(f"Signatures Audited: {total_sigs}")
        print(f"Biased 'R' Detected: {bias_hits} ({bias_ratio:.2f}%)")

        if bias_ratio > 10:
            return "VERDICT: CONFIRMED BIT-BIAS. Highly vulnerable to Lattice Attack (LLL)."
        elif total_sigs > 50:
            return "VERDICT: STATISTICALLY SAFE. Nonces appear sufficiently random."
        else:
            return "VERDICT: INSUFFICIENT DATA. Need more signatures for confidence."

    except Exception as e:
        return f"Audit failed: {str(e)}"

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
    

def detect_bit_bias(address):
    """
    Upgraded auditor that looks for actual mathematical bias (Leading Zeros)
    in signature R-values, identifying 2013-era RNG flaws.
    """
    api_url = f"https://mempool.space/api/address/{address}/txs"
    
    try:
        response = requests.get(api_url, timeout=10)
        txs = response.json()
        
        bias_hits = 0
        total_sigs = 0
        
        print(f"--- Mathematical Audit: {address} ---")

        for tx in txs:
            for vin in tx.get('vin', []):
                # Analyze signatures from the target address
                if vin.get('prevout', {}).get('scriptpubkey_address') == address:
                    scriptsig = vin.get('scriptsig', '')
                    
                    # 2026 AUDIT LOGIC: Extract R-value from DER signature
                    # DER format usually: 304[len]02[r_len][r_value]...
                    if len(scriptsig) > 70 and scriptsig.startswith('30'):
                        total_sigs += 1
                        # The R-value starts after the '02' tag (usually at index 8)
                        r_value = scriptsig[8:72]
                        
                        # CHECK FOR MSB BIAS (The Android Bug Fingerprint)
                        # If the first byte is '00', it's an 8-bit bias.
                        if r_value.startswith('00'):
                            bias_hits += 1
        
        if total_sigs == 0: return "No outgoing signatures found."

        bias_ratio = (bias_hits / total_sigs) * 100
        
        # VERDICT ENGINE
        print(f"Signatures Audited: {total_sigs}")
        print(f"Biased 'R' Detected: {bias_hits} ({bias_ratio:.2f}%)")

        if bias_ratio > 10:
            return "VERDICT: CONFIRMED BIT-BIAS. Highly vulnerable to Lattice Attack (LLL)."
        elif total_sigs > 50:
            return "VERDICT: STATISTICALLY SAFE. Nonces appear sufficiently random."
        else:
            return "VERDICT: INSUFFICIENT DATA. Need more signatures for confidence."

    except Exception as e:
        return f"Audit failed: {str(e)}"
    

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

def audit_address_via_scan(address):
    """
    Finds and audits transactions for an address NOT in your local wallet.
    Requires -txindex=1 to be enabled.
    """
    print(f"--- External Private Audit: {address} ---")
    
    # 1. Use scantxoutset to find the active UTXOs for this external address
    print("Scanning UTXO set (Step 1 of 2)...")
    scan = call_cli(["scantxoutset", "start", f'["addr({address})"]'])
    
    if not scan or not scan.get('unspents'):
        return "ERROR: No active UTXOs found. If this address is fully spent, historical audit requires a custom index (like Bitcoin Knots)."

    txids = [utxo['txid'] for utxo in scan['unspents']]
    hits = 0
    total = 0

    # 2. Extract signatures from the found transactions
    for txid in txids:
        tx_data = call_cli(["getrawtransaction", txid, "true"])
        if not tx_data: continue

        for vin in tx_data.get('vin', []):
            scriptsig = vin.get('scriptSig', {}).get('hex', '')
            if scriptsig.startswith('30'): # Legacy DER format
                total += 1
                r_val = scriptsig[8:72]
                if r_val.startswith('00'): # Leading zero 8-bit bias
                    hits += 1

    if total == 0:
        return "Found UTXOs, but could not access historical signature data (VIN). Audit limited without patch."

    ratio = (hits / total) * 100
    print(f"Results: {hits}/{total} biased signatures ({ratio:.2f}%)")
    
    if ratio > 5.0:
        return "VERDICT: LATTICE BIAS CONFIRMED."
    return "VERDICT: STATISTICALLY SECURE."


def get_full_history(address):
    all_txs = []
    last_txid = None
    # cmp_time = 1375315200  # 2013.8.1
    cmp_time = 1388534400  # 2014.1.1
    print(f"Starting deep history scan for {address}...")
    
    while True:
        # Construct the URL with paging if we have a last_txid
        if last_txid:
            url = f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
        else:
            url = f"https://mempool.space/api/address/{address}/txs"
            
        response = requests.get(url)
        if response.status_code != 200:
            break
            
        batch = response.json()
        if not batch: # No more transactions found
            break

        for tx in batch:
            block_time = tx.get('status', {}).get('block_time', 0)
            if int(block_time) < cmp_time:
                all_txs.extend(batch)
        last_txid = batch[-1]['txid'] # Update the anchor for the next page
        
        # Monitor progress
        last_date = batch[-1].get('status', {}).get('block_time', 0)
        print(f"Collected {len(all_txs)} txs... reached date: {time.ctime(last_date)}")
        
        # Stop once we reach the end of 2012
        # if last_date > cmp_time: # Jan 1, 2012
        #     break
        
        time.sleep(0.5) # Avoid rate limiting

    return all_txs

def detectBias(scriptsig_hex):
    if not scriptsig_hex: return 0
    try:
        # The push-byte (e.g., 0x47, 0x48) indicates total sig length
        push_byte = int(scriptsig_hex[0:2], 16)
        if push_byte >= 0x48: return 0 # Standard 72+ bytes
        return (0x48 - push_byte) * 8 # 8 bits per missing byte
    except: return 0

def get_z_legacy(raw_tx_hex, input_index, script_pub_key_hex):
    """
    Calculates the 'z' value (the hash to be signed) for a legacy P2PKH input.
    """
    try:
        # 1. Initialize for Mainnet
        setup('mainnet')
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
    totalCnt = 0

    for tx in full_history:
        # raw_tx_hex = requests.get(f"https://mempool.space/api/tx/{tx['txid']}/hex").text
        # print(raw_tx_hex)
        # return

        for i, vin in enumerate(tx.get('vin', [])):
            if vin.get('prevout', {}).get('scriptpubkey_address') == my_address:
                scriptsig = vin.get('scriptsig', '')
                if not scriptsig or '30' not in scriptsig: continue
                
                # Precise DER Parsing
                try:
                    totalCnt += 1
                    approBias = (detectBias(scriptsig))
                    if approBias == 0:
                        continue
                    print(tx['txid'])
                    print(scriptsig)
                    tx_data = call_cli(["getrawtransaction", tx['txid'], "true"])
                    raw_tx_hex = tx_data['hex']

                    if approBias > maxBias:
                        maxBias = approBias
                    print(approBias)
                    der_start = scriptsig.find('30')
                    r_len = int(scriptsig[der_start+6:der_start+8], 16) * 2
                    r = scriptsig[der_start+8:der_start+8+r_len]
                    print(len(r), " ", r)
  
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

                    print("\n",pubkey)
                    
                    # Z Calculation: 
                    # CRITICAL: For a correct Z, you must replace the scriptSig 
                    # with the spent scriptPubKey before hashing.
                    spent_script_pub_key = vin.get('prevout', {}).get('scriptpubkey', '')
                    
                    # # This simplified template works for single-input legacy txs:
                    # template = binascii.unhexlify(raw_tx_hex) + binascii.unhexlify("01000000")
                    # z = hashlib.sha256(hashlib.sha256(template).digest()).hexdigest()
                    z = get_z_legacy(raw_tx_hex, i, spent_script_pub_key)
                    print("z=>  ", z)

                    entry = {'txid': tx['txid'], 'r': r, 's': s, 'z': z, 'pubkey': pubkey}
                    recovered_data.append(entry)

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
                    else:
                        r_seen[r] = []
                        r_seen[r].append(s)
                    # r_seen[r] = tx['txid']
                    if tx['txid'] in out_txs:
                        continue
                    out_txs.add(tx['txid'])
                    print(tx['txid'])

                except Exception as e:
                    print(f"Skip TX {tx['txid']}: Parsing error {e}")

    print(maxBias)
    return recovered_data, r_seen, totalCnt

if __name__ == "__main__":
    # Example:
    address= "1NibfhHfgA857dtG6pB25Y5hDcxpDo2J47"
    # address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    # report = detect_vulnerable_software(address)
    # print(report)
    allHistory = get_full_history(address)
    result, r_du, totalCnt = extract_rsz_data(allHistory, address)
    verfiedCnt = 0
    for entity in result:
        res = verify_sig_integrity(entity['r'], entity['s'], entity['z'], entity['pubkey'])
        if res:
            verfiedCnt += 1
        # print(res)
    print(len(result), "-", verfiedCnt, "-", totalCnt)


# Finds any signature starting with the 71-byte push (47) or 70-byte push (46)
# grep -E "4730440220|463043021f" transactions.txt