import requests
import time
import hashlib
import binascii
import json
from bitcoinlib.transactions import Transaction

def get_signatures(address):
    # API to get address details (Blockchain.info is reliable for legacy addresses)
    url = f"https://blockchain.info/rawaddr/{address}"

    response = requests.get(url)
    data = response.json()

    print(f"Total Transactions for {address}: {len(data['txs'])}")

    # Filter for OUTGOING transactions (where address appears in inputs)
    outgoing_txids = []
    for tx in data['txs']:
        # Check if our address is in the 'inputs' of this transaction
        is_sender = any(address == i.get('prev_out', {}).get('addr') for i in tx.get('inputs', []))
        if is_sender:
            outgoing_txids.append(tx['hash'])

    print("\nOutgoing Transaction Hashes (TXIDs):")
    for txid in outgoing_txids:
        print(txid)

def extract_rsz(address, sort_order="asc"):
     # Native API sorting control
    url = f"https://api.bitaps.com/btc/v1/blockchain/address/transactions/{address}?order={sort_order}"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        # Bitaps returns data in a 'data' list
        tx_list = data.get('data', {}).get('list', [])
        print(tx_list)
        print(f"[+] Retrieved {len(tx_list)} transactions from API.")
    except Exception as e:
        return f"API Error: {e}"

    sigs = []
    for tx in tx_list:
        height = tx.get('block_height', 0)
        
        # Filter for vulnerable era
        if 160000 <= height <= 280000:
            # Bitaps provides structured signature data
            for inp in tx.get('inputs', []):
                if address in inp.get('address', ''):
                    try:
                        # Extract components
                        # Note: Check API response structure for exact 'r' and 's' field names
                        # If raw hex is provided, use the DER parser from earlier
                        r = int(inp['r'], 16)
                        s = int(inp['s'], 16)
                        z = int(inp['message_hash'], 16)
                        
                        sigs.append((z, r, s))
                        print(f"[+] Captured: Block {height}")
                    except KeyError:
                        continue
    
    return sigs

def get_rs_tx(raw_tx_hex):
    # tx = Transaction.import_raw(raw_tx_hex)
    tx = Transaction(raw_tx_hex)
    print(tx)

    # input_total = 0
    # for i in tx.inputs:
    #     # Check if the value is available (it might be None if the tx is offline/raw)
    #     if hasattr(i, 'value') and i.value is not None:
    #         input_total += i.value
    #     else:
    #         # If value is missing, you may need to look up the previous TXID
    #         print(f"Value for input spending {i.prev_txid} is not in the raw hex.")

    # print(f"Total Input Value (Satoshi): {input_total}")

def extract_rsz_old_data(full_history, my_address):
    recovered_data = []
    for tx in full_history:
        for vin in tx.get('vin', []):
            if vin.get('prevout', {}).get('scriptpubkey_address') == my_address:
                scriptsig = vin.get('scriptsig', '')
                if not scriptsig: continue
                
                # Manual DER Parsing
                # Format: 30 [len] 02 [r_len] [r] 02 [s_len] [s]
                r_len = int(scriptsig[6:8], 16) * 2
                r = scriptsig[8:8+r_len]
                s_start = 8 + r_len + 2
                s_len = int(scriptsig[s_start:s_start+2], 16) * 2
                s = scriptsig[s_start+2:s_start+2+s_len]
                
                # Z Calculation (Placeholder for logic in Step 3-5)
                # In 2026, many use 'rsz' tools to automate the tx reconstruction
                z = "CALCULATED_DOUBLE_SHA256_HEX" 

                recovered_data.append({'txid': tx['txid'], 'r': r, 's': s, 'z': z})
    return recovered_data

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

def extract_rsz_data(full_history, my_address):
    """
    Extracts r, s, and calculates z for Legacy P2PKH transactions.
    """
    recovered_data = []
    r_seen = {} # For instant duplicate R detection
    out_txs = set()

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
                    der_start = scriptsig.find('30')
                    r_len = int(scriptsig[der_start+6:der_start+8], 16) * 2
                    r = scriptsig[der_start+8:der_start+8+r_len]
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
                    
                    # Z Calculation: 
                    # CRITICAL: For a correct Z, you must replace the scriptSig 
                    # with the spent scriptPubKey before hashing.
                    # spent_script_pub_key = vin.get('prevout', {}).get('scriptpubkey', '')
                    
                    # # This simplified template works for single-input legacy txs:
                    # template = binascii.unhexlify(raw_tx_hex) + binascii.unhexlify("01000000")
                    # z = hashlib.sha256(hashlib.sha256(template).digest()).hexdigest()

                    z = "hashed"

                    entry = {'txid': tx['txid'], 'r': r, 's': s, 'z': z}
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

    return recovered_data, r_seen

if __name__ == "__main__":
    # address = "1EsHer57RA9YTNJVoH7gTHfXwt6RCphDdj"
    address = "1NibfhHfgA857dtG6pB25Y5hDcxpDo2J47"
    # address = "1CSsutw7JFAj66AkyMPsDVvZ7yi2aoNyh2"
    # address = "1LDzTExuhjgPppon8qZ8AmyfqWomw6mpHF"
    txhash = "79930170be40f5e5db8573c1c2b4326d25ad4bcbf29fb7719c9d5940e4b19207"
    allHistory = get_full_history(address)
    print(len(allHistory))
    # with open("history.txt", "w") as f:
    #     f.write(json.dumps(allHistory))
    # print(allHistory)
    result, r_du = extract_rsz_data(allHistory, address)
    # result = extract_rsz_old_data(allHistory, address)
    # print(result)
    # print(r_du)
    # get_rs_tx(txhash)
    # get_signatures(address)
    # results = extract_rsz(address)
    # print(results)