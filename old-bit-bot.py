import requests
import time
import hashlib
import binascii
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

def get_full_history(address):
    all_txs = []
    last_txid = None
    cmp_time = 1375315200  # 2013.8.1
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
        if last_date > cmp_time: # Jan 1, 2012
            break
            
        time.sleep(0.5) # Avoid rate limiting

    return all_txs

def extract_rsz_data(full_history, my_address):
    """
    Extracts r, s, and calculates z for Legacy P2PKH transactions.
    """
    recovered_data = []
    r_seen = {} # For instant duplicate R detection

    for tx in full_history:
        raw_tx_hex = requests.get(f"https://mempool.space/api/tx/{tx['txid']}/hex").text
        
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
                    
                    # Z Calculation: SHA256(SHA256(Raw_TX + Sighash_All))
                    # Note: Simplified for Legacy. Professional recovery uses full tx reconstruction.
                    # z = "hashed"
                    template = binascii.unhexlify(raw_tx_hex) + binascii.unhexlify("01000000")
                    z = hashlib.sha256(hashlib.sha256(template).digest()).hexdigest()

                    entry = {'txid': tx['txid'], 'r': r, 's': s, 'z': z}
                    recovered_data.append(entry)

                    # Instant Duplicate Check
                    if r in r_seen:
                        # print(f"!!! ALERT: DUPLICATE R DETECTED !!!")
                        print(f"R: {r}\nTX1: {r_seen[r]}\nTX2: {tx['txid']}")
                        return
                    r_seen[r] = tx['txid']

                except Exception as e:
                    print(f"Skip TX {tx['txid']}: Parsing error {e}")

    return recovered_data

if __name__ == "__main__":
    # address = "1EsHer57RA9YTNJVoH7gTHfXwt6RCphDdj"
    # address = "1FdPpELnjHfwSM4Nvi7LdYS4S4GVGsLUQY"
    address = "13MWy1aUCn9mDRdjo537VkyxuibTKGZG2R"
    txhash = "79930170be40f5e5db8573c1c2b4326d25ad4bcbf29fb7719c9d5940e4b19207"
    allHistory = get_full_history(address)
    # print(allHistory)
    result = extract_rsz_data(allHistory, address)
    print(result)
    # get_rs_tx(txhash)
    # get_signatures(address)
    # results = extract_rsz(address)
    # print(results)