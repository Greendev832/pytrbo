import subprocess
import json
import sqlite3
import os

# RPC credentials
RPC_USER = "ace"
RPC_PASS = "browser"

# Setup Database
db_exists = os.path.exists("sigs_database.db")
conn = sqlite3.connect("sigs_database.db")
cursor = conn.cursor()

if not db_exists:
    cursor.execute('''CREATE TABLE signatures 
                     (r_value TEXT, txid TEXT, block_height INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cursor.execute('CREATE INDEX idx_r ON signatures(r_value)')
    conn.commit()

def call_cli(command):
    cmd = ["bitcoin-cli", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}", *command]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return None

    # This part finds the FIRST '{' and LAST '}' to strip away extra text/warnings
    raw_output = result.stdout.strip()
    try:
        start_index = raw_output.find('{')
        end_index = raw_output.rfind('}') + 1
        if start_index != -1 and end_index != 0:
            clean_json = raw_output[start_index:end_index]
            return json.loads(clean_json)
        return json.loads(raw_output)
    except json.JSONDecodeError:
        # If it's a simple string (like a block hash), it won't have { }
        try:
            return json.loads(f'"{raw_output}"') if '"' not in raw_output else raw_output
        except:
            return raw_output

def extract_r(asm):
    if "304" in asm:
        parts = asm.split(" ")
        for part in parts:
            if part.startswith("30") and len(part) > 20:
                try:
                    r_len = int(part[6:8], 16) * 2
                    return part[8:8+r_len]
                except: continue
    return None

def scan_blocks(start, end):
    print(f"Starting scan at {start}...")
    for height in range(start, end + 1):
        if height % 5 == 0: print(f"Currently at Block: {height}")
        
        block_hash = call_cli(["getblockhash", str(height)])
        block = call_cli(["getblock", block_hash, "2"])
        
        for tx in block['tx']:
            for vin in tx.get('vin', []):
                asm = vin.get('scriptSig', {}).get('asm', '')
                r_val = extract_r(asm)
                
                if r_val:
                    # Check database for existing R-value
                    cursor.execute("SELECT txid FROM signatures WHERE r_value=?", (r_val,))
                    match = cursor.fetchone()
                    
                    if match:
                        print(f"\n[!!!] REUSE DETECTED!")
                        print(f"R-Value: {r_val}\nTX1: {match[0]}\nTX2: {tx['txid']}\n")
                        with open("found_keys.txt", "a") as f:
                            f.write(f"R: {r_val} | TX1: {match[0]} | TX2: {tx['txid']}\n")
                    else:
                        cursor.execute("INSERT INTO signatures (r_value, txid, block_height) VALUES (?, ?, ?)", 
                                       (r_val, tx['txid'], height))
        
        if height % 50 == 0: conn.commit() # Save progress every 50 blocks

# 200,000 is mid-2012 | 278,500 is your current sync limit
scan_blocks(200000, 278500)