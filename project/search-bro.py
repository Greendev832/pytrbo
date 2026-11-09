import sys

# Define 'n' (the standard secp256k1 elliptic curve group order)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def force_js_int32(val):
    """Enforces JavaScript's native 32-bit signed integer behavior for bitwise logic."""
    return (val & 0xFFFFFFFF) - 0x100000000 if (val & 0x80000000) else (val & 0xFFFFFFFF)

# -------------------------------------------------------------------------
# BROWSER ENGINE 1: Google Chrome 24 (V8 Engine - MWC1616)
# -------------------------------------------------------------------------
def simulate_chrome_24_math_random(seed_x, seed_y, count=128):
    """
    Simulates V8's legacy Multiply-With-Carry (MWC1616) algorithm.
    Returns an array of 16-bit unsigned integers matching Math.floor(65536 * Math.random()).
    """
    x = seed_x & 0xFFFF
    y = seed_y & 0xFFFF
    outputs = []
    
    for _ in range(count):
        # Constants from 2012 V8 source code
        x = (18000 * x + (x >> 16)) & 0xFFFFFFFF
        y = (30903 * y + (y >> 16)) & 0xFFFFFFFF
        
        # V8 stitched two 16-bit parts to form a double
        # Math.floor(65536 * rand) effectively isolates the upper 16 bits of the state
        val = ((x & 0xFFFF) << 16) | (y & 0xFFFF)
        outputs.append((val >> 16) & 0xFFFF)
    return outputs

# -------------------------------------------------------------------------
# BROWSER ENGINE 2: Firefox 17 (SpiderMonkey - Linear Congruential Generator)
# -------------------------------------------------------------------------
def simulate_firefox_17_math_random(seed, count=128):
    """Simulates SpiderMonkey's classic 32-bit LCG state transitions."""
    state = seed & 0xFFFFFFFF
    outputs = []
    for _ in range(count):
        # Standard POSIX/glibc LCG constants active in early builds
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        t = (state >> 16) & 0xFFFF
        outputs.append(t)
    return outputs

# -------------------------------------------------------------------------
# BROWSER ENGINE 3: Safari 6 / iOS 6 (WebKit - XorShift32)
# -------------------------------------------------------------------------
def simulate_safari_6_math_random(seed, count=128):
    """Simulates WebKit's legacy 32-bit XorShift variant used for fast math execution."""
    x = seed if seed != 0 else 1354320000  # Cannot be seeded with 0
    outputs = []
    for _ in range(count):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        outputs.append((x >> 16) & 0xFFFF)
    return outputs

# -------------------------------------------------------------------------
# BROWSER ENGINE 4: Internet Explorer 10 (Trident/Chakra - MSVC LCG)
# -------------------------------------------------------------------------
def simulate_ie10_math_random(seed, count=128):
    """Simulates Microsoft's proprietary Chakra engine baseline LCG footprint."""
    state = seed & 0xFFFFFFFF
    outputs = []
    for _ in range(count):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        t = (state >> 16) & 0x7FFF # Microsoft limits standard rand up to 32767
        outputs.append(t)
    return outputs

# -------------------------------------------------------------------------
# THE CENTRAL JSBN CIPHER WRAPPER ENGINE
# -------------------------------------------------------------------------
def execute_jsbn_pipeline(browser_bytes, timestamp_ms):
    """
    Executes the exact 2012 JSBN crypto layering pipeline:
    Pool Population -> XOR Timestamp Seeding -> RC4/Arcfour KSA -> RC4 PRGA -> secp256k1 Clamp.
    """
    # 1. Initialize 256-byte pool array
    rng_pool = [0] * 256
    for i, b_val in enumerate(browser_bytes):
        rng_pool[i] = b_val & 255
        
    # 2. Replicate 4-byte native JS int32 bitwise XOR timestamp placement
    # Replicates JS memory behavior using forced Int32 shifts
    rng_pool[0] ^= force_js_int32(timestamp_ms & 255)
    rng_pool[1] ^= force_js_int32((timestamp_ms >> 8) & 255)
    rng_pool[2] ^= force_js_int32((timestamp_ms >> 16) & 255)
    rng_pool[3] ^= force_js_int32((timestamp_ms >> 24) & 255)
    
    # 3. Arcfour Key Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + rng_pool[i % len(rng_pool)]) & 255
        S[i], S[j] = S[j], S[i]
        
    # 4. Arcfour Pseudo-Random Generation Algorithm (PRGA) - Pull 32 Bytes
    arcfour_i = 0
    arcfour_j = 0
    random_bytes = []
    
    for _ in range(32):
        arcfour_i = (arcfour_i + 1) & 255
        arcfour_j = (arcfour_j + S[arcfour_i]) & 255
        S[arcfour_i], S[arcfour_j] = S[arcfour_j], S[arcfour_i]
        
        output_byte = S[(S[arcfour_i] + S[arcfour_j]) & 255]
        random_bytes.append(output_byte)
        
    # 5. Core secp256k1 Clamping Mathematics (.mod(n-1).add(1))
    k_raw = int.from_bytes(bytes(random_bytes), byteorder='big')
    k = (k_raw % (SECP256K1_N - 1)) + 1
    return hex(k)

# -------------------------------------------------------------------------
# MASTER EXECUTION FUNCTION FOR THE FOUR PATHWAYS
# -------------------------------------------------------------------------
def generate_nonce_for_browser(browser_name, timestamp_ms, base_seed=55555):
    """Orchestrates the conversion of 16-bit PRNG loops into the 256-byte pool formats."""
    # Every 't' from Math.floor(65536 * Math.random()) yields 16-bits (2 bytes)
    # To fully fill a 256-byte pool, we need exactly 128 extractions.
    uint16_array = []
    
    if browser_name.lower() == "chrome":
        uint16_array = simulate_chrome_24_math_random(base_seed, base_seed + 9999, count=128)
    elif browser_name.lower() == "firefox":
        uint16_array = simulate_firefox_17_math_random(base_seed, count=128)
    elif browser_name.lower() == "safari":
        uint16_array = simulate_safari_6_math_random(base_seed, count=128)
    elif browser_name.lower() == "ie":
        uint16_array = simulate_ie10_math_random(base_seed, count=128)
    else:
        raise ValueError("Unknown browser variant specified.")
        
    # Flatten the 128 16-bit values into 256 individual 8-bit bytes
    browser_bytes = []
    for val in uint16_array:
        browser_bytes.append((val >> 8) & 255)
        browser_bytes.append(val & 255)
        
    return execute_jsbn_pipeline(browser_bytes, timestamp_ms)

# --- EXECUTION DEMO (Targeting an exact December 2012 Date) ---
if __name__ == "__main__":
    # Target: Dec 20, 2012, 10:15:30 GMT in Milliseconds
    target_dec_2012_ms = 1355998530000 
    mock_prng_seed = 888888  # The internal state variable of the browser window
    
    print(f"🕵️‍♂️ Compiling December 2012 Nonce Search Paths...")
    print(f"⏱ Target Epoch: {target_dec_2012_ms}\n" + "="*50)
    
    for browser in ["Chrome", "Firefox", "Safari", "IE"]:
        nonce_k = generate_nonce_for_browser(browser, target_dec_2012_ms, base_seed=mock_prng_seed)
        print(f"🌐 Browser Framework: {browser:7} | Resulting Nonce k: {nonce_k}")
