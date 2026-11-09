
import sys
import time
import json

# ---------- secp256k1 ----------
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8


def j_double(Pt):
    X, Y, Z = Pt
    if Y == 0:
        return (0, 0, 0)
    A = (X * X) % P
    B = (Y * Y) % P
    C = (B * B) % P
    D = (2 * (((X + B) * (X + B)) % P - A - C)) % P
    E = (3 * A) % P
    F = (E * E) % P
    X3 = (F - 2 * D) % P
    Y3 = (E * (D - X3) - 8 * C) % P
    Z3 = (2 * Y * Z) % P
    return (X3, Y3, Z3)


def j_add(Pt, Qt):
    if Pt[2] == 0:
        return Qt
    if Qt[2] == 0:
        return Pt
    Z1 = (Pt[2] * Pt[2]) % P
    Z2 = (Qt[2] * Qt[2]) % P
    U1 = (Pt[0] * Z2) % P
    U2 = (Qt[0] * Z1) % P
    S1 = (Pt[1] * Qt[2] * Z2) % P
    S2 = (Qt[1] * Pt[2] * Z1) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 0)
        return j_double(Pt)
    H = (U2 - U1) % P
    I = (4 * H * H) % P
    J = (H * I) % P
    rr = (2 * (S2 - S1)) % P
    V = (U1 * I) % P
    X3 = (rr * rr - J - 2 * V) % P
    Y3 = (rr * (V - X3) - 2 * S1 * J) % P
    Z3 = (((Pt[2] + Qt[2]) * (Pt[2] + Qt[2]) - Z1 - Z2) * H) % P
    return (X3, Y3, Z3)


def mul_x(k, Px, Py):
    """Return affine x-coordinate of k*(Px,Py)."""
    R = (0, 0, 0)
    Q = (Px, Py, 1)
    while k > 0:
        if k & 1:
            R = j_add(R, Q)
        Q = j_double(Q)
        k >>= 1
    if R[2] == 0:
        return None
    zi = pow(R[2], -1, P)
    return (R[0] * (zi * zi % P)) % P


M32 = 0xffffffff
M48 = (1 << 48) - 1
MULT = 0x5DEECE66D
ADD = 0xB

def _firefox_random16(base_seed, pending, n):
    """Firefox (SpiderMonkey, Java-style 48-bit LCG). In-window: Firefox 15-27.
    Replaced by xorshift128+ in Firefox 48 (2016). (IE/Chakra used a different
    generator and is intentionally not modeled here.)"""
    seed = (base_seed << 8) ^ 1
    state = (seed ^ 0x5DEECE66D) & M48

    def nxt(bits):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & M48
        return state >> (48 - bits)

    out = []
    for idx in range(n + pending):
        numerator = (nxt(26) << 27) + nxt(27)     # 53-bit integer
        if idx >= pending:
            out.append((numerator * 65536) >> 53)     # floor(65536 * num/2**53)
    return out

# The three in-window (Sept 2012 - early 2014) browser generators.
ENGINES = {
    "firefox": _firefox_random16,  # Firefox 15-27 (SpiderMonkey)
}


# ---------- RC4 (Arcfour) ----------
def rc4_init(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    return {"i": 0, "j": 0, "S": S}


def rc4_next(st):
    st["i"] = (st["i"] + 1) & 255
    st["j"] = (st["j"] + st["S"][st["i"]]) & 255
    S = st["S"]
    S[st["i"]], S[st["j"]] = S[st["j"]], S[st["i"]]
    return S[(S[st["i"]] + S[st["j"]]) & 255]


# ---------- k pipeline (matches bitcoinjs.js worker path) ----------
def k_from(seed, t1, t2, pending, engine="v8"):
    draws = []
    if engine == 'v8':
        s0, s1 = seed
        draws = ENGINES[engine](s0, s1, 128)   # 128 draws -> 256 pool bytes
    else:
        seed_value = seed
        draws = ENGINES[engine](seed_value, pending, 128)   # 128 draws -> 256 pool bytes
    pool = [0] * 256
    for i, t in enumerate(draws):        # t is already floor(65536*Math.random())
        pool[2 * i] = (t >> 8) & 255
        pool[2 * i + 1] = t & 255

    def seed_int(x, at):
        xi = x & 0xffffffff  # JS bitwise ops work on 32-bit, &255 hides sign
        pool[at] ^= xi & 255
        pool[at + 1] ^= (xi >> 8) & 255
        pool[at + 2] ^= (xi >> 16) & 255
        pool[at + 3] ^= (xi >> 24) & 255

    seed_int(t1, 0)
    seed_int(t2, 4)

    st = rc4_init(pool)
    xb = [rc4_next(st) for _ in range(33)]
    xb[0] = 0
    v = 0
    for b in xb:
        v = (v << 8) | b
    return v % (N - 1) + 1

def firefox_range(nTime):
    nBin = f"{nTime: b}"
    nBin = nBin.lstrip(' ')
    start = nBin[:9].ljust(41, "0")
    end = nBin[:9].ljust(41, "1")
    start_ms = int(start, 2)
    end_ms = int(end, 2)
    return (start_ms, end_ms)

def main(label, end_t1, target_R):
    # end_t1 = 1330107858000
    # target_R = [15418708180275493399148615105543371698452277500462241568750217526447599349573] 
    temp = 15*60*1000
    size_t1 = 400
    size_t2 = 30
    found = 0

    if found == 0:
        ENGINE = "firefox"
        for start_time in range(end_t1 - temp, end_t1):
            for seed_temp in range(0, 1000):
                for temp_t1 in range(0, size_t1):
                    for temp_t2 in range(0, size_t2):
                        seed = start_time * 1000 + seed_temp
                        t1 = start_time + temp_t1
                        k = k_from(seed, t1, t1 + temp_t2, 0, ENGINE)
                        cal_r = mul_x(k, Gx, Gy)
                        if cal_r in target_R:
                            found = 1
                            print("Success:-> ", k)
                            return (label, k)
    return (label, found)

def load_json_data():
    with open("tar_addresses.json", "r", encoding="utf-8") as f:
        loaded_list = json.load(f)
    return loaded_list

if __name__ == "__main__":
    cmp_data_list = load_json_data()
    print(cmp_data_list)
    for cmp_data in cmp_data_list:
        (label, k_result) = main(cmp_data["label"], cmp_data["time"], cmp_data["target"])
        with open("results.txt", "a", encoding="utf-8") as f:
            f.write(f"{label} \t{k_result}\n")
    k = k_from(1357547742949006, t1, t1 + temp_t2, 0, "firefox")