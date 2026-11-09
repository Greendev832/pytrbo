#!/usr/bin/env python3
"""Illustrate PRNG state recovery on synthetic values.

Scenario: a browser-style MWC1616 Math.random() is seeded (here from a small
range, e.g. a clock value). An observer sees only a few raw outputs. Because the
state is small and deterministic, the observer can search the seed/state space,
find the one that reproduces the observed outputs, and then PREDICT all future
outputs. This is purely about the PRNG; no keys or wallets involved.
"""
import time

MASK = 0xffffffff


def mwc_stream(seed, n):
    """MWC1616, state seeded from `seed` (like the browser stand-in)."""
    s0 = (seed & 0xffff) or 1
    s1 = ((seed >> 16) & 0xffff) or 2
    out = []
    for _ in range(n):
        s0 = (18030 * (s0 & 0xffff) + (s0 >> 16)) & MASK
        s1 = (30903 * (s1 & 0xffff) + (s1 >> 16)) & MASK
        out.append(((s0 << 16) + (s1 & 0xffff)) & MASK)
    return out


# ---- victim: pick a hidden seed, emit a short observed sequence ----
HIDDEN_SEED = 0x0009_1A3B          # unknown to the observer
SEED_SPACE = 1 << 20               # observer knows seed is in [0, 2^20) (e.g. a time window)

full = mwc_stream(HIDDEN_SEED, 8)
observed = full[:3]                # observer sees only the first 3 outputs
future_truth = full[3:]            # the rest, which the observer will try to predict

print("Observer sees only these 3 raw Math.random() outputs (as u32):")
print("  ", observed)
print("Hidden seed (secret):", hex(HIDDEN_SEED))
print(f"Observer knows the seed is somewhere in [0, {SEED_SPACE}) and knows the algorithm.")
print()

# ---- observer: search the seed space for one matching the observed outputs ----
t0 = time.time()
matches = []
for seed in range(SEED_SPACE):
    if mwc_stream(seed, 3) == observed:
        matches.append(seed)
secs = round(time.time() - t0, 2)

print(f"Searched {SEED_SPACE} seeds in {secs}s")
print(f"Seeds that reproduce the 3 observed outputs: {[hex(m) for m in matches]}")
print()

# ---- observer: predict the NEXT outputs from the recovered state ----
recovered = matches[0]
predicted = mwc_stream(recovered, 8)[3:]
print("Now the observer PREDICTS the next 5 outputs it never saw:")
print("  predicted:", predicted)
print("  actual   :", future_truth)
print("  correct  :", predicted == future_truth)
print()
print("Takeaway: 3 outputs + a small state were enough to pin the exact state,")
print("then every future output is fully determined. Bigger state = bigger search,")
print("but the same idea; a secure RNG has no such fixed state to recover.")
