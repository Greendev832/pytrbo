#!/usr/bin/env python3
"""State recovery across the browser Math.random() generators of 2012-2014.

Same experiment as recover_state.py, repeated for three real algorithms:
  - V8 MWC1616         (Chrome, Opera>=2013)
  - 48-bit LCG         (Firefox SpiderMonkey, IE Chakra/Trident) -- Java-style
  - GameRand/WeakRandom(Safari WebKit JavaScriptCore)

Each is seeded from a small window (as a clock seed would be), an observer sees
a few raw outputs, recovers the seed by search, and predicts future outputs.
Synthetic values only; this is about the PRNGs, not keys or wallets.
"""
import time

M32 = 0xffffffff
M48 = (1 << 48) - 1


# ---- Chrome / Opera (V8): MWC1616, 64-bit state ----
def v8_stream(seed, n):
    s0 = (seed & 0xffff) or 1
    s1 = ((seed >> 16) & 0xffff) or 2
    out = []
    for _ in range(n):
        s0 = (18030 * (s0 & 0xffff) + (s0 >> 16)) & M32
        s1 = (30903 * (s1 & 0xffff) + (s1 >> 16)) & M32
        out.append(((s0 << 16) + (s1 & 0xffff)) & M32)
    return out


# ---- Firefox / IE: 48-bit LCG (Java util.Random-style nextDouble numerator) ----
def lcg_stream(seed, n):
    state = (seed ^ 0x5DEECE66D) & M48       # Java-style seed scramble

    def nxt(bits):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & M48
        return state >> (48 - bits)

    # nextDouble numerator = (next(26) << 27) + next(27)  (a 53-bit integer)
    return [((nxt(26) << 27) + nxt(27)) for _ in range(n)]


# ---- Safari (WebKit JSC): GameRand / WeakRandom, 32-bit ----
def gamerand_stream(seed, n):
    m_low = (seed ^ 0x49616E42) & M32
    m_high = seed & M32
    out = []
    for _ in range(n):
        m_high = ((m_high << 16) + (m_high >> 16)) & M32
        m_high = (m_high + m_low) & M32
        m_low = (m_low + m_high) & M32
        out.append(m_high)
    return out


GENERATORS = [
    ("Chrome/Opera  V8 MWC1616", v8_stream),
    ("Firefox/IE    48-bit LCG ", lcg_stream),
    ("Safari        GameRand   ", gamerand_stream),
]

HIDDEN_SEED = 0x0009_1A3C<<20
SEED_SPACE = 1 << 40          # observer's known window, e.g. a clock range
N_OBSERVED = 3
N_PREDICT = 5

print(f"Hidden seed (secret): {hex(HIDDEN_SEED)};  observer window [0, {SEED_SPACE})")
print(f"Observer sees {N_OBSERVED} raw outputs, then predicts the next {N_PREDICT}.\n")

for name, stream in GENERATORS:
    full = stream(HIDDEN_SEED, N_OBSERVED + N_PREDICT)
    observed, future_truth = full[:N_OBSERVED], full[N_OBSERVED:]
    print(observed, future_truth)

    t0 = time.time()
    matches = [s for s in range(SEED_SPACE) if stream(s, N_OBSERVED) == observed]
    print(matches)
    secs = round(time.time() - t0, 2)

    recovered = matches[0]
    predicted = stream(recovered, N_OBSERVED + N_PREDICT)[N_OBSERVED:]
    print(f"{name}")
    print(f"   candidates matching observed: {len(matches)}  "
          f"(recovered seed {hex(recovered)}, {secs}s)")
    print(f"   predicted next {N_PREDICT} correct: {predicted == future_truth}")
    print()

print("Every 2012-2014 browser generator is deterministic with a small, "
      "recoverable state:\nobserve a little, search the space, then all future "
      "output is fixed. A secure RNG\nhas no such state to recover.")
