MULTIPLIER = 0x5DEECE66D
ADDEND = 0xB
MASK = (1 << 48) - 1
SCALE = float(1 << 53)


def set_seed(seed: int) -> int:
    return (seed ^ MULTIPLIER) & MASK


def init_random(now_us: int, cx: int, cx_next: int) -> int:
    seed = (now_us // 1000) ^ cx ^ cx_next
    return set_seed(seed)


def next_bits(state: int, bits: int) -> tuple[int, int]:
    state = (state * MULTIPLIER + ADDEND) & MASK
    return state, state >> (48 - bits)


def math_random(state: int) -> tuple[int, float]:
    state, hi = next_bits(state, 26)
    state, lo = next_bits(state, 27)
    return state, ((hi << 27) + lo) / SCALE


# state = init_random(now_us, cx, cx_next)
# state, value = math_random(state)

print(init_random(1300000000000, 0x0C000000, 0x0B000000))