M32 = 0xffffffff

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

def chrome_thread_renderer():
    hold = 1
    hold, priv0 = msvc_rand(hold)
    hold, priv1 = msvc_rand(hold)
    _, _, bits = mwc_step(priv0, priv1)
    hash_seed = bits & 0x3FFFFFFF  
    s0 = 0
    s1 = 0

    def math_random():
        nonlocal hold, s0, s1
        if s0 == 0:
            hold, s0 = msvc_rand(hold)
            hold, s1 = msvc_rand(hold)
        s0, s1, bits = mwc_step(s0, s1)
        return bits / 2**32

    def navigate():
        nonlocal s0, s1
        s0 = 0
        s1 = 0

    return math_random, navigate

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
        return bits / 2**32

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
    hash_seed = bits & 0x3FFFFFFF  
    s0 = 0
    s1 = 0

    def math_random():
        nonlocal hold, s0, s1
        if s0 == 0:
            hold, s0 = msvc_rand(hold)
            hold, s1 = msvc_rand(hold)
        s0, s1, bits = mwc_step(s0, s1)
        return bits / 2**32

    def navigate():
        nonlocal s0, s1
        s0 = 0
        s1 = 0

    return math_random, navigate

time_ms = 1348531200000

math_random, navigate = chrome17_renderer(time_ms)
for _ in range(5):
    print(math_random())

math_random, navigate = chrome18_renderer(time_ms)
for _ in range(5):
    print(math_random())

math_random, navigate = chrome_thread_renderer()
print(math_random())

math_random, navigate = chrome18_renderer(1)
print(math_random())