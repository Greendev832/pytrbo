MASK32 = 0xFFFFFFFF

def srand_from_millis(time_ms):

    return int(time_ms) & MASK32

def msvc_rand(hold):
    hold = (hold * 214013 + 2531011) & MASK32
    return hold, (hold >> 16) & 0x7FFF

def mwc_step(s0, s1):
    s0 = (18273 * (s0 & 0xFFFF) + (s0 >> 16)) & MASK32
    s1 = (36969 * (s1 & 0xFFFF) + (s1 >> 16)) & MASK32
    bits = ((s0 << 14) + (s1 & 0x3FFFF)) & MASK32
    return s0, s1, bits


class Page:

    def __init__(self, renderer):
        self.renderer = renderer
        self.s0 = 0
        self.s1 = 0

    def math_random(self):

        if self.s0 == 0:
            self.s0 = self.renderer.rand()
            self.s1 = self.renderer.rand()
        self.s0, self.s1, bits = mwc_step(self.s0, self.s1)
        return bits / 2**32


class Renderer:
    def __init__(self, time_ms, chrome18):
        # V8::Initialize → OS::SetUp
        self.hold = srand_from_millis(time_ms)
        self.priv0 = 0
        self.priv1 = 0
        self.page = None
        if chrome18:

            self.random_private()

    def rand(self):

        self.hold, value = msvc_rand(self.hold)
        return value

    def random_private(self):

        if self.priv0 == 0:
            self.priv0 = self.rand()
            self.priv1 = self.rand()
        self.priv0, self.priv1, bits = mwc_step(self.priv0, self.priv1)
        return bits & 0x3FFFFFFF

    def navigate(self):

        self.page = Page(self)
        return self.page



tab = Renderer(1348531200000, chrome18=False)
tab.navigate()
tab.page.math_random()   # 0.22620298364199698
tab.navigate()
tab.page.math_random()   # 0.8961049225181341


tab = Renderer(1348531200000, chrome18=True)
tab.navigate()
print(tab.page.math_random())   # 0.8961049225181341
tab.navigate()
print(tab.page.s0)
print(tab.page.math_random())   # 0.8684130108449608