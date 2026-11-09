#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>
#include <string>   // std::string

static const uint8_t N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint64_t M48 = (1ULL << 48) - 1;

struct U256 { uint64_t w[4]; };

static inline U256 u256_from_be(const uint8_t* b) {
    U256 r;
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | b[i*8 + j];
        r.w[3 - i] = v;
    }
    return r;
}
static inline void u256_to_be(const U256& a, uint8_t* b) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = a.w[3 - i];
        for (int j = 7; j >= 0; j--) { b[i*8 + j] = v & 0xFF; v >>= 8; }
    }
}
static inline int u256_cmp(const U256& a, const U256& b) {
    for (int i = 3; i >= 0; i--) {
        if (a.w[i] < b.w[i]) return -1;
        if (a.w[i] > b.w[i]) return 1;
    }
    return 0;
}
static inline U256 u256_sub(const U256& a, const U256& b) {
    U256 r; uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t diff = a.w[i] - b.w[i] - borrow;
        borrow = (a.w[i] < b.w[i] + borrow) ? 1 : 0;
        r.w[i] = diff;
    }
    return r;
}
static inline U256 u256_add(const U256& a, const U256& b) {
    U256 r; uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t s = a.w[i] + b.w[i] + carry;
        carry = (s < a.w[i] || (carry && s == a.w[i])) ? 1 : 0;
        r.w[i] = s;
    }
    return r;
}
static U256 u256_mod(const U256& a, const U256& m) {
    if (u256_cmp(a, m) < 0) return a;
    U256 rem = {0,0,0,0};
    for (int bit = 255; bit >= 0; bit--) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t nc = rem.w[i] >> 63;
            rem.w[i] = (rem.w[i] << 1) | carry;
            carry = nc;
        }
        int word = bit / 64, off = bit % 64;
        if ((a.w[word] >> off) & 1) rem.w[0] |= 1;
        if (u256_cmp(rem, m) >= 0) rem = u256_sub(rem, m);
    }
    return rem;
}

static inline void firefox_random16(uint64_t base_seed, int pending, int n, uint16_t* out) {
    uint64_t seed = (base_seed << 8) ^ 1;
    uint64_t state = (seed ^ 0x5DEECE66DULL) & M48;
    int idx = 0;
    for (int i = 0; i < n + pending; i++) {
        state = (state * 0x5DEECE66DULL + 0xB) & M48;
        uint64_t hi = state >> 22;
        state = (state * 0x5DEECE66DULL + 0xB) & M48;
        uint64_t lo = state >> 21;
        uint64_t numerator = (hi << 27) + lo;
        if (i >= pending) out[idx++] = (uint16_t)(numerator >> 37);
    }
}

struct RC4 { uint8_t S[256]; int i, j; };
static inline void rc4_init(RC4& st, const uint8_t* key, int klen) {
    for (int i = 0; i < 256; i++) st.S[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + st.S[i] + key[i % klen]) & 255;
        std::swap(st.S[i], st.S[j]);
    }
    st.i = 0; st.j = 0;
}
static inline uint8_t rc4_next(RC4& st) {
    st.i = (st.i + 1) & 255;
    st.j = (st.j + st.S[st.i]) & 255;
    std::swap(st.S[st.i], st.S[st.j]);
    return st.S[(st.S[st.i] + st.S[st.j]) & 255];
}

static inline U256 k_from(uint64_t seed_value, uint64_t t1, uint64_t t2, int pending = 0) {
    uint16_t draws[128];
    firefox_random16(seed_value, pending, 128, draws);

    uint8_t pool[256];
    for (int i = 0; i < 128; i++) {
        pool[2*i]   = (draws[i] >> 8) & 255;
        pool[2*i+1] = draws[i] & 255;
    }
    uint32_t x1 = (uint32_t)(t1 & 0xFFFFFFFF);
    uint32_t x2 = (uint32_t)(t2 & 0xFFFFFFFF);
    uint32_t vals[2] = { x1, x2 };
    for (int v = 0; v < 2; v++) {
        uint32_t x = vals[v];
        int base = v * 4;
        pool[base]   ^= x & 255;
        pool[base+1] ^= (x >> 8) & 255;
        pool[base+2] ^= (x >> 16) & 255;
        pool[base+3] ^= (x >> 24) & 255;
    }

    RC4 st;
    rc4_init(st, pool, 256);
    rc4_next(st);
    uint8_t v[32];
    for (int i = 0; i < 32; i++) v[i] = rc4_next(st);

    U256 val = u256_from_be(v);
    U256 N = u256_from_be(N_BYTES);
    U256 Nm1 = N; Nm1.w[0] -= 1;
    U256 rem = u256_mod(val, Nm1);
    U256 one = {1,0,0,0};
    return u256_add(rem, one);
}

static U256 dec_to_u256(const std::string& dec) {
    U256 r = {0,0,0,0};
    for (char c : dec) {
        if (c < '0' || c > '9') continue;
        // r = r * 10 + (c - '0')
        uint64_t carry = (uint64_t)(c - '0');
        for (int i = 0; i < 4; i++) {
            // r.w[i] * 10 + carry, 128-bit intermediate
            unsigned __int128 prod = (unsigned __int128)r.w[i] * 10 + carry;
            r.w[i] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
    }
    return r;
}

static std::string u256_to_dec(const U256& v) {
    if (v.w[0] == 0 && v.w[1] == 0 && v.w[2] == 0 && v.w[3] == 0) return "0";
    U256 tmp = v;
    std::string dec;
    while (tmp.w[0] || tmp.w[1] || tmp.w[2] || tmp.w[3]) {
        uint64_t rem = 0;
        for (int i = 3; i >= 0; i--) {
            unsigned __int128 cur = ((unsigned __int128)rem << 64) | tmp.w[i];
            tmp.w[i] = (uint64_t)(cur / 10);
            rem = (uint64_t)(cur % 10);
        }
        dec.push_back('0' + (char)rem);
    }
    std::reverse(dec.begin(), dec.end());
    return dec;
}

int main() {
    uint64_t seed = 1365882564000000ULL;
    uint64_t t1   = 1365882564000ULL;
    uint64_t t2   = 1365882564000ULL;
    U256 k = k_from(seed, t1, t2, 0);
    uint8_t be[32];
    u256_to_be(k, be);
    printf("k=");
    for (int i = 0; i < 32; i++) printf("%02x", be[i]);
    printf("\n");

    const char* s = "26329801829260609769066116643113100199158085603771696721971142443971041749083";
    U256 v = dec_to_u256(s);
    std::string back = u256_to_dec(v);
    printf("original: %s\n", s);
    printf("roundtrip: %s\n", back.c_str());
    printf("match: %s\n", (std::string(s) == back) ? "YES" : "NO");
    return 0;
}

/*
clang++ -O3 -std=c++17 test_k.cpp -o test_k
./test_k
*/