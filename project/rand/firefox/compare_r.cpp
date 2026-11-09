#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>

#include <secp256k1.h>

// ---------- secp256k1 constants ----------
static const uint8_t N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint64_t M48 = (1ULL << 48) - 1;

// ---------- 256-bit helpers ----------
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

// ---------- PRNG / RC4 / k_from ----------
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

// ---------- secp256k1 ----------
static secp256k1_context* g_ctx = nullptr;

static void ensure_ctx() {
    if (!g_ctx) g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
}

static inline bool mul_x(const U256& k, uint8_t out_x[32]) {
    ensure_ctx();
    uint8_t seckey[32];
    u256_to_be(k, seckey);
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(g_ctx, &pub, seckey)) return false;
    uint8_t out[33];
    size_t outlen = 33;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pub, SECP256K1_EC_COMPRESSED);
    memcpy(out_x, out + 1, 32);
    return true;
}

// ---------- main: compare k, x, r ----------
int main(int argc, char** argv) {
    // 사용법: ./compare_r <k_hex_64chars>
    // 예: ./compare_r 98bdaa50edc2259e39f8ae26ebc21f8437b117048d83bfbf0b9926ad88904b6b
    if (argc < 2) {
        printf("usage: %s <k_hex_64chars>\n", argv[0]);
        return 1;
    }
    const char* k_hex = argv[1];
    if (strlen(k_hex) != 64) {
        printf("k_hex must be 64 hex chars\n");
        return 1;
    }

    // hex -> U256
    uint8_t k_be[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        sscanf(k_hex + 2*i, "%2x", &b);
        k_be[i] = (uint8_t)b;
    }
    U256 k = u256_from_be(k_be);

    printf("k=");
    for (int i = 0; i < 32; i++) printf("%02x", k_be[i]);
    printf("\n");

    // x = k*G (compressed x)
    uint8_t x[32];
    if (!mul_x(k, x)) {
        printf("mul_x failed\n");
        return 1;
    }
    printf("x=");
    for (int i = 0; i < 32; i++) printf("%02x", x[i]);
    printf("\n");

    // r = x mod N
    U256 xv = u256_from_be(x);
    U256 N = u256_from_be(N_BYTES);
    U256 rv = u256_mod(xv, N);
    uint8_t r[32];
    u256_to_be(rv, r);
    printf("r=");
    for (int i = 0; i < 32; i++) printf("%02x", r[i]);
    printf("\n");

    return 0;
}

/*
clang++ -O3 -std=c++17 compare_r.cpp -o compare_r \
    -I/opt/homebrew/opt/libsecp256k1/include \
    -L/opt/homebrew/opt/libsecp256k1/lib -lsecp256k1
*/