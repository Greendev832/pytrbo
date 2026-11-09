#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <utility>   // std::swap
#include <omp.h>

#include <secp256k1.h>

// ---------- secp256k1 constants ----------
static const uint8_t N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint64_t M48 = (1ULL << 48) - 1;

// ---------- 256-bit helpers ----------
struct U256 { uint64_t w[4]; }; // little-endian words

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

// a mod m via bitwise long division (slow path only)
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

// ---------- Firefox PRNG ----------
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

// ---------- RC4 ----------
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

// ---------- k pipeline ----------
// t1, t2 are in milliseconds (64-bit). Internally truncated to 32 bits
// to match bitcoinjs.js's `& 0xffffffff` behavior.
static inline U256 k_from(uint64_t seed_value, uint64_t t1, uint64_t t2, int pending = 0) {
    uint16_t draws[128];
    firefox_random16(seed_value, pending, 128, draws);

    uint8_t pool[256];
    for (int i = 0; i < 128; i++) {
        pool[2*i]   = (draws[i] >> 8) & 255;
        pool[2*i+1] = draws[i] & 255;
    }

    // Truncate t1, t2 to 32 bits (matches Python's & 0xffffffff)
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
    rc4_next(st); // discard first byte (xb[0] = 0)
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

// ---------- JSON parsing ----------
struct Entry {
    std::string label;
    uint64_t time_ms;
    std::vector<std::string> targets; // 64-char hex (big-endian)
};

static void dec_to_be32(const std::string& dec, uint8_t out[32]) {
    memset(out, 0, 32);
    std::string cur = dec;
    int pos = 31;
    while (pos >= 0 && cur != "0" && !cur.empty()) {
        int rem = 0;
        std::string q;
        for (char c : cur) {
            int d = rem * 10 + (c - '0');
            q.push_back('0' + d / 256);
            rem = d % 256;
        }
        out[pos--] = (uint8_t)rem;
        size_t nz = q.find_first_not_of('0');
        cur = (nz == std::string::npos) ? "0" : q.substr(nz);
    }
}

static std::vector<Entry> load_entries(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss; ss << f.rdbuf();
    std::string s = ss.str();
    std::vector<Entry> entries;

    size_t pos = 0;
    while (true) {
        size_t obj_start = s.find('{', pos);
        if (obj_start == std::string::npos) break;
        size_t obj_end = s.find('}', obj_start);
        if (obj_end == std::string::npos) break;
        std::string obj = s.substr(obj_start, obj_end - obj_start + 1);
        pos = obj_end + 1;

        Entry e;

        size_t lp = obj.find("\"label\"");
        if (lp == std::string::npos) continue;
        size_t lq1 = obj.find('"', obj.find(':', lp) + 1);
        size_t lq2 = obj.find('"', lq1 + 1);
        e.label = obj.substr(lq1 + 1, lq2 - lq1 - 1);

        size_t tp = obj.find("\"time\"");
        if (tp == std::string::npos) continue;
        size_t tcolon = obj.find(':', tp);
        size_t tend = obj.find_first_of(",}", tcolon);
        std::string time_str = obj.substr(tcolon + 1, tend - tcolon - 1);
        size_t a = time_str.find_first_not_of(" \t\n\r");
        size_t b = time_str.find_last_not_of(" \t\n\r");
        e.time_ms = std::stoull(time_str.substr(a, b - a + 1));

        size_t tap = obj.find("\"target\"");
        if (tap == std::string::npos) continue;
        size_t abeg = obj.find('[', tap);
        size_t aend = obj.find(']', abeg);
        std::string arr = obj.substr(abeg + 1, aend - abeg - 1);

        size_t p = 0;
        while (p < arr.size()) {
            size_t comma = arr.find(',', p);
            if (comma == std::string::npos) comma = arr.size();
            std::string tok = arr.substr(p, comma - p);
            size_t a2 = tok.find_first_not_of(" \t\n\r");
            size_t b2 = tok.find_last_not_of(" \t\n\r");
            if (a2 != std::string::npos) {
                std::string num = tok.substr(a2, b2 - a2 + 1);
                uint8_t be[32];
                dec_to_be32(num, be);
                char hex[65];
                for (int i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", be[i]);
                hex[64] = 0;
                e.targets.push_back(std::string(hex, 64));
            }
            p = comma + 1;
        }
        entries.push_back(e);
    }
    return entries;
}

static inline bool hex_eq(const uint8_t* a, const std::string& hex) {
    for (int i = 0; i < 32; i++) {
        char buf[3];
        snprintf(buf, 3, "%02x", a[i]);
        if (buf[0] != hex[2*i] || buf[1] != hex[2*i+1]) return false;
    }
    return true;
}

// ---------- main ----------
int main(int argc, char** argv) {
    std::string data_path = "tar_addresses.json";
    bool test = false, debug = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--test") test = true;
        else if (a == "--debug") debug = true;
        else if (a == "--data" && i + 1 < argc) data_path = argv[++i];
    }

    auto entries = load_entries(data_path);
    printf("[main] loaded %zu labels\n", entries.size());

    uint64_t temp_ms = test ? 60 : 15ULL * 60 * 1000;
    int size_t1 = test ? 5 : 400;
    int size_t2 = test ? 3 : 30;
    int seed_max = test ? 10 : 1000;

    U256 N = u256_from_be(N_BYTES);

    for (auto& e : entries) {
        uint64_t lo = e.time_ms - temp_ms;
        uint64_t hi = e.time_ms;
        uint64_t total = (hi - lo) * seed_max * size_t1 * size_t2;
        printf("[main] label=%s range=%llu~%llu iters=%llu\n",
               e.label.c_str(), (unsigned long long)lo, (unsigned long long)hi,
               (unsigned long long)total);
        fflush(stdout);

        auto t0 = std::chrono::steady_clock::now();
        volatile int found = 0;
        U256 found_k = {0,0,0,0};
        uint8_t found_r[32] = {0};

        #pragma omp parallel for schedule(dynamic, 1)
        for (long long st = (long long)lo; st < (long long)hi; st++) {
            if (found) continue;
            uint64_t start_time = (uint64_t)st;
            uint64_t base_ms = start_time * 1000;
            for (int ss = 0; ss < seed_max && !found; ss++) {
                uint64_t seed = base_ms + ss;
                for (int t1o = 0; t1o < size_t1 && !found; t1o++) {
                    // t1 is in milliseconds (start_time is ms)
                    uint64_t t1 = start_time + (uint64_t)t1o;
                    for (int t2o = 0; t2o < size_t2 && !found; t2o++) {
                        // t2 is in milliseconds
                        uint64_t t2 = t1 + (uint64_t)t2o;
                        U256 k = k_from(seed, t1, t2, 0);
                        uint8_t x[32];
                        if (!mul_x(k, x)) continue;

                        U256 xv = u256_from_be(x);
                        U256 rv = u256_mod(xv, N);
                        uint8_t r[32];
                        u256_to_be(rv, r);

                        if (debug) {
                            printf("[debug] seed=%llu t1=%llu t2=%llu k=", 
                                   (unsigned long long)seed,
                                   (unsigned long long)t1,
                                   (unsigned long long)t2);
                            for (int i = 3; i >= 0; i--) printf("%016llx", (unsigned long long)k.w[i]);
                            printf(" r=");
                            for (int i = 0; i < 32; i++) printf("%02x", r[i]);
                            printf("\n");
                            fflush(stdout);
                        }

                        for (auto& tgt : e.targets) {
                            if (hex_eq(r, tgt)) {
                                #pragma omp critical
                                {
                                    if (!found) {
                                        found = 1;
                                        found_k = k;
                                        memcpy(found_r, r, 32);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        auto t1 = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(t1 - t0).count();
        if (found) {
            printf("[main] SUCCESS label=%s k=", e.label.c_str());
            for (int i = 3; i >= 0; i--) printf("%016llx", (unsigned long long)found_k.w[i]);
            printf(" r=");
            for (int i = 0; i < 32; i++) printf("%02x", found_r[i]);
            printf(" in %.1fs\n", sec);
        } else {
            printf("[main] NOT FOUND label=%s in %.1fs\n", e.label.c_str(), sec);
        }
        fflush(stdout);
    }
    return 0;
}