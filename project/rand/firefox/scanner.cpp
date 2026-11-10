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
#include <utility>
#include <atomic>
#include <stdexcept>
#include <omp.h>

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

// a < 2^256, m > 2^255  =>  a < 2*m, so one subtraction suffices.
static inline U256 u256_mod_fast(const U256& a, const U256& m) {
    if (u256_cmp(a, m) < 0) return a;
    return u256_sub(a, m);
}

// ---------- 10진수 <-> U256 ----------
static U256 dec_to_u256(const std::string& dec) {
    U256 r = {0,0,0,0};
    for (char c : dec) {
        if (c < '0' || c > '9') continue;
        uint64_t carry = (uint64_t)(c - '0');
        for (int i = 0; i < 4; i++) {
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
    U256 rem = u256_mod_fast(val, Nm1);
    U256 one = {1,0,0,0};
    return u256_add(rem, one);
}

// ---------- secp256k1 (per-thread context) ----------
static inline bool mul_x_with_ctx(secp256k1_context* ctx, const U256& k, uint8_t out_x[32]) {
    uint8_t seckey[32];
    u256_to_be(k, seckey);
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, seckey)) return false;
    uint8_t out[33];
    size_t outlen = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &outlen, &pub, SECP256K1_EC_COMPRESSED);
    memcpy(out_x, out + 1, 32);
    return true;
}

// ---------- JSON parsing ----------
struct Entry {
    std::string label;
    uint64_t time_ms;
    std::vector<U256> targets;
};

static std::vector<Entry> load_entries(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("cannot open " + path);
    }
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
        if (lq1 == std::string::npos || lq2 == std::string::npos) continue;
        e.label = obj.substr(lq1 + 1, lq2 - lq1 - 1);

        size_t tp = obj.find("\"time\"");
        if (tp == std::string::npos) continue;
        size_t tcolon = obj.find(':', tp);
        size_t tend = obj.find_first_of(",}", tcolon);
        std::string time_str = obj.substr(tcolon + 1, tend - tcolon - 1);
        size_t a = time_str.find_first_not_of(" \t\n\r");
        size_t b = time_str.find_last_not_of(" \t\n\r");
        try {
            e.time_ms = std::stoull(time_str.substr(a, b - a + 1));
        } catch (...) {
            fprintf(stderr, "[warn] bad time for label %s\n", e.label.c_str());
            continue;
        }

        size_t tap = obj.find("\"target\"");
        if (tap == std::string::npos) continue;
        size_t abeg = obj.find('[', tap);
        size_t aend = obj.find(']', abeg);
        if (abeg == std::string::npos || aend == std::string::npos) continue;
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
                e.targets.push_back(dec_to_u256(num));
            }
            p = comma + 1;
        }
        entries.push_back(e);
    }
    return entries;
}

// ---------- worker ----------
struct WorkerResult {
    bool found;
    U256 k;
    U256 r;
    uint64_t iters;
};

static WorkerResult scan_range(
    uint64_t lo, uint64_t hi,
    int seed_max,
    int t1_start, int t1_end,
    int t2_start, int t2_end,
    const std::vector<U256>& targets,
    const U256& N,
    std::atomic<bool>& found,
    bool debug
) {
    WorkerResult res = {false, {0,0,0,0}, {0,0,0,0}, 0};

    #pragma omp parallel
    {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!ctx) {
            #pragma omp critical
            { fprintf(stderr, "[error] secp256k1_context_create failed in thread\n"); }
        }

        uint64_t local_iters = 0;

        #pragma omp for schedule(dynamic, 1)
        for (long long st = (long long)lo; st < (long long)hi; st++) {
            if (found.load(std::memory_order_relaxed)) continue;
            if (!ctx) continue;
            uint64_t start_time = (uint64_t)st;
            uint64_t base_ms = start_time * 1000;
            for (int ss = 0; ss < seed_max; ss++) {
                if (found.load(std::memory_order_relaxed)) break;
                uint64_t seed = base_ms + ss;
                for (int t1o = t1_start; t1o < t1_end; t1o++) {
                    if (found.load(std::memory_order_relaxed)) break;
                    uint64_t t1 = start_time + (uint64_t)t1o;
                    for (int t2o = t2_start; t2o < t2_end; t2o++) {
                        uint64_t t2 = t1 + (uint64_t)t2o;
                        U256 k = k_from(seed, t1, t2, 0);
                        uint8_t x[32];
                        if (!mul_x_with_ctx(ctx, k, x)) continue;
                        local_iters++;

                        U256 xv = u256_from_be(x);
                        U256 rv = u256_mod_fast(xv, N);

                        if (debug) {
                            #pragma omp critical(debug_print)
                            {
                                printf("[debug] seed=%llu t1=%llu t2=%llu k=%s r=%s\n",
                                       (unsigned long long)seed,
                                       (unsigned long long)t1,
                                       (unsigned long long)t2,
                                       u256_to_dec(k).c_str(),
                                       u256_to_dec(rv).c_str());
                                fflush(stdout);
                            }
                        }

                        for (auto& tgt : targets) {
                            if (u256_cmp(rv, tgt) == 0) {
                                bool expected = false;
                                if (found.compare_exchange_strong(expected, true)) {
                                    #pragma omp critical(result)
                                    {
                                        res.found = true;
                                        res.k = k;
                                        res.r = rv;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        #pragma omp atomic
        res.iters += local_iters;

        if (ctx) secp256k1_context_destroy(ctx);
    }

    return res;
}

// ---------- main ----------
int main(int argc, char** argv) {
    std::string data_path = "tar_addresses.json";
    std::string results_path = "results.txt";
    bool test = false, debug = false;
    int num_threads = omp_get_num_procs();

    int t1_start = 0, t1_end = 400;
    int t2_start = 0, t2_end = 30;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--test") test = true;
        else if (a == "--debug") debug = true;
        else if (a == "--threads" && i + 1 < argc) num_threads = std::stoi(argv[++i]);
        else if (a == "--data" && i + 1 < argc) data_path = argv[++i];
        else if (a == "--results" && i + 1 < argc) results_path = argv[++i];
        else if (a == "--t1-start" && i + 1 < argc) t1_start = std::stoi(argv[++i]);
        else if (a == "--t1-end" && i + 1 < argc) t1_end = std::stoi(argv[++i]);
        else if (a == "--t2-start" && i + 1 < argc) t2_start = std::stoi(argv[++i]);
        else if (a == "--t2-end" && i + 1 < argc) t2_end = std::stoi(argv[++i]);
    }
    if (num_threads < 1) num_threads = 1;
    omp_set_num_threads(num_threads);

    if (test) {
        t1_start = 0; t1_end = 5;
        t2_start = 0; t2_end = 3;
    }

    if (t1_start < 0 || t1_end < t1_start) {
        fprintf(stderr, "[error] invalid t1 range: [%d, %d)\n", t1_start, t1_end);
        return 1;
    }
    if (t2_start < 0 || t2_end < t2_start) {
        fprintf(stderr, "[error] invalid t2 range: [%d, %d)\n", t2_start, t2_end);
        return 1;
    }

    int size_t1 = t1_end - t1_start;
    int size_t2 = t2_end - t2_start;

    printf("[main] threads=%d\n", num_threads);
    printf("[main] data=%s results=%s\n", data_path.c_str(), results_path.c_str());
    printf("[main] t1 range=[%d, %d) size=%d\n", t1_start, t1_end, size_t1);
    printf("[main] t2 range=[%d, %d) size=%d\n", t2_start, t2_end, size_t2);

    std::vector<Entry> entries;
    try {
        entries = load_entries(data_path);
    } catch (const std::exception& ex) {
        fprintf(stderr, "[error] %s\n", ex.what());
        return 1;
    }
    printf("[main] loaded %zu labels\n", entries.size());

    std::ofstream results_file(results_path, std::ios::app);
    if (!results_file.is_open()) {
        fprintf(stderr, "[error] cannot open results file: %s\n", results_path.c_str());
        return 1;
    }

    uint64_t temp_ms = test ? 60 : 15ULL * 60 * 1000;
    int seed_max = test ? 10 : 1000;

    U256 N = u256_from_be(N_BYTES);

    for (auto& e : entries) {
        if (e.time_ms < temp_ms) {
            fprintf(stderr, "[warn] label %s time too small, skipping\n", e.label.c_str());
            continue;
        }
        uint64_t lo = e.time_ms - temp_ms;
        uint64_t hi = e.time_ms;
        uint64_t total = (hi - lo) * (uint64_t)seed_max * (uint64_t)size_t1 * (uint64_t)size_t2;
        printf("[main] label=%s range=%llu~%llu iters=%llu targets=%zu\n",
               e.label.c_str(), (unsigned long long)lo, (unsigned long long)hi,
               (unsigned long long)total, e.targets.size());
        fflush(stdout);

        auto t0 = std::chrono::steady_clock::now();
        std::atomic<bool> found(false);

        WorkerResult res = scan_range(lo, hi, seed_max, t1_start, t1_end, t2_start, t2_end,
                                      e.targets, N, found, debug);

        auto t1 = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(t1 - t0).count();
        double rate = res.iters / (sec > 0 ? sec : 1.0);

        if (res.found) {
            printf("[main] SUCCESS label=%s\n", e.label.c_str());
            printf("[main]   k=%s\n", u256_to_dec(res.k).c_str());
            printf("[main]   r=%s\n", u256_to_dec(res.r).c_str());
            printf("[main]   iters=%llu in %.1fs (%.0f iter/s)\n",
                   (unsigned long long)res.iters, sec, rate);

            results_file << e.label << "\t" << u256_to_dec(res.k) << "\n";
            results_file.flush();
            printf("[main] wrote result to %s\n", results_path.c_str());
        } else {
            printf("[main] NOT FOUND label=%s iters=%llu in %.1fs (%.0f iter/s)\n",
                   e.label.c_str(), (unsigned long long)res.iters, sec, rate);

            results_file << e.label << "\t0\n";
            results_file.flush();
        }
        fflush(stdout);
    }

    results_file.close();
    return 0;
}