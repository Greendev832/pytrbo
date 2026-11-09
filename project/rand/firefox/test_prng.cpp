#include <cstdint>
#include <cstdio>

static const uint64_t M48 = (1ULL << 48) - 1;

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

int main() {
    uint64_t seed = 1365882564000000ULL;
    uint16_t draws[5];
    firefox_random16(seed, 0, 5, draws);
    printf("first 5 draws: ");
    for (int i = 0; i < 5; i++) printf("%u ", draws[i]);
    printf("\n");
    return 0;
}

/*
clang++ -O3 -std=c++17 test_prng.cpp -o test_prng
./test_prng
*/