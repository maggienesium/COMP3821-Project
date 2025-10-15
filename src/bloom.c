#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "wm.h"

static inline uint32_t fnv1a(const unsigned char *s, int len, uint32_t seed) {
    uint32_t h = seed;
    for (int i = 0; i < len; ++i)
        h = (h ^ s[i]) * 0x01000193;
    return h;
}

void bloom_init(BloomFilter *bf, int n, double p) {
    double m = -(n * log(p)) / (log(2) * log(2));
    double k = (m / n) * log(2);

    bf->size = (uint32_t)m;
    bf->num_hashes = (uint32_t)k;
    bf->bit_array = calloc((bf->size + 7) / 8, sizeof(uint8_t));
}

void bloom_add(BloomFilter *bf, const unsigned char *data, int len) {
    uint32_t h1 = fnv1a(data, len, 0x811C9DC5);
    uint32_t h2 = fnv1a(data, len, 0x01000193);

    for (uint32_t i = 0; i < bf->num_hashes; ++i) {
        uint32_t idx = (h1 + i * h2) % bf->size;
        bf->bit_array[idx >> 3] |= (1 << (idx & 7));
    }
}

int bloom_check(const BloomFilter *bf, const unsigned char *data, int len) {
    uint32_t h1 = fnv1a(data, len, 0x811C9DC5);
    uint32_t h2 = fnv1a(data, len, 0x01000193);

    for (uint32_t i = 0; i < bf->num_hashes; ++i) {
        uint32_t idx = (h1 + i * h2) % bf->size;
        if (!(bf->bit_array[idx >> 3] & (1 << (idx & 7))))
            return 0;  // definitely not present
    }
    return 1; // possibly present
}

void bloom_free(BloomFilter *bf) {
    free(bf->bit_array);
}
