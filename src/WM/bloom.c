/* 
 *                      Bloom Filter Module
 *
 * ---------------------------------------------------------------
 * Implements a simple Bloom filter for fast probabilistic
 * prefix filtering in Wu–Manber preprocessing.
 *
 * Reference:
 *   Bloom, B. H. (1970).
 *   “Space/time trade-offs in hash coding with allowable errors.”
 *   Communications of the ACM, 13(7):422–426.
 * ---------------------------------------------------------------
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "wm.h"

/* ---------------------------------------------------------------
 * Function: fnv1a
 *
 * Purpose:
 *   Compute the 32-bit FNV-1a hash of a byte sequence.
 *
 * Parameters:
 *   s    - pointer to input data
 *   len  - length of data in bytes
 *   seed - initial hash seed
 *
 * Returns:
 *   32-bit FNV-1a hash value
 * ---------------------------------------------------------------
 */
static inline uint32_t fnv1a(const unsigned char *s, int len, uint32_t seed) {
    uint32_t h = seed;
    for (int i = 0; i < len; ++i)
        h = (h ^ s[i]) * 0x01000193;
    return h;
}

/* ---------------------------------------------------------------
 * Function: bloom_init
 *
 * Purpose:
 *   Initialize a Bloom filter given the number of expected items
 *   and desired false positive probability.
 *
 * Parameters:
 *   bf - pointer to BloomFilter struct
 *   n  - expected number of items
 *   p  - desired false positive probability (e.g. 0.01 = 1%)
 * ---------------------------------------------------------------
 */
void bloom_init(BloomFilter *bf, int n, double p) {
    double m = -(n * log(p)) / (log(2) * log(2));
    double k = (m / n) * log(2);

    bf->size = (uint32_t)m;
    bf->num_hashes = (uint32_t)k;
    bf->bit_array = wm_calloc((bf->size + 7) / 8, sizeof(uint8_t));
}

/* ---------------------------------------------------------------
 * Function: bloom_add
 *
 * Purpose:
 *   Insert a data element into the Bloom filter.
 *
 * Parameters:
 *   bf   - pointer to initialized Bloom filter
 *   data - pointer to input data
 *   len  - data length in bytes
 * ---------------------------------------------------------------
 */
void bloom_add(BloomFilter *bf, const unsigned char *data, int len) {
    uint32_t h1 = fnv1a(data, len, 0x811C9DC5);
    uint32_t h2 = fnv1a(data, len, 0x01000193);

    for (uint32_t i = 0; i < bf->num_hashes; ++i) {
        uint32_t idx = (h1 + i * h2) % bf->size;
        bf->bit_array[idx >> 3] |= (1 << (idx & 7));
    }
}

/* ---------------------------------------------------------------
 * Function: bloom_check
 *
 * Purpose:
 *   Check whether a data element may exist in the Bloom filter.
 *
 * Parameters:
 *   bf   - pointer to Bloom filter
 *   data - pointer to input data
 *   len  - data length in bytes
 *
 * Returns:
 *   1 if possibly present, 0 if definitely not present
 * ---------------------------------------------------------------
 */
int bloom_check(const BloomFilter *bf, const unsigned char *data, int len) {
    uint32_t h1 = fnv1a(data, len, 0x811C9DC5);
    uint32_t h2 = fnv1a(data, len, 0x01000193);

    for (uint32_t i = 0; i < bf->num_hashes; ++i) {
        uint32_t idx = (h1 + i * h2) % bf->size;
        if (!(bf->bit_array[idx >> 3] & (1 << (idx & 7))))
            return 0;   // definitely not present
    }
    return 1;   // possibly present
}

/* ---------------------------------------------------------------
 * Function: bloom_free
 *
 * Purpose:
 *   Release dynamically allocated memory used by the Bloom filter.
 *
 * Parameters:
 *   bf - pointer to BloomFilter to clear
 * ---------------------------------------------------------------
 */
void bloom_free(BloomFilter *bf) {
    if (!bf) return;
    wm_free(bf->bit_array);
    bf->bit_array = NULL;
}
