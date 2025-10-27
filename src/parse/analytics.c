#include <stdlib.h>

#include "analytics.h"

/* ---------------------------------------------------------------
 *  Global memory tracker (assign this in each algorithm)
 * --------------------------------------------------------------- */
MemoryStats *global_mem_stats = NULL;

/* ---------------------------------------------------------------
 *  Memory tracking wrappers
 * --------------------------------------------------------------- */
void *track_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr && global_mem_stats) {
        global_mem_stats->alloc_count++;
        global_mem_stats->total_bytes += size;
    }
    return ptr;
}

void *track_calloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (ptr && global_mem_stats) {
        global_mem_stats->alloc_count++;
        global_mem_stats->total_bytes += count * size;
    }
    return ptr;
}

void *track_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (new_ptr && global_mem_stats) {
        global_mem_stats->alloc_count++;
        global_mem_stats->total_bytes += size;
    }
    return new_ptr;
}

void track_free(void *ptr) {
    if (!ptr) return;
    if (global_mem_stats)
        global_mem_stats->free_count++;
    free(ptr);
}
