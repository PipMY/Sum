#include "allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Original heap pointer used for relative alignment checks.
static uint8_t *g_heap_base = NULL;
// Tests write via user APIs, so alignment issues surface quickly.

// Simple rand_r replacement to keep builds portable.
static unsigned lcg_rand_r(unsigned *seed) {
    // Linear congruential generator to avoid non-portable rand_r.
    *seed = (uint32_t)(1103515245u * (*seed) + 12345u);
    return *seed;
}

static size_t parse_size(int argc, char **argv, const char *flag, size_t def) {
    // Parse a size flag of the form "--size N" with a default fallback.
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) {
            return (size_t)strtoull(argv[i + 1], NULL, 10);
        }
    }
    return def;
}

static int parse_int(int argc, char **argv, const char *flag, int def) {
    // Parse an integer flag for storm count or seed values.
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) {
            return atoi(argv[i + 1]);
        }
    }
    return def;
}

static int parse_flag(int argc, char **argv, const char *flag) {
    // Presence-only flag: returns 1 if provided, else 0.
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) return 1;
    }
    return 0;
}

static void flip_bits(uint8_t *heap,
                      size_t heap_size,
                      int flips,
                      unsigned *seed) {
    // Randomly toggle bits in the heap to simulate storms.
    for (int i = 0; i < flips; ++i) {
        size_t pos = (size_t)lcg_rand_r(seed) % heap_size;
        uint8_t bit = (uint8_t)(1u << (lcg_rand_r(seed) % 8));
        heap[pos] ^= bit;
    }
}

static int check_alignment(void *p) {
    if (!p || !g_heap_base) return 0;
    return (((uintptr_t)p - (uintptr_t)g_heap_base) % MM_ALIGNMENT) == 0;
}

static void print_result(const char *name, int pass) {
    // Uniform result line used by all tests for easy grepping.
    printf("[%-28s] %s\n", name, pass ? "ok" : "FAIL");
}

static void check_and_log_alignment(const char *label, void *p) {
    if (!p) {
        printf("[align-debug] %s is NULL\n", label);
        return;
    }
    if (!check_alignment(p)) {
        unsigned long mod =
            (unsigned long)(((uintptr_t)p - (uintptr_t)g_heap_base) %
                            MM_ALIGNMENT);
        printf("[align-debug] %s misaligned: %p (rel mod %u = %lu)\n",
               label,
               p,
               (unsigned)MM_ALIGNMENT,
               mod);
    }
}

// Basic read/write sanity and alignment.
static int test_basic_rw(void) {
    void *p = mm_malloc(64);
    check_and_log_alignment("basic_rw", p);
    if (!check_alignment(p)) return 0;
    // Write then read a small string to verify user-facing API.
    const char msg[] = "mars rocks";
    if (mm_write(p, 0, msg, sizeof(msg)) != (int)sizeof(msg)) return 0;
    char buf[32] = {0};
    if (mm_read(p, 0, buf, sizeof(msg)) != (int)sizeof(msg)) return 0;
    int pass = (strcmp(buf, msg) == 0);
    mm_free(p);
    return pass;
}

// Alignment across small/large allocations and splits.
static int test_alignment_and_split(void) {
    void *a = mm_malloc(1);   // should align up
    void *b = mm_malloc(39);  // near alignment boundary
    void *c = mm_malloc(80);  // larger
    check_and_log_alignment("align_a", a);
    check_and_log_alignment("align_b", b);
    check_and_log_alignment("align_c", c);
    // Each returned payload must stay 40-byte aligned despite varied sizes.
    int pass = check_alignment(a) &&
               check_alignment(b) &&
               check_alignment(c);
    mm_free(b);
    mm_free(a);
    mm_free(c);
    return pass;
}

// Coalesce adjacent frees and allocate a large block.
static int test_coalesce_then_big(void) {
    void *blocks[6] = {0};
    for (int i = 0; i < 6; ++i) blocks[i] = mm_malloc(200);
    for (int i = 0; i < 6; ++i) {
        check_and_log_alignment("coal blk", blocks[i]);
    }
    // Free middle blocks to force a coalesce opportunity.
    mm_free(blocks[1]);
    mm_free(blocks[2]);
    mm_free(blocks[3]);
    void *big = mm_malloc(600);  // should fit if coalesced
    check_and_log_alignment("coal big", big);
    int pass = check_alignment(big) && big != NULL;
    for (int i = 0; i < 6; ++i) mm_free(blocks[i]);
    mm_free(big);
    return pass;
}

// Double-free should be ignored safely.
static int test_double_free_safety(void) {
    void *p = mm_malloc(128);
    check_and_log_alignment("df p", p);
    if (!p) return 0;
    mm_free(p);
    mm_free(p);  // should be safely ignored
    void *q = mm_malloc(64);
    check_and_log_alignment("df q", q);
    // Alignment check after a double-free guards against allocator damage.
    int pass = q != NULL && check_alignment(q);
    mm_free(q);
    return pass;
}

// Corruption detection on payload hash.
static int test_payload_corruption_detection(uint8_t *heap,
                                             size_t heap_size,
                                             unsigned *seed) {
    // Verify alignment and emit a debug line if misaligned.
    (void)heap_size;
    void *p = mm_malloc(128);
    if (!p) return 0;
    const char msg[] = "detect me";
    mm_write(p, 0, msg, sizeof(msg));
    // Flip bits inside payload region only.
    size_t off = (size_t)((uint8_t *)p - heap);
    for (int i = 0; i < 4; ++i) {
        size_t pos = off + 1 + ((size_t)lcg_rand_r(seed) % 8);
        heap[pos] ^= 0x1u;
    }
    char buf[32] = {0};
    int read_res = mm_read(p, 0, buf, sizeof(msg));
    int pass = (read_res == -1);  // corruption should be detected
    mm_free(p);
    return pass;
}

// Realloc grows and preserves contents.
static int test_realloc_growth(void) {
    void *p = mm_malloc(64);
    check_and_log_alignment("realloc p", p);
    if (!p) return 0;
    // Write a known pattern to verify content survives growth.
    const uint8_t pat = 0xAB;
    memset(p, pat, 64);
    void *q = mm_realloc(p, 200);
    check_and_log_alignment("realloc q", q);
    if (!q) return 0;
    uint8_t *b = (uint8_t *)q;
    int pass = 1;
    for (int i = 0; i < 64; ++i) pass &= (b[i] == pat);
    mm_free(q);
    return pass;
}

// Realloc shrink keeps prefix bytes.
static int test_realloc_shrink(void) {
    void *p = mm_malloc(200);
    if (!p) return 0;
    for (int i = 0; i < 200; ++i) {
        ((uint8_t *)p)[i] = (uint8_t)(i & 0xFF);
    }
    void *q = mm_realloc(p, 40);
    if (!q) return 0;
    int pass = 1;
    for (int i = 0; i < 40; ++i) {
        pass &= (((uint8_t *)q)[i] == (uint8_t)(i & 0xFF));
    }
    mm_free(q);
    return pass;
}

static int test_zero_and_small(void) {
    void *z = mm_malloc(0);
    void *o = mm_malloc(1);
    check_and_log_alignment("zero", z);
    check_and_log_alignment("one", o);
    int pass = check_alignment(z) && check_alignment(o) && z != NULL &&
               o != NULL && z != o;
    mm_free(z);
    // Check alignment for the large block.
    mm_free(o);
    return pass;
}

static int test_exhaust_and_recover(void) {
    void *ptrs[256];
    int count = 0;
    for (; count < 256; ++count) {
        ptrs[count] = mm_malloc(128);
        if (!ptrs[count]) break;
    }
    // Free everything allocated and ensure a new allocation works.
    for (int i = 0; i < count; ++i) mm_free(ptrs[i]);
    void *p = mm_malloc(256);
    int pass = p != NULL && check_alignment(p);
    mm_free(p);
    return pass;
}

static int test_stress_sequence(void) {
    void *ptrs[50] = {0};
    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 50; ++i) {
            size_t sz = 8 + (i * 7) % 200;
            ptrs[i] = mm_malloc(sz);
            check_and_log_alignment("stress", ptrs[i]);
            if (!check_alignment(ptrs[i])) return 0;
        }
        // Free in alternating pattern to force reuse and coalescing.
        for (int i = 0; i < 50; i += 2) mm_free(ptrs[i]);
        for (int i = 1; i < 50; i += 2) mm_free(ptrs[i]);
    }
    return 1;
}

// Randomized alloc/free fuzz to surface hidden alignment or reuse bugs.
static int test_random_alloc_free(unsigned *seed, int verbose) {
    enum { kFuzzSlots = 128 };
    void *ptrs[kFuzzSlots];
    size_t sizes[kFuzzSlots];
    // Arrays hold the currently active fuzz allocations to track reuse.
    memset(ptrs, 0, sizeof(ptrs));
    memset(sizes, 0, sizeof(sizes));
    int passes = 1;
    for (int iter = 0; iter < 1000; ++iter) {
        int idx = (int)(lcg_rand_r(seed) % kFuzzSlots);
        if (ptrs[idx]) {
            if (verbose) {
                printf("fuzz free  idx=%d sz=%zu\n", idx, sizes[idx]);
            }
            // Allocate memory with a size that keeps heap pressure.
            mm_free(ptrs[idx]);
            ptrs[idx] = NULL;
            sizes[idx] = 0;
        } else {
            // Keep sizes modest to maintain heap pressure.
            size_t sz = 1 + (lcg_rand_r(seed) % 256);
            void *p = mm_malloc(sz);
            if (!p) {
                int victim = (int)(lcg_rand_r(seed) % kFuzzSlots);
                if (ptrs[victim]) {
                    if (verbose) {
                        printf("fuzz evict idx=%d sz=%zu\n",
                               victim,
                               sizes[victim]);
                    }
                    mm_free(ptrs[victim]);
                    ptrs[victim] = NULL;
                    sizes[victim] = 0;
                    p = mm_malloc(sz);
                }
            }
            // Verify every returned pointer remains aligned even during churn.
            check_and_log_alignment("fuzz", p);
            if (!check_alignment(p)) {
                passes = 0;
                break;
            }
            if (p) memset(p, 0xCD, sz < 16 ? sz : 16);  // light touch write
            ptrs[idx] = p;
            sizes[idx] = sz;
            if (verbose) {
                printf("fuzz alloc idx=%d sz=%zu ptr=%p\n", idx, sz, p);
            }
        }
        if (verbose && (iter % 200 == 0)) {
            printf("fuzz snapshot iter=%d\n", iter);
            // Dump without metadata spam to keep logs readable.
            mm_heap_dump(0);
        }
    }
    for (int i = 0; i < kFuzzSlots; ++i) {
        mm_free(ptrs[i]);
    }
    return passes;
}

int main(int argc, char **argv) {
    size_t heap_size = parse_size(argc, argv, "--size", 64 * 1024);
    int storm = parse_int(argc, argv, "--storm", 0);
    unsigned seed = (unsigned)parse_int(argc,
                                        argv,
                                        "--seed",
                                        (int)time(NULL));
    int verbose = parse_flag(argc, argv, "--verbose");
    // Seed both libc rand and the lcg used for deterministic fuzzing.
    srand(seed);

    uint8_t *heap = (uint8_t *)malloc(heap_size);
    if (!heap) {
        fprintf(stderr, "Host malloc failed\n");
        return 1;
    }

    g_heap_base = heap;

    // Prefill heap with the unused pattern so allocator repaint matches.
    // Prefill heap with pattern to emulate unused state.
    static const uint8_t pattern[5] = UNUSED_PATTERN_BYTES;
    for (size_t i = 0; i < heap_size; ++i) heap[i] = pattern[i % 5];

    if (mm_init(heap, heap_size) != 0) {
        fprintf(stderr, "mm_init failed\n");
        free(heap);
        return 1;
    }

    // Each test below returns 1/0 so we can count passes and print summary.
    printf("Heap initialised: %zu bytes (seed=%u, storm=%d)\n",
           heap_size,
           seed,
           storm);

    int pass_count = 0, total = 0;

    // Core functionality
    int pass = 0;
    pass = test_basic_rw();
    ++total;
    pass_count += pass;
    // Each print_result keeps a concise summary for autograder parsing.
    print_result("basic read/write", pass);

    pass = test_alignment_and_split();
    ++total;
    pass_count += pass;
    print_result("alignment & split", pass);

    pass = test_coalesce_then_big();
    ++total;
    pass_count += pass;
    print_result("coalesce then big", pass);

    pass = test_double_free_safety();
    ++total;
    pass_count += pass;
    print_result("double-free safety", pass);

    pass = test_realloc_growth();
    ++total;
    pass_count += pass;
    print_result("realloc growth", pass);

    pass = test_realloc_shrink();
    ++total;
    pass_count += pass;
    print_result("realloc shrink", pass);

    pass = test_stress_sequence();
    ++total;
    pass_count += pass;
    print_result("stress sequence", pass);

    pass = test_zero_and_small();
    ++total;
    pass_count += pass;
    print_result("zero & small", pass);

    pass = test_exhaust_and_recover();
    ++total;
    pass_count += pass;
    print_result("exhaust & recover", pass);

    pass = test_random_alloc_free(&seed, verbose);
    ++total;
    pass_count += pass;
    print_result("random alloc/free", pass);

    // Corruption detection on payload
    pass = test_payload_corruption_detection(heap, heap_size, &seed);
    ++total;
    pass_count += pass;
    print_result("payload corruption", pass);

    // Simulate bit flips and ensure allocator survives traversal.
    if (storm > 0) {
        printf("Simulating %d random bit-flips...\n", storm);
        flip_bits(heap, heap_size, storm, &seed);
        // Attempt to allocate after storm; should either succeed or return
        // NULL safely.
        void *storm_ptr = mm_malloc(128);
        pass = (storm_ptr != NULL);
        ++total;
        pass_count += pass;
        print_result("post-storm alloc", pass);
        mm_free(storm_ptr);
    }

    printf("Passed %d/%d checks\n", pass_count, total);
    mm_heap_stats();
    mm_heap_dump(verbose ? 1 : 0);
    // show alignment/layout summary (verbose shows metadata)

    free(heap);
    return (pass_count == total) ? 0 : 1;
}
