#include "allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Brownout-focused test harness. This mirrors the autograder flags and adds
// heavy alignment/corruption checks so storms and random flips are surfaced
// early. Usage: ./runme --seed N --storm N --size N [--verbose]

static uint8_t *g_heap_base = NULL;  // used for alignment calculations

// Minimal copies of allocator metadata layouts for brownout simulation.
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t size;
    uint32_t inv_size;
    uint32_t status;
    uint64_t reserved_a;
    uint64_t reserved_b;
    uint32_t canary;
    uint32_t checksum;
} MetaHeader;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t size;
    uint32_t inv_size;
    uint32_t checksum;
} MetaFooter;

#define HEADER_SIZE 40u
#define FOOTER_SIZE 16u
#define BLOCK_MAGIC 0xC0FFEE01u
#define FOOTER_MAGIC 0xF00DBA5Eu

// Simple rand_r replacement to stay portable.
static unsigned lcg_rand_r(unsigned *seed) {
    *seed = (uint32_t)(1103515245u * (*seed) + 12345u);
    return *seed;
}

static size_t parse_size(int argc, char **argv, const char *flag, size_t def) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) return (size_t)strtoull(argv[i + 1], NULL, 10);
    }
    return def;
}

static int parse_int(int argc, char **argv, const char *flag, int def) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) return atoi(argv[i + 1]);
    }
    return def;
}

static int parse_flag(int argc, char **argv, const char *flag) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) return 1;
    }
    return 0;
}

// Randomly toggle bits in the heap to simulate brownout storms.
static void flip_bits(uint8_t *heap, size_t heap_size, int flips, unsigned *seed) {
    for (int i = 0; i < flips; ++i) {
        size_t pos = (size_t)lcg_rand_r(seed) % heap_size;
        uint8_t bit = (uint8_t)(1u << (lcg_rand_r(seed) % 8));
        heap[pos] ^= bit;
    }
}

static double now_sec(void) {
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

static int check_alignment(void *p) {
    if (!p || !g_heap_base) return 0;
    return (((uintptr_t)p - (uintptr_t)g_heap_base) % MM_ALIGNMENT) == 0;
}

static void print_result(const char *name, int pass) {
    printf("[%-28s] %s\n", name, pass ? "ok" : "FAIL");
}

static void check_and_log_alignment(const char *label, void *p) {
    if (!p) {
        printf("[align-debug] %s is NULL\n", label);
        return;
    }
    if (!check_alignment(p)) {
        unsigned long mod = (unsigned long)(((uintptr_t)p - (uintptr_t)g_heap_base) % MM_ALIGNMENT);
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
    void *a = mm_malloc(1);
    void *b = mm_malloc(39);
    void *c = mm_malloc(80);
    check_and_log_alignment("align_a", a);
    check_and_log_alignment("align_b", b);
    check_and_log_alignment("align_c", c);
    int pass = check_alignment(a) && check_alignment(b) && check_alignment(c);
    mm_free(b);
    mm_free(a);
    mm_free(c);
    return pass;
}

// Coalesce adjacent frees and allocate a large block.
static int test_coalesce_then_big(void) {
    void *blocks[6] = {0};
    for (int i = 0; i < 6; ++i) blocks[i] = mm_malloc(200);
    for (int i = 0; i < 6; ++i) check_and_log_alignment("coal blk", blocks[i]);
    mm_free(blocks[1]);
    mm_free(blocks[2]);
    mm_free(blocks[3]);
    void *big = mm_malloc(600);
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
    mm_free(p);
    void *q = mm_malloc(64);
    check_and_log_alignment("df q", q);
    int pass = q != NULL && check_alignment(q);
    mm_free(q);
    return pass;
}

// Corruption detection on payload hash.
static int test_payload_corruption_detection(uint8_t *heap, size_t heap_size, unsigned *seed) {
    (void)heap_size;
    void *p = mm_malloc(128);
    if (!p) return 0;
    const char msg[] = "detect me";
    mm_write(p, 0, msg, sizeof(msg));
    size_t off = (size_t)((uint8_t *)p - heap);
    for (int i = 0; i < 4; ++i) {
        size_t pos = off + 1 + ((size_t)lcg_rand_r(seed) % 8);
        heap[pos] ^= 0x1u;
    }
    char buf[32] = {0};
    int read_res = mm_read(p, 0, buf, sizeof(msg));
    int pass = (read_res == -1);
    mm_free(p);
    return pass;
}

// Realloc grows and preserves contents.
static int test_realloc_growth(void) {
    void *p = mm_malloc(64);
    check_and_log_alignment("realloc p", p);
    if (!p) return 0;
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
    for (int i = 0; i < 200; ++i) ((uint8_t *)p)[i] = (uint8_t)(i & 0xFF);
    void *q = mm_realloc(p, 40);
    if (!q) return 0;
    int pass = 1;
    for (int i = 0; i < 40; ++i) pass &= (((uint8_t *)q)[i] == (uint8_t)(i & 0xFF));
    mm_free(q);
    return pass;
}

static int test_zero_and_small(void) {
    void *z = mm_malloc(0);
    void *o = mm_malloc(1);
    check_and_log_alignment("zero", z);
    check_and_log_alignment("one", o);
    int pass = check_alignment(z) && check_alignment(o) && z != NULL && o != NULL && z != o;
    mm_free(z);
    mm_free(o);
    return pass;
}

static MetaHeader *get_header(uint8_t *heap, void *payload) {
    size_t off = (size_t)((uint8_t *)payload - heap);
    if (off < HEADER_SIZE) return NULL;
    return (MetaHeader *)(heap + off - HEADER_SIZE);
}

static MetaFooter *get_footer(uint8_t *heap, void *payload, MetaHeader *h) {
    if (!h) return NULL;
    size_t hoff = (size_t)((uint8_t *)payload - heap) - HEADER_SIZE;
    size_t foff = hoff + h->size - FOOTER_SIZE;
    return (MetaFooter *)(heap + foff);
}

// Simulate a brownout that half-updates the header (size changed, checksum left stale).
static int test_brownout_partial_header(uint8_t *heap) {
    void *p = mm_malloc(128);
    if (!p) return 0;
    const char msg[] = "partial header";
    mm_write(p, 0, msg, sizeof(msg));

    MetaHeader *h = get_header(heap, p);
    MetaFooter *f = get_footer(heap, p, h);
    if (!h || !f) return 0;

    // Change size field only (mimics interrupted write) and clear checksum.
    h->size += MM_ALIGNMENT;
    h->checksum = 0;

    char buf[32] = {0};
    int rc = mm_read(p, 0, buf, sizeof(msg));
    int pass = (rc == -1);  // allocator should reject corrupted metadata

    mm_free(p);  // allocator may quarantine internally
    (void)f;     // kept for symmetry
    return pass;
}

// Simulate a brownout that half-updates the footer (footer size diverges from header).
static int test_brownout_partial_footer(uint8_t *heap) {
    void *p = mm_malloc(96);
    if (!p) return 0;
    const char msg[] = "partial footer";
    mm_write(p, 0, msg, sizeof(msg));

    MetaHeader *h = get_header(heap, p);
    MetaFooter *f = get_footer(heap, p, h);
    if (!h || !f) return 0;

    f->size += MM_ALIGNMENT;
    f->checksum = 0;

    char buf[32] = {0};
    int rc = mm_read(p, 0, buf, sizeof(msg));
    int pass = (rc == -1);  // allocator should detect mismatch via footer

    mm_free(p);
    return pass;
}

// Simulate header status flip to free without updating checksum/footer.
static int test_brownout_status_flip(uint8_t *heap) {
    void *p = mm_malloc(64);
    if (!p) return 0;
    const char msg[] = "status flip";
    mm_write(p, 0, msg, sizeof(msg));

    MetaHeader *h = get_header(heap, p);
    MetaFooter *f = get_footer(heap, p, h);
    if (!h || !f) return 0;

    h->status = 0;     // pretend it was freed
    h->checksum = 0;   // stale checksum

    char buf[32] = {0};
    int rc = mm_read(p, 0, buf, sizeof(msg));
    int pass = (rc == -1);

    mm_free(p);
    (void)f;
    return pass;
}

// Simulate footer magic corruption with otherwise matching size.
static int test_brownout_footer_magic(uint8_t *heap) {
    void *p = mm_malloc(72);
    if (!p) return 0;
    const char msg[] = "footer magic";
    mm_write(p, 0, msg, sizeof(msg));

    MetaHeader *h = get_header(heap, p);
    MetaFooter *f = get_footer(heap, p, h);
    if (!h || !f) return 0;

    f->magic ^= 0x1u;  // flip a bit in magic

    char buf[32] = {0};
    int rc = mm_read(p, 0, buf, sizeof(msg));
    int pass = (rc == -1);

    mm_free(p);
    return pass;
}

static int test_exhaust_and_recover(void) {
    void *ptrs[256];
    int count = 0;
    for (; count < 256; ++count) {
        ptrs[count] = mm_malloc(128);
        if (!ptrs[count]) break;
    }
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
    memset(ptrs, 0, sizeof(ptrs));
    memset(sizes, 0, sizeof(sizes));
    int passes = 1;
    for (int iter = 0; iter < 1000; ++iter) {
        int idx = (int)(lcg_rand_r(seed) % kFuzzSlots);
        if (ptrs[idx]) {
            if (verbose) printf("fuzz free  idx=%d sz=%zu\n", idx, sizes[idx]);
            mm_free(ptrs[idx]);
            ptrs[idx] = NULL;
            sizes[idx] = 0;
        } else {
            size_t sz = 1 + (lcg_rand_r(seed) % 256);
            void *p = mm_malloc(sz);
            if (!p) {
                int victim = (int)(lcg_rand_r(seed) % kFuzzSlots);
                if (ptrs[victim]) {
                    if (verbose) printf("fuzz evict idx=%d sz=%zu\n", victim, sizes[victim]);
                    mm_free(ptrs[victim]);
                    ptrs[victim] = NULL;
                    sizes[victim] = 0;
                    p = mm_malloc(sz);
                }
            }
            check_and_log_alignment("fuzz", p);
            if (!check_alignment(p)) { passes = 0; break; }
            if (p) memset(p, 0xCD, sz < 16 ? sz : 16);
            ptrs[idx] = p;
            sizes[idx] = sz;
            if (verbose) printf("fuzz alloc idx=%d sz=%zu ptr=%p\n", idx, sz, p);
        }
        if (verbose && (iter % 200 == 0)) {
            printf("fuzz snapshot iter=%d\n", iter);
            mm_heap_dump(0);
        }
    }
    for (int i = 0; i < kFuzzSlots; ++i) mm_free(ptrs[i]);
    return passes;
}

// Simple micro-benchmark to gather throughput numbers for the report.
static void run_bench(uint8_t *heap, size_t heap_size, int iters, int flip_batch, unsigned *seed, const char *label) {
    enum { kSlots = 128 };
    void *ptrs[kSlots];
    size_t sizes[kSlots];
    memset(ptrs, 0, sizeof(ptrs));
    memset(sizes, 0, sizeof(sizes));

    double t0 = now_sec();
    for (int i = 0; i < iters; ++i) {
        if (flip_batch > 0 && (i % 200) == 0) {
            flip_bits(heap, heap_size, flip_batch, seed);
        }

        int idx = (int)(lcg_rand_r(seed) % kSlots);
        if (ptrs[idx]) {
            mm_free(ptrs[idx]);
            ptrs[idx] = NULL;
            sizes[idx] = 0;
        } else {
            size_t sz = 1 + (lcg_rand_r(seed) % 512);
            void *p = mm_malloc(sz);
            ptrs[idx] = p;
            sizes[idx] = sz;
            if (p) {
                uint8_t byte = (uint8_t)(sz ^ idx);
                mm_write(p, 0, &byte, 1);
            }
        }
    }
    for (int i = 0; i < kSlots; ++i) mm_free(ptrs[i]);

    double t1 = now_sec();
    double secs = t1 - t0;
    double ops = (double)iters;
    double ops_sec = secs > 0.0 ? ops / secs : 0.0;
    double ns_per = secs > 0.0 ? (secs * 1e9) / ops : 0.0;

    printf("[bench %-6s] iters=%d flips/200=%d time=%.3f s ops/s=%.1f ns/op=%.1f\n",
           label,
           iters,
           flip_batch,
           secs,
           ops_sec,
           ns_per);
}

int main(int argc, char **argv) {
    size_t heap_size = parse_size(argc, argv, "--size", 64 * 1024);
    int storm = parse_int(argc, argv, "--storm", 0);
    unsigned seed = (unsigned)parse_int(argc, argv, "--seed", (int)time(NULL));
    int verbose = parse_flag(argc, argv, "--verbose");
    int bench = parse_flag(argc, argv, "--bench");
    int bench_iters = parse_int(argc, argv, "--bench-iters", 20000);
    int bench_flips = parse_int(argc, argv, "--bench-flips", 8);
    int bench_warmup = parse_int(argc, argv, "--bench-warmup", 2000);
    srand(seed);

    uint8_t *heap = (uint8_t *)malloc(heap_size);
    if (!heap) {
        fprintf(stderr, "Host malloc failed\n");
        return 1;
    }

    g_heap_base = heap;

    static const uint8_t pattern[5] = UNUSED_PATTERN_BYTES;
    for (size_t i = 0; i < heap_size; ++i) heap[i] = pattern[i % 5];

    if (mm_init(heap, heap_size) != 0) {
        fprintf(stderr, "mm_init failed\n");
        free(heap);
        return 1;
    }

    printf("Heap initialised: %zu bytes (seed=%u, storm=%d)\n", heap_size, seed, storm);

    int pass_count = 0, total = 0, pass = 0;

    pass = test_basic_rw();           ++total; pass_count += pass; print_result("basic read/write", pass);
    pass = test_alignment_and_split();++total; pass_count += pass; print_result("alignment & split", pass);
    pass = test_coalesce_then_big();  ++total; pass_count += pass; print_result("coalesce then big", pass);
    pass = test_double_free_safety(); ++total; pass_count += pass; print_result("double-free safety", pass);
    pass = test_realloc_growth();     ++total; pass_count += pass; print_result("realloc growth", pass);
    pass = test_realloc_shrink();     ++total; pass_count += pass; print_result("realloc shrink", pass);
    pass = test_stress_sequence();    ++total; pass_count += pass; print_result("stress sequence", pass);
    pass = test_zero_and_small();     ++total; pass_count += pass; print_result("zero & small", pass);
    pass = test_exhaust_and_recover();++total; pass_count += pass; print_result("exhaust & recover", pass);
    pass = test_random_alloc_free(&seed, verbose);
                                      ++total; pass_count += pass; print_result("random alloc/free", pass);
    pass = test_payload_corruption_detection(heap, heap_size, &seed);
                                      ++total; pass_count += pass; print_result("payload corruption", pass);
    pass = test_brownout_partial_header(heap);
                                      ++total; pass_count += pass; print_result("brownout header", pass);
    pass = test_brownout_partial_footer(heap);
                                      ++total; pass_count += pass; print_result("brownout footer", pass);
    pass = test_brownout_status_flip(heap);
                                      ++total; pass_count += pass; print_result("brownout status", pass);
    pass = test_brownout_footer_magic(heap);
                                      ++total; pass_count += pass; print_result("brownout footer magic", pass);

    // Brownout storm: flip random bits and attempt to continue allocating.
    if (storm > 0) {
        printf("Simulating %d random bit-flips...\n", storm);
        flip_bits(heap, heap_size, storm, &seed);
        void *storm_ptr = mm_malloc(128);
        pass = (storm_ptr != NULL);
        ++total; pass_count += pass; print_result("post-storm alloc", pass);
        mm_free(storm_ptr);
    }

    if (bench) {
        if (bench_warmup > 0) {
            run_bench(heap, heap_size, bench_warmup, 0, &seed, "warmup");
        }
        printf("Running benchmarks (iters=%d flips/200=%d, warmup=%d)\n", bench_iters, bench_flips, bench_warmup);
        run_bench(heap, heap_size, bench_iters, 0, &seed, "clear");
        run_bench(heap, heap_size, bench_iters, bench_flips, &seed, "storm");
    }

    printf("Passed %d/%d checks\n", pass_count, total);
    mm_heap_stats();
    mm_heap_dump(verbose ? 1 : 0);

    free(heap);
    return (pass_count == total) ? 0 : 1;
}
