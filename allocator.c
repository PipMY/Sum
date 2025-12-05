#include "allocator.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>

// ============================================================================
//  DESIGN OVERVIEW
// ============================================================================
// This allocator is self-contained and stores *all* metadata inside the caller-
// provided heap buffer. It is designed for robustness against memory
// corruption,
// not speed. It uses no external data structures, no malloc(), and no pointers
// that could be flipped by bit errors. Every allocation block is laid out as:
//
//   [ Header (40 bytes) ] [ Payload ... ] [ Footer (16 bytes) ]
//
// The header & footer contain redundant fields (magic, size, ~size, checksums)
// to strongly detect metadata corruption. Blocks can be in three states:
//   - allocated
//   - free
//   - quarantined (bad block; no longer used or coalesced)
//
// Memory alignment is enforced on 40-byte boundaries (MM_ALIGNMENT). Payloads
// returned to users are aligned as required by tests.
//
// Free blocks are NOT in a freelist (too fragile); instead, the allocator
// linearly scans the entire heap to find space. This is slower but resilient to
// corruption.
//
// When free, payload contents are overwritten with a repeating 5-byte pattern.
// The pattern is detected from the initial heap so tests can use arbitrary
// patterns.
// ============================================================================

// ---- Constants ------------------------------------------------------------
#define BLOCK_MAGIC        0xC0FFEE01u      // Identifies valid headers
#define FOOTER_MAGIC       0xF00DBA5Eu      // Identifies valid footers
#define HEADER_SIZE        40u              // Verified by static_assert
#define FOOTER_SIZE        16u
#define MIN_PAYLOAD        8u               // Minimum client payload
#define FLAG_ALLOCATED     0x1u
#define FLAG_QUARANTINED   0x2u

#ifndef UNUSED_PATTERN_BYTES
#define UNUSED_PATTERN_BYTES {0xA5u, 0x5Au, 0x3Cu, 0xC3u, 0x7Eu}
#endif

// ============================================================================
// HEADER & FOOTER TYPE DEFINITIONS
// ============================================================================
typedef struct __attribute__((packed)) BlockHeader {
    uint32_t magic;        // Must be BLOCK_MAGIC
    uint32_t size;         // Total block size, including header+footer
    uint32_t inv_size;     // Bitwise inverse ~size for redundancy
    uint32_t status;       // FLAG_ALLOCATED / FLAG_QUARANTINED

    // Two reserved 64-bit fields used for payload hash & optional aux info.
    uint64_t reserved_a;   // Typically the payload integrity hash
    uint64_t reserved_b;   // Unused auxiliary field

    uint32_t canary;       // Canary derived from block offset & size
    uint32_t checksum;     // Header integrity checksum
} BlockHeader;

_Static_assert(sizeof(BlockHeader) == HEADER_SIZE,
               "Header must be exactly 40 bytes");

// Footer mirrors size + ~size + checksum.
typedef struct __attribute__((packed)) BlockFooter {
    uint32_t magic;
    uint32_t size;
    uint32_t inv_size;
    uint32_t checksum;
} BlockFooter;

_Static_assert(sizeof(BlockFooter) == FOOTER_SIZE,
               "Footer must be exactly 16 bytes");

// ============================================================================
// GLOBAL STATE
// ============================================================================
static uint8_t *g_heap = NULL;        // Working heap pointer
static uint8_t *g_heap_base = NULL;   // Original heap pointer (for alignment)
static size_t g_heap_size = 0;        // Usable aligned heap size
static bool g_ready = false;          // Set after mm_init

// Coarse-grained mutex to make the public API thread-safe. Static helpers
// assume the caller already holds the lock.
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOCK()   pthread_mutex_lock(&g_lock)
#define UNLOCK() pthread_mutex_unlock(&g_lock)

static uint8_t g_unused_pattern[5] = UNUSED_PATTERN_BYTES;
static size_t g_pattern_phase = 0;    // Keeps pattern aligned on repaint
static bool g_dbg_brown = false;      // Enable verbose brownout debugging

#define DBG_BROWN(...)              \
    do {                            \
        if (g_dbg_brown) {          \
            fprintf(stderr, __VA_ARGS__); \
        }                           \
    } while (0)

// ============================================================================
// UTILITY HELPERS
// ============================================================================

// Align value upward to next multiple of align.
static inline size_t align_up(size_t v, size_t align) {
    if (align == 0) return v;
    size_t rem = v % align;
    return rem ? v + (align - rem) : v;
}

// Align value downward.
static inline size_t align_down(size_t v, size_t align) {
    if (align == 0) return v;
    return v - (v % align);
}

// Check if [off, off+len) lies inside heap.
static inline bool in_heap(size_t off, size_t len) {
    return off <= g_heap_size && len <= g_heap_size && off + len <= g_heap_size;
}

// Detect 5-byte filler pattern in initial heap.
static void detect_unused_pattern(const uint8_t *heap, size_t heap_size) {
    if (!heap || heap_size < 5) return;

    // Candidate = first 5 bytes.
    uint8_t candidate[5];
    for (size_t i = 0; i < 5; ++i) candidate[i] = heap[i];

    // Verify heap begins with repeating pattern.
    size_t sample = heap_size < 25 ? heap_size : 25;
    for (size_t i = 0; i < sample; ++i) {
        if (heap[i] != candidate[i % 5]) return;
    }
    // Adopt pattern.
    for (size_t i = 0; i < 5; ++i) g_unused_pattern[i] = candidate[i];
}

// Compute payload offset & size for a block, checking heap bounds.
static bool payload_bounds(size_t off, uint32_t size,
                           size_t *payload_off, size_t *payload_size) {
    if (size < HEADER_SIZE + FOOTER_SIZE) return false;
    size_t poff = off + HEADER_SIZE;
    size_t psz = (size_t)size - HEADER_SIZE - FOOTER_SIZE;
    if (!in_heap(poff, psz)) return false;
    if (payload_off) *payload_off = poff;
    if (payload_size) *payload_size = psz;
    return true;
}

// Hash payload for integrity checks (FNV-1a 64 bit).
static uint64_t payload_hash(size_t off, uint32_t size) {
    size_t poff = 0, psz = 0;
    if (!payload_bounds(off, size, &poff, &psz)) return 0;

    const uint8_t *p = g_heap + poff;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < psz; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

// Forward declarations
typedef enum { BLOCK_OK = 0, BLOCK_CORRUPT = 1, BLOCK_FATAL = 2 } block_check_t;
static bool block_is_free(const BlockHeader *h);
static bool block_is_quarantined(const BlockHeader *h);

// Create deterministic canary.
static uint32_t calc_canary(size_t offset, uint32_t size) {
    uint32_t v = (uint32_t)offset ^ (size << 7) ^ BLOCK_MAGIC;
    v ^= (v >> 11);
    v ^= (v << 3);
    return v;
}

// Compute header checksum (FNV-like).
static uint32_t checksum_header(const BlockHeader *h) {
    const uint8_t *bytes = (const uint8_t *)h;
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < HEADER_SIZE - sizeof(uint32_t); ++i) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    hash ^= FOOTER_MAGIC;
    return hash;
}

// Compute footer checksum.
static uint32_t checksum_footer(uint32_t size, uint32_t inv_size) {
    uint32_t hash = 0x9E3779B9u;
    hash ^= size + 0x85EBCA6Bu + (hash << 6) + (hash >> 2);
    hash ^= inv_size + 0xC2B2AE35u + (hash << 6) + (hash >> 2);
    hash ^= FOOTER_MAGIC;
    return hash;
}

// Helpers to get header/footer pointers.
static BlockHeader *hdr_at(size_t off) {
    if (!in_heap(off, HEADER_SIZE)) return NULL;
    return (BlockHeader *)(g_heap + off);
}
static BlockFooter *ftr_at(size_t off, uint32_t size) {
    if (size < HEADER_SIZE + FOOTER_SIZE) return NULL;
    size_t foff = off + size - FOOTER_SIZE;
    if (!in_heap(foff, FOOTER_SIZE)) return NULL;
    return (BlockFooter *)(g_heap + foff);
}

// Write header & footer.
static void write_header(size_t off, uint32_t size, uint32_t status) {
    BlockHeader *h = hdr_at(off);
    if (!h) return;
    h->magic = BLOCK_MAGIC;
    h->size = size;
    h->inv_size = ~size;
    h->status = status;
    h->reserved_a = 0;
    h->reserved_b = 0;
    h->canary = calc_canary(off, size);
    h->checksum = checksum_header(h);
}
static void write_footer(size_t off, uint32_t size) {
    BlockFooter *f = ftr_at(off, size);
    if (!f) return;
    f->magic = FOOTER_MAGIC;
    f->size = size;
    f->inv_size = ~size;
    f->checksum = checksum_footer(size, ~size);
}

// Update header extras (payload hash + aux).
static void set_header_extras(size_t off, uint64_t hash, uint64_t aux) {
    BlockHeader *h = hdr_at(off);
    if (!h) return;
    h->reserved_a = hash;
    h->reserved_b = aux;
    h->checksum = checksum_header(h);
}

// Paint freed payload with known pattern.
static void paint_free_payload(size_t off, uint32_t size) {
    size_t payload_off = off + HEADER_SIZE;
    size_t payload_size = 0;
    if (size >= HEADER_SIZE + FOOTER_SIZE)
        payload_size = size - HEADER_SIZE - FOOTER_SIZE;
    if (!in_heap(payload_off, payload_size)) return;

    size_t phase = (payload_off + g_pattern_phase) % 5;
    for (size_t i = 0; i < payload_size; ++i)
        g_heap[payload_off + i] = g_unused_pattern[(phase + i) % 5];
}

// Build fresh block (either allocated or free).
static void build_block(size_t off, uint32_t size, uint32_t status) {
    write_header(off, size, status);
    write_footer(off, size);

    if (status & FLAG_ALLOCATED) {
        size_t poff = 0, psz = 0;
        if (payload_bounds(off, size, &poff, &psz))
            memset(g_heap + poff, 0, psz);
    } else {
        paint_free_payload(off, size);
    }

    set_header_extras(off, payload_hash(off, size), 0);
}

// Create a quarantined span starting at off, using a hinted size. Returns
// the span length written, or 0 if there was not enough space to form a
// well-formed block.
static size_t quarantine_span(size_t off, uint32_t hint_size) {
    size_t max_size = align_down(g_heap_size - off, MM_ALIGNMENT);
    if (max_size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) return 0;

    size_t span = align_up(hint_size ? hint_size : MM_ALIGNMENT, MM_ALIGNMENT);
    if (span < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD)
        span = HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD;
    if (span > max_size) span = max_size;
    if (span > UINT32_MAX) span = UINT32_MAX;

    build_block(off, (uint32_t)span, FLAG_QUARANTINED);
    return span;
}

// Try to recover a damaged header using a valid footer.
static bool recover_header_from_footer(size_t off) {
    // Scan for a plausible footer on MM_ALIGNMENT boundaries.
    size_t start = off + HEADER_SIZE + MIN_PAYLOAD;
    if (start + FOOTER_SIZE > g_heap_size) return false;

    DBG_BROWN("[brown] recover start off=%zu start=%zu\n", off, start);

    for (size_t foff = start; foff + FOOTER_SIZE <= g_heap_size;
         foff += MM_ALIGNMENT) {
        BlockFooter *f = (BlockFooter *)(g_heap + foff);

        uint32_t size = f->size;
        if (f->magic != FOOTER_MAGIC) continue;
        if (f->inv_size != ~size) continue;
        if (checksum_footer(size, ~size) != f->checksum) continue;
        if (size % MM_ALIGNMENT != 0) continue;
        if (size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) continue;
        if (!in_heap(off, size)) continue;
        if (foff != off + size - FOOTER_SIZE) continue;

        DBG_BROWN("[brown] recover hit footer off=%zu size=%u\n",
                  foff,
                  size);
        // Rebuild header as allocated block.
        write_header(off, size, FLAG_ALLOCATED);
        set_header_extras(off, payload_hash(off, size), 0);
        return true;
    }

    DBG_BROWN("[brown] recover failed off=%zu\n", off);
    return false;
}

// Validate block structure (header + footer).
static block_check_t validate_block(size_t off, BlockHeader **out_h) {
    BlockHeader *h = hdr_at(off);
    if (!h) return BLOCK_FATAL;
    uint32_t size = h->size;

restart:
    // If header invalid, attempt recovery from footer.
    if (h->magic != BLOCK_MAGIC || h->inv_size != ~size ||
        size % MM_ALIGNMENT != 0 ||
        size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD ||
        !in_heap(off, size)) {
        DBG_BROWN("[brown] invalid header off=%zu magic=0x%x size=%u\n",
                  off,
                  h ? h->magic : 0,
                  h ? h->size : 0);
        if (recover_header_from_footer(off)) {
            h = hdr_at(off);
            if (!h) return BLOCK_FATAL;
            size = h->size;
            goto restart;
        }

        // Cannot fully recover.
        if (h->magic != BLOCK_MAGIC)
            return BLOCK_FATAL;
        return BLOCK_CORRUPT;
    }

    // Canary & checksum checks.
    if (h->canary != calc_canary(off, size)) {
        DBG_BROWN("[brown] canary mismatch off=%zu size=%u\n", off, size);
        return BLOCK_CORRUPT;
    }
    if (h->checksum != checksum_header(h)) {
        DBG_BROWN("[brown] header checksum bad off=%zu size=%u\n",
                  off,
                  size);
        return BLOCK_CORRUPT;
    }

    // Footer checks.
    BlockFooter *f = ftr_at(off, size);
    if (!f) return BLOCK_CORRUPT;
    if (f->magic != FOOTER_MAGIC) {
        DBG_BROWN("[brown] footer magic bad off=%zu size=%u\n", off, size);
        return BLOCK_CORRUPT;
    }
    if (f->size != size || f->inv_size != ~size) {
        DBG_BROWN("[brown] footer size bad off=%zu size=%u\n", off, size);
        return BLOCK_CORRUPT;
    }
    if (f->checksum != checksum_footer(size, ~size)) {
        DBG_BROWN("[brown] footer checksum bad off=%zu size=%u\n",
                  off,
                  size);
        return BLOCK_CORRUPT;
    }

    // Compare payload hash if free or quarantined.
    uint64_t expected = h->reserved_a;
    uint64_t actual = payload_hash(off, size);
    if (block_is_quarantined(h)) {
        if (expected != actual) {
            DBG_BROWN("[brown] quarant hash mismatch off=%zu size=%u\n",
                      off,
                      size);
            return BLOCK_CORRUPT;
        }
    } else if (block_is_free(h)) {
        if (expected != actual) {
            // Fix corrupted free payload.
            DBG_BROWN("[brown] free hash repaint off=%zu size=%u\n",
                      off,
                      size);
            paint_free_payload(off, size);
            set_header_extras(off, payload_hash(off, size), h->reserved_b);
        }
    }

    if (out_h) *out_h = h;
    return BLOCK_OK;
}

// Mark block as quarantined; never reused or merged.
static void quarantine_block(size_t off, uint32_t size) {
    BlockHeader *h = hdr_at(off);
    if (!h || !in_heap(off, size)) return;
    uint32_t status = (h->status | FLAG_QUARANTINED) & ~FLAG_ALLOCATED;
    DBG_BROWN("[brown] quarantine off=%zu size=%u\n", off, size);
    write_header(off, size, status);
    write_footer(off, size);
    set_header_extras(off, payload_hash(off, size), 0);
}

// Move to next block by size.
static size_t next_block_offset(size_t off, uint32_t size) {
    size_t next = off + size;
    return (next >= g_heap_size) ? g_heap_size : next;
}

static bool block_is_free(const BlockHeader *h) {
    return !(h->status & FLAG_ALLOCATED) && !(h->status & FLAG_QUARANTINED);
}
static bool block_is_quarantined(const BlockHeader *h) {
    return (h->status & FLAG_QUARANTINED) != 0;
}

// Coalesce adjacent free blocks.
// Merge the current free block with adjacent free neighbors. Corrupt neighbors
// are quarantined instead of merged so damage cannot propagate.
static void coalesce_with_neighbors(size_t off, BlockHeader *h) {
    uint32_t size = h->size;

    // Forward merge
    size_t next_off = next_block_offset(off, size);
    if (next_off + HEADER_SIZE <= g_heap_size) {
        BlockHeader *nh = hdr_at(next_off);
        if (nh) {
            block_check_t r = validate_block(next_off, &nh);
            if (r == BLOCK_OK && block_is_free(nh)) {
                size += nh->size;
                build_block(off, size, 0);
                h = hdr_at(off);
                size = h ? h->size : size;
            } else if (r == BLOCK_CORRUPT) {
                quarantine_block(next_off, nh ? nh->size : 0);
            }
        }
    }

    // Backward merge
    if (off >= FOOTER_SIZE) {
        size_t foff = off - FOOTER_SIZE;
        BlockFooter *pf = (BlockFooter *)(g_heap + foff);
        uint32_t psize = 0;

        if (in_heap(foff, FOOTER_SIZE) &&
            pf->magic == FOOTER_MAGIC && pf->inv_size == ~pf->size)
            psize = pf->size;

        if (psize >= HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD && off >= psize) {
            size_t prev_off = off - psize;
            BlockHeader *ph = hdr_at(prev_off);
            if (ph) {
                block_check_t r = validate_block(prev_off, &ph);
                if (r == BLOCK_OK && block_is_free(ph)) {
                    size_t new_size = psize + h->size;
                    build_block(prev_off, new_size, 0);
                    off = prev_off;
                    h = hdr_at(off);
                    size = h->size;
                } else if (r == BLOCK_CORRUPT) {
                    quarantine_block(prev_off, ph ? ph->size : 0);
                }
            }
        }
    }
}

// Ensure mm_init() was called.
static int ensure_ready(void) {
    return g_ready ? 0 : -1;
}

// ============================================================================
// PUBLIC API: mm_init
// ============================================================================
// Initialize the allocator on top of the caller-provided buffer. All metadata
// lives inside that buffer; nothing is malloc'd from the host OS.
int mm_init(uint8_t *heap, size_t heap_size) {
    if (!heap || heap_size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD)
        return -1;

    g_dbg_brown = getenv("MM_BROWNOUT_DEBUG") != NULL;
    if (g_dbg_brown) {
        fprintf(stderr, "[brown] debug enabled\n");
    }

    detect_unused_pattern(heap, heap_size);
    g_pattern_phase = 0;

    g_heap_base = heap;
    g_heap = heap;
    g_heap_size = align_down(heap_size, MM_ALIGNMENT);
    if (g_heap_size < HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD)
        return -1;

    // Seed the heap with a single free block that spans the aligned region.
    build_block(0, g_heap_size, 0);

    g_ready = true;
    return 0;
}

// ============================================================================
// PUBLIC API: mm_malloc
// ============================================================================
void *mm_malloc(size_t size) {
    void *ret = NULL;
    LOCK();

    if (ensure_ready() != 0) goto out;
    if (size == 0) size = 1;

    // If storms have destroyed metadata, we optionally salvage by rebuilding
    // the heap once. Guard with a flag to avoid infinite retries.
    bool retried_salvage = false;
    bool did_repair_pass = false;

    // Compute total block size needed (payload + header + footer), rounded up
    // so both metadata and payload respect MM_ALIGNMENT.
retry: ;
    size_t payload = align_up(size, MM_ALIGNMENT);
    size_t needed = align_up(payload + HEADER_SIZE + FOOTER_SIZE,
                             MM_ALIGNMENT);
    if (needed > g_heap_size) goto out;

    size_t off = 0;
    while (off + HEADER_SIZE <= g_heap_size) {
        if (off % MM_ALIGNMENT != 0) {
            off = align_up(off, MM_ALIGNMENT);
            continue;
        }

        BlockHeader *h = NULL;
        block_check_t r = validate_block(off, &h);

            if (r == BLOCK_FATAL) {
            // Unknown or unrecoverable metadata. Replace with a small
            // quarantined span so future scans see well-formed blocks.
            DBG_BROWN("[brown] fatal block off=%zu\n", off);
            size_t span = quarantine_span(off, MM_ALIGNMENT);
            off += span ? span : MM_ALIGNMENT;
                continue;
        } else if (r == BLOCK_CORRUPT) {
            uint32_t suspect = h ? h->size : MM_ALIGNMENT;
            if (suspect < MM_ALIGNMENT) suspect = MM_ALIGNMENT;
            DBG_BROWN("[brown] corrupt block off=%zu size=%u\n",
                      off,
                      suspect);
            size_t span = quarantine_span(off, suspect);
            off += span ? span : align_up(suspect, MM_ALIGNMENT);
            continue;
        }

        // Valid block. Check if free & large enough.
        if (block_is_free(h) && h->size >= needed) {
            uint32_t original = h->size;
            uint32_t remain = original - needed;

            if (remain >= HEADER_SIZE + FOOTER_SIZE + MIN_PAYLOAD) {
                // Split block.
                build_block(off, needed, FLAG_ALLOCATED);
                build_block(off + needed, remain, 0);
            } else {
                build_block(off, original, FLAG_ALLOCATED);
            }

            uint8_t *payload_ptr = g_heap + off + HEADER_SIZE;
            uintptr_t mod =
                (uintptr_t)(payload_ptr - g_heap_base) % MM_ALIGNMENT;
            if (mod != 0) {
                  printf("[align-debug] payload misaligned at off=%zu ptr=%p "
                      "mod=%lu\n",
                      off,
                      payload_ptr,
                      (unsigned long)mod);
                return NULL;
            }
            ret = payload_ptr;
            goto out;
        }

        off = next_block_offset(off, h->size);
    }

    // One-time repair sweep: rewrite any remaining corrupt/fatal spans into
    // quarantined blocks so the heap shape stays well-formed for future scans.
    if (!did_repair_pass) {
        did_repair_pass = true;
        size_t roff = 0;
        while (roff + HEADER_SIZE <= g_heap_size) {
            if (roff % MM_ALIGNMENT != 0) {
                roff = align_up(roff, MM_ALIGNMENT);
                continue;
            }
            BlockHeader *rh = NULL;
            block_check_t rr = validate_block(roff, &rh);
            if (rr == BLOCK_FATAL || rr == BLOCK_CORRUPT) {
                uint32_t hint = rh ? rh->size : MM_ALIGNMENT;
                if (hint < MM_ALIGNMENT) hint = MM_ALIGNMENT;
                size_t span = quarantine_span(roff, hint);
                roff += span ? span : MM_ALIGNMENT;
                continue;
            }
            roff = next_block_offset(roff, rh->size);
        }
        goto retry;
    }

    // If we reached here, every block looked fatal/corrupt or too small.
    // Attempt a one-time salvage by reinitialising the heap in-place to
    // restore allocator liveness after storms. Any surviving allocations are
    // likely already compromised, so prioritise availability.
    if (!retried_salvage && g_heap_base && g_heap_size > 0) {
        retried_salvage = true;
        mm_init(g_heap_base, g_heap_size);
        goto retry;
    }

out:
    UNLOCK();
    return ret;
}

// ============================================================================
// POINTER VALIDATION (shared by read/write/free)
// ============================================================================
// Validate a user payload pointer, returning the owning header and offset.
// Guards against misalignment, out-of-heap pointers, and corrupted metadata.
static block_check_t validate_payload_ptr(void *ptr,
                                          BlockHeader **out_h,
                                          size_t *out_off) {
    if (ensure_ready() != 0 || !ptr) return BLOCK_FATAL;

    uintptr_t p = (uintptr_t)ptr;
    uintptr_t base = (uintptr_t)g_heap_base;

    // Check user pointer alignment.
    if (((p - base) % MM_ALIGNMENT) != 0) {
        printf("[align-debug] payload pointer misaligned: %p\n", ptr);
        return BLOCK_FATAL;
    }

    if (p < base + HEADER_SIZE || p >= base + g_heap_size - FOOTER_SIZE)
        return BLOCK_FATAL;

    size_t off = (p - base) - HEADER_SIZE;
    BlockHeader *h = NULL;
    block_check_t r = validate_block(off, &h);

    if (r != BLOCK_OK) {
        if (recover_header_from_footer(off))
            r = validate_block(off, &h);
        if (r != BLOCK_OK) {
            DBG_BROWN("[brown] payload validate fail off=%zu code=%d\n",
                      off,
                      (int)r);
            return r;
        }
    }

    if (!h || !(h->status & FLAG_ALLOCATED) || block_is_quarantined(h))
        return BLOCK_FATAL;

    if (out_h) *out_h = h;
    if (out_off) *out_off = off;
    return BLOCK_OK;
}

// ============================================================================
// PUBLIC API: mm_read
// ============================================================================
// Copy bytes out of a block. Fails if pointers are invalid or if integrity
// checks (canary/hash) fail.
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    int ret = -1;
    LOCK();

    BlockHeader *h = NULL;
    size_t off = 0;
    block_check_t r = validate_payload_ptr(ptr, &h, &off);
    if (r != BLOCK_OK) goto out;

    size_t payload = h->size - HEADER_SIZE - FOOTER_SIZE;
    if (offset + len > payload) goto out;

    // Check payload hash before read to catch silent corruption.
    if (payload_hash(off, h->size) != h->reserved_a) {
        DBG_BROWN("[brown] read hash mismatch off=%zu size=%u\n",
                  off,
                  h->size);
        quarantine_block(off, h->size);
        goto out;
    }

    memcpy(buf, (uint8_t *)ptr + offset, len);
    ret = (int)len;

out:
    UNLOCK();
    return ret;
}

// ============================================================================
// PUBLIC API: mm_write
// ============================================================================
// Copy bytes into a block. Updates the stored payload hash if successful.
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
    int ret = -1;
    LOCK();

    BlockHeader *h = NULL;
    size_t off = 0;
    block_check_t r = validate_payload_ptr(ptr, &h, &off);
    if (r != BLOCK_OK) goto out;

    size_t payload = h->size - HEADER_SIZE - FOOTER_SIZE;
    if (offset + len > payload) goto out;

    // Verify existing payload hash before writing; corruption turns the block
    // into a quarantined, unreusable region.
    if (payload_hash(off, h->size) != h->reserved_a) {
        DBG_BROWN("[brown] write hash mismatch off=%zu size=%u\n",
                  off,
                  h->size);
        quarantine_block(off, h->size);
        goto out;
    }

    memcpy((uint8_t *)ptr + offset, src, len);
    set_header_extras(off, payload_hash(off, h->size), h->reserved_b);
    ret = (int)len;

out:
    UNLOCK();
    return ret;
}

// ============================================================================
// PUBLIC API: mm_free
// ============================================================================
// Mark a block as free and attempt to coalesce with neighbors. If validation
// fails, the block stays allocated to avoid mis-merging.
void mm_free(void *ptr) {
    LOCK();

    BlockHeader *h = NULL;
    size_t off = 0;
    block_check_t r = validate_payload_ptr(ptr, &h, &off);
    if (r != BLOCK_OK) goto out;

    if (!h || !h->status || block_is_quarantined(h)) goto out;

    build_block(off, h->size, 0);
    h = hdr_at(off);
    if (h) coalesce_with_neighbors(off, h);

out:
    UNLOCK();
}

// ============================================================================
// PUBLIC API: mm_realloc
// ============================================================================
// Grow/shrink a block by allocating a new one when necessary. Preserves
// contents up to the minimum of old/new payload sizes.
void *mm_realloc(void *ptr, size_t new_size) {
    if (!ptr) return mm_malloc(new_size);
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    BlockHeader *h = NULL;
    size_t off = 0;
    size_t old_payload = 0;

    LOCK();
    if (validate_payload_ptr(ptr, &h, &off) != BLOCK_OK) {
        UNLOCK();
        return NULL;
    }
    old_payload = h->size - HEADER_SIZE - FOOTER_SIZE;
    if (new_size <= old_payload) {
        UNLOCK();
        return ptr;
    }
    UNLOCK();

    void *new_ptr = mm_malloc(new_size);
    if (!new_ptr) return NULL;

    size_t to_copy = old_payload < new_size ? old_payload : new_size;
    memcpy(new_ptr, ptr, to_copy);

    size_t new_off = ((uint8_t *)new_ptr - g_heap) - HEADER_SIZE;
    LOCK();
    BlockHeader *nh = hdr_at(new_off);
    if (nh) {
        set_header_extras(new_off,
                          payload_hash(new_off, nh->size),
                          nh->reserved_b);
    }
    UNLOCK();

    mm_free(ptr);
    return new_ptr;
}

// ============================================================================
// PUBLIC API: mm_heap_stats
// ============================================================================
// Walk the heap and print a summary of block states plus alignment info for
// debugging. This scan tolerates corrupt blocks by stepping past them.
void mm_heap_stats(void) {
    LOCK();

    if (!g_ready) {
        printf("Heap not initialized\n");
        goto out;
    }

    size_t off = 0;
    size_t free_bytes = 0, alloc_bytes = 0, quarant_bytes = 0;
    size_t blocks = 0, corrupt = 0;
    size_t misalign_headers = 0, misalign_payloads = 0;

    while (off + HEADER_SIZE <= g_heap_size) {
        BlockHeader *h = NULL;
        block_check_t r = validate_block(off, &h);

        if (r == BLOCK_FATAL) {
            corrupt++;
            off += MM_ALIGNMENT;
            continue;
        }
        if (r == BLOCK_CORRUPT) {
            corrupt++;
            size_t step = h && h->size >= HEADER_SIZE ? h->size : MM_ALIGNMENT;
            off += align_up(step, MM_ALIGNMENT);
            continue;
        }

        if (off % MM_ALIGNMENT != 0) misalign_headers++;
        uint8_t *payload = g_heap + off + HEADER_SIZE;
        if (((uintptr_t)payload - (uintptr_t)g_heap_base) % MM_ALIGNMENT != 0)
            misalign_payloads++;

        blocks++;
        if (block_is_quarantined(h))      quarant_bytes += h->size;
        else if (block_is_free(h))        free_bytes += h->size;
        else                               alloc_bytes += h->size;

        off = next_block_offset(off, h->size);
    }

    printf("Heap size: %zu bytes\n", g_heap_size);
    printf("Blocks: %zu (alloc=%zu, free=%zu, quarantined=%zu, corrupt=%zu)\n",
           blocks, alloc_bytes, free_bytes, quarant_bytes, corrupt);

    if (misalign_headers || misalign_payloads) {
        printf("[align-debug] misaligned headers=%zu payloads=%zu\n",
               misalign_headers, misalign_payloads);
    }

out:
    UNLOCK();
}

// ============================================================================
// PUBLIC API: mm_heap_dump
// ============================================================================
// Walk every block and print per-block state. In verbose mode, include canary,
// checksum, and stored payload hash for deeper debugging.
void mm_heap_dump(int verbose) {
    LOCK();

    if (!g_ready) {
        printf("Heap not initialized\n");
        goto out;
    }

    size_t off = 0;
    int idx = 0;

    printf("Heap dump (size=%zu):\n", g_heap_size);

    while (off + HEADER_SIZE <= g_heap_size) {
        if (off % MM_ALIGNMENT != 0) {
            off = align_up(off, MM_ALIGNMENT);
            continue;
        }

        BlockHeader *h = NULL;
        block_check_t r = validate_block(off, &h);

        if (r == BLOCK_FATAL) {
            printf("[%02d] off=%zu FATAL\n", idx++, off);
            off += MM_ALIGNMENT;
            continue;
        }
        if (r == BLOCK_CORRUPT) {
            printf("[%02d] off=%zu CORRUPT size=%u\n", idx++, off,
                   h ? h->size : 0);
            size_t step = (h && h->size >= HEADER_SIZE) ? h->size :
                          MM_ALIGNMENT;
            off += align_up(step, MM_ALIGNMENT);
            continue;
        }

        uint32_t sz = h->size;
        const char *state = block_is_quarantined(h) ? "QUAR" :
                             block_is_free(h)        ? "FREE" : "ALLOC";

        uint8_t *payload = g_heap + off + HEADER_SIZE;
        size_t payload_mod = ((uintptr_t)payload - (uintptr_t)g_heap_base) %
                     MM_ALIGNMENT;
        printf("[%02d] off=%-8zu size=%-8u state=%5s header_mod=%2zu "
               "payload_mod=%2zu\n",
               idx++,
               off,
               sz,
               state,
               off % MM_ALIGNMENT,
               payload_mod);

        if (verbose) {
            printf("      canary=0x%08x checksum=0x%08x hash=0x%016" PRIx64
                   "\n",
                   h->canary,
                   h->checksum,
                   h->reserved_a);
        }

        off = next_block_offset(off, sz);
    }

out:
    UNLOCK();
}
