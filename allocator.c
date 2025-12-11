#include "allocator.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

// ---------------------------------------------------------------------------
//  CONSTANTS AND METADATA FORMAT
// ---------------------------------------------------------------------------
//
//  Each block ("segment") has:
//     [SegmentHead (40 bytes)] [payload ...] [SegmentTail (16 bytes)]
//
//  All block boundaries and payload pointers are aligned to MM_ALIGNMENT
//  (40 bytes).
// ---------------------------------------------------------------------------

#define SEG_MAGIC_HEADER   0x8F51C2A3u
#define SEG_MAGIC_FOOTER   0x3AC2F158u
#define SEG_HEAD_BYTES     40u
#define SEG_TAIL_BYTES     16u
#define MIN_USER_BYTES     8u
#define SEG_FLAG_INUSE     0x10u
#define SEG_FLAG_ISOLATED  0x40u

// Hash parameters for payload fingerprint
#define PAY_HASH_INIT      1469598103934665603ull
#define PAY_HASH_FACTOR    1099511628211ull

// Header checksum parameters
#define HDR_HASH_SEED      0x5F1Du
#define HDR_HASH_FACTOR    31337u

// Footer checksum parameters
#define FTR_HASH_SEED      0xBADC0FFEu

// Poison pattern used to fill freed memory
#ifndef UNUSED_PATTERN_BYTES
#define UNUSED_PATTERN_BYTES {0xDEu, 0xADu, 0xFAu, 0xCEu, 0x42u}
#endif

// ---------------------------------------------------------------------------
//  BLOCK HEADER AND FOOTER STRUCTURES
// ---------------------------------------------------------------------------

typedef struct __attribute__((packed)) SegmentHead {
    uint32_t tag;
    uint32_t span;
    uint32_t span_neg;
    uint32_t flags;
    uint64_t meta_a;   // payload hash
    uint64_t meta_b;   // requested size
    uint32_t guard;
    uint32_t crc;
} SegmentHead;

_Static_assert(sizeof(SegmentHead) == SEG_HEAD_BYTES, "");

typedef struct __attribute__((packed)) SegmentTail {
    uint32_t tag;
    uint32_t span;
    uint32_t span_neg;
    uint32_t crc;
} SegmentTail;

_Static_assert(sizeof(SegmentTail) == SEG_TAIL_BYTES, "");

// ---------------------------------------------------------------------------
//  GLOBAL STATE
// ---------------------------------------------------------------------------
//
//  All allocator state is stored inside the heap except:
//    arena_mem    - heap pointer
//    arena_origin - original base for alignment checks
//    arena_bytes  - aligned usable size
//    arena_online - init flag
// ---------------------------------------------------------------------------

static uint8_t *arena_mem    = NULL;
static uint8_t *arena_origin = NULL;
static size_t   arena_bytes  = 0;
static bool     arena_online = false;

// No actual locking; macros kept for shape.
#define ARENA_LOCK()
#define ARENA_UNLOCK()

// Poison pattern for freed blocks.
static uint8_t poison_pattern[5] = UNUSED_PATTERN_BYTES;
static size_t  poison_phase = 0;

// Debug logging for storms.
static bool storm_trace = false;
#define STORM_LOG(...)              \
    do {                            \
        if (storm_trace) {          \
            fprintf(stderr, __VA_ARGS__); \
        }                           \
    } while (0)

// Segment health used by validation routines.
typedef enum {
    SEG_HEALTH_OK = 0,
    SEG_HEALTH_CORRUPT = 1,
    SEG_HEALTH_FATAL = 2
} seg_health_t;

// ============================================================================
//  UTILITY ROUTINES
// ============================================================================

// Align upward.
static inline size_t ceil_to_align(size_t v, size_t a) {
    size_t r = v % a;
    return r ? v + (a - r) : v;
}

// Align downward.
static inline size_t floor_to_align(size_t v, size_t a) {
    return v - (v % a);
}

// Check if [off, off+len) is inside heap.
static inline bool within_arena(size_t off, size_t len) {
    return off <= arena_bytes &&
           len <= arena_bytes &&
           off + len <= arena_bytes;
}

// Get header pointer from heap offset.
static SegmentHead *head_at(size_t off) {
    if (!within_arena(off, SEG_HEAD_BYTES)) {
        return NULL;
    }
    return (SegmentHead *)(arena_mem + off);
}

// Get footer pointer.
static SegmentTail *tail_at(size_t off, uint32_t span) {
    size_t to = off + span - SEG_TAIL_BYTES;
    if (!within_arena(to, SEG_TAIL_BYTES)) {
        return NULL;
    }
    return (SegmentTail *)(arena_mem + to);
}

// Check if segment is free (not in use and not isolated).
static inline bool seg_is_free(const SegmentHead *h) {
    return !(h->flags & SEG_FLAG_INUSE) &&
           !(h->flags & SEG_FLAG_ISOLATED);
}

// Check if segment is isolated/quarantined.
static inline bool seg_is_isolated(const SegmentHead *h) {
    return (h->flags & SEG_FLAG_ISOLATED) != 0;
}

// Compute next segment offset.
static inline size_t next_segment_offset(size_t off, uint32_t span) {
    size_t n = off + span;
    return (n >= arena_bytes) ? arena_bytes : n;
}

// Detect poison pattern at mm_init by checking start of heap.
static void detect_poison_pattern(const uint8_t *buf, size_t len) {
    if (!buf || len < 5) {
        return;
    }

    uint8_t cand[5];
    for (size_t i = 0; i < 5; ++i) {
        cand[i] = buf[i];
    }

    size_t s = (len < 25) ? len : 25;
    for (size_t i = 0; i < s; ++i) {
        if (buf[i] != cand[i % 5]) {
            return;
        }
    }

    for (size_t i = 0; i < 5; ++i) {
        poison_pattern[i] = cand[i];
    }
}

// Guard value derived from offset and span.
static uint32_t derive_guard(size_t off, uint32_t span) {
    uint32_t v = (uint32_t)(off * 1315423911u) ^
                 (span * 2654435761u);
    v ^= SEG_MAGIC_HEADER;
    v ^= (v << 5);
    v ^= (v >> 13);
    v ^= (v << 17);
    return v;
}

// Header checksum.
static uint32_t checksum_head(const SegmentHead *h) {
    const uint8_t *b = (const uint8_t *)h;
    uint32_t hash = HDR_HASH_SEED;

    // Do not include crc field itself.
    for (size_t i = 0; i < SEG_HEAD_BYTES - sizeof(uint32_t); ++i) {
        hash ^= b[i];
        hash *= HDR_HASH_FACTOR;
        hash ^= (hash >> 7);
    }
    hash ^= SEG_MAGIC_FOOTER;
    return hash;
}

// Footer checksum.
static uint32_t checksum_tail(uint32_t s, uint32_t sn) {
    uint32_t h = FTR_HASH_SEED;
    h ^= s;
    h += (h << 3) ^ 0xA1B2C3D4u;
    h ^= sn;
    h += (h >> 5) ^ 0x1F2E3D4Cu;
    h ^= SEG_MAGIC_FOOTER;
    return h;
}

// Get payload region for a segment.
static bool payload_region(size_t off, uint32_t span,
                           size_t *poff, size_t *plen) {
    if (span < SEG_HEAD_BYTES + SEG_TAIL_BYTES) {
        return false;
    }

    size_t p = off + SEG_HEAD_BYTES;
    size_t l = span - SEG_HEAD_BYTES - SEG_TAIL_BYTES;

    if (!within_arena(p, l)) {
        return false;
    }

    if (poff) {
        *poff = p;
    }
    if (plen) {
        *plen = l;
    }
    return true;
}

// Compute payload hash used for integrity checks.
static uint64_t hash_payload_bytes(size_t off, uint32_t span) {
    size_t p = 0;
    size_t l = 0;

    if (!payload_region(off, span, &p, &l)) {
        return 0;
    }

    const uint8_t *x = arena_mem + p;
    uint64_t h = PAY_HASH_INIT;

    for (size_t i = 0; i < l; ++i) {
        h ^= x[i];
        h *= PAY_HASH_FACTOR;
    }
    return h;
}

// Emit header into memory.
static void emit_head(size_t off, uint32_t span, uint32_t flags) {
    SegmentHead *h = head_at(off);
    if (!h) {
        return;
    }

    h->tag = SEG_MAGIC_HEADER;
    h->span = span;
    h->span_neg = ~span;
    h->flags = flags;
    h->meta_a = 0;
    h->meta_b = 0;
    h->guard = derive_guard(off, span);
    h->crc = checksum_head(h);
}

// Emit footer into memory.
static void emit_tail(size_t off, uint32_t span) {
    SegmentTail *t = tail_at(off, span);
    if (!t) {
        return;
    }

    t->tag = SEG_MAGIC_FOOTER;
    t->span = span;
    t->span_neg = ~span;
    t->crc = checksum_tail(span, ~span);
}

// Update payload hash and requested size, then recompute header CRC.
static void update_head_extras(size_t off, uint64_t ha, uint64_t b) {
    SegmentHead *h = head_at(off);
    if (!h) {
        return;
    }

    h->meta_a = ha;
    h->meta_b = b;
    h->crc = checksum_head(h);
}

// Paint freed payload with poison pattern.
static void paint_free_payload(size_t off, uint32_t span) {
    size_t p = off + SEG_HEAD_BYTES;
    size_t l = span - SEG_HEAD_BYTES - SEG_TAIL_BYTES;

    if (!within_arena(p, l)) {
        return;
    }

    size_t ph = (p + poison_phase) % 5;
    for (size_t i = 0; i < l; ++i) {
        arena_mem[p + i] = poison_pattern[(ph + i) % 5];
    }
}

// Initialize a segment as either allocated or free.
static void init_segment(size_t off, uint32_t span,
                         uint32_t flags, uint64_t req) {
    emit_head(off, span, flags);
    emit_tail(off, span);

    if (flags & SEG_FLAG_INUSE) {
        // Keep existing payload; update hash metadata.
        update_head_extras(off,
                           hash_payload_bytes(off, span),
                           req);
    } else {
        paint_free_payload(off, span);
        update_head_extras(off,
                           hash_payload_bytes(off, span),
                           0);
    }
}

// Create an isolated span for corrupt metadata so scans can continue.
static size_t isolate_span(size_t off, uint32_t hint) {
    size_t max = floor_to_align(arena_bytes - off, MM_ALIGNMENT);
    if (max < SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES) {
        return 0;
    }

    size_t s = hint ? hint : MM_ALIGNMENT;
    s = ceil_to_align(s, MM_ALIGNMENT);

    if (s < SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES) {
        s = SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES;
    }
    if (s > max) {
        s = max;
    }
    if (s > UINT32_MAX) {
        s = UINT32_MAX;
    }

    init_segment(off, (uint32_t)s, SEG_FLAG_ISOLATED, 0);
    return s;
}

// Try to rebuild the header of a corrupt segment from a valid footer.
static bool rebuild_header_via_footer(size_t off) {
    size_t start = off + SEG_HEAD_BYTES + MIN_USER_BYTES;
    if (start + SEG_TAIL_BYTES > arena_bytes) {
        return false;
    }

    for (size_t f = start;
         f + SEG_TAIL_BYTES <= arena_bytes;
         f += MM_ALIGNMENT) {
        SegmentTail *t = (SegmentTail *)(arena_mem + f);
        uint32_t sp = t->span;

        if (t->tag != SEG_MAGIC_FOOTER) {
            continue;
        }
        if (t->span_neg != ~sp) {
            continue;
        }
        if (checksum_tail(sp, ~sp) != t->crc) {
            continue;
        }
        if (sp % MM_ALIGNMENT != 0) {
            continue;
        }
        if (sp < SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES) {
            continue;
        }
        if (!within_arena(off, sp)) {
            continue;
        }
        if (f != off + sp - SEG_TAIL_BYTES) {
            continue;
        }

        emit_head(off, sp, SEG_FLAG_INUSE);
        update_head_extras(off,
                           hash_payload_bytes(off, sp),
                           0);
        return true;
    }
    return false;
}

// Mark segment as isolated (quarantined).
static void isolate_segment(size_t off, uint32_t span) {
    SegmentHead *h = head_at(off);
    if (!h || !within_arena(off, span)) {
        return;
    }

    uint32_t fl = (h->flags | SEG_FLAG_ISOLATED) & ~SEG_FLAG_INUSE;

    emit_head(off, span, fl);
    emit_tail(off, span);
    update_head_extras(off,
                       hash_payload_bytes(off, span),
                       0);
}

// ============================================================================
//  SEGMENT VALIDATION
// ============================================================================

static seg_health_t verify_segment(size_t off, SegmentHead **out) {
    SegmentHead *h = head_at(off);
    if (!h) {
        return SEG_HEALTH_FATAL;
    }

    uint32_t sp = h->span;

again:
    if (h->tag != SEG_MAGIC_HEADER ||
        h->span_neg != ~sp ||
        sp % MM_ALIGNMENT != 0 ||
        sp < SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES ||
        !within_arena(off, sp)) {
        if (rebuild_header_via_footer(off)) {
            h = head_at(off);
            sp = h ? h->span : 0;
            if (!h) {
                return SEG_HEALTH_FATAL;
            }
            goto again;
        }

        if (h->tag != SEG_MAGIC_HEADER) {
            return SEG_HEALTH_FATAL;
        }
        return SEG_HEALTH_CORRUPT;
    }

    if (h->guard != derive_guard(off, sp)) {
        return SEG_HEALTH_CORRUPT;
    }
    if (h->crc != checksum_head(h)) {
        return SEG_HEALTH_CORRUPT;
    }

    SegmentTail *t = tail_at(off, sp);
    if (!t) {
        return SEG_HEALTH_CORRUPT;
    }
    if (t->tag != SEG_MAGIC_FOOTER) {
        return SEG_HEALTH_CORRUPT;
    }
    if (t->span != sp || t->span_neg != ~sp) {
        return SEG_HEALTH_CORRUPT;
    }
    if (t->crc != checksum_tail(sp, ~sp)) {
        return SEG_HEALTH_CORRUPT;
    }

    uint64_t exp = h->meta_a;
    uint64_t act = hash_payload_bytes(off, sp);

    if (seg_is_isolated(h)) {
        if (exp != act) {
            return SEG_HEALTH_CORRUPT;
        }
    } else if (seg_is_free(h)) {
        if (exp != act) {
            paint_free_payload(off, sp);
            update_head_extras(off,
                               hash_payload_bytes(off, sp),
                               h->meta_b);
        }
    }

    if (out) {
        *out = h;
    }
    return SEG_HEALTH_OK;
}

// Merge adjacent free segments when possible.
static void merge_adjacent_free_segments(size_t off, SegmentHead *h) {
    uint32_t sp = h->span;

    // Forward merge.
    size_t next = next_segment_offset(off, sp);
    if (next + SEG_HEAD_BYTES <= arena_bytes) {
        SegmentHead *nh = head_at(next);
        if (nh) {
            seg_health_t st = verify_segment(next, &nh);
            if (st == SEG_HEALTH_OK && seg_is_free(nh)) {
                sp += nh->span;
                init_segment(off, sp, 0, 0);
                h = head_at(off);
                sp = h ? h->span : sp;
            } else if (st == SEG_HEALTH_CORRUPT) {
                isolate_segment(next, nh ? nh->span : 0);
            }
        }
    }

    // Backward merge.
    if (off >= SEG_TAIL_BYTES) {
        size_t pt = off - SEG_TAIL_BYTES;
        SegmentTail *t = (SegmentTail *)(arena_mem + pt);
        uint32_t psp = 0;

        if (within_arena(pt, SEG_TAIL_BYTES) &&
            t->tag == SEG_MAGIC_FOOTER &&
            t->span_neg == ~t->span) {
            psp = t->span;
        }

        if (psp >= SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES &&
            off >= psp) {
            size_t po = off - psp;
            SegmentHead *ph = head_at(po);
            if (ph) {
                seg_health_t st = verify_segment(po, &ph);
                if (st == SEG_HEALTH_OK && seg_is_free(ph)) {
                    size_t ns = psp + h->span;
                    init_segment(po, ns, 0, 0);
                    off = po;
                    h = head_at(off);
                    sp = h->span;
                } else if (st == SEG_HEALTH_CORRUPT) {
                    isolate_segment(po, ph ? ph->span : 0);
                }
            }
        }
    }
}

// Ensure allocator is ready.
static int arena_ready(void) {
    return arena_online ? 0 : -1;
}

// Validate user pointer and find owning segment.
static seg_health_t locate_segment_from_userptr(void *ptr,
                                                SegmentHead **out,
                                                size_t *ooff) {
    if (arena_ready() != 0 || !ptr) {
        return SEG_HEALTH_FATAL;
    }

    uintptr_t p = (uintptr_t)ptr;
    uintptr_t b = (uintptr_t)arena_origin;

    if (((p - b) % MM_ALIGNMENT) != 0) {
        return SEG_HEALTH_FATAL;
    }
    if (p < b + SEG_HEAD_BYTES ||
        p >= b + arena_bytes - SEG_TAIL_BYTES) {
        return SEG_HEALTH_FATAL;
    }

    size_t off = (p - b) - SEG_HEAD_BYTES;
    SegmentHead *h = NULL;
    seg_health_t st = verify_segment(off, &h);

    if (st != SEG_HEALTH_OK) {
        if (rebuild_header_via_footer(off)) {
            st = verify_segment(off, &h);
        }
        if (st != SEG_HEALTH_OK) {
            return st;
        }
    }

    if (!h || !(h->flags & SEG_FLAG_INUSE) || seg_is_isolated(h)) {
        return SEG_HEALTH_FATAL;
    }

    if (out) {
        *out = h;
    }
    if (ooff) {
        *ooff = off;
    }

    return SEG_HEALTH_OK;
}

// ============================================================================
//  PUBLIC API
// ============================================================================

// Initialize allocator on top of caller-provided heap.
int mm_init(uint8_t *mem, size_t len) {
    if (!mem ||
        len < SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES) {
        return -1;
    }

    storm_trace = getenv("MM_BROWNOUT_DEBUG") != NULL;

    detect_poison_pattern(mem, len);
    poison_phase = 0;

    arena_origin = mem;
    arena_mem = mem;
    arena_bytes = floor_to_align(len, MM_ALIGNMENT);

    if (arena_bytes <
        SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES) {
        return -1;
    }

    init_segment(0, arena_bytes, 0, 0);
    arena_online = true;
    return 0;
}

// Allocate memory using a first-fit scan and robust validation.
void *mm_malloc(size_t size) {
    void *ret = NULL;

    printf("[debug] mm_malloc called with size=%zu\n", size);

    ARENA_LOCK();
    if (arena_ready() != 0) {
        goto out;
    }

    if (size == 0) {
        size = 1;
    }

    bool salvage = false;
    bool repair = false;

retry: {
    size_t plen = ceil_to_align(size, MM_ALIGNMENT);
    size_t need = ceil_to_align(plen + SEG_HEAD_BYTES + SEG_TAIL_BYTES,
                                MM_ALIGNMENT);
    if (need > arena_bytes) {
        goto out;
    }

    for (size_t off = 0; off + SEG_HEAD_BYTES <= arena_bytes; ) {
        if (off % MM_ALIGNMENT) {
            off = ceil_to_align(off, MM_ALIGNMENT);
            continue;
        }

        SegmentHead *h = NULL;
        seg_health_t st = verify_segment(off, &h);

        if (st == SEG_HEALTH_FATAL) {
            size_t sp = isolate_span(off, MM_ALIGNMENT);
            off += sp ? sp : MM_ALIGNMENT;
            continue;
        }

        if (st == SEG_HEALTH_CORRUPT) {
            uint32_t hint = h ? h->span : MM_ALIGNMENT;
            if (hint < MM_ALIGNMENT) {
                hint = MM_ALIGNMENT;
            }
            size_t sp = isolate_span(off, hint);
            off += sp ? sp : ceil_to_align(hint, MM_ALIGNMENT);
            continue;
        }

        if (seg_is_free(h) && h->span >= need) {
            uint32_t full = h->span;
            uint32_t left = full - need;

            if (left >= SEG_HEAD_BYTES + SEG_TAIL_BYTES + MIN_USER_BYTES) {
                init_segment(off, need, SEG_FLAG_INUSE, size);
                init_segment(off + need, left, 0, 0);
            } else {
                init_segment(off, full, SEG_FLAG_INUSE, size);
            }

            uint8_t *p = arena_mem + off + SEG_HEAD_BYTES;
            uint64_t mod =
                (uint64_t)((p - arena_origin) % MM_ALIGNMENT);
            if (mod != 0) {
                ret = NULL;
                goto out;
            }
            ret = p;
            goto out;
        }

        off = next_segment_offset(off, h->span);
    }

    if (!repair) {
        repair = true;
        size_t pos = 0;

        while (pos + SEG_HEAD_BYTES <= arena_bytes) {
            if (pos % MM_ALIGNMENT) {
                pos = ceil_to_align(pos, MM_ALIGNMENT);
                continue;
            }

            SegmentHead *h = NULL;
            seg_health_t st = verify_segment(pos, &h);

            if (st == SEG_HEALTH_FATAL || st == SEG_HEALTH_CORRUPT) {
                uint32_t hint = h ? h->span : MM_ALIGNMENT;
                if (hint < MM_ALIGNMENT) {
                    hint = MM_ALIGNMENT;
                }
                size_t sp = isolate_span(pos, hint);
                pos += sp ? sp : MM_ALIGNMENT;
                continue;
            }

            pos = next_segment_offset(pos, h->span);
        }

        goto retry;
    }

    if (!salvage && arena_origin && arena_bytes > 0) {
        salvage = true;
        mm_init(arena_origin, arena_bytes);
        goto retry;
    }
}  // end retry block

out:
    ARENA_UNLOCK();
    return ret;
}

// Safe read from an allocated block.
int mm_read(void *ptr, size_t off, void *buf, size_t len) {
    int r = -1;

    ARENA_LOCK();

    SegmentHead *h = NULL;
    size_t so = 0;

    seg_health_t st = locate_segment_from_userptr(ptr, &h, &so);
    if (st != SEG_HEALTH_OK) {
        goto out;
    }

    size_t plen = h->span - SEG_HEAD_BYTES - SEG_TAIL_BYTES;
    if (off + len > plen) {
        goto out;
    }

    if (hash_payload_bytes(so, h->span) != h->meta_a) {
        isolate_segment(so, h->span);
        goto out;
    }

    memcpy(buf, (uint8_t *)ptr + off, len);
    r = (int)len;

out:
    ARENA_UNLOCK();
    return r;
}

// Safe write into an allocated block with integrity checks.
int mm_write(void *ptr, size_t off, const void *src, size_t len) {
    int r = -1;

    ARENA_LOCK();

    SegmentHead *h = NULL;
    size_t so = 0;

    seg_health_t st = locate_segment_from_userptr(ptr, &h, &so);
    if (st != SEG_HEALTH_OK) {
        goto out;
    }

    if (off + len != (size_t)h->meta_b) {
        goto out;
    }

    if (hash_payload_bytes(so, h->span) != h->meta_a) {
        isolate_segment(so, h->span);
        goto out;
    }

    memcpy((uint8_t *)ptr + off, src, len);

    update_head_extras(so,
                       hash_payload_bytes(so, h->span),
                       h->meta_b);

    r = (int)len;

out:
    ARENA_UNLOCK();
    return r;
}

// Free an allocated block, repaint payload, and coalesce with neighbours.
void mm_free(void *ptr) {
    ARENA_LOCK();

    SegmentHead *h = NULL;
    size_t so = 0;

    seg_health_t st = locate_segment_from_userptr(ptr, &h, &so);
    if (st != SEG_HEALTH_OK) {
        ARENA_UNLOCK();
        return;
    }

    if (!h || !h->flags || seg_is_isolated(h)) {
        ARENA_UNLOCK();
        return;
    }

    init_segment(so, h->span, 0, 0);

    h = head_at(so);
    if (h) {
        merge_adjacent_free_segments(so, h);
    }

    ARENA_UNLOCK();
}
