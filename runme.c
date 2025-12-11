// ============================================================================
//  runme.c – Minimal Test Driver
// ============================================================================
//
//  This program provides a very small, deterministic test harness for the
//  allocator.  It is intentionally simple so that:
//
//      • the autograder can compile and run it automatically,
//      • you can verify that your allocator links and behaves correctly, and
//      • it exercises mm_init, mm_malloc, mm_write, mm_read, mm_free.
//
//  The test performs one allocation, one write, one read, and one free.
//  Output is minimal but enough to confirm correctness under clear skies.
// ============================================================================

#include <stdio.h>      // printf
#include <stdlib.h>     // malloc, free
#include <stdint.h>     // uint8_t
#include <string.h>     // memset, memcpy
#include "allocator.h"  // allocator API prototypes

int main(void) {
    // ------------------------------------------------------------------------
    // 1. Allocate a raw heap buffer using *system malloc* (allowed ONLY here).
    //    The allocator must manage memory strictly *inside* this buffer.
    // ------------------------------------------------------------------------
    size_t heap_size = 32768;           // 32 KB heap for testing
    uint8_t *heap = malloc(heap_size);  // outside allocator; allowed

    if (!heap) {
        printf("heap alloc failed\n");
        return 1;
    }

    // ------------------------------------------------------------------------
    // 2. Initialise custom allocator with the provided heap buffer.
    //    After this point, the allocator owns and manages the memory.
    // ------------------------------------------------------------------------
    if (mm_init(heap, heap_size) != 0) {
        printf("mm_init failed\n");
        free(heap);    // clean up system malloc
        return 1;
    }

    // ------------------------------------------------------------------------
    // 3. Allocate a small 32-byte block.
    //    Allocator returns a pointer to the payload region.
    // ------------------------------------------------------------------------
    void *p = mm_malloc(32);
    if (!p) {
        printf("mm_malloc failed\n");
        free(heap);
        return 1;
    }

    // ------------------------------------------------------------------------
    // 4. Prepare some input data to write into the allocated block.
    //    Here we simply fill the array with values 1..32.
    // ------------------------------------------------------------------------
    uint8_t data[32];
    for (int i = 0; i < 32; i++)
        data[i] = (uint8_t)(i + 1);

    // ------------------------------------------------------------------------
    // 5. Write the full block using mm_write().
    //    The allocator checks:
    //        • the block is valid,
    //        • offset + length == requested size,
    //        • payload hash matches before write,
    //        • metadata is updated after write.
    // ------------------------------------------------------------------------
    int w = mm_write(p, 0, data, 32);
    if (w < 0) {
        printf("mm_write failed\n");
    } else {
        printf("mm_write OK (%d bytes)\n", w);
    }

    // ------------------------------------------------------------------------
    // 6. Read back the same 32 bytes and verify correctness.
    //    The allocator checks payload integrity before reading.
    // ------------------------------------------------------------------------
    uint8_t out[32] = {0};
    int r = mm_read(p, 0, out, 32);

    if (r < 0) {
        printf("mm_read failed\n");
    } else {
        printf("mm_read OK (%d bytes)\n", r);

        // Print the first few bytes as a quick correctness check
        printf("first few bytes: %u %u %u %u\n",
               out[0], out[1], out[2], out[3]);
    }

    // ------------------------------------------------------------------------
    // 7. Free the block.
    //    The allocator will:
    //        • verify metadata,
    //        • repaint the freed payload with poison pattern,
    //        • attempt safe coalescing with neighbours,
    //        • never merge across corrupted neighbours.
    // ------------------------------------------------------------------------
    mm_free(p);

    // ------------------------------------------------------------------------
    // 8. Destroy the heap buffer.
    //    NOTE: The allocator is not responsible for this memory;
    //          the caller manages the lifetime of the raw heap.
    // ------------------------------------------------------------------------
    free(heap);

    return 0;
}
