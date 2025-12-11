#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "allocator.h"

int main(void) {
    size_t heap_size = 32768;
    uint8_t *heap = malloc(heap_size);

    if (!heap) {
        printf("heap alloc failed\n");
        return 1;
    }

    if (mm_init(heap, heap_size) != 0) {
        printf("mm_init failed\n");
        free(heap);
        return 1;
    }

    void *p = mm_malloc(32);
    if (!p) {
        printf("mm_malloc failed\n");
        free(heap);
        return 1;
    }

    uint8_t data[32];
    for (int i = 0; i < 32; i++)
        data[i] = (uint8_t)(i + 1);

    int w = mm_write(p, 0, data, 32);
    if (w < 0) {
        printf("mm_write failed\n");
    } else {
        printf("mm_write OK (%d bytes)\n", w);
    }

    uint8_t out[32] = {0};
    int r = mm_read(p, 0, out, 32);
    if (r < 0) {
        printf("mm_read failed\n");
    } else {
        printf("mm_read OK (%d bytes)\n", r);
        printf("first few bytes: %u %u %u %u\n",
               out[0], out[1], out[2], out[3]);
    }

    mm_free(p);
    free(heap);

    return 0;
}
