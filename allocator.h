#ifndef ALLOCATOR_H
#define ALLOCATOR_H
#include <stddef.h>
#include <stdint.h>

// Alignment requirement for all payload pointers
#define MM_ALIGNMENT 40u

// Recurring 5-byte pattern used to mark unused / freed space.
#ifndef UNUSED_PATTERN_BYTES
#define UNUSED_PATTERN_BYTES {0xA5u, 0x5Au, 0x3Cu, 0xC3u, 0x7Eu}
#endif

int mm_init(uint8_t *heap, size_t heap_size);
void *mm_malloc(size_t size);
int mm_read(void *ptr, size_t offset, void *buf, size_t len);
int mm_write(void *ptr, size_t offset, const void *src, size_t len);
void mm_free(void *ptr);
void *mm_realloc(void *ptr, size_t new_size);
// optional, may return NULL if not implemented

void mm_heap_stats(void);
// optional helper

void mm_heap_dump(int verbose);
// debug helper: prints block layout and alignment

#endif
