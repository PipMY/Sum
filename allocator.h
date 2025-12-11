#ifndef ALLOCATOR_H_
#define ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

#define MM_ALIGNMENT 40u

int mm_init(uint8_t *heap, size_t heap_size);
void *mm_malloc(size_t size);
int mm_read(void *ptr, size_t offset, void *buf, size_t len);
int mm_write(void *ptr, size_t offset, const void *src, size_t len);
void mm_free(void *ptr);

#endif // ALLOCATOR_H_
