CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -fPIC -O2
LDFLAGS_SHARED=-shared

all: liballocator.so runme

allocator.o: allocator.c allocator.h
	$(CC) $(CFLAGS) -c allocator.c -o allocator.o

liballocator.so: allocator.o
	$(CC) $(LDFLAGS_SHARED) -o liballocator.so allocator.o

runme.o: runme.c allocator.h
	$(CC) $(CFLAGS) -c runme.c -o runme.o

runme: runme.o allocator.o
	$(CC) -o runme runme.o allocator.o

.PHONY: test clean runme

clean:
	rm -f *.o liballocator.so runme

test: runme
	./runme --size 125600 --storm 999 --seed 5