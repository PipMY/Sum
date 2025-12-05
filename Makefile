CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -pedantic -fPIC -O2 -pthread
LDFLAGS_SHARED=-shared

all: liballocator.so runme

allocator.o: allocator.c allocator.h
	$(CC) $(CFLAGS) -c allocator.c -o allocator.o

liballocator.so: allocator.o
	$(CC) $(LDFLAGS_SHARED) -o liballocator.so allocator.o -pthread

runme.o: runme.c allocator.h
	$(CC) $(CFLAGS) -c runme.c -o runme.o

runme: runme.o allocator.o
	$(CC) -o runme runme.o allocator.o -pthread

.PHONY: test clean runme

test: runme
	./runme --size 32768 --storm 10 --seed 1

clean:
	rm -f *.o liballocator.so runme
