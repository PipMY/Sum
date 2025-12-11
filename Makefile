CCOMP     = gcc
FLAGS     = -std=c11 -Wall -Wextra -pedantic -O2 -fPIC
SHLIBOPT  = -shared

all: libmem.so demo

core.obj: allocator.c allocator.h
	$(CCOMP) $(FLAGS) -c allocator.c -o core.obj

libmem.so: core.obj
	$(CCOMP) $(SHLIBOPT) -o libmem.so core.obj

demo.obj: runme.c allocator.h
	$(CCOMP) $(FLAGS) -c runme.c -o demo.obj

demo: demo.obj core.obj
	$(CCOMP) -o demo demo.obj core.obj

.PHONY: test clean demo

test: demo
	./demo --size 40960 --storm 4 --seed 99

clean:
	rm -f *.obj libmem.so demo
