
AR?=ar
CFLAGS+=-g

all: t9p tests/bvec_test

clean:
	rm t9p
	rm *.o
	rm *.a
	rm tests/bvec_test

.PHONY: clean

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

libt9p.a: t9p.o t9proto.o
	$(AR) cvr $@ $?

t9p: t9p_main.c libt9p.a
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS) -L. -lt9p -lreadline

tests/bvec_test: tests/bvec_test.c bvec.h
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

runtests: tests/bvec_test
	./tests/bvec_test
	valgrind -- ./tests/bvec_test