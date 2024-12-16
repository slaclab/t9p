
AR?=ar
CFLAGS+=-g -Wall

all: t9p tests/bvec_test tests

clean:
	rm t9p
	rm *.o
	rm *.a
	rm tests/bvec_test

.PHONY: clean

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

libt9p.a: t9p.o t9proto.o t9p_posix.o
	$(AR) cvr $@ $^

t9p: t9p_main.c libt9p.a
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS) t9p_posix.o -L. -lt9p -lreadline

tests/bvec_test: tests/bvec_test.c bvec.h
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

tests/t9p_threaded_test: tests/t9p_threaded_test.c libt9p.a
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

runtests: tests/bvec_test tests/t9p_threaded_test
	#./tests/bvec_test
	#valgrind -- ./tests/bvec_test
	/sbin/diod -L stderr -e $(shell readlink -f tests/fs) -l 0.0.0.0:10002 -n & sleep 2; \
	$(DEBUGGER) ./tests/t9p_threaded_test -i 1000 -a $(shell readlink -f tests/fs) -m $(shell readlink -f tests/fs)/mnt 0.0.0.0:10002 -t 10 -n 4; \
	kill -9 %1;

tests: tests/t9p_threaded_test
