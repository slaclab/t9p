
all: t9p

clean:
	rm t9p

.PHONY: clean

t9p: t9p.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)