LDFLAGS=-lcrypto
CFLAGS=-Iinclude -O2 -std=c99 -Wall -Wextra

OBJS= \
  ../../dust-internal.o \
  ../../dust-file-utils.o \
  ../../io.o \
  ../../memory.o \
  ../../types.o

.PHONY: all tidy clean

all: \
  test-dust_open_index \
  test-dust_open_arena

tidy:
	rm -f index* arena*

clean: tidy
	rm -f test-dust_open_index test-dust_open_arena

test-dust_open_index: dust_open_index.c $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -I../../include $(OBJS) dust_open_index.c -o $@

test-dust_open_arena: dust_open_arena.c $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -I../../include $(OBJS) dust_open_arena.c -o $@

