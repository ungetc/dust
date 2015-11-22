include personal.mk
include mkutils.mk

# Install directory. Binaries will go in $PREFIX/bin,
# manpages in $PREFIX/man, and so on.
PREFIX=$$HOME/opt/`uname`.`uname -m`

LDFLAGS=-lcrypto
CFLAGS=-Iinclude -O2 -std=c99 -Wall -Wextra

OBJS= \
  dust-internal.o \
  dust-file-utils.o \
  io.o \
  memory.o \
  types.o

BINARIES= \
  dust \
  dust-check \
  dust-archive \
  dust-extract \
  dust-listing \
  dust-rebuild-index

.PHONY: clean all testsuite install

all: .git/hooks/pre-commit $(BINARIES)

clean:
	rm -f $(BINARIES) $(OBJS)

testsuite: all
	rm -f $(PWD)/testsuite/index $(PWD)/testsuite/arena
	cd testsuite && \
	  DUST_INDEX=$(PWD)/testsuite/index DUST_ARENA=$(PWD)/testsuite/arena ./run-tests.sh
	rm -f $(PWD)/testsuite/index $(PWD)/testsuite/arena

install: all
	install -m 755 -d $(PREFIX)/bin/
	install -m 755 $(BINARIES) $(PREFIX)/bin/

.git/hooks/pre-commit: hooks/pre-commit
	cp $? $@

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) $(PERSONAL_CFLAGS) $< -o $@

dust: dust.c memory.o
	$(CC) $(CFLAGS) $(PERSONAL_CFLAGS) $(LDFLAGS) $(ALLDEPS) -o $@

dust-archive: dust-archive.c $(OBJS)
	$(CC) $(CFLAGS) $(PERSONAL_CFLAGS) $(LDFLAGS) $(ALLDEPS) -o $@

dust-check: dust-check.c $(OBJS)
	$(CC) $(CFLAGS) $(PERSONAL_CFLAGS) $(LDFLAGS) $(ALLDEPS) -o $@

dust-extract: dust-extract.c $(OBJS)
	$(CC) $(CFLAGS) $(PERSONAL_CFLAGS) $(LDFLAGS) $(ALLDEPS) -o $@

dust-listing: dust-listing.c $(OBJS)
	$(CC) $(CFLAGS) $(PERSONAL_CFLAGS) $(LDFLAGS) $(ALLDEPS) -o $@

dust-rebuild-index: dust-rebuild-index.c $(OBJS)
	$(CC) $(CFLAGS) $(PERSONAL_CFLAGS) $(LDFLAGS) $(ALLDEPS) -o $@

