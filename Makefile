# Install directory. Binaries will go in $PREFIX/bin,
# manpages in $PREFIX/man, and so on.
PREFIX=$$HOME/opt/`uname`.`uname -m`

LDFLAGS=-lcrypto
CFLAGS=-Iinclude -O2 -std=c99 -Wall -Wextra -Werror

OBJS= \
  dust-internal.o \
  dust-file-utils.o \
  memory.o \
  types.o

BINARIES= \
  dust \
  dust-check \
  dust-archive \
  dust-extract \
  dust-listing

.PHONY: clean all install

all: $(BINARIES)

clean:
	rm -f $(BINARIES) $(OBJS)

install: all
	install -m 755 -d $(PREFIX)/bin/
	install -m 755 $(BINARIES) $(PREFIX)/bin/

build-binary: $(BINARY_NAME).c $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(BINARY_NAME).c $(OBJS) -o $(BINARY_NAME)

$(BINARIES):
	$(MAKE) BINARY_NAME=$@ build-binary

