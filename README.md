Overview
--------

dust is a deduplicating, integrity-checking backup tool.

It isn't yet ready for general use; I'd discourage you from relying on it for
anything you aren't enthused about losing.

The general structure is inspired by Plan 9's Venti -- an append-only arena
holds the actual file data, and a large hash table lets you look up data
blocks in the arena by their fingerprint. This index is currently sized at
4 GB, which should be big enough to address arenas up to around a terabyte
in size.

Building
--------

Provided you're on a Unix-like system, the only dependancy you should need
is OpenSSL.

The Makefile should work with at least GNU make and FreeBSD's make. To build:

    make all

To run the (still diminutive) testsuite:

    make testsuite

To install:

    make install

By default, it installs to a somewhat idiosyncratic location in your homedir;
if you'd prefer to install it somewhere else, change the PREFIX value in the
Makefile before running "make install".

Usage
-----

The arena and index locations are read from the DUST_ARENA and DUST_INDEX
environment variables. If those variables are unset, the default paths used
are "arena" and "index", respectively.

To archive the current directory:

    find . | dust-archive > archive.dust

The resulting "archive.dust" file contains nothing but a magic number and
the 32-byte fingerprint for the archived data.

To extract an archive:

    dust-extract archive.dust

dust-extract will not overwrite already-existing files; there isn't currently
a way to override this behaviour. (Actually, it will fail outright if it sees
that an already-existing file is at the same path that it wants to extract a
file to; this behaviour is a bit extreme and will probably be changed in the
future).

To perform an integrity check on the block-level data in the arena, run:

    dust-check

In addition to block-level hashes, dust-archive stores file-level hashes. These
aren't visible to dust-check, but are always checked by dust-extract. To
perform an integrity check on the file-level hashes without actually extracting
any files, run:

    dust-extract --dry-run archive.dust

If any of dust-archive, dust-extract, or dust-check fail, they will return
a nonzero exit code and produce a message explaining what went wrong.

