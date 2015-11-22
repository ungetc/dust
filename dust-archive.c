#define _WITH_GETLINE
#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "dust-internal.h"
#include "io.h"
#include "options.h"

#define DUST_VERSION 1

#define DUST_MAGIC ((uint32_t)0xa7842a73ULL)

#define DUST_TYPE_FILEDATA     0
#define DUST_TYPE_FINGERPRINTS 1

#define DUST_LISTING_FILE      0
#define DUST_LISTING_DIRECTORY 1
#define DUST_LISTING_SYMLINK   2

struct dust_fingerprint add_file(FILE *file,
                                 dust_index *index,
                                 dust_arena *arena,
                                 unsigned char *hash,
                                 uint32_t type)
{
  unsigned char block[DUST_DATA_BLOCK_SIZE];
  SHA256_CTX context;
  FILE *fplisting = tmpfile();
  uint64_t fpcount = 0;

  assert(file);
  assert(index);
  assert(arena);

  if (!fplisting) {
    fprintf(stderr, "Couldn't open fingerprint listing. Bailing.\n");
    exit(1);
  }

  if (hash) {
    assert(1 == SHA256_Init(&context));
  }

  while (1) {
    size_t bytes = fread(block, 1, DUST_DATA_BLOCK_SIZE, file);

    if (bytes < DUST_DATA_BLOCK_SIZE) {
      if (ferror(file)) {
        /* TODO return an error code, instead of blowing up */
        fprintf(stderr, "Error encountered while reading from file. Bailing.\n");
        exit(1);
      }
    }

    if (hash) {
      assert(1 == SHA256_Update(&context, block, bytes));
    }

    struct dust_fingerprint f = dust_put(index, arena, block, bytes, type);

    /* If we only needed to write out one data block for the file,
     * just return the fingerprint of that block. */
    if (feof(file) && fpcount == 0) {
      if (hash) {
        assert(1 == SHA256_Final(hash, &context));
      }
      assert(0 == fclose(fplisting));
      return f;
    }

    dfwrite(&f, DUST_FINGERPRINT_SIZE, 1, fplisting);
    fpcount++;

    if (feof(file)) {
      break;
    }
  }

  if (0 != fseek(fplisting, 0, SEEK_SET)) {
    fprintf(stderr,
            "Couldn't seek to beginning of fingerprint listing. Bailing.\n");
    exit(1);
  }

  struct dust_fingerprint f = add_file(fplisting, index, arena, hash, DUST_TYPE_FINGERPRINTS);
  assert(0 == fclose(fplisting));

  if (hash) {
    assert(1 == SHA256_Final(hash, &context));
  }

  return f;
}

/* Returns DUST_OK on success, and some other value on failure. */
int archive_files(dust_index *index, dust_arena *arena)
{
  FILE *listing = tmpfile();

  assert(index);
  assert(arena);

  if (listing == NULL) {
    fprintf(stderr,
            "Could not open temporary file to hold file listing. Bailing.\n");
    return !DUST_OK;
  }

  uint32_t magic = htonl(DUST_MAGIC);
  dfwrite(&magic, sizeof(magic), 1, listing);

  uint32_t version = htonl(DUST_VERSION);
  dfwrite(&version, sizeof(version), 1, listing);

  while (1) {
    struct stat sb;
    char *filename = NULL;
    size_t linecap = 0;
    ssize_t linelen = 0;

    linelen = getline(&filename, &linecap, stdin);
    if (linelen <= 0) break;

    /* drop the trailing newline */
    if (filename[linelen-1] == '\n') {
      filename[linelen-1] = '\0';
      linelen--;
    }

    if (0 != lstat(filename, &sb)) {
      fprintf(stderr,
              "Failed to stat file '%s'. Bailing.\n",
              filename);
      return !DUST_OK;
    }
    uint32_t permissions = htonl(sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO));

    if (S_ISREG(sb.st_mode)) {
      if (g_verbosity >= 1) {
        fprintf(stderr, "Archiving file: %s\n", filename);
      }

      FILE *file = fopen(filename, "r");
      if (file == NULL) {
        fprintf(stderr,
                "Could not open file '%s' for reading. Bailing.\n",
                filename);
        return !DUST_OK;
      }

      uint32_t recordtype = htonl(DUST_LISTING_FILE);
      uint32_t pathbytes = htonl(linelen+1); /* +1 for the trailing \0 */
      unsigned char hash[SHA256_DIGEST_LENGTH];
      struct dust_fingerprint f = add_file(file, index, arena, hash, DUST_TYPE_FILEDATA);

      dfwrite(&recordtype, sizeof(recordtype), 1, listing);
      dfwrite(&pathbytes, sizeof(pathbytes), 1, listing);
      dfwrite(filename, 1, linelen+1, listing);
      dfwrite(f.bytes, 1, DUST_FINGERPRINT_SIZE, listing);
      dfwrite(hash, 1, SHA256_DIGEST_LENGTH, listing);
      dfwrite(&permissions, sizeof(permissions), 1, listing);

      assert(0 == fclose(file));
      continue;
    }

    if (S_ISDIR(sb.st_mode)) {
      if (g_verbosity >= 1) {
        fprintf(stderr, "Archiving directory: %s\n", filename);
      }

      uint32_t recordtype = htonl(DUST_LISTING_DIRECTORY);
      uint32_t pathbytes = htonl(linelen+1);

      dfwrite(&recordtype, sizeof(recordtype), 1, listing);
      dfwrite(&pathbytes, sizeof(pathbytes), 1, listing);
      dfwrite(filename, 1, linelen+1, listing);
      dfwrite(&permissions, sizeof(permissions), 1, listing);
      continue;
    }

    if (S_ISLNK(sb.st_mode)) {
      if (g_verbosity >= 1) {
        fprintf(stderr, "Archiving symlink: %s\n", filename);
      }

      uint32_t recordtype = htonl(DUST_LISTING_SYMLINK);
      uint32_t pathbytes = htonl(linelen+1);
      uint32_t targetbytes = 0;
      ssize_t targetlen = 0;
      char targetpath[4096];

      memset(targetpath, 0, sizeof(targetpath));
      targetlen = readlink(filename, targetpath, sizeof(targetpath));
      if (targetlen == -1) {
        fprintf(stderr,
                "Error encountered reading link '%s'. Bailing.\n",
                filename);
        return !DUST_OK;
      }

      targetbytes = htonl(targetlen + 1); /* include trailing '\0' */

      dfwrite(&recordtype, sizeof(recordtype), 1, listing);
      dfwrite(&pathbytes, sizeof(pathbytes), 1, listing);
      dfwrite(filename, 1, linelen+1, listing);
      dfwrite(&targetbytes, sizeof(targetbytes), 1, listing);
      dfwrite(targetpath, 1, targetlen+1, listing);
      dfwrite(&permissions, sizeof(permissions), 1, listing);
      continue;
    }

    fprintf(stderr, "Couldn't open file or directory '%s' for reading.\n", filename);
    return !DUST_OK;
  }

  if (0 != fflush(listing)) {
    fprintf(stderr, "Couldn't flush listing file to disk. Bailing.\n");
    return !DUST_OK;
  }

  if (0 != fseeko(listing, 0, SEEK_SET)) {
    fprintf(stderr, "Couldn't seek to beginning of listing. Bailing.\n");
    return !DUST_OK;
  }

  struct dust_fingerprint f = add_file(listing, index, arena, NULL, DUST_TYPE_FILEDATA);

  dfwrite(&magic, sizeof(magic), 1, stdout);
  dfwrite(f.bytes, 1, DUST_FINGERPRINT_SIZE, stdout);
  assert(0 == fclose(listing));

  return DUST_OK;
}

int parse_options(int argc, char **argv)
{
  int ch;
  struct option opts[] = {
#include "shared-options.c"
  };

  while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1) {
    switch (ch) {
    case 0:
      break;
    default:
      exit(2);
    }
  }

  return optind;
}

int main(int argc, char **argv)
{
  char *index_path = getenv("DUST_INDEX");
  char *arena_path = getenv("DUST_ARENA");
  dust_index *index = NULL;
  dust_arena *arena = NULL;

  if (!index_path || strlen(index_path) == 0) index_path = "index";
  if (!arena_path || strlen(arena_path) == 0) arena_path = "arena";

  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  index = dust_open_index(
    index_path,
    DUST_PERM_RW,
    DUST_INDEX_FLAG_CREATE,
    DUST_DEFAULT_NUM_BUCKETS
  );
  if (!index) {
    fprintf(stderr, "Failed to open index file at '%s'.\n", index_path);
    goto fail;
  }

  arena = dust_open_arena(
    arena_path,
    DUST_PERM_RW,
    DUST_ARENA_FLAG_CREATE
  );
  if (!arena) {
    fprintf(stderr, "Failed to open arena file at '%s'.\n", arena_path);
    goto fail;
  }

  if (archive_files(index, arena) != DUST_OK) {
    fprintf(stderr, "Errors encountered while archiving files.\n");
    goto fail;
  }

  if (dust_close_arena(&arena) != DUST_OK) {
    fprintf(
      stderr,
      "Errors encountered while closing arena. Data may have been lost.\n"
    );
    arena = NULL;
    goto fail;
  }

  if (dust_close_index(&index) != DUST_OK) {
    fprintf(
      stderr,
      "Errors encountered while closing index. Index file is likely to be corrupt.\n"
    );
    index = NULL;
    goto fail;
  }

  return 0;

fail:
  if (arena) {
    dust_close_arena(&arena);
  }
  if (index) {
    dust_close_index(&index);
  }
  return 1;
}

