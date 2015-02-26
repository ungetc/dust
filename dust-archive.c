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
#include "options.h"

#define DUST_VERSION 1

#define DUST_MAGIC ((uint32_t)0xa7842a73ULL)

#define DUST_TYPE_FILEDATA     0
#define DUST_TYPE_FINGERPRINTS 1

#define DUST_LISTING_FILE      0
#define DUST_LISTING_DIRECTORY 1
#define DUST_LISTING_SYMLINK   2

struct dust_fingerprint add_file(FILE *file,
                                 struct dust_log *log,
                                 unsigned char *hash,
                                 uint32_t type)
{
  unsigned char block[DUST_DATA_BLOCK_SIZE];
  SHA256_CTX context;
  FILE *fplisting = tmpfile();
  uint64_t fpcount = 0;

  assert(file);
  assert(log);

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

    struct dust_fingerprint f = dust_put(log, block, bytes, type);

    /* If we only needed to write out one data block for the file,
     * just return the fingerprint of that block. */
    if (feof(file) && fpcount == 0) {
      if (hash) {
        assert(1 == SHA256_Final(hash, &context));
      }
      assert(0 == fclose(fplisting));
      return f;
    }

    assert(1 == fwrite(&f, DUST_FINGERPRINT_SIZE, 1, fplisting));
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

  struct dust_fingerprint f = add_file(fplisting, log, hash, DUST_TYPE_FINGERPRINTS);
  assert(0 == fclose(fplisting));

  if (hash) {
    assert(1 == SHA256_Final(hash, &context));
  }

  return f;
}

/* Returns DUST_OK on success, and some other value on failure. */
int archive_files(struct dust_log *log)
{
  FILE *listing = tmpfile();

  if (log == NULL) {
    fprintf(stderr, "Invalid log. Bailing.\n");
    return !DUST_OK;
  }

  if (listing == NULL) {
    fprintf(stderr,
            "Could not open temporary file to hold file listing. Bailing.\n");
    return !DUST_OK;
  }

  uint32_t magic = htonl(DUST_MAGIC);
  if (1 != fwrite(&magic, sizeof(magic), 1, listing)) {
    fprintf(stderr, "Error while attempting to write to listing. Bailing.\n");
    return !DUST_OK;
  }

  uint32_t version = htonl(DUST_VERSION);
  if (1 != fwrite(&version, sizeof(version), 1, listing)) {
    fprintf(stderr, "Error while attempting to write to listing. Bailing.\n");
    return !DUST_OK;
  }

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
      struct dust_fingerprint f = add_file(file, log, hash, DUST_TYPE_FILEDATA);

      assert(1 == fwrite(&recordtype, sizeof(recordtype), 1, listing));
      assert(1 == fwrite(&pathbytes, sizeof(pathbytes), 1, listing));
      assert((size_t)(linelen+1) == fwrite(filename, 1, linelen+1, listing));
      assert(DUST_FINGERPRINT_SIZE == fwrite(f.bytes, 1, DUST_FINGERPRINT_SIZE, listing));
      assert(SHA256_DIGEST_LENGTH == fwrite(hash, 1, SHA256_DIGEST_LENGTH, listing));
      assert(1 == fwrite(&permissions, sizeof(permissions), 1, listing));

      assert(0 == fclose(file));
      continue;
    }

    if (S_ISDIR(sb.st_mode)) {
      if (g_verbosity >= 1) {
        fprintf(stderr, "Archiving directory: %s\n", filename);
      }

      uint32_t recordtype = htonl(DUST_LISTING_DIRECTORY);
      uint32_t pathbytes = htonl(linelen+1);

      assert(1 == fwrite(&recordtype, sizeof(recordtype), 1, listing));
      assert(1 == fwrite(&pathbytes, sizeof(pathbytes), 1, listing));
      assert((size_t)(linelen+1) == fwrite(filename, 1, linelen+1, listing));
      assert(1 == fwrite(&permissions, sizeof(permissions), 1, listing));
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

      assert(1 == fwrite(&recordtype, sizeof(recordtype), 1, listing));
      assert(1 == fwrite(&pathbytes, sizeof(pathbytes), 1, listing));
      assert((size_t)(linelen+1) == fwrite(filename, 1, linelen+1, listing));
      assert(1 == fwrite(&targetbytes, sizeof(targetbytes), 1, listing));
      assert((size_t)(targetlen+1) == fwrite(targetpath, 1, targetlen+1, listing));
      assert(1 == fwrite(&permissions, sizeof(permissions), 1, listing));
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

  struct dust_fingerprint f = add_file(listing, log, NULL, DUST_TYPE_FILEDATA);

  assert(1 == fwrite(&magic, sizeof(magic), 1, stdout));
  assert(DUST_FINGERPRINT_SIZE == fwrite(f.bytes, 1, DUST_FINGERPRINT_SIZE, stdout));
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
  char *index = getenv("DUST_INDEX");
  char *arena = getenv("DUST_ARENA");
  int rv = 0;

  if (!index || strlen(index) == 0) index = "index";
  if (!arena || strlen(arena) == 0) arena = "arena";

  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  struct dust_log *log = dust_setup(index, arena);

  if (archive_files(log) == DUST_OK) {
    rv = 0;
  } else {
    rv = 1;
  }

  dust_teardown(&log);

  return rv;
}

