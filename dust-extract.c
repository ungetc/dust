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

#include "dust-internal.h"
#include "dust-file-utils.h"
#include "options.h"

#define DUST_OK 0

#define DUST_LISTING_FILE      0
#define DUST_LISTING_DIRECTORY 1
#define DUST_LISTING_SYMLINK   2

/* If set, operate in 'dry run' mode -- don't actually extract any
 * files, but perform all other processing normally. */
int g_dry_run = 0;

/* Returns DUST_OK on success. */
int extract_files(struct dust_log *log, char *archive_file)
{
  assert(log);
  assert(archive_file);

  FILE *listing = extract_archive_listing(log, archive_file);
  if (!listing) { exit(1); }

  while (1) {
    uint32_t recordtype, pathlen;
    char *path = NULL;

    int c = getc(listing);
    if (c == EOF) {
      break;
    } else {
      assert(c == ungetc(c, listing));
    }

    assert(1 == fread(&recordtype, sizeof(recordtype), 1, listing));
    recordtype = ntohl(recordtype);

    assert(1 == fread(&pathlen, sizeof(pathlen), 1, listing));
    pathlen = ntohl(pathlen);

    path = malloc(pathlen);
    assert(path);
    assert(pathlen == fread(path, 1, pathlen, listing));

    switch (recordtype) {
    case DUST_LISTING_FILE: {
      FILE *out = NULL;
      struct dust_fingerprint f;
      unsigned char hash[SHA256_DIGEST_LENGTH];
      unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
      SHA256_CTX context;

      assert(1 == SHA256_Init(&context));
      assert(DUST_FINGERPRINT_SIZE == fread(f.bytes, 1, DUST_FINGERPRINT_SIZE, listing));
      assert(SHA256_DIGEST_LENGTH == fread(hash, 1, SHA256_DIGEST_LENGTH, listing));

      if (g_verbosity >= 1) {
        fprintf(stderr, "Extracting file: %s\n", path);
      }
      if (!g_dry_run) {
        out = fopen(path, "w");
        assert(out);
      }
      extract_file(log, f, out, &context);
      if (!g_dry_run) {
        assert(0 == fclose(out));
      }
      assert(1 == SHA256_Final(calculated_hash, &context));

      if (0 != memcmp(hash, calculated_hash, SHA256_DIGEST_LENGTH)) {
        fprintf(stderr,
                "Stored and calculated hashes of file don't match; probable "
                "corruption. Bailing.\n");
        assert(0 == fclose(listing));
        return !DUST_OK;
      }
      break;
    }
    case DUST_LISTING_DIRECTORY: {
      if (g_verbosity >= 1) {
        fprintf(stderr, "Extracting directory: %s\n", path);
      }
      if (!g_dry_run && (0 != mkdir(path, 0755))) {
        fprintf(stderr,
                "Failed to create directory. Bailing.\n");
        assert(0 == fclose(listing));
        return !DUST_OK;
      }
      break;
    }
    case DUST_LISTING_SYMLINK: {
      uint32_t targetbytes = 0;
      char *targetpath = NULL;

      assert(1 == fread(&targetbytes, sizeof(targetbytes), 1, listing));
      targetbytes = ntohl(targetbytes);

      targetpath = malloc(targetbytes);
      assert(targetpath);
      assert(targetbytes == fread(targetpath, 1, targetbytes, listing));

      if (g_verbosity >= 1) {
        fprintf(stderr, "Extracting symlink: %s\n", path);
      }
      if (!g_dry_run && (0 != symlink(targetpath, path))) {
        fprintf(stderr,
                "Failed to created symlink. Bailing.\n");
        assert(0 == fclose(listing));
        free(targetpath);
        return !DUST_OK;
      }
      free(targetpath);
      break;
    }
    default: {
      assert(0 && "invalid record type in listing");
    }
    }

    uint32_t permissions;
    assert(1 == fread(&permissions, sizeof(permissions), 1, listing));
    permissions = ntohl(permissions);

    if (!g_dry_run && (0 != lchmod(path, permissions))) {
      fprintf(stderr,
              "Failed to set permissions for '%s' to %" PRIu32 "\n. Bailing.\n",
              path,
              permissions);
      assert(0 == fclose(listing));
      return !DUST_OK;
    }

    free(path);
  }

  return DUST_OK;
}

int parse_options(int argc, char **argv)
{
  int ch;
  struct option opts[] = {
#include "shared-options.c"
    { "dry-run", no_argument, &g_dry_run, 1 }
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

  if (argc == 1) {
    if (DUST_OK == extract_files(log, argv[0])) {
      rv = 0;
    } else {
      rv = 1;
    }
  }

  dust_teardown(&log);

  return rv;
}

