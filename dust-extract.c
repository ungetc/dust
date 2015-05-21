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

/* If set, operate in 'dry run' mode -- don't actually extract any
 * files, but perform all other processing normally. */
int g_dry_run = 0;

int extract_listing_item(struct dust_log *log, struct listing_item item)
{
  switch (item.recordtype) {
  case DUST_LISTING_FILE: {
    FILE *out = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX context;

    assert(1 == SHA256_Init(&context));
    if (g_verbosity >= 1) {
      fprintf(stderr, "Extracting file: %s\n", item.path);
    }
    if (!g_dry_run) {
      out = fopen(item.path, "w");
      assert(out);
    }

    extract_file(log, item.data.file.expected_fingerprint, out, &context);

    if (!g_dry_run) {
      assert(0 == fclose(out));
    }
    assert(1 == SHA256_Final(hash, &context));
    if (0 != memcmp(hash, item.data.file.expected_hash, SHA256_DIGEST_LENGTH)) {
      fprintf(stderr,
              "Stored and calculated hashes of file don't match; probable "
              "corruption. Bailing.\n");
      exit(1);
    }
    break;
  }
  case DUST_LISTING_DIRECTORY: {
    if (g_verbosity >= 1) {
      fprintf(stderr, "Extracting directory: %s\n", item.path);
    }
    if (!g_dry_run && (0 != mkdir(item.path, 0755))) {
      fprintf(stderr, "Failed to create directory. Bailing.\n");
      exit(1);
    }
    break;
  }
  case DUST_LISTING_SYMLINK: {
    if (g_verbosity >= 1) {
      fprintf(stderr, "Extracting symlink: %s\n", item.path);
    }
    if (!g_dry_run && (0 != symlink(item.data.symlink.targetpath, item.path))) {
      fprintf(stderr,
              "Failed to create symlink. Bailing.\n");
      exit(1);
    }
    break;
  }
  default: {
    fprintf(stderr,
            "Encountered invalid listing record type '%" PRIu32 "'\n",
            item.recordtype);
    exit(1);
  }
  }

  if (!g_dry_run && (0 != lchmod(item.path, item.permissions))) {
    fprintf(stderr,
            "Failed to set permissions for '%s' to %" PRIu32 ". Bailing.\n",
            item.path,
            item.permissions);
    exit(1);
  }

  return DUST_OK;
}

/* Returns DUST_OK on success. */
int extract_files(struct dust_log *log, char *archive_file)
{
  assert(log);
  assert(archive_file);

  FILE *listing = extract_archive_listing(log, archive_file);
  if (!listing) { exit(1); }

  if (DUST_OK != for_item_in_listing(log, listing, extract_listing_item)) {
    fprintf(stderr, "Error encountered while extracting listing item. Bailing.\n");
    exit(1);
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

