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

int extract_listing_item(dust_index *index, dust_arena *arena, struct listing_item item)
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

    extract_file(index, arena, item.data.file.expected_fingerprint, out, &context);

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
int extract_files(dust_index *index, dust_arena *arena, char *archive_file)
{
  assert(index);
  assert(arena);
  assert(archive_file);

  FILE *listing = extract_archive_listing(index, arena, archive_file);
  if (!listing) { exit(1); }

  if (for_item_in_listing(index, arena, listing, extract_listing_item) != DUST_OK) {
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
  char *archive_path = NULL;
  char *index_path = getenv("DUST_INDEX");
  char *arena_path = getenv("DUST_ARENA");
  dust_index *index = NULL;
  dust_arena *arena = NULL;

  if (!index_path || strlen(index_path) == 0) index_path = "index";
  if (!arena_path || strlen(arena_path) == 0) arena_path = "arena";

  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  if (argc != 1) {
    // TODO: usage
    goto fail;
  }
  archive_path = argv[0];

  index = dust_open_index(
    index_path,
    DUST_PERM_READ,
    DUST_INDEX_FLAG_NONE
  );
  if (!index) {
    fprintf(stderr, "Failed to open index file at '%s'.\n", index_path);
    goto fail;
  }

  arena = dust_open_arena(
    arena_path,
    DUST_PERM_READ,
    DUST_ARENA_FLAG_NONE
  );
  if (!arena) {
    fprintf(stderr, "Failed to open arena file at '%s'.\n", arena_path);
    goto fail;
  }

  if (extract_files(index, arena, archive_path) != DUST_OK) {
    fprintf(stderr, "Errors encountered while extracting files.\n");
    goto fail;
  }

  if (dust_close_arena(&arena) != DUST_OK) {
    fprintf(
      stderr,
      "Errors encountered while closing arena.\n"
    );
    arena = NULL;
    goto fail;
  }

  if (dust_close_index(&index) != DUST_OK) {
    fprintf(
      stderr,
      "Errors encountered while closing index.\n"
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

