#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "dust-internal.h"
#include "dust-file-utils.h"
#include "options.h"

void fprint_permissions(FILE *f, int permissions)
{
  char permstr[10] = "---------";

  if (permissions & S_IRUSR) permstr[0] = 'r';
  if (permissions & S_IWUSR) permstr[1] = 'w';
  if (permissions & S_IXUSR) permstr[2] = 'x';
  if (permissions & S_IRGRP) permstr[3] = 'r';
  if (permissions & S_IWGRP) permstr[4] = 'w';
  if (permissions & S_IXGRP) permstr[5] = 'x';
  if (permissions & S_IROTH) permstr[6] = 'r';
  if (permissions & S_IWOTH) permstr[7] = 'w';
  if (permissions & S_IXOTH) permstr[8] = 'x';
  fprintf(f, "%s", permstr);
}

void fprint_hash(FILE *f, unsigned char *hash)
{
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    unsigned char c = hash[i];
    fprintf(f, "%c", "0123456789ABCDEF"[(c >> 4) & 0xF]);
    fprintf(f, "%c", "0123456789ABCDEF"[c & 0xF]);
  }
}

void fprint_fingerprint(FILE *f, struct dust_fingerprint fp)
{
  fprint_hash(f, fp.bytes);
}

int display_listing_item(dust_index *index, dust_arena *arena, struct listing_item item)
{
  (void)index;
  (void)arena;
  switch (item.recordtype) {
  case DUST_LISTING_FILE: {
    printf("F ");
    fprint_permissions(stdout, item.permissions);
    printf(" ");
    fprint_hash(stdout, item.data.file.expected_hash);
    printf(" ");
    fprint_fingerprint(stdout, item.data.file.expected_fingerprint);
    printf(" %s\n", item.path);
    break;
  }
  case DUST_LISTING_DIRECTORY: {
    printf("D ");
    fprint_permissions(stdout, item.permissions);
    printf(" %s\n", item.path);
    break;
  }
  case DUST_LISTING_SYMLINK: {
    printf("S ");
    fprint_permissions(stdout, item.permissions);
    printf(" %s => %s\n", item.path, item.data.symlink.targetpath);
    break;
  }
  default: {
    /* Don't know how to process this. */
    return !DUST_OK;
  }
  }
  return DUST_OK;
}

/* Returns DUST_OK on success. */
int display_listing(dust_index *index,
                    dust_arena *arena,
                    char *archive_file)
{
  assert(index);
  assert(arena);
  assert(archive_file);

  FILE *listing = extract_archive_listing(index, arena, archive_file);
  if (!listing) { exit(1); }

  return for_item_in_listing(index, arena, listing, display_listing_item);
}

int main(int argc, char **argv)
{
  char *archive_file = NULL;
  char *index_path = getenv("DUST_INDEX");
  char *arena_path = getenv("DUST_ARENA");
  dust_index *index = NULL;
  dust_arena *arena = NULL;

  if (argc != 2) {
    // TODO usage
    goto fail;
  }
  archive_file = argv[1];

  if (!index_path || strlen(index_path) == 0) index_path = "index";
  if (!arena_path || strlen(arena_path) == 0) arena_path = "arena";

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

  if (display_listing(index, arena, archive_file) != DUST_OK) {
    fprintf(stderr, "Errors encountered while displaying listing.\n");
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

