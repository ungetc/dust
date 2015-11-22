#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dust-internal.h"

int main(int argc, char **argv)
{
  char *new_index_path = NULL;
  char *index_path = getenv("DUST_INDEX");
  char *arena_path = getenv("DUST_ARENA");
  dust_index *index = NULL;
  dust_arena *arena = NULL;

  if (argc != 2) {
    fprintf(stderr, "Usage: dust-rebuild-index <new-index-file>\n");
    exit(2);
  }

  new_index_path = argv[1];
  if (index_path && (strcmp(index_path, new_index_path) == 0)) {
    fprintf(stderr, "Path of new index must not match that in DUST_INDEX.\n");
    goto fail;
  }

  index = dust_open_index(
    new_index_path,
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
    DUST_PERM_READ,
    DUST_ARENA_FLAG_NONE
  );
  if (!arena) {
    fprintf(stderr, "Failed to open arena file at '%s'.\n", arena_path);
    goto fail;
  }

  if (dust_fill_index_from_arena(index, arena) != DUST_OK) {
    fprintf(stderr, "Errors encountered while rebuilding index.\n");
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
      "Errors encountered while closing new index. It is likely to be corrupt.\n"
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

