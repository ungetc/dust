#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dust-internal.h"

int main(void)
{
  char *index_path = getenv("DUST_INDEX");
  char *arena_path = getenv("DUST_ARENA");
  dust_index *index = NULL;
  dust_arena *arena = NULL;

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

  if (dust_check(index, arena) != DUST_OK) {
    fprintf(
      stderr,
      "Errors encountered while checking integrity of index and arena.\n"
      "One or both is likely corrupt.\n"
    );
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

