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
    goto fail;
  }

  arena = dust_open_arena(
    arena_path,
    DUST_PERM_READ,
    DUST_ARENA_FLAG_NONE
  );
  if (!arena) {
    goto fail;
  }

  if (dust_check(index, arena) != DUST_OK) {
    goto fail;
  }

  if (dust_close_arena(&arena) != DUST_OK) {
    arena = NULL;
    goto fail;
  }

  if (dust_close_index(&index) != DUST_OK) {
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

