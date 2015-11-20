#include "dust-internal.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  dust_arena *arena = NULL;
  int rv;

  arena = dust_open_arena("arena1", DUST_PERM_READ, DUST_ARENA_FLAG_NONE);
  assert(!arena);

  arena = dust_open_arena("arena2", DUST_PERM_READ, DUST_ARENA_FLAG_CREATE);
  assert(!arena);

  arena = dust_open_arena("arena3", DUST_PERM_RW, DUST_ARENA_FLAG_NONE);
  assert(!arena);

  {
    arena = dust_open_arena("arena4", DUST_PERM_RW, DUST_ARENA_FLAG_CREATE);
    assert(arena);
    rv = dust_close_arena(&arena);
    assert(rv == DUST_OK);
    assert(!arena);

    arena = dust_open_arena("arena4", DUST_PERM_READ, DUST_ARENA_FLAG_NONE);
    assert(arena);
    rv = dust_close_arena(&arena);
    assert(rv == DUST_OK);
    assert(!arena);

    arena = dust_open_arena("arena4", DUST_PERM_READ, DUST_ARENA_FLAG_CREATE);
    assert(!arena);

    arena = dust_open_arena("arena4", DUST_PERM_RW, DUST_ARENA_FLAG_NONE);
    assert(arena);
    rv = dust_close_arena(&arena);
    assert(rv == DUST_OK);
    assert(!arena);

    arena = dust_open_arena("arena4", DUST_PERM_RW, DUST_ARENA_FLAG_CREATE);
    assert(arena);
    rv = dust_close_arena(&arena);
    assert(rv == DUST_OK);
    assert(!arena);
  }

  arena = dust_open_arena("/dir/does/not/exist/arena5", DUST_PERM_RW, DUST_ARENA_FLAG_CREATE);
  assert(!arena);

  return 0;
}

