#include "dust-internal.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Reading and writing a a 4GB index is slow; don't do it for unit tests.
 */
#define TINY_INDEX_NUM_BUCKETS 1024

int main(void)
{
  dust_index *index = NULL;
  int rv;

  index = dust_open_index("index1", DUST_PERM_RW, DUST_INDEX_FLAG_NONE);
  assert(!index);

  index = dust_open_index("index2", DUST_PERM_RW, DUST_INDEX_FLAG_MMAP);
  assert(!index);

  index = dust_open_index("index3", DUST_PERM_READ, DUST_INDEX_FLAG_NONE);
  assert(!index);

  index = dust_open_index("index4", DUST_PERM_READ, DUST_INDEX_FLAG_MMAP);
  assert(!index);

  {
    index = dust_open_index("index5", DUST_PERM_RW, DUST_INDEX_FLAG_CREATE, TINY_INDEX_NUM_BUCKETS);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);

    index = dust_open_index("index5", DUST_PERM_READ, DUST_INDEX_FLAG_NONE);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);

    index = dust_open_index("index5", DUST_PERM_READ, DUST_INDEX_FLAG_MMAP | DUST_INDEX_FLAG_NONE);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);
  }

  {
    index = dust_open_index("index6", DUST_PERM_RW, DUST_INDEX_FLAG_MMAP | DUST_INDEX_FLAG_CREATE, TINY_INDEX_NUM_BUCKETS);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);

    index = dust_open_index("index6", DUST_PERM_READ, DUST_INDEX_FLAG_NONE);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);

    index = dust_open_index("index6", DUST_PERM_READ, DUST_INDEX_FLAG_MMAP | DUST_INDEX_FLAG_NONE);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);
  }

  index = dust_open_index("/dir/does/not/exist/index7", DUST_PERM_RW, DUST_INDEX_FLAG_CREATE, TINY_INDEX_NUM_BUCKETS);
  assert(!index);

  {
    FILE *f = fopen("index8", "w");
    assert(f);
    assert(fclose(f) == 0);

    index = dust_open_index("index8", DUST_PERM_READ, DUST_INDEX_FLAG_NONE);
    assert(!index);

    index = dust_open_index("index8", DUST_PERM_RW, DUST_INDEX_FLAG_NONE);
    assert(!index);

    index = dust_open_index("index8", DUST_PERM_READ, DUST_INDEX_FLAG_MMAP);
    assert(!index);

    index = dust_open_index("index8", DUST_PERM_RW, DUST_INDEX_FLAG_MMAP);
    assert(!index);

    index = dust_open_index("index8", DUST_PERM_RW, DUST_INDEX_FLAG_CREATE);
    assert(index);
    rv = dust_close_index(&index);
    assert(rv == DUST_OK);
    assert(!index);
  }

  return 0;
}

