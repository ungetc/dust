#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dust-internal.h"

int main(int argc, char **argv)
{
  char *arena = getenv("DUST_ARENA"), *new_index_path = NULL;
  int rv = 0;

  if (argc == 2) {
    fprintf(stderr, "Usage: dust-rebuild-index <new-index-file>\n");
    exit(2);
  }

  new_index_path = argv[1];
  rv = dust_rebuild_index(arena, new_index_path);

  if (rv != DUST_OK) {
    fprintf(stderr, "Errors encountered while rebuilding index.\n");
  }

  return rv;
}

