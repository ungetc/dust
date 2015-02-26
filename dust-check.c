#include <stdlib.h>
#include <string.h>

#include "dust-internal.h"

int main(void)
{
  char *index = getenv("DUST_INDEX");
  char *arena = getenv("DUST_ARENA");
  int rv = 0;

  if (!index || strlen(index) == 0) index = "index";
  if (!arena || strlen(arena) == 0) arena = "arena";

  struct dust_log *log = dust_setup(index, arena);

  if (dust_check(log) == DUST_OK) {
    rv = 0;
  } else {
    rv = 1;
  }

  dust_teardown(&log);

  return rv;
}

