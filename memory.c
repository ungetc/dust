#include "memory.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void *dmalloc(size_t size)
{
  void *buf = malloc(size);
  if (!buf) {
    fprintf(stderr,
            "%s: Failed to allocate memory. Terminating.\n",
            __func__);
    exit(1);
  }
  return buf;
}

char *dstrdup(const char *str)
{
  char *buf = strdup(str);
  if (!buf) {
    fprintf(stderr,
            "%s: Failed to allocate memory. Terminating.\n",
            __func__);
    exit(1);
  }
  return buf;
}

