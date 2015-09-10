#include "io.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(void)
{
  fprintf(stderr, "Terminating.\n");
  exit(1);
}

void dfwrite_func(const void *ptr, size_t size, size_t nmemb, FILE *stream, const char *file, int line)
{
  const char *cptr = ptr;
  size_t rv = 0;

  /* I hit a bug on FreeBSD where doing this:
   *   fwrite(ptr, size, nmemb, stream);
   * would return nmemb, but write nothing to stream. To work around
   * this bug, instead write one item at a time, in a loop. I didn't
   * investigate the failure in detail, but the conditions to trigger
   * it appeared to be something along the lines of "size * nmemb >
   * UINT_MAX".
   */
  for (rv = 0; rv < nmemb; rv++) {
    size_t inner_rv = fwrite(cptr, size, 1, stream);
    if (inner_rv != 1) {
      fprintf(stderr,
              "%s:%d: failed to complete write: %s\n",
              file,
              line,
              strerror(errno));
      die();
    }
    cptr += size;
  }
}

void dfread_func(void *ptr, size_t size, size_t nmemb, FILE *stream, const char *file, int line)
{
  size_t rv = fread(ptr, size, nmemb, stream);
  if (rv != nmemb) {
    if (ferror(stream)) {
      fprintf(stderr,
              "%s:%d: failed to complete read: %s\n",
              file,
              line,
              strerror(errno));
      die();
    } else if (feof(stream)) {
      fprintf(stderr,
              "%s:%d: failed to complete read: eof\n",
              file,
              line);
      die();
    } else {
      fprintf(stderr,
              "%s:%d: failed to complete read: unknown stream state: "
              "neither error nor eof\n",
              file,
              line);
      die();
    }
  }
}

