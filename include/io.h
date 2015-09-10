#ifndef DUST_IO_H
#define DUST_IO_H

#include <stddef.h>
#include <stdio.h>

/* As fwrite(), but writes an error message to stderr and terminates
 * the process if the write fails.
 */
#define dfwrite(ptr, size, nmemb, stream) \
  dfwrite_func((ptr), (size), (nmemb), (stream), __FILE__, __LINE__)
void dfwrite_func(const void *ptr,
                  size_t size,
                  size_t nmemb,
                  FILE *stream,
                  const char *file,
                  int line);

/* As fread(), but writes an error message to stderr and terminates
 * the process if the read fails -- either because of an error or
 * because eof was encountered.
 */
#define dfread(ptr, size, nmemb, stream) \
  dfread_func((ptr), (size), (nmemb), (stream), __FILE__, __LINE__)
void dfread_func(void *ptr,
                 size_t size,
                 size_t nmemb,
                 FILE *stream,
                 const char *file,
                 int line);

#endif /* DUST_IO_H */

