#ifndef DUST_MEMORY_H
#define DUST_MEMORY_H

#include <stddef.h>

/*
 * As a rule, dfoo behaves as the function "foo()" from the stdlib,
 * but will write a message to stderr and terminate the process if
 * it fails to allocate memory.
 */

void *dmalloc(size_t size);
char *dstrdup(const char *str);

#endif /* DUST_MEMROY_H */

