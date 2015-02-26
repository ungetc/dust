#ifndef DUST_H
#define DUST_H

#include <inttypes.h>

#define DUST_DATA_BLOCK_SIZE (1024 * 64)
#define DUST_FINGERPRINT_SIZE 32

#define DUST_OK 0

struct dust_log;
struct dust_block;

struct dust_fingerprint {
  unsigned char bytes[DUST_FINGERPRINT_SIZE];
};

struct dust_log *dust_setup(const char *index_path, const char *arena_path);
void dust_teardown(struct dust_log **log);

/* Checks each block in the specified log, confirming that it's fingerprint
 * agrees with its contents.
 * log must be a value returned by dust_setup().
 * Returns DUST_OK if no errors are found; otherwise, returns some other value.
 */
int dust_check(struct dust_log *log);

struct dust_fingerprint dust_put(struct dust_log *log, unsigned char *data, uint32_t size, uint32_t type);
struct dust_block *dust_get(struct dust_log *log, struct dust_fingerprint fingerprint);
void dust_release(struct dust_block **block);

uint32_t dust_block_type(struct dust_block *block);
uint32_t dust_block_size(struct dust_block *block);
uint64_t dust_block_wtime(struct dust_block *block);
unsigned char *dust_block_data(struct dust_block *block);

#endif /* DUST_H */

