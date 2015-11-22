#ifndef DUST_H
#define DUST_H

#include <inttypes.h>

#define DUST_DATA_BLOCK_SIZE (1024 * 64)
#define DUST_FINGERPRINT_SIZE 32

#define DUST_OK 0

struct dust_block;

typedef struct dust_arena dust_arena;
typedef struct dust_index dust_index;

struct dust_fingerprint {
  unsigned char bytes[DUST_FINGERPRINT_SIZE];
};

#define DUST_DEFAULT_NUM_BUCKETS (1024 * 1024) /* 4kB per index bucket; 4GB index by default */

#define DUST_PERM_READ 0 /* makes arena or index readable */
#define DUST_PERM_RW   1 /* makes arena or index read+writable; does not truncate */

#define DUST_ARENA_FLAG_NONE   0 /* default behaviour */
#define DUST_ARENA_FLAG_CREATE 1 /* create a new arena if one does not already exist; requires write permissions */

#define DUST_INDEX_FLAG_NONE   0 /* default behaviour */
#define DUST_INDEX_FLAG_CREATE 1 /* create a new index if one does not already exist; requires write permissions */
#define DUST_INDEX_FLAG_MMAP   2 /* index will be accessed with mmap, instead with stdio */

/* Returns a non-null value on success, and null on failure.
 * "permissions" is one of the DUST_PERM_* values.
 * "flags" is an or-ed combination of DUST_ARENA_FLAG_* values. */
dust_arena *dust_open_arena(const char *arena_path, int permissions, int flags);

/* Returns a non-null value on success, and null on failure.
 * "permissions" is one of the DUST_PERM_* values.
 * "flags" is an or-ed combination of DUST_INDEX_FLAG_* values.
 * If DUST_INDEX_FLAG_CREATE is specified, an additional uint64_t argument must be provided,
 *   specifying the number of buckets the newly-created index should have. Use
 *   DUST_DEFAULT_NUM_BUCKETS unless you have a concrete reason to do otherwise. */
dust_index *dust_open_index(const char *index_path, int permissions, int flags, ...);

/* Returns DUST_OK on success; some other value on failure. */
int dust_close_arena(dust_arena **arena);

/* Returns DUST_OK on success; some other value on failure. */
int dust_close_index(dust_index **index);

/* Checks each block in the specified log, confirming that it's fingerprint
 * agrees with its contents.
 * log must be a value returned by dust_setup().
 * Returns DUST_OK if no errors are found; otherwise, returns some other value.
 */
int dust_check(dust_index *index, dust_arena *arena);

/* Scans the specified arena, and adds each block in it to the specified index.
 * Useful for building a fresh index from an existing arena, and perhaps for
 * other things.
 * Returns DUST_OK on success, and some other value on failure.
 */
int dust_fill_index_from_arena(dust_index *index, dust_arena *arena);

struct dust_fingerprint dust_put(dust_index *index, dust_arena *arena, unsigned char *data, uint32_t size, uint32_t type);
struct dust_block *dust_get(dust_index *index, dust_arena *arena, struct dust_fingerprint fingerprint);
void dust_release(struct dust_block **block);

uint32_t dust_block_type(struct dust_block *block);
uint32_t dust_block_size(struct dust_block *block);
uint64_t dust_block_wtime(struct dust_block *block);
unsigned char *dust_block_data(struct dust_block *block);

#endif /* DUST_H */

