#ifndef DUST_H
#define DUST_H

#include <inttypes.h>

#define DUST_DATA_BLOCK_SIZE (1024 * 64)
#define DUST_FINGERPRINT_SIZE 32

#define DUST_OK 0

struct dust_log;
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

struct dust_log *dust_setup(const char *index_path, const char *arena_path);
void dust_teardown(struct dust_log **log);

/* Checks each block in the specified log, confirming that it's fingerprint
 * agrees with its contents.
 * log must be a value returned by dust_setup().
 * Returns DUST_OK if no errors are found; otherwise, returns some other value.
 */
int dust_check(struct dust_log *log);

/* Scans the specified arena, and produces a new index file at the specified
 * path. To minimize the chance of accidentally overwriting an existing index,
 * new_index_path must not be the same as the value of the DUST_INDEX envvar.
 * Returns DUST_OK if the rebuild completes successfully, and some other value
 * otherwise.
 */
int dust_rebuild_index(const char *arena_path, const char *new_index_path);

struct dust_fingerprint dust_put(struct dust_log *log, unsigned char *data, uint32_t size, uint32_t type);
struct dust_block *dust_get(struct dust_log *log, struct dust_fingerprint fingerprint);
void dust_release(struct dust_block **block);

uint32_t dust_block_type(struct dust_block *block);
uint32_t dust_block_size(struct dust_block *block);
uint64_t dust_block_wtime(struct dust_block *block);
unsigned char *dust_block_data(struct dust_block *block);

#endif /* DUST_H */

