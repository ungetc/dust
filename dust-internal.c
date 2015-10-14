#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include "dust-internal.h"
#include "io.h"
#include "memory.h"
#include "types.h"

/* compile-time assert */
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define ct_assert(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/((e)?1:0) }

#define MAX_ENTRIES_PER_INDEX_BUCKET ((1024 * 4) / (sizeof (struct index_entry)))

#define ARENA_HUNK_SIZE (100 * 1000 * 1000)

ct_assert(DUST_FINGERPRINT_SIZE == SHA256_DIGEST_LENGTH);

struct index_entry {
  unsigned char fingerprint[DUST_FINGERPRINT_SIZE];
  uint64_t_be address; /* of the arena block */
};

ct_assert(sizeof (struct index_entry) == 40);
ct_assert(MAX_ENTRIES_PER_INDEX_BUCKET == 102);

struct index_bucket {
  struct index_entry entries[MAX_ENTRIES_PER_INDEX_BUCKET];
  uint32_t_be num_entries;
  uint8_t unused[12];
};

ct_assert(sizeof (struct index_bucket) == 4096);

struct index_header {
  uint64_t_be num_buckets;
  uint8_t unused[4088];
};

ct_assert(sizeof (struct index_header) == 4096);

struct arena_block_header {
  unsigned char fingerprint[DUST_FINGERPRINT_SIZE];
  uint32_t_be type;
  uint32_t_be size;
  uint64_t_be wtime;
};

ct_assert(sizeof (struct arena_block_header) == 48);

struct arena_block {
  struct arena_block_header header;
  unsigned char data[DUST_DATA_BLOCK_SIZE];
};

ct_assert(sizeof (struct arena_block) == sizeof (struct arena_block_header) + DUST_DATA_BLOCK_SIZE);

struct dust_log {
  struct index *index;
  FILE *arena;
  char *index_path;
};

struct dust_block {
  struct arena_block ablock;
};

struct index {
  struct index_header *header;
  struct index_bucket *buckets; /* array of header->num_buckets buckets */
};

int g_index_dirtied = 0;

static void fprint_fingerprint(FILE *out, const unsigned char *fingerprint)
{
  int i;
  assert(out);
  assert(fingerprint);
  for (i = 0; i < DUST_FINGERPRINT_SIZE; i++) {
    fprintf(out, "%c", "0123456789ABCDEF"[fingerprint[i] >> 4]);
    fprintf(out, "%c", "0123456789ABCDEF"[fingerprint[i] & 0xf]);
  }
}

/* Returns 0 for success, any other value for failure. */
static int load_existing_index(const char *index_path, struct index *index)
{
  assert(index_path);
  assert(index);

  FILE *index_file = fopen(index_path, "r");

  if (index_file == NULL) {
    fprintf(stderr, "Unable to open file '%s' for reading.\n", index_path);
    return -1;
  }

  struct index_header header;
  dfread(&header, sizeof(header), 1, index_file);

  uint64_t num_buckets = uint64be_to_host(header.num_buckets);
  /* TODO check for overflow when calculating the size of this buffer */
  uint64_t bufsize = sizeof(struct index_header) + (num_buckets * sizeof(struct index_bucket));
  char *index_buf = dmalloc(bufsize);

  memset(index_buf, 0, bufsize);
  memcpy(index_buf, &header, sizeof(header));
  dfread(index_buf + sizeof(header),
         sizeof(struct index_bucket),
         num_buckets,
         index_file);

  index->header = (struct index_header *)index_buf;
  index->buckets = (struct index_bucket *)(index_buf + sizeof(struct index_header));

  assert(0 == fclose(index_file));

  return 0;
}

static void init_new_index(struct index *index)
{
  assert(index);

  uint64_t default_num_buckets = (4ULL * 1024 * 1024 * 1024) / sizeof(struct index_bucket);

  index->header = dmalloc(sizeof(struct index_header));
  index->header->num_buckets = uint64host_to_be(default_num_buckets);

  index->buckets = calloc(default_num_buckets, sizeof(struct index_bucket));
  assert(index->buckets);
  memset(index->buckets, 0, default_num_buckets * sizeof(struct index_bucket));

  g_index_dirtied = 1;
}

static uint64_t index_bucket_expected_to_contain_fingerprint(struct index *index, unsigned char *fingerprint)
{
  uint64_t bucket = 0;

  for (size_t i = 0; i < DUST_FINGERPRINT_SIZE; i++) {
    bucket ^= (fingerprint[i] << ((i % 8) * 8));
  }
  bucket %= uint64be_to_host(index->header->num_buckets);

  return bucket;
}

/* Returns (uint64_t)-1 if fingerprint is not found in the index. */
static uint64_t get_address_of_fingerprint(struct index *index, unsigned char *fingerprint)
{
  assert(fingerprint);

  uint64_t bucket = index_bucket_expected_to_contain_fingerprint(index, fingerprint);
  struct index_bucket *b = &index->buckets[bucket];
  uint32_t num_entries = uint32be_to_host(b->num_entries);

  assert(num_entries <= MAX_ENTRIES_PER_INDEX_BUCKET);
  for (size_t i = 0; i < num_entries; i++) {
    if (memcmp(fingerprint, b->entries[i].fingerprint, DUST_FINGERPRINT_SIZE) == 0) {
      return uint64be_to_host(b->entries[i].address);
    }
  }
  return (uint64_t)-1;
}

/* Returns 0 for false, anything else for true. */
static int index_contains(struct index *index, unsigned char *fingerprint)
{
  assert(fingerprint);

  uint64_t address = get_address_of_fingerprint(index, fingerprint);
  return address != (uint64_t)-1;
}

static void add_fingerprint_to_index(struct index *index, unsigned char *fingerprint, uint64_t offset)
{
  assert(fingerprint);

  uint64_t bucket = index_bucket_expected_to_contain_fingerprint(index, fingerprint);
  struct index_bucket *b = &index->buckets[bucket];
  uint32_t num_entries = uint32be_to_host(b->num_entries);

  /* If we've overflowed the index, we want to know that asap. It's
   * too big to resize on the fly; might be able to do it as a separate
   * command at some point. */
  assert(num_entries < MAX_ENTRIES_PER_INDEX_BUCKET);

  memcpy(b->entries[num_entries].fingerprint, fingerprint, DUST_FINGERPRINT_SIZE);
  b->entries[num_entries].address = uint64host_to_be(offset);
  b->num_entries = uint32host_to_be(num_entries + 1);

  g_index_dirtied = 1;
}

static void add_block_to_arena(struct index *index, FILE *arena, struct arena_block *block)
{
  assert(index);
  assert(arena);
  assert(block);

  if (!index_contains(index, block->header.fingerprint)) {
    off_t foff = ftello(arena);
    uint32_t size = uint32be_to_host(block->header.size);
    uint64_t address = 0;

    assert(foff >= 0);
    address = foff;
    int64_t current_offset = address % ARENA_HUNK_SIZE;
    int64_t next_offset = current_offset + sizeof(block->header) + size;
    if (next_offset >= ARENA_HUNK_SIZE) {
      /* Zero out the remainder of our current hunk. */
      for ((void)current_offset; current_offset < ARENA_HUNK_SIZE; current_offset++) {
        assert(0 == putc(0, arena));
      }
    }

    foff = ftello(arena);
    assert(foff >= 0);
    address = foff;

    dfwrite(&block->header, sizeof(block->header), 1, arena);
    dfwrite(block->data, 1, size, arena);
    assert(0 == fflush(arena));
    add_fingerprint_to_index(index, block->header.fingerprint, address);
  }
}

static void fast_sanity_check_arena(FILE *arena)
{
  int fd = -1;
  uint64_t hunks_in_arena = 0;
  struct stat sb;

  assert(arena);
  fd = fileno(arena);
  assert(0 == fstat(fd, &sb));
  hunks_in_arena = sb.st_size / ARENA_HUNK_SIZE;
  assert(0 == fseeko(arena, hunks_in_arena * ARENA_HUNK_SIZE, SEEK_SET));

  while (1) {
    /* Starting from the beginning of our current arena hunk,
     * read each data block in turn, confirm it's the right size,
     * and confirm its fingerprint matches its contents.
     * This gives us a limited form of self-synchronization -- we
     * don't need to re-parse the entire arena in order to confirm
     * the most recent write wasn't cut off somehow. */
    struct arena_block block;
    uint32_t size = 0;
    unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
    int c;

    if (sb.st_size % ARENA_HUNK_SIZE == 0) break;
    c = getc(arena);
    if (c == EOF) {
      break;
    } else {
      assert(c == ungetc(c, arena));
    }

    dfread(&block.header, sizeof(block.header), 1, arena);
    size = uint32be_to_host(block.header.size);
    dfread(block.data, 1, size, arena);

    assert(SHA256_DIGEST_LENGTH == DUST_FINGERPRINT_SIZE);
    SHA256(block.data, size, calculated_hash);
    assert(0 == memcmp(block.header.fingerprint, calculated_hash, DUST_FINGERPRINT_SIZE));
  }
}

struct dust_log *dust_setup(const char *index_path, const char *arena_path)
{
  struct dust_log *log = dmalloc(sizeof *log);
  int existing_index_loaded = 0;

  log->index = dmalloc(sizeof *log->index);
  if (load_existing_index(index_path, log->index) != 0) {
    fprintf(stderr, "Unable to load existing index\n");
  } else {
    existing_index_loaded = 1;
  }

  log->arena = fopen(arena_path, "a+");
  assert(log->arena);
  log->index_path = dstrdup(index_path);

  fast_sanity_check_arena(log->arena);

  struct stat sb;
  int fd = fileno(log->arena);
  assert(0 == fstat(fd, &sb));

  if (sb.st_size == 0) {
    if (!existing_index_loaded) {
      fprintf(stderr, "creating new index...\n");
      init_new_index(log->index);
    }
  } else {
    assert(existing_index_loaded == 1);
  }

  return log;
}

static void fwrite_index(FILE *stream, struct index *index)
{
  uint64_t num_buckets = 0;

  assert(index);
  assert(index->header);
  assert(index->buckets);
  assert(stream);

  num_buckets = uint64be_to_host(index->header->num_buckets);
  dfwrite(index->header, sizeof(struct index_header), 1, stream);
  dfwrite(index->buckets, sizeof(struct index_bucket), num_buckets, stream);
}

void dust_teardown(struct dust_log **log)
{
  assert(log);
  assert(*log);

  if (g_index_dirtied) {
    FILE *index_file = fopen((*log)->index_path, "w");
    assert(index_file);
    fwrite_index(index_file, (*log)->index);
    assert(0 == fclose(index_file));
  }

  assert(0 == fclose((*log)->arena));
  free((*log)->index);
  free(*log);
  *log = NULL;
}

/* Returns DUST_OK if iteration was completed successfully.
 * Callback must return DUST_OK if it successfully processed its block,
 * and !DUST_OK if it failed for some reason.
 */
static int for_block_in_arena(FILE *arena,
                              int callback(struct arena_block block))
{
  struct arena_block_header zero_header;
  uint64_t arena_offset = 0;
  int rv = DUST_OK;

  assert(arena);
  assert(0 == fseeko(arena, 0, SEEK_SET));
  memset(&zero_header, 0, sizeof(zero_header));

  while (1) {
    struct arena_block block;
    uint32_t block_size = 0;
    int end_of_hunk = 0;
    int ch;

    ch = getc(arena);
    if (ch == EOF) {
      return rv;
    } else {
      assert(ch == ungetc(ch, arena));
    }

    if ((arena_offset % ARENA_HUNK_SIZE) + sizeof(block.header) > ARENA_HUNK_SIZE) {
      end_of_hunk = 1;
    }

    if (!end_of_hunk) {
      dfread(&block.header, sizeof(block.header), 1, arena);

      /* if it looks like the next header is all zeroes, we're at the
       * end of the current arena hunk; do a sanity check to make sure
       * this looks right, then confirm all remaining bytes in the hunk
       * are zero, and finally move on to processing the next hunk */
      if (memcmp(&block.header, &zero_header, sizeof(block.header)) == 0) {
        uint32_t offset_in_hunk = arena_offset % ARENA_HUNK_SIZE;

        if (offset_in_hunk + sizeof(struct arena_block) < ARENA_HUNK_SIZE) {
          fprintf(stderr,
                  "Arena hunk end encountered too soon: offset %" PRIu64 "\n",
                  arena_offset);
          rv = !DUST_OK;
        }
        end_of_hunk = 1;
      }
      arena_offset += sizeof(block.header);
    }

    if (end_of_hunk) {
      for ((void)arena_offset; (arena_offset % ARENA_HUNK_SIZE) != 0; arena_offset++) {
        int byte = getc(arena);
        if (byte != 0) {
          fprintf(stderr,
                  "Arena hunk trailer byte at location %" PRIu64 " == %d; expected 0.\n",
                  arena_offset,
                  byte);
          rv = !DUST_OK;
        }
      }

      /* We've hit the end of the current arena hunk; move onto processing the next
       * data block. */
      continue;
    }

    block_size = uint32be_to_host(block.header.size);
    dfread(block.data, 1, block_size, arena);
    arena_offset += block_size;

    rv = (callback(block) == DUST_OK ? rv : !DUST_OK);
  }

  return rv;
}

static int arena_block_fingerprint_matches_contents(struct arena_block block)
{
  unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
  uint32_t size = 0;

  assert(SHA256_DIGEST_LENGTH == DUST_FINGERPRINT_SIZE);
  size = uint32be_to_host(block.header.size);
  SHA256(block.data, size, calculated_hash);

  if (memcmp(block.header.fingerprint, calculated_hash, DUST_FINGERPRINT_SIZE) != 0) {
    fprintf(stderr, "%s:%d: Block fingerprint is ", __FILE__, __LINE__);
    fprint_fingerprint(stderr, block.header.fingerprint);
    fprintf(stderr, " but contents hash to ");
    fprint_fingerprint(stderr, calculated_hash);
    fprintf(stderr, "\n");
    return !DUST_OK;
  }

  return DUST_OK;
}

int dust_check(struct dust_log *log)
{
  int rv = DUST_OK;

  assert(log);
  assert(log->index);
  assert(log->arena);

  rv = for_block_in_arena(log->arena, arena_block_fingerprint_matches_contents);

  if (rv != DUST_OK) {
    fprintf(stderr, "Errors encountered during check.\n");
    return !DUST_OK;
  }

  return DUST_OK;
}

struct dust_fingerprint dust_put(struct dust_log *log, unsigned char *data, uint32_t size, uint32_t type)
{
  struct arena_block block;

  assert(log);
  assert(log->index);
  assert(log->arena);
  assert(data);
  assert(size <= sizeof(block.data));

  const char *fake_curtime = getenv("DUST_FAKE_TIMESTAMP");
  time_t curtime = (time_t)-1;

  if (fake_curtime) {
    curtime = atoi(fake_curtime);
  } else {
    curtime = time(NULL);
  }
  assert(curtime != (time_t)-1);

  SHA256(data, size, block.header.fingerprint);
  block.header.type = uint32host_to_be(type);
  block.header.size = uint32host_to_be(size);
  block.header.wtime = uint64host_to_be(curtime);
  memset(block.data, 0, sizeof(block.data));
  memcpy(block.data, data, size);

  struct dust_fingerprint result;
  memcpy(result.bytes, block.header.fingerprint, DUST_FINGERPRINT_SIZE);

  add_block_to_arena(log->index, log->arena, &block);

  return result;
}

struct dust_block *dust_get(struct dust_log *log, struct dust_fingerprint fingerprint)
{
  assert(log);

  uint64_t address = get_address_of_fingerprint(log->index, fingerprint.bytes);
  uint32_t size = 0;

  assert(address != (uint64_t)-1);
  /* TODO ensure address fits into an off_t, somehow */
  assert(0 == fseeko(log->arena, address, SEEK_SET));

  struct dust_block *result = dmalloc(sizeof *result);

  dfread(&result->ablock.header, sizeof(result->ablock.header), 1, log->arena);

  size = uint32be_to_host(result->ablock.header.size);
  dfread(result->ablock.data, 1, size, log->arena);

  assert(0 == memcmp(fingerprint.bytes, result->ablock.header.fingerprint, DUST_FINGERPRINT_SIZE));

  unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
  SHA256(result->ablock.data, size, calculated_hash);
  assert(SHA256_DIGEST_LENGTH == DUST_FINGERPRINT_SIZE);
  assert(0 == memcmp(fingerprint.bytes, calculated_hash, DUST_FINGERPRINT_SIZE));

  return result;
}

void dust_release(struct dust_block **block)
{
  assert(block);
  assert(*block);

  free(*block);
  *block = NULL;
}

uint32_t dust_block_type(struct dust_block *block)
{
  assert(block);
  return uint32be_to_host(block->ablock.header.type);
}

uint32_t dust_block_size(struct dust_block *block)
{
  assert(block);
  return uint32be_to_host(block->ablock.header.size);
}

uint64_t dust_block_wtime(struct dust_block *block)
{
  assert(block);
  return uint64be_to_host(block->ablock.header.wtime);
}

unsigned char *dust_block_data(struct dust_block *block)
{
  assert(block);
  return block->ablock.data;
}

