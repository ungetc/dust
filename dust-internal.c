#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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
  uint64_t_be version;
  uint8_t unused[4080];
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
  struct dust_index *index;
  FILE *arena;
  char *index_path;
};

struct dust_block {
  struct arena_block ablock;
};

struct dust_arena {
  FILE *stream;
};

struct dust_index {
  int dirtied;
  int mmapped;
  int writable;
  union {
    int mmapped_fd;
    char *stdio_pathname;
  } file_data;
  struct index_header *header;
  struct index_bucket *buckets; /* array of header->num_buckets buckets */
};

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

/* index must be a valid pointer to a dust_index object.
 * fd must be a rw file descriptor open on an empty file to be used for an index
 * Returns DUST_OK on success, and some other value on failure.
 */
static int init_and_mmap_index_from_fd(int fd, dust_index *index, int mmap_prot, int num_buckets)
{
  uint64_t default_index_size = sizeof(*index->header)
                              + num_buckets * sizeof(*index->buckets);

  assert(index);
  index->header = MAP_FAILED;
  index->buckets = MAP_FAILED;

  if (ftruncate(fd, default_index_size) != 0) {
    goto fail;
  }
  if (lseek(fd, 0, SEEK_SET) != 0) {
    goto fail;
  }

  index->header = mmap(
    NULL,
    sizeof *index->header,
    mmap_prot,
    MAP_SHARED,
    fd,
    0
  );
  if (index->header == MAP_FAILED) {
    goto fail;
  }

  memset(index->header, 0, sizeof *index->header);
  index->header->num_buckets = uint64host_to_be(num_buckets);

  index->buckets = mmap(
    NULL,
    num_buckets * sizeof(*index->buckets),
    mmap_prot,
    MAP_SHARED,
    fd,
    sizeof *index->header
  );
  if (index->buckets == MAP_FAILED) {
    goto fail;
  }
  memset(index->buckets, 0, num_buckets * sizeof(*index->buckets));

  index->dirtied = 1;
  index->mmapped = 1;
  index->file_data.mmapped_fd = fd;

  return DUST_OK;

fail:
  if (index->header != MAP_FAILED) {
    assert(munmap(index->header, sizeof *index->header) == 0);
  }
  if (index->buckets != MAP_FAILED) {
    assert(munmap(index->buckets, num_buckets * sizeof(*index->buckets)) == 0);
  }
  return !DUST_OK;
}

/* index must be a valid pointer to a dust_index object.
 * fd must be a readable file descriptor open on an index file
 * Returns DUST_OK on success, and some other value on failure.
 */
static int mmap_existing_index_from_fd(int fd, dust_index *index, int mmap_prot)
{
  uint64_t num_buckets = 0;

  assert(index);
  index->header = MAP_FAILED;
  index->buckets = MAP_FAILED;

  index->header = mmap(
    NULL,
    sizeof *index->header,
    mmap_prot,
    MAP_SHARED,
    fd,
    0
  );
  if (index->header == MAP_FAILED) {
    goto fail;
  }

  num_buckets = uint64be_to_host(index->header->num_buckets);

  index->buckets = mmap(
    NULL,
    num_buckets * sizeof(*index->buckets),
    mmap_prot,
    MAP_SHARED,
    fd,
    sizeof *index->header
  );
  if (index->buckets == MAP_FAILED) {
    goto fail;
  }

  index->dirtied = 0;
  index->mmapped = 1;
  index->file_data.mmapped_fd = fd;

  return DUST_OK;

fail:
  if (index->header != MAP_FAILED) {
    assert(munmap(index->header, sizeof *index->header) == 0);
  }
  if (index->buckets != MAP_FAILED) {
    assert(munmap(index->buckets, num_buckets * sizeof(*index->buckets)) == 0);
  }
  return !DUST_OK;
}

/* index must be a valid pointer to a dust_index object.
 * stream must be a readable FILE* open on an index file
 * Returns DUST_OK on success, and some other value on failure.
 */
static int load_existing_index_from_stream(FILE *stream, dust_index *index)
{
  uint64_t num_buckets = 0;

  assert(index);
  index->header = NULL;
  index->buckets = NULL;

  index->header = malloc(sizeof *index->header);
  if (!index->header) {
    goto fail;
  }
  dfread(index->header, sizeof *index->header, 1, stream);

  num_buckets = uint64be_to_host(index->header->num_buckets);

  index->buckets = calloc(num_buckets, sizeof *index->buckets);
  if (!index->buckets) {
    goto fail;
  }
  dfread(index->buckets, sizeof *index->buckets, num_buckets, stream);

  index->dirtied = 0;
  index->mmapped = 0;

  return DUST_OK;

fail:
  if (index->header) {
    free(index->header);
  }
  if (index->buckets) {
    free(index->buckets);
  }
  return !DUST_OK;
}

static void init_new_index(struct dust_index *index, int num_buckets)
{
  assert(index);

  index->header = dmalloc(sizeof(struct index_header));
  index->header->num_buckets = uint64host_to_be(num_buckets);

  index->buckets = calloc(num_buckets, sizeof(struct index_bucket));
  assert(index->buckets);
  memset(index->buckets, 0, num_buckets * sizeof(struct index_bucket));

  index->dirtied = 1;
  index->mmapped = 0;
}

static uint64_t index_bucket_expected_to_contain_fingerprint(struct dust_index *index, unsigned char *fingerprint)
{
  uint64_t bucket = 0;

  for (size_t i = 0; i < DUST_FINGERPRINT_SIZE; i++) {
    bucket ^= (fingerprint[i] << ((i % 8) * 8));
  }
  bucket %= uint64be_to_host(index->header->num_buckets);

  return bucket;
}

/* Returns (uint64_t)-1 if fingerprint is not found in the index. */
static uint64_t get_address_of_fingerprint(struct dust_index *index, unsigned char *fingerprint)
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
static int index_contains(struct dust_index *index, unsigned char *fingerprint)
{
  assert(fingerprint);

  uint64_t address = get_address_of_fingerprint(index, fingerprint);
  return address != (uint64_t)-1;
}

static void add_fingerprint_to_index(struct dust_index *index, unsigned char *fingerprint, uint64_t offset)
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

  index->dirtied = 1;
}

static void add_block_to_arena(dust_index *index, dust_arena *arena, struct arena_block *block)
{
  assert(index);
  assert(arena);
  assert(block);

  if (!index_contains(index, block->header.fingerprint)) {
    off_t foff = 0;
    uint32_t size = uint32be_to_host(block->header.size);
    uint64_t address = 0;

    assert(fseek(arena->stream, 0, SEEK_END) == 0);
    foff = ftello(arena->stream);
    assert(foff >= 0);
    address = foff;
    int64_t current_offset = address % ARENA_HUNK_SIZE;
    int64_t next_offset = current_offset + sizeof(block->header) + size;
    if (next_offset >= ARENA_HUNK_SIZE) {
      /* Zero out the remainder of our current hunk. */
      for ((void)current_offset; current_offset < ARENA_HUNK_SIZE; current_offset++) {
        assert(0 == putc(0, arena->stream));
      }
    }

    assert(fseek(arena->stream, 0, SEEK_END) == 0);
    foff = ftello(arena->stream);
    assert(foff >= 0);
    address = foff;

    dfwrite(&block->header, sizeof(block->header), 1, arena->stream);
    dfwrite(block->data, 1, size, arena->stream);
    assert(0 == fflush(arena->stream));
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

dust_arena *dust_open_arena(const char *arena_path, int permissions, int flags)
{
  dust_arena *arena = NULL;
  int open_flags = 0;
  char *fopen_flags = NULL;
  FILE *stream = NULL;
  int fd = -1;

  assert(arena_path);
  assert(*arena_path);

  if (permissions == DUST_PERM_READ) {
    open_flags = O_RDONLY;
    fopen_flags = "r";
  } else if (permissions == DUST_PERM_RW) {
    open_flags = O_RDWR | O_APPEND;
    fopen_flags = "a+";
  } else {
    /* Invalid permissions. */
    goto fail;
  }

  if (flags & DUST_ARENA_FLAG_CREATE) {
    open_flags = open_flags | O_CREAT;

    /* CREATE requires us to have the write permission set. Failing to
     * do so is a programming error. */
    if (permissions != DUST_PERM_RW) {
      goto fail;
    }
  }

  fd = open(arena_path, open_flags, 0755);
  if (fd == -1) {
    goto fail;
  }

  stream = fdopen(fd, fopen_flags);
  if (!stream) {
    goto fail;
  }

  arena = malloc(sizeof *arena);
  if (!arena) {
    goto fail;
  }

  arena->stream = stream;
  return arena;

fail:
  if (stream) {
    fclose(stream);
  } else if (fd != -1) {
    close(fd);
  }
  if (arena) {
    free(arena);
  }
  return NULL;
}

dust_index *dust_open_index(const char *index_path, int permissions, int flags, ...)
{
  dust_index *index = NULL;
  int open_flags = 0, mmap_prot = PROT_NONE;
  FILE *stream = NULL;
  int fd = -1, fstat_rv = -1;
  struct stat sb;
  va_list ap;
  uint64_t num_buckets = DUST_DEFAULT_NUM_BUCKETS;

  assert(index_path);
  assert(*index_path);

  va_start(ap, flags);
  if (flags & DUST_INDEX_FLAG_CREATE) {
    num_buckets = va_arg(ap, uint64_t);
  }
  va_end(ap);

  if (permissions == DUST_PERM_READ) {
    open_flags = O_RDONLY;
    mmap_prot = PROT_READ;
  } else if (permissions == DUST_PERM_RW) {
    open_flags = O_RDWR;
    mmap_prot = PROT_READ | PROT_WRITE;
  } else {
    /* Invalid permissions. */
    goto fail;
  }

  if (flags & DUST_INDEX_FLAG_CREATE) {
    open_flags = open_flags | O_CREAT;

    /* CREATE requires us to have the write permission set. Failing to
     * do so is a programming error. */
    if (permissions != DUST_PERM_RW) {
      goto fail;
    }
  }

  fd = open(index_path, open_flags, 0755);
  if (fd == -1) {
    goto fail;
  }

  fstat_rv = fstat(fd, &sb);
  if (fstat_rv == -1) {
    goto fail;
  }

  index = malloc(sizeof *index);
  if (!index) {
    goto fail;
  }
  index->writable = (permissions == DUST_PERM_RW);

  if (!(flags & DUST_INDEX_FLAG_MMAP)) {
    index->file_data.stdio_pathname = strdup(index_path);
    assert(index->file_data.stdio_pathname);
  }

  if (sb.st_size == 0) {
    /* new or invalid index */

    if (!(flags & DUST_INDEX_FLAG_CREATE)) {
      /* couldn't have created new index, so it must be invalid */
      goto fail;
    }

    /* if mmap, then ftruncate the file to the expected size and mmap it */
    /* if not, then set up a new dust_index object and return a pointer to it */
    if (flags & DUST_INDEX_FLAG_MMAP) {
      if (init_and_mmap_index_from_fd(fd, index, mmap_prot, num_buckets) != DUST_OK) {
        goto fail;
      }
    } else {
      init_new_index(index, num_buckets);
      if (close(fd) != 0) {
        goto fail;
      }
    }
  } else {
    /* already-existing index; still possibly invalid */
    /* if mmap, then mmap the file */
    /* if not, then read the file and populate a dust_index object with it */
    if (flags & DUST_INDEX_FLAG_MMAP) {
      if (mmap_existing_index_from_fd(fd, index, mmap_prot) != DUST_OK) {
        goto fail;
      }
    } else {
      stream = fdopen(fd, "r");
      if (!stream) {
        goto fail;
      }
      if (load_existing_index_from_stream(stream, index) != DUST_OK) {
        goto fail;
      }
      if (fclose(stream) != 0) {
        goto fail;
      }
    }
  }

  if (uint64be_to_host(index->header->version) != 0) {
    goto fail;
  }

  return index;

fail:
  if (stream) {
    fclose(stream);
  } else if (fd != -1) {
    close(fd);
  }
  if (index) {
    free(index);
  }
  return NULL;
}

static void fwrite_index(FILE *stream, struct dust_index *index)
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

int dust_close_arena(dust_arena **arena)
{
  assert(arena && *arena);
  assert((*arena)->stream);

  if (fclose((*arena)->stream) != 0) {
    goto fail;
  }
  (*arena)->stream = NULL;
  free(*arena);
  *arena = NULL;

  return DUST_OK;

fail:
  return !DUST_OK;
}

int dust_close_index(dust_index **index)
{
  assert(index && *index);
  if ((*index)->writable) {
    if ((*index)->dirtied) {
      if ((*index)->mmapped) {
        uint64_t num_buckets = uint64be_to_host((*index)->header->num_buckets);
        assert(msync((*index)->header,
                     sizeof *(*index)->header,
                     MS_SYNC) == 0);
        assert(msync((*index)->buckets,
                     num_buckets * sizeof(*(*index)->buckets),
                     MS_SYNC) == 0);
        assert(munmap((*index)->header,
                      sizeof *(*index)->header) == 0);
        assert(munmap((*index)->buckets,
                      num_buckets * sizeof(*(*index)->buckets)) == 0);
        assert(close((*index)->file_data.mmapped_fd) == 0);
      } else {
        FILE *index_file = fopen((*index)->file_data.stdio_pathname, "w");
        assert(index_file);
        fwrite_index(index_file, *index);
        assert(fclose(index_file) == 0);

        free((*index)->header);
        free((*index)->buckets);
        memset((*index), 0, sizeof **index); /* make programming errors more likely to crash */
      }
    }
  }

  free(*index);
  *index = NULL;
  return DUST_OK;
}

/* Returns DUST_OK if iteration was completed successfully.
 * Callback must return DUST_OK if it successfully processed its block,
 * and !DUST_OK if it failed for some reason.
 * "offset" is the byte position of the block in the arena.
 */
static int for_block_in_arena(FILE *arena,
                              int callback(struct arena_block block, off_t offset, void *data),
                              void *data)
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

    off_t block_start_offset = arena_offset - block_size - sizeof(block.header);
    rv = (callback(block, block_start_offset, data) == DUST_OK ? rv : !DUST_OK);
  }

  return rv;
}

static int arena_block_fingerprint_matches_contents(struct arena_block block, off_t offset, void *data)
{
  unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
  uint32_t size = 0;

  (void)offset;
  (void)data;

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

static int add_block_fingerprint_to_index(struct arena_block block, off_t offset, void *data)
{
  struct dust_index *index = data;

  /* add_fingerprint_to_index asserts on failure */
  add_fingerprint_to_index(index, block.header.fingerprint, offset);
  return DUST_OK;
}

int dust_rebuild_index(const char *arena_path, const char *new_index_path)
{
  char *old_index_path = getenv("DUST_INDEX");
  int rv = DUST_OK;
  FILE *arena = NULL;
  struct dust_index *index = NULL;

  if (strcmp(old_index_path, new_index_path) == 0) {
    fprintf(stderr,
            "When rebuilding index, new index path must not "
            "match $DUST_INDEX. This is to ensure the existing "
            "index file is not overwritten unintentionally.\n");
    return !DUST_OK;
  }

  index = dmalloc(sizeof *index);
  init_new_index(index, DUST_DEFAULT_NUM_BUCKETS);

  assert(arena_path);
  assert(strlen(arena_path) > 0);
  arena = fopen(arena_path, "r");
  assert(arena);
  fast_sanity_check_arena(arena);

  rv = for_block_in_arena(arena, add_block_fingerprint_to_index, index);

  if (rv != DUST_OK) {
    fprintf(stderr, "Encountered errors while rebuilding index.\n");
    return !DUST_OK;
  }

  /* Teardown. */
  FILE *new_index_file = fopen(new_index_path, "w");
  assert(new_index_file);
  fwrite_index(new_index_file, index);
  assert(0 == fclose(new_index_file));
  assert(0 == fclose(arena));
  free(index->header);
  free(index->buckets);
  free(index);

  return DUST_OK;
}

int dust_check(dust_index *index, dust_arena *arena)
{
  int rv = DUST_OK;

  assert(index);
  assert(arena);

  rv = for_block_in_arena(arena->stream, arena_block_fingerprint_matches_contents, NULL);

  if (rv != DUST_OK) {
    fprintf(stderr, "Errors encountered during check.\n");
    return !DUST_OK;
  }

  return DUST_OK;
}

struct dust_fingerprint dust_put(dust_index *index, dust_arena *arena, unsigned char *data, uint32_t size, uint32_t type)
{
  struct arena_block block;

  assert(index);
  assert(arena);
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

  add_block_to_arena(index, arena, &block);

  return result;
}

struct dust_block *dust_get(dust_index *index, dust_arena *arena, struct dust_fingerprint fingerprint)
{
  assert(index);
  assert(arena);

  uint64_t address = get_address_of_fingerprint(index, fingerprint.bytes);
  uint32_t size = 0;

  assert(address != (uint64_t)-1);
  /* TODO ensure address fits into an off_t, somehow */
  assert(0 == fseeko(arena->stream, address, SEEK_SET));

  struct dust_block *result = dmalloc(sizeof *result);

  dfread(&result->ablock.header, sizeof(result->ablock.header), 1, arena->stream);

  size = uint32be_to_host(result->ablock.header.size);
  dfread(result->ablock.data, 1, size, arena->stream);

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

