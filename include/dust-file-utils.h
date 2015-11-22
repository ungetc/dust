#ifndef DUST_FILE_UTILS_H
#define DUST_FILE_UTILS_H

#include "dust-internal.h"

#include <inttypes.h>
#include <openssl/sha.h>

#define DUST_MAGIC ((uint32_t)0xa7842a73ULL)
#define DUST_VERSION 1

#define DUST_OK 0

#define DUST_TYPE_FILEDATA     0
#define DUST_TYPE_FINGERPRINTS 1

#define DUST_LISTING_FILE      0
#define DUST_LISTING_DIRECTORY 1
#define DUST_LISTING_SYMLINK   2

struct listing_item {
  uint32_t recordtype; /* DUST_LISTING_... */
  uint32_t permissions;
  char *path;
  union {
    struct {
      struct dust_fingerprint expected_fingerprint;
      unsigned char expected_hash[SHA256_DIGEST_LENGTH];
    } file;
    struct {

    } directory;
    struct {
      char *targetpath;
    } symlink;
  } data;
};

/* Returns non-null on success. */
FILE *extract_archive_listing(dust_index *index, dust_arena *arena, char *archive_infile);

/* Returns DUST_OK if all items in the listing were processed successfully.
 * callback() must return DUST_OK if it succeeds in processing the item passed to
 * it, and !DUST_OK otherwise.
 * Be aware that strings, etc. pointed to by item may be deallocated by
 * for_item_in_listing after callback() has returned -- if you want a copy
 * of them, make a copy of them.
 */
int for_item_in_listing(dust_index *index,
                        dust_arena *arena,
                        FILE *listing,
                        int callback(dust_index *index, dust_arena *arena, struct listing_item item));

/* Returns DUST_OK on success. */
int extract_file(dust_index *index,
                 dust_arena *arena,
                 struct dust_fingerprint fingerprint,
                 FILE *outfile,
                 SHA256_CTX *hash_context);

#endif /* DUST_UTILS_H */

