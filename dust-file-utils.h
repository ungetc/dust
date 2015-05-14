#ifndef DUST_FILE_UTILS_H
#define DUST_FILE_UTILS_H

#include "dust-internal.h"

#include <openssl/sha.h>

#define DUST_TYPE_FILEDATA     0
#define DUST_TYPE_FINGERPRINTS 1

#define DUST_MAGIC ((uint32_t)0xa7842a73ULL)
#define DUST_VERSION 1

/* Returns non-null on success. */
FILE *extract_archive_listing(struct dust_log *log, char *archive_infile);

/* Returns DUST_OK on success. */
int extract_file(struct dust_log *log,
                 struct dust_fingerprint fingerprint,
                 FILE *outfile,
                 SHA256_CTX *hash_context);

#endif /* DUST_UTILS_H */

