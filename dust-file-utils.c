#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "dust-file-utils.h"
#include "memory.h"

FILE *extract_archive_listing(struct dust_log *log, char *archive_infile)
{
  FILE *archive = NULL, *listing = NULL;
  uint32_t version = 0, magic = 0;
  struct dust_fingerprint f;

  assert(archive_infile);

  archive = fopen(archive_infile, "r");
  if (!archive) {
    fprintf(stderr,
            "Failed to open archive file '%s'. Bailing.\n",
            archive_infile);
    return NULL;
  }

  /* read and parse archive file */
  assert(1 == fread(&magic, sizeof(magic), 1, archive));
  assert(DUST_FINGERPRINT_SIZE == fread(f.bytes, 1, DUST_FINGERPRINT_SIZE, archive));
  assert(0 == fclose(archive));
  assert(ntohl(magic) == DUST_MAGIC);

  /* write out listing */
  listing = tmpfile();
  if (!listing) {
    fprintf(stderr,
            "Failed to open temporary file to hold file listing. Bailing.\n");
    return NULL;
  }

  if (DUST_OK != extract_file(log, f, listing, NULL)) {
    fprintf(stderr,
            "Failed to extract file listing. Bailing.\n");
    assert(0 == fclose(listing));
    return NULL;
  }

  assert(0 == fseek(listing, 0, SEEK_SET));
  assert(1 == fread(&magic, sizeof(magic), 1, listing));
  assert(1 == fread(&version, sizeof(version), 1, listing));
  assert(ntohl(magic) == DUST_MAGIC);
  assert(ntohl(version) == DUST_VERSION);

  return listing;
}

int for_item_in_listing(struct dust_log *log,
                        FILE *listing,
                        int callback(struct dust_log *log, struct listing_item item))
{
  int rv = DUST_OK;

  assert(log);
  assert(listing);
  assert(callback);

  while (1) {
    struct listing_item item;
    uint32_t pathlen;

    int c = getc(listing);
    if (c == EOF) {
      break;
    } else {
      assert(c == ungetc(c, listing));
    }

    /* Read record type and path length */
    assert(1 == fread(&item.recordtype, sizeof(item.recordtype), 1, listing));
    assert(1 == fread(&pathlen, sizeof(pathlen), 1, listing));
    item.recordtype = ntohl(item.recordtype);
    pathlen = ntohl(pathlen);

    /* Read path */
    item.path = dmalloc(pathlen);
    assert(pathlen == fread(item.path, 1, pathlen, listing));

    switch (item.recordtype) {
    case DUST_LISTING_FILE: {
      assert(1 == fread(&item.data.file.expected_fingerprint,
                        DUST_FINGERPRINT_SIZE,
                        1,
                        listing));
      assert(SHA256_DIGEST_LENGTH == fread(item.data.file.expected_hash,
                                           1,
                                           SHA256_DIGEST_LENGTH,
                                           listing));
      break;
    }
    case DUST_LISTING_DIRECTORY: {
      /* nothing special stored for directories */
      break;
    }
    case DUST_LISTING_SYMLINK: {
      uint32_t targetlen = 0;

      assert(1 == fread(&targetlen, sizeof(targetlen), 1, listing));
      targetlen = ntohl(targetlen);

      item.data.symlink.targetpath = dmalloc(targetlen);
      assert(targetlen == fread(item.data.symlink.targetpath,
                                1,
                                targetlen,
                                listing));
      break;
    }
    default: {
      assert(0 && "invalid record type in listing");
    }
    }

    assert(1 == fread(&item.permissions, sizeof(item.permissions), 1, listing));
    item.permissions = ntohl(item.permissions);

    if (DUST_OK != callback(log, item)) {
      rv = !DUST_OK;
    }

    free(item.path);
    if (item.recordtype == DUST_LISTING_SYMLINK) {
      free(item.data.symlink.targetpath);
    }
  }

  return rv;
}

int extract_file(struct dust_log *log,
                 struct dust_fingerprint fingerprint,
                 FILE *outfile,
                 SHA256_CTX *hash_context)
{
  assert(log);

  struct dust_block *block = dust_get(log, fingerprint);
  assert(block);

  if (dust_block_type(block) == DUST_TYPE_FILEDATA) {
    uint32_t size = dust_block_size(block);
    unsigned char *data = dust_block_data(block);

    if (hash_context) {
      assert(1 == SHA256_Update(hash_context, data, size));
    }

    if (outfile && (size != fwrite(data, 1, size, outfile))) {
      fprintf(stderr,
              "Expected to write %" PRIu32 " bytes of data to outfile, "
              "but failed. Bailing.\n",
              size);
      return !DUST_OK;
    }

    dust_release(&block);
    return DUST_OK;
  }

  if (dust_block_type(block) == DUST_TYPE_FINGERPRINTS) {
    uint32_t size = dust_block_size(block);
    unsigned char *fingerprints = dust_block_data(block);

    if (size % DUST_FINGERPRINT_SIZE != 0) {
      fprintf(stderr,
              "Expected fingerprints listing block to have a size an integer "
              "multiple of the size of a fingerprint. Bailing.\n");
      return !DUST_OK;
    }

    for (uint32_t i = 0; i < size; i += DUST_FINGERPRINT_SIZE) {
      struct dust_fingerprint f;
      memcpy(f.bytes, fingerprints + i, DUST_FINGERPRINT_SIZE);
      if (DUST_OK != extract_file(log, f, outfile, hash_context)) {
        fprintf(stderr,
                "Encountered a problem while extracting a file. Bailing.\n");
        return !DUST_OK;
      }
    }

    dust_release(&block);
    return DUST_OK;
  }

  assert(0 && "should not be possible to reach here");
}

