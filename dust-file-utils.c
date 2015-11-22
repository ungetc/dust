#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "dust-file-utils.h"
#include "io.h"
#include "memory.h"

FILE *extract_archive_listing(dust_index *index, dust_arena *arena, char *archive_infile)
{
  FILE *archive = NULL, *listing = NULL;
  uint32_t version = 0, magic = 0;
  struct dust_fingerprint f;

  assert(index);
  assert(arena);
  assert(archive_infile);

  archive = fopen(archive_infile, "r");
  if (!archive) {
    fprintf(stderr,
            "Failed to open archive file '%s'. Bailing.\n",
            archive_infile);
    return NULL;
  }

  /* read and parse archive file */
  dfread(&magic, sizeof(magic), 1, archive);
  dfread(f.bytes, 1, DUST_FINGERPRINT_SIZE, archive);
  assert(0 == fclose(archive));
  assert(ntohl(magic) == DUST_MAGIC);

  /* write out listing */
  listing = tmpfile();
  if (!listing) {
    fprintf(stderr,
            "Failed to open temporary file to hold file listing. Bailing.\n");
    return NULL;
  }

  if (extract_file(index, arena, f, listing, NULL) != DUST_OK) {
    fprintf(stderr,
            "Failed to extract file listing. Bailing.\n");
    assert(0 == fclose(listing));
    return NULL;
  }

  assert(0 == fseek(listing, 0, SEEK_SET));
  dfread(&magic, sizeof(magic), 1, listing);
  dfread(&version, sizeof(version), 1, listing);
  assert(ntohl(magic) == DUST_MAGIC);
  assert(ntohl(version) == DUST_VERSION);

  return listing;
}

int for_item_in_listing(dust_index *index,
                        dust_arena *arena,
                        FILE *listing,
                        int callback(dust_index *index, dust_arena *arena, struct listing_item item))
{
  int rv = DUST_OK;

  assert(index);
  assert(arena);
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
    dfread(&item.recordtype, sizeof(item.recordtype), 1, listing);
    dfread(&pathlen, sizeof(pathlen), 1, listing);
    item.recordtype = ntohl(item.recordtype);
    pathlen = ntohl(pathlen);

    /* Read path */
    item.path = dmalloc(pathlen);
    dfread(item.path, 1, pathlen, listing);

    switch (item.recordtype) {
    case DUST_LISTING_FILE: {
      dfread(&item.data.file.expected_fingerprint,
             DUST_FINGERPRINT_SIZE,
             1,
             listing);
      dfread(item.data.file.expected_hash,
             1,
             SHA256_DIGEST_LENGTH,
             listing);
      break;
    }
    case DUST_LISTING_DIRECTORY: {
      /* nothing special stored for directories */
      break;
    }
    case DUST_LISTING_SYMLINK: {
      uint32_t targetlen = 0;

      dfread(&targetlen, sizeof(targetlen), 1, listing);
      targetlen = ntohl(targetlen);

      item.data.symlink.targetpath = dmalloc(targetlen);
      dfread(item.data.symlink.targetpath,
             1,
             targetlen,
             listing);
      break;
    }
    default: {
      assert(0 && "invalid record type in listing");
    }
    }

    dfread(&item.permissions, sizeof(item.permissions), 1, listing);
    item.permissions = ntohl(item.permissions);

    if (DUST_OK != callback(index, arena, item)) {
      rv = !DUST_OK;
    }

    free(item.path);
    if (item.recordtype == DUST_LISTING_SYMLINK) {
      free(item.data.symlink.targetpath);
    }
  }

  return rv;
}

int extract_file(dust_index *index,
                 dust_arena *arena,
                 struct dust_fingerprint fingerprint,
                 FILE *outfile,
                 SHA256_CTX *hash_context)
{
  assert(index);
  assert(arena);

  struct dust_block *block = dust_get(index, arena, fingerprint);
  assert(block);

  if (dust_block_type(block) == DUST_TYPE_FILEDATA) {
    uint32_t size = dust_block_size(block);
    unsigned char *data = dust_block_data(block);

    if (hash_context) {
      assert(1 == SHA256_Update(hash_context, data, size));
    }

    if (outfile) {
      dfwrite(data, 1, size, outfile);
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
      if (DUST_OK != extract_file(index, arena, f, outfile, hash_context)) {
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

