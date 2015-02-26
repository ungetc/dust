#define _WITH_GETLINE
#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "dust-internal.h"
#include "options.h"

#define DUST_OK 0

#define DUST_VERSION 1

#define DUST_MAGIC ((uint32_t)0xa7842a73ULL)

#define DUST_TYPE_FILEDATA     0
#define DUST_TYPE_FINGERPRINTS 1

#define DUST_LISTING_FILE      0
#define DUST_LISTING_DIRECTORY 1
#define DUST_LISTING_SYMLINK   2

/* If set, operate in 'dry run' mode -- don't actually extract any
 * files, but perform all other processing normally. */
int g_dry_run = 0;

/* Returns DUST_OK on success. */
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

/* Returns DUST_OK on success. */
int extract_files(struct dust_log *log, char *archive_file)
{
  assert(log);
  assert(archive_file);

  FILE *archive = fopen(archive_file, "r");
  if (!archive) {
    fprintf(stderr,
            "Failed to open archive file '%s'. Bailing.\n",
            archive_file);
    return !DUST_OK;
  }

  uint32_t magic;
  assert(1 == fread(&magic, sizeof(magic), 1, archive));
  magic = ntohl(magic);
  assert(magic == DUST_MAGIC);

  struct dust_fingerprint f;
  assert(DUST_FINGERPRINT_SIZE == fread(f.bytes, 1, DUST_FINGERPRINT_SIZE, archive));

  assert(0 == fclose(archive));

  FILE *listing = tmpfile();
  if (!listing) {
    fprintf(stderr,
            "Failed to open temporary file to hold file listing. Bailing.\n");
    return !DUST_OK;
  }
  
  if (DUST_OK != extract_file(log, f, listing, NULL)) {
    fprintf(stderr,
            "Failed to extract file listing. Bailing.\n");
    assert(0 == fclose(listing));
    return !DUST_OK;
  }

  assert(0 == fseek(listing, 0, SEEK_SET));

  assert(1 == fread(&magic, sizeof(magic), 1, listing));
  magic = ntohl(magic);
  assert(magic == DUST_MAGIC);

  uint32_t version;
  assert(1 == fread(&version, sizeof(version), 1, listing));
  version = ntohl(version);
  assert(version == DUST_VERSION);

  while (1) {
    uint32_t recordtype, pathlen;
    char *path = NULL;

    int c = getc(listing);
    if (c == EOF) {
      break;
    } else {
      assert(c == ungetc(c, listing));
    }

    assert(1 == fread(&recordtype, sizeof(recordtype), 1, listing));
    recordtype = ntohl(recordtype);

    assert(1 == fread(&pathlen, sizeof(pathlen), 1, listing));
    pathlen = ntohl(pathlen);

    path = malloc(pathlen);
    assert(path);
    assert(pathlen == fread(path, 1, pathlen, listing));

    switch (recordtype) {
    case DUST_LISTING_FILE: {
      FILE *out = NULL;
      struct dust_fingerprint f;
      unsigned char hash[SHA256_DIGEST_LENGTH];
      unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
      SHA256_CTX context;

      assert(1 == SHA256_Init(&context));
      assert(DUST_FINGERPRINT_SIZE == fread(f.bytes, 1, DUST_FINGERPRINT_SIZE, listing));
      assert(SHA256_DIGEST_LENGTH == fread(hash, 1, SHA256_DIGEST_LENGTH, listing));

      if (g_verbosity >= 1) {
        fprintf(stderr, "Extracting file: %s\n", path);
      }
      if (!g_dry_run) {
        out = fopen(path, "w");
        assert(out);
      }
      extract_file(log, f, out, &context);
      if (!g_dry_run) {
        assert(0 == fclose(out));
      }
      assert(1 == SHA256_Final(calculated_hash, &context));

      if (0 != memcmp(hash, calculated_hash, SHA256_DIGEST_LENGTH)) {
        fprintf(stderr,
                "Stored and calculated hashes of file don't match; probable "
                "corruption. Bailing.\n");
        assert(0 == fclose(listing));
        return !DUST_OK;
      }
      break;
    }
    case DUST_LISTING_DIRECTORY: {
      if (g_verbosity >= 1) {
        fprintf(stderr, "Extracting directory: %s\n", path);
      }
      if (!g_dry_run && (0 != mkdir(path, 0755))) {
        fprintf(stderr,
                "Failed to create directory. Bailing.\n");
        assert(0 == fclose(listing));
        return !DUST_OK;
      }
      break;
    }
    case DUST_LISTING_SYMLINK: {
      uint32_t targetbytes = 0;
      char *targetpath = NULL;

      assert(1 == fread(&targetbytes, sizeof(targetbytes), 1, listing));
      targetbytes = ntohl(targetbytes);

      targetpath = malloc(targetbytes);
      assert(targetpath);
      assert(targetbytes == fread(targetpath, 1, targetbytes, listing));

      if (g_verbosity >= 1) {
        fprintf(stderr, "Extracting symlink: %s\n", path);
      }
      if (!g_dry_run && (0 != symlink(targetpath, path))) {
        fprintf(stderr,
                "Failed to created symlink. Bailing.\n");
        assert(0 == fclose(listing));
        free(targetpath);
        return !DUST_OK;
      }
      free(targetpath);
      break;
    }
    default: {
      assert(0 && "invalid record type in listing");
    }
    }

    uint32_t permissions;
    assert(1 == fread(&permissions, sizeof(permissions), 1, listing));
    permissions = ntohl(permissions);

    if (!g_dry_run && (0 != lchmod(path, permissions))) {
      fprintf(stderr,
              "Failed to set permissions for '%s' to %" PRIu32 "\n. Bailing.\n",
              path,
              permissions);
      assert(0 == fclose(listing));
      return !DUST_OK;
    }

    free(path);
  }

  return DUST_OK;
}

int parse_options(int argc, char **argv)
{
  int ch;
  struct option opts[] = {
#include "shared-options.c"
    { "dry-run", no_argument, &g_dry_run, 1 }
  };

  while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1) {
    switch (ch) {
    case 0:
      break;
    default:
      exit(2);
    }
  }

  return optind;
}

int main(int argc, char **argv)
{
  char *index = getenv("DUST_INDEX");
  char *arena = getenv("DUST_ARENA");
  int rv = 0;

  if (!index || strlen(index) == 0) index = "index";
  if (!arena || strlen(arena) == 0) arena = "arena";

  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  struct dust_log *log = dust_setup(index, arena);

  if (argc == 1) {
    if (DUST_OK == extract_files(log, argv[0])) {
      rv = 0;
    } else {
      rv = 1;
    }
  }

  dust_teardown(&log);

  return rv;
}

