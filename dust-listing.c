#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "dust-internal.h"
#include "dust-file-utils.h"
#include "options.h"

void fprint_permissions(FILE *f, int permissions)
{
  char permstr[10] = "---------";

  if (permissions & S_IRUSR) permstr[0] = 'r';
  if (permissions & S_IWUSR) permstr[1] = 'w';
  if (permissions & S_IXUSR) permstr[2] = 'x';
  if (permissions & S_IRGRP) permstr[3] = 'r';
  if (permissions & S_IWGRP) permstr[4] = 'w';
  if (permissions & S_IXGRP) permstr[5] = 'x';
  if (permissions & S_IROTH) permstr[6] = 'r';
  if (permissions & S_IWOTH) permstr[7] = 'w';
  if (permissions & S_IXOTH) permstr[8] = 'x';
  fprintf(f, "%s", permstr);
}

void fprint_hash(FILE *f, unsigned char *hash)
{
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    unsigned char c = hash[i];
    fprintf(f, "%c", "0123456789ABCDEF"[(c >> 4) & 0xF]);
    fprintf(f, "%c", "0123456789ABCDEF"[c & 0xF]);
  }
}

void fprint_fingerprint(FILE *f, struct dust_fingerprint fp)
{
  fprint_hash(f, fp.bytes);
}

int display_listing_item(struct dust_log *log, struct listing_item item)
{
  (void)log;
  switch (item.recordtype) {
  case DUST_LISTING_FILE: {
    printf("F ");
    fprint_permissions(stdout, item.permissions);
    printf(" ");
    fprint_hash(stdout, item.data.file.expected_hash);
    printf(" ");
    fprint_fingerprint(stdout, item.data.file.expected_fingerprint);
    printf(" %s\n", item.path);
    break;
  }
  case DUST_LISTING_DIRECTORY: {
    printf("D ");
    fprint_permissions(stdout, item.permissions);
    printf(" %s\n", item.path);
    break;
  }
  case DUST_LISTING_SYMLINK: {
    printf("S ");
    fprint_permissions(stdout, item.permissions);
    printf(" %s => %s\n", item.path, item.data.symlink.targetpath);
    break;
  }
  default: {
    /* Don't know how to process this. */
    return !DUST_OK;
  }
  }
  return DUST_OK;
}

/* Returns DUST_OK on success. */
int display_listing(struct dust_log *log,
                    char *archive_file)
{
  assert(log);
  assert(archive_file);

  FILE *listing = extract_archive_listing(log, archive_file);
  if (!listing) { exit(1); }

  return for_item_in_listing(log, listing, display_listing_item);
}

int main(int argc, char **argv)
{
  char *index = getenv("DUST_INDEX");
  char *arena = getenv("DUST_ARENA");
  int rv = 0;

  if (!index || strlen(index) == 0) index = "index";
  if (!arena || strlen(arena) == 0) arena = "arena";

  struct dust_log *log = dust_setup(index, arena);
  if (argc == 2) {
    if (DUST_OK != display_listing(log, argv[1])) rv = 1;
  }

  return rv;
}

