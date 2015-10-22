#!/bin/sh

. ../test-common.sh

setup

cd "$TEST_DIR"
ln -s foo bar

echo bar | "$DUST"-archive > "$TEST_DIR/archive.dust"

mkdir "$TEST_DIR/extracted"
cd "$TEST_DIR/extracted"

# Perform a dry-run extraction, and confirm nothing was actually extracted.
"$DUST"-extract --dry-run "$TEST_DIR/archive.dust"
banner "Filesystem after dry run" >> "$RAW_OUTPUT"
find . >> "$RAW_OUTPUT"

# Perform an actual extraction and confirm the expected file was extracted.
"$DUST"-extract "$TEST_DIR/archive.dust"
banner "Filesystem after extraction" >> "$RAW_OUTPUT"
find . >> "$RAW_OUTPUT"

banner "Destination of extracted symlink" >> "$RAW_OUTPUT"
readlink bar >> "$RAW_OUTPUT"

echo "SHA512 of dust archive file: `sha512 $TEST_DIR/archive.dust`" >> "$RAW_OUTPUT"

compare_output

teardown

