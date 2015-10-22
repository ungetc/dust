#!/bin/sh

. ../test-common.sh

setup

echo foobar | "$DUST"-archive > "$TEST_DIR/archive.dust"

mkdir "$TEST_DIR/extracted"
cd "$TEST_DIR/extracted"

# Perform a dry-run extraction, and confirm nothing was actually extracted.
"$DUST"-extract --dry-run "$TEST_DIR/archive.dust"
banner "Filesystem after dry run" >> "$RAW_OUTPUT"
find . >> "$RAW_OUTPUT"

# Perform an actual extraction, confirm the one expected file was extracted,
# and confirm its contents are as expected.
"$DUST"-extract "$TEST_DIR/archive.dust"
banner "Filesystem after extraction" >> "$RAW_OUTPUT"
find . >> "$RAW_OUTPUT"

echo "SHA512 of dust archive file: `sha512 $TEST_DIR/archive.dust`" >> "$RAW_OUTPUT"
echo "SHA512 of original foobar file: `sha512 $ORIG_PWD/foobar`" >> "$RAW_OUTPUT"
echo "SHA512 of extracted foobar file: `sha512 foobar`" >> "$RAW_OUTPUT"

compare_output

teardown

