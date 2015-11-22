#!/bin/sh

. ../test-common.sh

setup

mkdir "$TEST_DIR/orig"
cd "$TEST_DIR/orig"

# Make sure there's something in the arena, and therefore the index.
touch testfile
dd if=/dev/zero of=testfile bs=70000 count=1
cd "$TEST_DIR"
find orig | "$DUST"-archive > "$TEST_DIR/archive.dust"

# Build a new index, and verify that it's the same as the existing one.
"$DUST"-rebuild-index new-index
cmp "$DUST_INDEX" new-index

teardown

