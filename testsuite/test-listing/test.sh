#!/bin/sh

. ../test-common.sh

setup

mkdir "$TEST_DIR/orig"
cd "$TEST_DIR/orig"

touch testfile
mkdir testdir
ln -s testfile testlink

dd if=/dev/zero of=testfile bs=70000 count=1

chmod 657 testfile
chmod 725 testdir

cd "$TEST_DIR"
find orig | "$DUST"-archive > "$TEST_DIR/archive.dust"

"$DUST"-listing "$TEST_DIR/archive.dust" >> "$RAW_OUTPUT"

compare_output

chmod -R 755 "$TEST_DIR/orig"

teardown

