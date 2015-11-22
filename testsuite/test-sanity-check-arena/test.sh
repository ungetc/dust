#!/bin/sh

. ../test-common.sh

setup

cat "$DUST_ARENA" corruption > "$TEST_DIR/arena"

export DUST_ARENA="$TEST_DIR/arena"
if ls testfile | "$DUST"-archive > "$TEST_DIR/archive.dust" 2> "$RAW_OUTPUT"; then
  echo "Corruption of arena was not detected; failing."
  exit 1
fi

teardown

