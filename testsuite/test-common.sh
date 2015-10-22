#!/bin/sh

# Tests should fail if any command fails.
set -e

# To avoid unpleasant surprises, don't permit unset envvars.
set -u

setup() {
  if test -z "`env | grep '^TMPDIR='`"; then
    export TEST_TMPDIR="/tmp"
  else
    export TEST_TMPDIR="$TMPDIR"
  fi

  export DUST="$PWD/../../dust"
  export TEST_DIR="$TEST_TMPDIR/`basename $PWD`"
  export ORIG_PWD="$PWD"

  export RAW_OUTPUT="$TEST_DIR/raw-output"
  export EXPECTED_OUTPUT="$ORIG_PWD/expected-output"

  export DUST_FAKE_TIMESTAMP=0

  rm -rf "$TEST_DIR"
  mkdir -p "$TEST_DIR"
}

compare_output() {
  test -d "$TEST_DIR"
  test -f "$RAW_OUTPUT"

  test -d "$ORIG_PWD"
  test -f "$EXPECTED_OUTPUT"

  diff "$RAW_OUTPUT" "$EXPECTED_OUTPUT"
}

teardown() {
  rm -r "$TEST_DIR"
}

sha512() {
  openssl sha512 "$1" | awk '{print $NF}'
}

banner() {
  echo "$1" | sed 's/./-/g'
  echo "$1"
  echo "$1" | sed 's/./-/g'
}

