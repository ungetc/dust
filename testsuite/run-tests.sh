#!/bin/sh

for testdir in `find . -type d -name 'test-*'`; do
  cd "$testdir"
  ./test.sh >/dev/null 2>&1

  if test $? -eq 0; then
    echo "Passed -- $testdir"
  else
    echo "FAILED -- $testdir"
  fi

  cd -
done

