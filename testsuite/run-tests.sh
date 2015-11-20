#!/bin/sh

make -C unit tidy all

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

cd unit
for testbin in `find . -type f -name 'test-*'`; do
  if ./$testbin; then
    echo "Passed -- $testbin"
  else
    echo "FAILED -- $testbin"
  fi
done
cd ..

make -C unit tidy

