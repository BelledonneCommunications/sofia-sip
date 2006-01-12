#!/bin/sh 

set -x

aclocal -I m4 &&
autoheader 

if libtoolize --force 2> /dev/null
  then echo using libtoolize
elif glibtoolize --force 2> /dev/null
  then echo using glibtoolize
else
  echo "error: no libtoolize or glibtoolize found."
  exit -1
fi

automake --add-missing --copy --include-deps --foreign &&
autoconf

find . \( -name 'run*' -o -name '*.sh' \) -a -type f | xargs chmod +x
chmod +x scripts/*
