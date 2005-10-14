#!/bin/sh 

set -x

aclocal -I m4 &&
autoheader &&
libtoolize --force &&
automake --add-missing --copy --include-deps --foreign &&
autoconf

find . -name 'run*' -o -name '*.sh' | xargs chmod +x
chmod +x scripts/*
