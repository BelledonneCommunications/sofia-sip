#!/bin/sh 

set -x

aclocal -I m4 && \
autoheader && \
libtoolize --force && \
automake --add-missing --copy --include-deps --force --foreign && \
autoconf
