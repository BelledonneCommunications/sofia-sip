#!/bin/sh 

autoconf=${autoconf:-autoconf} autoheader=${autoheader:-autoheader}

for version in 2.60 2.59 2.58 2.57 2.53 2.52; do
  if autoconf --version 2>/dev/null | fgrep -q "$version" ; then
    break
  elif autoconf-$version --version 2>/dev/null | fgrep -q "$version" ; then
    autoconf=autoconf-$version autoheader=autoheader-$version
    break
  fi
done

aclocal=${aclocal:-aclocal} automake=${automake:-automake}

for version in 1.9 1.7 1.8; do # No more 1.6
  if automake --version 2>/dev/null | fgrep -q "$version" ; then 
    break
  elif automake-$version --version 2>/dev/null | fgrep -q "$version" ; then
    automake=automake-$version aclocal=aclocal-$version
    break
  fi
done

libtoolize=${libtoolize:-libtoolize} glibtoolize=${glibtoolize:-glibtoolize}

set -x

$aclocal -I m4 &&
$autoheader 

if $libtoolize --force 2> /dev/null
  then echo using $libtoolize
elif $glibtoolize --force 2> /dev/null
  then echo using $glibtoolize
else
  echo "error: no libtoolize or glibtoolize found."
  exit -1
fi

$automake --add-missing --copy --include-deps --foreign &&
$autoconf

find . \( -name 'run*' -o -name '*.sh' \) -a -type f | xargs chmod +x
chmod +x scripts/*
