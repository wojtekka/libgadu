#!/bin/sh
# $Id$

echo protobuf && ./protobufgen.sh || exit 1
echo aclocal && aclocal -I m4 || exit 1
echo autoheader && autoheader || exit 1
echo libtoolize && libtoolize --copy || exit 1
echo automake && automake --add-missing --copy --foreign || exit 1
echo autoconf && autoconf || exit 1

if test x$NOCONFIGURE = x ; then
  echo configure
  ./configure $*
fi

