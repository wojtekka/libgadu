#!/bin/sh
# $Id$

echo aclocal && aclocal -I m4 || exit 1
echo autoheader && autoheader || exit 1
echo libtoolize && libtoolize --copy --force || exit 1
echo automake && automake --add-missing --copy --force --foreign || exit 1
echo autoconf && autoconf || exit 1

test x$NOCONFIGURE = x && echo configure && ./configure $*

