#!/bin/sh
# $Id$

echo aclocal && aclocal -I m4
echo autoheader && autoheader
echo libtoolize && libtoolize --copy --force
echo automake && automake --add-missing --copy --force --foreign
echo autoconf && autoconf

test x$NOCONFIGURE = x && echo configure && ./configure $*

