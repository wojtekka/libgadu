#!/bin/sh
# $Id$

aclocal -I m4
autoheader
libtoolize --copy --force
automake --add-missing --copy --force --foreign
autoconf

test x$NOCONFIGURE = x && ./configure $*

