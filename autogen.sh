#!/bin/sh
# $Id$

aclocal -I m4
autoheader
autoconf
automake --add-missing
libtoolize --force

test x$NOCONFIGURE = x && ./configure $*

