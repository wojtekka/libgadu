#!/bin/sh
# $Id$

make clean
rm -rf config.* autom4te.cache Makefile.in Makefile COPYING INSTALL aclocal.m4 libtool 
rm -rf ltmain.sh depcomp install-sh missing mkinstalldirs stamp* configure confdefs.h ltconfig
rm -rf src/Makefile src/Makefile.in src/libgadu-config.h src/libgadu-config.h.in
rm -rf src/.deps
rm -rf src/libgadu-stdint.h stdint.h src/libgadu.pc
