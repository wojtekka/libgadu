#!/bin/sh
# $Id$

test -f Makefile && make clean

rm -rf \
	aclocal.m4 \
	autom4te.cache \
	compile \
	confdefs.h \
	config.* \
	configure \
	depcomp \
	install-sh \
	INSTALL \
	libtool \
	ltconfig \
	ltmain.sh \
	Makefile \
	Makefile.in \
	missing \
	mkinstalldirs \
	stamp* \
	stdint.h \
	src/Makefile \
	src/Makefile.in \
	src/.deps \
	src/.libs \
	include/Makefile \
	include/Makefile.in \
	include/libgadu-config.h \
	include/libgadu-stdint.h \
	include/stamp* \
	pkgconfig/Makefile \
	pkgconfig/Makefile.in \
	pkgconfig/libgadu.pc \
	pkgconfig/stamp*
