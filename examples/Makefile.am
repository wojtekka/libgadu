noinst_PROGRAMS = send httphash conn-async status
LDADD = $(top_builddir)/src/libgadu.la
AM_LDFLAGS = @LDFLAGS_NO_INSTALL@
EXTRA_DIST = register.c remind.c token.c

#necessary for network.h file
AM_CFLAGS = -I$(top_srcdir)/include

httphash_CFLAGS = -DGG_IGNORE_DEPRECATED
