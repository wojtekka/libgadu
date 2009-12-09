# XXX uzależnić libgadu.la od libgadu.sym
lib_LTLIBRARIES = libgadu.la
libgadu_la_SOURCES = common.c dcc.c dcc7.c events.c http.c obsolete.c pubdir.c pubdir50.c libgadu.c sha1.c resolver.c session.c encoding.c message.c debug.c buffer.c handlers.c
libgadu_la_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -DGG_IGNORE_DEPRECATED #-fprofile-arcs -ftest-coverage
libgadu_la_LDFLAGS = -version-number 3:90 -export-symbols libgadu.sym
EXTRA_DIST = libgadu.sym
