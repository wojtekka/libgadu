lib_LTLIBRARIES = libgadu.la
libgadu_la_SOURCES = common.c dcc.c dcc7.c debug.c deflate.c encoding.c events.c handlers.c http.c libgadu.c message.c obsolete.c pubdir.c pubdir50.c resolver.c sha1.c
libgadu_la_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -DGG_IGNORE_DEPRECATED
libgadu_la_LDFLAGS = -version-number 3:13 -export-symbols $(srcdir)/libgadu.sym
EXTRA_DIST = libgadu.sym
