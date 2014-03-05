SUBDIRS = lib

check_PROGRAMS = client userlist

if HAVE_GLIBC
check_PROGRAMS += dcc7
else
if HAVE_MINGW
check_PROGRAMS += dcc7
endif
endif

if HAVE_CURL_AND_EXPAT
check_PROGRAMS += search
endif
# Wyłączone.
# if HAVE_SPEEX_AND_GSM
# check_PROGRAMS += voice7
# endif

EXTRA_PROGRAMS = client userlist dcc7 search voice7
CLEANFILES = client userlist dcc7 search voice7

AM_CPPFLAGS = -DGG_IGNORE_DEPRECATED -I$(top_srcdir)/include
AM_LDFLAGS = @LDFLAGS_NO_INSTALL@

dcc7_LDADD = $(top_builddir)/src/libgadu.la
dcc7_SOURCES = dcc7.c userconfig.c userconfig.h
nodist_dcc7_SOURCES = libgadu-network.c

client_LDADD = $(top_builddir)/src/libgadu.la
client_SOURCES = client.c userconfig.c userconfig.h

userlist_LDADD = $(top_builddir)/src/libgadu.la
userlist_SOURCES = userlist.c userconfig.c userconfig.h

search_SOURCES = search.c
search_LDADD = lib/libsearch.a -lcurl -lexpat @MINGW_LDFLAGS@

voice7_CFLAGS = -DHAVE_SPEEX -DHAVE_GSM
voice7_LDADD = $(top_builddir)/src/libgadu.la -lgsm -lspeex

clean-local:
	rm -f *.log *-valgrind libgadu-*.c

check-local:      $(check_PROGRAMS)
	for i in $(check_PROGRAMS); do ln -sf ../valgrind $${i}-valgrind; done

libgadu-%.c: ../../src/%.c
	$(AM_V_GEN)cat "$<" > "$@"
