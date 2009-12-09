noinst_PROGRAMS = protocol convert message $(OPTIONAL_TESTS)
EXTRA_PROGRAMS = protocol convert message connect packet resolver

CFLAGS = -Wall -ggdb
protocol_LDADD = $(top_builddir)/src/libgadu.la
convert_LDADD = $(top_builddir)/src/libgadu.la
message_LDADD = $(top_builddir)/src/libgadu_la-message.lo
connect_LDADD = $(top_builddir)/src/libgadu.la
packet_LDADD = $(top_builddir)/src/libgadu.la
resolver_LDADD = $(top_builddir)/src/libgadu.la
EXTRA_DIST = protocol.txt connect.txt

protocol_SOURCES = protocol.c script/script.c
protocol_CFLAGS = -Iscript

SUBDIRS = script

script/script.c:       $(wildcard script/*.scr) script/compile
	script/compile script/*.scr > script/script.c

clean-local:
	rm -f *.html *.log *-valgrind

all-local:	$(noinst_PROGRAMS)
	for i in $(noinst_PROGRAMS); do ln -sf ../valgrind $${i}-valgrind; done
