noinst_PROGRAMS = protocol convert message $(OPTIONAL_TESTS)
EXTRA_PROGRAMS = protocol convert message connect packet resolver

CFLAGS = -Wall
LDADD = $(top_builddir)/src/libgadu.la
EXTRA_DIST = protocol.txt connect.txt

protocol_SOURCES = protocol.c script/script.c
protocol_CFLAGS = -Iscript

SUBDIRS = script

script/script.c:       $(wildcard script/*.scr) script/compile
	script/compile script/*.scr > script/script.c

clean-local:
	rm -f *.html *.log
