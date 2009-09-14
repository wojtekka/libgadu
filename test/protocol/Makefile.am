noinst_PROGRAMS = protocol
protocol_CFLAGS = -Wall
protocol_LDADD = $(top_builddir)/src/libgadu.la
protocol_SOURCES = protocol.c
nodist_protocol_SOURCES = script.c
noinst_HEADERS = script.h
EXTRA_DIST = compile readme.txt valgrind
SUBDIRS = tests

script.c:	$(wildcard tests/*.scr) compile
	./compile tests/*.scr > script.c

clean-local:
	rm -f *.log script.c
