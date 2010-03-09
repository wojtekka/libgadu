noinst_PROGRAMS = protocol
LDADD = ../../src/libgadu.la
protocol_SOURCES = protocol.c
noinst_HEADERS = script.h
nodist_protocol_SOURCES = script.c
EXTRA_DIST = compile readme.txt valgrind
SUBDIRS = tests

script.c:	$(wildcard tests/*.scr) compile
	$(PERL) compile tests/*.scr > script.c

clean-local:
	rm -f *.log script.c
