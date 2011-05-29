TESTS = convert message2 message1 $(OPTIONAL_TESTS_GLIBC) $(OPTIONAL_TESTS_PERL)
check_PROGRAMS = convert message2 message1 $(OPTIONAL_TESTS_GLIBC) $(OPTIONAL_TESTS_PERL)
EXTRA_PROGRAMS = convert message2 message1 connect packet resolver protocol

CFLAGS = -Wall -ggdb -DGG_IGNORE_DEPRECATED

protocol_SOURCES = protocol.c
nodist_protocol_SOURCES = script/script.c
protocol_CFLAGS = -Iscript
protocol_LDADD = $(top_builddir)/src/libgadu.la

convert_SOURCES = convert.c $(top_builddir)/src/encoding.c

message1_SOURCES = message1.c

message2_SOURCES = message2.c $(top_builddir)/src/message.c
message2_LDADD = @LIBXML2_LIBS@
message2_CFLAGS = @LIBXML2_CFLAGS@

connect_LDADD = $(top_builddir)/src/libgadu.la

packet_LDADD = $(top_builddir)/src/libgadu.la

resolver_LDADD = $(top_builddir)/src/libgadu.la

EXTRA_DIST = protocol.txt connect.txt

SUBDIRS = script

script/script.c:       $(wildcard script/*.scr) script/compile
	$(PERL) script/compile script/*.scr > script/script.c

clean-local:
	rm -f *.html *.log *-valgrind

check-local:	$(check_PROGRAMS)
	for i in $(check_PROGRAMS); do ln -sf ../valgrind $${i}-valgrind; done
