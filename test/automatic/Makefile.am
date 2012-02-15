TESTS = convert endian1 message2 message1 hash $(OPTIONAL_TESTS_GLIBC) $(OPTIONAL_TESTS_GLIBC_GNUTLS) $(OPTIONAL_TESTS_PERL)
check_PROGRAMS = convert endian1 message2 message1 hash $(OPTIONAL_TESTS_GLIBC) $(OPTIONAL_TESTS_GLIBC_GNUTLS) $(OPTIONAL_TESTS_PERL)
EXTRA_PROGRAMS = convert endian1 message2 message1 hash connect packet resolver protocol

CFLAGS += -DGG_IGNORE_DEPRECATED

protocol_SOURCES = protocol.c
nodist_protocol_SOURCES = script/script.c
protocol_CFLAGS = -Iscript
protocol_LDADD = $(top_builddir)/src/libgadu.la

convert_SOURCES = convert.c $(top_builddir)/src/encoding.c

message1_SOURCES = message1.c

message2_SOURCES = message2.c $(top_builddir)/src/message.c
message2_LDADD = @LIBXML2_LIBS@
message2_CFLAGS = @LIBXML2_CFLAGS@

hash_SOURCES = hash.c $(top_builddir)/src/sha1.c $(top_builddir)/src/endian.c

endian1_SOURCES = endian1.c $(top_builddir)/src/endian.c

connect_LDADD = $(top_builddir)/src/libgadu.la -lgcrypt -lgnutls

packet_LDADD = $(top_builddir)/src/libgadu.la

resolver_LDADD = $(top_builddir)/src/libgadu.la

EXTRA_DIST = protocol.txt connect.txt

SUBDIRS = script

script/script.c:       $(wildcard script/*.scr) script/compile
	$(PERL) script/compile script/*.scr > script/script.c

clean-local:
	rm -f *.html *.log *-valgrind script/script.c

check-local:	$(check_PROGRAMS)
	for i in $(check_PROGRAMS); do ln -sf ../valgrind $${i}-valgrind; done
