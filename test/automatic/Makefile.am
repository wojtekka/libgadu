TESTS = convert endian1 message2 message1 hash $(OPTIONAL_TESTS_PERL)
if HAVE_GLIBC
TESTS += resolver packet
if HAVE_GNUTLS_TESTS
TESTS += connect
endif
endif
if HAVE_PERL
TESTS += protocol
endif

check_PROGRAMS = $(TESTS)
EXTRA_PROGRAMS = convert endian1 message2 message1 hash resolver packet connect protocol

CFLAGS += -DGG_IGNORE_DEPRECATED -I$(top_srcdir)/include
AM_LDFLAGS = -no-install

protocol_SOURCES = protocol.c
nodist_protocol_SOURCES = script/script.c
protocol_CFLAGS = -I$(top_srcdir)/test/automatic/script
protocol_LDADD = $(top_builddir)/src/libgadu.la

convert_SOURCES = convert.c ../../src/encoding.c

message1_SOURCES = message1.c

message2_SOURCES = message2.c ../../src/message.c
message2_LDADD = @LIBXML2_LIBS@
message2_CFLAGS = @LIBXML2_CFLAGS@

hash_SOURCES = hash.c ../../src/sha1.c ../../src/endian.c

endian1_SOURCES = endian1.c ../../src/endian.c

connect_LDADD = $(top_builddir)/src/libgadu.la @GNUTLS_LIBS@
connect_CFLAGS = @GNUTLS_CFLAGS@

packet_LDADD = $(top_builddir)/src/libgadu.la

resolver_LDADD = $(top_builddir)/src/libgadu.la

EXTRA_DIST = protocol.txt connect.txt connect.pem

SUBDIRS = script

script/script.c: $(wildcard script/*.scr) script/compile
	$(PERL) $(top_srcdir)/test/automatic/script/compile $(top_srcdir)/test/automatic/script/*.scr > script/script.c

clean-local:
	rm -f *-valgrind.log *-valgrind script/script.c

check-local: $(check_PROGRAMS)
	for i in $(check_PROGRAMS); do ln -sf ../valgrind $${i}-valgrind; done
