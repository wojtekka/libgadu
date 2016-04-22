TESTS = connect convert endian1 hash message1 message2 packet protocol resolver

check_PROGRAMS = $(TESTS)

AM_CPPFLAGS = -DGG_IGNORE_DEPRECATED -I$(top_srcdir)/include -I$(top_srcdir)/test
AM_LDFLAGS = @LDFLAGS_NO_INSTALL@

EXTRA_DIST = protocol.txt connect.txt connect.pem wine-wrapper.sh skipped.c

if HAVE_PERL
protocol_SOURCES = protocol.c
nodist_protocol_SOURCES = script.c libgadu-network.c
protocol_CFLAGS = -I$(top_srcdir)/test/automatic/script
protocol_LDADD = $(top_builddir)/src/libgadu.la
else
EXTRA_DIST += protocol.c
nodist_protocol_SOURCES = skipped.c
endif

convert_SOURCES = convert.c
nodist_convert_SOURCES = libgadu-encoding.c

message1_SOURCES = message1.c

message2_SOURCES = message2.c
nodist_message2_SOURCES = libgadu-message.c
message2_LDADD = @LIBXML2_LIBS@
message2_CFLAGS = @LIBXML2_CFLAGS@

hash_SOURCES = hash.c
nodist_hash_SOURCES = libgadu-sha1.c libgadu-endian.c

endian1_SOURCES = endian1.c
nodist_endian1_SOURCES = libgadu-endian.c

if BUILD_CONNECT_TEST
connect_SOURCES = connect.c
nodist_connect_SOURCES = libgadu-network.c
connect_LDADD = $(top_builddir)/src/libgadu.la @GNUTLS_LIBS@
connect_CFLAGS = @GNUTLS_CFLAGS@
else
EXTRA_DIST += connect.c
nodist_connect_SOURCES = skipped.c
endif

packet_LDADD = $(top_builddir)/src/libgadu.la

resolver_LDADD = $(top_builddir)/src/libgadu.la

SUBDIRS = script

script.c: $(wildcard script/*.scr) script/compile
	$(AM_V_GEN)$(PERL) $(top_srcdir)/test/automatic/script/compile $(top_srcdir)/test/automatic/script/*.scr > script.c

clean-local:
	rm -f *-valgrind.log *-valgrind script.c skipped.c libgadu-*.c

check-local: $(check_PROGRAMS)
	for i in $(check_PROGRAMS); do ln -sf ../valgrind $${i}-valgrind; done

libgadu-%.c: ../../src/%.c
	$(AM_V_GEN)cat "$<" > "$@"

skipped.c:
	echo 'int main() { return 77; }' > $@
