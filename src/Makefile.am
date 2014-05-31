lib_LTLIBRARIES = libgadu.la
libgadu_la_SOURCES = common.c dcc.c dcc7.c debug.c deflate.c encoding.c endian.c events.c handlers.c http.c libgadu.c message.c network.c obsolete.c packets.pb-c.c protobuf.c pubdir.c pubdir50.c resolver.c sha1.c tvbuff.c tvbuilder.c
libgadu_la_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -DGG_IGNORE_DEPRECATED
libgadu_la_LDFLAGS = -version-number 3:13 -export-symbols $(top_builddir)/src/libgadu.sym @MINGW_LDFLAGS@ @MINGW_LIBGEN@
EXTRA_libgadu_la_DEPENDENCIES = libgadu.sym
libgadu_libextradir = $(libdir)
libgadu_libextra_DATA = @MINGW_LIBDATA@
BUILT_SOURCES = libgadu.sym
CLEANFILES = libgadu.sym libgadu.def libgadu.def.in
EXTRA_DIST = libgadu.sym.in protobuf-c.c.patch

if !HAVE_PROTOBUF_C
libgadu_la_SOURCES += protobuf-c.c
else
EXTRA_DIST += protobuf-c.c
endif

packets.pb-c.c: ../packets.proto
	$(AM_V_GEN)cd $(top_builddir) ; sh protobufgen.sh

if HAVE_MINGW
# Win32 only - needed for MSVC libgadu.lib file generation.
# To generate libgadu.lib file, do one of the following:
# mingw: $ dlltool --def libgadu.def --output-lib libgadu.lib
# msvc:  > lib /machine:i386 /def:libgadu.def
# you might also need to convert libgadu.h file with declspec.sh
libgadu.def: libgadu.def.in
	$(AM_V_GEN)echo "LIBRARY libgadu-3.dll" > $@
	$(AM_V_at)cat $< >> $@

libgadu.def.in: libgadu.la
endif

libgadu.sym: libgadu.sym.in ../config.h
	$(AM_V_GEN)cat "$<" > "$@"
if IS_GPL_COMPLIANT
	$(AM_V_at)echo "gg_is_gpl_compliant" >> "$@"
endif
