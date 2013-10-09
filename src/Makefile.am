lib_LTLIBRARIES = libgadu.la
libgadu_la_SOURCES = common.c dcc.c dcc7.c debug.c deflate.c encoding.c endian.c events.c handlers.c http.c libgadu.c message.c network.c obsolete.c packets.pb-c.c protobuf.c pubdir.c pubdir50.c resolver.c sha1.c tvbuff.c tvbuilder.c
libgadu_la_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include -DGG_IGNORE_DEPRECATED
libgadu_la_LDFLAGS = -version-number 3:13 -export-symbols $(srcdir)/libgadu.sym @MINGW_LDFLAGS@
libgadu_libextradir = $(libdir)
libgadu_libextra_DATA = @MINGW_LIBDATA@
EXTRA_DIST = libgadu.sym

if !HAVE_PROTOBUF_C
libgadu_la_SOURCES += protobuf-c.c
endif

packets.pb-c.c: ../packets.proto
	cd $(top_builddir) ; sh protobufgen.sh

# Win32 only - needed for MSVC libgadu.lib file generation.
# To generate libgadu.lib file, do one of the following:
# mingw: $ dlltool --def libgadu.def --output-lib libgadu.lib
# msvc:  > lib /machine:i386 /def:libgadu.def
libgadu.def: libgadu.la
	echo "LIBRARY libgadu-3.dll" > libgadu.def.new
	cat libgadu.def >> libgadu.def.new
	rm libgadu.def
	mv libgadu.def.new libgadu.def
