SUBDIRS = include src pkgconfig examples @SUBDIRS_DOXYGEN@
if ENABLE_TESTS
SUBDIRS += test
endif

DIST_SUBDIRS = include src pkgconfig examples docs test

EXTRA_DIST = packets.proto protobufgen.sh autogen.sh

LIBTOOL_DEPS = @LIBTOOL_DEPS@

libtool:	$(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

ACLOCAL_AMFLAGS = -I m4
