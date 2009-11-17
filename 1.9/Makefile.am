SUBDIRS = include src pkgconfig test examples @SUBDIRS_DOXYGEN@
DIST_SUBDIRS = include src pkgconfig test examples docs

LIBTOOL_DEPS = @LIBTOOL_DEPS@

libtool:	$(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

ACLOCAL_AMFLAGS = -I m4
