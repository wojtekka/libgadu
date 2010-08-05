SUBDIRS = include src pkgconfig examples @SUBDIRS_TEST@ @SUBDIRS_DOXYGEN@
DIST_SUBDIRS = include src pkgconfig examples test docs

LIBTOOL_DEPS = @LIBTOOL_DEPS@

libtool:	$(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

ACLOCAL_AMFLAGS = -I m4
