SUBDIRS = include src pkgconfig

LIBTOOL_DEPS = @LIBTOOL_DEPS@                                                   
libtool:	$(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck                                      

ACLOCAL_AMFLAGS = -I m4
