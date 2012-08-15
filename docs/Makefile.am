EXTRA_DIST = Doxyfile protocol.html *.dox

all-local:	html-stamp

html-stamp:	$(top_builddir)/include/libgadu.h $(wildcard $(top_srcdir)/include/*.h) $(wildcard $(top_srcdir)/src/*.c) $(wildcard $(srcdir)/*.dox)
	rm -rf $(DOXYFILE_HTML_DIR)
	$(DOXYGEN)
	touch html-stamp

clean-local:
	rm -rf $(DOXYFILE_HTML_DIR) html-stamp
