EXTRA_DIST = \
	Doxyfile \
	protocol.html \
	build.dox \
	changelog.dox \
	contacts.dox \
	dcc6.dox \
	dcc7.dox \
	events.dox \
	groups.dox \
	http.dox \
	importexport.dox \
	login.dox \
	mainpage.dox \
	messages.dox \
	proxy.dox \
	pubdir50.dox \
	re.dox \
	status.dox \
	todo.dox \
	token.dox

all-local:	html-stamp

html-stamp:	$(top_builddir)/include/libgadu.h $(wildcard $(top_srcdir)/include/*.h) $(wildcard $(top_srcdir)/src/*.c) $(wildcard $(srcdir)/*.dox)
	rm -rf $(DOXYFILE_HTML_DIR)
	$(DOXYGEN)
	touch html-stamp

clean-local:
	rm -rf $(DOXYFILE_HTML_DIR) html-stamp
