EXTRA_DIST = Doxyfile protocol.html *.dox

all-local:	html

html:	../include/libgadu.h
	test -d html || doxygen || true

clean-local:
	rm -rf html

