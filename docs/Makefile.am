EXTRA_DIST = Doxyfile protocol.html *.dox

all-local:	html-stamp

# Do not fail if doxygen is not available.
html-stamp:	../include/libgadu.h $(wildcard ../src/*.c) $(wildcard *.dox)
	@DOXYGEN@
	touch html-stamp

clean-local:
	rm -rf html

