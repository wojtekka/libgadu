EXTRA_DIST = Doxyfile protocol.html *.dox

all-local:	html-stamp

html-stamp:	../include/libgadu.h $(wildcard ../src/*.c) $(wildcard *.dox)
	doxygen
	touch html-stamp

clean-local:
	rm -rf html

