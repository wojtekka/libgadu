EXTRA_DIST = Doxyfile protocol.html *.dox

all-local:	html-stamp

# Do not fail if doxygen is not available.
html-stamp:	../include/libgadu.h $(wildcard ../src/*.c) $(wildcard *.dox)
	if doxygen --version > /dev/null; then if doxygen; then touch html-stamp; fi; fi

clean-local:
	rm -rf html

