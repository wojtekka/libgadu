EXTRA_DIST = Doxyfile protocol.html *.dox

all-local:	html

# Only try to generate documentation if it is not already there.
# Do not fail if doxygen is not available.
html:	../include/libgadu.h
	test -d html || if doxygen --version > /dev/null; then doxygen; fi

clean-local:
	rm -rf html

