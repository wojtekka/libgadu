SOURCES = script.c
noinst_HEADERS = script.h
EXTRA_DIST = *.scr

script.c:	$(wildcard *.scr) compile
	$(PERL) compile *.scr > script.c

clean-local:
	rm -f script.c
