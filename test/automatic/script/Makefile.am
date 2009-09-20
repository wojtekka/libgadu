SOURCES = script.c
noinst_HEADERS = script.h
EXTRA_DIST = *.scr

script.c:	$(wildcard *.scr) compile
	./compile *.scr > script.c

clean-local:
	rm -f script.c
