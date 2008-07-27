noinst_PROGRAMS = dcc7
# noinst_PROGRAMS = dcc7 voice7

LDADD = ../../src/libgadu.la
EXTRA_DIST = valgrind

voice7_LDFLAGS = -lgsm -lspeex
voice7_CFLAGS = -DHAVE_GSM=1 -DHAVE_SPEEX=1

clean-local:
	rm -f *.log
