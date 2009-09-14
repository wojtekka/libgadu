noinst_PROGRAMS = dcc7
# noinst_PROGRAMS = dcc7 voice7
dcc7_CFLAGS = -Wall
dcc7_LDADD = $(top_builddir)/src/libgadu.la
# voice7_CFLAGS = -DHAVE_GSM=1 -DHAVE_SPEEX=1
# voice7_LDFLAGS = -lgsm -lspeex
EXTRA_DIST = valgrind

clean-local:
	rm -f *.log
