CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LDFLAGS = $(shell grep -q ssl ../../pkgconfig/libgadu.pc && echo "-lssl -lcrypto")
LIBS = ../../src/.libs/libgadu.a

all:	dcc7

test:
	echo "Not an automatic test"

dcc7:	dcc7.o $(LIBS)
	$(CC) -o $@ $< $(LIBS) $(LDFLAGS)

poke:	test

clean:
	rm -f *.o dcc7 *~ core *.log

.PHONY:	all test poke clean
