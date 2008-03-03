CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LDFLAGS = $(shell grep -q ssl ../../pkgconfig/libgadu.pc && echo "-lssl -lcrypto")
LIBS = ../../src/.libs/libgadu.a

all:	connect

test:	connect
	./connect

connect:	connect.o $(LIBS)
	$(CC) -o $@ $< $(LIBS) $(LDFLAGS)

poke:	test

clean:
	rm -f *.o connect *~ core *.log

.PHONY:	all test poke clean
