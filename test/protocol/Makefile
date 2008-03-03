CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LDFLAGS = $(shell grep -q ssl ../../pkgconfig/libgadu.pc && echo "-lssl -lcrypto")
LIBS = ../../src/.libs/libgadu.a

all:	protocol

test:	protocol
	./protocol

protocol:	protocol.o script.o $(LIBS)
	$(CC) -o $@ protocol.o script.o $(LIBS) $(LDFLAGS)

script.o:	script.c
	$(CC) $(CFLAGS) -c $< -o $@

script.c:	test.scr compile
	./compile < test.scr > script.c

poke:	test

clean:
	rm -f *.o protocol *~ core *.log script.c

.PHONY:	all test poke clea
