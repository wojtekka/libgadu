CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LIBS = ../../src/.libs/libgadu.a

all:	test

protocol:	protocol.o script.o $(LIBS)
	$(CC) -o $@ protocol.o script.o $(LIBS)

test:	protocol
	./protocol

script.o:	script.c
	$(CC) $(CFLAGS) -c $< -o $@

script.c:	test.scr compile
	./compile < test.scr > script.c

poke:	protocol
	./protocol

clean:
	rm -f *.o protocol *~ core *.log script.c

.PHONY:	all clean poke test
