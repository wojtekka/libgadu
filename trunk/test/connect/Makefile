CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LIBS = ../../src/.libs/libgadu.a

all:	connect

connect:	connect.o $(LIBS)
	$(CC) -o $@ $< $(LIBS)

poke:
	./connect

clean:
	rm -f *.o connect *~ core *.log
