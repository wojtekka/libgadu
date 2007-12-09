CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LIBS = ../../src/.libs/libgadu.a

all:	dcc7

dcc7:	dcc7.o $(LIBS)
	$(CC) -o $@ $< $(LIBS)

clean:
	rm -f *.o dcc7 *~ core *.log
