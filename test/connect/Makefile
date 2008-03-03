CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LDFLAGS = -lssl -lcrypto
LIBS = ../../src/.libs/libgadu.a

all:	connect

connect:	connect.o $(LIBS)
	$(CC) -o $@ $< $(LIBS) $(LDFLAGS)

poke:
	./connect

clean:
	rm -f *.o connect *~ core *.log
