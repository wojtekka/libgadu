CC = gcc
CFLAGS = -Wall -I../../include -ggdb
LDFLAGS = $(shell grep -q ssl ../pkgconfig/libgadu.pc && echo "-lssl -lcrypto")
LIBS = ../src/.libs/libgadu.a

all:	register-sync register-async conn-async send remind-async remind-sync httphash

register-sync: register.c $(LIBS)
	$(CC) $(CFLAGS) register.c -o register-sync $(LIBS) $(LDFLAGS)

register-async: register.c $(LIBS)
	$(CC) $(CFLAGS) register.c -o register-async -DASYNC $(LIBS) $(LDFLAGS)

remind-sync: remind.c $(LIBS)
	$(CC) $(CFLAGS) remind.c -o remind-sync $(LIBS) $(LDFLAGS)

remind-async: remind.c $(LIBS)
	$(CC) $(CFLAGS) remind.c -o remind-async -DASYNC $(LIBS) $(LDFLAGS)

send:	send.c $(LIBS)
	$(CC) $(CFLAGS) send.c -o send $(LIBS) $(LDFLAGS)

httphash: httphash.c $(LIBS)
	$(CC) $(CFLAGS) httphash.c -o httphash $(LIBS) $(LDFLAGS)

conn-async: conn-async.c $(LIBS)
	$(CC) $(CFLAGS) conn-async.c -o conn-async $(LIBS) $(LDFLAGS)

clean:
	rm -f *.o *~ core register-sync register-async conn-async send remind-async remind-sync httphash

.PHONY:	all clean
