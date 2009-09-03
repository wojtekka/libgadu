noinst_PROGRAMS = search

EXTRA_DIST = valgrind

search_SOURCES = base64.c base64.h ../../config.h hmac.c hmac.h http.c http.h oauth.c oauth.h oauth_parameter.c oauth_parameter.h search.c sha1.c sha1.h urlencode.c urlencode.h xml.c xml.h
search_LDFLAGS = -lcurl -lexpat -lssl
# search_CFLAGS = -Wall -DHAVE_OPENSSL -DWORDS_BIGENDIAN
search_CFLAGS = -Wall -DHAVE_OPENSSL

clean-local:
	rm -f *.log
