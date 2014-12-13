if HAVE_CURL_AND_EXPAT
noinst_LIBRARIES = libsearch.a
endif

AM_CPPFLAGS = -DGG_IGNORE_DEPRECATED -I$(top_srcdir)/include

libsearch_a_SOURCES = base64.c base64.h hmac.c hmac.h http.c http.h oauth.c oauth.h oauth_parameter.c oauth_parameter.h sha1.c sha1.h urlencode.c urlencode.h xml.c xml.h
