noinst_PROGRAMS = send httphash conn-async register-sync register-async remind-sync remind-async status token-sync token-async
LDADD = ../src/libgadu.la
AM_LDFLAGS = @LDFLAGS_NO_INSTALL@

httphash_CFLAGS = -DGG_IGNORE_DEPRECATED

register_sync_SOURCES = register.c

register_async_SOURCES = register.c
register_async_CFLAGS = -DASYNC

remind_sync_SOURCES = remind.c

remind_async_SOURCES = remind.c
remind_async_CFLAGS = -DASYNC

token_sync_SOURCES = token.c

token_async_SOURCES = token.c
token_async_CFLAGS = -DASYNC

