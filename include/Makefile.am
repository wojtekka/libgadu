nodist_include_HEADERS = libgadu.h
noinst_HEADERS = debug.h deflate.h encoding.h fileio.h internal.h message.h network.h packets.pb-c.h protobuf.h protobuf-c.h protocol.h resolver.h session.h strman.h tvbuff.h tvbuilder.h

packets.pb-c.h: ../packets.proto
	cd $(top_builddir) ; sh protobufgen.sh
