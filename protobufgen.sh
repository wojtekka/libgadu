#!/bin/sh

protoc-c --c_out=. packets.proto

if [ $? != 0 ] ; then
	exit -1
fi

sed -i 's/<google\/protobuf-c\/protobuf-c.h>/"protobuf.h"/g' packets.pb-c.h

if ! cat packets.pb-c.c | grep "PROTOBUF_C_NO_DEPRECATED" > /dev/null; then
	echo "Warning: protobuf-c-compiler < 0.14 detected, trying to fix the output"
	sed -i 's|    NULL,NULL    /\* reserved1, reserved2 \*/|    0, 0, NULL, NULL|g' packets.pb-c.c
fi

mv packets.pb-c.h include
mv packets.pb-c.c src
