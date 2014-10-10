#!/bin/sh

if ! protoc-c --version | grep "protobuf-c 1." > /dev/null; then
	PROTOC_VER=`protoc-c --version | grep protobuf-c | cut -d' ' -f 2`
	if [ "$PROTOC_VER" = "" ]; then
		PROTOC_VER="none"
	fi
	echo "Invalid protoc-c version. Required 1.x.y, but $PROTOC_VER found."
	exit -2
fi

protoc-c --c_out=. packets.proto

if [ $? != 0 ] ; then
	exit -1
fi

sed -i 's/<protobuf-c\/protobuf-c.h>/"protobuf.h"/g' packets.pb-c.h

mv packets.pb-c.h include
mv packets.pb-c.c src
