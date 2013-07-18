#!/bin/sh

protoc-c --c_out=. packets.proto

if [ $? != 0 ] ; then
	exit -1
fi

sed -i 's/<google\/protobuf-c\/protobuf-c.h>/"protobuf.h"/g' packets.pb-c.h
mv packets.pb-c.h include
mv packets.pb-c.c src
