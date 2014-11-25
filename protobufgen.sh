#!/bin/sh

PROTOC_LEGACY=no

if ! protoc-c --version | grep "protobuf-c 1." > /dev/null; then
	PROTOC_VER=`protoc-c --version | grep protobuf-c | cut -d' ' -f 2`
	if [ "$PROTOC_VER" = "" ]; then
		echo
		echo "########################################"
		echo "# WARNING"
		echo "########################################"
		echo
		echo "protoc-c < 1.0.0 found"
		echo "The output will be fixed to match the new API, but it's better to update."
		echo
		PROTOC_LEGACY=yes
	else
		echo "Invalid protoc-c version. Required 1.x.y, but $PROTOC_VER found."
		exit -2
	fi
fi

protoc-c --c_out=. packets.proto

if [ $? != 0 ] ; then
	exit -1
fi

if [ "x$PROTOC_LEGACY" = "xyes" ]; then
	sed -i 's/<google\/protobuf-c\/protobuf-c.h>/"protobuf.h"/g' packets.pb-c.h

	# fix protoc-c < 0.14 output
	if ! cat packets.pb-c.c | grep "PROTOBUF_C_NO_DEPRECATED" > /dev/null; then
		sed -i 's| NULL,NULL \+/\* reserved1, reserved2 \*/| 0, 0, NULL, NULL|g' packets.pb-c.c
	fi

	# translate 0.15 output to 1.0.2
	sed -i 's/PROTOBUF_C_BEGIN_DECLS/PROTOBUF_C__BEGIN_DECLS/g' packets.pb-c.h
	sed -i 's/PROTOBUF_C_END_DECLS/PROTOBUF_C__END_DECLS/g' packets.pb-c.h
	sed -i 's/PROTOBUF_C_ASSERT/assert /g' packets.pb-c.c
	sed -i 's/PROTOBUF_C_OFFSETOF/offsetof/g' packets.pb-c.c
	sed -i 's/PROTOBUF_C_MESSAGE_DESCRIPTOR_MAGIC/PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC/g' packets.pb-c.c
	sed -i 's/PROTOBUF_C_ENUM_DESCRIPTOR_MAGIC/PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC/g' packets.pb-c.c
else
	sed -i 's/<protobuf-c\/protobuf-c.h>/"protobuf.h"/g' packets.pb-c.h
fi

mv packets.pb-c.h include
mv packets.pb-c.c src
