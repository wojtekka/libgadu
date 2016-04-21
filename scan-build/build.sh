#!/bin/sh

NOCONFIGURE=indeed ./autogen.sh
scan-build ./configure --without-protobuf ${CONFIGURE_FLAGS}
scan-build -o /artifacts make
