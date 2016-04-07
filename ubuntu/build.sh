#!/bin/sh

./autogen.sh
make distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-werror ${CONFIGURE_FLAGS}"
