#!/bin/sh

./autogen.sh ${CONFIGURE_FLAGS}
make distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-werror ${CONFIGURE_FLAGS}"
