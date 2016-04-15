#!/bin/sh

export PKG_CONFIG_PATH=/usr/${TARGET}/sys-root/mingw/lib/pkgconfig:/usr/${TARGET}/sys-root/mingw/share/pkgconfig
export PKG_CONFIG=/usr/bin/${TARGET}-pkg-config
export WINEPREFIX="/.wine"

export LIBGADU_FLAGS="--host=${TARGET} --target=${TARGET} CC=${TARGET}-gcc \
	--enable-shared --disable-static --with-c99-vsnprintf --with-pthread \
	--enable-werror ${CONFIGURE_FLAGS}"
./autogen.sh $LIBGADU_FLAGS
DISTCHECK_CONFIGURE_FLAGS="$LIBGADU_FLAGS" make distcheck
