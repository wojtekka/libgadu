#!/bin/sh

export PKG_CONFIG_PATH=/usr/i686-w64-mingw32/sys-root/mingw/lib/pkgconfig:/usr/i686-w64-mingw32/sys-root/mingw/share/pkgconfig
export PKG_CONFIG=/usr/bin/i686-w64-mingw32-pkg-config
export WINEPREFIX="/.wine32"

# TODO: --enable-werror
export LIBGADU_FLAGS="--host=i686-w64-mingw32 --target=i686-w64-mingw32 CC=i686-w64-mingw32-gcc \
	--enable-shared --disable-static --with-c99-vsnprintf --with-pthread \
	${CONFIGURE_FLAGS}"
./autogen.sh $LIBGADU_FLAGS
DISTCHECK_CONFIGURE_FLAGS="$LIBGADU_FLAGS" make distcheck
