#!/bin/sh

export PKG_CONFIG_PATH=/usr/i686-w64-mingw32/sys-root/mingw/lib/pkgconfig:/usr/i686-w64-mingw32/sys-root/mingw/share/pkgconfig
export PKG_CONFIG=/usr/bin/i686-w64-mingw32-pkg-config
export WINEPREFIX="/.wine"

if [ -n "${WINE_SET_PATH}" ]; then
	echo -e 'REGEDIT4\n\n[HKEY_CURRENT_USER\\Environment]' > /wine-set-path.reg
	echo "\"PATH\"=\"${WINE_SET_PATH}\"" >> /wine-set-path.reg
	wine regedit /S /wine-set-path.reg
	rm -f /wine-set-path.reg
fi

export LIBGADU_FLAGS="--host=${TARGET} --target=${TARGET} CC=${TARGET}-gcc \
	--enable-shared --disable-static --with-c99-vsnprintf --with-pthread \
	--enable-werror ${CONFIGURE_FLAGS}"
./autogen.sh $LIBGADU_FLAGS
DISTCHECK_CONFIGURE_FLAGS="$LIBGADU_FLAGS" make distcheck
