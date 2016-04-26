#!/bin/sh

export PKG_CONFIG_PATH=/usr/${TARGET}/sys-root/mingw/lib/pkgconfig:/usr/${TARGET}/sys-root/mingw/share/pkgconfig
export PKG_CONFIG=/usr/bin/${TARGET}-pkg-config
export LDFLAGS="-L/usr/${TARGET}/sys-root/mingw/lib"
export MINGW_FLAGS="--host=${TARGET} --target=${TARGET} --enable-shared --disable-static"
export CC=${TARGET}-gcc
export WINEPREFIX="/.wine"

export LIBGADU_FLAGS="${MINGW_FLAGS} ${CONFIGURE_FLAGS} \
	--with-c99-vsnprintf --enable-werror"
export LIBGADU_FLAGS_RELEASE=""
export LIBGADU_FLAGS_CHECK="--without-protobuf"

./autogen.sh --prefix=/pkg-build/install $LIBGADU_FLAGS $LIBGADU_FLAGS_RELEASE
DISTCHECK_CONFIGURE_FLAGS="$LIBGADU_FLAGS $LIBGADU_FLAGS_CHECK" make distcheck

# prepare release package

export PKG_VERSION=`cat /libgadu/configure.ac | grep 'AC_INIT' | sed -e 's/.*\[.*\[\(.*\)\].*/\1/'`
export PKG_NAME=libgadu-${PKG_VERSION}-${SIMPLE_TARGET}
export PKG_DIR=/pkg-build/${PKG_NAME}

cp /libgadu/libgadu-${PKG_VERSION}.tar.gz /artifacts/

mkdir -p ${PKG_DIR}/dev ${PKG_DIR}/deps
make install
cp /pkg-build/install/bin/libgadu-*.dll ${PKG_DIR}/
cp /pkg-build/install/include/*.h ${PKG_DIR}/dev/
cp /pkg-build/install/lib/libgadu.def ${PKG_DIR}/dev/
cp /usr/${TARGET}/sys-root/${TARGET}/bin/*.dll ${PKG_DIR}/deps/
cp /libgadu/README ${PKG_DIR}/
cp /libgadu/COPYING ${PKG_DIR}/

mkdir -p ${PKG_DIR}tests
make -C /libgadu/test/automatic check-local
cp /libgadu/test/automatic/.libs/*.exe ${PKG_DIR}tests/
cp /libgadu/COPYING ${PKG_DIR}tests/

cd /pkg-build/
mv ${PKG_NAME}/deps/libxml2-*.dll ${PKG_NAME}tests/
zip -r9X /artifacts/${PKG_NAME}.zip ${PKG_NAME}/
zip -r9X /artifacts/${PKG_NAME}tests.zip ${PKG_NAME}tests/
cd -
