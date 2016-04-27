#!/bin/sh

if [ -z "${STAY_INTERACTIVE}" ]; then
	set -ex
fi

export EXIT_CODE=1
trap "chown -R ${UID}:${GID} /artifacts; exit \${EXIT_CODE}" INT QUIT TERM EXIT

git clone -b ${BRANCH} ${REPO} libgadu
cd libgadu
git reset --hard ${REVISION}

export PKG_VERSION=`cat /libgadu/configure.ac | grep 'AC_INIT' | sed -e 's/.*\[.*\[\(.*\)\].*/\1/'`

. /build.sh

if [ -n "${SHIP_TARBALL}" ]; then
	cp /libgadu/libgadu-${PKG_VERSION}.tar.gz /artifacts/
fi

export EXIT_CODE=0

if [ -n "${STAY_INTERACTIVE}" ]; then
	bash
fi
