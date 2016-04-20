#!/bin/sh

if [ -z "${STAY_INTERACTIVE}" ]; then
	set -ex
fi

export EXIT_CODE=1
trap "chown -R ${UID}:${GID} /artifacts; exit \${EXIT_CODE}" INT QUIT TERM EXIT

git clone -b ${BRANCH} ${REPO} libgadu
cd libgadu

. /build.sh

export EXIT_CODE=0

if [ -n "${STAY_INTERACTIVE}" ]; then
	bash
fi
