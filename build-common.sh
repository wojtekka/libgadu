#!/bin/sh

set -ex

export EXIT_CODE=1
trap "chown -R ${UID}:${GID} /artifacts; exit \${EXIT_CODE}" INT QUIT TERM EXIT

git clone -b ${BRANCH} ${REPO} libgadu
cd libgadu

. /build.sh

find -name "*.log" -exec cp {} /artifacts/ \;

export EXIT_CODE=0
