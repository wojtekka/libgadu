#!/bin/sh

set -ex

trap "chown -R ${UID}:${GID} /artifacts; exit" INT QUIT TERM EXIT

git clone -b ${BRANCH} ${REPO} libgadu
cd libgadu

. /build.sh

find -name "*.log" -exec cp {} /artifacts/ \;
