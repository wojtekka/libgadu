#!/bin/sh

set -ex

trap "chown -R ${UID}:${GID} /artifacts; exit" INT QUIT TERM EXIT

git clone -b ${BRANCH} ${REPO} libgadu
cd libgadu

./autogen.sh
make distcheck
