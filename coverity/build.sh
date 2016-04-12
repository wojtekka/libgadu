#!/bin/sh

./autogen.sh --without-protobuf --enable-werror ${CONFIGURE_FLAGS}
cov-build --dir cov-int make check
tar cjf /artifacts/libgadu-cov.tar.bz2 cov-int

VERSION=$(git rev-parse --short HEAD)

curl --fail \
	--form token=${COVERITY_TOKEN} \
	--form email=${COVERITY_EMAIL} \
	--form file=@/artifacts/libgadu-cov.tar.bz2 \
	--form version="${VERSION}" \
	https://scan.coverity.com/builds?project=wojtekka%2Flibgadu
