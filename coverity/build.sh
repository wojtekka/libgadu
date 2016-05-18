#!/bin/sh

./autogen.sh --without-protobuf --enable-werror ${CONFIGURE_FLAGS}
cov-build --dir cov-int make check
tar cjf /artifacts/libgadu-cov.tar.bz2 cov-int

GIT_REVISION=$(git rev-parse --short HEAD)

curl --fail \
	--form token=${COVERITY_TOKEN} \
	--form email=${COVERITY_EMAIL} \
	--form file=@/artifacts/libgadu-cov.tar.bz2 \
	--form version="${PKG_VERSION}" \
	--form description="Rev_${GIT_REVISION}" \
	https://scan.coverity.com/builds?project=wojtekka%2Flibgadu
