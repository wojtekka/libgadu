FROM opensuse:42.1
MAINTAINER Tomasz Wasilczyk

RUN zypper -n install \
		git \
		protobuf-c autoconf automake libtool gcc make \
		libgnutls-devel doxygen \
		libcurl-devel libexpat-devel libxml2-devel glibc-locale \
		clang \
	&& \
	zypper -n clean --all
