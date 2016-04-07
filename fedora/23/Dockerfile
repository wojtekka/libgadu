FROM fedora:23
MAINTAINER Tomasz Wasilczyk

RUN dnf install -y \
		git \
		protobuf-c-devel autoconf automake libtool gcc make file \
		gnutls-devel doxygen \
		libcurl-devel expat-devel libxml2-devel \
	&& \
	dnf install --best -y \
		nss \
	&& \
	dnf clean all
