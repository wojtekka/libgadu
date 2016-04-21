FROM fedora:23

RUN dnf install -y \
		git \
		protobuf-c-devel autoconf automake libtool gcc make file \
		gnutls-devel doxygen \
		libcurl-devel expat-devel libxml2-devel \
		openssl-devel \
	&& \
	dnf install --best -y \
		nss \
	&& \
	dnf clean all
