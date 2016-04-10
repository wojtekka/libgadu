FROM opensuse:tumbleweed

COPY .deps/install-winbind.sh /

RUN /install-winbind.sh && \
	zypper addrepo -f -G \
		http://download.opensuse.org/repositories/windows:/mingw:/win64/openSUSE_Factory/ windows:mingw:win64 \
	&& \
	zypper -n install \
		git \
		mingw64-cross-gcc mingw64-cross-pkg-config \
		protobuf-c autoconf automake libtool make \
		mingw64-libgnutls-devel \
		mingw64-libcurl-devel mingw64-libexpat-devel mingw64-libxml2-devel \
		wine \
		mingw64-gnutls mingw64-libxml2-2 \
	&& \
	zypper -n clean --all
