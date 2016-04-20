FROM opensuse:tumbleweed

COPY .deps/install-winbind.sh /

RUN /install-winbind.sh && \
	zypper addrepo -f -G \
		http://download.opensuse.org/repositories/windows:/mingw:/win32/openSUSE_Factory/ windows:mingw:win32 \
	&& \
	zypper -n install \
		git \
		mingw32-cross-gcc mingw32-cross-pkg-config \
		protobuf-c autoconf automake libtool make \
		mingw32-libgnutls-devel \
		mingw32-libcurl-devel mingw32-libexpat-devel mingw32-libxml2-devel \
		wine \
		mingw32-gnutls mingw32-libxml2-2 \
		zip \
	&& \
	zypper -n clean --all
