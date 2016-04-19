FROM opensuse:42.1

RUN zypper -n install \
		git \
		protobuf-c autoconf automake libtool gcc make \
		libgnutls-devel doxygen \
		libcurl-devel libexpat-devel libxml2-devel glibc-locale \
		clang \
		valgrind gdb \
	&& \
	zypper -n clean --all
