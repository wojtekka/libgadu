all:	../include/libgadu.h
	doxygen

../include/libgadu.h:	../include/libgadu.h.in ../configure
	make -C ../include

../configure:	../configure.ac
	(cd ..; ./configure)
