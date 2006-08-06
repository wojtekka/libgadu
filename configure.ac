dnl $Id$

AC_INIT(src/libgadu.c)
AM_INIT_AUTOMAKE(libgadu, 1.7.0)

AC_PREREQ(2.50)
AC_CANONICAL_HOST
AC_CONFIG_HEADERS(config.h)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_C_CONST
AC_PROG_LIBTOOL

AC_SUBST(LIBGADU_STDINT_H)
AC_SUBST(REQUIRES)

dnl
dnl  W³±czamy ostrze¿enia dla gcc.
dnl

if test "$GCC"; then
	CFLAGS="$CFLAGS -Wall"
fi

dnl
dnl  Tworzymy osobny plik include/libgadu-config.h niezale¿ny od autoconfa
dnl  z w³asn± przestrzeni± nazw (__GG_LIBGADU), ¿eby móc go spokojnie
dnl  w³±czyæ w <libgadu.h> 
dnl

AC_DEFUN([AC_LIBGADU_DEFINE],
[
	sed 's/#undef __GG_LIBGADU_$1/#define __GG_LIBGADU_$1/' < include/libgadu-config.h > include/libgadu-config.h-
	mv -f include/libgadu-config.h- include/libgadu-config.h
])

AC_DEFUN([AC_LIBGADU_UNDEF],
[
	sed 's/#undef __GG_LIBGADU_$1.*/\/* & *\//' < include/libgadu-config.h > include/libgadu-config.h-
	mv -f include/libgadu-config.h- include/libgadu-config.h
])

echo "/* Generated automatically by configure. Do not edit. */" > include/libgadu-config.h
cat include/libgadu-config.h.in >> include/libgadu-config.h

dnl
dnl  Najpierw sprawdzamy te opcje, które s± wspólne dla libgadu i ekg.
dnl

AC_C_BIGENDIAN

if test "x$ac_cv_c_bigendian" = "xyes"; then
	AC_LIBGADU_DEFINE([BIGENDIAN])
fi

AC_NEED_STDINT_H

if test "x$STDINT_H" = "x"; then
	cp stdint.h lib/libgadu-stdint.h
	AC_DEFINE([LIBGADU_STDINT_H], [], [Define if libgadu-stdint.h is needed])
fi

sed "s/#include <stdint.h>/#include <$STDINT_H>/" < include/libgadu-config.h > include/libgadu-config.h-
mv -f include/libgadu-config.h- include/libgadu-config.h

dnl SunOS
AC_CHECK_LIB(nsl, t_accept, LIBS="$LIBS -lnsl")
AC_CHECK_LIB(socket, socket, LIBS="$LIBS -lsocket")

dnl BeOS
AC_ARG_WITH(bind,
	[  --without-bind          Disable linking with libbind when found])

if test "x$with_bind" != "xno"; then
	AC_CHECK_LIB(bind, __inet_addr, LIBS="$LIBS -lbind")
fi

dnl threadsafe
AC_CHECK_FUNCS([gethostbyname_r], [AC_LIBGADU_DEFINE([HAVE_GETHOSTBYNAME_R])])

dnl inet_pton
AC_CHECK_FUNCS(inet_pton)

AC_MSG_CHECKING([for va_copy])
AC_TRY_LINK([#include <stdarg.h>], [va_list a, b; va_copy(a, b);], 
[
	AC_MSG_RESULT([yes])
	AC_DEFINE([HAVE_VA_COPY], [], [Define if you have va_copy()])
], [
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([for __va_copy])
AC_TRY_LINK([#include <stdarg.h>], [va_list a, b; __va_copy(a, b);], 
[
	AC_MSG_RESULT([yes])
	AC_DEFINE([HAVE___VA_COPY], [], [Define if you have __va_copy()])
], [
	AC_MSG_RESULT([no])
])

AC_ARG_ENABLE(debug, 
	[  --disable-debug         Compile without debugging support])

if test "x$enable_debug" = "xno"; then 
	AC_MSG_WARN([--disable-debug is obsolete.])
fi

dnl
dnl  Sprawd¼my, jak± wersjê vsnprintf() dostajemy. Dodatkowa opcja jest
dnl  dla kompilacji skro¶nej, bo nie mo¿na wtedy korzystaæ z AC_TRY_RUN().
dnl

AC_ARG_WITH(c99-vsnprintf,
	[  --with-c99-vsnprintf    Target system has C99-compatible vsnprintf()])

if test "x$with_c99_vsnprintf" = "xyes"; then
	AC_LIBGADU_DEFINE([HAVE_C99_VSNPRINTF])
fi

if test "x$with_c99_vsnprintf" = "x"; then
	AC_MSG_CHECKING([for C99-compatible vsnprintf()])
	AC_TRY_RUN(
	[
		#include <stdio.h>
		int main()
		{
			char tmp;
			return (snprintf(&tmp, sizeof(tmp), "test") != 4);
		}
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_C99_VSNPRINTF], [], [Define if you have C99-compatible vsnprintf()])
	], [
		AC_MSG_RESULT([no])
	])
fi

dnl
dnl  Resolver libgadu oparty na pthread
dnl

AC_ARG_WITH(pthread,
  [  --with-pthread          Use pthread in resolver])

if test "x$with_pthread" = "xyes"; then
	dnl najpierw sprawdzamy czy pomijaæ testy pthreads/shared
	pthreads_shared_skip=0
	if test "x$lib_shared_enabled" = "xno"; then
		pthreads_shared_skip=1
	fi
	ACX_PTHREAD(
	[
		dnl workaround dla pkgconfiga
		if test "x$PTHREAD_CFLAGS" = "x-pthread"; then
			PTHREAD_LIBS="$PTHREAD_LIBS -pthread"
		fi

		LIBS="$PTHREAD_LIBS $LIBS"
		CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
		CC="$PTHREAD_CC"
		have_pthread=yes

		AC_DEFINE([HAVE_PTHREAD], [], [Define if you want threaded resolver])
	], [
		AC_MSG_ERROR([Your system is not supporting pthreads])
	], [$pthreads_shared_skip])
fi

dnl
dnl  Sprawdzamy, czy jest ,,long long'' na potrzeby obliczeñ czasów DCC
dnl

AC_MSG_CHECKING([for long long])

AC_TRY_COMPILE([],
[
	long long a = 1LL;
	unsigned long long b = 1LL;
], [
	AC_MSG_RESULT([yes])
	AC_LIBGADU_DEFINE([HAVE_LONG_LONG])
])

dnl
dnl  Sprawdzamy OpenSSL
dnl

AC_CHECK_OPENSSL

AC_ARG_ENABLE(libgadu-openssl,
	[  --enable-libgadu-openssl Enable libgadu OpenSSL support])

if test "x$have_openssl" = "xyes"; then
	if test "x$enable_libgadu_openssl"; then
		LIBS="$LIBS $OPENSSL_LIBS"
		CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
		REQUIRES="$REQUIRES openssl"
		AC_LIBGADU_DEFINE([HAVE_OPENSSL])
	fi
fi

AC_CONFIG_FILES([Makefile src/Makefile include/Makefile pkgconfig/Makefile pkgconfig/libgadu.pc])

AC_OUTPUT
