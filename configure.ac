dnl $Id$

AC_INIT(src/libgadu.c)
AM_INIT_AUTOMAKE(libgadu, 1.9.0-pre)

AC_PREREQ(2.50)
AC_CANONICAL_HOST
AC_CONFIG_HEADERS(config.h include/libgadu.h)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_C_CONST
AC_PROG_LIBTOOL

AC_SUBST(REQUIRES)
AC_SUBST(INCLUDES)

if test "$GCC"; then
	CFLAGS="$CFLAGS -Wall"
fi

AC_C_BIGENDIAN

if test "x$ac_cv_c_bigendian" = "xyes"; then
	AC_DEFINE([GG_CONFIG_BIGENDIAN], [], [Defined if libgadu was compiled for bigendian machine.])
fi

AC_NEED_STDINT_H

if test "x$STDINT_H" = "xstdint.h"; then
	AC_DEFINE([GG_CONFIG_HAVE_STDINT_H], [], [Defined if uintX_t types are defined in <stdint.h>.])
fi

if test "x$STDINT_H" = "xinttypes.h"; then
	AC_DEFINE([GG_CONFIG_HAVE_INTTYPES_H], [], [Defined if uintX_t types are defined in <inttypes.h>.])
fi

if test "x$STDINT_H" = "xsys/inttypes.h"; then
	AC_DEFINE([GG_CONFIG_HAVE_SYS_INTTYPES_H], [], [Defined if uintX_t types are defined in <sys/inttypes.h>.])
fi

if test "x$STDINT_H" = "xsys/int_types.h"; then
	AC_DEFINE([GG_CONFIG_HAVE_SYS_INT_TYPES_H], [], [Defined if uintX_t types are defined in <sys/int_types.h>.])
fi

if test "x$STDINT_H" = "xsys/types.h"; then
	AC_DEFINE([GG_CONFIG_HAVE_SYS_TYPES_H], [], [Defined if uintX_t types are defined in <sys/types.h>.])
fi

AC_DEFINE([GG_LIBGADU_VERSION], [], [Library version])
AC_DEFINE_UNQUOTED(GG_LIBGADU_VERSION, "${VERSION}")

dnl
dnl  Sprawdźmy, jaką wersję vsnprintf() dostajemy. Dodatkowa opcja jest
dnl  dla kompilacji skrośnej, bo nie można wtedy korzystać z AC_TRY_RUN().
dnl

AC_ARG_WITH(c99-vsnprintf,
	[  --with-c99-vsnprintf    target system has C99-compatible vsnprintf()])

if test "x$with_c99_vsnprintf" = "xyes"; then
	AC_DEFINE([GG_CONFIG_HAVE_C99_VSNPRINTF], [], [Defined if this machine has C99-compiliant vsnprintf().])
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
		AC_DEFINE([GG_CONFIG_HAVE_C99_VSNPRINTF], [], [Defined if this machine has C99-compiliant vsnprintf().])
	], [
		AC_MSG_RESULT([no])
	])
fi

dnl
dnl  Sprawdzamy, czy jest ,,long long'' na potrzeby obliczeń czasów DCC
dnl

AC_MSG_CHECKING([for long long])

AC_TRY_COMPILE([],
[
	long long a = 1LL;
	unsigned long long b = 1LL;
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([GG_CONFIG_HAVE_LONG_LONG], [], [Defined if this machine supports long long.])
])

dnl
dnl  SunOS
dnl

AC_CHECK_LIB(nsl, t_accept, LIBS="$LIBS -lnsl")
AC_CHECK_LIB(socket, socket, LIBS="$LIBS -lsocket")

dnl
dnl  BeOS
dnl

AC_ARG_WITH(bind,
	[  --without-bind          do not use libbind even if found])

if test "x$with_bind" != "xno"; then
	AC_CHECK_LIB(bind, __inet_addr, LIBS="$LIBS -lbind")
fi

dnl
dnl  threadsafe
dnl

AC_CHECK_FUNCS([gethostbyname_r], [AC_DEFINE([GG_CONFIG_HAVE_GETHOSTBYNAME_R], [], [Defined if this machine has gethostbyname_r().])])

AC_MSG_CHECKING([for va_copy])
AC_TRY_LINK([#include <stdarg.h>], [va_list a, b; va_copy(a, b);], 
[
	AC_MSG_RESULT([yes])
	AC_DEFINE([GG_CONFIG_HAVE_VA_COPY], [], [Defined if this machine has va_copy().])
], [
	AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([for __va_copy])
AC_TRY_LINK([#include <stdarg.h>], [va_list a, b; __va_copy(a, b);], 
[
	AC_MSG_RESULT([yes])
	AC_DEFINE([GG_CONFIG_HAVE___VA_COPY], [], [Defined if this machine has __va_copy().])
], [
	AC_MSG_RESULT([no])
])

AC_ARG_ENABLE(debug, 
	[  --disable-debug         compile without debugging support])

if test "x$enable_debug" = "xno"; then 
	AC_MSG_WARN([--disable-debug is obsolete.])
fi

dnl
dnl  Resolver libgadu oparty na pthread
dnl

AC_ARG_WITH(pthread,
  [  --without-pthread       do not use pthread resolver even if possible])

if test "x$with_pthread" != "xno"; then
	ACX_PTHREAD(
	[
		dnl workaround dla pkgconfiga
		if test "x$PTHREAD_CFLAGS" = "x-pthread"; then
			PTHREAD_LIBS="$PTHREAD_LIBS -pthread"
		fi

		LIBS="$PTHREAD_LIBS $LIBS"
		CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
		INCLUDES="$INCLUDES $PTHREAD_CFLAGS"
		CC="$PTHREAD_CC"
		have_pthread=yes

		AC_DEFINE([GG_CONFIG_HAVE_PTHREAD], [], [Defined if libgadu was compiled and linked with pthread support.])
	], [
		if test "x$with_pthread" = "xyes"; then
			AC_MSG_ERROR([Your system is not supporting pthreads])
		fi
	])
fi

if test "x$with_pthread" = "xyes"; then
	AC_DEFINE([GG_CONFIG_PTHREAD_DEFAULT], [], [Defined if pthread resolver is the default one.])
fi

dnl
dnl  Sprawdzamy OpenSSL
dnl

AC_CHECK_OPENSSL

if test "x$have_openssl" = "xyes"; then
	LIBS="$LIBS $OPENSSL_LIBS"
	CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
	INCLUDES="$INCLUDES $OPENSSL_INCLUDES"
	REQUIRES="$REQUIRES openssl"
	AC_DEFINE([GG_CONFIG_HAVE_OPENSSL], [], [Defined if libgadu was compiled and linked with TLS support.])
fi

dnl
dnl  Sprawdź, czy można korzystać z __funkcji w libc.
dnl 

AC_SUBST([OPTIONAL_TESTS])
AC_CHECK_LIB(c, __connect, [
	OPTIONAL_TESTS="connect resolver"
],
[
	OPTIONAL_TESTS=""
])

AC_CONFIG_FILES([Makefile src/Makefile include/Makefile pkgconfig/Makefile pkgconfig/libgadu.pc docs/Makefile docs/Doxyfile examples/Makefile test/Makefile test/protocol/Makefile test/protocol/tests/Makefile test/dcc7/Makefile test/connect/Makefile test/gg8oauth/Makefile test/resolver/Makefile test/convert/Makefile])

AC_OUTPUT
