dnl $Id$

AC_INIT(src/libgadu.h)
AM_INIT_AUTOMAKE(libgadu, 1.1.0)
AC_PREREQ(2.50)
AC_CONFIG_HEADERS(config.h)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL
AC_C_CONST
AC_C_BIGENDIAN

dnl SunOS
AC_CHECK_LIB(nsl, t_accept, LIBS="$LIBS -lnsl")
AC_CHECK_LIB(socket, socket, LIBS="$LIBS -lsocket")

dnl BeOS
AC_CHECK_LIB(bind, __inet_addr, LIBS="$LIBS -lbind")

dnl threadsafe
AC_CHECK_FUNCS([gethostbyname_r])

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

dnl
dnl  Je¶li u¿ytkownik nie chce debugowaæ, nikt mu nie ka¿e.
dnl

AC_ARG_ENABLE(debug, 
	[  --disable-debug         Compile without debugging support])

if test "x$enable_debug" = "xno"; then 
	CFLAGS="$CFLAGS -DGG_DEBUG_DISABLE"
	strip_ekg="strip-ekg"
	strip_ioctld="strip-ioctld"
	strip_libgadu_so="strip-libgadu-so"
fi

dnl
dnl  Sprawd¼my, jak± wersjê vsnprintf() dostajemy.
dnl

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

dnl
dnl  Resolver libgadu oparty na pthread
dnl

AC_ARG_WITH(pthread,
  [  --with-pthread          Use pthread in resolver])

if test "x$with_pthread" = "xyes"; then
	ACX_PTHREAD(
	[
		LIBS="$PTHREAD_LIBS $LIBS"
		CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
		CC="$PTHREAD_CC"
		have_pthread=yes

		AC_DEFINE([HAVE_PTHREAD], [], [Define if you want threaded resolver])
	], [
		AC_MSG_ERROR([Your system is not supporting pthreads])
	])
fi

dnl
dnl  Sprawdzamy, czy jest ,,long long'' na potrzeby obliczeñ czasów DCC
dnl

AC_CHECK_TYPES([long long])

AC_CONFIG_FILES([Makefile src/Makefile src/libgadu.pc])

AC_OUTPUT

