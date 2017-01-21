AC_INIT([libgadu], [1.12.2])
AC_CONFIG_SRCDIR([src/libgadu.c])
AM_INIT_AUTOMAKE()

AC_PREREQ(2.50)
AC_CANONICAL_HOST
AC_CONFIG_HEADERS(config.h include/libgadu.h)
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_C_CONST
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_SUBST(AM_CPPFLAGS)
dnl Zależności dla pkgconfig
AC_SUBST(REQUIRES_PRIVATE)
AC_SUBST(LIBS_PRIVATE)

export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig"
PKG_PROG_PKG_CONFIG

if test "$GCC"; then
dnl Other warnings that may be useful:
dnl -Wdeclaration-after-statement -Wendif-labels
dnl -Werror-implicit-function-declaration -Wformat-security -Winit-self
dnl -Wmissing-declarations -Wmissing-noreturn -Wfloat-equal
	CFLAGS="$CFLAGS -Wall -Wextra -Wmissing-prototypes \
		-Wno-unused-parameter -Waggregate-return \
		-Wdeclaration-after-statement -Wundef -Wcast-align \
		-Wpointer-arith"
fi

dnl
dnl  Egzotyczne systemy operacyjne
dnl
is_mingw="no"
case "$host" in
	*-*-mingw* | *-*-cygwin*)
		MINGW_LDFLAGS="-no-undefined -lws2_32"
		MINGW_LIBGEN="-Wl,--output-def,libgadu.def.in"
		MINGW_LIBDATA="libgadu.def"
		LDFLAGS_NO_INSTALL="-no-fast-install"
		SRCDIR=`(cd $srcdir && pwd)`
		AC_SUBST([AM_TESTS_ENVIRONMENT], [$SRCDIR/test/automatic/wine-wrapper.sh])
		is_mingw="yes"
		;;
	*)
		MINGW_LDFLAGS=""
		MINGW_LIBDATA=""
		LDFLAGS_NO_INSTALL="-no-install"
		;;
esac
AM_CONDITIONAL([HAVE_MINGW], [test "x$is_mingw" = "xyes"])
AC_SUBST([MINGW_LDFLAGS])
AC_SUBST([MINGW_LIBGEN])
AC_SUBST([MINGW_LIBDATA])
AC_SUBST([LDFLAGS_NO_INSTALL])

AC_CHECK_FUNCS([mkstemp])

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

AC_DEFINE_UNQUOTED([GG_LIBGADU_VERSION], ["${VERSION}"], [Library version])

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
	if test "x$cross_compiling" = "xyes"; then
		AC_MSG_ERROR([cannot determine vsnprintf() behaviour when cross-compiling. You need to provide --with-c99-vsnprintf or --without-c99-vsnprintf option instead. It is safe to assume that the former is valid on most modern operating systems.])
	fi
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
dnl  Sprawdzamy dostępność specyficznego dla Win32 _vscprintf(), które
dnl  pozwala oszczędzić użycie alokatora na MSVC, które nie posiada
dnl  vsnprintf() zgodnego z C99.
dnl

AC_CHECK_FUNCS([_vscprintf])

dnl
dnl  Sprawdzamy, czy jest system obsługuje zmienne 64-bitowe.
dnl

AC_MSG_CHECKING([for long long])

AC_TRY_COMPILE([],
[
	long long a = 1LL;
	unsigned long long b = 1LL;
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE([GG_CONFIG_HAVE_LONG_LONG], [], [Defined if this machine supports long long.])
], [
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([Your system does not support 64-bit variables.])
])

AC_CHECK_FUNCS([strtoull])
AC_CHECK_FUNCS([_strtoui64])

AC_MSG_CHECKING([if <$STDINT_H> has uint64_t])
AC_TRY_COMPILE([#include <$STDINT_H>], [uint64_t foo],
    AC_DEFINE([GG_CONFIG_HAVE_UINT64_T], [], [Defined if this machine has uint64_t.])
    AC_MSG_RESULT([yes]),
    AC_MSG_RESULT([no]))

dnl
dnl  SunOS
dnl

AC_CHECK_LIB(nsl, t_accept, LIBS_PRIVATE="$LIBS_PRIVATE -lnsl")
AC_CHECK_LIB(socket, socket, LIBS_PRIVATE="$LIBS_PRIVATE -lsocket")

dnl
dnl  BeOS
dnl

AC_ARG_WITH(bind,
	[  --without-bind          do not use libbind even if found])

if test "x$with_bind" != "xno"; then
	AC_CHECK_LIB(bind, __inet_addr, LIBS_PRIVATE="$LIBS_PRIVATE -lbind")
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

AC_CHECK_FUNCS([_exit])

AC_CHECK_FUNCS([fork], [AC_DEFINE([GG_CONFIG_HAVE_FORK], [], [Defined if this machine has fork().])])

AC_ARG_ENABLE(debug, 
	[  --disable-debug         compile without debugging support])

if test "x$enable_debug" = "xno"; then 
	AC_MSG_WARN([--disable-debug is obsolete.])
fi

dnl
dnl  Resolver libgadu oparty na pthread
dnl

AC_ARG_WITH(pthread,
  [  --without-pthread       do not use pthread resolver even if found])

have_pthread="no"
if test "x$with_pthread" != "xno"; then
	ACX_PTHREAD(
	[
		dnl workaround dla pkgconfiga
		if test "x$PTHREAD_CFLAGS" = "x-pthread"; then
			PTHREAD_LIBS="$PTHREAD_LIBS -pthread"
			PTHREAD_CFLAGS=""
		fi

		LIBS_PRIVATE="$PTHREAD_LIBS $LIBS_PRIVATE"
		CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
		CC="$PTHREAD_CC"
		have_pthread=yes

		AC_DEFINE([GG_CONFIG_HAVE_PTHREAD], [], [Defined if libgadu was compiled and linked with pthread support.])
	], [
		if test "x$with_pthread" = "xyes"; then
			AC_MSG_ERROR([Your system does not support pthreads])
		fi
	])
fi

dnl
dnl  Sprawdzamy zlib
dnl

AC_CHECK_LIB(z, inflateEnd, [have_zlib=yes], [have_zlib=no])
AC_CHECK_HEADER(zlib.h, [have_zlib_h=yes], [have_zlib_h=no])

if test "x$have_zlib" = "xyes" -a "x$have_zlib_h" = "xyes"; then
	LIBS_PRIVATE="$LIBS_PRIVATE -lz"
	AC_DEFINE(HAVE_ZLIB, 1, [define if you have zlib])
	AC_DEFINE([GG_CONFIG_HAVE_ZLIB], [], [Defined if libgadu was compiled and linked with zlib support.])
fi

dnl
dnl  Sprawdzamy libprotobuf-c
dnl

AC_ARG_WITH(protobuf,
  [  --without-protobuf      do not use libprotobuf-c even if found])

if test "x$with_protobuf" != "xno"; then
	PKG_CHECK_MODULES([PROTOBUF_C], [libprotobuf-c >= 1.0.0], [
		protobufc_ver=`$PKG_CONFIG --modversion libprotobuf-c`
		if test "x$protobufc_ver" = "x1.0.0-rc1"; then
			echo "WARNING: libprotobuf-c $protobufc_ver found. It's not compatible with 1.0.0 API"
			have_protobuf_c=no
		else
			LIBS_PRIVATE="$LIBS_PRIVATE $PROTOBUF_C_LIBS"
			AC_DEFINE([GG_CONFIG_HAVE_PROTOBUF_C], [], [Defined if libgadu was compiled and linked with system provided libprotobuf-c.])
			have_protobuf_c=yes
		fi
	], [have_protobuf_c=no])
else
	have_protobuf_c=no
fi
AM_CONDITIONAL([HAVE_PROTOBUF_C], [test "x$have_protobuf_c" = "xyes"])

dnl
dnl  Sprawdzamy GnuTLS
dnl

AC_ARG_WITH(gnutls,
  [  --without-gnutls        do not use GnuTLS even if found])

have_gnutls="no"

if test "x$with_gnutls" != "xno"; then
	PKG_CHECK_MODULES([GNUTLS], [gnutls >= 2.10.0], [
		AC_DEFINE([HAVE_GNUTLS], [], [Defined if GnuTLS is available.])
		AC_DEFINE([GG_CONFIG_HAVE_GNUTLS], [], [Defined if libgadu was compiled and linked with GnuTLS support.])
		REQUIRES_PRIVATE="$REQUIRES_PRIVATE gnutls"
		CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
		# Note: not adding to LIBS_PRIVATE, because
		# "REQUIRES_PRIVATE" takes care of that for pkg-config.
		LIBS="$LIBS $GNUTLS_LIBS"
		have_gnutls="yes"
	], [:])
	PKG_CHECK_MODULES([GNUTLS_2_12], [gnutls >= 2.12.0], [
		AC_DEFINE([HAVE_GNUTLS_2_12], [], [Defined if GnuTLS >= 2.12.0 is available.])
	], [:])
fi

dnl
dnl  Sprawdzamy czy mamy używać systemowych certyfikatów
dnl

AC_ARG_ENABLE(ssl-system-trust,
       	[  --disable-ssl-system-trust  disable the use of system default trusted CAs])

AC_ARG_WITH([gnutls-system-trust-store],
	[  --with-gnutls-system-trust-store=FILE  provide alternative path of system default trust store for GnuTLS versions <= 3.x])

if test "x$enable_ssl_system_trust" != "xno"; then
	AC_DEFINE([GG_CONFIG_SSL_SYSTEM_TRUST], [], [Defined if libgadu uses system defalt trusted CAs])

	if test "x$have_gnutls" = "xyes"; then
		AC_CHECK_FUNCS([gnutls_certificate_set_x509_system_trust], [have_gnutls_certificate_set_x509_system_trust=yes], [have_gnutls_certificate_set_x509_system_trust=no])

		if test "x$with_gnutls_system_trust_store" = "x"; then
			# Lista certyfikatów skopiowana z GnuTLS (https://gitorious.org/gnutls/gnutls/blobs/c59329a089a9ed108692066de95f533f482b5422/configure.ac)
			for i in /etc/ssl/ca-bundle.pem \
				/etc/ssl/certs/ca-certificates.crt \
				/etc/pki/tls/cert.pem \
				/usr/local/share/certs/ca-root-nss.crt \
				/etc/ssl/cert.pem
				do	
				if test -e $i; then
					with_gnutls_system_trust_store="$i"
					break
				fi
			done
		fi

		if test "x$with_gnutls_system_trust_store" = "xno";then
			with_gnutls_system_trust_store=""
		fi

		if test "x$with_gnutls_system_trust_store" != "x"; then
			AC_DEFINE_UNQUOTED([GG_CONFIG_GNUTLS_SYSTEM_TRUST_STORE], ["$with_gnutls_system_trust_store"], [use the given file as GnuTLS default trust store])
		fi
	fi
fi

dnl
dnl  Sprawdzamy OpenSSL, jeśli nie ma GnuTLS
dnl

if test "x$have_gnutls" != "xyes"; then
	AC_CHECK_OPENSSL
fi

if test "x$have_openssl" = "xyes"; then
	# Note: not adding to LIBS_PRIVATE, because "REQUIRES_PRIVATE" takes care
	# of that for pkg-config.
	LIBS="$LIBS $OPENSSL_LIBS"
	CFLAGS="$CFLAGS $OPENSSL_CFLAGS"
	REQUIRES_PRIVATE="$REQUIRES_PRIVATE openssl"
	AC_DEFINE([GG_CONFIG_HAVE_OPENSSL], [], [Defined if libgadu was compiled and linked with OpenSSL support.])
else
	have_openssl="no"
	AC_DEFINE([GG_CONFIG_IS_GPL_COMPLIANT], [], [Defined if libgadu is GPL compliant (was not linked with OpenSSL or any other non-GPL compliant library support).])
fi

AM_CONDITIONAL([IS_GPL_COMPLIANT], [test "x$have_openssl" != "xyes"])

# We need separate lists of libs handled with and without pkgconfig help, for the pkgconfig file.
# We concatenate them here so that libtool can pick the pkgconfig-less libs too.
LIBS="$LIBS $LIBS_PRIVATE"

dnl
dnl  Testy
dnl

AC_ARG_ENABLE(tests,
        [  --disable-tests         do not compile tests])

AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" != "xno"])

if test "x$enable_tests" != "xno"; then
	enable_tests="yes"

	dnl
	dnl  Sprawdź, czy można korzystać z __funkcji w libc.
	dnl

	AC_CHECK_LIB(c, __connect, [have_glibc="yes"], [have_glibc="no"])

	dnl
	dnl  curl i expat dla search
	dnl

	AC_CHECK_LIB(curl, curl_easy_init, [have_curl="yes"], [have_curl="no"])
	if test "x$have_curl" = "xyes"; then
		AC_CHECK_HEADERS(curl/curl.h, [], [have_curl="no"])
	fi

	AC_CHECK_LIB(expat, XML_ParserCreate, [have_expat="yes"], [have_expat="no"])
	if test "x$have_expat" = "xyes"; then
		AC_CHECK_HEADERS(expat.h, [], [have_expat="no"])
	fi

	dnl
	dnl  Perl dla protocol
	dnl

	AC_CHECK_PROG([PERL], [perl], [perl], [:])
	if test "x$PERL" != "x:"; then
		have_perl="yes"
	else
		have_perl="no"
	fi

	dnl
	dnl  Sprawdź, czy mamy libxml2 do testów automatycznych
	dnl

	PKG_CHECK_MODULES([LIBXML2], [libxml-2.0 >= 2.2.3], [
		have_libxml2="yes"
		AC_DEFINE([HAVE_LIBXML2], [], [Defined if libxml2 is available.])
	], [
		have_libxml2="no"
	])
fi

AM_CONDITIONAL([HAVE_GLIBC], [test "x$have_glibc" = "xyes"])
AM_CONDITIONAL([HAVE_CURL_AND_EXPAT], [test "x$have_curl" = "xyes" -a "x$have_expat" = "xyes"])
AM_CONDITIONAL([HAVE_PERL], [test "x$have_perl" = "xyes"])

AM_CONDITIONAL([BUILD_CONNECT_TEST], [test \( "x$have_glibc" = "xyes" -a \
	"x$have_gnutls" = "xyes" -a "x$have_pthread" = "xyes" \) -o \
	"x$is_mingw" = "xyes"])

dnl
dnl  Sprawdź, czy mamy czym generować dokumentację
dnl

AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen], [:])

AC_SUBST([SUBDIRS_DOXYGEN])
if test "x$DOXYGEN" = "xdoxygen"; then
	SUBDIRS_DOXYGEN="docs"
	AC_SUBST([DOXYFILE_HTML_DIR])
	DOXYFILE_HTML_DIR="html"
	have_doxygen="yes"
else
	SUBDIRS_DOXYGEN=""
	have_doxygen="no"
fi

dnl
dnl  Ostrzeżenia kompilatora
dnl

AC_ARG_ENABLE(werror,
        [  --enable-werror         halt on warnings])

if test "x$enable_werror" == "xyes"; then
	CFLAGS="$CFLAGS -Werror"
fi


AC_CONFIG_FILES([Makefile src/Makefile include/Makefile pkgconfig/Makefile pkgconfig/libgadu.pc docs/Makefile docs/Doxyfile examples/Makefile])

AM_COND_IF([ENABLE_TESTS],
	[AC_CONFIG_FILES([
		test/Makefile
		test/automatic/Makefile
		test/automatic/script/Makefile
		test/manual/Makefile
		test/manual/lib/Makefile
	])]
)

AC_OUTPUT

echo
echo $PACKAGE $VERSION
echo

echo Build with gnutls.... : $have_gnutls
echo Build with openssl... : $have_openssl
echo Build with protobuf-c : $have_protobuf_c
echo Build with pthread... : $have_pthread
echo Build with zlib...... : $have_zlib
echo Build with docs...... : $have_doxygen
echo

echo Enable tests......... : $enable_tests
if test "x$enable_tests" = "xyes"; then
	echo Build with glibc..... : $have_glibc
	echo Build with libcurl... : $have_curl
	echo Build with libexpat.. : $have_expat
	echo Build with libxml2... : $have_libxml2
	echo Build with perl...... : $have_perl
fi

echo
echo configure complete, now type \'make\'
echo
