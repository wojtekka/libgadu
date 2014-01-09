dnl based on curses.m4 
dnl $Id$

AC_DEFUN([AC_CHECK_OPENSSL],[
  AC_SUBST(OPENSSL_LIBS)
  AC_SUBST(OPENSSL_INCLUDES)

  with_arg=""

  AC_ARG_WITH(openssl,
    [[  --with-openssl          use OpenSSL, if found (the resulting binary won't be GPL-compliant)]],
      if test "x$withval" != "xyes" -a "x$withval" != "xno" ; then
        with_arg=$withval/include:-L$withval/lib
        with_openssl="yes"
      fi,
      with_openssl="no")

  if test "x$with_openssl" = "xyes" -a "x$with_arg" = "x"; then
    PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.7], [
	AC_DEFINE(HAVE_OPENSSL, 1, [define if you have OpenSSL])
        without_openssl=yes
	have_openssl=yes
	], [:])
  fi

  if test "x$with_openssl" = "xyes" -a "x$have_openssl" != "xyes" ; then
    dnl Beware, this code is not able to check installed openssl version

    AC_MSG_CHECKING(for ssl.h)

    for i in $with_arg \
    		/usr/include: \
		/usr/local/include:"-L/usr/local/lib" \
		/usr/local/ssl/include:"-L/usr/local/ssl/lib" \
		/usr/pkg/include:"-L/usr/pkg/lib" \
		/usr/contrib/include:"-L/usr/contrib/lib" \
		/usr/freeware/include:"-L/usr/freeware/lib32" \
    		/sw/include:"-L/sw/lib" \
    		/cw/include:"-L/cw/lib" \
		/boot/home/config/include:"-L/boot/home/config/lib"; do
	
      incl=`echo "$i" | sed 's/:.*//'`
      lib=`echo "$i" | sed 's/.*://'`

      if test -f $incl/openssl/ssl.h; then
        AC_MSG_RESULT($incl/openssl/ssl.h)
	ldflags_old="$LDFLAGS"
	LDFLAGS="$lib -lssl -lcrypto"
	save_LIBS="$LIBS"
	LIBS="-lssl -lcrypto $LIBS"
	AC_CHECK_LIB(ssl, RSA_new, [
	  AC_DEFINE(HAVE_OPENSSL, 1, [define if you have OpenSSL])
	  have_openssl=yes
	  OPENSSL_LIBS="$lib -lssl -lcrypto"
	  if test "x$incl" != "x/usr/include"; then
    	    OPENSSL_INCLUDES="-I$incl"
	  fi
	])
	LIBS="$save_LIBS"
	LDFLAGS="$ldflags_old"
	break
      fi
    done

    if test "x$have_openssl" != "xyes"; then
      AC_MSG_RESULT(not found)
    fi
  fi
])
