dnl Based on AC_NEED_STDINT_H by Guido Draheim <guidod@gmx.de> that can be
dnl found at http://www.gnu.org/software/ac-archive/. Do not complain him
dnl about this macro.
dnl 
dnl $Id$

AC_DEFUN([AC_NEED_STDINT_H],
 [AC_MSG_CHECKING([for uintXX_t types])

  ac_header_stdint=""
  dnl inttypes have PRIu64 defined, stdint.h does not
  for i in inttypes.h stdint.h sys/inttypes.h sys/int_types.h sys/types.h; do
    if test "x$ac_header_stdint" = "x"; then
      AC_TRY_COMPILE([#include <$i>], [uint32_t foo], [ac_header_stdint=$i])
    fi
  done

  if test "x$ac_header_stdint" != "x" ; then
    AC_MSG_RESULT([found in <$ac_header_stdint>])
    STDINT_H="$ac_header_stdint"
  else
    AC_MSG_RESULT([not found, using reasonable defaults])
    STDINT_H=""
  fi
])
