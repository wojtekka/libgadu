dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/htmldoc/acx_pthread.html
dnl
dnl Slightly modified by Wojtek Kaniewski <wojtekka@irc.pl> to remove
dnl dependency from AC_CANONICAL_HOST
dnl
dnl Checks for GCC shared/pthread inconsistency added by
dnl Marcin Owsiany <marcin@owsiany.pl>
AC_DEFUN([ACX_PTHREAD], [
AC_LANG_SAVE
AC_LANG_C
acx_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, acx_pthread_ok=yes)
        AC_MSG_RESULT($acx_pthread_ok)
        if test x"$acx_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all.

acx_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
# pthread: Linux, etcetera
# --thread-safe: KAI C++

UNAME_SYSTEM=`(uname -s) 2> /dev/null` || UNAME_SYSTEM=unknown

case "$UNAME_SYSTEM" in
        *SunOS*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthread or
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        acx_pthread_flags="-pthread -pthreads pthread -mt $acx_pthread_flags"
        ;;
esac

if test x"$acx_pthread_ok" = xno; then
for flag in $acx_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>],
                    [pthread_t th; pthread_join(th, 0);
                     pthread_attr_init(0); pthread_cleanup_push(0, 0);
                     pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
                    [acx_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($acx_pthread_ok)
        if test "x$acx_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$acx_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: threads are created detached by default
        # and the JOINABLE attribute has a nonstandard name (UNDETACHED).
        AC_MSG_CHECKING([for joinable pthread attribute])
        AC_TRY_LINK([#include <pthread.h>],
                    [int attr=PTHREAD_CREATE_JOINABLE;],
                    ok=PTHREAD_CREATE_JOINABLE, ok=unknown)
        if test x"$ok" = xunknown; then
                AC_TRY_LINK([#include <pthread.h>],
                            [int attr=PTHREAD_CREATE_UNDETACHED;],
                            ok=PTHREAD_CREATE_UNDETACHED, ok=unknown)
        fi
        if test x"$ok" != xPTHREAD_CREATE_JOINABLE; then
                AC_DEFINE(PTHREAD_CREATE_JOINABLE, $ok,
                          [Define to the necessary symbol if this constant
                           uses a non-standard name on your system.])
        fi
        AC_MSG_RESULT(${ok})
        if test x"$ok" = xunknown; then
                AC_MSG_WARN([we do not know how to create joinable pthreads])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
	case "$UNAME_SYSTEM" in 
		*GNU/kFreeBSD*) flag=no;;
                *AIX* | *FreeBSD*)     flag="-D_THREAD_SAFE";;
                *SunOS* | *OSF* | *HP-UX*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
                PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with cc_r
        AC_CHECK_PROG(PTHREAD_CC, cc_r, cc_r, ${CC})

	# The next part tries to detect GCC inconsistency with -shared on some
	# architectures and systems. The problem is that in certain
	# configurations, when -shared is specified, GCC "forgets" to
	# internally use various flags which are still necessary.
	
	# First, check whether caller wants us to skip -shared checks
	# this is useful
	AC_MSG_CHECKING([whether to check for GCC pthread/shared inconsistencies])
	if test x"$3" = x1; then
		AC_MSG_RESULT([no])
	else
		AC_MSG_RESULT([yes])

		# In order not to create several levels of indentation, we test
		# the value of "$ok" until we find out the cure or run out of
		# ideas.
		ok="no"

		#
		# Prepare the flags
		#
		save_CFLAGS="$CFLAGS"
		save_LIBS="$LIBS"
		save_CC="$CC"
		# Try with the flags determined by the earlier checks.
		#
		# -Wl,-z,defs forces link-time symbol resolution, so that the
		# linking checks with -shared actually have any value
		#
		# FIXME: -fPIC is required for -shared on many architectures,
		# so we specify it here, but the right way would probably be to
		# properly detect whether it is actually required.
		CFLAGS="-shared -fPIC -Wl,-z,defs $CFLAGS $PTHREAD_CFLAGS"
		LIBS="$PTHREAD_LIBS $LIBS"
		CC="$PTHREAD_CC"

		AC_MSG_CHECKING([whether -pthread is sufficient with -shared])
		AC_TRY_LINK([#include <pthread.h>],
			[pthread_t th; pthread_join(th, 0);
			pthread_attr_init(0); pthread_cleanup_push(0, 0);
			pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
			[ok=yes])
		
		if test "x$ok" = xyes; then
			AC_MSG_RESULT([yes])
		else
			AC_MSG_RESULT([no])
		fi
	
		#
		# Linux gcc on some architectures such as mips/mipsel forgets
		# about -lpthread
		#
		if test x"$ok" = xno; then
			AC_MSG_CHECKING([whether -lpthread fixes that])
			LIBS="-lpthread $PTHREAD_LIBS $save_LIBS"
			AC_TRY_LINK([#include <pthread.h>],
				[pthread_t th; pthread_join(th, 0);
				pthread_attr_init(0); pthread_cleanup_push(0, 0);
				pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
				[ok=yes])
	
			if test "x$ok" = xyes; then
				AC_MSG_RESULT([yes])
				PTHREAD_LIBS="-lpthread $PTHREAD_LIBS"
			else
				AC_MSG_RESULT([no])
			fi
		fi
	
		#
		# FreeBSD 4.10 gcc forgets to use -lc_r instead of -lc
		#
		if test x"$ok" = xno; then
			AC_MSG_CHECKING([whether -lc_r fixes that])
			LIBS="-lc_r $PTHREAD_LIBS $save_LIBS"
			AC_TRY_LINK([#include <pthread.h>],
			    [pthread_t th; pthread_join(th, 0);
			     pthread_attr_init(0); pthread_cleanup_push(0, 0);
			     pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
			    [ok=yes])
	
			if test "x$ok" = xyes; then
				AC_MSG_RESULT([yes])
				PTHREAD_LIBS="-lc_r $PTHREAD_LIBS"
			else
				AC_MSG_RESULT([no])
			fi
		fi
		
		if test x"$ok" = xno; then
			# OK, we have run out of ideas
			AC_MSG_WARN([Impossible to determine how to use pthreads with shared libraries])

			# so it's not safe to assume that we may use pthreads
			acx_pthread_ok=no
		fi

		CFLAGS="$save_CFLAGS"
		LIBS="$save_LIBS"
		CC="$save_CC"
	fi
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$acx_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        acx_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl ACX_PTHREAD
