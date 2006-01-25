dnl ======================================================================
dnl su module
dnl ======================================================================

dnl This is in a separate file because otherwise AM_CONFIG_HEADER in
dnl SAC_SOFIA_SU confuses autoheader. If SAC_SOFIA_SU is included to a
dnl aclocal.m4 of another package, autoheader returns a spurious error and
dnl automake complains about missing su/su_configure.h.

AC_DEFUN([SAC_SOFIA_SU], [
# Beginning of SAC_SOFIA_SU

AC_REQUIRE([SAC_WITH_RT])

# ======================================================================
# Check for features used by su

dnl Define compilation options for su_configure.h
SAC_SU_DEFINE([SU_HAVE_BSDSOCK], 1, [Define as 1 if you have BSD socket interface])

case "$target" in 
*-*-solaris?.* )
  SAC_SU_DEFINE(__EXTENSIONS__, 1, [Define this in Solaris in order to get POSIX extensions.])
;;
esac

case "$target" in 
i?86-*-* )
  SAC_SU_DEFINE(SU_HAVE_TAGSTACK, 1, [Define this as 1 if we can use tags directly from stack.])
;;
esac

if false; then
  #
  # Define Win32 macros
  #
  AC_DEFINE([HAVE_WIN32], 1, [Define as 1 you have WIN32])

  SAC_SU_DEFINE([SU_HAVE_WINSOCK], 1, [Define as 1 you have WinSock])

  SAC_SU_DEFINE([SU_HAVE_WINSOCK2], 1, [Define as 1 you have WinSock2])

  AC_DEFINE([HAVE_IPHLPAPI_H], 1, [Define as 1 you have WIN32 <iphlpapi.h>])

  AC_DEFINE([HAVE_FILETIME], 1, [
     Define this as 1 if you have WIN32 FILETIME type and 
     GetSystemTimeAsFileTime().])

  AC_DEFINE([HAVE_INTERFACE_INFO_EX], 1, [
     Define this as 1 if you have WIN32 INTERFACE_INFO_EX type.])

  AC_DEFINE([HAVE_SIO_ADDRESS_LIST_QUERY], 1, [
     Define this as 1 if you have WIN32 WSAIoctl SIO_ADDRESS_LIST_QUERY.])
fi

# Check includes used by su includes
AC_CHECK_HEADER(sys/types.h, 
	SAC_SU_DEFINE([SU_HAVE_SYS_TYPES], 1, 
		     [Define as 1 if Sofia uses sys/types.h]))

ax_inttypes=false
AC_CHECK_HEADER(stdint.h, [
	ax_inttypes=true
	SAC_SU_DEFINE([SU_HAVE_STDINT], 1, 
		     [Define as 1 if Sofia uses stdint.h])])
AC_CHECK_HEADER(inttypes.h,[
	ax_inttypes=true
	SAC_SU_DEFINE([SU_HAVE_INTTYPES], 1, 
		     [Define as 1 if Sofia uses inttypes.h])])

if $ax_inttypes; then : ; else 
	AC_MSG_ERROR("No <stdint.h> or <inttypes.h> found.")
fi

AC_CHECK_HEADER(pthread.h, 
        HAVE_PTHREADS=1;
	SAC_SU_DEFINE([SU_HAVE_PTHREADS], 1, [Sofia SU uses pthreads]))

AC_CHECK_HEADERS([unistd.h sys/time.h])
AC_CHECK_HEADERS([sys/socket.h sys/ioctl.h sys/filio.h sys/sockio.h])
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h netdb.h net/if.h net/if_types.h])

if test "1${ac_cv_arpa_inet_h}2${ac_cv_netdb_h}3${ac_cv_sys_socket_h}4${ac_cv_net_if_h}" = 1yes2yes3yes4yes; then

AC_TRY_COMPILE([#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>], [
struct ifreq ifreq; int index; index = ifreq.ifr_index;
], AC_DEFINE(HAVE_IFR_INDEX, 1, [Define this as 1 if you have ifr_index in <net/if.h>]))dnl

AC_TRY_COMPILE([#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>], [
struct ifreq ifreq; int index; index = ifreq.ifr_ifindex;
], AC_DEFINE(HAVE_IFR_IFINDEX, 1, [Define this as 1 if you have ifr_ifindex in <net/if.h>]))dnl

fi

dnl ===========================================================================
dnl Checks for typedefs, structures, and compiler characteristics.
dnl ===========================================================================

AC_REQUIRE([AC_C_CONST])
AC_REQUIRE([AC_C_INLINE])
AC_REQUIRE([AC_HEADER_TIME])
AC_REQUIRE([AC_TYPE_SIZE_T])
AC_REQUIRE([AC_C_VAR_FUNC])
AC_REQUIRE([AC_C_MACRO_FUNCTION])
AC_REQUIRE([AC_STRUCT_SIN6])
AC_REQUIRE([AC_SYS_SA_LEN])

if test "$ac_cv_sa_len" = yes ;then
  SAC_SU_DEFINE([SU_HAVE_SOCKADDR_SA_LEN], 1, 
	        [Define this as 1 if you have sa_len in struct sockaddr])
fi

AC_COMPILE_IFELSE([long long ll;],dnl
AC_DEFINE(HAVE_LONG_LONG, 1, [Define this as 1 if you have long long]))dnl

case "$ac_cv_c_inline" in
  yes) SAC_SU_DEFINE(su_inline, static inline, [
		Define this as declarator for static inline functions.
	])dnl
       SAC_SU_DEFINE(SU_INLINE, inline, [
		Define this as declarator for inline functions.
	])dnl
       SAC_SU_DEFINE(SU_HAVE_INLINE, 1, [
		Define this as 1 if you have inline functions.
	])dnl
  ;;
  no)  SAC_SU_DEFINE(su_inline, static)dnl
       SAC_SU_DEFINE(SU_INLINE)dnl
       SAC_SU_DEFINE(SU_HAVE_INLINE)dnl
  ;;
  *)   SAC_SU_DEFINE_UNQUOTED(su_inline, static $ac_cv_c_inline)dnl
       SAC_SU_DEFINE_UNQUOTED(SU_INLINE, $ac_cv_c_inline)dnl
       SAC_SU_DEFINE(SU_HAVE_INLINE, 1)dnl
  ;;
esac

case $ac_cv_sin6 in 
yes) SAC_SU_DEFINE(SU_HAVE_IN6, 1, [
	Define this as 1 if you have struct sockaddr_in6]) ;;
 no) ;;
  *) AC_MSG_ERROR([Inconsistent struct sockaddr_sin6 test]) ;;
esac

AC_MSG_CHECKING([for struct sockaddr_storage])
AC_EGREP_HEADER([struct.+sockaddr_storage], [sys/socket.h], [dnl
  AC_MSG_RESULT(yes)
  SAC_SU_DEFINE(SU_HAVE_SOCKADDR_STORAGE)],[dnl
  AC_MSG_RESULT(no)
])

dnl SIOGCIFCONF & struct ifconf
AC_MSG_CHECKING(for struct ifconf)
AC_EGREP_HEADER(struct.+ifconf, net/if.h, 
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_IFCONF, 1, [Define this as 1 if you have SIOCGIFCONF])], 
  [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(for SIOCGIFNUM)
AC_EGREP_CPP(yes, [
#include <sys/sockio.h>
#ifdef SIOCGIFNUM
  yes
#endif
], [HAVE_IFNUM=1; AC_MSG_RESULT(yes); 
    AC_DEFINE(HAVE_IFNUM, 1, [Define this as 1 if you have SIOCGIFNUM ioctl])], 
   [HAVE_IFNUM=0; AC_MSG_RESULT(no)])

# ===========================================================================
# Checks for libraries
# ===========================================================================

SAC_CHECK_SU_LIBS

AC_ARG_WITH(glib,
[  --with-glib=version     use GLib (default=2.0)], [
case "$with_glib" in 
yes | "" ) with_glib=2.0 ;;
esac
], [with_glib=2.0])

if test X$with_glib != Xno ; then 

PKG_CHECK_MODULES(GLIB, glib-$with_glib, [dnl
SAC_SU_DEFINE([SU_HAVE_GLIB], 1, [Define as 1 if you have >= glib-2.0])
HAVE_GLIB=yes
])

fi

AM_CONDITIONAL([HAVE_GLIB], [test "x$HAVE_GLIB" != x])
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_VERSION)

# ===========================================================================
# Checks for library functions.
# ===========================================================================

AC_CHECK_FUNCS(gettimeofday strerror random initstate tcsetattr flock alarm)
AC_CHECK_FUNCS(socketpair gethostname getipnodebyname poll)

if false; then
	# not yet
	AC_CHECK_FUNCS(epoll)
fi

# _GNU_SOURCE stuff
AC_CHECK_FUNCS(getline getdelim getpass)

AC_REQUIRE([SAC_WITH_RT])

if test "${with_rt}" != no; then
    AC_CHECK_FUNCS(clock_gettime clock_getcpuclockid)
fi

SAC_REPLACE_FUNCS(memmem memccpy memspn memcspn strcasestr strtoull)

# Test for getaddrinfo(), getnameinfo(), freeaddrinfo() and gai_strerror()
AC_CHECK_FUNC([getaddrinfo],[
	SAC_SU_DEFINE([SU_HAVE_GETADDRINFO], 1, [
	Define this as 1 if you have getaddrinfo() function.
	])])

AC_CHECK_FUNC([poll], 
	SAC_SU_DEFINE([SU_HAVE_POLL], 1, [
	Define this as 1 if you have poll() function.
	]))

AC_CHECK_FUNC([if_nameindex], 
	SAC_SU_DEFINE([SU_HAVE_IF_NAMEINDEX], 1, [
	Define this as 1 if you have if_nameindex() function.
	]))

# ===========================================================================
# Check pthread_rwlock_unlock()
# ===========================================================================

AC_DEFUN([AC_DEFINE_HAVE_PTHREAD_RWLOCK],[dnl
AC_DEFINE([HAVE_PTHREAD_RWLOCK], 1,[
Define this as 1 if you have working pthread_rwlock_t implementation.

   A  thread  may hold multiple concurrent read locks on rwlock - that is,
   successfully call the pthread_rwlock_rdlock() function  n  times.  If
   so,  the  application  shall  ensure that the thread performs matching
   unlocks - that is, it  calls  the  pthread_rwlock_unlock()  function  n
   times.
])])

if test x$HAVE_PTHREADS = x1 ; then

AC_RUN_IFELSE([
#define _XOPEN_SOURCE (500)

#include <pthread.h>

pthread_rwlock_t rw;

int main()
{
  pthread_rwlock_init(&rw, NULL);
  pthread_rwlock_rdlock(&rw);
  pthread_rwlock_rdlock(&rw);
  pthread_rwlock_unlock(&rw);
  /* pthread_rwlock_trywrlock() should fail (not return 0) */
  return pthread_rwlock_trywrlock(&rw) != 0 ? 0  : 1;
}
],[AC_DEFINE_HAVE_PTHREAD_RWLOCK],[
AC_MSG_WARN([Recursive pthread_rwlock_rdlock() does not work!!! ])
],[AC_DEFINE_HAVE_PTHREAD_RWLOCK])

fi

# ===========================================================================
# Check IPv6 addresss configuration
# ===========================================================================
case "$target" in
 *-*-linux*) AC_DEFINE([HAVE_PROC_NET_IF_INET6], 1, 
	[Define this as 1 if you have /proc/net/if_inet6 control file]) ;;
esac

# ===========================================================================
# Check for partial su distibutions
# ===========================================================================

if test -r ${srcdir}/libsofia-sip-ua/su/su_wait.h ; then
  AC_DEFINE(HAVE_SU_WAIT_H, 1, 
            [Define to 1 if you have the <su_wait.h> header file.])
fi

AM_CONFIG_HEADER([libsofia-sip-ua/su/su_configure.h])
])

# SAC_SU_DEFINE(VARIABLE, [VALUE], [DESCRIPTION])
# -------------------------------------------
# Set VARIABLE to VALUE, verbatim, or 1.  Remember the value
# and if VARIABLE is affected the same VALUE, do nothing, else
# die.  The third argument is used by autoheader.
m4_define([SAC_SU_DEFINE],[
cat >>confdefs.h <<\_AXEOF
[@%:@define] $1 m4_if($#, 2, [$2], $#, 3, [$2], 1)
_AXEOF
])

# SAC_SU_DEFINE_UNQUOTED(VARIABLE, [VALUE], [DESCRIPTION])
# ----------------------------------------------------
# Similar, but perform shell substitutions $ ` \ once on VALUE.
m4_define([SAC_SU_DEFINE_UNQUOTED],[
cat >>confdefs.h <<_ACEOF
[@%:@define] $1 m4_if($#, 2, [$2], $#, 3, [$2], 1)
_ACEOF
])

AC_DEFUN([SAC_REPLACE_FUNCS],[dnl
AC_CHECK_FUNCS($1,ifelse([$2], , :, [$2]),[dnl
case "$REPLACE_LIBADD" in
    "$ac_func.lo"   | \
  *" $ac_func.lo"   | \
    "$ac_func.lo "* | \
  *" $ac_func.lo "* ) ;;
  *) REPLACE_LIBADD="$REPLACE_LIBADD $ac_func.lo" ;;
esac])
AC_SUBST([REPLACE_LIBADD])
ifelse([$3], , :, [$3])
])
