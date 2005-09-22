dnl ======================================================================
dnl su module
dnl ======================================================================

dnl This is in a separate file because otherwise AM_CONFIG_HEADER in
dnl SAC_SOFIA_SU confuses autoheader. If SAC_SOFIA_SU is included to a
dnl aclocal.m4 of another package, autoheader returns a spurious error and
dnl automake complains about missing su/su_configure.h.

AC_DEFUN([SAC_SOFIA_SU], [
# Beginning of SAC_SOFIA_SU
# $Id: sac-su2.m4,v 1.3 2005/09/19 11:12:10 kaiv Exp $

AC_REQUIRE([SAC_WITH_RT])

# ======================================================================
# Check for features used by su

# Define compilation options for su_configure.h
SAC_SU_DEFINE([SU_HAVE_BSDSOCK], 1, [Define as 1 if you have BSD socket interface])

case "$target" in 
*-*-solaris?.* )
  SAC_SU_DEFINE(__EXTENSIONS__, 1, [Define this in Solaris in order to get POSIX extensions.])
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
	SAC_SU_DEFINE([SU_HAVE_PTHREADS], 1, [Sofia SU uses pthreads]))

AC_CHECK_HEADERS([unistd.h sys/time.h sys/socket.h sys/filio.h])
AC_CHECK_HEADERS([net/if.h sys/sockio.h])

AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>], [
struct ifreq ifreq; int index; index = ifreq.ifr_index;
], AC_DEFINE(HAVE_IFR_INDEX, 1, [Define this as 1 if you have ifr_index in <net/if.h>]))dnl

AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>], [
struct ifreq ifreq; int index; index = ifreq.ifr_ifindex;
], AC_DEFINE(HAVE_IFR_IFINDEX, 1, [Define this as 1 if you have ifr_ifindex in <net/if.h>]))dnl

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
	Define this as 1 if you have struct sockaddr_in6])
;; 
no) ;;
*) AC_MSG_ERROR([Inconsistent struct sockaddr_sin6 test]) ;;
esac

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

SAC_CHECK_SU_LIBS

# ===========================================================================
# Checks for library functions.
# ===========================================================================

AC_CHECK_FUNCS(gettimeofday strerror random initstate tcsetattr flock alarm)
AC_CHECK_FUNCS(socketpair gethostname getipnodebyname getaddrinfo poll)

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

AC_CHECK_FUNCS(memccpy memcspn memspn strcasestr)
AC_REPLACE_FUNCS(memmem)

AC_CHECK_FUNC([poll], 
	SAC_SU_DEFINE([SU_HAVE_POLL], 1, [
	Define this as 1 if you have poll() function.
	]))

AC_CHECK_FUNC([if_nameindex], 
	SAC_SU_DEFINE([SU_HAVE_IF_NAMEINDEX], 1, [
	Define this as 1 if you have if_nameindex() function.
	]))

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
