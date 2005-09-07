dnl ======================================================================
dnl SAC_TPORT - perform checks for tport
dnl ======================================================================
AC_DEFUN([SAC_TPORT], [
# Check for features used by tport.
AC_SYS_IP_RECVERR
AC_SYS_IPV6_RECVERR

if test x$with_sctp != xno; then
AC_CHECK_HEADERS(netinet/sctp.h, [
AC_DEFINE(HAVE_SCTP, 1, [Define this a 1 if you have SCTP])
])
fi

AM_CONDITIONAL(HAVE_TLS, test x$HAVE_TLS = x1)
])
