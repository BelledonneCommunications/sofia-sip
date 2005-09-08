dnl 
dnl ref: http://www.gnu.org/software/autoconf/manual/autoconf.info.gz
dnl
AC_PREREQ(2.57)

dnl information on the package
dnl ---------------------------

AC_INIT([sofia-sip], [1.10.1.2005.09.08])
AC_CONFIG_SRCDIR([libsofia-sip-ua/sip/sip.h])

# dnl calls AC_CANONICAL_ macros that are required by AM_INIT_AUTOMAKE
AX_PROG_RANLIB

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_CONFIG_HEADER(config.h)

SAC_ENABLE_NDEBUG

dnl checks for programs
dnl -------------------
AX_TOOL_CC
AC_PROG_INSTALL
AC_PROG_CPP
AC_CHECK_PROG(ETAGS, etags, etags, echo)
AC_CHECK_TOOL(AR, ar, ar)
AC_CHECK_TOOL(LD, ld, ld)
AC_PROG_LIBTOOL

### checks for libraries
### --------------------
AC_CHECK_LIB(pthread, pthread_create)

PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_VERSION)

SAC_GNU_SOURCE
SAC_SOFIA_SU
SAC_OPENSSL
SAC_TPORT
SAC_SU

### internal modules
### ----------------
AC_DEFINE([HAVE_SOFIA_SIP], 1, [Define as 1 always])
AC_DEFINE([HAVE_SOFIA_STUN], 1, [Define as 1 if we use STUN library])
AC_DEFINE([HAVE_SOFIA_SRESOLV], 1, [Define as 1 if we use DNS library])
AC_DEFINE([HAVE_SOFIA_SMIME], 0, [Define as 1 if we use S/MIME library])

AC_DEFINE([HAVE_SRTP], 0, [Define as 1 if we use SRTP])
AC_DEFINE([HAVE_UPNP], 0, [Define as 1 if we use UPnP])

### checks for header files
### -----------------------

### checks for types
### ----------------

AC_TYPE_SIGNAL
AC_CHECK_TYPE([long long],[
AC_DEFINE([longlong], [long long], [Define as at least 64-bit int type])dnl
AC_DEFINE([LLU], ["%llu"], [Define as format (%llu) for unsigned long long])dnl
AC_DEFINE([LLI], ["%lli"], [Define as format (%lli) for long long])dnl
AC_DEFINE([LLX], ["%llx"], [Define as format (%llx) for long long hex])dnl
])dnl

### checks for structures
### ---------------------
AC_HEADER_STDC
AC_CHECK_HEADERS(pthread.h)
AC_CHECK_HEADERS(stdint.h)
AC_CHECK_HEADERS(inttypes.h)

### checks for typedefs, structures, and compiler characteristics.
### --------------------------------------------------------------
AC_C_CONST
AC_C_INLINE
AC_C_INLINE_DEFINE
AC_C_BIGENDIAN

AC_C_VAR_FUNC
AC_C_MACRO_FUNCTION
AC_C_KEYWORD_STRUCT

AC_HEADER_TIME
AC_TYPE_SIZE_T

AC_STRUCT_SIN6
AC_SYS_SA_LEN

### checks for library functions
### ----------------------------
AC_SEARCH_LIBS(gethostbyname, xnet nsl)
AC_SEARCH_LIBS(getipnodebyname, xnet socket nsl)
AC_SEARCH_LIBS(getaddrinfo, xnet socket nsl)
AC_SEARCH_LIBS(socket, xnet socket)
AC_SEARCH_LIBS(inet_ntop, socket nsl)
AC_SEARCH_LIBS(inet_pton, socket nsl)

### checks for system services
### --------------------------
dnl XXX

### output
### ------

AC_CONFIG_FILES([
Makefile
sofia-sip.spec
libsofia-sip-ua/Makefile
libsofia-sip-ua/bnf/Makefile
libsofia-sip-ua/docs/Makefile
libsofia-sip-ua/docs/pictures/Makefile
libsofia-sip-ua/docs/Doxyfile.version
libsofia-sip-ua/docs/sofia-footer.html
libsofia-sip-ua/http/Makefile
libsofia-sip-ua/ipt/Makefile
libsofia-sip-ua/iptsec/Makefile
libsofia-sip-ua/msg/Makefile
libsofia-sip-ua/nea/Makefile
libsofia-sip-ua/nta/Makefile
libsofia-sip-ua/nth/Makefile
libsofia-sip-ua/nua/Makefile
libsofia-sip-ua/sdp/Makefile
libsofia-sip-ua/sdp/tests/Makefile
libsofia-sip-ua/soa/Makefile
libsofia-sip-ua/sip/Makefile
libsofia-sip-ua/sip/images/Makefile
libsofia-sip-ua/sip/tests/Makefile
libsofia-sip-ua/sresolv/Makefile 
libsofia-sip-ua/stun/Makefile
libsofia-sip-ua/su/Makefile
libsofia-sip-ua/tport/Makefile
libsofia-sip-ua/url/Makefile
utils/Makefile
sofia-sip-ua.pc
])

AC_OUTPUT
