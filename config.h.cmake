/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (c) 2010-2021 Belledonne Communications SARL.
 *
 * This file is part of Liblinphone.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


/*
 * This file as been extracted by configuring the project with the Autotools configure
 * script on a x86_64 machine and a recent GNU/Linux distribution. The current macro
 * definitions should work on most UNIX platforms but some adjustments
 * may be required for supporting SofiaSip on some of them.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define to 1 if using 'alloca.c'. */
/* #undef C_ALLOCA */

/* Define to the random number source name. */
#define DEV_URANDOM 1

/* Define to 1 if you have addrinfo structure. */
/* #undef HAVE_ADDRINFO */

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have 'alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if <alloca.h> works. */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if printf supports C99 size specifiers */
#define HAVE_C99_FORMAT 1

/* Define to 1 if check library is available */
#cmakedefine HAVE_CHECK 1

/* Define to 1 if you have the `clock_getcpuclockid' function. */
#define HAVE_CLOCK_GETCPUCLOCKID 1

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have CLOCK_MONOTONIC */
#define HAVE_CLOCK_MONOTONIC 1

/* Defined when gcov is enabled to force by changing config.h */
/* #undef HAVE_COVERAGE */

/* Define to 1 if you have /dev/urandom. */
#define HAVE_DEV_URANDOM 1

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have epoll interface. */
#define HAVE_EPOLL 1

/* Define to 1 if you have the `epoll_create' function. */
#define HAVE_EPOLL_CREATE 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have WIN32 FILETIME type and GetSystemTimeAsFileTime().
   */
/* #undef HAVE_FILETIME */

/* Define to 1 if you have the `flock' function. */
#define HAVE_FLOCK 1

/* Define to 1 if you have the <fnmatch.h> header file. */
#define HAVE_FNMATCH_H 1

/* Define to 1 if you have the `freeaddrinfo' function. */
#define HAVE_FREEADDRINFO 1

/* Define this as 1 if your c library does not crash with free(0) */
#define HAVE_FREE_NULL 1

/* Define to 1 if the C compiler supports __func__ */
#define HAVE_FUNC 1

/* Define to 1 if the C compiler supports __FUNCTION__ */
#define HAVE_FUNCTION 1

/* Define to 1 if you have the `gai_strerror' function. */
#define HAVE_GAI_STRERROR 1

/* Define to 1 if you have the `getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `getdelim' function. */
#define HAVE_GETDELIM 1

/* Define to 1 if you have the `gethostbyname' function. */
#define HAVE_GETHOSTBYNAME 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getifaddrs' function. */
#define HAVE_GETIFADDRS 1

/* Define to 1 if you have the `getipnodebyname' function. */
/* #undef HAVE_GETIPNODEBYNAME */

/* Define to 1 if you have the `getline' function. */
#define HAVE_GETLINE 1

/* Define to 1 if you have the `getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define to 1 if you have the `getpass' function. */
#define HAVE_GETPASS 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <ifaddr.h> header file. */
/* #undef HAVE_IFADDR_H */

/* Define to 1 if you have SIOCGIFCONF */
#define HAVE_IFCONF 1

/* Define to 1 if you have SIOCGIFNUM ioctl */
/* #undef HAVE_IFNUM */

/* Define to 1 if you have ifr_ifindex in <net/if.h> */
#define HAVE_IFR_IFINDEX 1

/* Define to 1 if you have ifr_index in <net/if.h> */
/* #undef HAVE_IFR_INDEX */

/* Define to 1 if you have the `if_nameindex' function. */
#define HAVE_IF_NAMEINDEX 1

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the `initstate' function. */
#define HAVE_INITSTATE 1

/* Define to 1 if you have inlining compiler */
#define HAVE_INLINE 1

/* Define to 1 if you have WIN32 INTERFACE_INFO_EX type. */
/* #undef HAVE_INTERFACE_INFO_EX */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <iphlpapi.h> header file. */
/* #undef HAVE_IPHLPAPI_H */

/* Define to 1 if you have IPV6_RECVERR in <netinet/in6.h> */
#define HAVE_IPV6_RECVERR 1

/* Define to 1 if you have IP_ADD_MEMBERSHIP */
#define HAVE_IP_ADD_MEMBERSHIP 1

/* Define to 1 if you have IP_MTU_DISCOVER */
#define HAVE_IP_MTU_DISCOVER 1

/* Define to 1 if you have IP_MULTICAST_LOOP */
#define HAVE_IP_MULTICAST_LOOP 1

/* Define to 1 if you have IP_RECVERR in <netinet/in.h> */
#define HAVE_IP_RECVERR 1

/* Define to 1 if you have the `kqueue' function. */
/* #undef HAVE_KQUEUE */

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#define HAVE_LIBCRYPTO 1

/* Define to 1 if dl library is available */
#define HAVE_LIBDL 1

/* Define to 1 if you have the `gcov' library (-lgcov). */
/* #undef HAVE_LIBGCOV */

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `ssl' library (-lssl). */
#define HAVE_LIBSSL 1

/* Define to 1 if dnssd library is available */
/* #undef HAVE_MDNS */

/* Define to 1 if you have the `memccpy' function. */
#define HAVE_MEMCCPY 1

/* Define to 1 if you have the `memcspn' function. */
/* #undef HAVE_MEMCSPN */

/* Define to 1 for memory-leak-related logging */
/* #undef HAVE_MEMLEAK_LOG */

/* Define to 1 if you have the `memmem' function. */
#define HAVE_MEMMEM 1

/* Define to 1 if you have the `memspn' function. */
/* #undef HAVE_MEMSPN */

/* Define to 1 if you are compiling in MinGW environment */
/* #undef HAVE_MINGW */

/* Define to 1 if you have the <minix/config.h> header file. */
/* #undef HAVE_MINIX_CONFIG_H */

/* Define to 1 if you have MSG_TRUNC flag */
#define HAVE_MSG_TRUNC 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/sctp.h> header file. */
#define HAVE_NETINET_SCTP_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <netpacket/packet.h> header file. */
#define HAVE_NETPACKET_PACKET_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Define to 1 if you have the <net/if_types.h> header file. */
/* #undef HAVE_NET_IF_TYPES_H */

/* tcase_add_test() with allowed_exit_value argument */
/* #undef HAVE_NEW_TCASE_ADD_TEST */

/* Define to 1 if you have OpenSSL */
#define HAVE_OPENSSL 1

/* Define to 1 if you have the <openssl/crypto.h> header file. */
/* #undef HAVE_OPENSSL_CRYPTO_H */

/* Define to 1 if you have the <openssl/err.h> header file. */
/* #undef HAVE_OPENSSL_ERR_H */

/* Define to 1 if you have the <openssl/pem.h> header file. */
/* #undef HAVE_OPENSSL_PEM_H */

/* Define to 1 if you have the <openssl/ssl.h> header file. */
/* #undef HAVE_OPENSSL_SSL_H */

/* Define to 1 if you have the <openssl/tls1.h> header file. */
/* #undef HAVE_OPENSSL_TLS1_H */

/* Define to 1 if you have the <openssl/x509.h> header file. */
/* #undef HAVE_OPENSSL_X509_H */

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you use poll in su_port. */
#define HAVE_POLL_PORT 1

/* Define to 1 if you have /proc/net/if_inet6 control file */
#define HAVE_PROC_NET_IF_INET6 1

/* Define to 1 if you have working pthread_rwlock_t implementation. A thread
   may hold multiple concurrent read locks on rwlock - that is, successfully
   call the pthread_rwlock_rdlock() function n times. If so, the application
   shall ensure that the thread performs matching unlocks - that is, it calls
   the pthread_rwlock_unlock() function n times. */
#define HAVE_PTHREAD_RWLOCK 1

/* Define to 1 if you have the `random' function. */
#define HAVE_RANDOM 1

/* Define to 1 if you have sa_len in struct sockaddr */
/* #undef HAVE_SA_LEN */

/* Define to 1 if you have SCTP */
/* #undef HAVE_SCTP */

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have Sofia sigcomp >= 2.5 */
/* #undef HAVE_SIGCOMP */

/* Define to 1 if you have the <sigcomp.h> header file. */
/* #undef HAVE_SIGCOMP_H */

/* Define to 1 if you have the `signal' function. */
#define HAVE_SIGNAL 1

/* Define to 1 if you have SIGPIPE */
#define HAVE_SIGPIPE 1

/* Define to 1 if you have IPv6 structures and constants */
#define HAVE_SIN6 1

/* Define to 1 if you have WIN32 WSAIoctl SIO_ADDRESS_LIST_QUERY. */
/* #undef HAVE_SIO_ADDRESS_LIST_QUERY */

/* Define to 1 if you have the `socketpair' function. */
#define HAVE_SOCKETPAIR 1

/* Define to 1 if we use HTTP parser library */
#define HAVE_SOFIA_HTTP 1

/* Define to 1 if we use NTH library */
#define HAVE_SOFIA_NTH 1

/* Define to 1 if we use NTLM library */
/* #undef HAVE_SOFIA_NTLM */

/* Define to 1 if you have Sofia sigcomp >= 2.5 */
/* #undef HAVE_SOFIA_SIGCOMP */

/* Define to 1 always */
#define HAVE_SOFIA_SIP 1

/* Define to 1 if we use S/MIME library */
#define HAVE_SOFIA_SMIME 0

/* Define to 1 if we use DNS library */
#define HAVE_SOFIA_SRESOLV 1

/* Define to 1 if we use STUN library */
#define HAVE_SOFIA_STUN 1

/* Define to 1 if you have socket option SO_RCVBUFFORCE */
#define HAVE_SO_RCVBUFFORCE 1

/* Define to 1 if you have socket option SO_SNDBUFFORCE */
#define HAVE_SO_SNDBUFFORCE 1

/* Define to 1 if we use SRTP */
#define HAVE_SRTP 0

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* Define to 1 if you have the `strtoull' function. */
#define HAVE_STRTOULL 1

/* Define to 1 if your CC supports C99 struct initialization */
#define HAVE_STRUCT_KEYWORDS 1

/* Define to 1 if you have the <sys/devpoll.h> header file. */
/* #undef HAVE_SYS_DEVPOLL_H */

/* Define to 1 if you have the <sys/epoll.h> header file. */
#define HAVE_SYS_EPOLL_H 1

/* Define to 1 if you have the <sys/filio.h> header file. */
/* #undef HAVE_SYS_FILIO_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the `tcsetattr' function. */
#define HAVE_TCSETATTR 1

/* Define to 1 if you have TLS */
#define HAVE_TLS 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if we use UPnP */
#define HAVE_UPNP 0

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 you have WIN32 */
/* #undef HAVE_WIN32 */

/* Define to 1 if you have the <windef.h> header file. */
/* #undef HAVE_WINDEF_H */

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to 1 if you have the <ws2tcpip.h> header file. */
/* #undef HAVE_WS2TCPIP_H */

/* Format (%lli) for long long */
#define LLI "%lli"

/* Format (%llu) for unsigned long long */
#define LLU "%llu"

/* Format (%llx) for long long hex */
#define LLX "%llx"

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define printf() modifier for ssize_t */
#define MOD_ZD "%zd"

/* Define printf() modifier for size_t */
#define MOD_ZU "%zu"

/* Name of package */
#define PACKAGE "${PROJECT_NAME}"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "${PROJECT_NAME}"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "${PROJECT_NAME} ${PROJECT_VERSION}"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "${PROJECT_NAME}"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "${PROJECT_VERSION}"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. This
   macro is obsolete. */
#define TIME_WITH_SYS_TIME 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable general extensions on macOS.  */
#ifndef _DARWIN_C_SOURCE
# define _DARWIN_C_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable X/Open compliant socket functions that do not require linking
   with -lxnet on HP-UX 11.11.  */
#ifndef _HPUX_ALT_XOPEN_SOCKET_API
# define _HPUX_ALT_XOPEN_SOCKET_API 1
#endif
/* Identify the host operating system as Minix.
   This macro does not affect the system headers' behavior.
   A future release of Autoconf may stop defining this macro.  */
#ifndef _MINIX
/* # undef _MINIX */
#endif
/* Enable general extensions on NetBSD.
   Enable NetBSD compatibility extensions on Minix.  */
#ifndef _NETBSD_SOURCE
# define _NETBSD_SOURCE 1
#endif
/* Enable OpenBSD compatibility extensions on NetBSD.
   Oddly enough, this does nothing on OpenBSD.  */
#ifndef _OPENBSD_SOURCE
# define _OPENBSD_SOURCE 1
#endif
/* Define to 1 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_SOURCE
/* # undef _POSIX_SOURCE */
#endif
/* Define to 2 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_1_SOURCE
/* # undef _POSIX_1_SOURCE */
#endif
/* Enable POSIX-compatible threading on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
# define __STDC_WANT_IEC_60559_ATTRIBS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
# define __STDC_WANT_IEC_60559_BFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
# define __STDC_WANT_IEC_60559_DFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
# define __STDC_WANT_IEC_60559_FUNCS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-3:2015.  */
#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
# define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
#ifndef __STDC_WANT_LIB_EXT2__
# define __STDC_WANT_LIB_EXT2__ 1
#endif
/* Enable extensions specified by ISO/IEC 24747:2009.  */
#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
# define __STDC_WANT_MATH_SPEC_FUNCS__ 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable X/Open extensions.  Define to 500 only if necessary
   to make mbstate_t available.  */
#ifndef _XOPEN_SOURCE
/* # undef _XOPEN_SOURCE */
#endif


/* Version number of package */
#define VERSION "${PROJECT_VERSION}"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to a at least 64-bit int type */
#define longlong long long

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

#endif /* CONFIG_H */
