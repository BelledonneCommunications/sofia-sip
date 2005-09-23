/**@file win-config.h
 * @brief <config.h> used by Windows.
 *
 * Copy this as config.h if you are running WIN32 (or run autoconf-all.cmd). 
 *
 * Copyright (c) 2000, 2002 Nokia Research Center.  All rights reserved.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @license
 *
 * The contents of this file are subject to the NOKOS License Version 1.0
 * (the "License"); you may not use this file except in compliance with the
 * License.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations under
 * the License.
 *
 * The Original Software is Sofia IPv6 Multimedia Communications Suite.
 *
 * Copyright (c) 2000 Nokia and others. All Rights Reserved.
 *
 * @par Contributor(s):
 *
 * @date Created: Tue Sep 12 19:22:54 2000 ppessi
 * $Id: config.h,v 1.1 2005/09/23 14:43:46 ppessi Exp $
 */

/* Define this as 1 if you have AAC */
#define HAVE_AAC 1

/* Define to 1 if you have the <ac.h> header file. */
#define HAVE_AC_H 1

/* Define to 1 if you have the <ad.h> header file. */
#define HAVE_AD_H 1

/* Define this a 1 if you have ALSA 1 library (in ALSA release 0.5) */
#undef HAVE_ALSA

/* Define this a 1 if you have ALSA library (alsa-lib-0.9.1 or newer) */
#undef HAVE_ALSA2

/* Define this as 1 if AMR codec is in use */
#define HAVE_AMR 1

/* Define this as 1 if fixed-point AMR codec is used */
#define HAVE_AMRFIX 1

/* Define this as 1 if AMR generic parts are used */
#define HAVE_AMRGEN 1

/* Define this as 1 if AMR wideband codec is used */
#define HAVE_AMRWB 1

/* Define to 1 if you have the <auth_digest.h> header file. */
#define HAVE_AUTH_DIGEST_H 1

/* Define to 1 if you have the <base64.h> header file. */
#define HAVE_BASE64_H 1

/* Define to 1 if you have the <bnf.h> header file. */
#define HAVE_BNF_H 1

/* Define to 1 if you have the `clock_getcpuclockid' function. */
#undef HAVE_CLOCK_GETCPUCLOCKID

/* Define to 1 if you have the `clock_gettime' function. */
#undef HAVE_CLOCK_GETTIME

/* Define to 1 if you have the <comedia.h> header file. */
#define HAVE_COMEDIA_H 1

/* Define this a 1 if you use EAP. */
#undef HAVE_EAP

/* Define this as 1 if GSM-EFR codec is in use */
#define HAVE_EFR 1

/* Define to 1 if you have the `flock' function. */
#undef HAVE_FLOCK

/* Define as 1 if the C compiler supports __func__ */
#undef HAVE_FUNC 

/* Define as 1 if the C compiler supports __FUNCTION__ */
#undef HAVE_FUNCTION 

/* Define this as 1 if G.723.1 codec is in use */
#define HAVE_G7231 1

/* Define to 1 if you have the `getaddrinfo' function. */
#undef HAVE_GETADDRINFO

/* Define to 1 if you have the `getdelim' function. */
#undef HAVE_GETDELIM

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getipnodebyname' function. */
#undef HAVE_GETIPNODEBYNAME

/* Define to 1 if you have the `getline' function. */
#undef HAVE_GETLINE

/* Define to 1 if you have the `getpass' function. */
#undef HAVE_GETPASS

/* Define to 1 if you have the `gettimeofday' function. */
#undef HAVE_GETTIMEOFDAY

/* Define this as 1 if you have glib library */
#undef HAVE_GLIB

/* Define to 1 if you have the <hss.h> header file. */
#undef HAVE_HSS_H

/* Define to 1 if you have the <http.h> header file. */
#define HAVE_HTTP_H 1

/* Define this as 1 if you have SIOCGIFNUM ioctl */
#undef HAVE_IFNUM

/* Define this as 1 if you have ifr_index in <net/if.h> */
#undef HAVE_IFR_INDEX

/* Define to 1 if you have the `initstate' function. */
#undef HAVE_INITSTATE

/* Define this as 1 if you have inlining compiler */
#define HAVE_INLINE 1

/* Define to 1 if you have the <inttypes.h> header file. */
#undef HAVE_INTTYPES_H

/* Define as 1 you have <iphlpapi.h> */
#undef HAVE_IPHLPAPI_H

/* Define this as 1 if you have IPV6_RECVERR in <netinet/in6.h> */
#undef HAVE_IPV6_RECVERR

/* Define this as 1 if you have IP_RECVERR in <netinet/in.h> */
#undef HAVE_IP_RECVERR

/* Define this a 1 if you use JACK. */
#undef HAVE_JACK

/* Define to 1 if you have the <jpip.h> header file. */
#undef HAVE_JPIP_H

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#undef HAVE_LIBCRYPTO

/* Define to 1 if you have the `c++asn1' library (-lc++asn1). */
#undef HAVE_LIBC__ASN1

/* Define to 1 if you have the `pthread' library (-lpthread). */
#undef HAVE_LIBPTHREAD

/* Define this as 1 if you have sigcomp libs */
#undef HAVE_LIBSIGCOMP

/* Define to 1 if you have the `ssl' library (-lssl). */
#undef HAVE_LIBSSL

/* Define this a 1 if you want ad_loopback to be used */
#define HAVE_LOOPBACK 1

/* Define to 1 if you have the `memmem' function. */
#undef HAVE_MEMMEM

/* Define to 1 if you have the <memory.h> header file. */
#undef HAVE_MEMORY_H

/* Define this as 1 if you want to have MIKEY enabled */
#undef HAVE_MIKEY

/* Define to 1 if you have the <mma.h> header file. */
#define HAVE_MMA_H 1

/* Define this as 1 if MP4A-LATM codec is in use */
#define HAVE_MP4A_LATM 1

/* Define to 1 if you have the <msg.h> header file. */
#define HAVE_MSG_H 1

/* Define this as 1 if you have MSG_NOSIGNAL flag for send() */
#undef HAVE_MSG_NOSIGNAL

/* Define this as 1 if you have mss includes */
#undef HAVE_MSS

/* Define to 1 if you have the <mss.h> header file. */
#define HAVE_MSS_H 1

/* Define to 1 if you have the <nea.h> header file. */
#define HAVE_NEA_H 1

/* Define to 1 if you have the <netinet/sctp.h> header file. */
#undef HAVE_NETINET_SCTP_H

/* Define to 1 if you have the <net/if.h> header file. */
#undef HAVE_NET_IF_H

/* Define to 1 if you have the <nta.h> header file. */
#define HAVE_NTA_H 1

/* Define to 1 if you have the <nth.h> header file. */
#define HAVE_NTH_H 1

/* Define to 1 if you have the <ntr.h> header file. */
#define HAVE_NTR_H 1

/* Define this as 1 if you have OpenSSL */
#undef HAVE_OPENSSL

/* Define to 1 if you have the <openssl/tls1.h> header file. */
#undef HAVE_OPENSSL_TLS1_H

/* Define this as a 1 if you have Linux OSS includes. */
#undef HAVE_OSS

/* Define this as 1 if you want to have POC features enabled */
#undef HAVE_POC

/* Define to 1 if you have the `poll' function. */
#undef HAVE_POLL

/* Define this as 1 if you have /proc/net/if_inet6 control file */
#undef HAVE_PROC_NET_IF_INET6

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define this as 1 if you have PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP */
#undef HAVE_PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP

/* Define this as 1 if you have pvt includes */
#define HAVE_PVT 0

/* Define to 1 if you have the `random' function. */
#define HAVE_RANDOM 1

/* Define this as 1 if you want to have RTCP enabled */
#define HAVE_RTCP 1

/* Define to 1 if you have the <rtp_frame.h> header file. */
#define HAVE_RTP_FRAME_H 1

/* Define to 1 if you have the <rtsp.h> header file. */
#define HAVE_RTSP_H 1

/* Define this as 1 if you have sa_len in struct sockaddr */
#undef HAVE_SA_LEN

/* Define this a 1 if you have SCTP */
#undef HAVE_SCTP

/* Define this as 1 if you want to have bsf features enabled */
#undef HAVE_SC_CRED_H

/* Define to 1 if you have the <sdp.h> header file. */
#define HAVE_SDP_H 1

/* Define this as 1 if you have sigcomp */
#undef HAVE_SIGCOMP

/* Define to 1 if you have the <sigcomp.h> header file. */
#undef HAVE_SIGCOMP_H

/* Define this as 1 if you have IPv6 structures and constants */
#define HAVE_SIN6 defined(IPPROTO_IPv6)

/* Define to 1 if you have the <sip.h> header file. */
#define HAVE_SIP_H 1

/* Define this as 1 if you have S/MIME module */
#undef HAVE_SMIME

/* Define to 1 if you have the <smime.h> header file. */
#undef HAVE_SMIME_H

/* Define to 1 if you have the `socketpair' function. */
#undef HAVE_SOCKETPAIR

/* Define this as 1 if you have ac headers */
#define HAVE_SOFIA_AC 1

/* Define this as 1 if you have ad includes */
#define HAVE_SOFIA_AD 1

/* Define this as 1 if you have bnf includes */
#define HAVE_SOFIA_BNF 1

/* Define this as 1 if you have comedia includes */
#define HAVE_SOFIA_COMEDIA 1

/* Define this as 1 if you have hss includes */
#undef HAVE_SOFIA_HSS

/* Define this as 1 if you have http includes */
#define HAVE_SOFIA_HTTP 1

/* Define this as 1 if you have ipt includes */
#define HAVE_SOFIA_IPT 1

/* Define this as 1 if you have iptsec includes */
#define HAVE_SOFIA_IPTSEC 1

/* Define this as 1 if you have JPIP includes */
#undef HAVE_SOFIA_JPIP

/* Define this as 1 if you have mma includes */
#undef HAVE_SOFIA_MMA

/* Define this as 1 if you have msg includes */
#define HAVE_SOFIA_MSG 1

/* Define this as 1 if you have mss includes */
#undef HAVE_SOFIA_MSS

/* Define this as 1 if you have nea includes */
#define HAVE_SOFIA_NEA 1

/* Define this as 1 if you have nta includes */
#define HAVE_SOFIA_NTA 1

/* Define this as 1 if you have nth includes */
#define HAVE_SOFIA_NTH 1

/* Define this as 1 if you have ntr includes */
#undef HAVE_SOFIA_NTR

/* Define this as 1 if you have pvt includes */
#undef HAVE_SOFIA_PVT

/* Define this as 1 if you have rtp headers */
#undef HAVE_SOFIA_RTP

/* Define this as 1 if you have rtsp includes */
#undef HAVE_SOFIA_RTSP

/* Define this as 1 if you have sdp headers */
#define HAVE_SOFIA_SDP 1

/* Define this as 1 if you have sip includes */
#define HAVE_SOFIA_SIP 1

/* Define this as 1 if you have sresolv */
#define HAVE_SOFIA_SRESOLV 1

/* Define this as 1 if you have stun */
#undef HAVE_SOFIA_STUN

/* Define this as 1 if you have su headers */
#define HAVE_SOFIA_SU 1

/* Define this as 1 if you have tport includes */
#define HAVE_SOFIA_TPORT 1

/* Define this as 1 if you have uicc includes */
#undef HAVE_SOFIA_UICC

/* Define this as 1 if you have upnp_wrapper includes */
#undef HAVE_SOFIA_UPNP_WRAPPER

/* Define this as 1 if you have url includes */
#define HAVE_SOFIA_URL 1

/* Define to 1 if you have the <sresolv.h> header file. */
#undef HAVE_SRESOLV_H

/* Define this as 1 if you want to have SRTP enabled */
#undef HAVE_SRTP

/* Define to 1 if you have the <stdint.h> header file. */
#undef HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasestr' function. */
#undef HAVE_STRCASESTR

/* Define to 1 if you have the <streaming/ext_include/streaming.h> header
   file. */
#undef HAVE_STREAMING_EXT_INCLUDE_STREAMING_H

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define this as 1 if your CC supports C99 struct initialization */
#undef HAVE_STRUCT_KEYWORDS

/* Define to 1 if you have the <stun.h> header file. */
#undef HAVE_STUN_H

/* Define to 1 if you have the <su_alloc_stat.h> header file. */
#define HAVE_SU_ALLOC_STAT_H 1

/* Define to 1 if you have the <su_config.h> header file. */
#define HAVE_SU_CONFIG_H 1

/* Define to 1 if you have the <su_debug.h> header file. */
#define HAVE_SU_DEBUG_H 1

/* Define to 1 if you have the <su.h> header file. */
#define HAVE_SU_H 1

/* Define to 1 if you have the <su_wait.h> header file. */
#define HAVE_SU_WAIT_H 1

/* Define to 1 if you have the <sys/filio.h> header file. */
#undef HAVE_SYS_FILIO_H

/* Define to 1 if you have the <sys/socket.h> header file. */
#undef HAVE_SYS_SOCKET_H

/* Define to 1 if you have the <sys/sockio.h> header file. */
#undef HAVE_SYS_SOCKIO_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#undef HAVE_SYS_TIME_H

/* Define to 1 if you have the <sys/types.h> header file. */
#undef HAVE_SYS_TYPES_H

/* Define to 1 if you have the `tcsetattr' function. */
#undef HAVE_TCSETATTR

/* Define to 1 if you have the <termios.h> header file. */
#undef HAVE_TERMIOS_H

/* Define this as 1 if you have TLS */
#undef HAVE_TLS

/* Define to 1 if you have the <tport.h> header file. */
#define HAVE_TPORT_H 1

/* Define this as 1 if you want mss transcoding support */
#undef HAVE_TRANSCODING

/* Define to 1 if you have the <uicc.h> header file. */
#undef HAVE_UICC_H

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Define this as 1 if you have UPNP enabled */
#undef HAVE_UPNP

/* Define to 1 if you have the <upnp_wrapper.h> header file. */
#undef HAVE_UPNP_WRAPPER_H

/* Define to 1 if you have the <url.h> header file. */
#define HAVE_URL_H 1

/* Define this a 1 if you have Ogg Vorbis. */
#define HAVE_VORBIS 1

/* Define this as default library path */
#define IPTEL_LIB_DIR "C:\\iptel\\lib\\"
#define LIBDIR "C:\\iptel\\lib\\"

/* Name of package */
#define PACKAGE "sofia"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "sofia-devel@isource.nokia.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "sofia"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "sofia win32"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME

/* Define to the version of this package. */
#define PACKAGE_VERSION "win32"

/* Define this as 1 if your host is big endian */
#undef RTP_BIG_ENDIAN

/* Define this as 1 if your host is little endian */
#define RTP_LITTLE_ENDIAN  1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#undef TIME_WITH_SYS_TIME

/* Version number of package */
#define VERSION "1.9.16"

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
#undef WORDS_BIGENDIAN

/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

/* Define to empty if `const' does not conform to ANSI C. */
#undef const

/* Define as `__inline' if that's what the C compiler calls it, or to nothing
   if it is not supported. */
#define inline  __inline

/* Define to `unsigned' if <sys/types.h> does not define. */
#undef size_t

#define HOSTTYPE "pc-xp-win32"
/* #define HOSTTYPE "pc-98-win32" */
/* #define HOSTTYPE "pc-nt-win32" */

/* Define this as locale-independent strcmp().  */
#define strcasecmp  _stricmp

/* Define this as locale-independent strncmp().  */
#define strncasecmp _strnicmp

#define snprintf _snprintf
#define vsnprintf _vsnprintf

#define srandom(x)    srand((x))
#define random()      rand()

/* This is GCC magic  */
#define __attribute__(x)

/* Define this as 1 if you have TimeGetTime() */
#define HAVE_TIMEGETTIME     1

#define PATH_MAX _MAX_PATH

#define HAVE_WINMM 1

/* Define this as 1 if you have FILETIME */
#define HAVE_FILETIME 1

/* Define this as 1 if you have WinSock2 ioctl SIO_ADDRESS_LIST_QUERY */
#define HAVE_SIO_ADDRESS_LIST_QUERY 1

// XXX: vehmanek-win32-fix:
/* Define this as 1 if you have WinSock IPHLPAPI */
#define HAVE_IPHLPAPI_H 0

/* Define this as 1 if you have INTERFACE_INFO ioctl */
#define HAVE_INTERFACE_INFO 	   (1) 

#define HAVE_WIN32 (1)

#define longlong __int64

#ifdef LIBSOFIA_SIP_UA_EXPORTS
#define NUA_EXPORTS 1
#define NEA_EXPORTS 1
#define SRESOLV_EXPORTS
#define NTH_EXPORTS 1
#define HTTP_EXPORTS 1
#define IPTSEC_EXPORTS 1
#define SDP_EXPORTS 1
#define NTA_EXPORTS 1
#define TPORT_EXPORTS 1
#define SIP_EXPORTS 1
#define MSG_EXPORTS 1
#define URL_EXPORTS 1
#define BNF_EXPORTS 1
#define SU_EXPORTS 1
#endif

/* Ignore certain warnings */
#ifdef _MSC_VER
#pragma warning( disable : 4204 4244 4018 4514 4706 4761)
#endif


