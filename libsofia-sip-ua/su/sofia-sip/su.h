/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#ifndef SU_H
/** Defined when <sofia-sip/su.h> has been included. */
#define SU_H
/**@ingroup su_socket 
 * @file sofia-sip/su.h Socket and network address interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Mar 18 19:40:51 1999 pessi
 */

/* ---------------------------------------------------------------------- */
/* Includes */

#ifndef SU_CONFIG_H
#include "sofia-sip/su_config.h"
#endif
#ifndef SU_TYPES_H
#include "sofia-sip/su_types.h"
#endif
#ifndef SU_ERRNO_H
#include <sofia-sip/su_errno.h>
#endif

#include <stdio.h>

SOFIA_BEGIN_DECLS

#if SU_HAVE_BSDSOCK		/* Unix-compatible includes */
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#if SU_HAVE_WINSOCK		/* Windows includes */
#  include <winsock2.h>
#  include <ws2tcpip.h>

static __inline
uint16_t su_ntohs(uint16_t s)
{
  return (uint16_t)(((s & 255) << 8) | ((s & 0xff00) >> 8));
}

static __inline
uint32_t su_ntohl(uint32_t l)
{
  return ((l & 0xff) << 24) | ((l & 0xff00) << 8)
       | ((l & 0xff0000) >> 8) | ((l & 0xff000000U) >> 24);
}

#define ntohs su_ntohs
#define htons su_ntohs
#define ntohl su_ntohl
#define htonl su_ntohl

#  if defined(IPPROTO_IPV6)
/* IPv6 defined in ws2tcpip.h */
#  elif SU_HAVE_IN6 
#    include <tpipv6.h>		/* From "IPv6 Tech Preview"  */
#  else
#    error Winsock with IPv6 support required
#  endif

#include <limits.h>

#endif

/* ---------------------------------------------------------------------- */
/* Constant definitions */

#if SU_HAVE_BSDSOCK || DOCUMENTATION_ONLY
enum {
  /** Invalid socket descriptor */ 
  INVALID_SOCKET = -1,
  /** Error from su_socket() call */
  SOCKET_ERROR = -1,

  /** Return code for a successful call */
  su_success = 0, 
  /** Return code for an unsuccessful call */
  su_failure = -1
};
#elif SU_HAVE_WINSOCK
enum { 
  su_success = 0, 
  su_failure = 0xffffffffUL 
};

#define MSG_NOSIGNAL (0)

#endif

/**@HI Maximum size of host name. */
#define SU_MAXHOST (1025)
/**@HI Maximum size of service name. */
#define SU_MAXSERV (25)

/**@HI Maximum size of address in text format. */
#define SU_ADDRSIZE (48)
/**@HI Maximum size of port number in text format. */
#define SU_SERVSIZE (16)

#define SU_SUCCESS su_success
#define SU_FAILURE su_failure

/* ---------------------------------------------------------------------- */
/* Type definitions */

/** Socket descriptor type. */
#if SU_HAVE_BSDSOCK || DOCUMENTATION_ONLY
typedef int su_socket_t;
#elif SU_HAVE_WINSOCK
typedef SOCKET su_socket_t;
#endif

#if !SU_HAVE_SOCKADDR_STORAGE
/*
 * RFC 2553: protocol-independent placeholder for socket addresses
 */
#define _SS_MAXSIZE	128
#define _SS_ALIGNSIZE	(sizeof(int64_t))
#define _SS_PAD1SIZE	(_SS_ALIGNSIZE - sizeof(u_char) * 2)
#define _SS_PAD2SIZE	(_SS_MAXSIZE - sizeof(u_char) * 2 - \
				_SS_PAD1SIZE - _SS_ALIGNSIZE)

struct sockaddr_storage {
#if SU_HAVE_SOCKADDR_SA_LEN
	unsigned char ss_len;		/* address length */
	unsigned char ss_family;	/* address family */
#else
	unsigned short ss_family;	/* address family */
#endif
	char	__ss_pad1[_SS_PAD1SIZE];
	int64_t __ss_align;	/* force desired structure storage alignment */
	char	__ss_pad2[_SS_PAD2SIZE];
};
#endif

/** Common socket address structure. */
union su_sockaddr_u {
#ifdef DOCUMENTATION_ONLY
  uint8_t             su_len;         /**< Length of structure */
  uint8_t             su_family;      /**< Address family. */
  uint16_t            su_port;        /**< Port number. */
#else
  short               su_dummy;	      /**< Dummy member to initialize */
#if SU_HAVE_SOCKADDR_SA_LEN
#define               su_len          su_sa.sa_len
#define               su_family       su_sa.sa_family
#else
#define               su_len          su_array[0]
  short               su_family;
#endif
#define               su_port         su_sin.sin_port  
#endif

  char                su_array[32];   /**< Presented as chars */
  uint16_t            su_array16[16]; /**< Presented as 16-bit ints */
  uint32_t            su_array32[8];  /**< Presented as 32-bit ints */
  struct sockaddr     su_sa;          /**< Address in struct sockaddr format */
  struct sockaddr_in  su_sin;         /**< Address in IPv4 format */
#if SU_HAVE_IN6
  struct sockaddr_in6 su_sin6;        /**< Address in IPv6 format */
#endif
#ifdef DOCUMENTATION_ONLY
  uint32_t            su_scope_id;    /**< Scope ID. */
#else
#define               su_scope_id     su_array32[6]
#endif
};

typedef union su_sockaddr_u su_sockaddr_t;

#if SU_HAVE_BSDSOCK || DOCUMENTATION_ONLY
/** IO vector for su_vsend() and su_vrecv(). 
 * @note Ordering of the fields is reversed on Windows.
 */
struct su_iovec_s {
  void  *siv_base;		/**< Pointer to buffer. */
  size_t siv_len;		/**< Size of buffer.  */
};
#endif

#if SU_HAVE_WINSOCK
struct su_iovec_s {
  long  siv_len;
  void *siv_base;
};
#endif

/** I/O vector for scatter-gather I/O. */
typedef struct su_iovec_s   su_iovec_t;

/* ---------------------------------------------------------------------- */
/* Socket compatibility functions */

SOFIAPUBFUN int su_init(void);
SOFIAPUBFUN void su_deinit(void);

/** Create an endpoint for communication. */
SOFIAPUBFUN su_socket_t su_socket(int af, int sock, int proto);
/** Close an socket descriptor. */
SOFIAPUBFUN int su_close(su_socket_t s);
/** Control socket. */
SOFIAPUBFUN int su_ioctl(su_socket_t s, int request, ...);

/** Checks if the previous call failed because it would have blocked. */
SOFIAPUBFUN int su_isblocking(void);
/** Set/reset blocking option. */ 
SOFIAPUBFUN int su_setblocking(su_socket_t s, int blocking);
/** Set/reset address reusing option. */
SOFIAPUBFUN int su_setreuseaddr(su_socket_t s, int reuse);
/** Get the error code associated with the socket. */
SOFIAPUBFUN int su_soerror(su_socket_t s);
/** Get size of message available in socket. */
SOFIAPUBFUN int su_getmsgsize(su_socket_t s);

/** Scatter-gather send. */
SOFIAPUBFUN
int su_vsend(su_socket_t s, su_iovec_t const iov[], int iovlen, int flags, 
             su_sockaddr_t const *su, socklen_t sulen);
/** Scatter-gather receive. */
SOFIAPUBFUN
int su_vrecv(su_socket_t s, su_iovec_t iov[], int iovlen, int flags, 
             su_sockaddr_t *su, socklen_t *sulen);
/** Return local IP address */
SOFIAPUBFUN int su_getlocalip(su_sockaddr_t *sin);

#include <sofia-sip/su_addrinfo.h>

#if SU_HAVE_BSDSOCK
#define su_ioctl  ioctl
#define su_isblocking() (su_errno() == EAGAIN || su_errno() == EWOULDBLOCK)
#endif

#if SU_HAVE_WINSOCK
SOFIAPUBFUN int inet_pton(int af, char const *src, void *dst);
SOFIAPUBFUN const char *inet_ntop(int af, void const *src,
				  char *dst, size_t size);
#endif

/* ---------------------------------------------------------------------- */
/* Other compatibility stuff */

#if SU_HAVE_WINSOCK
#define getuid() (0x505)
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP (132)
#endif

/* ---------------------------------------------------------------------- */
/* Address manipulation macros */

/**@HI Get pointer to address field.
 *
 * The macro SU_ADDR() returns pointer to the address field (sin_data,
 * sin_addr or sin_addr6, depending on the address family).
 */
#if SU_HAVE_IN6
#define SU_ADDR(su) \
  ((su)->su_family == AF_INET ? (void *)&(su)->su_sin.sin_addr : \
  ((su)->su_family == AF_INET6 ? (void *)&(su)->su_sin6.sin6_addr : \
  (void *)&(su)->su_sa.sa_data))
#else
#define SU_ADDR(su) \
  ((su)->su_family == AF_INET ? (void *)&(su)->su_sin.sin_addr : \
  (void *)&(su)->su_sa.sa_data)
#endif

/**@HI Get length of address field.
 *
 * The macro SU_ADDRLEN() returns length of the address field (sin_data,
 * sin_addr or sin_addr6, depending on the address family).
 */
#if SU_HAVE_IN6
#define SU_ADDRLEN(su) \
  ((su)->su_family == AF_INET ? sizeof((su)->su_sin.sin_addr) :	    \
   ((su)->su_family == AF_INET6 ? sizeof((su)->su_sin6.sin6_addr) : \
    sizeof((su)->su_sa.sa_data)))
#else
#define SU_ADDRLEN(su) \
  ((su)->su_family == AF_INET ? sizeof((su)->su_sin.sin_addr) :	    \
   sizeof((su)->su_sa.sa_data))
#endif

/**@HI Test if su_sockaddr_t is INADDR_ANY or IN6ADDR_ANY. */
#if SU_HAVE_IN6
#define SU_HAS_INADDR_ANY(su) \
  ((su)->su_family == AF_INET \
   ? ((su)->su_sin.sin_addr.s_addr == INADDR_ANY) \
   : ((su)->su_family == AF_INET6 \
      ? (memcmp(&(su)->su_sin6.sin6_addr, su_in6addr_any(), \
		sizeof(*su_in6addr_any())) == 0) : 0))
#else
#define SU_HAS_INADDR_ANY(su) \
  ((su)->su_family == AF_INET \
  ? ((su)->su_sin.sin_addr.s_addr == INADDR_ANY) : 0)
#endif

#define SU_SOCKADDR_INADDR_ANY(su) SU_HAS_INADDR_ANY(su)

/**@HI Calculate correct size of su_sockaddr_t structure. */ 
#if SU_HAVE_IN6
#define SU_SOCKADDR_SIZE(su) \
  ((su)->su_family == AF_INET ? sizeof((su)->su_sin) \
   : ((su)->su_family == AF_INET6 ? sizeof((su)->su_sin6) \
      : sizeof(*su)))
#else
#define SU_SOCKADDR_SIZE(su) \
  ((su)->su_family == AF_INET ? sizeof((su)->su_sin) \
    : sizeof(*su))
#endif
#define su_sockaddr_size SU_SOCKADDR_SIZE

#if SU_HAVE_IN6
#if SU_HAVE_BSDSOCK
#define su_in6addr_any()         (&in6addr_any)
#define su_in6addr_loopback()    (&in6addr_loopback)
#define SU_IN6ADDR_ANY_INIT      IN6ADDR_ANY_INIT
#define SU_IN6ADDR_LOOPBACK_INIT IN6ADDR_LOOPBACK_INIT
#endif
#if SU_HAVE_WINSOCK || DOCUMENTATION_ONLY
SOFIAPUBVAR const struct in_addr6 *su_in6addr_any(void);
SOFIAPUBVAR const struct in_addr6 *su_in6addr_loopback(void);
#define SU_IN6ADDR_ANY_INIT      { 0 }
#define SU_IN6ADDR_LOOPBACK_INIT { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 }
#endif
#endif /* SU_HAVE_IN6 */

SOFIAPUBFUN int su_cmp_sockaddr(su_sockaddr_t const *a,
				su_sockaddr_t const *b);
SOFIAPUBFUN int su_match_sockaddr(su_sockaddr_t const *a,
				  su_sockaddr_t const *b);
SOFIAPUBFUN void su_canonize_sockaddr(su_sockaddr_t *su);

#if SU_HAVE_IN6
#define SU_CANONIZE_SOCKADDR(su) \
  ((su)->su_family == AF_INET6 ? su_canonize_sockaddr(su) : (void)0)
#else
#define SU_CANONIZE_SOCKADDR(su) \
  ((void)0)
#endif

SOFIA_END_DECLS

#endif /* !defined(SU_H) */
