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

/**@ingroup su_socket
 * @CFILE su.c OS-independent socket functions
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Mar 18 19:40:51 1999 pessi
 */

#include "config.h" 

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "su.h"
#include "su_log.h"
#include "su_alloc.h"

#if !SU_HAVE_BSDSOCK && !SU_HAVE_WINSOCK
#error Bad configuration
#endif

#if SU_HAVE_BSDSOCK
int su_init(void)
{
  su_home_threadsafe(NULL);

  signal(SIGPIPE, SIG_IGN);	/* we want to get EPIPE instead */

  su_log_init(su_log_default);
  su_log_init(su_log_global);

  return 0;
}

void su_deinit(void)
{
}

int su_setblocking(int s, int blocking)
{
  unsigned mode = fcntl(s, F_GETFL, 0);

  if (mode < 0)
     return -1;

  if (blocking) 
    mode &= ~(O_NDELAY | O_NONBLOCK);
  else
    mode |= O_NDELAY | O_NONBLOCK;

  return fcntl(s, F_SETFL, mode);
}
#endif

#if SU_HAVE_WINSOCK
int su_init(void)
{
  WORD	wVersionRequested;
  WSADATA	wsaData;

  wVersionRequested = MAKEWORD(2, 0);

  if (WSAStartup(wVersionRequested, &wsaData) !=0) {
    return -1;
  }

  su_log_init(su_log_default);

  su_log_init(su_log_global);

  return 0;
}

void su_deinit(void)
{
  WSACleanup();
}

/** Create an endpoint for communication. */
su_socket_t su_socket(int af, int sock, int proto)
{
  return socket(af, sock, proto);
}

/** Close an socket descriptor. */
int su_close(su_socket_t s)
{
  return closesocket(s);
}

/** Control socket. */
int su_ioctl(su_socket_t s, int request, ...)
{
  int retval;
  void *argp;
  va_list va;
  va_start(va, request);
  argp = va_arg(va, void *);
  retval = ioctlsocket(s, request, argp);
  va_end(va);
  return retval;
}

int su_setblocking(su_socket_t s, int blocking)
{
  unsigned long nonBlock = !blocking;
  
  return ioctlsocket(s, FIONBIO, &nonBlock);
}

/** Get the latest socket error. */
int su_errno(void)
{
  return WSAGetLastError();
}

/** Set the socket error. */
int su_seterrno(int errcode)
{
  WSASetLastError(errcode);

  return -1;
}

const char *su_strerror(int errcode)
{
  static struct { int no; const char *msg; } *msgp, msgs[] = {
    { 0, "Success" },
    { WSAEINTR, "Interrupted system call" },
    { WSAEBADF, "Bad file descriptor" },
    { WSAEACCES, "Permission denied" },
    { WSAEFAULT, "Bad address" },
    { WSAEINVAL, "Invalid argument" },
    { WSAEMFILE, "Too many open files" },
    { WSAEWOULDBLOCK, "Another winsock call while a "
      "blocking function was in progress" },
    { WSAEINPROGRESS, "Operation now in progress" },
    { WSAEALREADY, "Operation already in progress" },
    { WSAENOTSOCK, "Socket operation on non-socket" },
    { WSAEDESTADDRREQ, "Destination address required" },
    { WSAEMSGSIZE, "Message too long" },
    { WSAEPROTOTYPE, "Protocol wrong type for socket" },
    { WSAENOPROTOOPT, "Protocol not available" },
    { WSAEPROTONOSUPPORT, "Protocol not supported" },
    { WSAESOCKTNOSUPPORT, "Socket type not supported" },
    { WSAEOPNOTSUPP, "Operation not supported" },
    { WSAEPFNOSUPPORT, "Protocol family not supported" },
    { WSAEAFNOSUPPORT, "Address family not supported" },
    { WSAEADDRINUSE, "Address already in use" },
    { WSAEADDRNOTAVAIL, "Can't assign requested address" },
    { WSAENETDOWN, "Network is down" },
    { WSAENETUNREACH, "Network is unreachable" },
    { WSAENETRESET, "Network dropped connection on reset" },
    { WSAECONNABORTED, "Software caused connection abort" },
    { WSAECONNRESET, "Connection reset by peer" },
    { WSAENOBUFS, "No buffer space available" },
    { WSAEISCONN, "Socket is already connected" },
    { WSAENOTCONN, "Socket is not connected" },
    { WSAESHUTDOWN, "Can't send after socket shutdown" },
    { WSAETOOMANYREFS, "Too many references: "
      "can't splice" },
    { WSAETIMEDOUT, "Operation timed out" },
    { WSAECONNREFUSED, "Connection refused" },
    { WSAELOOP, "Too many levels of symbolic links" },
    { WSAENAMETOOLONG, "File name too long" },
    { WSAEHOSTDOWN, "Host is down" },
    { WSAEHOSTUNREACH, "No route to host" },
    { WSAENOTEMPTY, "Directory not empty" },
    { WSAEPROCLIM, "Too many processes" },
    { WSAEUSERS, "Too many users" },
    { WSAEDQUOT, "Disc quota exceeded" },
    { WSAESTALE, "Stale NFS file handle" },
    { WSAEREMOTE, "Too many levels of remote in path" },
    { WSASYSNOTREADY, "Network subsystem is unvailable" },
    { WSAVERNOTSUPPORTED, "WinSock version is not "
      "supported" },
    { WSANOTINITIALISED, "Successful WSAStartup() not yet "
      "performed" },
    { WSAEDISCON, "Graceful shutdown in progress" },
    /* Resolver errors */
    { WSAHOST_NOT_FOUND, "No such host is known" },
    { WSATRY_AGAIN, "Host not found, or server failed" },
    { WSANO_RECOVERY, "Unexpected server error "
      "encountered" },
    { WSANO_DATA, "Valid name without requested data" },
    { WSANO_ADDRESS, "No address, look for MX record" },
    { 0, NULL }
  };

  static char buf[64];

  for (msgp = msgs; msgp->msg; msgp++) {
    if (errcode == msgp->no) {
      return msgp->msg;
    }
  }

  /* This can not overflow, but in other hand, it is not thread-safe */
  sprintf(buf, "winsock error %d", errcode);

  return buf;
}

void su_perror(const char *s)
{
  int errcode = WSAGetLastError();
  su_log("%s: %s\n", s, su_strerror(errcode));
}

#endif /* SU_HAVE_WINSOCK */

void su_perror2(const char *s, int errcode)
{
  su_log("%s: %s\n", s, su_strerror(errcode));
}

int su_soerror(su_socket_t s)
{
  int error = 0;
  socklen_t errorlen = sizeof(error);

  getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)&error, &errorlen);

  return error;
}

int su_setreuseaddr(su_socket_t s, int reuse)
{
  return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, 
		    (void *)&reuse, sizeof(reuse));
}


#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

int su_getmsgsize(su_socket_t s)
{
  int n = -1;
  if (su_ioctl(s, FIONREAD, &n) == -1)
    return -1;
  return n;
}

#if SU_HAVE_WINSOCK && SU_HAVE_IN6
/** Return a pointer to the in6addr_any. */
struct in_addr6 const *su_in6addr_any(void)
{
  static const struct in_addr6 a = SU_IN6ADDR_ANY_INIT;
  return &a;
}

/** Return a pointer to IPv6 loopback address */
struct in_addr6 const *su_in6addr_loopback(void)
{
  static const struct in_addr6 a = SU_IN6ADDR_LOOPBACK_INIT;
  return &a;
}
#endif

#if SU_HAVE_WINSOCK

/** Scatter/gather send */
int su_vsend(su_socket_t s, su_iovec_t const iov[], int iovlen, int flags, 
             su_sockaddr_t const *su, socklen_t sulen)
{
  int ret;
  DWORD bytes_sent = -1;
  
  ret =  WSASendTo(s,
		   (LPWSABUF)iov,
		   iovlen,
		   &bytes_sent,
		   flags,
		   &su->su_sa,
		   sulen,
		   NULL,
		   NULL);
  if (ret < 0)
    return ret;
  else
    return bytes_sent;
}


/** Scatter/gather recv */
int su_vrecv(su_socket_t s, su_iovec_t iov[], int iovlen, int flags, 
             su_sockaddr_t *su, socklen_t *sulen)
{
  int ret;
  DWORD bytes_recv = -1;
  DWORD dflags = flags;

  ret =  WSARecvFrom(s,
		     (LPWSABUF)iov,
		     iovlen,
		     &bytes_recv,
		     &dflags,
		     &su->su_sa,
		     sulen,
		     NULL,
		     NULL);
  if (ret < 0)
    return ret;
  else
    return bytes_recv;
}


#else

int su_vsend(su_socket_t s, su_iovec_t const iov[], int iovlen, int flags, 
             su_sockaddr_t const *su, socklen_t sulen)
{
  struct msghdr hdr[1] = {{0}};

  hdr->msg_name = (struct sockaddr *)&su->su_sa;
  hdr->msg_namelen = sulen;
  hdr->msg_iov = (struct iovec *)iov;
  hdr->msg_iovlen = iovlen;

  return sendmsg(s, hdr, flags);
}

int su_vrecv(su_socket_t s, su_iovec_t iov[], int iovlen, int flags, 
             su_sockaddr_t *su, socklen_t *sulen)
{
  struct msghdr hdr[1] = {{0}};
  int retval;

  hdr->msg_name = (struct sockaddr *)&su->su_sa;
  if (su && sulen)
    hdr->msg_namelen = *sulen;
  hdr->msg_iov = (struct iovec *)iov;
  hdr->msg_iovlen = iovlen;

  retval = recvmsg(s, hdr, flags);

  if (su && sulen)
    *sulen = hdr->msg_namelen;

  return retval;
}

#endif

/** Compare two socket addresses */
int su_cmp_sockaddr(su_sockaddr_t const *a, su_sockaddr_t const *b)
{
  int rv;

  /* Check that a and b are non-NULL */
  if ((rv = (a != NULL) - (b != NULL)) || a == NULL /* && b == NULL */)
    return rv;

  if ((rv = a->su_family - b->su_family))
    return rv;
  
  if (a->su_family == AF_INET)
    rv = memcmp(&a->su_sin.sin_addr, &b->su_sin.sin_addr, 
		sizeof(struct in_addr));
#if SU_HAVE_IN6
  else if (a->su_family == AF_INET6)
    rv = memcmp(&a->su_sin6.sin6_addr, &b->su_sin6.sin6_addr, 
		sizeof(struct in6_addr));
#endif
  else
    rv = memcmp(a, b, sizeof(struct sockaddr));

  if (rv)
    return rv;
  
  return a->su_port - b->su_port;
}

/** Check if socket address b match with a.
 *
 * The function su_match_sockaddr() returns true if the socket address @a b
 * matches with the socket address @a a. This happens if either all the
 * interesting fields are identical: address family, port number, address,
 * and scope ID (in case of IPv6) or that the @a a contains a wildcard
 * (zero) in their place.
 */
int su_match_sockaddr(su_sockaddr_t const *a, su_sockaddr_t const *b)
{
  /* Check that a and b are non-NULL */
  if (a == NULL)
    return 1;
  if (b == NULL)
    return 0;

  if (a->su_family != 0 && a->su_family != b->su_family)
    return 0;

  if (a->su_family == 0 || SU_SOCKADDR_INADDR_ANY(a))
    ;
  else if (a->su_family == AF_INET) {
    if (memcmp(&a->su_sin.sin_addr, &b->su_sin.sin_addr, 
	       sizeof(struct in_addr)))
      return 0;
  }
#if SU_HAVE_IN6
  else if (a->su_family == AF_INET6) {
    if (a->su_scope_id != 0 && a->su_scope_id != b->su_scope_id)
      return 0;
    if (memcmp(&a->su_sin6.sin6_addr, &b->su_sin6.sin6_addr, 
	       sizeof(struct in6_addr)))
      return 0;
  }
#endif
  else if (memcmp(a, b, sizeof(struct sockaddr)))
    return 0;

  if (a->su_port == 0)
    return 1;
  
  return a->su_port == b->su_port;
}

/** Convert mapped/compat address to IPv4 address */
void su_canonize_sockaddr(su_sockaddr_t *su)
{
#if SU_HAVE_IN6
  if (su->su_family != AF_INET6)
    return;

  if (!IN6_IS_ADDR_V4MAPPED(&su->su_sin6.sin6_addr) &&
      !IN6_IS_ADDR_V4COMPAT(&su->su_sin6.sin6_addr))
    return;
  
  su->su_family = AF_INET;
  su->su_array32[1] = su->su_array32[5];
  su->su_array32[2] = 0; 
  su->su_array32[3] = 0;
#endif
}

