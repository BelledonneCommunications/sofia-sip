/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2006 Nokia Corporation.
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

/**@CFILE tport_connect.c Transport using HTTP CONNECT.
 *
 * See tport.docs for more detailed description of tport interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti.Mela@nokia.com>
 *
 * @date Created: Fri Mar 24 08:45:49 EET 2006 ppessi
 */

#include "config.h"

#include "tport_internal.h"

#undef HAVE_SIGCOMP

#if HAVE_IP_RECVERR || HAVE_IPV6_RECVERR
#include <linux/types.h>
#include <linux/errqueue.h>
#include <sys/uio.h>
#endif

#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

/* ---------------------------------------------------------------------- */
/* UDP */

static int tport_recv_stun_dgram(tport_t const *self, int N);
static int tport_recv_sigcomp_dgram(tport_t *self, int N);

tport_vtable_t const tport_udp_client_vtable =
{
  "udp", tport_type_client,
  sizeof (tport_primary_t),
  NULL,
  NULL,
  NULL,
  NULL,
  sizeof (tport_t),
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  tport_recv_dgram,
  tport_send_dgram,
};

tport_vtable_t const tport_udp_vtable =
{
  "udp", tport_type_local,
  sizeof (tport_primary_t),
  tport_udp_init_primary,
  NULL,
  NULL,
  NULL,
  sizeof (tport_t),
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  tport_recv_dgram,
  tport_send_dgram,
};

int tport_udp_init_primary(tport_primary_t *pri,
			   tp_name_t tpn[1],
			   su_addrinfo_t *ai,
			   tagi_t const *tags,
			   char const **return_culprit)
{
  unsigned rmem = 0, wmem = 0;
  int events = SU_WAIT_IN;
  int s;

  s = su_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (s == SOCKET_ERROR)
    return *return_culprit = "socket", -1;

  pri->pri_primary->tp_socket = s;

  if (tport_bind_socket(s, ai, return_culprit) < 0)
    return -1;

#if HAVE_IP_RECVERR
  if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
    int const one = 1;
    if (setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0) {
      if (ai->ai_family == AF_INET)
	SU_DEBUG_3(("setsockopt(IPVRECVERR): %s\n", su_strerror(su_errno())));
    }
    events |= SU_WAIT_ERR;
  }
#endif
#if HAVE_IPV6_RECVERR
  if (ai->ai_family == AF_INET6) {
    int const one = 1;
    if (setsockopt(s, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one)) < 0)
      SU_DEBUG_3(("setsockopt(IPV6_RECVERR): %s\n", su_strerror(su_errno())));
    events |= SU_WAIT_ERR;
  }
#endif

  tl_gets(tags, 
	  TPTAG_UDP_RMEM_REF(rmem),
	  TPTAG_UDP_WMEM_REF(wmem),
	  TAG_END());

  if (rmem != 0 && 
      setsockopt(s, SOL_SOCKET, SO_RCVBUF, (void *)&rmem, sizeof rmem) < 0) {
    SU_DEBUG_3(("setsockopt(SO_RCVBUF): %s\n", 
		su_strerror(su_errno())));
  }

  if (wmem != 0 && 
      setsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *)&wmem, sizeof wmem) < 0) {
    SU_DEBUG_3(("setsockopt(SO_SNDBUF): %s\n", 
		su_strerror(su_errno())));
  }

  pri->pri_primary->tp_events = events;

  return 0;
}

/** Receive datagram.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 */
int tport_recv_dgram(tport_t *self)
{
  int N;
  int s = self->tp_socket;
  unsigned char sample[2];

  /* Simulate packet loss */
  if (self->tp_params->tpp_drop && 
      su_randint(0, 1000) < self->tp_params->tpp_drop) {
    recv(self->tp_socket, sample, 1, 0);
    SU_DEBUG_3(("tport(%p): simulated packet loss!\n", self));
    return 0;
  }

  /* Peek for first two bytes in message:
     determine if this is stun, sigcomp or sip
  */
  N = recv(s, sample, sizeof sample, MSG_PEEK | MSG_TRUNC);

  if (N < 0) {
    if (su_errno() == EAGAIN || su_errno() == EWOULDBLOCK)
      N = 0;
  }
  else if (N <= 1) {
    SU_DEBUG_1(("%s(%p): runt of %u bytes\n", "tport_recv_dgram", self, N));
    recv(s, sample, sizeof sample, 0);
    N = 0;
  }
#if MSG_TRUNC
  else if ((N = su_getmsgsize(s)) < 0)
    SU_DEBUG_1(("%s: su_getmsgsize(): %s (%d)\n", __func__, 
		su_strerror(su_errno()), su_errno()));
#endif
  else if ((sample[0] & 0xf8) == 0xf8) {
    return tport_recv_sigcomp_dgram(self, N); /* SigComp */
  }
  else if (sample[0] == 0 || sample[0] == 1) {
    return tport_recv_stun_dgram(self, N);    /* STUN */
  }
  else
    return tport_recv_dgram_r(self, &self->tp_msg, N);

  return N;
}

/** Receive datagram statelessly.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive (should never happen)
 * @retval 2  incomplete recv, recv again (should never happen)
 * @retval 3  STUN keepalive, ignore
 */
int tport_recv_dgram_r(tport_t const *self, msg_t **mmsg, int N)
{
  msg_t *msg;
  int n, veclen;
  su_sockaddr_t *from;
  socklen_t *fromlen;
  msg_iovec_t iovec[msg_n_fragments] = {{ 0 }};

  assert(*mmsg == NULL);

  veclen = tport_recv_iovec(self, mmsg, iovec, N, 1);
  if (veclen < 0)
    return -1;

  msg = *mmsg;

  n = su_vrecv(self->tp_socket, iovec, veclen, 0, 
	       from = msg_addr(msg), fromlen = msg_addrlen(msg));
  if (n == SOCKET_ERROR) {
    int error = su_errno();
    msg_destroy(msg); *mmsg = NULL;
    su_seterrno(error);
    return -1;
  }

  SU_CANONIZE_SOCKADDR(from);
  assert(n <= N);		/* FIONREAD tells the size of all messages.. */

  if (self->tp_master->mr_dump_file && !self->tp_pri->pri_threadpool)
    tport_dump_iovec(self, msg, n, iovec, veclen, "recv", "from");

  msg_recv_commit(msg, n, 1);  /* Mark buffer as used */

  return 0;
}

/** Receive data from datagram using SigComp. */
int tport_recv_sigcomp_dgram(tport_t *self, int N)
{
  char dummy[1];
  int error = EBADMSG;
#if HAVE_SIGCOMP
  struct sigcomp_udvm *udvm;

  if (self->tp_sigcomp->sc_udvm == 0)
    self->tp_sigcomp->sc_udvm = tport_init_udvm(self);

  udvm = self->tp_sigcomp->sc_udvm;

  if (udvm) {
    retval = tport_recv_sigcomp_r(self, &self->tp_msg, udvm, N);
    if (retval < 0)
      sigcomp_udvm_reject(udvm);
    return retval;
  }
  error = su_errno();
#endif
  recv(self->tp_socket, dummy, 1, 0); /* remove msg from socket */
  /* XXX - send NACK ? */
  return su_seterrno(error);     
}

/** Receive STUN datagram.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 */
int tport_recv_stun_dgram(tport_t const *self, int N)
{
  int n;
  su_sockaddr_t from[1];
  socklen_t fromlen = sizeof(su_sockaddr_t);
  int status = 600;
  char const *error = NULL;
  
  unsigned char buffer[128];
  unsigned char *dgram = buffer;

  if (N > sizeof buffer)
    dgram = malloc(N);

  if (dgram == NULL)
    dgram = buffer, N = sizeof buffer, status = 500, error = "Server Error";

  memset(from, 0, sizeof(su_sockaddr_t));
  n = recvfrom(self->tp_socket, (void *)dgram, N, MSG_TRUNC, 
	       (void *)from, &fromlen);

  if (n < 20) {
    if (n != SOCKET_ERROR)
      su_seterrno(EBADMSG);	/* Runt */
    if (dgram != buffer)
      free(dgram);
    return -1;
  }

  if ((!error || dgram[0] == 1) && self->tp_master->mr_nat->stun) {
#if HAVE_SOFIA_STUN
    if (n > N) n = N;		/* Truncated? */
    stun_process_message(self->tp_master->mr_nat->stun, self->tp_socket,
			 from, fromlen, (void *)dgram, n);
    if (dgram != buffer)
      free(dgram);
    return 0;
#endif /* HAVE_SOFIA_STUN */
  }

  if (dgram[0] == 0 && (dgram[1] == 1 || dgram[1] == 2)) {
    uint16_t elen;
    if (error == NULL)
      status = 600, error = "Not Implemented";
    elen = strlen(error);

    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      STUN Message Type        |         Message Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                             Transaction ID
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

#define set16(b, offset, value)			\
  (((b)[(offset) + 0] = ((value) >> 8) & 255),	\
   ((b)[(offset) + 1] = (value) & 255))

    /* Respond to request */
    dgram[0] = 1; /* Mark as response */
    dgram[1] |= 0x10; /* Mark as error response */
    set16(dgram, 2, elen + 4 + 4);
    /* TransactionID is there at bytes 4..19 */
    /*
    TLV At 20:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Type                  |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    set16(dgram, 20, 0x0009); /* ERROR-CODE */
    set16(dgram, 22, elen + 4);
    /*
    ERROR-CODE at 24:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   0                     |Class|     Number    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Reason Phrase (variable)                                ..
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    dgram[24] = 0, dgram[25] = 0;
    dgram[26] = status / 100, dgram[27] = status % 100;
    memcpy(dgram + 28, error, elen);
    N = 28 + elen;
    sendto(self->tp_socket, (void *)dgram, N, 0, (void *)from, fromlen);

#undef set16
  }

  if (dgram != buffer)
    free(dgram);

  return 0;
}

/** Send using su_vsend(). Map IPv4 addresses as IPv6 addresses, if needed. */
int tport_send_dgram(tport_t const *self, msg_t *msg, 
		     msg_iovec_t iov[], 
		     int iovused)
{
  su_sockaddr_t *su;
  int sulen;
#if SU_HAVE_IN6 && defined(IN6_INADDR_TO_V4MAPPED)
  su_sockaddr_t su0[1];
#endif

  if (tport_is_connection_oriented(self))
    return su_vsend(self->tp_socket, iov, iovused, MSG_NOSIGNAL, NULL, 0);

  su = msg_addr(msg);
  sulen = *msg_addrlen(msg);

#if SU_HAVE_IN6 && defined(IN6_INADDR_TO_V4MAPPED)
  if (su->su_family == AF_INET && self->tp_addrinfo->ai_family == AF_INET6) {
    memset(su0, 0, sizeof su0);

    su0->su_family = self->tp_addrinfo->ai_family;
    su0->su_port = su->su_port;

    IN6_INADDR_TO_V4MAPPED(&su->su_sin.sin_addr, &su0->su_sin6.sin6_addr);

    su = su0, sulen = sizeof(su0->su_sin6);
  }
#endif

  su_soerror(self->tp_socket); /* XXX - we *still* have a race condition */

  return su_vsend(self->tp_socket, iov, iovused, MSG_NOSIGNAL, su, sulen);
}


#if !HAVE_IP_RECVERR && !HAVE_IPV6_RECVERR

/** Process UDP error event. */
int tport_udp_error(tport_t const *self, su_sockaddr_t name[1])
{
  if (tport_is_connection_oriented(self))
    name[0] = self->tp_addr[0];
  return su_soerror(self->tp_socket);
}

#else

/** Process UDP error event. */
int tport_udp_error(tport_t const *self, su_sockaddr_t name[1])
{
  struct cmsghdr *c;
  struct sock_extended_err *ee;
  su_sockaddr_t *from;
  char control[512];
  char errmsg[64 + 768];
  struct iovec iov[1];
  struct msghdr msg[1] = {{ 0 }};
  int n;

  msg->msg_name = name, msg->msg_namelen = sizeof(*name);
  msg->msg_iov = iov, msg->msg_iovlen = 1;
  iov->iov_base = errmsg, iov->iov_len = sizeof(errmsg);
  msg->msg_control = control, msg->msg_controllen = sizeof(control);

  n = recvmsg(self->tp_socket, msg, MSG_ERRQUEUE);

  if (n < 0) {
    int err = su_errno();
    if (err != EAGAIN && err != EWOULDBLOCK)
      SU_DEBUG_1(("%s: recvmsg: %s\n", __func__, su_strerror(err)));
    return 0;
  }

  if ((msg->msg_flags & MSG_ERRQUEUE) != MSG_ERRQUEUE) {
    SU_DEBUG_1(("%s: recvmsg: no errqueue\n", __func__));
    return 0;
  }

  if (msg->msg_flags & MSG_CTRUNC) {
    SU_DEBUG_1(("%s: extended error was truncated\n", __func__));
    return 0;
  }

  if (msg->msg_flags & MSG_TRUNC) {
    /* ICMP message may contain original message... */
    SU_DEBUG_3(("%s: icmp(6) message was truncated (at %d)\n", __func__, n));
  }

  /* Go through the ancillary data */
  for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
    if (0
#if HAVE_IP_RECVERR
	|| (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR)
#endif
#if HAVE_IPV6_RECVERR
	|| (c->cmsg_level == SOL_IPV6 && c->cmsg_type == IPV6_RECVERR)
#endif
	) {
      char info[128];
      char const *origin;

      ee = (struct sock_extended_err *)CMSG_DATA(c);
      from = (su_sockaddr_t *)SO_EE_OFFENDER(ee);
      info[0] = '\0';

      switch (ee->ee_origin) {
      case SO_EE_ORIGIN_LOCAL:
	origin = "local";
	break;
      case SO_EE_ORIGIN_ICMP:
	origin = "icmp";
	snprintf(info, sizeof(info), " type=%u code=%u", 
		 ee->ee_type, ee->ee_code);
	break;
      case SO_EE_ORIGIN_ICMP6:
	origin = "icmp6";
	snprintf(info, sizeof(info), " type=%u code=%u", 
		ee->ee_type, ee->ee_code);
	break;
      case SO_EE_ORIGIN_NONE:
	origin = "none";
	break;
      default:
	origin = "unknown";
	break;
      }

      if (ee->ee_info)
	snprintf(info + strlen(info), sizeof(info) - strlen(info), 
		 " info=%08x", ee->ee_info);

      SU_DEBUG_3(("%s: %s (%d) [%s%s]\n",
		  __func__, su_strerror(ee->ee_errno), ee->ee_errno, 
		  origin, info));
      if (from->su_family != AF_UNSPEC)
	SU_DEBUG_3(("\treported by [%s]:%u\n",
		    inet_ntop(from->su_family, SU_ADDR(from), 
			      info, sizeof(info)),
		    ntohs(from->su_port)));

      if (msg->msg_namelen == 0)
	name->su_family = AF_UNSPEC;

      SU_CANONIZE_SOCKADDR(name);

      return ee->ee_errno;
    }
  }

  return 0;
}
#endif

