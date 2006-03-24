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

/**@CFILE tport_type_sctp.c Transport using SCTP.
 *
 * See tport.docs for more detailed description of tport interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti.Mela@nokia.com>
 *
 * @date Created: Fri Mar 24 08:45:49 EET 2006 ppessi
 * @date Original Created: Thu Jul 20 12:54:32 2000 ppessi
 */

#include "config.h"

#if HAVE_SCTP

#include "tport_internal.h"

#if HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#undef HAVE_SCTP
#define HAVE_SCTP 1
#endif

#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

/* ---------------------------------------------------------------------- */
/* SCTP */

#define TP_SCTP_MSG_MAX (32768)

static int tport_sctp_init_primary(tport_primary_t *, 
				   tp_name_t const tpn[1], 
				   su_addrinfo_t *, tagi_t const *,
				   char const **return_culprit);
static int tport_sctp_init_client(tport_primary_t *, 
				  tp_name_t const tpn[1], 
				  su_addrinfo_t *, tagi_t const *,
				  char const **return_culprit);
static int tport_sctp_init_secondary(tport_t *self, int socket, int accepted);
static int tport_recv_sctp(tport_t *self);
static int tport_send_sctp(tport_t const *self, msg_t *msg,
			   msg_iovec_t iov[], int iovused);

tport_vtable_t const tport_sctp_client_vtable =
{
  "sctp", tport_type_client,
  sizeof (tport_primary_t),
  tport_sctp_init_client,
  NULL,
  NULL,
  tport_accept,
  NULL,
  sizeof (tport_t),
  tport_sctp_init_secondary,
  NULL,
  NULL,
  NULL,
  NULL,
  tport_recv_sctp,
  tport_send_sctp,
};

#undef NEXT_VTABLE
#define NEXT_VTABLE &tport_sctp_client_vtable

tport_vtable_t const tport_sctp_vtable =
{
  "sctp", tport_type_local,
  sizeof (tport_primary_t),
  tport_sctp_init_primary,
  NULL,
  NULL,
  tport_accept,
  NULL,
  sizeof (tport_t),
  tport_sctp_init_secondary,
  NULL,
  NULL,
  NULL,
  NULL,
  tport_recv_sctp,
  tport_send_sctp,
};

#undef NEXT_VTABLE
#define NEXT_VTABLE &tport_sctp_vtable

static int tport_sctp_init_primary(tport_primary_t *pri, 
				   tp_name_t const tpn[1],
				   su_addrinfo_t *ai,
				   tagi_t const *tags,
				   char const **return_culprit)
{
  if (pri->pri_params->tpp_mtu > TP_SCTP_MSG_MAX)
    pri->pri_params->tpp_mtu = TP_SCTP_MSG_MAX;

  return tport_tcp_init_primary(pri, tpn, ai, tags, return_culprit);
}

static int tport_sctp_init_client(tport_primary_t *pri, 
				   tp_name_t const tpn[1],
				   su_addrinfo_t *ai,
				   tagi_t const *tags,
				   char const **return_culprit)
{
  if (pri->pri_params->tpp_mtu > TP_SCTP_MSG_MAX)
    pri->pri_params->tpp_mtu = TP_SCTP_MSG_MAX;

  return tport_tcp_init_client(pri, tpn, ai, tags, return_culprit);
}


static int tport_sctp_init_secondary(tport_t *self, int socket, int accepted)
{
  self->tp_connected = 1;

  if (su_setblocking(socket, 0) < 0)
    return -1;

  return 0;
}

/** Receive data available on the socket.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive
 * @retval 2  incomplete recv, recv again
 */
static 
int tport_recv_sctp(tport_t *self)
{
  msg_t *msg;
  int N, veclen, exact = 0, eos;
  msg_iovec_t iovec[2] = {{ 0 }};

  char sctp_buf[TP_SCTP_MSG_MAX];

  iovec[0].mv_base = sctp_buf;
  iovec[0].mv_len = sizeof(sctp_buf);

  N = su_vrecv(self->tp_socket, iovec, 1, 0, NULL, NULL);
  if (N == SOCKET_ERROR)
    return tport_recv_error_report(self);

  veclen = tport_recv_iovec(self, &self->tp_msg, iovec, N, exact = 1);
  if (veclen < 0)
    return -1;

  assert(veclen == 1); assert(iovec[0].mv_len == N);
  msg = self->tp_msg;

  /* Message address */
  *msg_addr(msg) = *self->tp_addr;
  *msg_addrlen(msg) = su_sockaddr_size(self->tp_addr);

  memcpy(iovec[0].mv_base, sctp_buf, iovec[0].mv_len);

  if (self->tp_master->mr_dump_file)
    tport_dump_iovec(self, msg, N, iovec, veclen, "recv", "from");

  msg_recv_commit(msg, N, eos = 1);  /* Mark buffer as used */

  return 2;
}

static int tport_send_sctp(tport_t const *self, msg_t *msg,
			   msg_iovec_t iov[], int iovused)
{
  return tport_send_dgram(self, msg, iov, iovused);
}

#endif
