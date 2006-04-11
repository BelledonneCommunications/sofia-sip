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

/**@CFILE sres_blocking.c
 * @brief Blocking interface for Sofia DNS Resolver implementation.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @date Created: Fri Mar 24 15:23:08 EET 2006 ppessi
 */

#include "config.h"

#if HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#else
#if defined(_WIN32)
typedef _int8 int8_t;
typedef unsigned _int8 uint8_t;
typedef unsigned _int16 uint16_t;
typedef unsigned _int32 uint32_t;
#endif
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>
#define HAVE_SELECT 1
#endif

typedef struct sres_blocking_s sres_blocking_t;
typedef struct sres_blocking_context_s sres_blocking_context_t;

#define SRES_CONTEXT_T struct sres_blocking_context_s
#define SRES_ASYNC_T struct sres_blocking_s

#include "sofia-resolv/sres.h"
#include "sofia-resolv/sres_async.h"

#if HAVE_POLL
#include <poll.h>
#elif HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <stdlib.h>
#include <errno.h>

struct sres_blocking_s
{
  int              n_sockets;
#if HAVE_POLL
  struct pollfd    fds[SRES_MAX_NAMESERVERS];
#elif HAVE_SELECT
  struct { int fd; } fds[SRES_MAX_NAMESERVERS];
#else
#error No wait mechanism!
#endif
  sres_record_t ***return_records;  
};

struct sres_blocking_context_s
{
  int          ready;
  sres_resolver_t *resolver;
  sres_blocking_t *block;
  sres_query_t *query;
  sres_record_t ***return_records;  
};

static
int sres_blocking_update(sres_blocking_t *b,
			 int new_socket,
			 int old_socket)
{
  int i, N = b->n_sockets;

  if (old_socket == new_socket) {
    if (old_socket == -1) {
      free(b);      /* Destroy us */
    }
    return 0;
  }

  if (old_socket != -1) {
    for (i = 0; i < N; i++) {
      if (b->fds[i].fd == old_socket)
	break;
    }
    if (i == N)
      return -1;

    N--;
    b->fds[i].fd = b->fds[N].fd;
    b->fds[N].fd = -1;
#if HAVE_POLL
    b->fds[i].events = b->fds[N].events;
    b->fds[N].events = 0;
#endif

    b->n_sockets = N;
  }
  
  if (new_socket != -1) {
    if (N == SRES_MAX_NAMESERVERS)
      return -1;
    b->fds[N].fd = new_socket;
#if HAVE_POLL
    b->fds[N].events = POLLIN;
#endif
    b->n_sockets = N + 1;
  }

  return 0;
}

static
int sres_blocking_complete(sres_blocking_context_t *c)
{
  while (c->ready > 0) {
    int n, i;
#if HAVE_POLL
    n = poll(c->block->fds, c->block->n_sockets, 500);
    if (n < 0) {
      c->ready = n;
    }
    else if (n == 0) {
      sres_resolver_timer(c->resolver, -1);
    }
    else for (i = 0; i < c->block->n_sockets; i++) {
      if (c->block->fds[n].revents | POLLERR)
	sres_resolver_error(c->resolver, c->block->fds[n].fd);
      if (c->block->fds[n].revents | POLLIN)
	sres_resolver_receive(c->resolver, c->block->fds[n].fd);
    }
#elif HAVE_SELECT
    fd_set readfds[1], errorfds[1];
    struct timeval timeval[1];

    FD_ZERO(readfds);
    FD_ZERO(errorfds);

    timeval->tv_sec = 0;
    timeval->tv_usec = 500000;

    for (i = 0, n = 0; i < c->block->n_sockets; i++) {
      FD_SET(c->block->fds[n].fd, readfds);
      FD_SET(c->block->fds[n].fd, errorfds);
      if (c->block->fds[n].fd >= n)
	n = c->block->fds[n].fd + 1;
    }

    n = select(n, readfds, NULL, errorfds, timeval);
  
    if (n <= 0)
      sres_resolver_timer(c->resolver, -1);
    else for (i = 0; i < c->block->n_sockets; i++) {
      if (c->block->fds[i].fd > n)
	continue;
      if (FD_ISSET(c->block->fds[i].fd, errorfds))
        sres_resolver_error(c->resolver, c->block->fds[i].fd);
      else if (FD_ISSET(c->block->fds[i].fd, readfds))
	sres_resolver_receive(c->resolver, c->block->fds[i].fd);
      else
	continue;
      break;
    }
#endif
  }

  return c->ready;
}

static
void sres_blocking_callback(sres_blocking_context_t *c, 
			    sres_query_t *query,
			    sres_record_t **answers)
{
  c->ready = 1;
  *c->return_records = answers;
}

static 
sres_blocking_t *sres_set_blocking(sres_resolver_t *res)
{
  sres_blocking_t *b;
  int i;

  b = sres_resolver_get_async(res, sres_blocking_update); 
  if (b)
    return b;

  /* Create a synchronous (blocking) interface towards resolver */
  b = calloc(1, sizeof *b);

  for (i = 0; i < SRES_MAX_NAMESERVERS; i++)
    b->fds[i].fd = -1;
  
  if (!sres_resolver_set_async(res, sres_blocking_update, b, 0)) {
    free(b), b = NULL;
  }

  return b;
}

/** Send a query, return results. */
int sres_blocking_query(sres_resolver_t *res,
			uint16_t type,
			char const *domain,
			sres_record_t ***return_records)
{
  sres_blocking_context_t c[1];
  sres_record_t **cached;

  if (return_records == NULL)
    return errno = EFAULT, -1;

  c->block = sres_set_blocking(res);
  if (c->block == NULL)
    return -1;

  cached = sres_cached_answers(res, type, domain);
  if (cached) {
    *return_records = cached;
    return 0;
  }

  c->ready = 0;
  c->resolver = res;
  c->return_records = return_records;
  c->query = sres_query(res, sres_blocking_callback, c, type, domain);

  return sres_blocking_complete(c);
}

/** Send a a reverse DNS query, return results. */
int sres_blocking_query_sockaddr(sres_resolver_t *res,
				 uint16_t type,
				 struct sockaddr const *addr,
				 sres_record_t ***return_records)
{
  sres_blocking_context_t c[1];
  sres_record_t **cached;

  if (return_records == NULL)
    return errno = EFAULT, -1;
  
  c->block = sres_set_blocking(res);
  if (c->block == NULL)
    return -1;

  cached = sres_cached_answers_sockaddr(res, type, addr);
  if (cached) {
    *return_records = cached;
    return 0;
  }

  c->ready = 0;
  c->resolver = res;
  c->return_records = return_records;
  c->query = sres_query_sockaddr(res, sres_blocking_callback, c, type, addr);

  return sres_blocking_complete(c);
}
