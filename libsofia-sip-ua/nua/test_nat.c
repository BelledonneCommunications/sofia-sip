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

/**@CFILE test_nat.c
 * @brief Simulated NAT for testing nua
 *
 * NAT thing works so that we set the outgoing proxy URI to point
 * towards its "private" address and give the real address of the proxy
 * as its "public" address. If we use different IP families here, we may
 * even manage to test real connectivity problems as proxy and endpoint
 * can not talk to each other.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 19:54:28 EET 2006
 */

#include "config.h"

#include <string.h>

struct nat;
struct binding;

#define SU_ROOT_MAGIC_T struct nat
#define SU_WAKEUP_ARG_T struct binding

#include <sofia-sip/su_wait.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/su_localinfo.h>
#include <sofia-sip/su_log.h>

#include <stdlib.h>
#include <assert.h>

#if !defined(EADDRNOTAVAIL) && defined(_WIN32)
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#endif


#define LIST_PROTOS(STORAGE, PREFIX, T)			 \
STORAGE void PREFIX ##_insert(T **list, T *node),	 \
        PREFIX ##_remove(T *node)

#define LIST_BODIES(STORAGE, PREFIX, T, NEXT, PREV)	  \
STORAGE void PREFIX ##_insert(T **list, T *node)   \
{							 \
  if ((node->NEXT = *list)) {				 \
    node->PREV = node->NEXT->PREV;			 \
    node->NEXT->PREV = &node->NEXT;			 \
  }							 \
  else							 \
    node->PREV = list;					 \
  *list = node;						 \
}							 \
STORAGE void PREFIX ##_remove(T *node)			 \
{							 \
  if (node->PREV)					 \
    if ((*node->PREV = node->NEXT))			 \
      node->NEXT->PREV = node->PREV;			 \
  node->PREV = NULL;					 \
}							 \
extern int LIST_DUMMY_VARIABLE

#include <test_nat.h>

struct nat {
  su_home_t    home[1];
  su_root_t   *parent;
  su_clone_r   clone;
  tagi_t      *tags;

  su_root_t   *root;

  struct binding *bindings;

  /* True if we act in symmetric way */
  int symmetric;

  /* Everything sent to in_address will be forwarded to out_address */
  su_sockaddr_t in_address[1], out_address[1];
  socklen_t in_addrlen, out_addrlen;

  int family;			/* Preferred private family */

  /* ...but source address will be "fake" */
  su_localinfo_t *localinfo, *private, *fake;

  int udp_socket, tcp_socket;
  int udp_register, tcp_register;

  char buffer[65536];
};

LIST_PROTOS(static, nat_binding, struct binding);

struct binding
{
  struct binding *next, **prev;
  struct nat *nat;		/* backpointer */
  int socktype;
  int in_socket, out_socket;
  int in_register, out_register;
  int in_closed, out_closed;
  char in_name[64], out_name[64];
};

static struct binding *nat_binding_new(struct nat *, int, int, int);
static void nat_binding_destroy(struct binding *);

static void flush_bindings(struct nat *nat);
static void invalidate_bindings(struct nat *nat);

static int new_udp(struct nat *, su_wait_t *wait, struct binding *dummy);
static int udp_in_to_out(struct nat *, su_wait_t *wait, struct binding *);
static int udp_out_to_in(struct nat *, su_wait_t *wait, struct binding *);

static int new_tcp(struct nat *, su_wait_t *wait, struct binding *dummy);
static int tcp_in_to_out(struct nat *, su_wait_t *wait, struct binding *);
static int tcp_out_to_in(struct nat *, su_wait_t *wait, struct binding *);

static int invalidate_binding(struct binding *b);

/* nat entry point */
static int
test_nat_init(su_root_t *root, struct nat *nat)
{
  su_localinfo_t *li, hints[1] = {{ 0 }};
  int error;
  unsigned port = 0, port0 = 0;
  su_sockaddr_t *su;
  socklen_t sulen;
  su_wait_t wait[1];

  nat->root = root;
  nat->udp_socket = -1, nat->tcp_socket = -1;

  error = su_getlocalinfo(hints, &nat->localinfo);
  if (error) {
    fprintf(stderr, "test_nat: su_getlocalinfo: %s\n", su_gli_strerror(error));
    return -1;
  }

  /* We must have two different IP addresses. */
  if (!nat->localinfo || !nat->localinfo->li_next) {
    fprintf(stderr, "test_nat: only one IP address available\n");
    return -1;
  }

  for (li = nat->localinfo; li; li = li->li_next) {
    if (nat->family == 0 || nat->family == li->li_family)
      break;
  }
  if (li == NULL)
    li = nat->localinfo;

  su = memcpy(nat->in_address, li->li_addr, sulen = li->li_addrlen);

  nat->private = li;

  /* Bind TCP and UDP to same port */
  for (;;) {
    nat->udp_socket = su_socket(li->li_family, SOCK_DGRAM, IPPROTO_UDP);
    if (nat->udp_socket == -1)
      return -1;

    if (bind(nat->udp_socket, (void *)su, sulen) < 0) {
      if (port0 == 0) {
	su_perror("nat: bind(udp_socket)");
	return -1;
      }

      fprintf(stderr, "test_nat: port %u: %s\n",
	      port, su_strerror(su_errno()));

      su_close(nat->udp_socket);
      nat->udp_socket = -1;

      if (++port > 65535)
	port = 1024;
      if (port == port0) {
	fprintf(stderr, "test_nat: could not find free port pairt\n");
	return -1;
      }

      continue;
    }

    if (getsockname(nat->udp_socket, (void *)su, &sulen) < 0) {
      su_perror("nat: bind(udp_socket)");
      return -1;
    }

    if (port0 == 0) {
      port = port0 = ntohs(su->su_port);
      if (port0 == 0) {
	fprintf(stderr, "test_nat: bind did not return port\n");
	return -1;
      }
    }

    nat->tcp_socket = su_socket(li->li_family, SOCK_STREAM, IPPROTO_TCP);
    if (nat->tcp_socket == -1)
      return -1;

    if (bind(nat->tcp_socket, (void *)su, sulen) < 0) {
      su_close(nat->tcp_socket);
      nat->tcp_socket = -1;

      fprintf(stderr, "test_nat: port %u: %s\n",
	      port, su_strerror(su_errno()));

      if (++port > 65535)
	port = 1024;
      if (port == port0) {
	fprintf(stderr, "test_nat: could not find free port pair\n");
	return -1;
      }

      continue;
    }

    break;
  }

  nat->in_addrlen = sulen;

  if (su_setreuseaddr(nat->udp_socket, 1) < 0) {
    su_perror("nat: su_setreuseaddr(udp_socket)");
    return -1;
  }

  if (listen(nat->tcp_socket, 5) < 0) {
    su_perror("nat: listen(tcp_socket)");
    return -1;
  }

  if (su_wait_create(wait, nat->udp_socket, SU_WAIT_IN) < 0) {
    su_perror("nat: su_wait_create");
    return -1;
  }

  nat->udp_register = su_root_register(root, wait, new_udp, NULL, 0);
  if (nat->udp_register < 0) {
    su_perror("nat: su_root_register");
    return -1;
  }

  if (su_wait_create(wait, nat->tcp_socket, SU_WAIT_IN) < 0) {
    su_perror("nat: su_wait_create");
    return -1;
  }

  nat->tcp_register = su_root_register(root, wait, new_tcp, NULL, 0);
  if (nat->tcp_register < 0) {
    su_perror("nat: su_root_register");
    return -1;
  }

  return 0;
}

static void
test_nat_deinit(su_root_t *root, struct nat *nat)
{
  flush_bindings(nat);

  if (nat->tcp_register)
    su_root_deregister(root, nat->tcp_register);
  if (nat->udp_register)
    su_root_deregister(root, nat->udp_register);

  if (nat->udp_socket != -1)
    su_close(nat->udp_socket);
  if (nat->tcp_socket != -1)
    su_close(nat->tcp_socket);

  su_freelocalinfo(nat->localinfo);

  free(nat->tags);
}

struct nat *test_nat_create(su_root_t *root,
			    int family,
			    tag_type_t tag, tag_value_t value, ...)
{
  struct nat *nat = su_home_new(sizeof *nat);

  if (nat) {
    ta_list ta;

    nat->parent = root;
    nat->family = family;

    ta_start(ta, tag, value);
    nat->tags = tl_llist(ta_tags(ta));
    ta_end(ta);

    if (su_clone_start(root,
		       nat->clone,
		       nat,
		       test_nat_init,
		       test_nat_deinit) == -1)
      su_home_unref(nat->home), nat = NULL;
  }

  return nat;
}

void test_nat_destroy(struct nat *nat)
{
  if (nat) {
    su_clone_wait(nat->parent, nat->clone);
    su_home_unref(nat->home);
  }
}

/** Get "private" address. */
int test_nat_private(struct nat *nat, void *address, int *return_addrlen)
{
  if (nat == NULL || address == NULL || return_addrlen == NULL)
    return su_seterrno(EFAULT);

  if (*return_addrlen < nat->in_addrlen)
    return su_seterrno(EINVAL);

  memcpy(address, nat->in_address, *return_addrlen = nat->in_addrlen);

  return 0;
}

/** Set "public" address. */
int test_nat_public(struct nat *nat, void const *address, int addrlen)
{
  su_sockaddr_t const *su = address;
  su_localinfo_t *li;

  if (nat == NULL)
    return su_seterrno(EFAULT);

  if (address == NULL) {
    nat->fake = NULL;
    return 0;
  }

  if (addrlen > sizeof nat->out_address)
    return su_seterrno(EINVAL);

  for (li = nat->localinfo; li; li = li->li_next) {
    if (li != nat->private &&
	li->li_scope == LI_SCOPE_HOST &&
	li->li_family == su->su_family)
      break;
  }

  if (li == NULL)
    for (li = nat->localinfo; li; li = li->li_next) {
      if (li != nat->private && li->li_family == su->su_family)
	break;
    }

  if (li == NULL)
    return su_seterrno(EADDRNOTAVAIL);

  su_clone_pause(nat->clone);
  memcpy(nat->out_address, address, nat->out_addrlen = addrlen);
  nat->fake = li;
  su_clone_resume(nat->clone);

  return 0;
}

int test_nat_flush(struct nat *nat)
{
  if (nat == NULL)
    return su_seterrno(EFAULT);

  return su_task_execute(su_clone_task(nat->clone), 
			 (void *)invalidate_bindings, nat, NULL);
}

/* ====================================================================== */

static struct binding *nat_binding_new(struct nat *nat,
				       int socktype,
				       int in_socket,
				       int out_socket)
{
  struct binding *b = su_zalloc(nat->home, sizeof *b);
  su_sockaddr_t addr[1];
  socklen_t addrlen = (sizeof addr);
  char name[64];

  if (b == NULL)
    return NULL;

  nat_binding_insert(&nat->bindings, b);

  b->nat = nat;
  b->socktype = socktype;
  b->in_socket = in_socket, b->out_socket = out_socket;
  b->in_register = -1, b->out_register = -1;

  getpeername(in_socket, (void *)addr, &addrlen);
  inet_ntop(addr->su_family, SU_ADDR(addr), name, sizeof name);
  snprintf(b->in_name, sizeof b->in_name,
	   addr->su_family == AF_INET6 ? "[%s]:%u" : "%s:%u",
	   name, ntohs(addr->su_port));

  getsockname(out_socket, (void *)addr, &addrlen);
  inet_ntop(addr->su_family, SU_ADDR(addr), name, sizeof name);
  snprintf(b->out_name, sizeof b->out_name,
	   addr->su_family == AF_INET6 ? "[%s]:%u" : "%s:%u",
	   name, ntohs(addr->su_port));

  return b;
}

static void nat_binding_destroy(struct binding *b)
{
  nat_binding_remove(b);
  if (b->in_register != -1)
    su_root_deregister(b->nat->root, b->in_register);
  if (b->out_register != -1)
    su_root_deregister(b->nat->root, b->out_register);
  su_close(b->in_socket), su_close(b->out_socket);
}

static void flush_bindings(struct nat *nat)
{
  struct binding *b;

  for (b = nat->bindings; b; b = b->next) {
    if (b->in_register)
      su_root_deregister(nat->root, b->in_register);
    su_close(b->in_socket);
    if (b->out_register)
      su_root_deregister(nat->root, b->out_register);
    su_close(b->out_socket);
  }
}

static void invalidate_bindings(struct nat *nat)
{
  struct binding *b;

  for (b = nat->bindings; b; b = b->next) {
    invalidate_binding(b);
  }
}

/* ====================================================================== */

LIST_BODIES(static, nat_binding, struct binding, next, prev);

/* ====================================================================== */

static int new_udp(struct nat *nat, su_wait_t *wait, struct binding *dummy)
{
  int events;
  su_sockaddr_t from[1];
  socklen_t fromlen = (sizeof from);
  struct binding *b;
  ssize_t n, m;
  int in, out;
  su_wait_t win[1], wout[1];

  events = su_wait_events(wait, nat->udp_socket);

  n = recvfrom(nat->udp_socket, nat->buffer, sizeof nat->buffer, 0,
	       (void *)from, &fromlen);
  if (n < 0) {
    su_perror("new_udp: recvfrom");
    return 0;
  }

  if (nat->fake == NULL) {	/* Xyzzy */
    fprintf(stderr, "test_nat: fake address missing\n");
    return -1;
  }

  in = su_socket(from->su_family, SOCK_DGRAM, IPPROTO_UDP);
  if (in < 0) {
    su_perror("new_udp: socket");
    return 0;
  }
  if (su_setreuseaddr(in, 1) < 0) {
    su_perror("nat: su_setreuseaddr(in)");
    su_close(in);
    return -1;
  }
  if (bind(in, (void *)nat->in_address, nat->in_addrlen) < 0) {
    su_perror("new_udp: bind(in)");
    su_close(in);
    return 0;
  }
  if (connect(in, (void *)from, fromlen) < 0) {
    su_perror("new_udp: connect(in)");
    su_close(in);
    return 0;
  }

  out = su_socket(nat->fake->li_family, SOCK_DGRAM, IPPROTO_UDP);
  if (out < 0) {
    su_perror("new_udp: socket");
    su_close(in);
    return 0;
  }
  if (bind(out, (void *)nat->fake->li_addr, nat->fake->li_addrlen) < 0) {
    su_perror("new_udp: bind(to)");
    su_close(in); su_close(out);
    return 0;
  }

  if (nat->symmetric)
    if (connect(out, (void *)nat->out_address, nat->out_addrlen) < 0) {
      su_perror("new_udp: connect(to)");
      su_close(in); su_close(out);
      return 0;
    }

  if (su_wait_create(win, in, SU_WAIT_IN) < 0) {
    su_perror("new_udp: su_wait_create");
    su_close(in); su_close(out);
    return 0;
  }
  if (su_wait_create(wout, out, SU_WAIT_IN) < 0) {
    su_perror("new_udp: su_wait_create");
    su_wait_destroy(win);
    su_close(in); su_close(out);
    return 0;
  }

  b = nat_binding_new(nat, SOCK_DGRAM, in, out);

  if (b == NULL) {
    su_perror("new_udp: nat_binding_new");
    su_close(in); su_close(out);
    return 0;
  }

  b->in_register = su_root_register(nat->root, win, udp_in_to_out, b, 0);
  if (b->in_register < 0) {
    su_perror("new_udp: su_root_register");
    su_wait_destroy(win); su_wait_destroy(wout);
    nat_binding_destroy(b);
    return 0;
  }

  b->out_register = su_root_register(nat->root, wout, udp_out_to_in, b, 0);
  if (b->out_register < 0) {
    su_perror("new_udp: su_root_register");
    su_wait_destroy(wout);
    nat_binding_destroy(b);
    return 0;
  }

  printf("nat: new UDP binding %s <=> %s\n", b->in_name, b->out_name);

  if (nat->symmetric)
    m = send(b->out_socket, nat->buffer, n, 0);
  else
    m = sendto(b->out_socket, nat->buffer, n, 0, 
	       (void *)nat->out_address, nat->out_addrlen);

  printf("nat: udp out %d/%d %s => %s\n",
	 (int)m, (int)n, b->in_name, b->out_name);

  return 0;
}

static int udp_in_to_out(struct nat *nat, su_wait_t *wait, struct binding *b)
{
  int events;
  ssize_t n, m;

  events = su_wait_events(wait, b->in_socket);

  n = recv(b->in_socket, nat->buffer, sizeof nat->buffer, 0);
  if (n < 0) {
    su_perror("udp_in_to_out: recv");
    return 0;
  }

  if (nat->symmetric)
    m = send(b->out_socket, nat->buffer, n, 0);
  else
    m = sendto(b->out_socket, nat->buffer, n, 0,
	       (void *)nat->out_address, nat->out_addrlen);

  printf("nat: udp out %d/%d %s => %s\n",
	 (int)m, (int)n, b->in_name, b->out_name);

  return 0;
}

static int udp_out_to_in(struct nat *nat, su_wait_t *wait, struct binding *b)
{
  int events;
  ssize_t n, m;

  events = su_wait_events(wait, b->out_socket);

  n = recv(b->out_socket, nat->buffer, sizeof nat->buffer, 0);
  if (n < 0) {
    su_perror("udp_out_to_out: recv");
    return 0;
  }

  m = send(b->in_socket, nat->buffer, n, 0);

  printf("nat: udp in %d/%d %s => %s\n",
	 (int)m, (int)n, b->out_name, b->in_name);

  return 0;
}

/* ====================================================================== */

static int new_tcp(struct nat *nat, su_wait_t *wait, struct binding *dummy)
{
  int events;
  su_sockaddr_t from[1];
  socklen_t fromlen = (sizeof from);
  struct binding *b;
  int in, out;
  su_wait_t win[1], wout[1];

  events = su_wait_events(wait, nat->tcp_socket);

  in = accept(nat->tcp_socket, (void *)from, &fromlen);
  if (in < 0) {
    su_perror("new_udp: accept");
    return 0;
  }

  if (nat->fake == NULL) {	/* Xyzzy */
    fprintf(stderr, "test_nat: fake address missing\n");
    su_close(in);
    return -1;
  }

  out = su_socket(nat->fake->li_family, SOCK_STREAM, IPPROTO_TCP);
  if (out < 0) {
    su_perror("new_tcp: socket");
    su_close(in);
    return 0;
  }
  if (bind(out, (void *)nat->fake->li_addr, nat->fake->li_addrlen) < 0) {
    su_perror("new_tcp: bind");
    su_close(in); su_close(out);
    return 0;
  }
  if (connect(out, (void *)nat->out_address, nat->out_addrlen) < 0) {
    su_perror("new_tcp: connect");
    su_close(in); su_close(out);
    return 0;
  }

  if (su_wait_create(win, in, SU_WAIT_IN) < 0) {
    su_perror("new_tcp: su_wait_create");
    su_close(in); su_close(out);
    return 0;
  }
  if (su_wait_create(wout, out, SU_WAIT_IN) < 0) {
    su_perror("new_tcp: su_wait_create");
    su_wait_destroy(win);
    su_close(in); su_close(out);
    return 0;
  }

  b = nat_binding_new(nat, SOCK_STREAM, in, out);

  if (b == NULL) {
    su_perror("new_tcp: nat_binding_new");
    su_close(in); su_close(out);
    return 0;
  }

  b->in_register = su_root_register(nat->root, win, tcp_in_to_out, b, 0);
  if (b->in_register < 0) {
    su_perror("new_tcp: su_root_register");
    su_wait_destroy(win); su_wait_destroy(wout);
    nat_binding_destroy(b);
    return 0;
  }

  b->out_register = su_root_register(nat->root, wout, tcp_out_to_in, b, 0);
  if (b->out_register < 0) {
    su_perror("new_tcp: su_root_register");
    su_wait_destroy(wout);
    nat_binding_destroy(b);
    return 0;
  }

  printf("nat: new TCP binding %s <=> %s\n", b->in_name, b->out_name);

  return 0;
}

static int tcp_in_to_out(struct nat *nat, su_wait_t *wait, struct binding *b)
{
  int events;
  ssize_t n, m, o;

  events = su_wait_events(wait, b->in_socket);

  n = recv(b->in_socket, nat->buffer, sizeof nat->buffer, 0);
  if (n < 0) {
    su_perror("tcp_in_to_out: recv");
    return 0;
  }

  if (n == 0) {
    printf("nat: tcp out FIN %s => %s\n", b->in_name, b->out_name);
    shutdown(b->out_socket, 1);
    su_root_eventmask(nat->root, b->in_register, b->in_socket, 0);
    b->in_closed = 1;
    if (b->out_closed && b->in_closed)
      nat_binding_destroy(b);
    return 0;
  }

  for (m = 0; m < n; m += o) {
    o = send(b->out_socket, nat->buffer + m, n - m, 0);
    if (o < 0) {
      su_perror("tcp_in_to_out: send");
      break;
    }
  }

  printf("nat: tcp out %d/%d %s => %s\n",
	 (int)m, (int)n, b->in_name, b->out_name);

  return 0;
}

static int tcp_out_to_in(struct nat *nat, su_wait_t *wait, struct binding *b)
{
  int events;
  ssize_t n, m, o;

  events = su_wait_events(wait, b->out_socket);

  n = recv(b->out_socket, nat->buffer, sizeof nat->buffer, 0);
  if (n < 0) {
    su_perror("tcp_out_to_in: recv");
    return 0;
  }

  if (n == 0) {
    printf("nat: tcp out FIN %s => %s\n", b->out_name, b->in_name);
    shutdown(b->in_socket, 1);
    su_root_eventmask(nat->root, b->in_register, b->out_socket, 0);
    b->out_closed = 1;
    if (b->out_closed && b->in_closed)
      nat_binding_destroy(b);
    return 0;
  }

  for (m = 0; m < n; m += o) {
    o = send(b->in_socket, nat->buffer + m, n - m, 0);
    if (o < 0) {
      su_perror("tcp_in_to_out: send");
      break;
    }
  }

  printf("nat: tcp in %d/%d %s => %s\n",
	 (int)m, (int)n, b->out_name, b->in_name);

  return 0;
}

static int invalidate_binding(struct binding *b)
{
  struct nat *nat = b->nat;
  su_sockaddr_t addr[1];
  socklen_t addrlen = (sizeof addr);
  int out, out_register;
  su_wait_t wout[1];
  char name[64];

  out = su_socket(nat->fake->li_family, b->socktype, 0);
  if (out < 0) {
    su_perror("new_udp: socket");
    return -1;
  }
  if (bind(out, (void *)nat->fake->li_addr, nat->fake->li_addrlen) < 0) {
    su_perror("new_udp: bind(to)");
    su_close(out);
    return -1;
  }

  if (nat->symmetric)
    if (connect(out, (void *)nat->out_address, nat->out_addrlen) < 0) {
      su_perror("new_udp: connect(to)");
      su_close(out);
      return -1;
    }

  if (su_wait_create(wout, out, SU_WAIT_IN) < 0) {
    su_perror("new_udp: su_wait_create");
    su_close(out);
    return -1;
  }

  if (b->socktype == SOCK_DGRAM)
    out_register = su_root_register(nat->root, wout, udp_out_to_in, b, 0);
  else
    out_register = su_root_register(nat->root, wout, tcp_out_to_in, b, 0);

  if (out_register < 0) {
    su_perror("new_udp: su_root_register");
    su_wait_destroy(wout);
    su_close(out);
    return -1;
  }

  su_root_deregister(nat->root, b->out_register);
  su_close(b->out_socket);

  b->out_socket = out;
  b->out_register = out_register;

  getsockname(out, (void *)addr, &addrlen);
  inet_ntop(addr->su_family, SU_ADDR(addr), name, sizeof name);
  snprintf(b->out_name, sizeof b->out_name,
	   addr->su_family == AF_INET6 ? "[%s]:%u" : "%s:%u",
	   name, ntohs(addr->su_port));

  printf("nat: flushed binding %s <=> %s\n", b->in_name, b->out_name);

  return 0;
}
