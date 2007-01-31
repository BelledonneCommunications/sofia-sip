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

/**@ingroup su_wait
 * @CFILE su_pthread_port.c
 *
 * OS-Independent Socket Syncronization Interface with pthreads
 *
 * This implements #su_msg_t message passing functionality using pthreads.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 *
 * @date Created: Tue Sep 14 15:51:04 1999 ppessi
 */

#include "config.h"

#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define su_pthread_port_s su_port_s

#include "sofia-sip/su.h"
#include "su_port.h"
#include "sofia-sip/su_alloc.h"

#if 1
#define PORT_LOCK_DEBUG(x)  ((void)0)
#else
#define PORT_LOCK_DEBUG(x)  printf x
#endif

#if HAVE_SOCKETPAIR
#define SU_MBOX_SEND 1
#else
#define SU_MBOX_SEND 0
#endif

/** @internal Message box wakeup function. */
static int su_mbox_port_wakeup(su_root_magic_t *magic, /* NULL */
			       su_wait_t *w,
			       su_wakeup_arg_t *arg)
{
  char buf[32];
  su_socket_t socket = *(su_socket_t*)arg;
  su_wait_events(w, socket);
  recv(socket, buf, sizeof(buf), 0);
  return 0;
}

/**@internal
 *
 * Initializes a message port. It creates a mailbox used to wake up the
 * thread waiting on the port if needed. Currently, the mailbox is a
 * socketpair or an UDP socket connected to itself.
 */
int su_pthread_port_init(su_port_t *self, su_port_vtable_t const *vtable)
{
  SU_DEBUG_9(("su_pthread_port_init(%p, %p) called\n", self, vtable));

  if (su_base_port_init(self, vtable) == 0 &&
      su_base_port_threadsafe(self) == 0) {
    int af;
    su_socket_t mb = INVALID_SOCKET;
    su_wait_t wait[1] = { SU_WAIT_INIT };
    char const *why;

    self->sup_tid = pthread_self();

#if HAVE_SOCKETPAIR
#if defined(AF_LOCAL)
    af = AF_LOCAL;
#else
    af = AF_UNIX;
#endif
    if (socketpair(af, SOCK_STREAM, 0, self->sup_mbox) == -1) {
      why = "socketpair"; goto error;
    }

    mb = self->sup_mbox[0];
    su_setblocking(self->sup_mbox[1], 0);

#else
    {
      struct sockaddr_in sin = { sizeof(struct sockaddr_in), 0 };
      socklen_t sinsize = sizeof sin;
      struct sockaddr *sa = (struct sockaddr *)&sin;

      af = PF_INET;

      self->sup_mbox[0] = mb = su_socket(af, SOCK_DGRAM, IPPROTO_UDP);
      if (mb == INVALID_SOCKET) {
	why = "socket"; goto error;
      }
  
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.1 */
      
      /* Get a port for us */
      if (bind(mb, sa, sizeof sin) == -1) {
	why = "bind"; goto error;
      }

      if (getsockname(mb, sa, &sinsize) == -1) {
	why = "getsockname"; goto error;
      }
    
      if (connect(mb, sa, sinsize) == -1) {
	why = "connect"; goto error;
      }
    }
#endif    

    su_setblocking(mb, 0);

    if (su_wait_create(wait, mb, SU_WAIT_IN) == -1) {
      why = "su_wait_create";
      goto error;
    }

    self->sup_mbox_index = su_port_register(self, NULL, wait, 
					    su_mbox_port_wakeup, 
					    (void *)self->sup_mbox, 0);

    if (self->sup_mbox_index <= 0) {
      why = "su_port_register";
      su_wait_destroy(wait);
      goto error;
    }

    SU_DEBUG_9(("%s() returns %d\n", "su_pthread_port_init", 0));

    return 0;

  error:
    su_log("%s: %s: %s\n", 
	   "su_pthread_port_init", why, su_strerror(su_errno()));
    su_pthread_port_deinit(self);
  }

  SU_DEBUG_9(("%s() returns %d\n", "su_pthread_port_init", -1));

  return -1;
}

/** @internal Deinit a base implementation of port. */
void su_pthread_port_deinit(su_port_t *self)
{
  assert(self);

  if (self->sup_mbox_index > 0)
    su_port_deregister(self, self->sup_mbox_index);
  self->sup_mbox_index = 0;

  if (self->sup_mbox[0] && self->sup_mbox[0] != INVALID_SOCKET)
    su_close(self->sup_mbox[0]); self->sup_mbox[0] = INVALID_SOCKET;
#if HAVE_SOCKETPAIR
  if (self->sup_mbox[1] && self->sup_mbox[1] != INVALID_SOCKET)
    su_close(self->sup_mbox[1]); self->sup_mbox[1] = INVALID_SOCKET;
#endif

  su_base_port_deinit(self);
}

void su_pthread_port_lock(su_port_t *self, char const *who)
{
  PORT_LOCK_DEBUG(("%p at %s locking(%p)...",
		   (void *)pthread_self(), who, self));

  su_home_mutex_lock(self->sup_base->sup_home);

  PORT_LOCK_DEBUG((" ...%p at %s locked(%p)...", 
		   (void *)pthread_self(), who, self));
}

void su_pthread_port_unlock(su_port_t *self, char const *who)
{
  su_home_mutex_unlock(self->sup_base->sup_home);

  PORT_LOCK_DEBUG((" ...%p at %s unlocked(%p)\n", 
		   (void *)pthread_self(), who, self));
}

/** @internal Send a message to the port. */
int su_pthread_port_send(su_port_t *self, su_msg_r rmsg)
{
  int wakeup = su_base_port_send(self, rmsg);

  if (wakeup < 0)
    return -1;
  if (wakeup == 0)
    return 0;

  assert(self->sup_mbox[SU_MBOX_SEND] != INVALID_SOCKET);

  if (send(self->sup_mbox[SU_MBOX_SEND], "X", 1, 0) == -1) {
#if HAVE_SOCKETPAIR
    if (su_errno() != EWOULDBLOCK)
#endif
      su_perror("su_msg_send: send()");
  }
  return 0;
}

/** @internal
 * Checks if the calling thread owns the port object.
 *
 * @param self pointer to a port object
 *
 * @retval true (nonzero) if the calling thread owns the port,
 * @retval false (zero) otherwise.
 */
int su_pthread_port_own_thread(su_port_t const *self)
{
  return self == NULL || 
    pthread_equal(self->sup_tid, pthread_self());
}
