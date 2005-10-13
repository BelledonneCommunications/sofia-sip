/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * * This library is free software; you can redistribute it and/or
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

/**@ingroup msg
 * @CFILE msg.c Message object implementation.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Thu Jun  8 19:28:55 2000 ppessi
 *
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

#include <assert.h>

#include <su_alloc.h>		/* XXX */
#include <su.h>

#include "msg_internal.h"
#include "msg_parser.h"
#include "msg_mclass.h"

/**
 * Create a message.
 *
 * @relates msg_s
 *
 * @param mc    message class
 * @param flags message control flags
 */
msg_t *msg_create(msg_mclass_t const *mc, int flags)
{
  msg_t *msg = su_home_clone(NULL, sizeof(*msg) + mc->mc_msize);

  if (msg) {
    if ((flags & MSG_FLG_THRDSAFE) &&
	su_home_threadsafe(msg->m_home) < 0) {
      su_home_zap(msg->m_home);
      return NULL;
    }

    msg->m_refs++;
    msg->m_tail = &msg->m_chain;
    msg->m_addrinfo.ai_addrlen = sizeof(msg->m_addr);
    msg->m_addrinfo.ai_addr = &msg->m_addr->su_sa;
    msg->m_maxsize = 0;

    flags &= MSG_FLG_USERMASK;

    msg->m_class = mc;
    msg->m_oflags = flags;
    msg->m_object = (void *)(msg + 1);
    msg->m_object->msg_size = mc->mc_msize;
    msg->m_object->msg_flags = mc->mc_flags | flags;
    msg->m_object->msg_common->h_class = (void *)mc;
  }

  return msg;
}

/**Increment a message reference count.
 *
 * @relates msg_s
 *
 * The function msg_ref_create() creates a reference to a message.  The
 * referenced message is not freed until all the references have been
 * destroyed.
 *
 * @param msg   message of which a reference is created
 * 
 * @return
 * The function msg_ref_create() returns a reference to a message.
 */
msg_t *msg_ref_create(msg_t *msg)
{
  if (msg) {
    su_home_mutex_lock(msg->m_home);
    msg->m_refs++;
    su_home_mutex_unlock(msg->m_home);
  }
  return msg;
}

/** Destroy a reference to a message.
 *
 * @relates msg_s
 */
void msg_ref_destroy(msg_t *ref)
{
  msg_destroy(ref);
}

/**Deinitialize and free a message.
 *
 * @relates msg_s
 *
 * @param msg  message to be destroyed
 */
void msg_destroy(msg_t *msg)
{
  msg_t *parent;
  
  for (; msg; msg = parent) {
    int refs;
    su_home_mutex_lock(msg->m_home);
    parent = msg->m_parent;
    if (msg->m_refs)
      msg->m_refs--;
    refs = msg->m_refs;
    su_home_mutex_unlock(msg->m_home);
    if (refs)
      break;
    su_home_zap(msg->m_home);
  }
}

/* Message object routines */

/**Retrieve public message structure.
 *
 * This function returns a pointer to the public message structure.
 * 
 * @param msg pointer to msg object
 * 
 * @returns
 * A pointer to the public message structure, or NULL if none.
 */
msg_pub_t *msg_object(msg_t const *msg)
{
  if (msg)
    return msg->m_object;
  else
    return NULL;
}

/**Retrieve public message structure of given type.
 *
 * @relates msg_s
 *
 * This function returns a pointer to the public message structure of the
 * given protocol.
 * 
 * @param msg pointer to msg object
 * @param tag tag of public message structure
 * 
 * @returns
 * A pointer to the public message structure, or NULL if there is none or
 * the message is not for desired protocol.
 */
msg_pub_t *msg_public(msg_t const *msg, void *tag)
{
  if (msg && msg->m_class->mc_tag == tag)
    return msg->m_object;
  else
    return NULL;
}

/**Retrieve message class.
 *
 * @relates msg_s
 *
 * The function msg_mclass() returns a pointer to the message class object
 * (factory object for the message).
 * 
 * @param msg pointer to msg object
 * 
 * @returns
 * A pointer to the message class, or NULL if none.
 */
msg_mclass_t const *msg_mclass(msg_t const *msg)
{
  if (msg)
    return msg->m_class;
  else
    return NULL;
}

/* Address management */

/** Zero the message address */ 
void msg_addr_zero(msg_t *msg)
{
  memset(&msg->m_addr, 0, sizeof(&msg->m_addr));
  memset(&msg->m_addrinfo, 0, sizeof(&msg->m_addrinfo));

  msg->m_addrinfo.ai_addrlen = sizeof(msg->m_addr);
  msg->m_addrinfo.ai_addr = &msg->m_addr->su_sa;
}

/** Get pointer to address length. */
socklen_t *msg_addrlen(msg_t *msg)
{
  return &msg->m_addrinfo.ai_addrlen;
}

/** Get socket address structure. */
su_sockaddr_t *msg_addr(msg_t *msg)
{
  return msg ? msg->m_addr : 0;
}

/** Get addrinfo structure. */
su_addrinfo_t *msg_addrinfo(msg_t *msg)
{
  return msg ? &msg->m_addrinfo : 0;
}

/**Copy message address.
 */
void msg_addr_copy(msg_t *dst, msg_t const *src)
{
  dst->m_addrinfo = src->m_addrinfo;
  dst->m_addrinfo.ai_next = NULL;
  dst->m_addrinfo.ai_canonname = NULL;
  memcpy(dst->m_addrinfo.ai_addr = &dst->m_addr->su_sa, 
	 src->m_addr, src->m_addrinfo.ai_addrlen);
  if (dst->m_addrinfo.ai_addrlen < sizeof(dst->m_addr))
    memset((char *)dst->m_addr + dst->m_addrinfo.ai_addrlen, 0, 
	   sizeof(dst->m_addr) - dst->m_addrinfo.ai_addrlen);
}


/** Get error classification flags */
unsigned msg_extract_errors(msg_t const *msg)
{
  return msg ? msg->m_extract_err : (unsigned)-1;
}


/** Get error number associated with message */
int msg_errno(msg_t const *msg)
{
  return msg ? msg->m_errno : EINVAL;
}

/** Set error number associated with message */
void msg_set_errno(msg_t *msg, int err)
{
  if (msg)
    msg->m_errno = err;
}
