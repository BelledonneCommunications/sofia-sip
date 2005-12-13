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

#ifndef STUN_H /** Defined when stun.h has been included. */
#define STUN_H
/**@file stun.h STUN client interface
 *
 * @author Tat Chan <Tat.Chan@nokia.com>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 */

#ifndef SU_WAIT_H
#include <su_wait.h>
#endif
#ifndef SU_TAG_H
#include <su_tag.h>
#endif
#include "stun_common.h"

#include <su_localinfo.h>

typedef struct stun_engine_s stun_engine_t;
typedef struct stun_socket_s stun_socket_t;

#ifndef STUN_MAGIC_T 
#define STUN_MAGIC_T            struct stun_magic_t
#endif
/** STUN server context */
typedef STUN_MAGIC_T stun_magic_t;


extern char const stun_version[]; /**< Name and version of STUN software */

/**
 * States of the STUN client->server query process.
 */ 
typedef enum stun_states_e {

  /* stun engine errors */
  stun_connect_error = -10,
  stun_no_shared_secret_obtained = -9,

  /* stun client errors */
  stun_client_error = -5,            /**< Sending query to server */
  stun_client_timeout = -1,

  /* stun_engine related */
  stun_shared_secret_obtained = 0,
  stun_connect_success,


  /* client: stun socket */
  stun_client_init,             /**< Initial state */
  stun_client_started,          /**< Discovery process started */
  stun_client_sending,          /**< Sending query to server */
  stun_client_sent,             /**< Query sent */
  stun_client_receiving,        /**< Waiting for server to answer */
  stun_client_received,         /**< Server answered */
  stun_client_processing,       /**< Processing server reply */
  stun_client_done,             /**< Initial state */

} stun_states_t;

int stun_is_requested(tag_type_t tag, tag_value_t value, ...);

typedef void (*stun_event_f)(stun_magic_t *magic,
			     stun_engine_t *se,
			     stun_states_t event);

su_root_t *stun_engine_root(stun_engine_t *self);

stun_engine_t *stun_engine_tcreate(stun_magic_t *context,
				   su_root_t *root,
				   stun_event_f cb,
				   tag_type_t tag, tag_value_t value, ...); 

stun_engine_t *stun_engine_create(stun_magic_t *context,
				  su_root_t *root,
				  stun_event_f cb,
				  char const *server,
				  int use_msgint); 

void stun_engine_destroy(stun_engine_t *);

stun_socket_t *stun_socket_create(stun_engine_t *se, int sockfd);
void stun_socket_destroy(stun_socket_t *ss);

/** Bind a socket using STUN.  */
int stun_bind(stun_socket_t *ss, 
	      su_localinfo_t *my_addr,
	      int *return_lifetime);

int stun_get_nattype(stun_socket_t *ss,
		     su_localinfo_t *my_addr,
		     int *addrlen);

int stun_get_lifetime(stun_socket_t *ss, 
		      su_localinfo_t *my_addr, int *addrlen,
		      int *lifetime);

/** other functions */
int stun_set_uname_pwd(stun_engine_t *se, const char *uname, int len_uname, 
		       const char *pwd, int len_pwd);

char const *stun_nattype(stun_engine_t *se);

#endif /* !defined(STUN_H) */
