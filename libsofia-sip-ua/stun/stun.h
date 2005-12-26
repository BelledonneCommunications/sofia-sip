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
 * @author Martti Mela <Martti.Mela@nokia.com>
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

typedef struct stun_handle_s  stun_handle_t;
typedef struct stun_socket_s  stun_socket_t;
typedef struct stun_request_s stun_request_t;

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

  /* TLS events */
  stun_tls_connecting,
  stun_tls_ssl_connecting,
  stun_tls_writing,
  stun_tls_closing,
  stun_tls_reading,
  stun_tls_done,

  /* STUN bind events */
  stun_bind_init,             /**< Initial state */
  stun_bind_started,          /**< Discovery process started */
  stun_bind_sending,          /**< Sending query to server */
  stun_bind_sent,             /**< Query sent */
  stun_bind_receiving,        /**< Waiting for server to answer */
  stun_bind_processing,       /**< Processing server reply */
  stun_bind_done,             /**< Initial state */

  /* STUN errors */
  /* Do not change the order! */

  stun_error,
  stun_tls_connection_timeout,
  stun_tls_connection_failed,
  stun_tls_ssl_connect_failed,

  /* stun client errors */
  stun_bind_error,
  stun_bind_timeout,

} stun_states_t;


typedef void (*stun_event_f)(stun_magic_t *magic,
			     stun_handle_t *se,
			     stun_request_t *req,
			     stun_states_t event);

/* Return the socket associated with the stun_socket_t structure */
int stun_handle_get_bind_socket(stun_handle_t *se);

char const *stun_str_state(stun_states_t state);

int stun_is_requested(tag_type_t tag, tag_value_t value, ...);

su_root_t *stun_handle_root(stun_handle_t *self);

stun_handle_t *stun_handle_tcreate(stun_magic_t *context,
				   su_root_t *root,
				   stun_event_f cb,
				   tag_type_t tag, tag_value_t value, ...); 

stun_handle_t *stun_handle_create(stun_magic_t *context,
				  su_root_t *root,
				  stun_event_f cb,
				  char const *server,
				  int use_msgint); 

int stun_handle_request_shared_secret(stun_handle_t *se);


void stun_handle_destroy(stun_handle_t *);

int stun_handle_set_bind_socket(stun_handle_t *se, int sockfd);

/** Bind a socket using STUN.  */
int stun_handle_bind(stun_handle_t *se, 
		     /* su_localinfo_t *my_addr, */
		     int *return_lifetime,
		     tag_type_t tag, tag_value_t value,
		     ...);

su_localinfo_t *stun_handle_get_local_addr(stun_handle_t *en);

int stun_handle_get_nattype(stun_handle_t *se,
			    /* su_localinfo_t *my_addr, */
			    int *addrlen);

int stun_handle_get_lifetime(stun_handle_t *se, 
			     su_localinfo_t *my_addr,
			     int *addrlen,
			     int *lifetime);

/** other functions */
int stun_handle_set_uname_pwd(stun_handle_t *se,
			      const char *uname,
			      int len_uname, 
			      const char *pwd,
			      int len_pwd);

char const *stun_nattype(stun_handle_t *se);

#endif /* !defined(STUN_H) */
