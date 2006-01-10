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

SOFIA_BEGIN_DECLS

typedef struct stun_handle_s    stun_handle_t;
typedef struct stun_request_s   stun_request_t;
typedef struct stun_discovery_s stun_discovery_t;

#ifndef STUN_MAGIC_T 
#define STUN_MAGIC_T            struct stun_magic_t
#endif
/** STUN server context */
typedef STUN_MAGIC_T stun_magic_t;

extern char const stun_version[]; /**< Name and version of STUN software */

/**
 * STUN Action types. These define the current discovery process.
 */
typedef enum stun_action_s {
  stun_action_no_action,
  stun_action_binding_request,
  stun_action_keepalive,
  stun_action_get_nattype,
  stun_action_get_lifetime,
} stun_action_t;


/**
 * States of the STUN client->server query process.
 */ 
typedef enum stun_state_e {
  
  stun_no_assigned_event,
  stun_dispose_me,

  /* TLS events */
  stun_tls_connecting,
  stun_tls_ssl_connecting,
  stun_tls_writing,
  stun_tls_closing,
  stun_tls_reading,
  stun_tls_done,

  /* STUN discovery events */
  stun_discovery_init,
  stun_discovery_processing,
  stun_discovery_done,

  /* STUN bind events */
  stun_bind_init,             /**< Initial state */
  stun_bind_processing,       /**< Processing server reply */
  stun_bind_done,             /**< Initial state */

  stun_request_not_found,     /**< Response without matching request */

  /* STUN errors */
  /* Do not change the order! Errors need to be after stun_error */

  stun_error,
  stun_tls_connection_timeout,
  stun_tls_connection_failed,
  stun_tls_ssl_connect_failed,

  /* stun client errors */
  stun_bind_error,
  stun_bind_timeout,

  stun_discovery_timeout,

} stun_state_t;


typedef void (*stun_event_f)(stun_magic_t *magic,
			     stun_handle_t *se,
			     stun_request_t *req,
			     stun_discovery_t *sd,
			     stun_action_t action,
			     stun_state_t event);

/* Return the associated socket */
int stun_handle_get_bind_socket(stun_handle_t *se);

char const *stun_str_state(stun_state_t state);

/** Check if a STUN handle should be created. */
int stun_is_requested(tag_type_t tag, tag_value_t value, ...);

stun_handle_t *stun_handle_create(stun_magic_t *context,
				  su_root_t *root,
				  stun_event_f cb,
				  tag_type_t tag, tag_value_t value, ...); 

void stun_handle_destroy(stun_handle_t *);

su_root_t *stun_handle_root(stun_handle_t *self);

int stun_handle_request_shared_secret(stun_handle_t *se);

/** Bind a socket using STUN.  */
int stun_handle_bind(stun_handle_t *se, 
		     /* su_localinfo_t *my_addr, */
		     int *return_lifetime,
		     tag_type_t tag, tag_value_t value,
		     ...);

int stun_handle_get_nattype(stun_handle_t *se,
			    tag_type_t tag, tag_value_t value,
			    ...);

char const *stun_nattype(stun_discovery_t *sd);

int stun_handle_get_lifetime(stun_handle_t *sh,
			     tag_type_t tag, tag_value_t value,
			     ...);

int stun_lifetime(stun_discovery_t *sd);

/* other functions */
int stun_handle_set_uname_pwd(stun_handle_t *se,
			      const char *uname,
			      int len_uname, 
			      const char *pwd,
			      int len_pwd);

su_localinfo_t *stun_request_get_localinfo(stun_request_t *req);


SOFIA_END_DECLS

#endif /* !defined(STUN_H) */
