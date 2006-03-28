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

/**
 * @file stunc.c STUN test client
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Jul 24 17:21:00 2003 ppessi
 */

#include "config.h" 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct stunc_s stunc_t;
#define SU_ROOT_MAGIC  stunc_t
#define STUN_MAGIC_T   stunc_t
#define STUN_DISCOVERY_MAGIC_T  stunc_t

#include "sofia-sip/stun.h"
#include "sofia-sip/stun_tag.h"
#include <sofia-sip/su.h>


#ifndef SU_DEBUG
#define SU_DEBUG 0
#endif
#define SU_LOG (stun_log)
#include <sofia-sip/su_debug.h>

char const *name = "stunc";

void usage(int exitcode)
{
  fprintf(stderr, "usage: %s server <use message integrity> <determine NAT type>\n", name);
  exit(exitcode);
}

struct stunc_s {
  su_socket_t  sc_socket;
  int          sc_test_nattype;
};


static
void stunc_nattype_cb(stunc_t *stunc,
		      stun_handle_t *sh,
		      stun_request_t *req,
		      stun_discovery_t *sd,
		      stun_action_t action,
		      stun_state_t event);

static
void stunc_bind_cb(stunc_t *stunc,
		   stun_handle_t *sh,
		   stun_request_t *req,
		   stun_discovery_t *sd,
		   stun_action_t action,
		   stun_state_t event);

static
void stunc_ss_cb(stunc_t *stunc,
		 stun_handle_t *sh,
		 stun_request_t *req,
		 stun_discovery_t *sd,
		 stun_action_t action,
		 stun_state_t event)
{
  int err;
  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  switch (event) {
  case stun_tls_done:
    err = stun_bind(sh, stunc_bind_cb, stunc,
		    STUNTAG_SOCKET(stunc->sc_socket),
		    STUNTAG_REGISTER_EVENTS(1),
		    TAG_NULL());

    if (err < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_bind()"));
      su_root_break(stun_handle_root(sh));
    }

  case stun_tls_connection_failed:
    SU_DEBUG_0(("%s: Obtaining shared secret failed, starting binding process.\n",
		__func__));

    err = stun_bind(sh, stunc_bind_cb, stunc,
		    STUNTAG_SOCKET(stunc->sc_socket),
		    STUNTAG_REGISTER_EVENTS(1),
		    TAG_NULL());

    if (err < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_bind()"));
      su_root_break(stun_handle_root(sh));
    }
    break;

  case stun_tls_connection_timeout:
    SU_DEBUG_0(("%s: Timeout when obtaining shared secret, starting binding process.\n",
		__func__));

    err = stun_bind(sh, stunc_bind_cb, stunc,
		    STUNTAG_SOCKET(stunc->sc_socket),
		    STUNTAG_REGISTER_EVENTS(1),
		    TAG_NULL());

    if (err < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_bind()"));
      su_root_break(stun_handle_root(sh));
    }
    break;

  default:
    su_root_break(stun_handle_root(sh));
    break;
  }

  return;
}


static
void stunc_bind_cb(stunc_t *stunc,
		   stun_handle_t *sh,
		   stun_request_t *req,
		   stun_discovery_t *sd,
		   stun_action_t action,
		   stun_state_t event)
{
  su_sockaddr_t sa[1];
  char ipaddr[48];
  char const *nattype;
  int lifetime, err;
  socklen_t addrlen;

  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  switch (event) {
  case stun_bind_done:
    addrlen = sizeof(*sa);
    memset(sa, 0, addrlen);
    
    if (stun_discovery_get_address(sd, sa, &addrlen) < 0) {
      return;
      SU_DEBUG_0(("%s: stun_discovery_get_address() failed", __func__));
    }

    SU_DEBUG_0(("%s: local address NATed as %s:%u\n", __func__,
		inet_ntop(sa->su_family, SU_ADDR(sa),
			  ipaddr, sizeof(ipaddr)),
		(unsigned) ntohs(sa->su_port)));

    if (stunc->sc_test_nattype) {
      err = stun_test_nattype(sh, stunc_nattype_cb, stunc,
			      STUNTAG_REGISTER_EVENTS(1),
			      STUNTAG_SOCKET(stunc->sc_socket),
			      TAG_NULL());

      if (err < 0) {
	SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_test_nattype()"));
	su_root_break(stun_handle_root(sh));
      }
    }
    else
      su_root_break(stun_handle_root(sh));

#if 0
    if (stun_handle_test_lifetime(sh, STUNTAG_SOCKET(s), TAG_NULL()) < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_test_lifetime()"));
      su_root_break(stun_handle_root(sh));
    }
#endif

  break;

  case stun_discovery_timeout:
    if (action == stun_action_binding_request) {
      su_root_break(stun_handle_root(sh));
    }
    break;

  case stun_bind_error:
  case stun_error:
/*     su_root_break(stun_handle_root(sh)); */

  case stun_bind_timeout:
  default:
    su_root_break(stun_handle_root(sh));
    break;
  }

  return;
}


static
void stunc_nattype_cb(stunc_t *stunc,
		      stun_handle_t *sh,
		      stun_request_t *req,
		      stun_discovery_t *sd,
		      stun_action_t action,
		      stun_state_t event)
{
  su_sockaddr_t sa[1];
  char ipaddr[48];
  char const *nattype;
  int lifetime;
  socklen_t addrlen;

  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  switch (event) {

  case stun_discovery_timeout:
    if (action == stun_action_binding_request) {
      su_root_break(stun_handle_root(sh));
    }
    break;

  case stun_discovery_done:
    SU_DEBUG_3(("%s: NAT type determined to be %s.\n", __func__, stun_nattype(sd)));

  case stun_error:
  default:
    su_root_break(stun_handle_root(sh));
    break;
  }

  return;
}


int main(int argc, char *argv[])
{
  int param_integrity, param_nattype, err;
  stunc_t stunc[1]; 
  su_root_t *root = su_root_create(stunc);
  stun_handle_t *sh;

  /* Our UDP socket */
  su_socket_t s;

  if (argc != 4)
    usage(1);

  param_integrity = atoi(argv[2]);

  param_nattype = atoi(argv[3]);

  /* Running this test requires a local STUN server on default port */
  sh = stun_handle_init(root,
			STUNTAG_SERVER(argv[1]), 
			STUNTAG_REQUIRE_INTEGRITY(param_integrity),
			TAG_NULL()); 

  if (!sh) {
    SU_DEBUG_0(("%s: %s failed\n", __func__, "stun_handle_init()"));
    return -1;
  }

  s = su_socket(AF_INET, SOCK_DGRAM, 0); 
  if (s == -1) {
    SU_DEBUG_0(("%s: %s  failed: %s\n", __func__, "su_socket()", su_gli_strerror(errno)));
    return -1;
  }

  stunc->sc_socket = s;
  stunc->sc_test_nattype = param_nattype;

  if (param_integrity == 1) {
    if (stun_obtain_shared_secret(sh, stunc_ss_cb, stunc, TAG_NULL()) < 0) {
      SU_DEBUG_3(("%s: %s failed\n", __func__, "stun_handle_request_shared_secret()"));
      return -1;
    }
    su_root_run(root);
    stun_handle_destroy(sh);
    return 0;
  }

  /* If no TSL query, start bind here */
  err = stun_bind(sh, stunc_bind_cb, stunc,
		  STUNTAG_SOCKET(s),
		  STUNTAG_REGISTER_EVENTS(1),
		  TAG_NULL());

  if (err < 0) {
    SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_bind()"));
    return -1;
  }
  su_root_run(root);

  stun_handle_destroy(sh);

  return 0;
}
