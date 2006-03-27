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

#include "sofia-sip/stun.h"
#include "sofia-sip/stun_tag.h"
#include <sofia-sip/su.h>


#ifndef SU_DEBUG
#define SU_DEBUG 0
#endif
#define SU_LOG (stun_log)
#include <sofia-sip/su_debug.h>

char const *name = "stunc";

/* Our UDP socket */
su_socket_t s;

void usage(int exitcode)
{
  fprintf(stderr, "usage: %s server use_msgint\n", name);
  exit(exitcode);
}

struct stunc_s {
  int nothing; 
};


void stunc_callback(stunc_t *stunc, stun_handle_t *sh,
		    stun_request_t *req,
		    stun_discovery_t *sd,
		    stun_action_t action,
		    stun_state_t event)
{
  su_sockaddr_t *sa = NULL;
  char ipaddr[48];
  char const *nattype;
  int lifetime;

  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  switch (event) {
  case stun_tls_done:
  case stun_tls_connection_failed:
  case stun_tls_connection_timeout:
    SU_DEBUG_0(("%s: TLS query done, start binding process.\n", __func__));
    if (stun_handle_bind(sh, STUNTAG_SOCKET(s), TAG_NULL()) < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_bind()"));
      su_root_break(stun_handle_root(sh));
    }
    break;

  case stun_discovery_done:
    if (action == stun_action_test_nattype) {
      nattype = stun_nattype(sd);
      SU_DEBUG_0(("%s: NAT type: %s\n", __func__, nattype));
    }
    else if (action == stun_action_test_lifetime) {
      lifetime = stun_lifetime(sd);
      SU_DEBUG_0(("%s: Life time is %d s.\n", __func__, lifetime));
      su_root_break(stun_handle_root(sh));
    }

    break;
    
  case stun_bind_done:
    sa = stun_discovery_get_address(sd);
    SU_DEBUG_0(("%s: local address NATed as %s:%u\n", __func__,
		inet_ntop(sa->su_family, SU_ADDR(sa),
			  ipaddr, sizeof(ipaddr)),
		(unsigned) ntohs(sa->su_port)));
    /* su_root_break(stun_handle_root(sh)); */

    /* XXX: do not work (2006/03;kv) */
#if 0
    if (stun_test_nattype(sh, STUNTAG_SOCKET(s), TAG_NULL()) < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_test_nattype()"));
      su_root_break(stun_handle_root(sh));
    }

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
    break;
  }

  return;
}


int main(int argc, char *argv[])
{
  int msg_integrity;
  stunc_t stunc[1]; 
  su_root_t *root = su_root_create(stunc);
  stun_handle_t *sh;
  

  if (argc != 3)
    usage(1);

  msg_integrity = atoi(argv[2]);

  /* Running this test requires a local STUN server on default port */
  sh = stun_handle_create(stunc,
			  root,
			  stunc_callback,
			  STUNTAG_SERVER(argv[1]), 
			  STUNTAG_REQUIRE_INTEGRITY(msg_integrity),
			   TAG_NULL()); 

  if (!sh) {
    SU_DEBUG_0(("%s: %s failed\n", __func__, "stun_handle_tcreate()"));
    return -1;
  }

  s = su_socket(AF_INET, SOCK_DGRAM, 0); 
  if (s == -1) {
    SU_DEBUG_0(("%s: %s  failed: %s\n", __func__, "stun_socket_create()", su_gli_strerror(errno)));
    return -1;
  }

  if (msg_integrity == 1) {
    if (stun_handle_request_shared_secret(sh) < 0) {
      SU_DEBUG_3(("%s: %s failed\n", __func__, "stun_handle_request_shared_secret()"));
      return -1;
    }
    su_root_run(root);
    stun_handle_destroy(sh);
    return 0;
  }

  /* If no TSL query, start bind here */
  if (stun_handle_bind(sh, STUNTAG_SOCKET(s), TAG_NULL()) < 0) {
    SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_bind()"));
    return -1;
  }
  su_root_run(root);

  stun_handle_destroy(sh);

  return 0;
}
