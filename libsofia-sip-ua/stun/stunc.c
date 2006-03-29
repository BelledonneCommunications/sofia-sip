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

enum {
  do_secret = 1,
  do_bind = 2,
  do_nat_check = 4,
  do_life_check = 8,
};


#ifndef SU_DEBUG
#define SU_DEBUG 0
#endif
#define SU_LOG (stun_log)
#include <sofia-sip/su_debug.h>

void usage(char *name)
{
  fprintf(stderr, "usage: %s <server> [-s] [-b] [-n] [-l]\n", name);
  exit(1);
}

struct stunc_s {
  su_socket_t  sc_socket;
  int          sc_flags;
};


static
void stunc_lifetime_cb(stunc_t *stunc,
		       stun_handle_t *sh,
		       stun_discovery_t *sd,
		       stun_action_t action,
		       stun_state_t event);

static
void stunc_nattype_cb(stunc_t *stunc,
		      stun_handle_t *sh,
		      stun_discovery_t *sd,
		      stun_action_t action,
		      stun_state_t event);

static
void stunc_bind_cb(stunc_t *stunc,
		   stun_handle_t *sh,
		   stun_discovery_t *sd,
		   stun_action_t action,
		   stun_state_t event);

static
void stunc_ss_cb(stunc_t *stunc,
		 stun_handle_t *sh,
		 stun_discovery_t *sd,
		 stun_action_t action,
		 stun_state_t event)
{
  int err;
  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  stunc->sc_flags &= ~do_secret;
  if (!stunc->sc_flags)
    su_root_break(stun_root(sh));

  switch (event) {
  case stun_tls_done:
    if (stunc->sc_flags & do_bind) {
      err = stun_bind(sh, stunc_bind_cb, stunc,
		      STUNTAG_SOCKET(stunc->sc_socket),
		      STUNTAG_REGISTER_EVENTS(1),
		      TAG_NULL());
    
      if (err < 0) {
	SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_bind()"));
	su_root_break(stun_root(sh));
      }
    }
    break;
    
  case stun_tls_connection_failed:
    SU_DEBUG_0(("%s: Obtaining shared secret failed.\n",
		__func__));
    stunc->sc_flags &= ~do_bind;
    if (!stunc->sc_flags)
      su_root_break(stun_root(sh));

    break;

  case stun_tls_connection_timeout:
    SU_DEBUG_0(("%s: Timeout when obtaining shared secret.\n",
		__func__));
    stunc->sc_flags &= ~do_bind;
    break;

  default:
    break;
  }

  return;
}


static
void stunc_bind_cb(stunc_t *stunc,
		   stun_handle_t *sh,
		   stun_discovery_t *sd,
		   stun_action_t action,
		   stun_state_t event)
{
  su_sockaddr_t sa[1];
  char ipaddr[48];
  socklen_t addrlen;

  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  stunc->sc_flags &= ~do_bind;

  if (!stunc->sc_flags)
    su_root_break(stun_root(sh));

  switch (event) {
  case stun_discovery_done:
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


#if 0
    if (stun_handle_test_lifetime(sh, STUNTAG_SOCKET(s), TAG_NULL()) < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_handle_test_lifetime()"));
      su_root_break(stun_handle_root(sh));
    }
#endif

  break;

  case stun_discovery_timeout:
  case stun_discovery_error:
  case stun_error:
  default:
    break;
  }

  return;
}


static
void stunc_nattype_cb(stunc_t *stunc,
		      stun_handle_t *sh,
		      stun_discovery_t *sd,
		      stun_action_t action,
		      stun_state_t event)
{
  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  stunc->sc_flags &= ~do_nat_check;

  if (!stunc->sc_flags)
    su_root_break(stun_root(sh));

  switch (event) {
  case stun_discovery_timeout:
    SU_DEBUG_3(("%s: NAT type determination timeout.\n", __func__));
    break;

  case stun_discovery_done:
    SU_DEBUG_3(("%s: NAT type determined to be %s.\n", __func__, stun_nattype(sd)));
    break;

  case stun_error:
  default:
    break;
  }

  return;
}


static
void stunc_lifetime_cb(stunc_t *stunc,
		       stun_handle_t *sh,
		       stun_discovery_t *sd,
		       stun_action_t action,
		       stun_state_t event)
{
  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  stunc->sc_flags &= ~do_life_check;

  if (!stunc->sc_flags)
    su_root_break(stun_root(sh));

  switch (event) {
  case stun_discovery_timeout:
    SU_DEBUG_3(("%s: Lifetime determination timeout.\n", __func__));
    break;

  case stun_discovery_done:
    SU_DEBUG_3(("%s: Lifetime determined to be %d.\n", __func__, stun_lifetime(sd)));
    break;

  case stun_error:
  default:
    break;
  }

  return;
}


int main(int argc, char *argv[])
{
  int err, i, sflags = 0;
  stunc_t stunc[1]; 
  su_root_t *root = su_root_create(stunc);
  stun_handle_t *sh;
  su_sockaddr_t sa[1];
  su_socket_t s;

  if (!argv[1] || !argv[2] || inet_pton(AF_INET, argv[1], sa) < 1)
    usage(argv[0]);

  for (i = 2; argv[i]; i++) {
    if (strcmp(argv[i], "-s") == 0)
      sflags |= do_secret;
    else if (strcmp(argv[i], "-b") == 0)
      sflags |= do_bind;
    else if (strcmp(argv[i], "-n") == 0)
      sflags |= do_nat_check;
    else if (strcmp(argv[i], "-l") == 0)
      sflags |= do_life_check;
    else
      usage(argv[0]);
  }

  /* Running this test requires a local STUN server on default port */
  sh = stun_handle_init(root,
			STUNTAG_SERVER(argv[1]), 
			STUNTAG_REQUIRE_INTEGRITY(sflags & do_secret),
			TAG_NULL()); 

  if (!sh) {
    SU_DEBUG_0(("%s: %s failed\n", __func__, "stun_handle_init()"));
    return -1;
  }

  s = su_socket(AF_INET, SOCK_DGRAM, 0); 
  if (s == -1) {
    SU_DEBUG_0(("%s: %s  failed: %s\n", __func__,
		"su_socket()", su_gli_strerror(errno)));
    return -1;
  }

  stunc->sc_socket = s;
  stunc->sc_flags = sflags;

  if (sflags & do_secret) {
    if (stun_obtain_shared_secret(sh, stunc_ss_cb, stunc, TAG_NULL()) < 0) {
      SU_DEBUG_3(("%s: %s failed\n", __func__,
		  "stun_handle_request_shared_secret()"));
      return -1;
    }
  }


  /* If we want to bind and no integrity required */
  if ((sflags & do_bind) && !(sflags & do_secret)) {
    err = stun_bind(sh, stunc_bind_cb, stunc,
		    STUNTAG_SOCKET(s),
		    STUNTAG_REGISTER_EVENTS(1),
		    TAG_NULL());
    
    if (err < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_bind()"));
      return -1;
    }
  }

  if (sflags & do_nat_check) {
    err = stun_test_nattype(sh, stunc_nattype_cb, stunc,
			    STUNTAG_REGISTER_EVENTS(1),
			    STUNTAG_SOCKET(stunc->sc_socket),
			    TAG_NULL());
    
    if (err < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_test_nattype()"));
      su_root_break(stun_root(sh));
    }
  }

  if (sflags & do_life_check) {
    err = stun_test_lifetime(sh, stunc_lifetime_cb, stunc,
			     STUNTAG_REGISTER_EVENTS(1),
			     STUNTAG_SOCKET(stunc->sc_socket),
			     TAG_NULL());
    
    if (err < 0) {
      SU_DEBUG_0(("%s: %s  failed\n", __func__, "stun_test_lifetime()"));
      su_root_break(stun_root(sh));
    }
  }
  
  su_root_run(root);

  stun_handle_destroy(sh);
  su_root_destroy(root);

  return 0;
}
