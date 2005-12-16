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
 * @date Last modified: Wed Jul 20 20:35:55 2005 kaiv
 */

#include "config.h" 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct stunc_s stunc_t;
#define SU_ROOT_MAGIC  stunc_t
#define STUN_MAGIC_T   stunc_t

#include "stun.h"
#include "stun_tag.h"
#include <su.h>

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif
#define SU_LOG (stun_log)
#include <su_debug.h>

char const *name = "stunc";

void usage(int exitcode)
{
  fprintf(stderr, "usage: %s server use_msgint\n", name);
  exit(exitcode);
}

struct stunc_s {
  int kakka; 
};


void stunc_callback(stunc_t *stunc, stun_handle_t *en, stun_socket_t *ss, stun_states_t event)
{
  su_localinfo_t *li = NULL;

  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  if (event == stun_client_done) {
    char ipaddr[48];
    li = stun_get_local_addr(en);
    inet_ntop(li->li_family, SU_ADDR(li->li_addr), ipaddr, sizeof(ipaddr)),
    SU_DEBUG_3(("%s: local address NATed as %s:%u\n", __func__,
		ipaddr, (unsigned) ntohs(li->li_addr->su_port)));
    su_root_break(stun_handle_root(en));
  }
  else if (event == stun_client_error) {
    SU_DEBUG_3(("%s: no nat detected\n", __func__));
    su_root_break(stun_handle_root(en));
  }

  if (event == stun_client_done || event == stun_client_error ||
      event == stun_client_connection_timeout || event ||
      stun_client_connection_failed) {
    su_root_break(stun_handle_root(en));
  }



  return;
}


int main(int argc, char *argv[])
{
  int s, lifetime;
  int msg_integrity;
  //socklen_t addrlen;
  stunc_t stunc[1]; 
  su_root_t *root = su_root_create(stunc);
  stun_handle_t *se;
  stun_socket_t *ss;
  

  if (argc != 3)
    usage(1);

  msg_integrity = atoi(argv[2]);

  /* Running this test requires a local STUN server on default port */
  se = stun_handle_tcreate(stunc,
			   root,
			   stunc_callback,
			   STUNTAG_SERVER(argv[1]), 
			   STUNTAG_INTEGRITY(msg_integrity),
			   TAG_NULL()); 

  if (!se) {
    SU_DEBUG_3(("%s: %s failed\n", __func__, "stun_handle_tcreate()"));
    return -1;
  }

  if (msg_integrity == 1 && stun_connect_start(se) < 0) {
    SU_DEBUG_3(("%s: %s failed\n", __func__, "stun_connect_start()"));
    return -1;
  }
 else if (msg_integrity == 1)
   su_root_run(root);

  s = su_socket(AF_INET, SOCK_DGRAM, 0); 
  
  if (s == -1) {
    SU_DEBUG_3(("%s: %s  failed: %s\n", __func__, "stun_socket_create()", su_gli_strerror(errno)));
    return -1;
  }

  ss = stun_socket_create(se, s);
  
  if (ss == NULL) {
    SU_DEBUG_3(("%s: %s  failed\n", __func__, "stun_socket_create()"));
    return -1;
  }
  
  lifetime = 0;

  if (stun_bind(ss, &lifetime) < 0) {
    SU_DEBUG_3(("%s: %s  failed\n", __func__, "stun_bind()"));
    return -1;
  }

  su_root_run(root);

  stun_socket_destroy(ss);
  stun_handle_destroy(se);

  return 0;
}
