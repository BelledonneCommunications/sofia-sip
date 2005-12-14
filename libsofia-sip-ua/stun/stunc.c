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


void stunc_callback(stunc_t *stunc, stun_engine_t *en, stun_states_t event);


void stunc_callback(stunc_t *stunc, stun_engine_t *en, stun_states_t event)
{
  su_localinfo_t *li = NULL;

  if (event < 0)
    su_root_break(stun_engine_root(en));

  if (event == stun_client_done) {
    char ipaddr[48];
    li = stun_get_local_addr(en);
    inet_ntop(li->li_family, SU_ADDR(li->li_addr), ipaddr, sizeof(ipaddr)),
    SU_DEBUG_3(("%s: local address NATed as %s:%u\n", __func__,
		ipaddr, (unsigned) ntohs(li->li_addr->su_port)));
    su_root_break(stun_engine_root(en));
  }
  else if (event == stun_client_error) {
    SU_DEBUG_3(("%s: no nat detected\n", __func__));
    su_root_break(stun_engine_root(en));
  }
  return;
}


int main(int argc, char *argv[])
{
  int result;
  int s, lifetime;
  //socklen_t addrlen;
  stunc_t stunc[1]; 
  su_root_t *root = su_root_create(stunc);
  stun_engine_t *se;
  stun_socket_t *ss;
  

  if (argc != 3)
    usage(1);

  /* Running this test requires a local STUN server on default port */
  se = stun_engine_create(stunc, root, stunc_callback, argv[1], atoi(argv[2]));

  if (!se) {
    SU_DEBUG_3(("%s: %s", __func__, "stun_engine_create"));
    return -1;
  }

  su_root_run(root);

  if (se == NULL) { perror("stun_engine_create"); exit(1); }

  s = socket(AF_INET, SOCK_DGRAM, 0); 
  
  if (s == -1) { perror("socket"); exit(1); }

  ss = stun_socket_create(se, s);

  if (ss == NULL) { perror("stun_socket_create"); exit(1); }
  
  lifetime = 0;

  result = stun_bind(ss, &lifetime); 

  su_root_run(root);

  stun_socket_destroy(ss);
  stun_engine_destroy(se);

  return 0;
}
