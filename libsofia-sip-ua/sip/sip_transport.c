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

/**@CFILE sip_transport.c
 *
 * SIP transport objects.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created      : Tue Jun 13 02:57:51 2000 ppessi
 * @date Last modified: Wed Jul 20 20:35:43 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <su_alloc.h>
#include <su.h>
#include <su_time.h>
#include <su_debug.h>

#include <nta.h>
#include "sip_agent.h"
#include "sip_header.h"
#include "sip_util.h"
#include "sip_transport.h"

struct sip_tport_s 
{
  su_home_t     tp_home[1];
  sip_tport_t  *tp_next;
  su_root_t    *tp_root;
  msg_stream_t *tp_stream;
  sip_via_t    *tp_via;
}

sip_tport_t *sip_tport_create(su_root_t *root, 
			      nta_agent_t *agent,
			      url_t const *url,
			      char const * const *url_params)
{
  sip_tport_t *self = su_home_clone(agent, sizeof(*self));
  
  if (self) {
    self->tp_root = root;
    
  }
  return self;
}

void sip_tport_destroy(sip_tport_t *);

sip_tport_t *sip_tport_url_find(sip_tport_t *, url_t const *, msg_t *);
sip_tport_t *sip_tport_via_find(sip_tport_t *, sip_via_t *, msg_t *);

sip_via_t *sip_tport_via(sip_tport_t *);

typedef sip_resolve_f(sip_tport_magic_t *, sip_tport_t *, msg_t *);

int sip_tport_url_resolve(sip_tport_t *, url_t const *, msg_t *, 
			  sip_resolve_f);
int sip_tport_via_resolve(sip_tport_t *, sip_via_t const *, msg_t *, 
			  sip_resolve_f);

