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

#ifndef SIP_TRANSPORT_H
#define SIP_TRANSPORT_H 

/** @internal @file sip_transport.h 
 *  SIP transport objects.
 *
 *  @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 *  @date Created      : Fri Sep  8 17:35:30 2000 ppessi
 *  @date Last modified: Fri Sep  8 19:48:53 2000 ppessi
 */

typedef struct sip_tport_s sip_tport_t;

sip_tport_t *sip_tport_create(su_root_t *root,
			      nta_agent_t *,
			      url_t const *url,
			      char const * const *url_params);
void sip_tport_destroy(sip_tport_t *);

sip_tport_t *sip_tport_url_find(sip_tport_t *, url_t const *, msg_t *);
sip_tport_t *sip_tport_via_find(sip_tport_t *, sip_via_t *, msg_t *);

sip_via_t *sip_tport_via(sip_tport_t *);

typedef sip_resolve_f(sip_tport_magic_t *, sip_tport_t *, msg_t *);

int sip_tport_url_resolve(sip_tport_t *, url_t const *, msg_t *, 
			  sip_resolve_f);
int sip_tport_via_resolve(sip_tport_t *, sip_via_t const *, msg_t *, 
			  sip_resolve_f);


#endif /* SIP_TRANSPORT_H */
