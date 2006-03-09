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

#ifndef NTA_TPORT_H /** Defined when nta_tport.h has been included. */
#define NTA_TPORT_H

/**
 * @file nta_tport.h
 * @brief Transport and SigComp handling
 *  
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Oct  7 20:04:39 2004 ppessi
 * 
 */

#ifndef NTA_H
#include <sofia-sip/nta.h>
#endif

SOFIA_BEGIN_DECLS

struct tport_s;

#ifndef TPORT_T
#define TPORT_T struct tport_s
typedef TPORT_T tport_t;
#endif

struct sigcomp_compartment;
struct sigcomp_udvm;

#define nta_transport nta_incoming_transport

struct tport_s *
nta_incoming_transport(nta_agent_t *agent, nta_incoming_t *irq, msg_t *msg);

struct sigcomp_compartment *
nta_incoming_compartment(nta_incoming_t *irq);

struct sigcomp_compartment *
nta_outgoing_compartment(nta_outgoing_t *orq);

void
nta_compartment_decref(struct sigcomp_compartment **);

SOFIA_END_DECLS

#endif /* !defined NTA_TPORT_H */
