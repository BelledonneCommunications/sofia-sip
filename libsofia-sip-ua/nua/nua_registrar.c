/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2006 Nokia Corporation.
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

/**@CFILE nua_registrar.c
 * @brief REGISTER UAS
 *
 * @author Michael Jerris
 *
 * @date Created: Tue Oct  3 10:14:54 EEST 2006 ppessi
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <assert.h>

#include <sofia-sip/string0.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_util.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s
#define NTA_INCOMING_MAGIC_T struct nua_handle_s
#define NTA_RELIABLE_MAGIC_T struct nua_handle_s

#include "nua_stack.h"

/* ======================================================================== */
/* REGISTER */

int nua_stack_process_register(nua_t *nua,
			       nua_handle_t *nh,
			       nta_incoming_t *irq,
			       sip_t const *sip)
{
  if (nh == NULL)
    if (!(nh = nua_stack_incoming_handle(nua, irq, sip, nh_has_nothing, 0)))
      return 500;		/* Respond with 500 Internal Server Error */

   nh->nh_registrar = irq;

   nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
		   nua_i_register, SIP_100_TRYING, TAG_END());

   return 0;	
}
