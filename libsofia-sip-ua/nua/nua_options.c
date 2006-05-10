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

/**@CFILE nua_options.c
 * @brief Implementation of OPTIONS method
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 17:02:19 EET 2006 ppessi
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

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s

#include "nua_stack.h"

/* ======================================================================== */
/* OPTIONS */

static int process_response_to_options(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int
nua_stack_options(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;

  if (nh_is_special(nh)) {
    return UA_EVENT2(e, 900, "Invalid handle for OPTIONS");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 900, "Request already in progress");
  }

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_OPTIONS, 
			 TAG_NEXT(tags));

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_options, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(tags));
  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);
  }

  return cr->cr_event = e;
}

void restart_options(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_options, tags);
}

static int process_response_to_options(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip)
{
  if (nua_creq_check_restart(nh, nh->nh_cr, orq, sip, restart_options))
    return 0;
  return nua_stack_process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

int nua_stack_process_options(nua_t *nua,
			      nua_handle_t *nh,
			      nta_incoming_t *irq,
			      sip_t const *sip)
{
  msg_t *msg;

  int status; char const *phrase;

  /* Hook to outbound */
  status = nua_registration_process_request(nua->nua_registrations, irq, sip);
  if (status)
    return status;

  SET_STATUS1(SIP_200_OK);

  if (nh == NULL)
    nh = nua->nua_dhandle;

  msg = nh_make_response(nua, nh, irq, status, phrase,
			 SIPTAG_ALLOW(NH_PGET(nh, allow)),
			 SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			 TAG_IF(NH_PGET(nh, path_enable),
				SIPTAG_SUPPORTED_STR("path")),
			 SIPTAG_ACCEPT_STR(SDP_MIME_TYPE),
			 TAG_END());

  if (msg) {
    su_home_t home[1] = { SU_HOME_INIT(home) };
#if 0				/* XXX */
    sdp_session_t *sdp;
    sip_t *sip = sip_object(msg);

    if ((sdp = nmedia_describe(nua, nh->nh_nm, nh, home))) {
      nh_sdp_insert(nh, home, msg, sip, sdp);
    }
#endif

    nta_incoming_mreply(irq, msg);

    su_home_deinit(home);
  }
  else
    SET_STATUS1(SIP_500_INTERNAL_SERVER_ERROR);

  msg = nta_incoming_getrequest(irq);

  nua_stack_event(nh->nh_nua, nh, msg, nua_i_options, status, phrase, TAG_END());

  return status;
}
