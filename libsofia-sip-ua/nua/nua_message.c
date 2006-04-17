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

/**@CFILE nua_message.c
 * @brief MESSAGE method
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 17:01:22 EET 2006 ppessi
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
/* MESSAGE */

static int process_response_to_message(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int 
nua_stack_message(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{ 
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;
  sip_t *sip;

  if (nh_is_special(nh)) {
    return UA_EVENT2(e, 900, "Invalid handle for MESSAGE");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 900, "Request already in progress");
  }

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_MESSAGE,
			 NUTAG_ADD_CONTACT(NH_PGET(nh, win_messenger_enable)),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

#if HAVE_SOFIA_SMIME_OLD 
  if (sip) {
    int status, bOverride;
    sm_option_t sm_opt; 

    tl_gets(tags, 
	    NUTAG_SMIME_ENABLE_REF(bOverride),
	    NUTAG_SMIME_OPT_REF(sm_opt),
	    TAG_END());
  
    if (nua->sm->sm_enable && sm_opt != SM_ID_NULL) {
      status = sm_adapt_message(nua->sm, msg, sip, 
				bOverride? sm_opt : SM_ID_NULL);
      switch(status)
	{
	case SM_SUCCESS:
	  break;
	case SM_ERROR:
	  return UA_EVENT2(e, SIP_500_INTERNAL_SERVER_ERROR);
	case SM_CERT_NOTFOUND:
	case SM_CERTFILE_NOTFOUND:
  	  /* currently just sent a sending fail signal, later on,
	     should trigger the options message to ask for
	     certificate. */ 
	  msg_destroy(msg);
	  return UA_EVENT2(e, SIP_500_INTERNAL_SERVER_ERROR);
	}
    } 
  }
#endif                   

  if (sip)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_message, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));
  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);
  }

  return cr->cr_event = e;
}

void restart_message(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_message, tags);
}

static int process_response_to_message(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip)
{
  if (nua_creq_check_restart(nh, nh->nh_cr, orq, sip, restart_message))
    return 0;
  return nua_stack_process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

int nua_stack_process_message(nua_t *nua,
			      nua_handle_t *nh,
			      nta_incoming_t *irq,
			      sip_t const *sip)
{
  msg_t *msg;

  if (nh
      ? !NH_PGET(nh, message_enable)
      : !DNH_PGET(nua->nua_dhandle, message_enable))
    return 403;

  if (nh == NULL)
    if (!(nh = nua_stack_incoming_handle(nua, irq, sip, nh_has_nothing, 0)))
      return 500;		/* respond with 500 Internal Server Error */

  msg = nta_incoming_getrequest(irq);

#if HAVE_SOFIA_SMIME
  if (nua->sm->sm_enable) {
    int sm_status = sm_decode_message(nua->sm, msg, sip);

    switch (sm_status) {
    case SM_SMIME_DISABLED:
      msg_destroy(msg);
      return 493;
    case SM_SUCCESS:
      break;
    case SM_ERROR:
      msg_destroy(msg);
      return 493;
    default:
      break;
    }
  }
#endif

  nua_stack_event(nh->nh_nua, nh, msg, nua_i_message, SIP_200_OK, TAG_END());

#if 0 /* XXX */
  if (nh->nh_nua->nua_messageRespond) {	
    nh->nh_irq = irq;
    return 0;
  }
#endif

  return 200;
}
