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

/**@CFILE nua_notifier.c
 * @brief SUBSCRIBE server, NOTIFY client and REFER server
 *
 * Simpler event server handling REFER requests.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 15:10:08 EET 2006 ppessi
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
#include <sofia-sip/su_uniqueid.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s

#include "nua_stack.h"

/* ---------------------------------------------------------------------- */
/* Notifier event usage */

struct notifier_usage
{
  enum nua_substate  nu_substate;	/**< Subscription state */
  sip_time_t         nu_expires;
};

static char const *nua_notify_usage_name(nua_dialog_usage_t const *du);
static int nua_notify_usage_add(nua_handle_t *nh, 
				   nua_dialog_state_t *ds,
				   nua_dialog_usage_t *du);
static void nua_notify_usage_remove(nua_handle_t *nh, 
				       nua_dialog_state_t *ds,
				       nua_dialog_usage_t *du);

static nua_usage_class const nua_notify_usage[1] = {
  {
    sizeof (struct notifier_usage), (sizeof nua_notify_usage),
    nua_notify_usage_add,
    nua_notify_usage_remove,
    nua_notify_usage_name,
  }};

static char const *nua_notify_usage_name(nua_dialog_usage_t const *du)
{
  return "notify";
}

static 
int nua_notify_usage_add(nua_handle_t *nh, 
			   nua_dialog_state_t *ds,
			   nua_dialog_usage_t *du)
{
  ds->ds_has_events++;
  ds->ds_has_notifys++;
  return 0;
}

static 
void nua_notify_usage_remove(nua_handle_t *nh, 
			       nua_dialog_state_t *ds,
			       nua_dialog_usage_t *du)
{
  ds->ds_has_events--;	
  ds->ds_has_notifys--;	
}

/* ====================================================================== */
/* SUBSCRIBE server */

/** @internal Process incoming SUBSCRIBE. */
int nua_stack_process_subscribe(nua_t *nua,
				nua_handle_t *nh,
				nta_incoming_t *irq,
				sip_t const *sip)
{
  nua_dialog_state_t *ds;
  nua_dialog_usage_t *du = NULL;
  struct notifier_usage *nu;
  sip_event_t *o = sip->sip_event;
  sip_contact_t const *m = NULL;
  int status; char const *phrase;
  unsigned long expires, refer_expires;
  sip_expires_t ex[1];
  nua_registration_t *nr;

  enter;

  if (nh)
    du = nua_dialog_usage_get(ds = nh->nh_ds, nua_notify_usage, o);

  if (nh == NULL || du == NULL) {
    /* Hard-coded support only for refer subscriptions */
    if (o && str0cmp(o->o_type, "refer") == 0)
      nta_incoming_treply(irq, SET_STATUS1(SIP_403_FORBIDDEN), TAG_END());
    else
      nta_incoming_treply(irq,
			  SET_STATUS1(SIP_489_BAD_EVENT), 
			  SIPTAG_ALLOW_EVENTS_STR("refer"),
			  SIPTAG_ACCEPT_STR("message/sipfrag"),
			  TAG_END());

    nua_stack_event(nua, nh, nta_incoming_getrequest(irq),
	     nua_i_subscribe, status, phrase, 
	     NUTAG_SUBSTATE(nua_substate_terminated),
	     TAG_END());

    return status;
  }

  /* Refresh existing subscription */
  nu = nua_dialog_usage_private(du);  assert(nh && du && nu);

  nua_dialog_store_peer_info(nh, nh->nh_ds, sip);
  nua_dialog_uas_route(nh, nh->nh_ds, sip, 1);

  refer_expires = NH_PGET(nh, refer_expires);
  expires = refer_expires;

  if (sip->sip_expires) {
    expires = sip->sip_expires->ex_delta;
    if (expires > refer_expires)
      expires = refer_expires;
  }

  if (expires == 0)
    nu->nu_substate = nua_substate_terminated;
  nu->nu_expires = sip_now() + expires;
  sip_expires_init(ex)->ex_delta = expires;

  if (nu->nu_substate == nua_substate_pending)
    SET_STATUS1(SIP_202_ACCEPTED);
  else
    SET_STATUS1(SIP_200_OK);


  if (status < 300) {
    nr = nua_registration_by_aor(nua->nua_registrations,
				 sip->sip_to,
				 sip->sip_request->rq_url,
				 0);
    m = nua_registration_contact(nr);
    if (m == NULL) {
      SET_STATUS1(SIP_500_INTERNAL_SERVER_ERROR); 
      nu->nu_substate = nua_substate_terminated;
    }
  }
  
  nta_incoming_treply(irq, status, phrase,
		      SIPTAG_CONTACT(m), 
		      SIPTAG_EXPIRES(ex),
		      TAG_END());

  nua_stack_event(nua, nh, nta_incoming_getrequest(irq),
	   nua_i_subscribe, status, phrase, 
	   NUTAG_SUBSTATE(nu->nu_substate),
	   TAG_END());

  nta_incoming_destroy(irq), irq = NULL;

  /* Immediate notify */
  if (status < 300)
    nua_stack_post_signal(nh, nua_r_notify,
			  SIPTAG_EVENT(du->du_event),
			  TAG_END());

  return 0;
}


/* ======================================================================== */
/* NOTIFY */

static int process_response_to_notify(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip);

/**@internal Send NOTIFY. */
int nua_stack_notify(nua_t *nua,
		     nua_handle_t *nh,
		     nua_event_t e,
		     tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = NULL;
  struct notifier_usage *nu;
  msg_t *msg;
  sip_t *sip;
  sip_time_t now;

  if (cr->cr_orq) {
    return UA_EVENT2(e, 900, "Request already in progress");
  }

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
		     SIP_METHOD_NOTIFY,
		     NUTAG_ADD_CONTACT(1),
		     TAG_NEXT(tags));

  sip = sip_object(msg);
  if (!sip)
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);

  du = nua_dialog_usage_get(nh->nh_ds, nua_notify_usage, sip->sip_event);
  nu = nua_dialog_usage_private(du);

  if (du && du->du_event && !sip->sip_event)
    sip_add_dup(msg, sip, (sip_header_t *)du->du_event);

  now = sip_now();

  if (!du)
    ;
  else if (sip->sip_subscription_state) {
    char const *ss_substate = sip->sip_subscription_state->ss_substate;

    if (strcasecmp(ss_substate, "terminated") == 0)
      nu->nu_substate = nua_substate_terminated;
    else if (strcasecmp(ss_substate, "pending") == 0)
      nu->nu_substate = nua_substate_pending;
    else /* if (strcasecmp(subs->ss_substate, "active") == 0) */ 
      nu->nu_substate = nua_substate_active;

    if (sip->sip_subscription_state->ss_expires) {
      unsigned long expires;
      expires = strtoul(sip->sip_subscription_state->ss_expires, NULL, 10);
      if (expires > 3600)
        expires = 3600;
      nu->nu_expires = now + expires;
    }
    else if (nu->nu_substate != nua_substate_terminated) {
      sip_subscription_state_t *ss = sip->sip_subscription_state;
      char *param;

      if (now < nu->nu_expires)
        param = su_sprintf(msg_home(msg), "expires=%lu", nu->nu_expires - now);
      else
        param = "expires=0";

      msg_header_add_param(msg_home(msg), ss->ss_common, param);
    }
  }
  else {
    sip_subscription_state_t *ss;
    char const *substate;
    unsigned long expires = 3600;

    switch (nu->nu_substate) {
    case nua_substate_embryonic:
      nu->nu_substate = nua_substate_pending;
      /*FALLTHROUGH*/
    case nua_substate_pending:
      substate = "pending";
      break;
    case nua_substate_active:
    default:
      substate = "active";
      break;
    case nua_substate_terminated:
      substate = "terminated";
      break;
    }

    if (nu->nu_expires <= now)
      nu->nu_substate = nua_substate_terminated;

    if (nu->nu_substate != nua_substate_terminated) {
      expires = nu->nu_expires - now;
      ss = sip_subscription_state_format(msg_home(msg), "%s;expires=%lu",
					 substate, expires);
    }
    else {
      ss = sip_subscription_state_make(msg_home(msg), "terminated; "
				       "reason=noresource");
    }

    msg_header_insert(msg, (void *)sip, (void *)ss);
  }

  if (du) {
    if (nu->nu_substate == nua_substate_terminated)
      du->du_terminating = 1;
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_notify, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));
  }

  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);
  }

  cr->cr_usage = du;

  return cr->cr_event = e;
}

static
void restart_notify(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_notify, tags);
}

static int process_response_to_notify(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip)
{
  if (nua_creq_check_restart(nh, nh->nh_cr, orq, sip, restart_notify))
    return 0;
  return nua_stack_process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}


/* ======================================================================== */
/* REFER */
/* RFC 3515 */

/** @internal Process incoming REFER. */
int nua_stack_process_refer(nua_t *nua,
			    nua_handle_t *nh,
			    nta_incoming_t *irq,
			    sip_t const *sip)
{
  nua_dialog_usage_t *du = NULL;
  struct notifier_usage *nu;
  sip_event_t *event;
  sip_referred_by_t *by = NULL, default_by[1];
  msg_t *response;
  sip_time_t expires;
  int created = 0;

  if (nh == NULL) {
    if (!(nh = nua_stack_incoming_handle(nua, irq, sip, nh_has_notify, 1)))
      return 500;
    created = 1;
  }

  if (nh->nh_ds->ds_has_referrals || NH_PGET(nh, refer_with_id))
    event = sip_event_format(nh->nh_home, "refer;id=%u", sip->sip_cseq->cs_seq);
  else
    event = sip_event_make(nh->nh_home, "refer");

  if (event)
    du = nua_dialog_usage_add(nh, nh->nh_ds, nua_notify_usage, event);

  if (!du || du->du_ready) {
    if (du->du_ready) {
      SU_DEBUG_1(("nua(%p): REFER with existing refer;id=%u\n", nh,
		  sip->sip_cseq->cs_seq));
    }
    if (created) 
      nh_destroy(nua, nh);
    return 500;
  }

  nu = nua_dialog_usage_private(du);
  du->du_ready = 1;
  nh->nh_ds->ds_has_referrals = 1;

  nua_dialog_uas_route(nh, nh->nh_ds, sip, 1);	/* Set route and tags */

  if (!sip->sip_referred_by) {
    sip_from_t *a = sip->sip_from;

    sip_referred_by_init(by = default_by);

    *by->b_url = *a->a_url;
    by->b_display = a->a_display;
  }

  response = nh_make_response(nua, nh, irq, 
			      SIP_202_ACCEPTED, 
			      NUTAG_ADD_CONTACT(1),
			      TAG_END());

  nta_incoming_mreply(irq, response);

  expires = NH_PGET(nh, refer_expires);

  if (sip->sip_expires && sip->sip_expires->ex_delta < expires)
    expires = sip->sip_expires->ex_delta;
  nu->nu_substate = nua_substate_pending;
  nu->nu_expires = sip_now() + expires;

  /* Immediate notify */
  nua_stack_post_signal(nh,
			nua_r_notify,
			SIPTAG_EVENT(event),
			SIPTAG_CONTENT_TYPE_STR("message/sipfrag"),
			SIPTAG_PAYLOAD_STR("SIP/2.0 100 Trying\r\n"),
			TAG_END());
  
  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
		  nua_i_refer, SIP_202_ACCEPTED, 
		  NUTAG_REFER_EVENT(event),
		  TAG_IF(by, SIPTAG_REFERRED_BY(by)),
		  TAG_END());
  
  su_free(nh->nh_home, event);

  return 500;   
}
