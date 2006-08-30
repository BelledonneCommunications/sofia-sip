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

/**@CFILE nua_subnotref.c
 * @brief Subscriber (event watcher)
 *
 * This module implements SUBSCRIBE UAC, NOTIFY UAS, REFER UAC.
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
/* Subcriber event usage */

struct event_usage
{
  enum nua_substate  eu_substate;	/**< Subscription state */
  sip_time_t eu_expires;	        /**< Proposed expiration time */
  unsigned eu_notified;		        /**< Number of NOTIFYs received */
  unsigned eu_final_wait:1;	        /**< Waiting for final NOTIFY */
  unsigned eu_no_id:1;		        /**< Do not use "id" (even if we have one) */
};

static char const *nua_subscribe_usage_name(nua_dialog_usage_t const *du);
static int nua_subscribe_usage_add(nua_handle_t *nh, 
				   nua_dialog_state_t *ds,
				   nua_dialog_usage_t *du);
static void nua_subscribe_usage_remove(nua_handle_t *nh, 
				       nua_dialog_state_t *ds,
				       nua_dialog_usage_t *du);
static void nua_subscribe_usage_refresh(nua_handle_t *,
					nua_dialog_usage_t *,
					sip_time_t);
static int nua_subscribe_usage_shutdown(nua_handle_t *,
					nua_dialog_usage_t *);

static nua_usage_class const nua_subscribe_usage[1] = {
  {
    sizeof (struct event_usage), (sizeof nua_subscribe_usage),
    nua_subscribe_usage_add,
    nua_subscribe_usage_remove,
    nua_subscribe_usage_name,
    NULL,
    nua_subscribe_usage_refresh,
    nua_subscribe_usage_shutdown
  }};

static char const *nua_subscribe_usage_name(nua_dialog_usage_t const *du)
{
  return "subscribe";
}

static 
int nua_subscribe_usage_add(nua_handle_t *nh, 
			   nua_dialog_state_t *ds,
			   nua_dialog_usage_t *du)
{
  ds->ds_has_events++;
  ds->ds_has_subscribes++;
  return 0;
}

static 
void nua_subscribe_usage_remove(nua_handle_t *nh, 
			       nua_dialog_state_t *ds,
			       nua_dialog_usage_t *du)
{
  ds->ds_has_events--;	
  ds->ds_has_subscribes--;	
}

/* ====================================================================== */
/* SUBSCRIBE */

static int process_response_to_subscribe(nua_handle_t *nh,
					 nta_outgoing_t *orq,
					 sip_t const *sip);

int
nua_stack_subscribe(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		    tagi_t const *tags)
{
  nua_client_request_t *cr = nh->nh_cr;
  nua_dialog_usage_t *du = NULL;
  struct event_usage *eu;
  msg_t *msg;
  sip_t *sip;

  if (nh->nh_special && nh->nh_special != nua_r_subscribe)
    return UA_EVENT3(e, 500, "Invalid handle for SUBSCRIBE", 
		     NUTAG_SUBSTATE(nua_substate_terminated));
  else if (cr->cr_orq)
    return UA_EVENT2(e, 900, "Request already in progress");

  /* Initialize allow and auth */
  nua_stack_init_handle(nua, nh, nh_has_subscribe, "NOTIFY", TAG_NEXT(tags));

  if (nh->nh_has_subscribe)
    /* We can re-use existing INVITE handle */
    nh->nh_special = nua_r_subscribe;

  msg = nua_creq_msg(nua, nh, cr, 0,
		     SIP_METHOD_SUBSCRIBE,
		     NUTAG_USE_DIALOG(1),
		     NUTAG_ADD_CONTACT(1),
		     TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    sip_event_t *o = sip->sip_event;

    du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, o);

    if (du == NULL && o == NULL)
      du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, NONE);

    eu = nua_dialog_usage_private(du);

    if (du && du->du_event && (o == NULL || (o->o_id && eu->eu_no_id))) {
      if (eu->eu_no_id)		/* No id (XXX - nor other parameters) */
	sip_add_make(msg, sip, sip_event_class, du->du_event->o_type);
      else
	sip_add_dup(msg, sip, (sip_header_t *)du->du_event);
    }

    if (e == nua_r_subscribe) {	
      if (du == NULL)		/* Create dialog usage */
	/* We allow here SUBSCRIBE without event */
	du = nua_dialog_usage_add(nh, nh->nh_ds, nua_subscribe_usage, o);
    }
    else if (du) { /* Unsubscribe */
      /* Embryonic subscription is just a placeholder */
      if (eu->eu_substate == nua_substate_terminated ||
	  eu->eu_substate == nua_substate_embryonic) {
	nua_dialog_usage_remove(nh, nh->nh_ds, du);
	msg_destroy(msg);
	return UA_EVENT3(e, SIP_200_OK, 
			 NUTAG_SUBSTATE(nua_substate_terminated),
			 TAG_END());
      }
    }
  }

  /* Store message template with supported features (eventlist) */
  if (du && sip) {
    if (du->du_msg)
      msg_destroy(du->du_msg);
    du->du_msg = msg_ref_create(cr->cr_msg);
  }

  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_subscribe, nh, NULL,
				      msg,
				      TAG_IF(e != nua_r_subscribe,
					     SIPTAG_EXPIRES_STR("0")),
				      SIPTAG_END(), TAG_NEXT(tags));

  eu = nua_dialog_usage_private(du);

  if (!cr->cr_orq) {
    int substate = nua_substate_terminated;

    if (du == NULL)
      ;
    else if (du->du_ready)
      substate = eu->eu_substate; /* No change in subscription state  */
    else
      nua_dialog_usage_remove(nh, nh->nh_ds, du);

    msg_destroy(msg);

    return UA_EVENT3(e, NUA_INTERNAL_ERROR, 
		     NUTAG_SUBSTATE(substate), TAG_END());
  }

  nua_dialog_usage_no_refresh(du); /* during SUBSCRIBE transaction */
  du->du_terminating = e != nua_r_subscribe; /* Unsubscribe or destroy */

  if (du->du_terminating)
    eu->eu_expires = 0;
  else if (sip->sip_expires)
    eu->eu_expires = sip->sip_expires->ex_delta;
  else
    /* We just use common default value, but the default is actually
       package-specific according to the RFC 3265 section 4.4.4:
       [Event] packages MUST also define a
       default "Expires" value to be used if none is specified. */
    eu->eu_expires = 3600;

  eu->eu_final_wait = 0;
    
  if (sip->sip_expires && sip->sip_expires->ex_delta == 0)
    du->du_terminating = 1;

  if (eu->eu_substate == nua_substate_terminated)
    eu->eu_substate = nua_substate_embryonic;

  cr->cr_usage = du;
  return cr->cr_event = e;
}

static void restart_subscribe(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_subscribe, tags);
}

static int process_response_to_subscribe(nua_handle_t *nh,
					 nta_outgoing_t *orq,
					 sip_t const *sip)
{
  nua_client_request_t *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage; 
  struct event_usage *eu = nua_dialog_usage_private(du);
  int status = sip ? sip->sip_status->st_status : 408;
  int gracefully = 0;
  int substate = nua_substate_embryonic;

  assert(du); assert(du->du_class == nua_subscribe_usage);

  if (status < 200)
    ;
  else if (du == NULL) {
    /* NOTIFY already removed du */
  }
  /* We have not received NOTIFY. */
  else if (status < 300) {
    int win_messenger_enable = NH_PGET(nh, win_messenger_enable);
    sip_time_t delta, now = sip_now();

    du->du_ready = 1;
    substate = eu->eu_substate;
    
    if (cr->cr_event == nua_r_unsubscribe)
      delta = 0;
    else
      /* If there is no expires header,
	 use default value stored in eu_expires */
      delta = sip_contact_expires(NULL, sip->sip_expires, sip->sip_date, 
				  eu->eu_expires, now);

    if (win_messenger_enable && !nua_dialog_is_established(nh->nh_ds)) {
      /* Notify from messanger does not match with dialog tag */ 
      nh->nh_ds->ds_remote_tag = su_strdup(nh->nh_home, "");
    }

    nua_dialog_uac_route(nh, nh->nh_ds, sip, 1);
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

    if (delta > 0) {
      nua_dialog_usage_set_refresh(du, delta);
    }
    else if (!eu->eu_notified) {
      /* This is a fetch: subscription was really terminated
	 but we wait 32 seconds for NOTIFY. */
      delta = 64 * NTA_SIP_T1 / 1000;

      if (win_messenger_enable)
	delta = 4 * 60; 	/* Wait 4 minutes for NOTIFY from Messenger */

      eu->eu_final_wait = 1;

      nua_dialog_usage_refresh_range(du, delta, delta);
    }
  }
  else /* if (status >= 300) */ {
    int terminated;

    if (nua_creq_check_restart(nh, cr, orq, sip, restart_subscribe))
      return 0;

    cr->cr_usage = NULL; /* We take care of removing/not removing usage */

    substate = eu->eu_substate;

    if (!sip || !sip->sip_retry_after)
      gracefully = 1;

    terminated = 
      sip_response_terminates_dialog(status, sip_method_subscribe, 
				     &gracefully);

    /* XXX - zap dialog if terminated < 0 ? */

    if (terminated || !du->du_ready || du->du_terminating) {
      substate = nua_substate_terminated;
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    }
    else if (gracefully && substate != nua_substate_terminated) 
      /* Post un-subscribe event */
      nua_stack_post_signal(nh, nua_r_unsubscribe, 
			    SIPTAG_EVENT(du->du_event), 
			    SIPTAG_EXPIRES_STR("0"),
			    TAG_END());
  }

  nua_stack_process_response(nh, cr, orq, sip, 
			     TAG_IF(substate >= 0, NUTAG_SUBSTATE(substate)),
			     TAG_END());
  return 0;
}

/** Refresh subscription */
static void nua_subscribe_usage_refresh(nua_handle_t *nh,
					nua_dialog_usage_t *du,
					sip_time_t now)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
  struct event_usage *eu = nua_dialog_usage_private(du);
  msg_t *msg;

  assert(eu);
  
  if (eu->eu_final_wait) {
    /* Did not receive NOTIFY for fetch... */
    sip_event_t const *o = du->du_event;
    char const *id = o ? o->o_id : NULL;

    SU_DEBUG_3(("nua(%p): fetch event %s%s%s timeouts\n",
		nh, o ? o->o_type : "(empty)",
		id ? "; id=" : "", id ? id : ""));

    nua_stack_event(nh->nh_nua, nh,  NULL,
		    nua_i_notify, 408, "Fetch Timeouts without NOTIFY", 
		    NUTAG_SUBSTATE(nua_substate_terminated),
		    SIPTAG_EVENT(o),
		    TAG_END());

    nua_dialog_usage_remove(nh, nh->nh_ds, du);

    return;
  }

  if (du->du_terminating)	/* No need to refresh. */
    return;

  if (cr->cr_msg) {
    /* Already doing something, delay 5..15 seconds? */
    if (cr->cr_usage != du)
      nua_dialog_usage_refresh_range(du, 5, 15);
    return;
  }

  cr->cr_msg = msg_copy(du->du_msg);

  msg = nua_creq_msg(nua, nh, cr, 1,
		     SIP_METHOD_SUBSCRIBE,
		     NUTAG_USE_DIALOG(1),
		     NUTAG_ADD_CONTACT(1),
		     /* If dialog is established, remove initial route */
		     TAG_IF(nua_dialog_is_established(nh->nh_ds),
			    SIPTAG_ROUTE(NONE)),
		     TAG_END());

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_subscribe, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(NULL));
  if (cr->cr_orq) {
    cr->cr_usage = du;
    cr->cr_event = nua_r_subscribe;
    return;
  }

  if (du->du_terminating)
    nua_dialog_usage_remove(nh, nh->nh_ds, du);
  else   /* Try again later? */
    nua_dialog_usage_refresh_range(du, 5, 15);

  msg_destroy(msg);
  UA_EVENT3(nua_r_subscribe, NUA_INTERNAL_ERROR, 
	    NUTAG_SUBSTATE(eu->eu_substate),
	    TAG_END());
}


/** Terminate subscription */
static int nua_subscribe_usage_shutdown(nua_handle_t *nh,
					nua_dialog_usage_t *du)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
  struct event_usage *eu = nua_dialog_usage_private(du);
  msg_t *msg;

  assert(eu);

  if (du->du_terminating)
    return 100;			/* ...in progress */
  
  if (cr->cr_msg)
    /* XXX - already doing something else? */
    return 100;

  cr->cr_msg = msg_copy(du->du_msg);

  msg = nua_creq_msg(nua, nh, cr, 1,
		     SIP_METHOD_SUBSCRIBE,
		     NUTAG_USE_DIALOG(1),
		     NUTAG_ADD_CONTACT(1),
		     SIPTAG_EXPIRES_STR("0"),
		     /* If dialog is established, remove initial route */
		     TAG_IF(nua_dialog_is_established(nh->nh_ds),
			    SIPTAG_ROUTE(NONE)),
		     TAG_END());

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_subscribe, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(NULL));
  if (cr->cr_orq) {
    cr->cr_usage = du;
    cr->cr_event = nua_r_destroy;
    return 100;
  }

  /* Too bad. */
  nua_dialog_usage_remove(nh, nh->nh_ds, du);
  msg_destroy(msg);
  return 200;
}

/* ======================================================================== */
/* NOTIFY server */

/** @internal Process incoming NOTIFY. */
int nua_stack_process_notify(nua_t *nua,
			     nua_handle_t *nh,
			     nta_incoming_t *irq,
			     sip_t const *sip)
{
  nua_dialog_state_t *ds = nh->nh_ds;
  nua_dialog_usage_t *du;
  struct event_usage *eu;
  sip_subscription_state_t *subs = sip ? sip->sip_subscription_state : NULL;
  sip_subscription_state_t ss0[1];
  msg_t *response;
  char expires[32];
  int retry = -1;
  char const *what = NULL, *why = NULL;

  enter;

  if (nh == NULL) {
    nta_incoming_treply(irq, 481, "Subscription Does Not Exist", 
			TAG_END());
    return 481;
  }
  assert(nh);

  if (/* XXX - support forking of subscriptions?... */
      ds->ds_remote_tag && ds->ds_remote_tag[0] && 
      sip && sip->sip_from->a_tag &&
      strcmp(ds->ds_remote_tag, sip->sip_from->a_tag)) {
    sip_contact_t const *m = NULL;
    sip_warning_t *w = NULL, w0[1];

    m = nua_stack_get_contact(nua->nua_registrations);
    if (m) {
      w = sip_warning_init(w0);
      w->w_code = 399;
      w->w_host = m->m_url->url_host;
      w->w_port = m->m_url->url_port;
      w->w_text = "Forking SUBSCRIBEs are not supported";
    }

    nta_incoming_treply(irq, 481, "Subscription Does Not Exist", 
			SIPTAG_WARNING(w),
			TAG_END());
    return 481;
  }

  du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, sip->sip_event);

  if (du == NULL) {
    nta_incoming_treply(irq, 481, "Subscription Does Not Exist", TAG_END());
    return 481;
  }

  eu = nua_dialog_usage_private(du); assert(eu);

  if (!sip->sip_event->o_id) {
    eu->eu_no_id = 1;
  }

  if (subs == NULL) {
    /* Do some compatibility stuff here */
    unsigned long delta;

    sip_subscription_state_init(subs = ss0);

    delta = sip->sip_expires ? sip->sip_expires->ex_delta : eu->eu_expires;

    if (delta == 0)
      subs->ss_substate = "terminated";
    else
      subs->ss_substate = "active";

    if (delta > 0 && sip->sip_expires) {
      snprintf(expires, sizeof expires, "%lu", delta);
      subs->ss_expires = expires;
    }
  }

  nua_dialog_store_peer_info(nh, nh->nh_ds, sip);
  nua_dialog_uas_route(nh, nh->nh_ds, sip, 1);

  if (strcasecmp(subs->ss_substate, what = "terminated") == 0) {
    eu->eu_substate = nua_substate_terminated;

    if (str0casecmp(subs->ss_reason, why = "deactivated") == 0) {
      eu->eu_substate = nua_substate_embryonic;
      retry = 0;		/* retry immediately */
    } 
    else if (str0casecmp(subs->ss_reason, why = "probation") == 0) {
      eu->eu_substate = nua_substate_embryonic;
      retry = 30;
      if (subs->ss_retry_after)
	retry = strtoul(subs->ss_retry_after, NULL, 10);
      if (retry > 3600)
	retry = 3600;
    }
    else
      why = subs->ss_reason;
  }
  else if (strcasecmp(subs->ss_substate, what = "pending") == 0)
    eu->eu_substate = nua_substate_pending;
  else /* if (strcasecmp(subs->ss_substate, "active") == 0) */ {
    /* Any extended state is considered as active */
    what = subs->ss_substate ? subs->ss_substate : "active";
    eu->eu_substate = nua_substate_active;
  }

  if (du->du_terminating)
    retry = -1;
  
  response = nh_make_response(nua, nh, irq, SIP_200_OK,
			      SIPTAG_ALLOW(NH_PGET(nh, allow)),
			      SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			      TAG_END());

  if (response && 
      nua_registration_add_contact_to_response(nh, response, NULL, 
					       sip->sip_record_route,
					       sip->sip_contact) >= 0)
    nta_incoming_mreply(irq, response);
  else
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());

  if (eu->eu_substate == nua_substate_terminated && retry > 0)
    eu->eu_substate = nua_substate_embryonic;

  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
		  nua_i_notify, SIP_200_OK, 
		  NUTAG_SUBSTATE(eu->eu_substate),
		  TAG_END());

  nta_incoming_destroy(irq), irq = NULL;

  SU_DEBUG_5(("nua(%p): nua_stack_process_notify: %s (%s)\n", 
	      nh, what, why ? why : ""));

  if (eu->eu_substate == nua_substate_terminated) {
    if (du != nh->nh_cr->cr_usage)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    else
      nua_dialog_usage_no_refresh(du);
  }
  else if (eu->eu_substate == nua_substate_embryonic) {
    if (retry >= 0) {
      /* Try to subscribe again */
      nua_dialog_remove(nh, nh->nh_ds, du); /* tear down */
      nua_dialog_usage_refresh_range(du, retry, retry + 5);
    }
    else if (du != nh->nh_cr->cr_usage)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    else
      nua_dialog_usage_no_refresh(du);
  }
  else if (du->du_terminating) {
    nua_dialog_usage_no_refresh(du);
  }
  else {
    sip_time_t delta;

    if (subs->ss_expires)
      delta = strtoul(subs->ss_expires, NULL, 10);
    else
      delta = eu->eu_expires;
    
    nua_dialog_usage_set_refresh(du, delta);
  }

  return 0;
}

/* ======================================================================== */
/* REFER */

static int process_response_to_refer(nua_handle_t *nh,
				     nta_outgoing_t *orq,
				     sip_t const *sip);

int
nua_stack_refer(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_dialog_usage_t *du = NULL;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;
  sip_t *sip;
  sip_referred_by_t by[1];
  sip_event_t *event = NULL;

  if (nh_is_special(nh) && !nua_handle_has_subscribe(nh)) {
    return UA_EVENT2(e, 900, "Invalid handle for REFER");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 900, "Request already in progress");
  }

  nua_stack_init_handle(nua, nh, nh_has_subscribe, "NOTIFY", TAG_NEXT(tags));
  if (nh->nh_has_subscribe)
    nh->nh_special = nua_r_subscribe;

  sip_referred_by_init(by);
  by->b_display = nua->nua_from->a_display;
  *by->b_url = *nua->nua_from->a_url;

  /* Now we create a REFER request message */
  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_REFER,
			 NUTAG_USE_DIALOG(1),
			 SIPTAG_EVENT(SIP_NONE), /* remove event */
			 SIPTAG_REFERRED_BY(by), /* Overriden by user tags */
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip && sip->sip_cseq)
    event = sip_event_format(nh->nh_home, "refer;id=%u", 
			     sip->sip_cseq->cs_seq);

  if (event)
    du = nua_dialog_usage_add(nh, nh->nh_ds, nua_subscribe_usage, event);
  
  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_refer, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));
  
  if (!cr->cr_orq) {
    if (du)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    su_free(nh->nh_home, event);
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);
  }

  /*
   * We send a 100 trying event so that application gets a event 
   * it can use to match NOTIFYs with its REFER
   */
  nua_stack_event(nua, nh, NULL, e, SIP_100_TRYING, 
	   NUTAG_REFER_EVENT(event),
	   TAG_END());
  su_free(nh->nh_home, event);

  cr->cr_usage = du;

  return cr->cr_event = e;
}

void restart_refer(nua_handle_t *nh, tagi_t *tags)
{
  nua_stack_refer(nh->nh_nua, nh, nh->nh_cr->cr_event, tags);
}

static int process_response_to_refer(nua_handle_t *nh,
				     nta_outgoing_t *orq,
				     sip_t const *sip)
{
  struct nua_client_request *cr = nh->nh_cr;
  int status = sip ? sip->sip_status->st_status : 408;

  if (status < 200)
    ;
  else if (status < 300) {
    if (cr->cr_usage)
      cr->cr_usage->du_ready = 1;
    nua_dialog_uac_route(nh, nh->nh_ds, sip, 1);
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);
  }
  else /* if (status >= 300) */ {
    if (cr->cr_usage)
      nua_dialog_usage_remove(nh, nh->nh_ds, cr->cr_usage), cr->cr_usage = NULL;
    if (nua_creq_check_restart(nh, cr, orq, sip, restart_refer))
      return 0;
  }

  return nua_stack_process_response(nh, cr, orq, sip, TAG_END());
}
