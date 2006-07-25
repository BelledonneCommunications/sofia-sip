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
 * @brief SUBSCRIBE, NOTIFY and REFER methods
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
/* Subcribe event usage */

struct event_usage
{
  enum nua_substate  eu_substate;	/**< Subscription state */
  sip_time_t eu_expires;	        /**< Proposed expiration time */
};

static char const *nua_subscribe_usage_name(nua_dialog_usage_t const *du);
static int nua_subscribe_usage_add(nua_handle_t *nh, 
				   nua_dialog_state_t *ds,
				   nua_dialog_usage_t *du);
static void nua_subscribe_usage_remove(nua_handle_t *nh, 
				       nua_dialog_state_t *ds,
				       nua_dialog_usage_t *du);

static nua_usage_class const nua_subscribe_usage[1] = {
  {
    sizeof (struct event_usage), (sizeof nua_subscribe_usage),
    nua_subscribe_usage_add,
    nua_subscribe_usage_remove,
    nua_subscribe_usage_name,
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

/* ---------------------------------------------------------------------- */
/* Notify event usage */

static char const *nua_notify_usage_name(nua_dialog_usage_t const *du);
static int nua_notify_usage_add(nua_handle_t *nh, 
				   nua_dialog_state_t *ds,
				   nua_dialog_usage_t *du);
static void nua_notify_usage_remove(nua_handle_t *nh, 
				       nua_dialog_state_t *ds,
				       nua_dialog_usage_t *du);

static nua_usage_class const nua_notify_usage[1] = {
  {
    sizeof (struct event_usage), (sizeof nua_notify_usage),
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
/* SUBSCRIBE */

static void 
  refresh_subscribe(nua_handle_t *nh, nua_dialog_usage_t *, sip_time_t now),
  terminate_subscription(nua_handle_t *nh, nua_dialog_usage_t *, sip_time_t now);
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
    return UA_EVENT2(e, 500, "Request already in progress");

  /* Initialize allow and auth */
  nua_stack_init_handle(nua, nh, nh_has_subscribe, "NOTIFY", TAG_NEXT(tags));

  if (nh->nh_has_subscribe)
    /* We can re-use existing INVITE handle */
    nh->nh_special = nua_r_subscribe;

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
		     SIP_METHOD_SUBSCRIBE,
		     NUTAG_USE_DIALOG(1),
		     NUTAG_ADD_CONTACT(1),
		     TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    sip_event_t *o = sip->sip_event;

    if (e != nua_r_subscribe) {	/* Unsubscribe */
      sip_add_make(msg, sip, sip_expires_class, "0");
      du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, o);

      if (du == NULL && o == NULL) {
	du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, NONE);
	if (du && du->du_event)
	  sip_add_dup(msg, sip, (sip_header_t *)du->du_event);
      }
    }
    else
      /* We allow here SUBSCRIBE without event */
      du = nua_dialog_usage_add(nh, nh->nh_ds, nua_subscribe_usage, o);
  }

  /* Store supported features (eventlist) */
  if (du && sip) {
    if (du->du_msg)
      msg_destroy(du->du_msg);
    du->du_msg = msg_ref_create(cr->cr_msg);
  }

  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_subscribe, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));

  eu = nua_dialog_usage_private(du);

  if (!cr->cr_orq) {
    int substate = nua_substate_terminated;

    if (du == NULL)
      ;
    else if (du->du_ready)
      substate = eu->eu_substate; /* We already  */
    else
      nua_dialog_usage_remove(nh, nh->nh_ds, du);

    msg_destroy(msg);

    return UA_EVENT3(e, NUA_INTERNAL_ERROR, 
		     NUTAG_SUBSTATE(substate), TAG_END());
  }

  du->du_pending = NULL;
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

    if (!win_messenger_enable)
      nua_dialog_uac_route(nh, nh->nh_ds, sip, 1);
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

    if (delta > 0) {
      nua_dialog_usage_set_refresh(du, delta);
      du->du_pending = refresh_subscribe;
    }
    else {
      if (win_messenger_enable)
	/* Wait 4 minutes for NOTIFY from Messenger */
	du->du_refresh = now + 4 * 60; 
      else
	/* Wait 32 seconds for NOTIFY */
	du->du_refresh = now + 64 * NTA_SIP_T1 / 1000;
      du->du_pending = terminate_subscription;
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
void
refresh_subscribe(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
  nua_event_t e;
  msg_t *msg;
  sip_t *sip;

  if (cr->cr_msg) {		/* Already doing something  */
    /* Delay of 5 .. 15 seconds */
    du->du_refresh = sip_now() + su_randint(5, 15);
    du->du_pending = refresh_subscribe;
    return;
  }

  if (now > 0)
    e = nua_r_subscribe;
  else
    e = nua_r_destroy, du->du_terminating = 1;

  cr->cr_msg = msg_copy(du->du_msg);

  {
    /* Remove initial route */
    sip_t *sip = sip_object(cr->cr_msg);
    if (sip->sip_route)
      msg_header_remove(cr->cr_msg, (msg_pub_t*)sip, (void *)sip->sip_route);
  }

  msg = nua_creq_msg(nua, nh, cr, 1,
		     SIP_METHOD_SUBSCRIBE,
		     NUTAG_USE_DIALOG(1),
		     NUTAG_ADD_CONTACT(1),
		     TAG_IF(du->du_terminating, 
			    SIPTAG_EXPIRES_STR("0")),
		     TAG_END());

  sip = sip_object(msg);

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_subscribe, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(NULL));

  if (!cr->cr_orq) {
    struct event_usage *eu = nua_dialog_usage_private(du);

    if (du->du_terminating)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    msg_destroy(msg);
    UA_EVENT3(e, NUA_INTERNAL_ERROR, 
	      NUTAG_SUBSTATE(eu->eu_substate), TAG_END());
    return;
  }

  cr->cr_usage = du;
  cr->cr_event = e;
}


/** Terminate subscription when we have not received a NOTIFY */
static void 
terminate_subscription(nua_handle_t *nh,
		       nua_dialog_usage_t *du,
		       sip_time_t now)
{
  sip_event_t const *o = NULL;
  char const *id;

  if (!du) {
    SU_DEBUG_1(("nua(%p): terminate_subscription() without usage to remove\n", 
		nh));
    return;
  }

  o = du->du_event;
  id = o ? o->o_id : NULL;
  SU_DEBUG_3(("nua(%p): terminate_subscription() with event %s%s%s\n",
	      nh, o ? o->o_type : "(empty)",
	      id ? "; id=" : "", id ? id : ""));

  nua_stack_event(nh->nh_nua, nh,  NULL,
	   nua_i_notify, 408, "Early Subscription Timeouts without NOTIFY", 
	   NUTAG_SUBSTATE(nua_substate_terminated),
	   SIPTAG_EVENT(o),
	   TAG_END());

  nua_dialog_usage_remove(nh, nh->nh_ds, du);
}

/** @internal Process incoming SUBSCRIBE. */
int nua_stack_process_subsribe(nua_t *nua,
			       nua_handle_t *nh,
			       nta_incoming_t *irq,
			       sip_t const *sip)
{
  nua_dialog_state_t *ds;
  nua_dialog_usage_t *du = NULL;
  struct event_usage *eu;
  sip_event_t *o = sip->sip_event;
  sip_contact_t const *m = NULL;
  int status; char const *phrase;
  unsigned long expires, refer_expires;
  nua_registration_t *nr;

  enter;

  if (nh)
    du = nua_dialog_usage_get(ds = nh->nh_ds, nua_notify_usage, o);

  if (nh == NULL || du == NULL) {
    /* Hard-coded support only for refer subscriptions */
    if (o && str0cmp(o->o_type, "refer") == 0)
      nta_incoming_treply(irq, 
			  SET_STATUS(481, "Subscription Does Not Exist"), 
			  TAG_END());
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
  eu = nua_dialog_usage_private(du);  assert(nh && du && eu);

  nua_dialog_store_peer_info(nh, nh->nh_ds, sip);
  nua_dialog_uas_route(nh, nh->nh_ds, sip, 1);

  refer_expires = NH_PGET(nh, refer_expires);
  expires = refer_expires;

  if (sip->sip_expires) {
    expires = sip->sip_expires->ex_delta;
    if (expires > refer_expires)
      expires = refer_expires;
  }

  if (expires == 0) {
    eu->eu_substate = nua_substate_terminated;
    du->du_refresh = sip_now();
  }
  else {
    du->du_refresh = sip_now() + expires;
  }

  if (eu->eu_substate == nua_substate_pending)
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
      eu->eu_substate = nua_substate_terminated;
    }
  }
    
  nta_incoming_treply(irq, status, phrase, SIPTAG_CONTACT(m), NULL);

  nua_stack_event(nua, nh, nta_incoming_getrequest(irq),
	   nua_i_subscribe, status, phrase, 
	   NUTAG_SUBSTATE(eu->eu_substate),
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

int
nua_stack_notify(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = NULL;
  struct event_usage *eu;
  msg_t *msg;
  sip_t *sip;

  if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
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
  eu = nua_dialog_usage_private(du);

  if (du && du->du_event && !sip->sip_event)
    sip_add_dup(msg, sip, (sip_header_t *)du->du_event);

  if (!du)
    ;
  else if (sip->sip_subscription_state) {
    char const *ss_substate = sip->sip_subscription_state->ss_substate;
    sip_time_t now = sip_now();

    if (strcasecmp(ss_substate, "terminated") == 0)
      eu->eu_substate = nua_substate_terminated;
    else if (strcasecmp(ss_substate, "pending") == 0)
      eu->eu_substate = nua_substate_pending;
    else /* if (strcasecmp(subs->ss_substate, "active") == 0) */ 
      eu->eu_substate = nua_substate_active;

    if (sip->sip_subscription_state->ss_expires) {
      unsigned long expires;
      expires = strtoul(sip->sip_subscription_state->ss_expires, NULL, 10);
      if (expires > 3600)
        expires = 3600;
      du->du_refresh = now + expires;
    }
    else if (eu->eu_substate != nua_substate_terminated) {
      sip_subscription_state_t *ss = sip->sip_subscription_state;
      char *param;

      if (now < du->du_refresh)
        param = su_sprintf(msg_home(msg), "expires=%lu", 
      		     du->du_refresh - now);
      else
        param = "expires=0";

      msg_header_add_param(msg_home(msg), ss->ss_common, param);
    }
  }
  else {
    sip_subscription_state_t *ss;
    char const *substate;
    sip_time_t now = sip_now();
    unsigned long expires = 3600;

    switch (eu->eu_substate) {
    case nua_substate_embryonic:
      eu->eu_substate = nua_substate_pending;
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

    if (du->du_refresh <= now)
      eu->eu_substate = nua_substate_terminated;

    if (eu->eu_substate != nua_substate_terminated) {
      if (du->du_refresh)
        expires = du->du_refresh - now;
      else
        du->du_refresh = now + expires;
      ss = sip_subscription_state_format(msg_home(msg), "%s;expires=%lu",
      				   substate, expires);
    }
    else {
      du->du_refresh = now;
      ss = sip_subscription_state_make(msg_home(msg), "terminated; "
      				 "reason=noresource");
    }

    msg_header_insert(msg, (void *)sip, (void *)ss);
  }

  if (du) {
    if (eu->eu_substate == nua_substate_terminated)
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
      ds->ds_remote_tag && sip && sip->sip_from->a_tag &&
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

  if (subs == NULL) {
    /* Do some compatibility stuff here */
    unsigned long delta = 3600;

    sip_subscription_state_init(subs = ss0);

    if (sip->sip_expires)
      delta = sip->sip_expires->ex_delta;
    else
      delta = eu->eu_expires;

    if (delta == 0)
      subs->ss_substate = "terminated";
    else
      subs->ss_substate = "active";

    if (delta > 0) {
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
      retry = 0;
    } 
    else if (str0casecmp(subs->ss_reason, why = "probation") == 0) {
      eu->eu_substate = nua_substate_embryonic;
      retry = 30;
      if (subs->ss_retry_after)
	retry = strtoul(subs->ss_retry_after, NULL, 10);
    }
    else
      why = subs->ss_reason;
  }
  else if (strcasecmp(subs->ss_substate, what = "pending") == 0)
    eu->eu_substate = nua_substate_pending;
  else /* if (strcasecmp(subs->ss_substate, "active") == 0) */ {
    what = subs->ss_substate ? subs->ss_substate : "active";
    /* XXX - any extended state is considered as active */
    eu->eu_substate = nua_substate_active;
  }
  
  response = nh_make_response(nua, nh, irq, SIP_200_OK,
			      SIPTAG_ALLOW(NH_PGET(nh, allow)),
			      SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			      TAG_END());

  if (response && nua_registration_add_contact(nh, response, NULL, 1, 0) >= 0)
    nta_incoming_mreply(irq, response);
  else
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());

  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_notify, SIP_200_OK, 
	   NUTAG_SUBSTATE(eu->eu_substate),
	   TAG_END());

  nta_incoming_destroy(irq), irq = NULL;

  SU_DEBUG_5(("nua(%p): nua_stack_process_notify: %s (%s)\n", 
	      nh, what, why ? why : ""));

  if (eu->eu_substate == nua_substate_terminated) {
    du->du_refresh = 0, du->du_pending = NULL;
    if (du != nh->nh_cr->cr_usage)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (eu->eu_substate == nua_substate_embryonic) {
    if (retry != -1 && !du->du_terminating) {
      /* Try to subscribe again */
      /* XXX - how to handle dialog ?? */
      nua_dialog_usage_set_refresh(du, retry);
      du->du_pending = refresh_subscribe;
    }
    else if (du != nh->nh_cr->cr_usage)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (subs->ss_expires) {
    sip_time_t delta = strtoul(subs->ss_expires, NULL, 10);
    
    if (!du->du_terminating) {
      nua_dialog_usage_set_refresh(du, delta);
      du->du_pending = refresh_subscribe;
    }
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
    return UA_EVENT2(e, 500, "Invalid handle for REFER");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
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

/** @internal Process incoming REFER. */
int nua_stack_process_refer(nua_t *nua,
			    nua_handle_t *nh,
			    nta_incoming_t *irq,
			    sip_t const *sip)
{
  nua_dialog_usage_t *du = NULL;
  sip_event_t *event;
  sip_referred_by_t *by = NULL, default_by[1];
  msg_t *response;
  int created = 0;

  if (nh == NULL) {
    if (!(nh = nua_stack_incoming_handle(nua, irq, sip, nh_has_notify, 1)))
      return 500;
    created = 1;
  }

  event = sip_event_format(nh->nh_home, "refer;id=%u", sip->sip_cseq->cs_seq);
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

  du->du_ready = 1;

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

  du->du_refresh = sip_now() + NH_PGET(nh, refer_expires);

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
