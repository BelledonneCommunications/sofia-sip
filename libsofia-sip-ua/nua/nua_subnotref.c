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
 * This file contains implementation SUBSCRIBE UAC, NOTIFY UAS, REFER UAC.
 * The implementation of SUBSCRIBE UAS, NOTIFY UAC and REFER UAS is in
 * nua_notifier.c.
 * Alternative implementation using nea is in nua_event_server.c.
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
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/su_uniqueid.h>

#include "nua_stack.h"

/* ---------------------------------------------------------------------- */
/* Subcriber event usage */

struct event_usage
{
  enum nua_substate eu_substate;	/**< Subscription state */
  sip_time_t eu_expires;	        /**< Proposed expiration time */
  unsigned eu_notified;		        /**< Number of NOTIFYs received */
  unsigned eu_refer:1;		        /**< Implied subscription by refer */
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
					nua_dialog_state_t *,
					nua_dialog_usage_t *,
					sip_time_t);
static int nua_subscribe_usage_shutdown(nua_handle_t *,
					nua_dialog_state_t *,
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

/** Subscribe to a SIP event. 
 *
 * Subscribe a SIP event using the SIP SUBSCRIBE request. If the 
 * SUBSCRBE is successful a subscription state is established and 
 * the subscription is refreshed regularly. The refresh requests will
 * generate #nua_r_subscribe events.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_URL()
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_subscribe \n
 *    #nua_i_notify
 *
 * @sa NUTAG_SUBSTATE(), @RFC3265
 */

/** Unsubscribe an event. 
 *
 * Unsubscribe an active or pending subscription with SUBSCRIBE request 
 * containing Expires: header with value 0. The dialog associated with 
 * subscription will be destroyed if there is no other subscriptions or 
 * call using this dialog.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    SIPTAG_EVENT() or SIPTAG_EVENT_STR() \n
 *    Tags in <sip_tag.h> except SIPTAG_EXPIRES() or SIPTAG_EXPIRES_STR()
 *
 * @par Events:
 *    #nua_r_unsubscribe 
 *
 * @sa NUTAG_SUBSTATE(), @RFC3265
 */

static int nua_subscribe_client_init(nua_client_request_t *cr, 
				     msg_t *, sip_t *,
				     tagi_t const *tags);
static int nua_subscribe_client_request(nua_client_request_t *cr,
					msg_t *, sip_t *,
					tagi_t const *tags);
static int nua_subscribe_client_response(nua_client_request_t *cr,
					 int status, char const *phrase,
					 sip_t const *sip);

static nua_client_methods_t const nua_subscribe_client_methods = {
  SIP_METHOD_SUBSCRIBE,
  0,
  { 
    /* create_dialog */ 1,
    /* in_dialog */ 1,
    /* target refresh */ 1
  },
  NULL,
  nua_subscribe_client_init,
  nua_subscribe_client_request,
  /* nua_subscribe_client_check_restart */ NULL,
  nua_subscribe_client_response
};

int
nua_stack_subscribe(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		    tagi_t const *tags)
{
  return nua_client_create(nh, e, &nua_subscribe_client_methods, tags);
}

static int nua_subscribe_client_init(nua_client_request_t *cr,
				     msg_t *msg, sip_t *sip,
				     tagi_t const *tags)
{
  nua_handle_t *nh = cr->cr_owner;
  nua_dialog_usage_t *du;
  sip_event_t *o = sip->sip_event;

  du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, o);

  if (du == NULL && o == NULL)
    du = nua_dialog_usage_get(nh->nh_ds, nua_subscribe_usage, NONE);

  if (du) {
    if (du->du_event && o == NULL)
      /* Add Event header */
      sip_add_dup(msg, sip, (sip_header_t *)du->du_event);
  }
  else if (cr->cr_event == nua_r_subscribe) {	
    /* Create dialog usage */
    du = nua_dialog_usage_add(nh, nh->nh_ds, nua_subscribe_usage, o);
    /* Note that we allow SUBSCRIBE without event */
  }

  cr->cr_usage = du;

  return 0;
}

static int nua_subscribe_client_request(nua_client_request_t *cr,
					msg_t *msg, sip_t *sip,
					tagi_t const *tags)
{
  nua_dialog_usage_t *du = cr->cr_usage; 
  sip_time_t expires = 0;

  if (cr->cr_event != nua_r_subscribe ||
      (du && du->du_shutdown) ||
      (sip->sip_expires && sip->sip_expires->ex_delta == 0))
    cr->cr_terminating = 1;

  if (du) {
    struct event_usage *eu = nua_dialog_usage_private(du);
    sip_event_t *o = sip->sip_event;

    if (nua_client_bind(cr, du) < 0)
      return -1;

    if (eu->eu_no_id && o && o->o_id) {
      /* Notifier does not handle id properly, remove it */
      msg_header_remove_param(o->o_common, "id");
    }

#if 0
    if (cr->cr_terminating) {
      /* Already terminated subscription? */
      if (eu->eu_substate == nua_substate_terminated ||
	  eu->eu_substate == nua_substate_embryonic) {
	return nua_client_return(cr, SIP_200_OK, msg);
      }
    }
#endif

    nua_dialog_usage_reset_refresh(du); /* during SUBSCRIBE transaction */
    
    if (cr->cr_terminating)
      expires = eu->eu_expires = 0;
    else if (sip->sip_expires)
      /* Use value specified by application or negotiated with Min-Expires */
      expires = eu->eu_expires = sip->sip_expires->ex_delta;
    else
    /* We just use common default value, but the default is actually
       package-specific according to the RFC 3265 section 4.4.4:
       [Event] packages MUST also define a
       default "Expires" value to be used if none is specified. */
      expires = eu->eu_expires = 3600;

    eu->eu_final_wait = 0;

    if (eu->eu_substate == nua_substate_terminated)
      eu->eu_substate = nua_substate_embryonic;
  }

  if (!sip->sip_expires || sip->sip_expires->ex_delta != expires) {
    sip_expires_t ex[1];
    sip_expires_init(ex)->ex_delta = expires;
    sip_add_dup(msg, sip, (sip_header_t *)ex);
  }

  return nua_base_client_request(cr, msg, sip, tags);
}

/** @NUA_EVENT nua_r_subscribe
 *
 * Response to an outgoing SUBSCRIBE request.
 *
 * The SUBSCRIBE request may have been sent explicitly by nua_subscribe() or
 * implicitly by NUA state machine.
 *
 * @param status response status code
 *               (if the request is retried, @a status is 100, the @a
 *               sip->sip_status->st_status contain the real status code
 *               from the response message, e.g., 302, 401, or 407)
 * @param phrase a short textual description of @a status code
 * @param nh     operation handle associated with the subscription
 * @param hmagic application context associated with the handle
 * @param sip    response to SUBSCRIBE request or NULL upon an error
 *               (status code is in @a status and 
 *                descriptive message in @a phrase parameters)
 * @param tags   NUTAG_SUBSTATE()
 *
 * @sa nua_subscribe(), @RFC3265
 *
 * @END_NUA_EVENT
 */

/** @NUA_EVENT nua_r_unsubscribe
 *
 * Response to an outgoing un-SUBSCRIBE.
 *
 * @param status response status code
 *               (if the request is retried, @a status is 100, the @a
 *               sip->sip_status->st_status contain the real status code
 *               from the response message, e.g., 302, 401, or 407)
 * @param phrase a short textual description of @a status code
 * @param nh     operation handle associated with the subscription
 * @param hmagic application context associated with the handle
 * @param sip    response to SUBSCRIBE request or NULL upon an error
 *               (status code is in @a status and 
 *                descriptive message in @a phrase parameters)
 * @param tags   NUTAG_SUBSTATE()
 *
 * @sa nua_unsubscribe(), @RFC3265
 *
 * @END_NUA_EVENT
 */

static int nua_subscribe_client_response(nua_client_request_t *cr,
					 int status, char const *phrase,
					 sip_t const *sip)
{
  nua_handle_t *nh = cr->cr_owner;
  nua_dialog_usage_t *du = cr->cr_usage; 
  struct event_usage *eu = nua_dialog_usage_private(du);
  enum nua_substate substate;

  if (eu == NULL || cr->cr_terminated)
    substate = nua_substate_terminated;
  else if (status >= 300)
    substate = eu->eu_substate;
  else {
    int win_messenger_enable = NH_PGET(nh, win_messenger_enable);
    sip_time_t delta, now = sip_now();

    du->du_ready = 1;

    if (eu->eu_substate != nua_substate_terminated)
      /* If there is no @Expires header, 
	 use default value stored in eu_expires */
      delta = sip_contact_expires(NULL, sip->sip_expires, sip->sip_date, 
				  eu->eu_expires, now);
    else
      delta = 0;

    if (win_messenger_enable && !nua_dialog_is_established(nh->nh_ds)) {
      /* Notify from messanger does not match with dialog tag */ 
      nh->nh_ds->ds_remote_tag = su_strdup(nh->nh_home, "");
    }

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
	
      if (eu->eu_substate == nua_substate_terminated)
	eu->eu_substate = nua_substate_embryonic;

      nua_dialog_usage_refresh_range(du, delta, delta);
    }
    else {
      eu->eu_substate = nua_substate_terminated;
    }

    substate = eu->eu_substate;

    if (substate == nua_substate_terminated)
      /* let nua_base_client_tresponse to remove usage */
      cr->cr_terminated = 1;	
  }
  
  return nua_base_client_tresponse(cr, status, phrase, sip, 
				   NUTAG_SUBSTATE(substate),
				   TAG_END());
}

/** Refresh subscription */
static void nua_subscribe_usage_refresh(nua_handle_t *nh,
					nua_dialog_state_t *ds,
					nua_dialog_usage_t *du,
					sip_time_t now)
{
  nua_client_request_t *cr = du->du_cr;
  struct event_usage *eu = nua_dialog_usage_private(du);
  
  assert(eu);
  
  if (eu->eu_final_wait) {
    /* Did not receive NOTIFY for fetch */
    sip_event_t const *o = du->du_event;
    char const *id = o ? o->o_id : NULL;

    SU_DEBUG_3(("nua(%p): event %s%s%s fetch timeouts\n",
		nh, o ? o->o_type : "(empty)",
		id ? "; id=" : "", id ? id : ""));

    nua_stack_tevent(nh->nh_nua, nh,  NULL,
		     nua_i_notify, 408, "Fetch Timeouts without NOTIFY", 
		     NUTAG_SUBSTATE(nua_substate_terminated),
		     SIPTAG_EVENT(du->du_event),
		     TAG_END());
    nua_dialog_usage_remove(nh, ds, du);

    return;
  }

  if (cr) {
    if (nua_client_is_queued(cr) || /* Already refreshing */
	nua_client_resend_request(cr, 0, NULL) >= 0)
      return;
  }
  else if (eu->eu_refer) {
    /*
     * XXX - If we have received a NOTIFY, we should try to terminate
     * subscription
     */
  }

  nua_stack_tevent(nh->nh_nua, nh, NULL,
		   nua_i_notify, NUA_INTERNAL_ERROR,
		   NUTAG_SUBSTATE(nua_substate_terminated),
		   SIPTAG_EVENT(du->du_event),
		   TAG_END());

  nua_dialog_usage_remove(nh, ds, du);
}

/** Terminate subscription.
 *
 * @retval >0  shutdown done
 * @retval 0   shutdown in progress
 * @retval <0  try again later
 */
static int nua_subscribe_usage_shutdown(nua_handle_t *nh,
					nua_dialog_state_t *ds,
					nua_dialog_usage_t *du)
{
  struct event_usage *eu = nua_dialog_usage_private(du);
  nua_client_request_t *cr = du->du_cr;

  assert(eu); (void)eu;

  if (cr) {
    if (nua_client_is_queued(cr)) /* Subscribing. */
      return -1;  /* Request in progress */

    if (nua_client_resend_request(cr, 1, NULL) >= 0)
      return 0;
  }
  
  nua_dialog_usage_remove(nh, ds, du);
  return 200;
}

/* ======================================================================== */
/* NOTIFY server */

/** @NUA_EVENT nua_i_notify
 *
 * Event for incoming NOTIFY request.
 *
 * @param status statuscode of response sent automatically by stack
 * @param phrase a short textual description of @a status code
 * @param nh     operation handle associated with the subscription
 * @param hmagic application context associated with the handle
 * @param sip    incoming NOTIFY request
 * @param tags   NUTAG_SUBSTATE() indicating the subscription state
 *
 * @sa nua_subscribe(), nua_unsubscribe(), @RFC3265, #nua_i_subscribe
 * 
 * @END_NUA_EVENT
 */

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
  eu->eu_notified++;

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

  if (du->du_shutdown || (du->du_cr && du->du_cr->cr_terminating))
    retry = -1;
  
  response = nh_make_response(nua, nh, irq, SIP_200_OK,
			      SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			      TAG_END());

  if (response)
    nta_incoming_mreply(irq, response);
  else
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());

  if (eu->eu_substate == nua_substate_terminated && retry > 0)
    eu->eu_substate = nua_substate_embryonic;

  nua_stack_tevent(nh->nh_nua, nh, nta_incoming_getrequest(irq),
		   nua_i_notify, SIP_200_OK, 
		   NUTAG_SUBSTATE(eu->eu_substate),
		   TAG_END());

  nta_incoming_destroy(irq), irq = NULL;

  SU_DEBUG_5(("nua(%p): nua_stack_process_notify: %s (%s)\n", 
	      nh, what, why ? why : ""));

  if (eu->eu_substate == nua_substate_terminated) {
    /* Leaves subscribe client transaction without cr_usage  */
    nua_dialog_usage_remove(nh, nh->nh_ds, du);	
  }
  else if (eu->eu_substate == nua_substate_embryonic) {
    if (retry >= 0) {
      /* Try to subscribe again */
      nua_dialog_remove(nh, nh->nh_ds, du); /* tear down */
      nua_dialog_usage_refresh_range(du, retry, retry + 5);
    }
    else
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (retry < 0) {
    nua_dialog_usage_reset_refresh(du);
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

/** Transfer a call. 
 * 
 * Send a REFER request asking the recipient to transfer the call. 
 *
 * The REFER request also establishes an implied subscription to the "refer"
 * event. The "refer" event can have an "id" parameter, which has the value
 * of CSeq number in the REFER request. After initiating the REFER request,
 * the nua engine sends application a #nua_r_refer event with status 100 and
 * tag NUTAG_REFER_EVENT() containing a matching event header with id
 * parameter.
 *
 * Note that the @Event header in the locally generated #nua_r_refer event
 * contains the @a id parameter. The @a id parameter contains the @CSeq
 * number of the REFER request, and it may get incremented if the request is
 * retried because it got challenged or redirected. In that case, the
 * application gets a new #nua_r_refer event with status 100 and tag
 * NUTAG_REFER_EVENT(). Also the recipient of the REFER request may or may
 * not include the @a id parameter with the @Event header in the NOTIFY
 * requests messages which it sends to the sender of the REFER request.
 *
 * Therefore the application is not able to modify the state of the implied
 * subscription before receiving the first NOTIFY request.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_URL() \n
 *    Tags of nua_set_hparams() \n
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_refer \n
 *    #nua_i_notify
 *
 * @sa #nua_r_refer, NUTAG_SUBSTATE(), NUTAG_REFER_EVENT(),#nua_i_refer,
 * @RFC3515, @ReferTo, @RFC3892, @ReferredBy
 */

/**@NUA_EVENT nua_r_refer
 *
 * @brief Response to outgoing REFER.
 *
 * @param status response status code
 *               (if the request is retried, @a status is 100, the @a
 *               sip->sip_status->st_status contain the real status code
 *               from the response message, e.g., 302, 401, or 407)
 * @param phrase a short textual description of @a status code
 * @param nh     operation handle associated with the REFER request
 * @param hmagic application context associated with the handle
 * @param sip    response to REFER request or NULL upon an error
 *               (status code is in @a status and 
 *                descriptive message in @a phrase parameters)
 * @param tags    NUTAG_REFER_EVENT() \n
 *                NUTAG_SUBSTATE()
 *
 * @sa nua_refer(), NUTAG_SUBSTATE(), #nua_i_refer,
 * @RFC3515, @ReferTo, @RFC3892, @ReferredBy
 *
 * @END_NUA_EVENT
 */

static int nua_refer_client_init(nua_client_request_t *cr, 
				 msg_t *, sip_t *,
				 tagi_t const *tags);
static int nua_refer_client_request(nua_client_request_t *cr,
				    msg_t *, sip_t *,
				    tagi_t const *tags);
static int nua_refer_client_response(nua_client_request_t *cr,
				     int status, char const *phrase,
				     sip_t const *sip);

static nua_client_methods_t const nua_refer_client_methods = {
  SIP_METHOD_REFER,
  0,
  { 
    /* create_dialog */ 1,
    /* in_dialog */ 1,
    /* target refresh */ 1
  },
  /*nua_refer_client_template*/ NULL,
  nua_refer_client_init,
  nua_refer_client_request,
  /* nua_refer_client_check_restart */ NULL,
  nua_refer_client_response,
  nua_refer_client_response,	/* Preliminary */
  NULL
};

int
nua_stack_refer(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		    tagi_t const *tags)
{
  return nua_client_create(nh, e, &nua_refer_client_methods, tags);
}

static int nua_refer_client_init(nua_client_request_t *cr,
				 msg_t *msg, sip_t *sip,
				 tagi_t const *tags)
{
  nua_handle_t *nh = cr->cr_owner;

  if (sip->sip_referred_by == NULL) {
    sip_from_t *a = sip->sip_from;
    sip_referred_by_t by[1];

    sip_referred_by_init(by);

    if (a == NULL)
      a = nh->nh_nua->nua_from;
    by->b_display = a->a_display;
    *by->b_url = *a->a_url;

    sip_add_dup(msg, sip, (sip_header_t *)by);
  }

  if (sip->sip_event)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_event);

  return 0;
}

static int nua_refer_client_request(nua_client_request_t *cr,
				    msg_t *msg, sip_t *sip,
				    tagi_t const *tags)
{
  nua_handle_t *nh = cr->cr_owner;
  nua_dialog_usage_t *du = cr->cr_usage;
  struct event_usage *eu;
  sip_event_t *event;
  int error;

  cr->cr_usage = NULL;

  if (du)
    nua_dialog_usage_remove(nh, nh->nh_ds, du);

  event = sip_event_format(nh->nh_home, "refer;id=%u", sip->sip_cseq->cs_seq);
  if (!event)
    return -1;
  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_subscribe_usage, event);
  if (!du)
    return -1;

  eu = nua_dialog_usage_private(cr->cr_usage = du);
  eu ->eu_refer = 1;

  error = nua_base_client_request(cr, msg, sip, tags);

  if (!error) {
    /* Give application an Event header for matching NOTIFYs with REFER */
    nua_stack_tevent(nh->nh_nua, nh, NULL,
		     cr->cr_event, SIP_100_TRYING,
		     NUTAG_REFER_EVENT(event),
		     TAG_END());
    su_free(nh->nh_home, event);
  }

  return error;
}

static int nua_refer_client_response(nua_client_request_t *cr,
				     int status, char const *phrase,
				     sip_t const *sip)
{
  nua_dialog_usage_t *du = cr->cr_usage; 
  enum nua_substate substate = nua_substate_terminated;

  if (du) {
    struct event_usage *eu = nua_dialog_usage_private(du);

    if (status < 200) {
      substate = eu->eu_substate;      
    } 
    else if (status < 300) {
      sip_refer_sub_t const *rs = sip_refer_sub(sip);

      if (rs && strcasecmp("false", rs->rs_value) == 0)
	cr->cr_terminated = 1;

      if (!cr->cr_terminated)
	substate = eu->eu_substate;
    }
  }
  
  return nua_base_client_tresponse(cr, status, phrase, sip, 
				   NUTAG_SUBSTATE(substate),
				   TAG_END());
}
