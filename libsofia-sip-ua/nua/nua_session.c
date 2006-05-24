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

/**@CFILE nua_session.c
 * @brief SIP session handling
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 16:17:27 EET 2006 ppessi
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
#include <sofia-sip/soa.h>

#if !defined(random) && defined(_WIN32)
#define random rand
#endif

#ifndef SDP_H
typedef struct sdp_session_s sdp_session_t;
#endif

/* ---------------------------------------------------------------------- */
/* Session event usage */

struct session_usage;

static char const *nua_session_usage_name(nua_dialog_usage_t const *du);
static int nua_session_usage_add(nua_handle_t *nh,
				 nua_dialog_state_t *ds,
				 nua_dialog_usage_t *du);
static void nua_session_usage_remove(nua_handle_t *nh,
				     nua_dialog_state_t *ds,
				     nua_dialog_usage_t *du);

static nua_usage_class const nua_session_usage[1] = {
  {
    0 /* sizeof (struct session_usage) */,
    sizeof nua_session_usage,
    nua_session_usage_add,
    nua_session_usage_remove,
    nua_session_usage_name,
  }};

static char const *nua_session_usage_name(nua_dialog_usage_t const *du)
{
  return "session";
}

static
int nua_session_usage_add(nua_handle_t *nh,
			   nua_dialog_state_t *ds,
			   nua_dialog_usage_t *du)
{
  if (ds->ds_has_session)
    return -1;
  ds->ds_has_session = 1;
  return 0;
}

static
void nua_session_usage_remove(nua_handle_t *nh,
			       nua_dialog_state_t *ds,
			       nua_dialog_usage_t *du)
{
  ds->ds_has_session = 0;
}

/* ======================================================================== */
/* INVITE and call (session) processing */

static int ua_invite2(nua_t *, nua_handle_t *, nua_event_t e,
		      int restarted, tagi_t const *tags);
static int process_response_to_invite(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip);
static int process_100rel(nua_handle_t *nh,
			  nta_outgoing_t *orq,
			  sip_t const *sip);
static void
  cancel_invite(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now),
  refresh_invite(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now),
  session_timeout(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now);

static void restart_invite(nua_handle_t *nh, tagi_t *tags);

static int process_response_to_prack(nua_handle_t *nh,
				     nta_outgoing_t *orq,
				     sip_t const *sip);

static void nsession_destroy(nua_handle_t *nh);

static int  use_session_timer(nua_handle_t *nh, int uas, msg_t *msg, sip_t *);
static int  init_session_timer(nua_handle_t *nh, sip_t const *);
static void set_session_timer(nua_handle_t *nh);

static int nh_referral_check(nua_handle_t *nh, tagi_t const *tags);
static void nh_referral_respond(nua_handle_t *,
				int status, char const *phrase);

static void signal_call_state_change(nua_handle_t *nh,
				     int status, char const *phrase,
				     enum nua_callstate next_state,
				     char const *oa_recv,
				     char const *oa_sent);

static
int session_get_description(msg_t *msg,
			    sip_t const *sip,
			    char const **return_sdp,
			    size_t *return_len);

static
int session_include_description(soa_session_t *soa,
				msg_t *msg,
				sip_t *sip);

static
int session_make_description(su_home_t *home,
			     soa_session_t *soa,
			     sip_content_disposition_t **return_cd,
			     sip_content_type_t **return_ct,
			     sip_payload_t **return_pl);

static
int session_process_response(nua_handle_t *nh,
			     struct nua_client_request *cr,
			     nta_outgoing_t *orq,
			     sip_t const *sip,
			     char const **return_received);

int
nua_stack_invite(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		 tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  struct nua_client_request *cr = ss->ss_crequest;
  char const *what;

  if (nh_is_special(nh))
    what = "Invalid handle for INVITE";
  else if (cr->cr_orq) {
    what = "INVITE request already in progress";
  }
  else if (nh_referral_check(nh, tags) < 0) {
    what = "Invalid referral";
  }
  else if (nua_stack_init_handle(nua, nh, nh_has_invite, NULL,
				 TAG_NEXT(tags)) < 0) {
    what = "Handle initialization failed";
  }
  else
    return ua_invite2(nua, nh, e, 0, tags);

  UA_EVENT2(e, 900, what);

  signal_call_state_change(nh, 900, what, nua_callstate_init, 0, 0);

  return e;
}

static int
ua_invite2(nua_t *nua, nua_handle_t *nh, nua_event_t e, int restarted,
	   tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  struct nua_client_request *cr = ss->ss_crequest;
  nua_dialog_usage_t *du;
  int offer_sent = 0;

  msg_t *msg = NULL;
  sip_t *sip;

  char const *what;

  if (ss->ss_state == nua_callstate_terminated)
    ss->ss_state = nua_callstate_init;

  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_session_usage, NULL);
  what = nua_internal_error;		/* Internal error */

  msg = du ? nua_creq_msg(nua, nh, cr, restarted,
			      SIP_METHOD_INVITE,
			      NUTAG_USE_DIALOG(1),
			      NUTAG_ADD_CONTACT(1),
			      TAG_NEXT(tags)) : NULL;
  sip = sip_object(msg);

  if (du && sip && nh->nh_soa) {
    soa_init_offer_answer(nh->nh_soa);

    if (sip->sip_payload)
      offer_sent = 0;
    else if (soa_generate_offer(nh->nh_soa, 0, NULL) < 0)
      offer_sent = -1;
    else
      offer_sent = 1;
  }

  assert(cr->cr_orq == NULL);

  if (du && sip && offer_sent >= 0) {
    sip_time_t invite_timeout = NH_PGET(nh, invite_timeout);
    if (invite_timeout == 0)
      invite_timeout = UINT_MAX;
    /* Cancel if we don't get response */
    nua_dialog_usage_set_refresh(du, invite_timeout);

    /* Add session timer headers */
    use_session_timer(nh, 0, msg, sip);

    ss->ss_100rel = NH_PGET(nh, early_media);
    ss->ss_precondition = sip_has_feature(sip->sip_require, "precondition");

    if (ss->ss_precondition)
      ss->ss_update_needed = ss->ss_100rel = 1;

    if (offer_sent > 0 &&
	session_include_description(nh->nh_soa, msg, sip) < 0)
      sip = NULL, what = "Internal media error";

    if (sip && nh->nh_soa &&
	NH_PGET(nh, media_features) && !nua_dialog_is_established(nh->nh_ds) &&
	!sip->sip_accept_contact && !sip->sip_reject_contact) {
      sip_accept_contact_t ac[1];
      sip_accept_contact_init(ac);

      ac->cp_params = (msg_param_t *)
	soa_media_features(nh->nh_soa, 1, msg_home(msg));

      if (ac->cp_params) {
	msg_header_replace_param(msg_home(msg), ac->cp_common, "explicit");
	sip_add_dup(msg, sip, (sip_header_t *)ac);
      }
    }

    if (sip && nh->nh_auth) {
      if (auc_authorize(&nh->nh_auth, msg, sip) < 0)
	sip = NULL, what = "Internal authentication error";
    }
    if (sip)
      cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
					process_response_to_invite, nh, NULL,
					msg,
					NTATAG_REL100(ss->ss_100rel),
					SIPTAG_END(), TAG_NEXT(tags));

    if (cr->cr_orq) {
      cr->cr_offer_sent = offer_sent;
      cr->cr_usage = du;
      du->du_pending = cancel_invite;
      du->du_refresh = 0;
      signal_call_state_change(nh, 0, "INVITE sent",
			       nua_callstate_calling, 0,
			       offer_sent ? "offer" : 0);
      return cr->cr_event = e;
    }
  }

  msg_destroy(msg);
  if (du && !du->du_ready)
    nua_dialog_usage_remove(nh, nh->nh_ds, du);

  UA_EVENT2(e, 900, what);
  signal_call_state_change(nh, 900, what, nua_callstate_init, 0, 0);

  return e;
}

static int process_response_to_invite(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip)
{
  nua_t *nua = nh->nh_nua;
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cr = ss->ss_crequest;
  nua_dialog_usage_t *du = cr->cr_usage;
  int status = sip->sip_status->st_status;
  char const *phrase = sip->sip_status->st_phrase;
  int terminated = 0;
  int gracefully = 1;
  char const *received = NULL;

  assert(du);

#if HAVE_SOFIA_SMIME
  if (status < 300) {
    int sm_status;
    msg_t *response;

    /* decrypt sdp payload if it's S/MIME */
    /* XXX msg had a problem!!?? */
    response = nta_outgoing_getresponse(orq);

    sm_status = sm_decode_message(nua->sm, response, sip);

    switch (sm_status) {
    case SM_SMIME_DISABLED:
    case SM_ERROR:
      status = 493, phrase = "Undecipherable";
      break;
    case SM_SUCCESS:
      break;
    default:
      break;
    }
  }
#endif

  if (status >= 300) {
    if (sip->sip_retry_after)
      gracefully = 0;

    terminated = sip_response_terminates_dialog(status, sip_method_invite,
						&gracefully);

    if (!terminated) {
      if (nua_creq_check_restart(nh, cr, orq, sip, restart_invite))
	return 0;

      if (nh->nh_ss->ss_state < nua_callstate_ready)
	terminated = 1;
    }
  }
  else if (status >= 200) {

    du->du_ready = 1;
    if (!ss->ss_usage)
      ss->ss_usage = du;
    cr->cr_usage = NULL;

    /* XXX - check remote tag, handle forks */
    /* Set route, contact, nh_ds->ds_remote_tag */
    nua_dialog_uac_route(nh, nh->nh_ds, sip, 1);
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

    init_session_timer(nh, sip);

    set_session_timer(nh);

    /* signal_call_state_change */
    if (session_process_response(nh, cr, orq, sip, &received) >= 0) {
      ss->ss_ack_needed = received ? received : "";

      if (NH_PGET(nh, auto_ack) ||
	  /* Auto-ACK response to re-INVITE unless auto_ack is set to 0 */
	  (ss->ss_state == nua_callstate_ready &&
	   !NH_PISSET(nh, auto_ack)))
	nua_stack_ack(nua, nh, nua_r_ack, NULL);
      else
	signal_call_state_change(nh, status, phrase,
				 nua_callstate_completing, received, 0);
      nh_referral_respond(nh, SIP_200_OK);
      return 0;
    }

    status = 900, phrase = "Malformed Session in Response";

    nua_stack_ack(nua, nh, nua_r_ack, NULL);
    gracefully = 1;
  }
  else if (sip->sip_rseq) {
    /* Reliable provisional response */
    nh_referral_respond(nh, status, phrase);

    return process_100rel(nh, orq, sip); /* signal_call_state_change */
  }
  else {
    /* Provisional response */
    nh_referral_respond(nh, status, phrase);
    session_process_response(nh, cr, orq, sip, &received);
    signal_call_state_change(nh, status, phrase,
			     nua_callstate_proceeding, received, 0);
    return 0;
  }

  cr->cr_usage = NULL;

  nh_referral_respond(nh, status, phrase);
  nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  if (terminated)
    signal_call_state_change(nh, status, phrase,
			     nua_callstate_terminated, 0, 0);

  if (terminated < 0) {
    nua_dialog_terminated(nh, nh->nh_ds, status, phrase);
  }
  else if (terminated > 0) {
    nua_dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (gracefully) {
    char *reason =
      su_sprintf(NULL, "SIP;cause=%u;text=\"%s\"", status, phrase);

    signal_call_state_change(nh, status, phrase,
			     nua_callstate_terminating, 0, 0);

    nua_stack_post_signal(nh, nua_r_bye,
			  SIPTAG_REASON_STR(reason),
			  TAG_END());

    su_free(NULL, reason);
  }

  return 0;
}

int nua_stack_ack(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		  tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  struct nua_client_request *cr = ss->ss_crequest;
  nta_outgoing_t *ack = NULL;
  msg_t *msg;
  sip_t *sip;
  int status = 200;
  char const *phrase = "OK", *reason = NULL, *sent = NULL;
  char const *received = ss->ss_ack_needed;

  if (!ss->ss_ack_needed)
    return UA_EVENT2(nua_i_error, 900, "No response to ACK");

  ss->ss_ack_needed = 0;

  if (!received[0])
    received = NULL;

  if (tags) {
    nua_stack_set_params(nua, nh, nua_r_ack, tags);
  }

  msg = nua_creq_msg(nua, nh, cr, 0,
			 SIP_METHOD_ACK,
			 /* NUTAG_COPY(0), */
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip && nh->nh_soa) {
    if (tags)
      soa_set_params(nh->nh_soa, TAG_NEXT(tags));

    if (cr->cr_offer_recv && !cr->cr_answer_sent) {
      if (soa_generate_answer(nh->nh_soa, NULL) < 0 ||
	  session_include_description(nh->nh_soa, msg, sip) < 0) {
	reason = soa_error_as_sip_reason(nh->nh_soa);
	status = 900, phrase = "Internal media error";
	reason = "SIP;cause=500;text=\"Internal media error\"";
      }
      else {
	cr->cr_answer_sent = 1;
	soa_activate(nh->nh_soa, NULL);

	/* signal that O/A round is complete */
	sent = "answer";
      }
    }

    if (!reason &&
	/* ss->ss_offer_sent && !ss->ss_answer_recv */
	!soa_is_complete(nh->nh_soa)) {
      /* No SDP answer in 2XX response -> terminate call */
      status = 988, phrase = "Incomplete offer/answer";
      reason = "SIP;cause=488;text=\"Incomplete offer/answer\"";
    }
  }

  if (sip)
    ack = nta_outgoing_mcreate(nua->nua_nta, NULL, NULL, NULL, msg,
			       SIPTAG_END(), TAG_NEXT(tags));

  if (!ack) {
    if (!reason) {
      status = 900, phrase = "Cannot send ACK";
      reason = "SIP;cause=500;text=\"Internal Error\"";
    }
    msg_destroy(msg);
  }

  nua_creq_deinit(cr, NULL);	/* Destroy INVITE transaction */
  nta_outgoing_destroy(ack);	/* TR engine keeps this around for T2 */

  if (status < 300) {
    signal_call_state_change(nh, status, phrase, nua_callstate_ready,
			     received, sent);
  }
  else {
    signal_call_state_change(nh, status, phrase, nua_callstate_terminating,
			     0, 0);
    nua_stack_post_signal(nh, nua_r_bye,
			  SIPTAG_REASON_STR(reason),
			  TAG_END());
  }

  return 0;
}

static int
process_100rel(nua_handle_t *nh,
	       nta_outgoing_t *orq,
	       sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  struct nua_client_request *cr_invite = ss->ss_crequest;
  struct nua_client_request *cr_prack = nh->nh_cr;

  /* Reliable provisional response */
  sip_content_disposition_t *cd = NULL;
  sip_content_type_t *ct = NULL;
  sip_payload_t *pl = NULL;

  nta_outgoing_t *prack;

  char const *recv = NULL, *sent = NULL;
  int status = 408;
  int offer_sent_in_prack = 0, answer_sent_in_prack = 0;

  su_home_t home[1] = { SU_HOME_INIT(home) };

  if (cr_prack->cr_orq) {
    SU_DEBUG_3(("nua(%p): cannot send PRACK because %s is pending\n", nh,
		nta_outgoing_method_name(cr_prack->cr_orq)));
    return 0;			/* We have to wait! */
  }

  if (sip && sip->sip_status)
    status = sip->sip_status->st_status;

  if (!nua_dialog_is_established(nh->nh_ds)) {
    /* Tag the INVITE request */
    nua_dialog_uac_route(nh, nh->nh_ds, sip, 1);
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

    cr_invite->cr_orq =
      nta_outgoing_tagged(orq, process_response_to_invite, nh,
			  sip->sip_to->a_tag, sip->sip_rseq);
    nta_outgoing_destroy(orq);
    orq = cr_invite->cr_orq;
  }

  if (session_process_response(nh, cr_invite, orq, sip, &recv) < 0) {
    /* XXX */
  }
  else if (cr_invite->cr_offer_recv && !cr_invite->cr_answer_sent) {
    if (soa_generate_answer(nh->nh_soa, NULL) < 0 ||
	session_make_description(home, nh->nh_soa, &cd, &ct, &pl) < 0)
      /* XXX */;
    else {
      answer_sent_in_prack = 1, sent = "answer";
      soa_activate(nh->nh_soa, NULL);
    }
  }
  else if (ss->ss_precondition && status == 183) { /* XXX */
    if (soa_generate_offer(nh->nh_soa, 0, NULL) < 0 ||
	session_make_description(home, nh->nh_soa, &cd, &ct, &pl) < 0)
      /* XXX */;
    else
      offer_sent_in_prack = 1, sent = "offer";
  }

  prack = nta_outgoing_prack(nh->nh_ds->ds_leg, orq,
			     process_response_to_prack, nh, NULL,
			     sip,
			     SIPTAG_CONTENT_DISPOSITION(cd),
			     SIPTAG_CONTENT_TYPE(ct),
			     SIPTAG_PAYLOAD(pl),
			     TAG_END());

  if (prack) {
    cr_prack->cr_event = nua_r_prack;
    cr_prack->cr_orq = prack;
    if (answer_sent_in_prack)
      cr_invite->cr_answer_sent = 1;
    else if (offer_sent_in_prack)
      cr_prack->cr_offer_sent = 1;

    signal_call_state_change(nh,
			     sip->sip_status->st_status,
			     sip->sip_status->st_phrase,
			     nua_callstate_proceeding, recv, sent);
  }
  else {
    /* XXX - call state? */
    nua_stack_event(nh->nh_nua, nh, NULL, nua_i_error,
		    900, "Cannot PRACK",
		    TAG_END());
  }

  su_home_deinit(home);

  return 0;
}

static int
process_response_to_prack(nua_handle_t *nh,
			  nta_outgoing_t *orq,
			  sip_t const *sip)
{
  struct nua_client_request *cr = nh->nh_cr;
  int status;
  char const *phrase = "OK", *reason = NULL, *recv = NULL;

  if (sip)
    status = sip->sip_status->st_status, phrase = sip->sip_status->st_phrase;
  else
    status = 408, phrase = sip_408_Request_timeout;

  SU_DEBUG_5(("nua: process_response_to_prack: %u %s\n", status, phrase));

#if 0
  if (nua_creq_check_restart(nh, cr, orq, sip, restart_prack))
    return 0;
#endif

  if (status < 200)
    return 0;

  if (status < 300) {
    if (session_process_response(nh, cr, orq, sip, &recv) < 0) {
      status = 900, phrase = "Malformed Session in Response";
      reason = "SIP;status=400;phrase=\"Malformed Session in Response\"";
    }
  }
  else
    nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  if (recv)
    signal_call_state_change(nh, status, phrase,
			     nua_callstate_proceeding, recv, NULL);

  if (status < 300 && nh->nh_ss->ss_update_needed)
    nua_stack_update(nh->nh_nua, nh, nua_r_update, NULL);

  return 0;
}

static
char const reason_timeout[] = "SIP;cause=408;text=\"Session timeout\"";

void cancel_invite(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  static tagi_t const timeout_tags[] = {
    { siptag_reason_str, (tag_value_t)reason_timeout },
    { NULL }
  };

  signal_call_state_change(nh, 487, "Call Canceled",
			   nua_callstate_init, NULL, NULL);

  nua_stack_cancel(nh->nh_nua, nh, nua_r_destroy, timeout_tags);
}

void
refresh_invite(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  tagi_t tags[2] = 
    {{ SIPTAG_SUBJECT_STR("Session refresh") }, { TAG_END() }};

  if (now > 0 && NH_PGET(nh, update_refresh))
    nua_stack_update(nh->nh_nua, nh, nua_r_update, tags);
  else if (now > 0)
    nua_stack_invite(nh->nh_nua, nh, nua_r_invite, tags);
  else
    session_timeout(nh, du, SIP_TIME_MAX);
}

static void
session_timeout(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  if (now > 1) {
    signal_call_state_change(nh, 408, "Session Timeout",
			     nua_callstate_terminating, NULL, NULL);
    nua_stack_post_signal(nh, nua_r_bye,
			  SIPTAG_REASON_STR(reason_timeout),
			  TAG_END());
  }
}

/** Restart invite (e.g., after 302 or 407) */
void
restart_invite(nua_handle_t *nh, tagi_t *tags)
{
  ua_invite2(nh->nh_nua, nh, nua_r_invite, 1, tags);
}

static int process_response_to_cancel(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip);

/* CANCEL */
int
nua_stack_cancel(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		 tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cri = ss->ss_crequest;
  nua_client_request_t *crc = nh->nh_cr;

  if (nh && cri->cr_orq && cri->cr_usage &&
      cri->cr_usage->du_pending == cancel_invite) {
    nua_dialog_usage_t *du = cri->cr_usage;
    nta_outgoing_t *orq;

    du->du_pending = NULL;

    /* nh_referral_respond(nh, SIP_487_REQUEST_TERMINATED); */

    if (e)
      orq = nta_outgoing_tcancel(cri->cr_orq, process_response_to_cancel, nh,
				 TAG_NEXT(tags));
    else
      orq = nta_outgoing_tcancel(cri->cr_orq, NULL, NULL, TAG_NEXT(tags));

    if (orq == NULL)
      return nua_stack_event(nua, nh, NULL, e, 400, "Internal error",
			     TAG_END());

    if (e && crc->cr_orq == NULL)
      crc->cr_orq = orq, crc->cr_event = e;

    return 0;
  }

  return UA_EVENT2(e, 481, "No transaction to CANCEL");
}

static int process_response_to_cancel(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip)
{
  return nua_stack_process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

/* ---------------------------------------------------------------------- */
/* UAS side of INVITE */

static void respond_to_invite(nua_t *nua, nua_handle_t *nh,
			      int status, char const *phrase,
			      tagi_t const *tags);

static int
  process_invite1(nua_t *, nua_handle_t**, nta_incoming_t *, msg_t *, sip_t *),
  process_invite2(nua_t *, nua_handle_t *, nta_incoming_t *, sip_t *),
  process_prack(nua_handle_t *, nta_reliable_t *, nta_incoming_t *,
		sip_t const *),
  process_ack_or_cancel(nua_handle_t *, nta_incoming_t *, sip_t const *),
  process_ack(nua_handle_t *, nta_incoming_t *, sip_t const *),
  process_cancel(nua_handle_t *, nta_incoming_t *, sip_t const *),
  process_timeout(nua_handle_t *, nta_incoming_t *);

/** @internal Process incoming INVITE. */
int nua_stack_process_invite(nua_t *nua,
			     nua_handle_t *nh0,
			     nta_incoming_t *irq,
			     sip_t const *sip)
{
  nua_handle_t *nh = nh0;
  msg_t *msg = nta_incoming_getrequest(irq);
  int status;

  status = process_invite1(nua, &nh, irq, msg, (sip_t *)sip);

  if (status) {
    msg_destroy(msg);
    if (nh != nh0)
      nh_destroy(nua, nh);
    return status;
  }

  return process_invite2(nua, nh, irq, (sip_t *)sip);
}

/** @internal Preprocess incoming invite - sure we have a valid request. */
static
int process_invite1(nua_t *nua,
		    nua_handle_t **return_nh,
		    nta_incoming_t *irq,
		    msg_t *msg,
		    sip_t *sip)
{
  nua_handle_t *nh = *return_nh;
  nua_handle_t *dnh = nua->nua_dhandle, *nh0 = nh ? nh : dnh;
  nua_server_request_t *sr;
  int have_sdp;
  char const *sdp;
  size_t len;
  sip_user_agent_t const *user_agent = NH_PGET(nh0, user_agent);

#if HAVE_SOFIA_SMIME
  int sm_status;

  sm_status = sm_decode_message(nua->sm, msg, sip);
  switch(sm_status) {
  case SM_SMIME_DISABLED:
  case SM_ERROR:
    nta_incoming_treply(irq, 493, "Undecipherable", TAG_END());
    return 493;

  case SM_SUCCESS:
    break;
  default:
    break;
  }
#endif

  if (nh0->nh_soa) {
    /* Make sure caller uses application/sdp without compression */
    if (nta_check_session_content(irq, sip,
				  nua->nua_invite_accept,
				  SIPTAG_USER_AGENT(user_agent),
				  SIPTAG_ACCEPT_ENCODING_STR(""),
				  TAG_END()))
      return 415;

    /* Make sure caller accepts application/sdp */
    if (nta_check_accept(irq, sip,
			 nua->nua_invite_accept,
			 NULL,
			 SIPTAG_USER_AGENT(user_agent),
			 SIPTAG_ACCEPT_ENCODING_STR(""),
			 TAG_END()))
      return 406;
  }

  if (sip->sip_session_expires) {
    unsigned min_se = nh ? nh->nh_ss->ss_min_se : DNH_PGET(dnh, min_se);
    if (nta_check_session_expires(irq, sip,
				  min_se,
				  SIPTAG_USER_AGENT(user_agent),
				  TAG_END()))
      return 500; /* respond with 500 Internal Server Error  */
  }

  if (!nh) {
    if (!DNH_PGET(dnh, invite_enable))
      return 403;

    if (!(nh = nua_stack_incoming_handle(nua, irq, sip, nh_has_invite, 1)))
      return 500;
  }

  have_sdp = session_get_description(msg, sip, &sdp, &len);

  if (nh->nh_ss->ss_srequest->sr_irq
      /* XXX || (have_sdp && nh->nh_sr->sr_offer_recv) XXX */) {
    /* Overlapping invites - RFC 3261 14.2 */
    sip_retry_after_t af[1];

    /* Random delay of 0..10 seconds */
    sip_retry_after_init(af)->af_delta = (unsigned)random() % 11U;
    af->af_comment = "Overlapping INVITE Request";

    nta_incoming_treply(irq, 500, af->af_comment,
			SIPTAG_RETRY_AFTER(af),
			TAG_END());
    return 500;
  }

  if (nh->nh_ss->ss_crequest->cr_orq ||
      (have_sdp && nh->nh_cr->cr_orq && nh->nh_cr->cr_offer_sent)) {
    /* Glare - RFC 3261 14.2 and RFC 3311 section 5.2 */
    nta_incoming_treply(irq, SIP_491_REQUEST_PENDING, TAG_END());
    return 491;
  }

  *return_nh = nh;

  sr = nh->nh_ss->ss_srequest; memset(sr, 0, sizeof *sr);

  if (nh->nh_soa) {
    soa_init_offer_answer(nh->nh_soa);

    if (have_sdp) {
      if (soa_set_remote_sdp(nh->nh_soa, NULL, sdp, len) < 0) {
	SU_DEBUG_5(("nua(%p): error parsing SDP in INVITE\n", nh));
	nta_incoming_treply(irq, 400, "Bad Session Description", TAG_END());
	return 400;
      }
      sr->sr_offer_recv = 1;
    }
  }

  /** Add a dialog usage */
  if (!nh->nh_ss->ss_usage)
    nh->nh_ss->ss_usage =
      nua_dialog_usage_add(nh, nh->nh_ds, nua_session_usage, NULL);
  if (!nh->nh_ss->ss_usage) {
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    return 500;
  }

  sr->sr_msg = msg;
  sr->sr_irq = irq;

  return 0;
}

/** @internal Process incoming invite - initiate media, etc. */
static
int process_invite2(nua_t *nua,
		    nua_handle_t *nh,
		    nta_incoming_t *irq,
		    sip_t *sip)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;

  ss->ss_100rel = NH_PGET(nh, early_media);
  ss->ss_precondition = sip_has_feature(sip->sip_require, "precondition");
  if (ss->ss_precondition)
    ss->ss_100rel = 1;

  /* Session Timer negotiation */
  init_session_timer(nh, sip);

  nua_dialog_uas_route(nh, nh->nh_ds, sip, 1);	/* Set route and tags */

  nta_incoming_bind(irq, process_ack_or_cancel, nh);

  assert(ss->ss_state >= nua_callstate_ready ||
	 ss->ss_state == nua_callstate_init);

  /* Magical value indicating autoanswer within respond_to_invite() */
#define AUTOANSWER ((void*)-1)

  if (NH_PGET(nh, auto_answer) ||
      /* Auto-answert to re-INVITE unless auto_answer is set to 0 */
      (ss->ss_state == nua_callstate_ready &&
       !NH_PISSET(nh, auto_answer))) {
    respond_to_invite(nua, nh, SIP_200_OK, AUTOANSWER);
    return 0;
  }

  ss->ss_srequest->sr_respond = respond_to_invite;

  if (NH_PGET(nh, auto_alert)) {
    if (ss->ss_100rel &&
	(sip_has_feature(nh->nh_ds->ds_remote_ua->nr_supported, "100rel") ||
	 sip_has_feature(nh->nh_ds->ds_remote_ua->nr_require, "100rel"))) {
      respond_to_invite(nua, nh, SIP_183_SESSION_PROGRESS, AUTOANSWER);
    }
    else {
      respond_to_invite(nua, nh, SIP_180_RINGING, AUTOANSWER);
    }
  }
  else {
    nta_incoming_treply(irq, SIP_100_TRYING, TAG_END());

    nua_stack_event(nh->nh_nua, nh, sr->sr_msg,
	     nua_i_invite, SIP_100_TRYING,
	     NH_ACTIVE_MEDIA_TAGS(1, nh->nh_soa),
	     TAG_END());
    sr->sr_msg = NULL;

    signal_call_state_change(nh, SIP_100_TRYING,
			     nua_callstate_received,
			     sr->sr_offer_recv ? "offer" : 0, 0);
  }

  return 0;
}

/** @internal Respond to an INVITE request.
 *
 * XXX - use tags to indicate when to use reliable responses.
 * XXX - change prototype.
 */
static
void respond_to_invite(nua_t *nua, nua_handle_t *nh,
		       int status, char const *phrase,
		       tagi_t const *tags)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  msg_t *msg;
  sip_t *sip;
  int reliable;
  int original_status = status;
  sip_warning_t *warning = NULL;
  nua_dialog_state_t *ds = nh->nh_ds;
  nua_session_state_t *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;

  int autoanswer = 0, offer = 0, answer = 0;
  
  enter;

  if (ss->ss_srequest->sr_irq == NULL ||
      nta_incoming_status(ss->ss_srequest->sr_irq) >= 200) {
    nua_stack_event(nh->nh_nua, nh, NULL,
	     nua_i_error, 900, "No INVITE request to response", TAG_END());
    return;
  }

  if (tags == AUTOANSWER)
    autoanswer = 1, tags = NULL;

  assert(ss->ss_usage);

  if (nh->nh_soa)
    soa_set_params(nh->nh_soa, TAG_NEXT(tags));

  reliable =
    (status >= 200)
    || (status > 100 &&
	ds->ds_remote_ua->nr_require &&
	sip_has_feature(ds->ds_remote_ua->nr_require, "100rel"))
    || (status > 100 && !NH_PGET(nh, only183_100rel) && 
	(NH_PGET(nh, early_media) ||
	 (ds->ds_remote_ua->nr_require &&
	  sip_has_feature(ds->ds_remote_ua->nr_require, "precondition"))) && 
	ds->ds_remote_ua->nr_supported &&
	sip_has_feature(ds->ds_remote_ua->nr_supported, "100rel"))
    || (status == 183 &&
	ds->ds_remote_ua->nr_supported &&
	sip_has_feature(ds->ds_remote_ua->nr_supported, "100rel"))
    || (status == 183 &&
	ds->ds_remote_ua->nr_require &&
	sip_has_feature(ds->ds_remote_ua->nr_require, "precondition"))
    || (status > 100 &&
	ds->ds_remote_ua->nr_require &&
	sip_has_feature(ds->ds_remote_ua->nr_require, "precondition") &&
	sr->sr_offer_recv && !sr->sr_answer_sent);

  msg = nh_make_response(nua, nh, ss->ss_srequest->sr_irq,
			 status, phrase,
			 TAG_IF(status < 300, NUTAG_ADD_CONTACT(1)),
			 SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  assert(sip);			/* XXX */

  if (!nh->nh_soa)
    /* Xyzzy */;
  else if (status >= 300) {
    soa_clear_remote_sdp(nh->nh_soa);
  }
  else if (status >= 200 || ss->ss_100rel) {
    if ((sr->sr_offer_recv && sr->sr_answer_sent) ||
	(sr->sr_offer_sent && !sr->sr_answer_recv))
      /* Nothing to do */;
    else if (sr->sr_offer_recv && !sr->sr_answer_sent) {
      if (soa_generate_answer(nh->nh_soa, NULL) < 0) {
	int wcode;
	char const *text;
	char const *host = "invalid.";
	status = soa_error_as_sip_response(nh->nh_soa, &phrase);

	wcode = soa_get_warning(nh->nh_soa, &text);
	if (wcode) {
	  if (sip->sip_contact)
	    host = sip->sip_contact->m_url->url_host;
	  warning = sip_warning_format(home, "%u %s \"%s\"",
				       wcode, host, text);
	}
      }
      else {
	answer = 1;
	soa_activate(nh->nh_soa, NULL);
	/* signal that O/A answer sent (answer to invite) */
      }
    }
    else if (!sr->sr_offer_recv && !sr->sr_offer_sent) {
      if (soa_generate_offer(nh->nh_soa, 0, NULL) < 0)
	status = soa_error_as_sip_response(nh->nh_soa, &phrase);
      else
	offer = 1;
    }

    if (offer || answer) {
      if (session_include_description(nh->nh_soa, msg, sip) < 0)
	SET_STATUS1(SIP_500_INTERNAL_SERVER_ERROR);
    }
  }

  if (ss->ss_refresher && 200 <= status && status < 300)
    use_session_timer(nh, 1, msg, sip);

#if HAVE_SOFIA_SMIME
  if (nua->sm->sm_enable && sdp) {
    int sm_status;

    sm_status = sm_encode_message(nua->sm, msg, sip, SM_ID_NULL);

    switch (sm_status) {
    case SM_SUCCESS:
      break;
    case SM_ERROR:
      status = 500, phrase = "S/MIME processing error";
      break;
    case SM_CERT_NOTFOUND:
    case SM_CERTFILE_NOTFOUND:
      status = 500, phrase = "S/MIME certificate error";
      break;
    }
  }
#endif

  if (reliable && status < 200) {
    nta_reliable_t *rel;
    rel = nta_reliable_mreply(ss->ss_srequest->sr_irq,
			      process_prack, nh, msg);
    if (!rel)
      SET_STATUS1(SIP_500_INTERNAL_SERVER_ERROR);
  }

  if (reliable && status < 200)
    /* we are done */;
  else if (status != original_status) {    /* Error responding */
    assert(status >= 200);
    ss->ss_srequest->sr_respond = NULL;
    nta_incoming_treply(ss->ss_srequest->sr_irq,
			status, phrase,
			SIPTAG_WARNING(warning),
			TAG_END());
    msg_destroy(msg), msg = NULL;
  }
  else {
    if (status >= 200)
      ss->ss_srequest->sr_respond = NULL;
    nta_incoming_mreply(ss->ss_srequest->sr_irq, msg);
  }

  if (autoanswer) {
    nua_stack_event(nh->nh_nua, nh, sr->sr_msg,
	     nua_i_invite, status, phrase,
	     NH_ACTIVE_MEDIA_TAGS(1, nh->nh_soa),
	     TAG_END());
    sr->sr_msg = NULL;
  }
  else if (status != original_status)
    nua_stack_event(nua, nh, NULL, nua_i_error, status, phrase, TAG_END());

  if (status >= 300)
    offer = 0, answer = 0;

  if (offer)
    sr->sr_offer_sent = 1;
  else if (answer)
    sr->sr_answer_sent = 1 + reliable;

  /* Update session state */
  assert(ss->ss_state != nua_callstate_calling);
  assert(ss->ss_state != nua_callstate_proceeding);

  signal_call_state_change(nh, status, phrase,
			   status >= 300
			   ? nua_callstate_init
			   : status >= 200
			   ? nua_callstate_completed
			   : nua_callstate_early,
			   autoanswer && sr->sr_offer_recv ? "offer" : 0,
			   offer ? "offer" : answer ? "answer" : 0);

  if (status == 180)
    ss->ss_alerting = 1;
  else if (status >= 200)
    ss->ss_alerting = 0;

  if (status >= 200) {
    ss->ss_usage->du_ready = 1;
  }

  if (status >= 300) {
    if (nh->nh_soa)
      soa_init_offer_answer(nh->nh_soa);
    nta_incoming_destroy(ss->ss_srequest->sr_irq);
    ss->ss_srequest->sr_irq = NULL;
    ss->ss_srequest->sr_respond = NULL;
  }

  su_home_deinit(home);

  if (ss->ss_state == nua_callstate_init)
    nsession_destroy(nh);
}


/** @internal Process ACK or CANCEL or timeout (no ACK) for incoming INVITE */
static
int process_ack_or_cancel(nua_handle_t *nh,
			  nta_incoming_t *irq,
			  sip_t const *sip)
{
  int retval;
  nua_server_request_t *sr = nh->nh_ss->ss_srequest;

  enter;

  if (sip && sip->sip_request->rq_method == sip_method_ack)
    retval = process_ack(nh, irq, sip);
  else if (sip && sip->sip_request->rq_method == sip_method_cancel)
    retval = process_cancel(nh, irq, sip);
  else
    retval = process_timeout(nh, irq);

  assert(sr->sr_irq == irq);
  nta_incoming_destroy(sr->sr_irq);
  memset(sr, 0, sizeof *sr);

  return retval;
}

/** @internal Process PRACK or (timeout from 100rel) */
static
int process_prack(nua_handle_t *nh,
		  nta_reliable_t *rel,
		  nta_incoming_t *irq,
		  sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;
  int status = 200; char const *phrase = sip_200_OK;
  char const *recv = NULL, *sent = NULL;

  nta_reliable_destroy(rel);

  if (!sr->sr_irq) /* XXX  */
    return 481;

  if (sip)
    /* received PRACK */;
  else if (sr->sr_respond == NULL) { /* Final response interrupted 100rel */
    /* Ignore */
    return 200;
  }
  else if (sip == NULL) {
    SET_STATUS(504, "Reliable Response Timeout");

    respond_to_invite(nh->nh_nua, nh, status, phrase, NULL);

    nua_stack_event(nh->nh_nua, nh, NULL,
		    nua_i_error, status, phrase, TAG_END());

    return status;
  }

  if (nh->nh_soa) {
    msg_t *msg = nta_incoming_getrequest(irq);
    char const *sdp;
    size_t len;

    if (session_get_description(msg, sip, &sdp, &len)) {
      su_home_t home[1] = { SU_HOME_INIT(home) };

      sip_content_disposition_t *cd = NULL;
      sip_content_type_t *ct = NULL;
      sip_payload_t *pl = NULL;

      if (soa_set_remote_sdp(nh->nh_soa, NULL, sdp, len) < 0) {
	SU_DEBUG_5(("nua(%p): error parsing SDP in INVITE\n", nh));
	msg_destroy(msg);
	status = 400, phrase = "Bad Session Description";
      }

      /* Respond to PRACK */

      if (status >= 300)
	;
      else if (sr->sr_offer_sent) {
	recv = "answer";
	sr->sr_answer_recv = 1;
	if (soa_process_answer(nh->nh_soa, NULL) < 0)
	  status = soa_error_as_sip_response(nh->nh_soa, &phrase);
      }
      else {
	recv = "offer";
	if (soa_generate_answer(nh->nh_soa, NULL) < 0) {
	  status = soa_error_as_sip_response(nh->nh_soa, &phrase);
	}
	else {
	  session_make_description(home, nh->nh_soa, &cd, &ct, &pl);
	  sent = "answer";
	}
      }

      if (nta_incoming_treply(irq, status, phrase,
			      SIPTAG_CONTENT_DISPOSITION(cd),
			      SIPTAG_CONTENT_TYPE(ct),
			      SIPTAG_PAYLOAD(pl),
			      TAG_END()) < 0)
	/* Respond with 500 if nta_incoming_treply() failed */
	SET_STATUS1(SIP_500_INTERNAL_SERVER_ERROR);

      su_home_deinit(home);
    }

    msg_destroy(msg);
  }

  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
		  nua_i_prack, status, phrase, TAG_END());

  if (status < 300 && (recv || sent)) {
    soa_activate(nh->nh_soa, NULL);
    signal_call_state_change(nh, status, phrase,
			     nua_callstate_early, recv, sent);
  }

  if (status < 300 &&
      NH_PGET(nh, auto_alert) && !ss->ss_alerting && !ss->ss_precondition)
    respond_to_invite(nh->nh_nua, nh, SIP_180_RINGING, NULL);

  return status;
}

int process_ack(nua_handle_t *nh,
		nta_incoming_t *irq,
		sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;
  msg_t *msg = nta_incoming_getrequest_ackcancel(irq);
  char const *recv = NULL;

  if (nh->nh_soa && sr->sr_offer_sent && !sr->sr_answer_recv) {
    char const *sdp;
    size_t len;

    if (!session_get_description(msg, sip, &sdp, &len) ||
	!(recv = "answer") ||
	soa_set_remote_sdp(nh->nh_soa, NULL, sdp, len) < 0 ||
	soa_process_answer(nh->nh_soa, NULL) < 0 ||
	soa_activate(nh->nh_soa, NULL)) {
      int status; char const *phrase, *reason;

      status = soa_error_as_sip_response(nh->nh_soa, &phrase);
      reason = soa_error_as_sip_reason(nh->nh_soa);

      nua_stack_event(nh->nh_nua, nh, msg,
	       nua_i_ack, status, phrase, TAG_END());
      nua_stack_event(nh->nh_nua, nh, NULL,
	       nua_i_media_error, status, phrase, TAG_END());

      signal_call_state_change(nh, 488, "Offer-Answer Error",
			       nua_callstate_terminating, recv, 0);
      nua_stack_post_signal(nh, nua_r_bye,
			    SIPTAG_REASON_STR(reason),
			    TAG_END());

      return 0;
    }
  }

  soa_clear_remote_sdp(nh->nh_soa);

  nua_stack_event(nh->nh_nua, nh, msg, nua_i_ack, SIP_200_OK, TAG_END());

  signal_call_state_change(nh, 200, "OK", nua_callstate_ready, recv, 0);

  set_session_timer(nh);

  return 0;
}

/* CANCEL  */
static
int process_cancel(nua_handle_t *nh,
		   nta_incoming_t *irq,
		   sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  msg_t *msg = nta_incoming_getrequest_ackcancel(irq);

  nua_stack_event(nh->nh_nua, nh, msg, nua_i_cancel, SIP_200_OK, TAG_END());

  signal_call_state_change(nh, 0, "Received CANCEL", nua_callstate_init, 0, 0);

  if (nh->nh_soa && ss->ss_state < nua_callstate_ready) {
    soa_terminate(nh->nh_soa, NULL);
    nsession_destroy(nh);
  }

  return 0;
}

/* Timeout (no ACK or PRACK received) */
static
int process_timeout(nua_handle_t *nh,
		    nta_incoming_t *irq)
{
  struct nua_session_state *ss = nh->nh_ss;

  nua_stack_event(nh->nh_nua, nh, 0, nua_i_error,
	   408, "Response timeout",
	   TAG_END());

  soa_terminate(nh->nh_soa, NULL);

  if (ss->ss_state == nua_callstate_ready) {
    /* send BYE if 200 OK (or 183 to re-INVITE) timeouts  */
    signal_call_state_change(nh, 0, "Timeout",
			     nua_callstate_terminating, 0, 0);
    nua_stack_post_signal(nh, nua_r_bye,
		 SIPTAG_REASON_STR("SIP;cause=408;text=\"ACK Timeout\""),
		 TAG_END());
  }
  else {
    nta_incoming_treply(irq, SIP_504_GATEWAY_TIME_OUT,
			SIPTAG_REASON_STR("SIP;cause=504;"
					  "text=\"PRACK Timeout\""),
			TAG_END());
    signal_call_state_change(nh, 0, "Timeout",
			     nua_callstate_init, 0, 0);
  }

  return 0;
}


/* ---------------------------------------------------------------------- */
/* Session timer */

/** Add timer featuretag and Session-Expires/Min-SE headers */
static int
use_session_timer(nua_handle_t *nh, int uas, msg_t *msg, sip_t *sip)
{
  struct nua_session_state *ss = nh->nh_ss;

  sip_min_se_t min_se[1];
  sip_session_expires_t session_expires[1];

  static sip_param_t const x_params_uac[] = {"refresher=uac", NULL};
  static sip_param_t const x_params_uas[] = {"refresher=uas", NULL};

  /* Session-Expires timer */
  if ((NH_PGET(nh, refresher) == 0 &&
       NH_PGET(nh, session_timer) == 0) ||
      /* Is timer feature supported? */
      !sip_has_supported(NH_PGET(nh, supported), "timer"))
    return 0;

  sip_min_se_init(min_se)->min_delta = ss->ss_min_se;
  sip_session_expires_init(session_expires)->x_delta = ss->ss_session_timer;

  if (ss->ss_refresher == nua_remote_refresher)
    session_expires->x_params = uas ? x_params_uac : x_params_uas;
  else if (ss->ss_refresher == nua_local_refresher)
    session_expires->x_params = uas ? x_params_uas : x_params_uac;

  sip_add_tl(msg, sip,
	     TAG_IF(ss->ss_session_timer,
		    SIPTAG_SESSION_EXPIRES(session_expires)),
	     TAG_IF(ss->ss_min_se != 0
		    /* Min-SE: 0 is optional with initial INVITE */
		    || ss->ss_state != nua_callstate_init,
		    SIPTAG_MIN_SE(min_se)),
	     TAG_IF(ss->ss_refresher == nua_remote_refresher,
		    SIPTAG_REQUIRE_STR("timer")),
	     TAG_END());

  return 1;
}

static int
init_session_timer(nua_handle_t *nh, sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;

  int server;

  ss->ss_refresher = nua_no_refresher;

  /* Check if we support the timer feature */
  if (!sip->sip_session_expires ||
      !sip_has_supported(NH_PGET(nh, supported), "timer")) {
    return 0;
  }

  ss->ss_session_timer = sip->sip_session_expires->x_delta;

  if (sip->sip_min_se != NULL
      && sip->sip_min_se->min_delta > ss->ss_min_se)
    ss->ss_min_se = sip->sip_min_se->min_delta;

  server = sip->sip_request != NULL;

  if (!str0casecmp("uac", sip->sip_session_expires->x_refresher))
    ss->ss_refresher = server ? nua_remote_refresher : nua_local_refresher;
  else if (!str0casecmp("uas", sip->sip_session_expires->x_refresher))
    ss->ss_refresher = server ? nua_local_refresher : nua_remote_refresher;
  else if (!server)
    return 0;			/* XXX */
  /* User preferences */
  else if (nua_local_refresher == NH_PGET(nh, refresher))
    ss->ss_refresher = nua_local_refresher;
  else
    ss->ss_refresher = nua_remote_refresher;

  return 0;
}

static void
set_session_timer(nua_handle_t *nh)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_dialog_usage_t *du = ss->ss_usage;

  assert(du);

  if (du == NULL)
    ;
  else if (ss->ss_refresher == nua_local_refresher) {
    nua_dialog_usage_set_refresh(du, ss->ss_session_timer);
    du->du_pending = refresh_invite; /* Set timer */
  }
  else if (ss->ss_refresher == nua_remote_refresher) {
    nua_dialog_usage_set_refresh(du, ss->ss_session_timer + 32);
    du->du_pending = session_timeout; /* Set timer */
  }
  else {
    du->du_refresh = 0;
    du->du_pending = NULL;
  }
}

static int
is_session_timer_set(nua_session_state_t *ss)
{
  return ss->ss_usage &&
    (ss->ss_usage->du_pending == refresh_invite ||
     ss->ss_usage->du_pending == session_timeout);
}

/* ---------------------------------------------------------------------- */
/* Automatic notifications from a referral */

static int
nh_referral_check(nua_handle_t *nh, tagi_t const *tags)
{
  sip_event_t const *event = NULL;
  int pause = 1;
  struct nua_referral *ref = nh->nh_referral;
  nua_handle_t *ref_handle = ref->ref_handle;

  if (!ref_handle
      &&
      tl_gets(tags,
	      NUTAG_NOTIFY_REFER_REF(ref_handle),
	      NUTAG_REFER_EVENT_REF(event),
	      NUTAG_REFER_PAUSE_REF(pause),
	      TAG_END()) == 0
      &&
      tl_gets(nh->nh_tags,
	      NUTAG_NOTIFY_REFER_REF(ref_handle),
	      NUTAG_REFER_EVENT_REF(event),
	      NUTAG_REFER_PAUSE_REF(pause),
	      TAG_END()) == 0)
    return 0;

  if (!ref_handle)
    return 0;

  /* Remove nh_referral and nh_notevent */
  tl_tremove(nh->nh_tags,
	     NUTAG_NOTIFY_REFER(ref_handle),
	     TAG_IF(event, NUTAG_REFER_EVENT(event)),
	     TAG_END());

  if (event)
    ref->ref_event = sip_event_dup(nh->nh_home, event);

  if (!nh_validate(nh->nh_nua, ref_handle)) {
    SU_DEBUG_3(("nua: invalid NOTIFY_REFER handle\n"));
    return -1;
  }
  else if (!ref->ref_event) {
    SU_DEBUG_3(("nua: NOTIFY event missing\n"));
    return -1;
  }

  if (ref_handle != ref->ref_handle) {
    if (ref->ref_handle)
      nua_handle_unref(ref->ref_handle);
    ref->ref_handle = nua_handle_ref(ref_handle);
  }

#if 0
  if (pause) {
    /* Pause media on REFER handle */
    nmedia_pause(nua, ref_handle->nh_nm, NULL);
  }
#endif

  return 0;
}


static void
nh_referral_respond(nua_handle_t *nh, int status, char const *phrase)
{
  char payload[128];
  char const *substate;
  struct nua_referral *ref = nh->nh_referral;

  if (!nh_validate(nh->nh_nua, ref->ref_handle)) {
    if (ref) {
      if (ref->ref_handle)
	SU_DEBUG_1(("nh_handle_referral: stale referral handle %p\n",
		    ref->ref_handle));
      ref->ref_handle = NULL;
    }
    return;
  }

  /* XXX - we should have a policy here whether to send 101..199 */

  assert(ref->ref_event);

  if (status >= 300)
    status = 503, phrase = sip_503_Service_unavailable;

  snprintf(payload, sizeof(payload), "SIP/2.0 %03u %s\r\n", status, phrase);

  if (status < 200)
    substate = "active";
  else
    substate = "terminated ;reason=noresource";

  nua_stack_post_signal(ref->ref_handle,
			nua_r_notify,
			SIPTAG_EVENT(ref->ref_event),
			SIPTAG_SUBSCRIPTION_STATE_STR(substate),
			SIPTAG_CONTENT_TYPE_STR("message/sipfrag"),
			SIPTAG_PAYLOAD_STR(payload),
			TAG_END());

  if (status < 200)
    return;

  su_free(nh->nh_home, ref->ref_event), ref->ref_event = NULL;

  nua_handle_unref(ref->ref_handle), ref->ref_handle = NULL;
}


/** Zap the session associated with the handle */
static
void nsession_destroy(nua_handle_t *nh)
{
  struct nua_session_state *ss = nh->nh_ss;

  ss->ss_active = 0;
  ss->ss_state = nua_callstate_init;

  /* Remove usage */
  if (ss->ss_usage)
    nua_dialog_usage_remove(nh, nh->nh_ds, ss->ss_usage);
  ss->ss_usage = 0;

  nh->nh_has_invite = 0;

  if (nh->nh_soa)
    soa_destroy(nh->nh_soa), nh->nh_soa = NULL;

  ss->ss_srequest->sr_respond = NULL;

  SU_DEBUG_5(("nua: terminated session %p\n", nh));
}


/* ======================================================================== */
/* INFO */

static int process_response_to_info(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int
nua_stack_info(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;

  if (nh_is_special(nh)) {
    return UA_EVENT2(e, 900, "Invalid handle for INFO");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 900, "Request already in progress");
  }

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_INFO ,
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_info, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(tags));
  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);
  }

  return cr->cr_event = e;
}

void restart_info(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_info, tags);
}

static int process_response_to_info(nua_handle_t *nh,
				    nta_outgoing_t *orq,
				    sip_t const *sip)
{
  if (nua_creq_check_restart(nh, nh->nh_cr, orq, sip, restart_info))
    return 0;
  return nua_stack_process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

int nua_stack_process_info(nua_t *nua,
			   nua_handle_t *nh,
			   nta_incoming_t *irq,
			   sip_t const *sip)
{
  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_info, SIP_200_OK, TAG_END());

  return 200;		/* Respond automatically with 200 Ok */
}


/* ======================================================================== */
/* UPDATE */

static int process_response_to_update(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int
nua_stack_update(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_session_state *ss = nh->nh_ss;
  struct nua_client_request *cr = nh->nh_cr;
  struct nua_client_request *cri = ss->ss_crequest;
  struct nua_server_request *sri = ss->ss_srequest;
  msg_t *msg;
  sip_t *sip;
  char const *offer_sent = 0;

  if (!nh_has_session(nh))
    return UA_EVENT2(e, 900, "Invalid handle for UPDATE");
  else if (cr->cr_orq)
    return UA_EVENT2(e, 900, "Request already in progress");

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_UPDATE,
			 NUTAG_USE_DIALOG(1),
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    if (nh->nh_soa && !sip->sip_payload &&
	!(cri->cr_offer_sent && !cri->cr_answer_recv) &&
	!(cri->cr_offer_recv && !cri->cr_answer_sent) &&
	!(sri->sr_offer_sent && !sri->sr_answer_recv) &&
	!(sri->sr_offer_recv && !sri->sr_answer_sent)) {
      soa_init_offer_answer(nh->nh_soa);

      if (soa_generate_offer(nh->nh_soa, 0, NULL) < 0 ||
	  session_include_description(nh->nh_soa, msg, sip) < 0) {
	if (ss->ss_state < nua_callstate_ready) {
	  /* XXX */
	}
	msg_destroy(msg);
	return UA_EVENT2(e, 900, "Local media failed");
      }

      offer_sent = "offer";
    }

    if (is_session_timer_set(ss))
      /* Add session timer headers */
      use_session_timer(nh, 0, msg, sip);

    if (nh->nh_auth) {
      if (auc_authorize(&nh->nh_auth, msg, sip) < 0)
	/* xyzzy */;
    }

    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_update, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));
    if (cr->cr_orq) {
      if (offer_sent)
	cr->cr_offer_sent = 1;
      ss->ss_update_needed = 0;
      signal_call_state_change(nh, 0, "UPDATE sent",
			       ss->ss_state, 0, offer_sent);
      return cr->cr_event = e;
    }
  }

  msg_destroy(msg);
  return UA_EVENT1(e, NUA_INTERNAL_ERROR);
}

void restart_update(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_update, tags);
}

static int process_response_to_update(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip)
{
  nua_t *nua = nh->nh_nua;
  struct nua_session_state *ss = nh->nh_ss;
  struct nua_client_request *cr = nh->nh_cr;

  int status = sip->sip_status->st_status;
  char const *phrase = sip->sip_status->st_phrase;
  char const *recv = NULL;
  int terminate = 0, gracefully = 1;

  if (status >= 300) {
    if (sip->sip_retry_after)
      gracefully = 0;

    terminate = sip_response_terminates_dialog(status, sip_method_invite,
					       &gracefully);

    if (!terminate &&
	nua_creq_check_restart(nh, cr, orq, sip, restart_update)) {
      return 0;
    }
    /* XXX - if we have a concurrent INVITE, what we do with it? */
  }
  else if (status >= 200) {
    /* XXX - check remote tag, handle forks */
    /* Set (route), contact, (remote tag) */
    nua_dialog_uac_route(nh, nh->nh_ds, sip, 1);
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

    if (is_session_timer_set(ss)) {
      init_session_timer(nh, sip);
      set_session_timer(nh);
    }

    if (session_process_response(nh, cr, orq, sip, &recv) < 0) {
      nua_stack_event(nua, nh, NULL, nua_i_error,
	       400, "Bad Session Description", TAG_END());
    }

    signal_call_state_change(nh, status, phrase, ss->ss_state, recv, 0);

    return 0;
  }
  else
    gracefully = 0;

  nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  if (terminate || gracefully)
    nh_referral_respond(nh, status, phrase);

  if (terminate) {
    signal_call_state_change(nh, status, phrase,
			     nua_callstate_terminated, recv, 0);
    nsession_destroy(nh);
  }
  else if (gracefully) {
    signal_call_state_change(nh, status, phrase,
			     nua_callstate_terminating, recv, 0);
#if 0
    if (nh->nh_ss->ss_crequest->cr_orq)
      nua_stack_post_signal(nh, nua_r_cancel, TAG_END());
    else
#endif
      nua_stack_post_signal(nh, nua_r_bye, TAG_END());
  }

  return 0;
}

int nua_stack_process_update(nua_t *nua,
			     nua_handle_t *nh,
			     nta_incoming_t *irq,
			     sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_dialog_usage_t *du = ss->ss_usage;
  msg_t *msg = nta_incoming_getrequest(irq);

  char const *sdp;
  size_t len;

  int original_status = 200, status = 200;
  char const *phrase = sip_200_OK;

  char const *offer_recv = NULL, *answer_sent = NULL;
  int do_timer = 0;

  msg_t *rmsg;
  sip_t *rsip;

  assert(nh);

  if (!du) {
    nua_dialog_state_t *ds = nh->nh_ds;

    /* No session for this dialog */
    nta_incoming_treply(irq,
			SET_STATUS1(SIP_405_METHOD_NOT_ALLOWED),
			TAG_IF(ds->ds_has_subscribes,
			       SIPTAG_ALLOW_STR("NOTIFY")),
			TAG_IF(ds->ds_has_notifys,
			       SIPTAG_ALLOW_STR("SUBSCRIBE, REFER")),
			TAG_END());
  }

  /* Do session timer negotiation if there is no ongoing INVITE transaction */
  if (status < 300 &&
      sip->sip_session_expires &&
      is_session_timer_set(ss))
    do_timer = 1, init_session_timer(nh, sip);

  if (status < 300 && nh->nh_soa &&
      session_get_description(msg, sip, &sdp, &len)) {

    offer_recv = "offer";

    if (soa_set_remote_sdp(nh->nh_soa, NULL, sdp, len) < 0) {
      SU_DEBUG_5(("nua(%p): error parsing SDP in UPDATE\n", nh));
      msg_destroy(msg);
      status = soa_error_as_sip_response(nh->nh_soa, &phrase);
      offer_recv = NULL;
    }
    /* Respond to UPDATE */
    else if (soa_generate_answer(nh->nh_soa, NULL) < 0) {
      SU_DEBUG_5(("nua(%p): error processing SDP in UPDATE\n", nh));
      msg_destroy(msg);
      status = soa_error_as_sip_response(nh->nh_soa, &phrase);
    }
    else if (soa_activate(nh->nh_soa, NULL) < 0) {
      SU_DEBUG_5(("nua(%p): error activating media after %s\n",
		  nh, "UPDATE"));
      /* XXX */
    }
    else {
      answer_sent = "answer";
    }
  }

  rmsg = nh_make_response(nua, nh, irq,
			  status, phrase,
			  TAG_IF(status < 300, NUTAG_ADD_CONTACT(1)),
			  SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			  TAG_NEXT(NULL));
  rsip = sip_object(rmsg);
  assert(sip);			/* XXX */

  if (answer_sent && session_include_description(nh->nh_soa, rmsg, rsip) < 0) {
    status = 500, phrase = sip_500_Internal_server_error;
    answer_sent = NULL;
  }

  if (do_timer && 200 <= status && status < 300) {
    use_session_timer(nh, 1, rmsg, rsip);
    set_session_timer(nh);
  }

  if (status == original_status) {
    if (nta_incoming_mreply(irq, rmsg) < 0)
      status = 500, phrase = sip_500_Internal_server_error;
  }

  if (status != original_status) {
    nua_stack_event(nua, nh, NULL, nua_i_error, status, phrase, TAG_END());
    nta_incoming_treply(irq, status, phrase, TAG_END());
    msg_destroy(rmsg), rmsg = NULL;
  }

  nua_stack_event(nh->nh_nua, nh, msg, nua_i_update, status, phrase, TAG_END());

  if (offer_recv || answer_sent)
    /* signal offer received, answer sent */
    signal_call_state_change(nh, 200, "OK", ss->ss_state,
			     offer_recv, answer_sent);

  if (NH_PGET(nh, auto_alert)
      && ss->ss_state < nua_callstate_ready
      && !ss->ss_alerting
      && ss->ss_precondition)
    respond_to_invite(nh->nh_nua, nh, SIP_180_RINGING, NULL);

  return status;
}


/* ======================================================================== */
/* BYE */

static int process_response_to_bye(nua_handle_t *nh,
				   nta_outgoing_t *orq,
				   sip_t const *sip);

int
nua_stack_bye(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cr = nh->nh_cr;
  nua_client_request_t *cr_invite = ss->ss_crequest;
  msg_t *msg;
  nta_outgoing_t *orq;

  if (nh_is_special(nh))
    return UA_EVENT2(e, 900, "Invalid handle for BYE");

  if (!nua_dialog_is_established(nh->nh_ds)) {
    if (cr_invite->cr_orq == NULL)
      return UA_EVENT2(e, 900, "No session to BYE");

    /* No (early) dialog. BYE is invalid action, do CANCEL instead */
    orq = nta_outgoing_tcancel(cr_invite->cr_orq,
			       process_response_to_bye, nh,
			       TAG_NEXT(tags));
    if (!cr->cr_orq)
      cr->cr_orq = orq, cr->cr_event = e;

    return 0;
  }

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_BYE,
			 TAG_NEXT(tags));
  orq = nta_outgoing_mcreate(nua->nua_nta,
			     process_response_to_bye, nh, NULL,
			     msg,
			     SIPTAG_END(), TAG_NEXT(tags));

  ss->ss_state = nua_callstate_terminating;
  if (nh->nh_soa)
    soa_terminate(nh->nh_soa, 0);

  if (!orq) {
    msg_destroy(msg);
    UA_EVENT2(e, 400, "Internal error");
    if (cr_invite->cr_orq == NULL)
      signal_call_state_change(nh, 400, "Failure sending BYE",
			       nua_callstate_terminated, 0, 0);
    return 0;
  }

  if (cr->cr_orq == NULL)
    cr->cr_orq = orq, cr->cr_event = e;

  return 0;
}


void restart_bye(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_bye, tags);
}


static int process_response_to_bye(nua_handle_t *nh,
				   nta_outgoing_t *orq,
				   sip_t const *sip)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cr_invite = ss->ss_crequest;
  nua_client_request_t *cr = nh->nh_cr;
  int status = sip ? sip->sip_status->st_status : 400;

  if (nua_creq_check_restart(nh, cr, orq, sip, restart_bye))
    return 0;

  nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  if (status >= 200 && cr_invite->cr_orq == NULL) {
    signal_call_state_change(nh, status, "to BYE",
			     nua_callstate_terminated, 0, 0);
    nsession_destroy(nh);
  }

  return 0;
}



int nua_stack_process_bye(nua_t *nua,
			  nua_handle_t *nh,
			  nta_incoming_t *irq,
			  sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;
  int early = 0;

  assert(nh);

  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_bye, SIP_200_OK, TAG_END());
  nta_incoming_treply(irq, SIP_200_OK, TAG_END());
  nta_incoming_destroy(irq), irq = NULL;

  if (sr->sr_irq) {
    char const *phrase;
    early = ss->ss_state < nua_callstate_ready;
    phrase = early ? "Early Session Terminated" : "Session Terminated";
    nta_incoming_treply(sr->sr_irq, 487, phrase, TAG_END());
    nta_incoming_destroy(sr->sr_irq);
    memset(sr, 0, sizeof *sr);
  }

  nsession_destroy(nh);

  signal_call_state_change(nh, 200,
			   early ? "Received early BYE" : "Received BYE",
			   nua_callstate_terminated, 0, 0);

  return 200;			/* Respond automatically with 200 Ok */
}

/* ---------------------------------------------------------------------- */

/**
 * Delivers call state changed event to the nua client.
 *
 * @param nh call handle
 * @param status status code
 * @param tr_event SIP transaction event triggering this change
 * @param oa_recv Received SDP
 * @param oa_sent Sent SDP
 */
static void signal_call_state_change(nua_handle_t *nh,
				     int status, char const *phrase,
				     enum nua_callstate next_state,
				     char const *oa_recv,
				     char const *oa_sent)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;
  enum nua_callstate ss_state = ss->ss_state;

  sdp_session_t const *remote_sdp = NULL;
  char const *remote_sdp_str = NULL;
  sdp_session_t const *local_sdp = NULL;
  char const *local_sdp_str = NULL;

  int offer_recv = 0, answer_recv = 0, offer_sent = 0, answer_sent = 0;

  if (ss_state != nua_callstate_ready || next_state > nua_callstate_ready)
    SU_DEBUG_5(("nua(%p): call state changed: %s -> %s%s%s%s%s\n",
		nh, nua_callstate_name(ss_state),
		nua_callstate_name(next_state),
		oa_recv ? ", received " : "", oa_recv ? oa_recv : "",
		oa_sent && oa_recv ? ", and sent " :
		oa_sent ? ", sent " : "", oa_sent ? oa_sent : ""));
  else
    SU_DEBUG_5(("nua(%p): ready call updated: %s%s%s%s%s\n",
		nh, nua_callstate_name(next_state),
		oa_recv ? " received " : "", oa_recv ? oa_recv : "",
		oa_sent && oa_recv ? ", sent " :
		oa_sent ? " sent " : "", oa_sent ? oa_sent : ""));

  if (oa_recv) {
    soa_get_remote_sdp(nh->nh_soa, &remote_sdp, &remote_sdp_str, 0);
    offer_recv = strcasecmp(oa_recv, "offer") == 0;
    answer_recv = strcasecmp(oa_recv, "answer") == 0;
  }

  if (oa_sent) {
    soa_get_local_sdp(nh->nh_soa, &local_sdp, &local_sdp_str, 0);
    offer_sent = strcasecmp(oa_sent, "offer") == 0;
    answer_sent = strcasecmp(oa_sent, "answer") == 0;
  }

  if (answer_recv || answer_sent) {
    /* Update ss->ss_hold_remote */

    char const *held;

    soa_get_params(nh->nh_soa, SOATAG_HOLD_REF(held), TAG_END());

    ss->ss_hold_remote = held && strlen(held) > 0;
  }

  (void)sr;

  /* Update state variables */
  if (next_state > ss_state)
    ss->ss_state = next_state;
  else if (next_state == nua_callstate_init && ss_state < nua_callstate_ready)
    ss->ss_state = nua_callstate_init, next_state = nua_callstate_terminated;

  if (next_state == nua_callstate_ready)
    ss->ss_active = 1;
  else if (next_state == nua_callstate_terminated)
    ss->ss_active = 0;

  /* Send events */
  if (phrase == NULL)
    phrase = "Call state";

  nua_stack_event(nh->nh_nua, nh, NULL, nua_i_state,
	   status, phrase,
	   NUTAG_CALLSTATE(next_state),
	   NH_ACTIVE_MEDIA_TAGS(1, nh->nh_soa),
	   /* NUTAG_SOA_SESSION(nh->nh_soa), */
	   TAG_IF(offer_recv, NUTAG_OFFER_RECV(offer_recv)),
	   TAG_IF(answer_recv, NUTAG_ANSWER_RECV(answer_recv)),
	   TAG_IF(offer_sent, NUTAG_OFFER_SENT(offer_sent)),
	   TAG_IF(answer_sent, NUTAG_ANSWER_SENT(answer_sent)),
	   TAG_IF(oa_recv, SOATAG_REMOTE_SDP(remote_sdp)),
	   TAG_IF(oa_recv, SOATAG_REMOTE_SDP_STR(remote_sdp_str)),
	   TAG_IF(oa_sent, SOATAG_LOCAL_SDP(local_sdp)),
	   TAG_IF(oa_sent, SOATAG_LOCAL_SDP_STR(local_sdp_str)),
	   TAG_END());

  if (next_state == nua_callstate_ready && ss_state <= nua_callstate_ready) {
    nua_stack_event(nh->nh_nua, nh, NULL, nua_i_active, status, "Call active",
	     NH_ACTIVE_MEDIA_TAGS(1, nh->nh_soa),
	     /* NUTAG_SOA_SESSION(nh->nh_soa), */
	     TAG_END());
  }
  else if (next_state == nua_callstate_terminated) {
    nua_stack_event(nh->nh_nua, nh, NULL, nua_i_terminated, status, phrase,
	     TAG_END());
  }
}

/* ======================================================================== */

/** Get SDP from a SIP message */
static
int session_get_description(msg_t *msg,
			    sip_t const *sip,
			    char const **return_sdp,
			    size_t *return_len)
{
  sip_payload_t const *pl = sip->sip_payload;
  sip_content_type_t const *ct = sip->sip_content_type;
  int matching_content_type = 0;

  if (pl == NULL)
    return 0;
  else if (pl->pl_len == 0 || pl->pl_data == NULL)
    return 0;
  else if (ct == NULL)
    /* Be bug-compatible with our old gateways */
    SU_DEBUG_3(("nua: no %s, assuming %s\n",
		"Content-Type", SDP_MIME_TYPE));
  else if (ct->c_type == NULL)
    SU_DEBUG_3(("nua: empty %s, assuming %s\n",
		"Content-Type", SDP_MIME_TYPE));
  else if (strcasecmp(ct->c_type, SDP_MIME_TYPE)) {
    SU_DEBUG_5(("nua: unknown %s: %s\n", "Content-Type", ct->c_type));
    return 0;
  }
  else
    matching_content_type = 1;

  if (pl == NULL)
    return 0;

  if (!matching_content_type) {
    /* Make sure we got SDP */
    if (pl->pl_len < 3 || strncasecmp(pl->pl_data, "v=0", 3))
      return 0;
  }

  *return_sdp = pl->pl_data;
  *return_len = pl->pl_len;

  return 1;
}

/** Insert SDP into SIP message */
static
int session_include_description(soa_session_t *soa,
				msg_t *msg,
				sip_t *sip)
{
  su_home_t *home = msg_home(msg);

  sip_content_disposition_t *cd;
  sip_content_type_t *ct;
  sip_payload_t *pl;

  if (!soa)
    return 0;

  if (session_make_description(home, soa, &cd, &ct, &pl) < 0)
    return -1;

  if (pl == NULL || ct == NULL || cd == NULL ||
      sip_header_insert(msg, sip, (sip_header_t *)cd) < 0 ||
      sip_header_insert(msg, sip, (sip_header_t *)ct) < 0 ||
      sip_header_insert(msg, sip, (sip_header_t *)pl) < 0)
    return -1;

  return 0;
}

/** Generate SDP headers */
static
int session_make_description(su_home_t *home,
			     soa_session_t *soa,
			     sip_content_disposition_t **return_cd,
			     sip_content_type_t **return_ct,
			     sip_payload_t **return_pl)
{
  char const *sdp;
  int len;

  if (!soa)
    return 0;

  if (soa_get_local_sdp(soa, 0, &sdp, &len) < 0)
    return -1;

  *return_pl = sip_payload_create(home, sdp, len);
  *return_ct = sip_content_type_make(home, SDP_MIME_TYPE);
  *return_cd = sip_content_disposition_make(home, "session");

  return 0;
}

/**
 * Stores and processes SDP from incoming response, then calls
 * nua_stack_process_response().
 *
 * @retval 1 if there was SDP to process.
 */
static
int session_process_response(nua_handle_t *nh,
			     struct nua_client_request *cr,
			     nta_outgoing_t *orq,
			     sip_t const *sip,
			     char const **return_received)
{
  char const *method = nta_outgoing_method_name(orq);
  msg_t *msg = nta_outgoing_getresponse(orq);
  int retval = 0;
  char const *sdp = NULL;
  size_t len;

  if (nh->nh_soa == NULL)
    /* Xyzzy */;
  else if (!session_get_description(msg, sip, &sdp, &len))
    /* No SDP */;
  else if (cr->cr_answer_recv) {
    /* Ignore spurious answers after completing O/A */
    SU_DEBUG_3(("nua(%p): %s: ignoring duplicate SDP in %u %s\n",
		nh, method,
		sip->sip_status->st_status, sip->sip_status->st_phrase));
    sdp = NULL;
  }
  else if (!cr->cr_offer_sent &&
	   nta_outgoing_method(orq) != sip_method_invite) {
    /* If non-invite request did not have offer, ignore SDP in response */
    SU_DEBUG_3(("nua(%p): %s: ignoring extra SDP in %u %s\n",
		nh, method,
		sip->sip_status->st_status, sip->sip_status->st_phrase));
    sdp = NULL;
  }
  else {
    if (cr->cr_offer_sent) {
      cr->cr_answer_recv = sip->sip_status->st_status;
      *return_received = "answer";
    }
    else {
      cr->cr_offer_recv = 1, cr->cr_answer_sent = 0;
      *return_received = "offer";
    }

    if (soa_set_remote_sdp(nh->nh_soa, NULL, sdp, len) < 0) {
      SU_DEBUG_5(("nua(%p): %s: error parsing SDP in %u %s\n",
		  nh, method,
		  sip->sip_status->st_status,
		  sip->sip_status->st_phrase));
      retval = -1;
      sdp = NULL;
    }
    else if (cr->cr_offer_recv) {
      /* note: case 1: incoming offer */
      SU_DEBUG_5(("nua(%p): %s: get SDP %s in %u %s\n",
		  nh, method, "offer",
		  sip->sip_status->st_status,
		  sip->sip_status->st_phrase));
      retval = 1;
    }
    else if (soa_process_answer(nh->nh_soa, NULL) < 0) {
      SU_DEBUG_5(("nua(%p): %s: error processing SDP answer in %u %s\n",
		  nh, method,
		  sip->sip_status->st_status,
		  sip->sip_status->st_phrase));
      sdp = NULL;
    }
    else {
      /* note: case 2: answer to our offer */
      if (soa_activate(nh->nh_soa, NULL) < 0) {
	SU_DEBUG_3(("nua(%p): %s: error activating media after %u %s\n",
		    nh, method,
		    sip->sip_status->st_status,
		    sip->sip_status->st_phrase));
	/* XXX */
      }
      else {
	SU_DEBUG_5(("nua(%p): %s: processed SDP answer in %u %s\n",
		    nh, method,
		    sip->sip_status->st_status,
		    sip->sip_status->st_phrase));
      }

      assert(!cr->cr_offer_recv);
    }
  }

  msg_destroy(msg);		/* unref */

  nua_stack_process_response(nh, cr, orq, sip,
			     NH_REMOTE_MEDIA_TAGS(sdp != NULL, nh->nh_soa),
			     TAG_END());

  return retval;
}

#if 0
/** Parse and store SDP from incoming request */
static
int session_process_request(nua_handle_t *nh,
			    nta_incoming_t *irq,
			    sip_t const *sip)
{
  char const *sdp = NULL;
  int len;

  if (nh->nh_soa) {
    msg_t *msg = nta_outgoing_getresponse(irq);

    if (session_get_description(msg, sip, &sdp, &len)) {
      if (soa_is_complete(nh->nh_soa)) {
	/* Ignore spurious answers after completing O/A */
	SU_DEBUG_5(("nua: ignoring duplicate SDP in %u %s\n",
		    sip->sip_status->st_status, sip->sip_status->st_phrase));
	sdp = NULL;
      }
      else if (soa_parse_sdp(nh->nh_soa, sdp, len) < 0) {
	SU_DEBUG_5(("nua: error parsing SDP in %u %s\n",
		    sip->sip_status->st_status,
		    sip->sip_status->st_phrase));
	sdp = NULL;
      }
    }

    msg_destroy(msg);
  }

  return
    nua_stack_process_response(nh, cr, orq, sip,
			       NH_REMOTE_MEDIA_TAGS(sdp != NULL, nh->nh_soa),
			       TAG_END());
}
#endif
