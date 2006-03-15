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

/**@CFILE nua_stack.c
 * @brief Nokia User Agent (NUA) implementation
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 * @author Martti Mela <Martti Mela@nokia.com>
 * @author Remeres Jacobs <Remeres.Jacobs@nokia.com>
 * @author Tat Chan <Tat.Chan@nokia.com>
 *
 * @date Created: Wed Feb 14 18:32:58 2001 ppessi
 */

#include "config.h"

#include <sofia-sip/su_tag_class.h>
#include <sofia-sip/su_tag_class.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/su_strlst.h>
#include <sofia-sip/su_uniqueid.h>

#include <sofia-sip/su_tag_io.h>

#define SU_ROOT_MAGIC_T   struct nua_s
#define SU_MSG_ARG_T      struct event_s

#define NUA_SAVED_EVENT_T su_msg_t *

#define NTA_AGENT_MAGIC_T    struct nua_s
#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s
#define NTA_INCOMING_MAGIC_T struct nua_handle_s

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_util.h>

#include <sofia-sip/tport_tag.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/auth_client.h>

#include <sofia-sip/soa.h>

#include "sofia-sip/nua.h"
#include "sofia-sip/nua_tag.h"
#include "nua_stack.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include <assert.h>

/* ========================================================================
 *
 *                       Protocol stack side
 *
 * ======================================================================== */

nua_handle_t *nh_create(nua_t *nua, tag_type_t t, tag_value_t v, ...);
static void nh_append(nua_t *nua, nua_handle_t *nh);
static void nh_remove(nua_t *nua, nua_handle_t *nh);

static int nh_authorize(nua_handle_t *nh,
			tag_type_t tag, tag_value_t value, ...);

static int nh_challenge(nua_handle_t *nh, sip_t const *sip);

static void nua_stack_timer(nua_t *nua, su_timer_t *t, su_timer_arg_t *a);

static void ua_set_from(nua_t *nua, sip_from_t const *f, char const *fromstr);

static void ua_init_instance(nua_t *nua, char const *instance);

/* ---------------------------------------------------------------------- */
/* Constant data */

/** Methods allowed by default. */
static char const nua_allow_str[] =
"INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, "
"MESSAGE, SUBSCRIBE, NOTIFY, REFER, UPDATE";

/** Default internal error */
char const nua_500_error[] = "Internal NUA Error";

char const nua_application_sdp[] = "application/sdp";

#define NUA_STACK_TIMER_INTERVAL (1000)

/* ----------------------------------------------------------------------
 * Initialization & deinitialization
 */

int nua_stack_init(su_root_t *root, nua_t *nua)
{
  su_home_t *home;
  void *sip_parser = NULL;
  url_string_t const *contact = NULL;
  url_string_t const *sips_contact = NULL;
  sip_from_t const *from = NULL;
  char const *from_str = NULL;

  char const *certificate_dir = NULL;
  char const *uicc_name = "default";

  nua_handle_t *dnh;
  nua_handle_preferences_t *dnhp;
  int media_enable = 1;
  soa_session_t *soa = NULL;
  char const *soa_name = NULL;
  char const *instance = NONE;

  static int initialized_logs = 0;

  enter;

  if (!initialized_logs) {
    extern su_log_t tport_log[];
    extern su_log_t nta_log[];
    extern su_log_t nea_log[];
    extern su_log_t iptsec_log[];

    su_log_init(tport_log);
    su_log_init(nta_log);
    su_log_init(nea_log);
    su_log_init(iptsec_log);

    initialized_logs = 1;
  }

  home = nua->nua_home;

  dnh = su_home_clone(home, sizeof (*dnh) + sizeof(*dnhp));
  if (!dnh)
    return -1;
  nua_handle_ref(dnh);

  nua->nua_root = root;
  nua->nua_handles_tail = &nua->nua_handles;
  nh_append(nua, dnh);

  dnh->nh_valid = nua_handle;
  dnh->nh_nua = nua;
  dnh->nh_ds->ds_local = sip_from_init(nua->nua_from);
  dnh->nh_ds->ds_remote = nua->nua_from;

  dnh->nh_ref_by_stack = 1; dnh->nh_ref_by_user = 1;

  dnh->nh_prefs = dnhp = (void *)(dnh + 1);

  /* Set some defaults */
  DNHP_SET(dnhp, retry_count, 3);
  DNHP_SET(dnhp, max_subscriptions, 20);

  DNHP_SET(dnhp, invite_enable, 1);
  DNHP_SET(dnhp, auto_alert, 0);
  DNHP_SET(dnhp, early_media, 0);
  DNHP_SET(dnhp, auto_answer, 0);
  DNHP_SET(dnhp, auto_ack, 1);
  DNHP_SET(dnhp, invite_timeout, 120);

  DNHP_SET(dnhp, natify, 1);
  DNHP_SET(dnhp, gruuize, 1);

  DNHP_SET(dnhp, session_timer, 1800);
  DNHP_SET(dnhp, min_se, 120);
  DNHP_SET(dnhp, refresher, nua_no_refresher);
  DNHP_SET(dnhp, update_refresh, 0);

  DNHP_SET(dnhp, message_enable, 1);
  DNHP_SET(dnhp, win_messenger_enable, 0);
  if (getenv("PIMIW_HACK") != 0)
    DNHP_SET(dnhp, message_auto_respond, 1);

  DNHP_SET(dnhp, media_features,  0);
  DNHP_SET(dnhp, callee_caps, 0);
  DNHP_SET(dnhp, service_route_enable, 1);
  DNHP_SET(dnhp, path_enable, 1);

  DNHP_SET(dnhp, refer_expires, 300);

  DNHP_SET(dnhp, substate, nua_substate_active);

  DNHP_SET(dnhp, allow, sip_allow_make(dnh->nh_home, nua_allow_str));
  DNHP_SET(dnhp, supported, sip_supported_make(dnh->nh_home, "timer, 100rel"));
  DNHP_SET(dnhp, user_agent,
	   sip_user_agent_make(dnh->nh_home, PACKAGE_NAME "/" PACKAGE_VERSION));

  /* Set initial nta parameters */
  tl_gets(nua->nua_args,
	  NUTAG_URL_REF(contact),
	  SIPTAG_FROM_REF(from),
	  SIPTAG_FROM_STR_REF(from_str),
	  NUTAG_SIPS_URL_REF(sips_contact),
	  NUTAG_CERTIFICATE_DIR_REF(certificate_dir),
	  NUTAG_SIP_PARSER_REF(sip_parser),
	  NUTAG_UICC_REF(uicc_name),
	  NUTAG_MEDIA_ENABLE_REF(media_enable),
	  /* NUTAG_SOA_SESSION_REF(soa), */
	  NUTAG_SOA_NAME_REF(soa_name),
	  NUTAG_INSTANCE_REF(instance),
	  TAG_NULL());

#if HAVE_UICC_H
  if (uicc_name)
    nua->nua_uicc = uicc_create(root, uicc_name);
#endif

  nua->nua_nta = nta_agent_create(root, NONE, NULL, NULL,
				  TPTAG_CERTIFICATE(certificate_dir),
				  NTATAG_TAG_3261(0),
				  TAG_NEXT(nua->nua_args));
  if (!nua->nua_nta)
    return -1;

  if (!contact && !sips_contact) {
    if (nta_agent_add_tport(nua->nua_nta, NULL,
			    TAG_NEXT(nua->nua_args)) < 0 &&
	nta_agent_add_tport(nua->nua_nta, URL_STRING_MAKE("sip:*:*"),
			    TAG_NEXT(nua->nua_args)) < 0)
      return -1;
  }
  else if ((!contact ||
       nta_agent_add_tport(nua->nua_nta, contact,
			   TAG_NEXT(nua->nua_args)) < 0) &&
      (!sips_contact ||
       nta_agent_add_tport(nua->nua_nta, sips_contact,
			   TAG_NEXT(nua->nua_args)) < 0)) {
    return -1;
  }

  if (nua_stack_registrations_init(nua) < 0)
    return -1;

  nua->nua_media_enable = media_enable;
  
  nta_agent_set_params(nua->nua_nta,
		       NTATAG_UA(1),
		       NTATAG_MERGE_482(1),
		       NTATAG_RPORT(1),	/* XXX */
#if HAVE_SOFIA_SMIME
		       NTATAG_SMIME(nua->sm),
#endif
		       TAG_NEXT(nua->nua_args));

  nua->nua_invite_accept = sip_accept_make(home, SDP_MIME_TYPE);

  if (media_enable) {
    if (soa == NULL)
      soa = soa_create(soa_name, nua->nua_root, nua->nua_dhandle);
    dnh->nh_soa = soa;
    soa_set_params(soa, TAG_NEXT(nua->nua_args));
  }

  dnh->nh_ds->ds_leg = nta_leg_tcreate(nua->nua_nta,
				       nua_stack_process_request, dnh,
				       NTATAG_NO_DIALOG(1),
				       TAG_END());

  ua_init_instance(nua, instance);
  ua_set_from(nua, from, from_str);

  nua->nua_timer = su_timer_create(su_root_task(root),
				   NUA_STACK_TIMER_INTERVAL);

  if (!(dnh->nh_ds->ds_leg &&
	dnhp->nhp_allow &&
	dnhp->nhp_supported &&
	nua->nua_registrations &&
	nua->nua_from &&
	nua->nua_timer))
    return -1;

  nua_stack_timer(nua, nua->nua_timer, NULL);

  nua->nua_args = NULL;

  return 0;
}

void nua_stack_deinit(su_root_t *root, nua_t *nua)
{
  enter;

  su_timer_destroy(nua->nua_timer), nua->nua_timer = NULL;
  nta_agent_destroy(nua->nua_nta), nua->nua_nta = NULL;
}

/** Set the default from field */
void ua_set_from(nua_t *nua, sip_from_t const *f, char const *str)
{
  sip_from_t from[1], *f0;

#if HAVE_UICC_H
  /* XXX: add */
#endif

  sip_from_init(from);

  if (f) {
    from->a_display = f->a_display;
    *from->a_url = *f->a_url;
    f0 = sip_from_dup(nua->nua_home, from);
  }
  else if (str) {
    f0 = sip_from_make(nua->nua_home, str);
    if (f0)
      *from = *f0, f0 = from, f0->a_params = NULL;
  }
  else {
    sip_contact_t const *m = nua_contact_by_aor(nua, NULL, 0);
    
    if (m) {
      from->a_display = m->m_display;
      *from->a_url = *m->m_url;
      f0 = sip_from_dup(nua->nua_home, from);
    }
  }

  if (f0)
    *nua->nua_from = *f0;
}


/** Initialize instance ID. */
static
void ua_init_instance(nua_t *nua, char const *instance)
{
  nua_handle_t *dnh = nua->nua_dhandle;
  nua_handle_preferences_t *dnhp = dnh->nh_prefs;

  if (instance == NONE) {
    char str[su_guid_strlen + 1];
    su_guid_t guid[1];

    su_guid_generate(guid);
    /*
     * Guid looks like "NNNNNNNN-NNNN-NNNN-NNNN-XXXXXXXXXXXX"
     * where NNNNNNNN-NNNN-NNNN-NNNN is timestamp and XX is MAC address
     * (but we use usually random ID for MAC because we do not have
     *  guid generator available for all processes within node)
     */
    su_guid_sprintf(str, su_guid_strlen + 1, guid);

    DNHP_SET(dnhp, instance, su_sprintf(dnh->nh_home, "urn:uuid:%s", str));
  }
  else {
    DNHP_SET(dnhp, instance, su_strdup(dnh->nh_home, instance));
  }
}


/* ----------------------------------------------------------------------
 * Sending events to client application
 */

static void nua_stack_shutdown(nua_t *);

void
  nua_stack_authenticate(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  nua_stack_respond(nua_t *, nua_handle_t *, int , char const *, tagi_t const *),
  nua_stack_destroy_handle(nua_t *, nua_handle_t *, tagi_t const *);

/* Notifier */
void
  nua_stack_authorize(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  nua_stack_notifier(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  nua_stack_terminate(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *);

int nh_notifier_shutdown(nua_handle_t *nh, nea_event_t *ev,
			 tag_type_t t, tag_value_t v, ...);

/** Send an event to the application. */
int nua_stack_event(nua_t *nua, nua_handle_t *nh, msg_t *msg,
		    nua_event_t event, int status, char const *phrase,
		    tag_type_t tag, tag_value_t value, ...)
{
  su_msg_r sumsg = SU_MSG_R_INIT;

  ta_list ta;
  int e_len, len, xtra, p_len;

  enter;

  if (nua_log->log_level >= 5) {
    char const *name = nua_event_name(event) + 4;
    char const *p = phrase ? phrase : "";

    if (status == 0)
      SU_DEBUG_5(("nua(%p): %s %s\n", nh, name, p));
    else
      SU_DEBUG_5(("nua(%p): %s %u %s\n", nh, name, status, p));
  }

  if (event == nua_r_destroy) {
    if (msg)
      msg_destroy(msg);
    if (status >= 200) {
      nh_destroy(nua, nh);
    }
    return event;
  }

  if (event > nua_r_method || (nh && !nh->nh_valid) ||
      (nua->nua_shutdown && event != nua_r_shutdown)) {
    if (msg)
      msg_destroy(msg);
    return event;
  }

  ta_start(ta, tag, value);

  e_len = offsetof(event_t, e_tags);
  len = tl_len(ta_args(ta));
  xtra = tl_xtra(ta_args(ta), len);
  p_len = phrase ? strlen(phrase) + 1 : 1;

  if (su_msg_create(sumsg, nua->nua_client, nua->nua_server,
		    nua_event, e_len + len + xtra + p_len) == 0) {
    event_t *e = su_msg_data(sumsg);

    tagi_t *t = e->e_tags, *t_end = (tagi_t *)((char *)t + len);
    void *b = t_end, *end = (char *)b + xtra;

    t = tl_dup(t, ta_args(ta), &b);
    assert(t == t_end); assert(b == end);

    e->e_event = event;
    e->e_nh = nh ? nua_handle_ref(nh) : nua->nua_dhandle;
    e->e_status = status;
    e->e_phrase = strcpy(end, phrase ? phrase : "");
    e->e_msg = msg;

    if (su_msg_send(sumsg) != 0)
      nua_handle_unref(nh);
  }

  ta_end(ta);

  return event;
}

/* ----------------------------------------------------------------------
 * Post signal to stack itself
 */
void nua_stack_post_signal(nua_handle_t *nh, nua_event_t event,
			   tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  ta_start(ta, tag, value);
  nua_signal((nh)->nh_nua, nh, NULL, 1, event, 0, NULL, ta_tags(ta));
  ta_end(ta);
}


/* ----------------------------------------------------------------------
 * Receiving events from client
 */
void nua_stack_signal(nua_t *nua, su_msg_r msg, nua_event_data_t *e)
{
  nua_handle_t *nh = e->e_nh;
  tagi_t *tags = e->e_tags;

  if (nh) {
    if (!nh->nh_prev)
      nh_append(nua, nh);
    if (!nh->nh_ref_by_stack) {
      nh->nh_ref_by_stack = 1;
      nua_handle_ref(nh);
    }
  }

  if (nua_log->log_level >= 5) {
    char const *name = nua_event_name(e->e_event);
    if (e->e_status == 0)
      SU_DEBUG_5(("nua(%p): signal %s\n", nh, name + 4));
    else
      SU_DEBUG_5(("nua(%p): signal %s %u %s\n",
		  nh, name + 4, e->e_status, e->e_phrase ? e->e_phrase : ""));
  }

  su_msg_save(nua->nua_signal, msg);

  if (nua->nua_shutdown && !e->e_always) {
    /* Shutting down */
    nua_stack_event(nua, nh, NULL, e->e_event, 500, "Stack is going down", TAG_END());
  }
  else switch (e->e_event) {
  case nua_r_get_params:
    nua_stack_get_params(nua, nh ? nh : nua->nua_dhandle, e->e_event, tags);
    break;
  case nua_r_set_params:
    nua_stack_set_params(nua, nh ? nh : nua->nua_dhandle, e->e_event, tags);
    break;
  case nua_r_shutdown:
    nua_stack_shutdown(nua);
    break;
  case nua_r_register:
  case nua_r_unregister:
    nua_stack_register(nua, nh, e->e_event, tags);
    break;
  case nua_r_invite:
    nua_stack_invite(nua, nh, e->e_event, tags);
    break;
  case nua_r_cancel:
    nua_stack_cancel(nua, nh, e->e_event, tags);
    break;
  case nua_r_bye:
    nua_stack_bye(nua, nh, e->e_event, tags);
    break;
  case nua_r_options:
    nua_stack_options(nua, nh, e->e_event, tags);
    break;
  case nua_r_refer:
    nua_stack_refer(nua, nh, e->e_event, tags);
    break;
  case nua_r_publish:
  case nua_r_unpublish:
    nua_stack_publish(nua, nh, e->e_event, tags);
    break;
  case nua_r_info:
    nua_stack_info(nua, nh, e->e_event, tags);
    break;
  case nua_r_update:
    nua_stack_update(nua, nh, e->e_event, tags);
    break;
  case nua_r_message:
    nua_stack_message(nua, nh, e->e_event, tags);
    break;
  case nua_r_subscribe:
  case nua_r_unsubscribe:
    nua_stack_subscribe(nua, nh, e->e_event, tags);
    break;
  case nua_r_notify:
    nua_stack_notify(nua, nh, e->e_event, tags);
    break;
  case nua_r_notifier:
    nua_stack_notifier(nua, nh, e->e_event, tags);
    break;
  case nua_r_terminate:
    nua_stack_terminate(nua, nh, e->e_event, tags);
    break;
  case nua_r_method:
    nua_stack_method(nua, nh, e->e_event, tags);
    break;
  case nua_r_authenticate:
    nua_stack_authenticate(nua, nh, e->e_event, tags);
    break;
  case nua_r_authorize:
    nua_stack_authorize(nua, nh, e->e_event, tags);
    break;
  case nua_r_ack:
    nua_stack_ack(nua, nh, e->e_event, tags);
    break;
  case nua_r_respond:
    nua_stack_respond(nua, nh, e->e_status, e->e_phrase, tags);
    break;
  case nua_r_destroy:
    nua_stack_destroy_handle(nua, nh, tags);
    break;
  default:
    break;
  }

  if (su_msg_is_non_null(nua->nua_signal))
    su_msg_destroy(nua->nua_signal);

  if (nh != nua->nua_dhandle)
    nua_handle_unref(nh);
}

/* ====================================================================== */

static int nh_call_pending(nua_handle_t *nh, sip_time_t time);

/** Timer routine.
 *
 * Go through all active handles and execute pending tasks
 */
void nua_stack_timer(nua_t *nua, su_timer_t *t, su_timer_arg_t *a)
{
  nua_handle_t *nh, *nh_next;
  sip_time_t now = sip_now();

  su_timer_set(t, nua_stack_timer, a);

  if (nua->nua_shutdown) {
    nua_stack_shutdown(nua);
    return;
  }

  for (nh = nua->nua_handles; nh; nh = nh_next) {
    nh_next = nh->nh_next;
    nh_call_pending(nh, now);
  }
}


static
int nh_call_pending(nua_handle_t *nh, sip_time_t now)
{
  nua_dialog_usage_t *du;
  sip_time_t next = now + NUA_STACK_TIMER_INTERVAL / 1000;

  for (du = nh->nh_ds->ds_usage; du; du = du->du_next) {
    if (!du->du_pending)
      continue;
    if (now == 0 || (du->du_refresh && du->du_refresh < next))
      break;
  }

  if (du == NULL)
    return 0;

  nua_handle_ref(nh);

  while (du) {
    nh_pending_f *pending = du->du_pending;
    nua_dialog_usage_t *du_next = du->du_next;

    du->du_pending = NULL;

    pending(nh, du, now);

    if (du_next == NULL)
      break;

    for (du = nh->nh_ds->ds_usage; du; du = du->du_next)
      if (du == du_next)
	break;

    for (; du; du = du->du_next) {
      if (!du->du_pending)
	continue;
      if (now == 0 || (du->du_refresh && du->du_refresh < next))
	break;
    }
  }

  nua_handle_unref(nh);

  return 1;
}


/* ====================================================================== */

/** Shut down stack. */
void nua_stack_shutdown(nua_t *nua)
{
  nua_handle_t *nh, *nh_next;
  int busy = 0;
  sip_time_t now = sip_now();
  int status;
  char const *phrase;
  struct nua_session_state *ss;

  enter;

  if (!nua->nua_shutdown)
    nua->nua_shutdown = now;

  for (nh = nua->nua_handles; nh; nh = nh_next) {
    nh_next = nh->nh_next;

    ss = nh->nh_ss;

    if (ss->ss_srequest->sr_respond) {
      ss->ss_srequest->sr_respond(nua, nh, SIP_410_GONE, NULL);
      busy++;
    }

    busy += nh_call_pending(nh, 0);

    if (nh->nh_soa) {
      soa_destroy(nh->nh_soa), nh->nh_soa = NULL;
    }

    if (nh->nh_cr->cr_orq || nh->nh_ss->ss_crequest->cr_orq)
      busy++;

    if (nh_notifier_shutdown(nh, NULL, NEATAG_REASON("noresource"), TAG_END()))
      busy++;
  }


  if (!busy)
    SET_STATUS(200, "Shutdown successful");
  else if (now == nua->nua_shutdown)
    SET_STATUS(100, "Shutdown started");
  else if (now - nua->nua_shutdown < 30)
    SET_STATUS(101, "Shutdown in progress");
  else
    SET_STATUS(500, "Shutdown timeout");

  if (status >= 200) {
    su_timer_destroy(nua->nua_timer), nua->nua_timer = NULL;
    nta_agent_destroy(nua->nua_nta), nua->nua_nta = NULL;
  }

  nua_stack_event(nua, NULL, NULL, nua_r_shutdown, status, phrase, TAG_END());
}

/* ----------------------------------------------------------------------
 * Parameters
 */

#include <sofia-sip/msg_parser.h>

int nua_stack_set_params(nua_t *nua, nua_handle_t *nh, nua_event_t e,
			 tagi_t const *tags)
{
  nua_handle_t *dnh = nua->nua_dhandle;
  nua_handle_preferences_t nhp[1], *ohp = nh->nh_prefs;
  nua_handle_preferences_t const *dnhp = dnh->nh_prefs;

  su_home_t tmphome[1] = { SU_HOME_INIT(tmphome) };

  unsigned retry_count = NHP_GET(ohp, dnhp, retry_count);
  unsigned max_subscriptions = NHP_GET(ohp, dnhp, max_subscriptions);

  int invite_enable = NHP_GET(ohp, dnhp, invite_enable);
  int auto_alert = NHP_GET(ohp, dnhp, auto_alert);
  int early_media = NHP_GET(ohp, dnhp, early_media);
  int auto_answer = NHP_GET(ohp, dnhp, auto_answer);
  int auto_ack = NHP_GET(ohp, dnhp, auto_ack);
  unsigned invite_timeout = NHP_GET(ohp, dnhp, invite_timeout);

  unsigned session_timer = NHP_GET(ohp, dnhp, session_timer);
  unsigned min_se = NHP_GET(ohp, dnhp, min_se);
  int refresher = NHP_GET(ohp, dnhp, refresher);
  int update_refresh = NHP_GET(ohp, dnhp, update_refresh);

  int message_enable = NHP_GET(ohp, dnhp, message_enable);
  int win_messenger_enable = NHP_GET(ohp, dnhp, win_messenger_enable);
  int message_auto_respond = NHP_GET(ohp, dnhp, message_auto_respond);

  int callee_caps = NHP_GET(ohp, dnhp, callee_caps);
  int media_features = NHP_GET(ohp, dnhp, media_features);
  int service_route_enable = NHP_GET(ohp, dnhp, service_route_enable);
  int path_enable = NHP_GET(ohp, dnhp, path_enable);

  int substate = NHP_GET(ohp, dnhp, substate);

  sip_allow_t const *allow = NONE;
  char const   *allow_str = NONE;
  char const   *allowing = NULL;
  sip_supported_t const *supported = NONE;
  char const *supported_str = NONE;
  sip_user_agent_t const *user_agent = NONE;
  char const *user_agent_str = NONE, *ua_name = NONE;
  sip_organization_t const *organization = NONE;
  char const *organization_str = NONE;

  url_string_t const *registrar = NONE;
  sip_from_t const *from = NONE;
  char const *from_str = NONE;

#if HAVE_SOFIA_SMIME
  int           smime_enable = nua->sm->sm_enable;
  int           smime_opt = nua->sm->sm_opt;
  int           smime_protection_mode = nua->sm->sm_protection_mode;
  char const   *smime_message_digest = NONE;
  char const   *smime_signature = NONE;
  char const   *smime_key_encryption = NONE;
  char const   *smime_message_encryption = NONE;
  char const   *smime_path = NONE;
#endif

  int n;

  enter;

  if (nh == dnh)
    if (nta_agent_set_params(nua->nua_nta, TAG_NEXT(tags)) < 0)
      return UA_EVENT2(e, 400, "Error setting NTA parameters"), -1;

  if (nh->nh_soa && soa_set_params(nh->nh_soa, TAG_NEXT(tags)) < 0)
    return UA_EVENT2(e, 400, "Error setting SOA parameters"), -1;

  n =  tl_gets(tags,
	       NUTAG_RETRY_COUNT_REF(retry_count),
	       NUTAG_MAX_SUBSCRIPTIONS_REF(max_subscriptions),

	       NUTAG_ENABLEINVITE_REF(invite_enable),
	       NUTAG_AUTOALERT_REF(auto_alert),
	       NUTAG_EARLY_MEDIA_REF(early_media),
	       NUTAG_AUTOANSWER_REF(auto_answer),
	       NUTAG_AUTOACK_REF(auto_ack),
	       NUTAG_INVITE_TIMER_REF(invite_timeout),

	       NUTAG_SESSION_TIMER_REF(session_timer),
	       NUTAG_MIN_SE_REF(min_se),
	       NUTAG_SESSION_REFRESHER_REF(refresher),
	       NUTAG_UPDATE_REFRESH_REF(update_refresh),

	       NUTAG_ENABLEMESSAGE_REF(message_enable),
	       NUTAG_ENABLEMESSENGER_REF(win_messenger_enable),
	       /* NUTAG_MESSAGE_AUTOANSWER(message_auto_respond), */

	       NUTAG_CALLEE_CAPS_REF(callee_caps),
	       NUTAG_MEDIA_FEATURES_REF(media_features),
	       NUTAG_SERVICE_ROUTE_ENABLE_REF(service_route_enable),
	       NUTAG_PATH_ENABLE_REF(path_enable),
	       NUTAG_SUBSTATE_REF(substate),

	       SIPTAG_SUPPORTED_REF(supported),
	       SIPTAG_SUPPORTED_STR_REF(supported_str),

	       SIPTAG_ALLOW_REF(allow),
	       SIPTAG_ALLOW_STR_REF(allow_str),
	       NUTAG_ALLOW_REF(allowing),

	       SIPTAG_USER_AGENT_REF(user_agent),
	       SIPTAG_USER_AGENT_STR_REF(user_agent_str),
	       NUTAG_USER_AGENT_REF(ua_name),

	       SIPTAG_ORGANIZATION_REF(organization),
	       SIPTAG_ORGANIZATION_STR_REF(organization_str),

	       TAG_IF(nh != dnh, TAG_END()),

	       NUTAG_REGISTRAR_REF(registrar),
	       SIPTAG_FROM_REF(from),
	       SIPTAG_FROM_STR_REF(from_str),

#if HAVE_SOFIA_SMIME
	       NUTAG_SMIME_ENABLE_REF(smime_enable),
	       NUTAG_SMIME_OPT_REF(smime_opt),
	       NUTAG_SMIME_PROTECTION_MODE_REF(smime_protection_mode),
	       NUTAG_SMIME_MESSAGE_DIGEST_REF(smime_message_digest),
	       NUTAG_SMIME_SIGNATURE_REF(smime_signature),
	       NUTAG_SMIME_KEY_ENCRYPTION_REF(smime_key_encryption),
	       NUTAG_SMIME_MESSAGE_ENCRYPTION_REF(smime_message_encryption),
	       NUTAG_CERTIFICATE_DIR_REF(smime_path),
#endif
	       TAG_NULL());
  if (n < 0)
    return UA_EVENT2(e, 400, "Error obtaining NUA parameters"), -1;

  *nhp = *ohp; NHP_UNSET_ALL(nhp);

#if 0
  reinit_contact =
    nua->nua_dhandle->nh_callee_caps != callee_caps ||
    media_path != NONE ||
    allow != NONE || allow_str != NONE;
#endif

  if (invite_timeout > 0 && invite_timeout < 30)
    invite_timeout = 30;

  if (min_se > 0 && min_se < 30)
    min_se = 30;
  if (session_timer > 0) {
    if (session_timer < 30)
      session_timer = 30;
    if (session_timer < min_se)
      session_timer = min_se;
  }
  if (refresher >= nua_remote_refresher)
    refresher = nua_remote_refresher;
  else if (refresher <= nua_no_refresher)
    refresher = nua_no_refresher;

  /* Set int in handle pref structure */
#define NHP_SET(nhp, pref, value)			   \
  (((nhp)->nhp_set.set_bits.nhp_##pref = (value) != (nhp)->nhp_##pref), \
   (nhp)->nhp_##pref = value)

  NHP_SET(nhp, retry_count, retry_count);
  NHP_SET(nhp, max_subscriptions, max_subscriptions);

  NHP_SET(nhp, invite_enable, invite_enable);
  NHP_SET(nhp, auto_alert, auto_alert != 0);
  NHP_SET(nhp, early_media, early_media != 0);
  NHP_SET(nhp, auto_answer, auto_answer != 0);
  NHP_SET(nhp, auto_ack, auto_ack != 0);
  NHP_SET(nhp, invite_timeout, invite_timeout);

  NHP_SET(nhp, session_timer, session_timer);
  NHP_SET(nhp, min_se, min_se);
  NHP_SET(nhp, refresher, refresher);
  NHP_SET(nhp, update_refresh, update_refresh != 0);

  NHP_SET(nhp, message_enable, message_enable);
  NHP_SET(nhp, win_messenger_enable, win_messenger_enable);
  NHP_SET(nhp, message_auto_respond, message_auto_respond);

  NHP_SET(nhp, media_features, media_features != 0);
  NHP_SET(nhp, callee_caps, callee_caps != 0);
  NHP_SET(nhp, service_route_enable, service_route_enable != 0);
  NHP_SET(nhp, path_enable, path_enable != 0);

  NHP_SET(nhp, substate, substate);

  /* Set string in handle pref structure */
#define NHP_SET_STR(nhp, name, str)				 \
  if (str != NONE && str0cmp(str, nhp->nhp_##name)) {		 \
    char *new_str = su_strdup(tmphome, str);			 \
    if (new_str != NULL || str == NULL) {			 \
      NHP_SET(nhp, name, new_str);				 \
    }								 \
    else {							 \
      n = -1;							 \
    }								 \
  }

  /* Set header in handle pref structure */
#define NHP_SET_HEADER(nhp, name, header, str)			 \
  if (header != NONE || str != NONE) {				 \
    sip_##name##_t *new_header;					 \
    if (header != NONE)						 \
      new_header = sip_##name##_dup(tmphome, header);		 \
    else							 \
      new_header = sip_##name##_make(tmphome, str);		 \
    if (new_header != NULL || (header == NULL || str == NULL)) { \
      NHP_SET(nhp, name, new_header);				 \
    }								 \
    else {							 \
      n = -1;							 \
    }								 \
  }

  /* Add contents of NUTAG_ALLOW() to list of currently allowed methods */
  if (allow == NONE && allow_str == NONE && allowing != NULL) {
    sip_allow_t *methods = sip_allow_make(tmphome, allowing);

    if (methods)
      allow = sip_allow_dup(tmphome, NHP_GET(ohp, dnhp, allow));

    if (allow == NULL)
      allow = NONE;

    if (allow != NONE)
      if (msg_params_join(tmphome,
			  (msg_param_t **)&allow->k_items, methods->k_items,
			  1 /* prune */, 0 /* don't dup */) < 0)
	allow = NONE;
  }

  NHP_SET_HEADER(nhp, supported, supported, supported_str);
  NHP_SET_HEADER(nhp, allow, allow, allow_str);
  /* Add contents of NUTAG_USER_AGENT() to our distribution name */
  if (ua_name != NONE && user_agent_str == NONE && user_agent == NONE)
    user_agent_str = ua_name
      ? su_sprintf(tmphome, "%s %s", ua_name, PACKAGE_NAME "/" PACKAGE_VERSION)
      : PACKAGE_NAME "/" PACKAGE_VERSION;
  NHP_SET_HEADER(nhp, user_agent, user_agent, user_agent_str);
  NHP_SET_STR(nhp, ua_name, ua_name);
  NHP_SET_HEADER(nhp, organization, organization, organization_str);

  if (n > 0 && NHP_IS_ANY_SET(nhp)) {
    /* Move allocations from tmphome to handle's home */
    if (nh != dnh && nh->nh_prefs == dnh->nh_prefs) {
      /* We have made changes to handle-specific settings
       * but we don't have a prefs structure owned by handle yet */
      nua_handle_preferences_t *ahp = su_alloc(nh->nh_home, sizeof *ahp);
      if (ahp && su_home_move(nh->nh_home, tmphome) >= 0) {
	memcpy(ahp, nhp, sizeof *ahp);

	/* Zap pointers which are not set */
#define NHP_ZAP_UNSET_PTR(nhp, pref) \
	(!(nhp)->nhp_set.set_bits.nhp_##pref ? (nhp)->nhp_##pref = NULL : NULL)

	NHP_ZAP_UNSET_PTR(ahp, supported);
	NHP_ZAP_UNSET_PTR(ahp, allow);
	NHP_ZAP_UNSET_PTR(ahp, user_agent);
	NHP_ZAP_UNSET_PTR(ahp, ua_name);
	NHP_ZAP_UNSET_PTR(ahp, organization);

	nh->nh_prefs = ahp;
      }
      else {
	n = -1;
      }
    }
    else if (su_home_move(nh->nh_home, tmphome) >= 0) {
      /* Update prefs structure */
      nua_handle_preferences_t tbf[1];
      nhp->nhp_set.set_any |= ohp->nhp_set.set_any;
      *tbf = *ohp; *ohp = *nhp;

      /* Free changed items */
#define NHP_ZAP_OVERRIDEN(tbf, nhp, pref)			\
      ((tbf)->nhp_set.set_bits.nhp_##pref			\
       && (tbf)->nhp_##pref != (nhp)->nhp_##pref		\
       ? su_free(nh->nh_home, (void *)(tbf)->nhp_##pref) : (void)0)

      NHP_ZAP_OVERRIDEN(tbf, nhp, supported);
      NHP_ZAP_OVERRIDEN(tbf, nhp, allow);
      NHP_ZAP_OVERRIDEN(tbf, nhp, user_agent);
      NHP_ZAP_OVERRIDEN(tbf, nhp, ua_name);
      NHP_ZAP_OVERRIDEN(tbf, nhp, organization);
    }
    else
      /* Fail miserably with ENOMEM */
      n = -1;
  }

  su_home_deinit(tmphome);

  if (n < 0)
    return UA_EVENT2(e, 500, "Error storing parameters"), -1;

  if (nh != dnh)
    return e == nua_r_set_params ? UA_EVENT2(e, 200, "OK") : 0;

  if (registrar != NONE) {
    if (registrar &&
	(url_string_p(registrar) ?
	 strcmp(registrar->us_str, "*") == 0 :
	 registrar->us_url->url_type == url_any))
      registrar = NULL;
    su_free(nua->nua_home, nua->nua_registrar);
    nua->nua_registrar = url_hdup(nua->nua_home, registrar->us_url);
  }

  if (from != NONE || from_str != NONE) {
    if (from == NONE) from = NULL;
    if (from_str == NONE) from_str = NULL;
    ua_set_from(nua, from, from_str);
  }

  /* XXX ua_init_contact(nua); */

#if HAVE_SOFIA_SMIME
  /* XXX - all S/MIME other parameters? */
  sm_set_params(nua->sm, smime_enable, smime_opt,
		smime_protection_mode, smime_path);
#endif
  return e == nua_r_set_params ? UA_EVENT2(e, 200, "OK") : 0;
}

/**Send a list of NUA parameters to the application.
 *
 * This function gets invoked when application calls either nua_get_params()
 * or nua_get_hparams().
 *
 * The parameter tag list will initially contain all the relevant parameter
 * tags, and it will be filtered down to parameters asked by application.
 *
 * The handle-specific parameters will contain only the parameters actually
 * modified by application, either by nua_set_hparams() or some other
 * handle-specific call. NTA parameters are returned only when application
 * asks for user-agent-level parameters using nua_get_params().
 *
 */
int nua_stack_get_params(nua_t *nua, nua_handle_t *nh, nua_event_t e,
			 tagi_t const *tags)
{
  nua_handle_t *dnh = nua->nua_dhandle;
  nua_handle_preferences_t const *nhp = nh->nh_prefs;

  tagi_t *lst;

  int has_from;
  sip_from_t from[1];

  sip_contact_t const *m;

  /* nta */
  unsigned udp_mtu = 0, sip_t1 = 0, sip_t2 = 0, sip_t4 = 0, sip_t1x64 = 0;
  unsigned debug_drop_prob = 0;
  url_string_t const *proxy = NULL;
  sip_contact_t const *aliases = NULL;
  unsigned flags = 0;

  /* soa */
  tagi_t *media_params = NULL;

  su_home_t tmphome[SU_HOME_AUTO_SIZE(16536)];

  enter;

  su_home_auto(tmphome, sizeof(tmphome));

  nta_agent_get_params(nua->nua_nta,
		       NTATAG_UDP_MTU_REF(udp_mtu),
		       NTATAG_SIP_T1_REF(sip_t1),
		       NTATAG_SIP_T2_REF(sip_t2),
		       NTATAG_SIP_T4_REF(sip_t4),
		       NTATAG_SIP_T1X64_REF(sip_t1x64),
		       NTATAG_DEBUG_DROP_PROB_REF(debug_drop_prob),
		       NTATAG_DEFAULT_PROXY_REF(proxy),
		       NTATAG_ALIASES_REF(aliases),
		       NTATAG_SIPFLAGS_REF(flags),
		       TAG_END());

  if (nh->nh_ds->ds_local)
    has_from = 1, *from = *nh->nh_ds->ds_local, from->a_params = NULL;
  else
    has_from = 0;

  media_params = soa_get_paramlist(nh->nh_soa, TAG_END());

  m = nua_contact_by_aor(nh->nh_nua, NULL, 0);

  /* Include tag in list returned to user
   * if it has been earlier set (by user) */
#define TIF(TAG, pref) \
  TAG_IF(nhp->nhp_set.set_bits.nhp_##pref, TAG(nhp->nhp_##pref))

  /* Include string tag made out of SIP header
   * if it has been earlier set (by user) */
#define TIF_STR(TAG, pref)						\
  TAG_IF(nhp->nhp_set.set_bits.nhp_##pref,				\
	 TAG(nhp->nhp_set.set_bits.nhp_##pref && nhp->nhp_##pref	\
	     ? sip_header_as_string(tmphome, (void *)nhp->nhp_##pref) : NULL))

  lst = tl_filtered_tlist
    (tmphome, tags,
     TAG_IF(has_from, SIPTAG_FROM(from)),
     TAG_IF(has_from,
	    SIPTAG_FROM_STR(has_from
			    ? sip_header_as_string(tmphome, (void *)from)
			    : NULL)),

     TIF(NUTAG_RETRY_COUNT, retry_count),
     TIF(NUTAG_MAX_SUBSCRIPTIONS, max_subscriptions),

     TIF(NUTAG_ENABLEINVITE, invite_enable),
     TIF(NUTAG_AUTOALERT, auto_alert),
     TIF(NUTAG_EARLY_MEDIA, early_media),
     TIF(NUTAG_AUTOANSWER, auto_answer),
     TIF(NUTAG_AUTOACK, auto_ack),
     TIF(NUTAG_INVITE_TIMER, invite_timeout),

     TIF(NUTAG_SESSION_TIMER, session_timer),
     TIF(NUTAG_MIN_SE, min_se),
     TIF(NUTAG_SESSION_REFRESHER, refresher),
     TIF(NUTAG_UPDATE_REFRESH, update_refresh),

     TIF(NUTAG_ENABLEMESSAGE, message_enable),
     TIF(NUTAG_ENABLEMESSENGER, win_messenger_enable),
     /* TIF(NUTAG_MESSAGE_AUTOANSWER, message_auto_respond), */

     TIF(NUTAG_CALLEE_CAPS, callee_caps),
     TIF(NUTAG_MEDIA_FEATURES, media_features),
     TIF(NUTAG_SERVICE_ROUTE_ENABLE, service_route_enable),
     TIF(NUTAG_PATH_ENABLE, path_enable),

     TIF(NUTAG_SUBSTATE, substate),

     TIF(SIPTAG_SUPPORTED, supported),
     TIF_STR(SIPTAG_SUPPORTED_STR, supported),
     TIF(SIPTAG_ALLOW, allow),
     TIF_STR(SIPTAG_ALLOW_STR, allow),
     TIF(SIPTAG_USER_AGENT, user_agent),
     TIF_STR(SIPTAG_USER_AGENT_STR, user_agent),
     TIF(NUTAG_USER_AGENT, ua_name),

     TIF(SIPTAG_ORGANIZATION, organization),
     TIF_STR(SIPTAG_ORGANIZATION_STR, organization),

     /* Skip user-agent-level parameters if parameters are for handle only */
     TAG_IF(nh != dnh, TAG_NEXT(media_params)),

     NUTAG_MEDIA_ENABLE(nua->nua_media_enable),
     NUTAG_REGISTRAR(nua->nua_registrar),

     NTATAG_CONTACT(m),

#if HAVE_SOFIA_SMIME
     NUTAG_SMIME_ENABLE(nua->sm->sm_enable),
     NUTAG_SMIME_OPT(nua->sm->sm_opt),
     NUTAG_SMIME_PROTECTION_MODE(nua->sm->sm_protection_mode),
     NUTAG_SMIME_MESSAGE_DIGEST(nua->sm->sm_message_digest),
     NUTAG_SMIME_SIGNATURE(nua->sm->sm_signature),
     NUTAG_SMIME_KEY_ENCRYPTION(nua->sm->sm_key_encryption),
     NUTAG_SMIME_MESSAGE_ENCRYPTION(nua->sm->sm_message_encryption),
#endif

     NTATAG_UDP_MTU(udp_mtu),
     NTATAG_SIP_T1(sip_t1),
     NTATAG_SIP_T2(sip_t2),
     NTATAG_SIP_T4(sip_t4),
     NTATAG_SIP_T1X64(sip_t1x64),
     NTATAG_DEBUG_DROP_PROB(debug_drop_prob),
     NTATAG_DEFAULT_PROXY(proxy),
     NTATAG_ALIASES(aliases),
     NTATAG_SIPFLAGS(flags),

     TAG_NEXT(media_params));

  nua_stack_event(nua, nh, NULL, nua_r_get_params, SIP_200_OK, TAG_NEXT(lst));

  su_home_deinit(tmphome);

  tl_vfree(media_params);

  return 0;
}

/* ---------------------------------------------------------------------- */

/** Create a handle */
nua_handle_t *nh_create(nua_t *nua, tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  nua_handle_t *nh;

  enter;

  ta_start(ta, tag, value);
  nh = nh_create_handle(nua, NULL, ta_args(ta));
  ta_end(ta);

  if (nh) {
    nh->nh_ref_by_stack = 1;
    nh_append(nua, nh);
  }

  return nh;
}

/** Append an handle to the list of handles */
void nh_append(nua_t *nua, nua_handle_t *nh)
{
  nh->nh_next = NULL;
  nh->nh_prev = nua->nua_handles_tail;
  *nua->nua_handles_tail = nh;
  nua->nua_handles_tail = &nh->nh_next;
}

nua_handle_t *nh_validate(nua_t *nua, nua_handle_t *maybe)
{
  nua_handle_t *nh;

  if (maybe)
    for (nh = nua->nua_handles; nh; nh = nh->nh_next)
      if (nh == maybe)
	return nh;

  return NULL;
}

void nua_stack_destroy_handle(nua_t *nua, nua_handle_t *nh, tagi_t const *tags)
{
  nh_call_pending(nh, 0);	/* Call pending operations with 0 */

  if (nh->nh_notifier)
    nua_stack_terminate(nua, nh, 0, NULL);

#if 0
  if (nh->nh_ref_by_user) {
    nh->nh_ref_by_user = 0;
    nua_handle_unref(nh);
  }
#endif

  nh_destroy(nua, nh);
}

#define nh_is_inserted(nh) ((nh)->nh_prev != NULL)

/** Remove a handle from list of handles */
static
void nh_remove(nua_t *nua, nua_handle_t *nh)
{
  assert(nh_is_inserted(nh)); assert(*nh->nh_prev == nh);

  if (nh->nh_next)
    nh->nh_next->nh_prev = nh->nh_prev;
  else
    nua->nua_handles_tail = nh->nh_prev;

  *nh->nh_prev = nh->nh_next;

  nh->nh_prev = NULL;
  nh->nh_next = NULL;
}


void nh_destroy(nua_t *nua, nua_handle_t *nh)
{
  assert(nh); assert(nh != nua->nua_dhandle);

  nh_enter;

  if (nh->nh_notifier)
    nea_server_destroy(nh->nh_notifier), nh->nh_notifier = NULL;

  nua_creq_deinit(nh->nh_cr, NULL);
  if (nh->nh_ss)
    nua_creq_deinit(nh->nh_ss->ss_crequest, NULL);

  if (nh->nh_ds->ds_leg) {
    nta_leg_destroy(nh->nh_ds->ds_leg), nh->nh_ds->ds_leg = NULL;
  }

  if (nh->nh_ss->ss_srequest->sr_irq) {
    nta_incoming_destroy(nh->nh_ss->ss_srequest->sr_irq);
    nh->nh_ss->ss_srequest->sr_irq = NULL;
  }

  if (nh->nh_soa)
    soa_destroy(nh->nh_soa), nh->nh_soa = NULL;

  if (nh_is_inserted(nh))
    nh_remove(nua, nh);

  nua_handle_unref(nh);		/* Remove stack reference */
}

void nua_creq_deinit(struct nua_client_request *cr, nta_outgoing_t *orq)
{
  if (orq == NULL || orq == cr->cr_orq) {
    cr->cr_retry_count = 0;
    cr->cr_offer_sent = cr->cr_answer_recv = 0;

    if (cr->cr_msg)
      msg_destroy(cr->cr_msg);
    cr->cr_msg = NULL;

    if (cr->cr_orq)
      nta_outgoing_destroy(cr->cr_orq);
    cr->cr_orq = NULL;
  }
  else {
    nta_outgoing_destroy(orq);
  }
}

/* ======================================================================== */

/** Initialize handle Allow and authentication info.
 *
 * @retval -1 upon an error
 * @retval 0 when successful
 */
int nua_stack_init_handle(nua_t *nua, nua_handle_t *nh,
			  enum nh_kind kind,
			  char const *default_allow,
			  tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int retval = 0;

  if (nh == NULL)
    return -1;

  if (kind && !nh_is_special(nh) && !nh->nh_has_invite) {
    switch (kind) {
    case nh_has_invite:    nh->nh_has_invite = 1;    break;
    case nh_has_subscribe: nh->nh_has_subscribe = 1; break;
    case nh_has_notify:    nh->nh_has_notify = 1;    break;
    case nh_has_register:  nh->nh_has_register = 1;  break;
    case nh_has_streaming: nh->nh_has_streaming = 1; break;
    case nh_has_nothing:
    default:
      break;
    }
  }

  assert(nh != nua->nua_dhandle);

  ta_start(ta, tag, value);

  if (nua_stack_set_params(nua, nh, nua_i_error, ta_args(ta)) < 0)
    retval = -1;

  if (!retval && !nh->nh_soa && nua->nua_dhandle->nh_soa) {
    nh->nh_soa = soa_clone(nua->nua_dhandle->nh_soa, nua->nua_root, nh);

    if (nh->nh_soa && nh->nh_tags)
      if (soa_set_params(nh->nh_soa, TAG_NEXT(nh->nh_tags)))
	retval = -1;
  }

  if (!retval && nh->nh_soa)
    if (soa_set_params(nh->nh_soa, ta_tags(ta)) < 0)
      retval = -1;

  ta_end(ta);

  if (retval || nh->nh_init) /* Already initialized? */
    return retval;

#if HAVE_UICC_H
  if (nh->nh_has_register && nua->nua_uicc)
    auc_with_uicc(&nh->nh_auth, nh->nh_home, nua->nua_uicc);
#endif

  if (nh->nh_tags)
    nh_authorize(nh, TAG_NEXT(nh->nh_tags));

  nh->nh_ss->ss_min_se = NH_PGET(nh, min_se);
  nh->nh_ss->ss_session_timer = NH_PGET(nh, session_timer);
  nh->nh_ss->ss_refresher = NH_PGET(nh, refresher);

  nh->nh_init = 1;

  return 0;
}

/** Create a handle for processing incoming request */
nua_handle_t *nua_stack_incoming_handle(nua_t *nua,
					nta_incoming_t *irq,
					sip_t const *sip,
					enum nh_kind kind,
					int create_dialog)
{
  nua_handle_t *nh;
  url_t const *url;
  char const *default_allow = NULL; /* XXX - should be argument? */
  sip_to_t to[1];
  sip_from_t from[1];

  assert(sip && sip->sip_from && sip->sip_to);

  if (sip->sip_contact)
    url = sip->sip_contact->m_url;
  else
    url = sip->sip_from->a_url;

  sip_from_init(from)->a_display = sip->sip_to->a_display;
  *from->a_url = *sip->sip_to->a_url;

  sip_to_init(to)->a_display = sip->sip_from->a_display;
  *to->a_url = *sip->sip_from->a_url;

  nh = nh_create(nua,
		 NUTAG_URL((url_string_t *)url),
		 SIPTAG_TO(to), /* Local address */
		 SIPTAG_FROM(from), /* Remote address */
		 TAG_END());

  if (nua_stack_init_handle(nh->nh_nua, nh, kind, default_allow,
			    TAG_END()) < 0)
    nh_destroy(nua, nh), nh = NULL;

  if (nh && create_dialog) {
    struct nua_dialog_state *ds = nh->nh_ds;

    nua_dialog_store_peer_info(nh, ds, sip);

    ds->ds_leg = nta_leg_tcreate(nua->nua_nta, nua_stack_process_request, nh,
				 SIPTAG_CALL_ID(sip->sip_call_id),
				 SIPTAG_FROM(sip->sip_to),
				 SIPTAG_TO(sip->sip_from),
				 NTATAG_REMOTE_CSEQ(sip->sip_cseq->cs_seq),
				 TAG_END());

    if (!ds->ds_leg || !nta_leg_tag(ds->ds_leg, nta_incoming_tag(irq, NULL)))
      nh_destroy(nua, nh), nh = NULL;
  }

  if (nh)
    nua_dialog_uas_route(nh, nh->nh_ds, sip, 1);

  return nh;
}


/** Add authorization data */
int nh_authorize(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  int retval = 0;
  tagi_t const *ti;
  ta_list ta;

  ta_start(ta, tag, value);

  for (ti = ta_args(ta); ti; ti = tl_next(ti)) {
    if (ti->t_tag == nutag_auth && ti->t_value) {
      char *data = (char *)ti->t_value;
      int rv = auc_credentials(&nh->nh_auth, nh->nh_home, data);

      if (rv > 0) {
	retval = 1;
      }
      else if (rv < 0) {
	retval = -1;
	break;
      }
    }
  }

  ta_end(ta);

  return retval;
}

/** Collect challenges from response.
 *
 * @return Number of updated challenges, 0 if no updates found.
 * @retval -1 upon error.
 */
static
int nh_challenge(nua_handle_t *nh, sip_t const *sip)
{
  int server = 0, proxy = 0;

  if (sip->sip_www_authenticate)
    server = auc_challenge(&nh->nh_auth, nh->nh_home,
			   sip->sip_www_authenticate,
			   sip_authorization_class);

  if (sip->sip_proxy_authenticate)
    proxy = auc_challenge(&nh->nh_auth, nh->nh_home,
			  sip->sip_proxy_authenticate,
			  sip_proxy_authorization_class);

  if (server < 0 || proxy < 0)
    return -1;

  return server + proxy;
}

/** Create request message.
 *
 * @param nua
 * @param nh
 * @param method
 * @param name
 * @param tag @a value list of tag-value pairs
 */
msg_t *nua_creq_msg(nua_t *nua, nua_handle_t *nh,
		  struct nua_client_request *cr,
		  int restart,
		  sip_method_t method, char const *name,
		  tag_type_t tag, tag_value_t value, ...)
{
  struct nua_dialog_state *ds = nh->nh_ds;
  msg_t *msg;
  sip_t *sip;
  url_string_t const *url = NULL;
  long seq = -1;
  int copy = 1;

  /* If restarting, use existing message */
  if (restart) {
    msg = cr->cr_msg; sip = sip_object(msg);

    /* Trying to restart different method? */
    if (sip && method && sip->sip_request->rq_method != method) {
      SU_DEBUG_3(("nua(%p): trying to %s "
		  "but there is already %s waiting to restart\n",
		  nh, name, sip->sip_request->rq_method_name));
      restart = 0, msg = NULL; sip = NULL;
    }

    /* Remove CSeq */
    if (sip && sip->sip_cseq)
      sip_header_remove(msg, sip, (sip_header_t *)sip->sip_cseq);
    if (sip && sip->sip_request)
      method = sip->sip_request->rq_method,
	name = sip->sip_request->rq_method_name;
  }

  if (!restart) {
    if (cr->cr_msg) {
      /* If method is ACK or CANCEL, use existing CSeq */
      if (method == sip_method_ack || method == sip_method_cancel) {
	sip_t *nh_sip = sip_object(cr->cr_msg);
	if (nh_sip && nh_sip->sip_cseq)
	  seq = nh_sip->sip_cseq->cs_seq;
	copy = 0;
      }
      else
	msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
    }
    msg = nta_msg_create(nua->nua_nta, 0);
    tl_gets(nh->nh_tags, NUTAG_URL_REF(url), TAG_END());
    sip_add_tl(msg, sip_object(msg), TAG_NEXT(nh->nh_tags));
  }

  if (msg) {
    ta_list ta;
    int use_dialog = 0, add_contact = 0;

    sip = sip_object(msg);

    ta_start(ta, tag, value);

    tl_gets(ta_args(ta),
	    NUTAG_URL_REF(url),
	    NUTAG_USE_DIALOG_REF(use_dialog),
	    /* NUTAG_COPY_REF(copy), */
	    NUTAG_ADD_CONTACT_REF(add_contact),
	    TAG_END());

    if (method == sip_method_register && url == NULL) {
      tl_gets(ta_args(ta), NUTAG_REGISTRAR_REF(url), TAG_END());
      if (url == NULL)
	tl_gets(nh->nh_tags, NUTAG_REGISTRAR_REF(url), TAG_END());
      if (url == NULL)
	url = (url_string_t *)nua->nua_registrar;
    }

    if (seq != -1) {
      sip_cseq_t *cseq =
	sip_cseq_create(msg_home(msg), seq, method, name);
      sip_header_insert(msg, sip, (sip_header_t *)cseq);
    }

    if (ds->ds_leg) {
      /* If leg has established route, use it, not original URL */
      if (ds->ds_route)
	url = NULL;

      if (sip_add_tl(msg, sip, ta_tags(ta)) < 0 ||
	  nta_msg_request_complete(msg, ds->ds_leg, method, name, url) < 0)
	msg_destroy(msg), msg = NULL;
    }
    else {
      // tl_gets(ta_args(ta), TAG_END());

      if ((sip_add_tl(msg, sip,
		      TAG_IF(method != sip_method_register,
			     SIPTAG_ROUTE(nua->nua_service_route)),
		      ta_tags(ta)) < 0)
	  || (ds->ds_remote_tag &&
	      sip_to_tag(nh->nh_home, sip->sip_to, ds->ds_remote_tag) < 0)
	  || nta_msg_request_complete(msg, nua->nua_dhandle->nh_ds->ds_leg,
				      method, name, url) < 0
	  || (sip->sip_from == NULL &&
	      sip_add_dup(msg, sip, (sip_header_t *)nua->nua_from) < 0))
	msg_destroy(msg), msg = NULL;

      if (use_dialog && msg) {
	sip_route_t *route = sip->sip_route;

	if (method == sip_method_invite ||
	    method == sip_method_subscribe ||
	    method == sip_method_notify)
	  route = NULL;

	ds->ds_leg = nta_leg_tcreate(nua->nua_nta, nua_stack_process_request, nh,
				     SIPTAG_CALL_ID(sip->sip_call_id),
				     SIPTAG_FROM(sip->sip_from),
				     SIPTAG_TO(sip->sip_to),
				     SIPTAG_ROUTE(route),
				     SIPTAG_CSEQ(sip->sip_cseq),
				     TAG_END());
	if (!sip->sip_from->a_tag) {
	  nta_leg_tag(ds->ds_leg, NULL);
	  sip_from_tag(msg_home(msg),
		       sip->sip_from,
		       nta_leg_get_tag(ds->ds_leg));
	}
	/* XXX - check error */
      }
    }

    if (add_contact && msg && !sip->sip_contact) {
      /* We are missing contact */

      /* If application did not specify an empty contact, use ours */
      if (!tl_find(nh->nh_tags, siptag_contact) &&
	  !tl_find(nh->nh_tags, siptag_contact_str) &&
	  !tl_find(ta_args(ta), siptag_contact) &&
	  !tl_find(ta_args(ta), siptag_contact_str)) {
	sip_contact_t const *m;
	m = nua_contact_by_aor(nh->nh_nua, sip->sip_request->rq_url, 0);
	sip_add_dup(msg, sip, (void const *)m);
      }
    }

    if (!sip->sip_user_agent && NH_PGET(nh, user_agent))
      sip_add_dup(msg, sip, (sip_header_t *)NH_PGET(nh, user_agent));

    if (method != sip_method_ack) {
      if (!sip->sip_allow && !ds->ds_remote_tag)
	sip_add_dup(msg, sip, (sip_header_t*)NH_PGET(nh, allow));

      if (!sip->sip_supported && NH_PGET(nh, supported))
	sip_add_dup(msg, sip, (sip_header_t *)NH_PGET(nh, supported));

      if (method == sip_method_register && NH_PGET(nh, path_enable) &&
	  !sip_has_feature(sip->sip_supported, "path") &&
	  !sip_has_feature(sip->sip_require, "path"))
	sip_add_make(msg, sip, sip_supported_class, "path");

      if (!sip->sip_organization && NH_PGET(nh, organization))
	sip_add_dup(msg, sip, (sip_header_t *)NH_PGET(nh, organization));

      if (nh->nh_auth) {
	nh_authorize(nh, ta_tags(ta));

	if (method != sip_method_invite &&
	    method != sip_method_update &&
	    /* auc_authorize() removes existing authentication headers */
	    auc_authorize(&nh->nh_auth, msg, sip) < 0)
	  msg_destroy(msg), msg = NULL;
      }
    }
    else /* ACK */ {
      while (sip->sip_allow)
	sip_header_remove(msg, sip, (sip_header_t*)sip->sip_allow);
      while (sip->sip_priority)
	sip_header_remove(msg, sip, (sip_header_t*)sip->sip_priority);
      while (sip->sip_proxy_require)
	sip_header_remove(msg, sip, (sip_header_t*)sip->sip_proxy_require);
      while (sip->sip_require)
	sip_header_remove(msg, sip, (sip_header_t*)sip->sip_require);
      while (sip->sip_subject)
	sip_header_remove(msg, sip, (sip_header_t*)sip->sip_subject);
      while (sip->sip_supported)
	sip_header_remove(msg, sip, (sip_header_t*)sip->sip_supported);
    }

    ta_end(ta);

    if (!ds->ds_remote)
      ds->ds_remote = sip_to_dup(nh->nh_home, sip->sip_to);
    if (!ds->ds_local)
      ds->ds_local = sip_from_dup(nh->nh_home, sip->sip_from);

    if (copy) {
      cr->cr_msg = msg;
      msg = msg_copy(msg);
    }
  }

  return msg;
}

/** Create response message.
 *
 * @param nua
 * @param nh
 * @param irq
 * @param status
 * @param phrase
 * @param tag, @a value, ... list of tag-value pairs
 */
msg_t *nh_make_response(nua_t *nua, nua_handle_t *nh,
			nta_incoming_t *irq,
			int status, char const *phrase,
			tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  msg_t *msg = nta_msg_create(nua->nua_nta, 0);
  sip_t *sip = sip_object(msg);
  sip_contact_t const *m;
  int add_contact = 0;

  m = nua_contact_by_aor(nua, nta_incoming_url(irq), 0);

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta),
	  NUTAG_ADD_CONTACT_REF(add_contact),
	  TAG_END());

  if (!msg)
    return NULL;
  else if (nta_msg_response_complete(msg, irq, status, phrase) < 0)
    msg_destroy(msg);
  else if (sip_add_tl(msg, sip, ta_tags(ta)) < 0)
    msg_destroy(msg);
  else if (sip_complete_message(msg) < 0)
    msg_destroy(msg);
  else if (add_contact && !sip->sip_contact && 
	   sip_add_dup(msg, sip, (sip_header_t *)m) < 0)
    msg_destroy(msg);
  else if (!sip->sip_supported && NH_PGET(nh, supported) &&
	   sip_add_dup(msg, sip, (sip_header_t *)NH_PGET(nh, supported)) < 0)
    msg_destroy(msg);
  else if (!sip->sip_user_agent && NH_PGET(nh, user_agent) &&
	   sip_add_dup(msg, sip, (sip_header_t *)NH_PGET(nh, user_agent)) < 0)
    msg_destroy(msg);
  else if (!sip->sip_organization && NH_PGET(nh, organization) &&
	   sip_add_dup(msg, sip, (sip_header_t *)NH_PGET(nh, organization)) < 0)
    msg_destroy(msg);
  else if (!sip->sip_allow && NH_PGET(nh, allow) &&
	   sip_add_dup(msg, sip, (sip_header_t*)NH_PGET(nh, allow)) < 0)
    msg_destroy(msg);
  else
    return msg;

  return NULL;
}


/* ======================================================================== */
/* Generic processing */

int nua_stack_process_unknown(nua_t *nua,
			      nua_handle_t *nh,
			      nta_incoming_t *irq,
			      sip_t const *sip)
{
  return 501;
}

int
nua_stack_method(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		 tagi_t const *tags)
{
  return UA_EVENT1(e, SIP_501_NOT_IMPLEMENTED);
}

/**Relay response message to the application.
 *
 * If handle has already been marked as destroyed by nua_handle_destroy(),
 * release the handle with nh_destroy().
 */
int nua_stack_process_response(nua_handle_t *nh,
			       struct nua_client_request *cr,
			       nta_outgoing_t *orq,
			       sip_t const *sip,
			       tag_type_t tag, tag_value_t value, ...)
{
  msg_t *msg = nta_outgoing_getresponse(orq);
  int status = sip->sip_status->st_status;
  char const *phrase = sip->sip_status->st_phrase;
  ta_list ta;
  int final;

  if (status >= 200 && status < 300)
    nh_challenge(nh, sip);  /* Collect nextnonce */

  if (nta_outgoing_method(orq) == sip_method_invite)
    final = status >= 300;
  else
    final = status >= 200;

  if (final) {
    nua_creq_deinit(cr, orq);

    if (cr->cr_usage && nh->nh_cr == cr) {
      if ((status >= 300 && !cr->cr_usage->du_ready) ||
	  cr->cr_usage->du_terminating)
	nua_dialog_usage_remove(nh, nh->nh_ds, cr->cr_usage);
    }

    cr->cr_usage = NULL;
  }

  ta_start(ta, tag, value);

  nua_stack_event(nh->nh_nua, nh, msg, cr->cr_event, status, phrase,
	   ta_tags(ta));

  if (final)
    cr->cr_event = nua_i_error;

  ta_end(ta);

  return 0;
}

static inline
int can_redirect(sip_contact_t const *m, sip_method_t method)
{
  if (m && m->m_url->url_host) {
    enum url_type_e type = m->m_url->url_type;
    return
      type == url_sip ||
      type == url_sips ||
      (type == url_tel &&
       (method == sip_method_invite || method == sip_method_message)) ||
      (type == url_im && method == sip_method_message) ||
      (type == url_pres && method == sip_method_subscribe);
  }
  return 0;
}

int nua_creq_restart_with(nua_handle_t *nh,
			  struct nua_client_request *cr,
			  nta_outgoing_t *orq,
			  int status, char const *phrase,
			  nua_creq_restart_f *f,
			  TAG_LIST)
{
  ta_list ta;
  msg_t *msg = nta_outgoing_getresponse(orq);

  nua_stack_event(nh->nh_nua, nh, msg, cr->cr_event, status, phrase,
		  TAG_END());

  nta_outgoing_destroy(orq);

  if (f) {
    ta_start(ta, tag, value);
    f(nh, ta_args(ta));
    ta_end(ta);
  }

  return 1;
}

/** Check response, return true if we can restart the request.
 *
 */
int nua_creq_check_restart(nua_handle_t *nh,
			   struct nua_client_request *cr,
			   nta_outgoing_t *orq,
			   sip_t const *sip,
			   nua_creq_restart_f *f)
{
  int status = sip->sip_status->st_status;
  sip_method_t method = nta_outgoing_method(orq);
  int removed = 0;

  nua_dialog_usage_t *du = cr->cr_usage;

  assert(f);

  if (orq == cr->cr_orq)
    removed = 1, cr->cr_orq = NULL;

  cr->cr_restart = NULL;

  if (cr->cr_msg == NULL || status < 200)
    ;
  else if (++cr->cr_retry_count > NH_PGET(nh, retry_count))
    ;
  else if (status == 302) {
    if (can_redirect(sip->sip_contact, method)) {
      return
	nua_creq_restart_with(nh, cr, orq, 100, "Redirected",
			      f, NUTAG_URL(sip->sip_contact->m_url),
			      TAG_END());
    }
  }
  else if (status == 423) {
    sip_t *req = sip_object(cr->cr_msg);
    unsigned my_expires = 0;

    if (req->sip_expires)
      my_expires = req->sip_expires->ex_delta;

    if (sip->sip_min_expires &&
	sip->sip_min_expires->me_delta > my_expires) {
      sip_expires_t ex[1];
      sip_expires_init(ex);
      ex->ex_delta = sip->sip_min_expires->me_delta;

      return
	nua_creq_restart_with(nh, cr, orq,
			      100, "Re-Negotiating Subscription Expiration",
			      f, SIPTAG_EXPIRES(ex), TAG_END());
    }
  }
  else if (method != sip_method_ack && method != sip_method_cancel &&
	   ((status == 401 && sip->sip_www_authenticate) ||
	    (status == 407 && sip->sip_proxy_authenticate)) &&
	   nh_challenge(nh, sip) > 0) {
    sip_t *rsip;
    int done;

    rsip = sip_object(cr->cr_msg);

    /* XXX - check for instant restart */
    done = auc_authorization(&nh->nh_auth, cr->cr_msg, (msg_pub_t*)rsip,
			     rsip->sip_request->rq_method_name,
			     rsip->sip_request->rq_url,
			     rsip->sip_payload);

    if (done > 0) {
      return
	nua_creq_restart_with(nh, cr, orq,
			      100, "Request Authorized by Cache",
			      f, TAG_END());
    }
    else if (done == 0) {
      msg_t *msg = nta_outgoing_getresponse(orq);
      nua_stack_event(nh->nh_nua, nh, msg, cr->cr_event,
	       status, sip->sip_status->st_phrase, TAG_END());
      nta_outgoing_destroy(orq);

      if (du) {
	du->du_pending = NULL;
	du->du_refresh = 0;
      }

      /* Operation waits for application to call nua_authenticate() */

      cr->cr_restart = f;
      return 1;
    }
    else {
      SU_DEBUG_5(("nua(%p): auc_authorization failed\n", nh));
    }
  }
#if HAVE_SOFIA_SMIME
  else if (status == 493)     /* try detached signature */
    ;
#endif
  else if (status == 422 && method == sip_method_invite) {
    if (sip->sip_min_se && nh->nh_ss->ss_min_se < sip->sip_min_se->min_delta)
      nh->nh_ss->ss_min_se = sip->sip_min_se->min_delta;
    if (nh->nh_ss->ss_min_se > nh->nh_ss->ss_session_timer)
      nh->nh_ss->ss_session_timer = nh->nh_ss->ss_min_se;

    return
      nua_creq_restart_with(nh, cr, orq,
			    100, "Re-Negotiating Session Timer",
			    f, TAG_END());
  }

  /* This was final response that cannot be restarted. */
  if (removed)
    cr->cr_orq = orq;

  if (du) {
    du->du_pending = NULL;
    du->du_refresh = 0;
  }

  cr->cr_retry_count = 0;

  if (cr->cr_msg)
    msg_destroy(cr->cr_msg), cr->cr_msg = NULL;

  return 0;
}

/** Restart a request */
int nua_creq_restart(nua_handle_t *nh,
		     struct nua_client_request *cr,
		     nta_response_f *cb,
		     tagi_t *tags)
{
  msg_t *msg;

  cr->cr_restart = NULL;

  if (!cr->cr_msg)
    return 0;

  msg = nua_creq_msg(nh->nh_nua, nh, cr, 1, SIP_METHOD_UNKNOWN,
		     TAG_NEXT(tags));

  cr->cr_orq = nta_outgoing_mcreate(nh->nh_nua->nua_nta, cb, nh, NULL, msg,
				    SIPTAG_END(), TAG_NEXT(tags));

  if (!cr->cr_orq) {
    msg_destroy(msg);
    return 0;
  }

  return 1;
}

/* ======================================================================== */
/* Authentication */

void
nua_stack_authenticate(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		       tagi_t const *tags)
{
  int status = nh_authorize(nh, TAG_NEXT(tags));

  if (status > 0) {
    nua_creq_restart_f *restart = NULL;

    nua_stack_event(nua, nh, NULL, e, SIP_200_OK, TAG_END());

    if (nh->nh_cr->cr_restart) {
      restart = nh->nh_cr->cr_restart;
      nh->nh_cr->cr_restart = NULL;
    }
    else if (nh->nh_ss->ss_crequest->cr_restart) {
      restart = nh->nh_ss->ss_crequest->cr_restart;
      nh->nh_ss->ss_crequest->cr_restart = NULL;
    }

    if (restart)
      restart(nh, (tagi_t *)tags);	/* Restart operation */
  }
  else if (status < 0) {
    nua_stack_event(nua, nh, NULL, e, 500, "Cannot add credentials", TAG_END());
  }
  else {
    nua_stack_event(nua, nh, NULL, e, 404, "No matching challenge", TAG_END());
  }
}

/* ======================================================================== */
/*
 * Process incoming requests
 */

int nua_stack_process_request(nua_handle_t *nh,
			      nta_leg_t *leg,
			      nta_incoming_t *irq,
			      sip_t const *sip)
{
  nua_t *nua = nh->nh_nua;
  sip_method_t method = sip->sip_request->rq_method;
  sip_user_agent_t const *user_agent = NH_PGET(nh, user_agent);
  sip_supported_t const *supported = NH_PGET(nh, supported);
  sip_allow_t const *allow = NH_PGET(nh, allow);
  enter;

  nta_incoming_tag(irq, NULL);

  if (nta_check_method(irq, sip, allow,
		       SIPTAG_SUPPORTED(supported),
		       SIPTAG_USER_AGENT(user_agent),
		       TAG_END()))
    return 405;

  switch (sip->sip_request->rq_url->url_type) {
  case url_sip:
  case url_sips:
  case url_im:
  case url_pres:
  case url_tel:
    break;
  default:
    nta_incoming_treply(irq, SIP_416_UNSUPPORTED_URI,
			SIPTAG_ALLOW(allow),
			SIPTAG_SUPPORTED(supported),
			SIPTAG_USER_AGENT(user_agent),
			TAG_END());
  }

  if (nta_check_required(irq, sip, supported,
			 SIPTAG_ALLOW(allow),
			 SIPTAG_USER_AGENT(user_agent),
			 TAG_END()))
    return 420;

  if (nh == nua->nua_dhandle) {
    if (!sip->sip_to->a_tag)
      ;
    else if (method == sip_method_message && NH_PGET(nh, win_messenger_enable))
      ;
    else {
      nta_incoming_treply(irq, 481, "Initial transaction with a To tag",
			  TAG_END());
      return 481;
    }
    nh = NULL;
  }

  if (sip->sip_timestamp)
    nta_incoming_treply(irq, SIP_100_TRYING, TAG_END());

  switch (method) {
  case sip_method_invite:
    return nua_stack_process_invite(nua, nh, irq, sip);

  case sip_method_info:
    if (nh) return nua_stack_process_info(nua, nh, irq, sip);
    /*FALLTHROUGH*/

  case sip_method_update:
    if (nh) return nua_stack_process_update(nua, nh, irq, sip);
    /*FALLTHROUGH*/

  case sip_method_bye:
    if (nh) return nua_stack_process_bye(nua, nh, irq, sip);

    nta_incoming_treply(irq,
			481, "Call Does Not Exist",
			SIPTAG_ALLOW(allow),
			SIPTAG_SUPPORTED(supported),
			SIPTAG_USER_AGENT(user_agent),
			TAG_END());
    return 481;

  case sip_method_message:
    return nua_stack_process_message(nua, nh, irq, sip);

  case sip_method_notify:
    return nua_stack_process_notify(nua, nh, irq, sip);

  case sip_method_subscribe:
    return nua_stack_process_subsribe(nua, nh, irq, sip);

  case sip_method_options:
    return nua_stack_process_options(nua, nh, irq, sip);

  case sip_method_refer:
    return nua_stack_process_refer(nua, nh, irq, sip);

  case sip_method_publish:
    return nua_stack_process_publish(nua, nh, irq, sip);

  case sip_method_ack:
  case sip_method_cancel:
    SU_DEBUG_1(("nua(%p): strange %s from <" URL_PRINT_FORMAT ">\n", nh,
		sip->sip_request->rq_method_name,
		URL_PRINT_ARGS(sip->sip_from->a_url)));
    /* Send nua_i_error ? */
    return 481;

  default:
    return nua_stack_process_unknown(nua, nh, irq, sip);
  }
}

void
nua_stack_respond(nua_t *nua, nua_handle_t *nh,
	   int status, char const *phrase, tagi_t const *tags)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;

  if (sr->sr_respond) {
    sr->sr_respond(nua, nh, status, phrase, tags);
  }
#if 0
  else if (nta_incoming_status(nh->nh_irq) < 200) {
    int add_contact = 0;
    sip_contact_t *m;

    if (nta_incoming_url(nh->nh_irq)->url_type == url_sips &&
	nua->nua_sips_contact)
      m = nua->nua_sips_contact;
    else
      m = nua->nua_contact;

    SU_DEBUG_1(("nua: anonymous response %u %s\n", status, phrase));

    tl_gets(tags, NUTAG_ADD_CONTACT_REF(add_contact), TAG_END());
    nta_incoming_treply(nh->nh_irq, status, phrase,
			TAG_IF(add_contact, SIPTAG_CONTACT(m)),
			TAG_NEXT(tags));
    if (status >= 200)
      nta_incoming_destroy(nh->nh_irq), nh->nh_irq = NULL;
  }
#endif

  else if (ss->ss_srequest->sr_irq) {
    nua_stack_event(nua, nh, NULL, nua_i_error,
		    500, "Already Sent Final Response", TAG_END());
  }
  else {
    nua_stack_event(nua, nh, NULL, nua_i_error,
		    500, "Responding to a Non-Existing Request", TAG_END());
  }
}
