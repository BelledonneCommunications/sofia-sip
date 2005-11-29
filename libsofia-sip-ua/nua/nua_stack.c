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
 * @author Remeres Jacobs <Remeres.Jacobs@nokia.com>
 * @author Tat Chan <Tat.Chan@nokia.com>
 *
 * @date Created: Wed Feb 14 18:32:58 2001 ppessi
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <assert.h>

#include <su_tag_class.h>
#include <su_tag_class.h>
#include <su_tagarg.h>

#include <stdio.h>

#include <su_tag_io.h>

#define SU_LOG (nua_log)
#include <su_debug.h>

#define SU_ROOT_MAGIC_T   struct nua_s
#define SU_MSG_ARG_T      struct event_s

#include <su_wait.h>

#include <su_strlst.h>

#include "nua.h"
#include "nua_tag.h"

#define NTA_AGENT_MAGIC_T    struct nua_s
#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s
#define NTA_INCOMING_MAGIC_T struct nua_handle_s
#define NTA_RELIABLE_MAGIC_T struct nua_handle_s

#define NEA_SMAGIC_T         nua_handle_t
#define NEA_EMAGIC_T         nua_handle_t

#include <sip.h>
#include <sip_header.h>
#include <sip_status.h>
#include <sip_util.h>

#include <nta.h>
#include <nea.h>

#include <tport_tag.h>
#include <auth_client.h>

#if HAVE_SOFIA_SMIME 
#include "smimec.h"
#endif                  

#include <sl_utils.h>

#if HAVE_SIGCOMP
#include <sigcomp.h>
#include <nta_tport.h>
#endif

#include "soa.h"

#include "nua_stack.h"

#ifndef SDP_MIME_TYPE
static char const nua_application_sdp[] = "application/sdp";
#define SDP_MIME_TYPE (nua_application_sdp)
#endif

#ifndef SDP_H
typedef struct sdp_session_s sdp_session_t;
#endif

typedef unsigned longlong ull;

#define SET_STATUS(_status, _phrase) status = _status, phrase = _phrase

/* This is interesting macro: 
 * x expands to "num, str", num is assigned to status, str to phrase.
 * Macro expands to two comma-separated expressions 
 * usable as function arguments
 */
#define SET_STATUS1(x) ((status = x), status), (phrase = ((void)x))

/* ========================================================================
 *
 *                       Protocol stack side
 *
 * ======================================================================== */

nua_handle_t *nh_create(nua_t *nua, tag_type_t t, tag_value_t v, ...);
static void nh_append(nua_t *nua, nua_handle_t *nh);
static void nh_remove(nua_t *nua, nua_handle_t *nh);
static void nh_destroy(nua_t *nua, nua_handle_t *nh);

static int nh_authorize(nua_handle_t *nh, 
			tag_type_t tag, tag_value_t value, ...);

static int nh_challenge(nua_handle_t *nh, sip_t const *sip);

static void dialog_uac_route(nua_handle_t *nh, sip_t const *sip, int rtag);
static void dialog_uas_route(nua_handle_t *nh, sip_t const *sip, int rtag);
static void dialog_get_peer_info(nua_handle_t *nh, sip_t const *sip);

static
int nh_notifier_shutdown(nua_handle_t *nh, nea_event_t *ev,
			 tag_type_t t, tag_value_t v, ...);

static void ua_timer(nua_t *nua, su_timer_t *t, su_timer_arg_t *a);

static void ua_set_from(nua_t *nua, sip_from_t const *f, char const *fromstr);

static void ua_init_contact(nua_t *nua);

static int process_request(nua_handle_t *nh,
			   nta_leg_t *leg,
			   nta_incoming_t *irq,
			   sip_t const *sip);

static int process_response(nua_handle_t *nh,
			    struct nua_client_request *cr,
			    nta_outgoing_t *orq,
			    sip_t const *sip,
			    tag_type_t tag, tag_value_t value, ...);

static void signal_call_state_change(nua_handle_t *nh, 
				     int status, char const *phrase, 
				     enum nua_callstate tr_event,
				     char const *sdp_recv, 
				     char const *sdp_sent);

#define SIP_METHOD_UNKNOWN sip_method_unknown, NULL

#define UA_INTERVAL 5

/* Private tags */
#define NUTAG_ADD_CONTACT(v) _nutag_add_contact, tag_bool_v(v)
extern tag_typedef_t _nutag_add_contact;

#define NUTAG_ADD_CONTACT_REF(v) _nutag_add_contact_ref, tag_bool_vr(&v)
extern tag_typedef_t _nutag_add_contact_ref;

#define NUTAG_COPY(v) _nutag_copy, tag_bool_v(v)
extern tag_typedef_t _nutag_copy;

#define NUTAG_COPY_REF(v) _nutag_copy_ref, tag_bool_vr(&v)
extern tag_typedef_t _nutag_copy_ref;

/** Methods allowed by default. */ 
static char const nua_allow_str[] =
"INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, "
"MESSAGE, SUBSCRIBE, NOTIFY, REFER, UPDATE";

/** Default internal error */
char const nua_500_error[] = "Internal NUA Error";

/* ----------------------------------------------------------------------
 * Initialization & deinitialization
 */

int ua_init(su_root_t *root, nua_t *nua)
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

  nua->nua_root = root;
  nua->nua_handles_tail = &nua->nua_handles;
  nh_append(nua, dnh);  
  
#if SU_HAVE_PTHREADS
  pthread_rwlock_init(dnh->nh_refcount, NULL);
#endif
  dnh->nh_valid = nua_handle;
  dnh->nh_nua = nua;
  dnh->nh_ds->ds_local = sip_from_init(nua->nua_from);
  dnh->nh_ds->ds_remote = nua->nua_from;

  nh_incref(dnh); dnh->nh_ref_by_stack = 1;
  nh_incref(dnh); dnh->nh_ref_by_user = 1;

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
    
  nua->nua_media_enable = media_enable;

  nta_agent_set_params(nua->nua_nta,
		       NTATAG_UA(1),
		       NTATAG_MERGE_482(1),
		       NTATAG_RPORT(1),	/* XXX */
#if HAVE_SOFIA_SMIME
		       NTATAG_SMIME(nua->sm),
#endif
		       TAG_NEXT(nua->nua_args));

  nua->nua_sdp_content = sip_content_type_make(home, SDP_MIME_TYPE);
  nua->nua_invite_accept = sip_accept_make(home, SDP_MIME_TYPE);

  if (media_enable) {
    if (soa == NULL)
      soa = soa_create(soa_name, nua->nua_root, nua->nua_dhandle);
    dnh->nh_soa = soa;
    soa_set_params(soa, TAG_NEXT(nua->nua_args));
  }

  dnh->nh_ds->ds_leg = nta_leg_tcreate(nua->nua_nta, process_request, dnh,
				      NTATAG_NO_DIALOG(1), 
				      TAG_END());

  ua_init_contact(nua);
  ua_set_from(nua, from, from_str);

  nua->nua_timer = su_timer_create(su_root_task(root), UA_INTERVAL * 1000);

  if (!(dnh->nh_ds->ds_leg &&
	dnhp->nhp_allow && 
	dnhp->nhp_supported &&
	(nua->nua_contact || nua->nua_sips_contact) &&
	nua->nua_from &&
	nua->nua_sdp_content &&
	nua->nua_timer))
    return -1;

  ua_timer(nua, nua->nua_timer, NULL);

  nua->nua_args = NULL;

  return 0;
}

void ua_deinit(su_root_t *root, nua_t *nua)
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
    sip_contact_t *m;
    m = nua->nua_contact ? nua->nua_contact : nua->nua_sips_contact;
    from->a_display = m->m_display;
    *from->a_url = *m->m_url;
    f0 = sip_from_dup(nua->nua_home, from);
  }

  if (f0)
    *nua->nua_from = *f0;
}


static 
void ua_init_a_contact(nua_t *nua, su_home_t *home, sip_contact_t *m);

/** Initialize our contacts. */
void ua_init_contact(nua_t *nua)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  sip_via_t *v;
  int sip = 0, sips = 0;
  sip_contact_t *m;

  for (v = nta_agent_via(nua->nua_nta); v; v = v->v_next) {
    if (strcasecmp(v->v_protocol, sip_transport_tls) != 0) {
      if (!sip) {
	m = sip_contact_create_from_via(home, v, NULL);
	if (m) {
	  ua_init_a_contact(nua, home, m);
	  sip = 1;
	}
      }
    } 
    else if (!sips) {
      m = sip_contact_create_from_via(home, v, NULL);
      if (m) {
	ua_init_a_contact(nua, home, m);
	sips = 1;
      }
    }

    if (sip && sips)
      break;
  }

  su_home_deinit(home);
}

static 
void ua_init_a_contact(nua_t *nua, su_home_t *home, sip_contact_t *m)
{
  char const ***m_params = (msg_param_t **)&m->m_params;
  su_strlst_t *l = su_strlst_create(home);
  nua_handle_t *dnh = nua->nua_dhandle;
  int i;

  if (DNH_PGET(dnh, callee_caps)) {
    sip_allow_t const *allow = DNH_PGET(dnh, allow);

    if (allow) {
      char *methods;
      if (allow->k_items)
	for (i = 0; allow->k_items[i]; i++)
	  su_strlst_append(l, allow->k_items[i]);
      methods = su_strlst_join(l, home, ",");
      methods = su_sprintf(home, "methods=\"%s\"", methods);
      msg_params_replace(home, m_params, methods);
    }

    if (dnh->nh_soa) {
      char **media = soa_media_features(dnh->nh_soa, 0, home);

      while (*media) {
	msg_params_replace(home, m_params, *media);
	media++;
      }
    }
  }

  m = sip_contact_dup(nua->nua_home, m);

  if (m) {
    if (m->m_url->url_type == url_sip)
      su_free(nua->nua_home, nua->nua_contact), 
	nua->nua_contact = m;
    else
      su_free(nua->nua_home, nua->nua_sips_contact), 
	nua->nua_sips_contact = m;
  }

}


/* ----------------------------------------------------------------------
 * Sending events to client application
 */

static void ua_shutdown(nua_t *);

static int
  ua_set_params(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_get_params(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_register(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_invite(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_ack(nua_t *, nua_handle_t *, tagi_t const *),
  ua_cancel(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_bye(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_options(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_publish(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_info(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_update(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_message(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_subscribe(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_notify(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_refer(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_method(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *);

static void
  ua_authenticate(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_authorize(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_notifier(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_terminate(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_respond(nua_t *, nua_handle_t *, int , char const *, tagi_t const *),
  ua_destroy(nua_t *, nua_handle_t *, tagi_t const *);

#define UA_EVENT1(e, statusphrase) \
  ua_event(nua, nh, NULL, e, statusphrase, TAG_END())

#define UA_EVENT2(e, status, phrase)			\
  ua_event(nua, nh, NULL, e, status, phrase, TAG_END())

#define UA_EVENT3(e, status, phrase, tag)			\
  ua_event(nua, nh, NULL, e, status, phrase, tag, TAG_END())

/** Send an event to the application. */
int ua_event(nua_t *nua, nua_handle_t *nh, msg_t *msg,
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
    e->e_nh = nh ? nh_incref(nh) : nua->nua_dhandle;
    e->e_status = status;
    e->e_phrase = strcpy(end, phrase ? phrase : "");
    e->e_msg = msg;

    if (su_msg_send(sumsg) != 0)
      nh_decref(nh);
  }

  ta_end(ta);

  return event;
}

/* ----------------------------------------------------------------------
 * Post signal to stack client
 */
static
void stack_signal(nua_handle_t *nh, nua_event_t event, 
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
void ua_signal(nua_t *nua, su_msg_r msg, event_t *e)
{
  nua_handle_t *nh = e->e_nh;
  tagi_t *tags = e->e_tags;

  if (nh) {
    if (!nh->nh_prev)
      nh_append(nua, nh);
    if (!nh->nh_ref_by_stack) {
      nh->nh_ref_by_stack = 1;
      nh_incref(nh);
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

  if (nua->nua_shutdown && !e->e_always) {
    /* Shutting down */
    ua_event(nua, nh, NULL, e->e_event, 500, "Stack is going down", TAG_END());
  }
  else switch (e->e_event) {
  case nua_r_get_params:
    ua_get_params(nua, nh ? nh : nua->nua_dhandle, e->e_event, tags);
    break;
  case nua_r_set_params:
    ua_set_params(nua, nh ? nh : nua->nua_dhandle, e->e_event, tags);
    break;
  case nua_r_shutdown:
    ua_shutdown(nua);
    break;
  case nua_r_register:
  case nua_r_unregister:
    ua_register(nua, nh, e->e_event, tags);
    break;
  case nua_r_invite:
    ua_invite(nua, nh, e->e_event, tags);
    break;
  case nua_r_cancel:
    ua_cancel(nua, nh, e->e_event, tags);
    break;
  case nua_r_bye:
    ua_bye(nua, nh, e->e_event, tags);
    break;
  case nua_r_options:
    ua_options(nua, nh, e->e_event, tags);
    break;
  case nua_r_refer:
    ua_refer(nua, nh, e->e_event, tags);
    break;
  case nua_r_publish:
  case nua_r_unpublish:
    ua_publish(nua, nh, e->e_event, tags);
    break;
  case nua_r_info:
    ua_info(nua, nh, e->e_event, tags);
    break;
  case nua_r_update:
    ua_update(nua, nh, e->e_event, tags);
    break;
  case nua_r_message:
    ua_message(nua, nh, e->e_event, tags);
    break;
  case nua_r_subscribe:
  case nua_r_unsubscribe:
    ua_subscribe(nua, nh, e->e_event, tags);
    break;
  case nua_r_notify:
    ua_notify(nua, nh, e->e_event, tags);
    break;
  case nua_r_notifier:
    ua_notifier(nua, nh, e->e_event, tags);
    break;
  case nua_r_terminate:
    ua_terminate(nua, nh, e->e_event, tags);
    break;
  case nua_r_method:
    ua_method(nua, nh, e->e_event, tags);
    break;
  case nua_r_authenticate:
    ua_authenticate(nua, nh, e->e_event, tags);
    break;
  case nua_r_authorize:
    ua_authorize(nua, nh, e->e_event, tags);
    break;
  case nua_r_ack:
    ua_ack(nua, nh, tags);
    break;
  case nua_r_respond:
    ua_respond(nua, nh, e->e_status, e->e_phrase, tags);
    break;
  case nua_r_destroy:
    ua_destroy(nua, nh, tags);
    break;
  default:
    break;
  }

  if (nh != nua->nua_dhandle)
    nh_decref(nh);
}

/* ====================================================================== */

static int nh_call_pending(nua_handle_t *nh, sip_time_t time);

/** Timer routine.
 *
 * Go through all handles and execute pending tasks
 */
void ua_timer(nua_t *nua, su_timer_t *t, su_timer_arg_t *a)
{
  nua_handle_t *nh, *nh_next;
  sip_time_t now = sip_now();

  su_timer_set(t, ua_timer, a);

  if (nua->nua_shutdown) {
    ua_shutdown(nua);
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
  sip_time_t next = now + UA_INTERVAL;

  for (du = nh->nh_ds->ds_usage; du; du = du->du_next) {
    if (!du->du_pending)
      continue;
    if (now == 0 || (du->du_refresh && du->du_refresh < next))
      break;
  }

  if (du == NULL)
    return 0;

  nh_incref(nh);

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

  nh_decref(nh);

  return 1;
}


/** Set refresh value suitably */
static 
void dialog_usage_set_refresh(nua_dialog_usage_t *du, unsigned delta)
{
  sip_time_t target = sip_now();

  if (delta > 60 && delta < 5 * 60)
    /* refresh 30 seconds before deadline */
    delta -= 30;
  else 
    /* refresh at half time before deadline */
    delta /= 2;

  if (target + delta >= target)
    target = target + delta;
  else
    target = SIP_TIME_MAX;

  du->du_refresh = target;
}


/* ====================================================================== */

/** Shut down stack. */
void ua_shutdown(nua_t *nua)
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

  ua_event(nua, NULL, NULL, nua_r_shutdown, status, phrase, TAG_END());
}

/* ----------------------------------------------------------------------
 * Parameters
 */

#include <msg_parser.h>

int ua_set_params(nua_t *nua, nua_handle_t *nh, nua_event_t e, 
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

  ua_init_contact(nua);

#if HAVE_SOFIA_SMIME 
  /* XXX - all S/MIME other parameters? */
  sm_set_params(nua->sm, smime_enable, smime_opt, 
		smime_protection_mode, smime_path);
#endif                  
  return e == nua_r_set_params ? UA_EVENT2(e, 200, "OK") : 0;
}

/** Get NUA parameters.
 *
 * The ua_get_params() sends a list of parameters to the application.  It
 * gets invoked when application calls either nua_get_params() or
 * nua_get_hparams(). 
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
int
ua_get_params(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_handle_t *dnh = nua->nua_dhandle;
  nua_handle_preferences_t const *nhp = nh->nh_prefs;

  tagi_t *lst;

  int has_from;
  sip_from_t from[1];

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
     NTATAG_CONTACT(nua->nua_contact
		    ? nua->nua_contact : nua->nua_sips_contact),

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

  ua_event(nua, nh, NULL, nua_r_get_params, SIP_200_OK, TAG_NEXT(lst));

  su_home_deinit(tmphome);

  tl_vfree(media_params);

  return 0;
}

/* ---------------------------------------------------------------------- */

static void crequest_deinit(struct nua_client_request *cr, 
			    nta_outgoing_t *orq);

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

int nh_is_special(nua_handle_t *nh)
{
  return nh == NULL || nh->nh_special;
}

static inline
int nh_has_session(nua_handle_t const *nh)
{
  return nh != NULL && 
    nh->nh_ss->ss_state > nua_callstate_init &&
    nh->nh_ss->ss_state < nua_callstate_terminated;
}

static inline
nua_handle_t *nh_validate(nua_t *nua, nua_handle_t *maybe)
{
  nua_handle_t *nh;

  if (maybe)
    for (nh = nua->nua_handles; nh; nh = nh->nh_next)
      if (nh == maybe)
	return nh;

  return NULL;
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

static
void nh_destroy(nua_t *nua, nua_handle_t *nh)
{
  assert(nh); assert(nh != nua->nua_dhandle);

  nh_enter;

  if (nh->nh_notifier)
    nea_server_destroy(nh->nh_notifier), nh->nh_notifier = NULL;

  crequest_deinit(nh->nh_cr, NULL);
  if (nh->nh_ss)
    crequest_deinit(nh->nh_ss->ss_crequest, NULL);

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

  nh_decref(nh);
}

static
void crequest_deinit(struct nua_client_request *cr, nta_outgoing_t *orq)
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
static
int nh_init(nua_t *nua, nua_handle_t *nh, 
	    enum nh_kind kind,
	    char const *default_allow,
	    tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int retval = 0;

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

  if (ua_set_params(nua, nh, nua_i_error, ta_args(ta)) < 0)
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
static
nua_handle_t *nh_create_from_incoming(nua_t *nua, 
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

  if (nh && nh_init(nh->nh_nua, nh, kind, default_allow, TAG_END()) < 0)
    nh_destroy(nua, nh), nh = NULL;

  if (nh && create_dialog) {
    struct nua_dialog_state *ds = nh->nh_ds;

    dialog_get_peer_info(nh, sip);

    ds->ds_leg = nta_leg_tcreate(nua->nua_nta, process_request, nh,
				 SIPTAG_CALL_ID(sip->sip_call_id),
				 SIPTAG_FROM(sip->sip_to),
				 SIPTAG_TO(sip->sip_from),
				 NTATAG_REMOTE_CSEQ(sip->sip_cseq->cs_seq),
				 TAG_END());

    if (!ds->ds_leg || !nta_leg_tag(ds->ds_leg, nta_incoming_tag(irq, NULL)))
      nh_destroy(nua, nh), nh = NULL;
  }

  if (nh)
    dialog_uas_route(nh, sip, 1);

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

/** Collect challenges from response */
static
int nh_challenge(nua_handle_t *nh, sip_t const *sip)
{
  if (sip->sip_www_authenticate)
    auc_challenge(&nh->nh_auth, nh->nh_home, sip->sip_www_authenticate,
		  sip_authorization_class);

  if (sip->sip_proxy_authenticate)
    auc_challenge(&nh->nh_auth, nh->nh_home, sip->sip_proxy_authenticate,
		      sip_proxy_authorization_class);

  return 0;
}

/** Create request message.
 *
 * @param nua  
 * @param nh
 * @param method
 * @param name
 * @param tag @a value list of tag-value pairs
 */
static
msg_t *crequest_message(nua_t *nua, nua_handle_t *nh,
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

	ds->ds_leg = nta_leg_tcreate(nua->nua_nta, process_request, nh,
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
	if (sip->sip_request->rq_url->url_type == url_sips &&
	    nua->nua_sips_contact)
	  sip_add_dup(msg, sip, (sip_header_t *)nua->nua_sips_contact);
	else
	  sip_add_dup(msg, sip, (sip_header_t *)nua->nua_contact);
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
static
msg_t *nh_make_response(nua_t *nua, nua_handle_t *nh, 
			nta_incoming_t *irq,
			int status, char const *phrase,
			tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  msg_t *msg = nta_msg_create(nua->nua_nta, 0);
  sip_t *sip = sip_object(msg);
  sip_header_t *m;
  int add_contact = 0;

  if (nta_incoming_url(irq)->url_type == url_sips && nua->nua_sips_contact)
    m = (sip_header_t*)nua->nua_sips_contact;
  else
    m = (sip_header_t*)nua->nua_contact;

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
  else if (add_contact && !sip->sip_contact && sip_add_dup(msg, sip, m) < 0)
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

static char const application_sdp[] = "application/sdp";

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
		"Content-Type", application_sdp));
  else if (ct->c_type == NULL)
    SU_DEBUG_3(("nua: empty %s, assuming %s\n", 
		"Content-Type", application_sdp));
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
int session_include_description(nua_handle_t *nh,
				msg_t *msg, 
				sip_t *sip)
{
  su_home_t *home = msg_home(msg);

  char const *sdp;
  int len;

  sip_content_disposition_t *cd;
  sip_content_type_t *ct;
  sip_payload_t *pl;
  
  if (!nh->nh_soa)
    return 0;

  if (soa_get_local_sdp(nh->nh_soa, 0, &sdp, &len) < 0)
    return -1;
    
  pl = sip_payload_create(home, sdp, len);
  ct = sip_content_type_make(home, application_sdp);
  cd = sip_content_disposition_make(home, "session");

  if (pl == NULL || ct == NULL || cd == NULL ||
      sip_header_insert(msg, sip, (sip_header_t *)cd) < 0 ||
      sip_header_insert(msg, sip, (sip_header_t *)ct) < 0 ||
      sip_header_insert(msg, sip, (sip_header_t *)pl) < 0)
    return -1;

  return 0;
}

/** Generate SDP headers */ 
int session_make_description(nua_handle_t *nh,
			     su_home_t *home,
			     sip_content_disposition_t **return_cd,
			     sip_content_type_t **return_ct,
			     sip_payload_t **return_pl)
{
  char const *sdp;
  int len;

  if (!nh->nh_soa)
    return 0;

  if (soa_get_local_sdp(nh->nh_soa, 0, &sdp, &len) < 0)
    return -1;
    
  *return_pl = sip_payload_create(home, sdp, len);
  *return_ct = sip_content_type_make(home, application_sdp);
  *return_cd = sip_content_disposition_make(home, "session");

  return 0;
}



/**
 * Stores and processes SDP from incoming response. 
 * 
 * @retval 1 if there was SDP to process
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
	SU_DEBUG_5(("nua(%p): %s: error activating media after %u %s\n", 
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
   
  process_response(nh, cr, orq, sip, 
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
   
  return process_response(nh, cr, orq, sip, 
			  NH_REMOTE_MEDIA_TAGS(sdp != NULL, nh->nh_soa),
			  TAG_END());
}
#endif

/* ======================================================================== */
/* Dialog handling */

static void 
dialog_usage_remove_at(nua_handle_t*, nua_dialog_state_t*, 
		       nua_dialog_usage_t**),
  dialog_log_usage(nua_handle_t *, nua_dialog_state_t *);

static inline
int dialog_is_established(struct nua_dialog_state const *ds)
{
  return ds->ds_remote_tag != NULL;
}

/** Refer usage */
static sip_event_t const first_refer_usage[1] = 
  {{{ 0, 0, sip_event_class, 0, 0 }, 0, "refer" }};

/** UAS tag and route */
static
void dialog_uas_route(nua_handle_t *nh, sip_t const *sip, int rtag)
{
  struct nua_dialog_state *ds = nh->nh_ds;
  int established = dialog_is_established(ds);

  if (!established && sip->sip_from->a_tag)
    ds->ds_remote_tag = su_strdup(nh->nh_home, sip->sip_from->a_tag);

  if (ds->ds_leg == NULL)
    return;

  nta_leg_server_route(ds->ds_leg, sip->sip_record_route, sip->sip_contact);
  ds->ds_route = ds->ds_route || sip->sip_record_route || sip->sip_contact;

  if (rtag && !established && sip->sip_from->a_tag)
    nta_leg_rtag(ds->ds_leg, sip->sip_from->a_tag);
}

/** UAC tag and route.
 *
 * Update dialog tags and route on the UAC side.
 *
 * @param nh   NUA handle
 * @param sip  SIP message containing response used to update dialog
 * @param rtag if true, set remote tag within the leg
 */
static
void dialog_uac_route(nua_handle_t *nh, sip_t const *sip, int rtag)
{
  struct nua_dialog_state *ds = nh->nh_ds;
  int established = dialog_is_established(ds);

  if (!established && sip->sip_to->a_tag)
    ds->ds_remote_tag = su_strdup(nh->nh_home, sip->sip_to->a_tag);

  if (ds->ds_leg == NULL)
    return;

  nta_leg_client_route(ds->ds_leg, sip->sip_record_route, sip->sip_contact);
  ds->ds_route = ds->ds_route || sip->sip_record_route || sip->sip_contact;

  if (rtag && !established && sip->sip_to->a_tag)
    nta_leg_rtag(ds->ds_leg, sip->sip_to->a_tag);
}

/** Store information from remote endpoint. */
static void 
dialog_get_peer_info(nua_handle_t *nh, sip_t const *sip)
{
  nua_remote_t *nr = nh->nh_ds->ds_remote_ua, old[1];

  *old = *nr;

  if (sip->sip_allow) {
    nr->nr_allow = sip_allow_dup(nh->nh_home, sip->sip_allow);
    su_free(nh->nh_home, old->nr_allow);
  }

  if (sip->sip_accept) {
    nr->nr_accept = sip_accept_dup(nh->nh_home, sip->sip_accept);
    su_free(nh->nh_home, old->nr_accept);
  }

  if (sip->sip_require) {
    nr->nr_require = sip_require_dup(nh->nh_home, sip->sip_require);
    su_free(nh->nh_home, old->nr_require);
  }

  if (sip->sip_supported) {
    nr->nr_supported = sip_supported_dup(nh->nh_home, sip->sip_supported);
    su_free(nh->nh_home, old->nr_supported);
  }

  if (sip->sip_user_agent) {
    nr->nr_user_agent = sip_user_agent_dup(nh->nh_home, sip->sip_user_agent);
    su_free(nh->nh_home, old->nr_user_agent);
  }
}

/** Get dialog usage slot */
nua_dialog_usage_t **
dialog_usage_at(nua_dialog_state_t const *ds, 
		enum nua_dialog_usage_e kind,
		sip_event_t const *event)
{
  static nua_dialog_usage_t *none = NULL;

  if (ds) {
    nua_dialog_usage_t *du, * const * prev;
    sip_event_t const *o;

    for (prev = &ds->ds_usage; (du = *prev); prev = &du->du_next) {
      if (du->du_kind != kind)
	continue;

      if (event == NONE || 
	  /* Subscriber usage requires event */
	  (event == NULL && kind != nua_subscriber_usage))
	return (nua_dialog_usage_t **)prev;

      o = du->du_event;

      if (event == o)
	return (nua_dialog_usage_t **)prev;

      if (event == NULL || o == NULL)
	continue;
      if (strcmp(event->o_type, o->o_type))
	continue;
      if (event == first_refer_usage)
	return (nua_dialog_usage_t **)prev;
      if (str0casecmp(event->o_id, o->o_id))
	continue;

      return (nua_dialog_usage_t **)prev;
    }
  }

  return &none;
}

/** Get a dialog usage */ 
static
nua_dialog_usage_t *
dialog_usage_get(nua_dialog_state_t const *ds, 
		 enum nua_dialog_usage_e kind,
		 sip_event_t const *event)
{
  return *dialog_usage_at(ds, kind, event);
}

/** Get dialog usage name */
static
char const *
dialog_usage_name(nua_dialog_usage_t const *du)
{
  switch (du->du_kind) {
  case nua_session_usage:  
    return "session";

  case nua_notifier_usage:
    return "notifier";

  case nua_subscriber_usage:
    return "subscription";

  case nua_register_usage:
    return "register";

  case nua_publish_usage:
    return "publish";

  case nua_transaction_usage:
    return "transaction";

  default:
    return "unknown";
  }
} 

/** Add dialog usage */
static nua_dialog_usage_t *
dialog_usage_add(nua_handle_t *nh, 
		 struct nua_dialog_state *ds, 
		 enum nua_dialog_usage_e kind,
		 sip_event_t const *event)
{
  if (ds) {
    sip_event_t *o;
    nua_dialog_usage_t *du, **prev_du;

    prev_du = dialog_usage_at(ds, kind, event);
    du = *prev_du;
    if (du) {		/* Already exists */
      SU_DEBUG_5(("nua(%p): adding already existing %s usage%s%s\n",
		  nh, dialog_usage_name(du), 
		  event ? "  with event " : "", event ? event->o_type : ""));
      
      if (prev_du != &ds->ds_usage) {
	/* Move as a first usage in the list */
	*prev_du = du->du_next;
	du->du_next = ds->ds_usage;
	ds->ds_usage = du;
      }
      return du;
    }

    o = event ? sip_event_dup(nh->nh_home, event) : NULL;

    if (o != NULL || event == NULL)
      du = su_zalloc(nh->nh_home, sizeof *du);

    if (du) {
      du->du_kind = kind;
      if (o)
	du->du_event = o;

      switch (kind) {
      case nua_session_usage:  
	ds->ds_has_session = 1; 
	break;
      case nua_notifier_usage:
	ds->ds_has_events = 1;
	ds->ds_has_notifier = 1;
	break;
      case nua_subscriber_usage:
	ds->ds_has_events = 1;
	ds->ds_has_subscription = 1;
	break;
      case nua_register_usage:
	ds->ds_has_register = 1;
	break;
      case nua_publish_usage:
	ds->ds_has_publish = 1;
	break;
      case nua_transaction_usage:
      default:
	break;
      }

      du->du_next = ds->ds_usage;

      SU_DEBUG_5(("nua(%p): adding %s usage%s%s\n",
		  nh, dialog_usage_name(du), 
		  event ? " with event " : "", event ? event->o_type :""));

      nh_incref(nh);

      return ds->ds_usage = du;
    }

    su_free(nh->nh_home, o);
  }

  return NULL;
}

/** Remove dialog usage. */
void
dialog_usage_remove(nua_handle_t *nh, 
		    nua_dialog_state_t *ds,
		    nua_dialog_usage_t *du)
{
  nua_dialog_usage_t **at;

  assert(nh); assert(ds); assert(du);

  for (at = &ds->ds_usage; *at; at = &(*at)->du_next)
    if (du == *at)
      break;

  assert(*at);

  dialog_usage_remove_at(nh, ds, at);
}

/** Remove dialog usage.
 *
 * Zap dialog state (leg, tag and route) if no usages remain. 
*/
static void
dialog_usage_remove_at(nua_handle_t *nh, 
		       nua_dialog_state_t *ds,
		       nua_dialog_usage_t **at)
{
  if (*at) {
    nua_dialog_usage_t *du = *at;
    enum nua_dialog_usage_e kind = du->du_kind;
    sip_event_t const *o = NULL;

    *at = du->du_next;

    if (kind == nua_notifier_usage || kind == nua_subscriber_usage)
      o = du->du_event;

    SU_DEBUG_5(("nua(%p): removing %s usage%s%s\n",
		nh, dialog_usage_name(du), 
		o ? " with event " : "", o ? o->o_type :""));

    switch (kind) {
    case nua_session_usage:  
      ds->ds_has_session = 0;
      break;

    case nua_notifier_usage:
      su_free(nh->nh_home, (void *)du->du_event);
      ds->ds_has_notifier = NULL != *dialog_usage_at(ds, kind, NONE);
      ds->ds_has_events = ds->ds_has_notifier || ds->ds_has_subscription;
      break;

    case nua_subscriber_usage:
      su_free(nh->nh_home, (void *)du->du_event);
      ds->ds_has_subscription = NULL != *dialog_usage_at(ds, kind, NONE);
      ds->ds_has_events = ds->ds_has_subscription || ds->ds_has_notifier;
      msg_destroy(du->du_subscriber->de_msg);
      break;

    case nua_register_usage:
      ds->ds_has_register = 0;
#if HAVE_SIGCOMP
      if (du->du_register->ru_compartment)
	sigcomp_compartment_unref(du->du_register->ru_compartment);
      du->du_register->ru_compartment = NULL;
#endif      
      msg_destroy(du->du_register->ru_msg);
      break;

    case nua_publish_usage:
      ds->ds_has_publish = 0;
      su_free(nh->nh_home, du->du_publisher->pu_etag);
      msg_destroy(du->du_publisher->pu_msg);
      break;

    case nua_transaction_usage:
    default:
      break;
    }

    nh_decref(nh);

    su_free(nh->nh_home, du);
  }

  /* Zap dialog if there is no more usages */
  if (ds->ds_usage == NULL) {
    nta_leg_destroy(ds->ds_leg), ds->ds_leg = NULL;
    su_free(nh->nh_home, (void *)ds->ds_remote_tag), ds->ds_remote_tag = NULL;
    ds->ds_route = 0;
    ds->ds_has_events = 0;
    ds->ds_terminated = 0;
    return;
  }
  else if (!ds->ds_terminated) {
    dialog_log_usage(nh, ds);
  }
}

static void
dialog_log_usage(nua_handle_t *nh, nua_dialog_state_t *ds)
{
  nua_dialog_usage_t *du;
  int has_session = 0;

  for (du = ds->ds_usage; du; du = du->du_next) {
    if (du->du_kind == nua_session_usage)
      has_session = 1;
    else if (du->du_kind == nua_notifier_usage ||
	     du->du_kind == nua_subscriber_usage)
      ds->ds_has_events = 1;
  }

  if (nua_log->log_level >= 3) {
    char buffer[160];
    int l = 0, n, N = sizeof buffer, has_session = 0;
    
    buffer[0] = '\0';

    for (du = ds->ds_usage; du; du = du->du_next) {
      msg_header_t const *h;

      if (du->du_kind != nua_notifier_usage &&
	  du->du_kind != nua_subscriber_usage)
	continue;

      h = (msg_header_t const *)du->du_event;
      n = sip_event_e(buffer + l, N - l, h, 0);
      if (n == -1)
	break;
      l += n;
      if (du->du_next && l + 2 < sizeof(buffer)) {
	strcpy(buffer + l, ", ");
	l += 2;
      }
    }
    
    SU_DEBUG_3(("nua(%p): still has %s%s%s\n", nh,
		has_session ? "session and " : "", 
		ds->ds_has_events ? "events " : "",
		buffer));
  }
}

/** Dialog has been terminated. */
static
void
dialog_terminated(nua_handle_t *nh,
		  struct nua_dialog_state *ds,
		  int status,
		  char const *phrase)
{
  int call = 0;

  ds->ds_terminated = 1;

  while (ds->ds_usage) {
    if (ds->ds_usage->du_kind == nua_session_usage)
      call = 1;			/* Delay sending the event */
    else
      /* XXX */;
    dialog_usage_remove_at(nh, ds, &ds->ds_usage);
  }
}

char const *convert_soa_error_to_sip_reason(soa_session_t *soa)
{

  return "SIP;cause=500;text=\"Internal media error\"";
}

/* ======================================================================== */
/* Request validation */

/** Check that all features UAC requires are also in supported */
static inline
int uas_check_required(nta_incoming_t *irq,
		       sip_t const *sip,
		       sip_supported_t const *supported,
		       tag_type_t tag, tag_value_t value, ...)
{
  if (sip->sip_require) {
    su_home_t home[1] = { SU_HOME_INIT(home) };
    sip_unsupported_t *us;

    us = sip_has_unsupported(home, supported, sip->sip_require);

    if (us) {
      ta_list ta;
      ta_start(ta, tag, value);
      nta_incoming_treply(irq,
			  SIP_420_BAD_EXTENSION,
			  SIPTAG_UNSUPPORTED(us),
			  SIPTAG_SUPPORTED(supported),
			  ta_tags(ta));
      ta_end(ta);
      su_home_deinit(home);
      return 420;
    }
  }
  return 0;
}

#if 0
static inline
int uas_check_supported(nta_incoming_t *irq,
			sip_t const *sip,
			sip_require_t *require,
			tag_type_t tag, tag_value_t value, ...)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  sip_unsupported_t *us;

  us = sip_has_unsupported(home, sip->sip_supported, require);

  if (us) {
    ta_list ta;
    ta_start(ta, tag, value);
    nta_incoming_treply(irq,
			SIP_421_EXTENSION_REQUIRED,
			SIPTAG_REQUIRE(require),
			ta_tags(ta));
    ta_end(ta);
    su_home_deinit(home);
    return 421;
  }

  return 0;
}
#endif

static inline
int uas_check_method(nta_incoming_t *irq,
		     sip_t const *sip,
		     sip_allow_t const *allow,
		     tag_type_t tag, tag_value_t value, ...)
{
  /* Check extensions */
  char const *name = sip->sip_request->rq_method_name;
  sip_param_t const *allowed;
  int i = 0;
  ta_list ta;

  if (allow && (allowed = allow->k_items))
    for (i = 0; allowed[i]; i++)
      if (strcasecmp(name, allowed[i]) == 0)
	return 0;

  ta_start(ta, tag, value);
  nta_incoming_treply(irq,
		      SIP_405_METHOD_NOT_ALLOWED,
		      SIPTAG_ALLOW(allow),
		      ta_tags(ta));
  ta_end(ta);

  return 405;
}

/* Check that we understand content. */
static inline
int uas_check_content(nta_incoming_t *irq,
		      sip_t const *sip,
		      tag_type_t tag, tag_value_t value, ...)
{
  sip_content_type_t const *c = sip->sip_content_type;
  sip_content_disposition_t const *cd = sip->sip_content_disposition;
  char const *accept = NULL, *accept_encoding = NULL;
  ta_list ta;

  if (sip->sip_payload == NULL)
    return 0;

  if (cd) {
    if (strcasecmp(cd->cd_type, "session") == 0) {
      if (c && strcasecmp(c->c_type, application_sdp))
	accept = application_sdp;
    }
  }

  if (sip->sip_content_encoding) { 
    /* Missing Content-Encoding implies identity */
    if (str0casecmp(sip->sip_content_encoding->g_value, "identity")) {
      accept_encoding = "identity";
    }
  }
    
  if (!accept && !accept_encoding)
    return 0;

  ta_start(ta, tag, value);
  nta_incoming_treply(irq,
		      SIP_415_UNSUPPORTED_MEDIA,
		      SIPTAG_ACCEPT_STR(accept),
		      SIPTAG_ACCEPT_ENCODING_STR(accept_encoding),
		      ta_tags(ta));
  ta_end(ta);

  return 415;
}

  
/** Check that UAC accepts (application/sdp) */
static inline
int uas_check_accept(nta_incoming_t *irq,
		     sip_t const *sip,
		     sip_accept_t const *acceptable,
		     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  sip_accept_t const *ac, *ab;

  if (!acceptable)
    return 0;

  /* Missing Accept implies support for SDP */
  if (!sip->sip_accept) {
    for (ab = acceptable; ab; ab = ab->ac_next)
      if (strcasecmp(application_sdp, ab->ac_type) == 0)
	return 0;
  } 

  for (ac = sip->sip_accept; ac; ac = ac->ac_next) {
    if (sip_q_value(ac->ac_q) == 0 || !ac->ac_type)
      continue;

    for (ab = acceptable; ab; ab = ab->ac_next)
      if (strcasecmp(ac->ac_type, ab->ac_type) == 0)
	return 0;
  }

  ta_start(ta, tag, value);
  nta_incoming_treply(irq, 
		      SIP_406_NOT_ACCEPTABLE, 
		      SIPTAG_ACCEPT(acceptable),
		      ta_tags(ta));
  ta_end(ta);

  return 406;
}

/**Check Session-Expires header. 
 *
 * If the proposed session-expiration time is smaller than Min-SE or our
 * minimal session expiration time, respond with 422 containing our minimal
 * session expiration time in Min-SE header.
 */
static int 
uas_check_session_expires(nta_incoming_t *irq,
			  sip_t const *sip,
			  sip_time_t my_min_se,
			  tag_type_t tag, tag_value_t value, ...)
{
  if ((sip->sip_min_se &&
       sip->sip_session_expires->x_delta < sip->sip_min_se->min_delta)
      || sip->sip_session_expires->x_delta < my_min_se) {
    sip_min_se_t min_se[1];

    sip_min_se_init(min_se)->min_delta = my_min_se;

    nta_incoming_treply(irq, 
			SIP_422_SESSION_TIMER_TOO_SMALL, 
			SIPTAG_MIN_SE(min_se),
			TAG_END());
    return 422;
  }

  return 0;
}

/* ======================================================================== */
/* Generic processing */

int process_method(nua_t *nua,
		   nua_handle_t *nh,
		   nta_incoming_t *irq,
		   sip_t const *sip)
{
  return 501;
}

int
ua_method(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  return UA_EVENT1(e, SIP_501_NOT_IMPLEMENTED);
}

/**Relay response message to the application.
 * 
 * If handle has already been marked as destroyed by nua_handle_destroy(),
 * release the handle with nh_destroy().
 */
static int process_response(nua_handle_t *nh,
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
    crequest_deinit(cr, orq);

    if (cr->cr_usage && nh->nh_cr == cr) {
      if ((status >= 300 && !cr->cr_usage->du_ready) ||
	  cr->cr_usage->du_terminating)
	dialog_usage_remove(nh, nh->nh_ds, cr->cr_usage);
    }

    cr->cr_usage = NULL;
  }

  ta_start(ta, tag, value);
  
  ua_event(nh->nh_nua, nh, msg, cr->cr_event, status, phrase, 
	   ta_tags(ta));

  if (final)
    cr->cr_event = nua_i_error;

  ta_end(ta);

  return 0;
}

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

  if (ss->ss_state != nua_callstate_ready || next_state > nua_callstate_ready)
    SU_DEBUG_5(("nua(%p): call state changed: %s -> %s%s%s%s%s\n", 
		nh, nua_callstate_name(ss->ss_state),
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

  if (next_state > ss_state)
    ss_state = next_state;
  else if (next_state == nua_callstate_init && ss_state < nua_callstate_ready)
    ss_state = nua_callstate_init, next_state = nua_callstate_terminated;

  if (phrase == NULL)
    phrase = "Call state";

  ua_event(nh->nh_nua, nh, NULL, nua_i_state, 
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

  if (next_state == nua_callstate_ready &&
      ss->ss_state <= nua_callstate_ready) {
    ua_event(nh->nh_nua, nh, NULL, nua_i_active, status, "Call active", 
	     NH_ACTIVE_MEDIA_TAGS(1, nh->nh_soa),
	     /* NUTAG_SOA_SESSION(nh->nh_soa), */
	     TAG_END());
    ss->ss_active = 1;
  }
  else if (next_state == nua_callstate_terminated || 
	   ss_state == nua_callstate_init) {
    ua_event(nh->nh_nua, nh, NULL, nua_i_terminated, status, phrase, 
	     TAG_END());
    ss->ss_active = 0;
  }

  ss->ss_state = ss_state;
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

static int
crequest_invoke_restart(nua_handle_t *nh,
			struct nua_client_request *cr,
			nta_outgoing_t *orq,
			int status, char const *phrase,
			crequest_restart_f *f, 
			TAG_LIST)
{
  ta_list ta;

  msg_t *msg = nta_outgoing_getresponse(orq);
  ua_event(nh->nh_nua, nh, msg, cr->cr_event, status, phrase, TAG_END());
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
static
int crequest_check_restart(nua_handle_t *nh,
			   struct nua_client_request *cr,
			   nta_outgoing_t *orq,
			   sip_t const *sip,
			   crequest_restart_f *f)
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
	crequest_invoke_restart(nh, cr, orq, 100, "Redirected",
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
	crequest_invoke_restart(nh, cr, orq, 
				100, "Re-Negotiating Subscription Expiration",
				f, SIPTAG_EXPIRES(ex), TAG_END());
    }
  }
  else if (method != sip_method_ack && method != sip_method_cancel &&
	   ((status == 401 && sip->sip_www_authenticate) ||
	    (status == 407 && sip->sip_proxy_authenticate))) {
    sip_t *rsip;
    int done;

    nh_challenge(nh, sip);

    rsip = sip_object(cr->cr_msg);

    /* XXX - check for instant restart */
    done = auc_authorization(&nh->nh_auth, cr->cr_msg, (msg_pub_t*)rsip,
			     rsip->sip_request->rq_method_name,
			     rsip->sip_request->rq_url,
			     rsip->sip_payload);

    if (done > 0) {
      return
	crequest_invoke_restart(nh, cr, orq, 
				100, "Request Authorized by Cache",
				f, TAG_END());
    }
    else if (done == 0) {
      msg_t *msg = nta_outgoing_getresponse(orq);
      ua_event(nh->nh_nua, nh, msg, cr->cr_event, 
	       status, sip->sip_status->st_phrase, TAG_END());
      nta_outgoing_destroy(orq); 

      if (du) {
	du->du_pending = NULL;
	du->du_refresh = 0;
      }
      /* Wait for nua_authenticate() */

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
      crequest_invoke_restart(nh, cr, orq, 
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

static int 
crequest_restart(nua_handle_t *nh,
		 struct nua_client_request *cr,
		 nta_response_f *cb,
		 tagi_t *tags)
{
  msg_t *msg;

  cr->cr_restart = NULL;

  if (!cr->cr_msg)
    return 0;

  msg = crequest_message(nh->nh_nua, nh, cr, 1,
			 SIP_METHOD_UNKNOWN, 
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
/* REGISTER */

static void 
register_expires_contacts(msg_t *msg, sip_t *sip),
  refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t),
  restart_register(nua_handle_t *nh, tagi_t *tags);

static int process_response_to_register(nua_handle_t *nh,
					nta_outgoing_t *orq,
					sip_t const *sip);

int
ua_register(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_dialog_usage_t *du;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg = NULL;
  sip_t *sip;
  int registering = e == nua_r_register;

  if (nh->nh_special && nh->nh_special != nua_r_register)
    return UA_EVENT2(e, 500, "Invalid handle for REGISTER");
  if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  /* Initialize allow and auth */
  nh_init(nua, nh, nh_has_register, "", TAG_NEXT(tags));	  
  nh->nh_special = nua_r_register;

  du = dialog_usage_add(nh, nh->nh_ds, nua_register_usage, NULL);

  if (du) {
    if (du->du_register->ru_msg)
      cr->cr_msg = msg_ref_create(du->du_register->ru_msg);

    msg = crequest_message(nua, nh, cr, cr->cr_msg != NULL,
			   SIP_METHOD_REGISTER,
			   NUTAG_ADD_CONTACT(1),
			   TAG_IF(!registering, NUTAG_USE_DIALOG(1)),
			   TAG_NEXT(tags));
  }
  sip = sip_object(msg);

  /* Validate contacts and expires */
  if (registering) {
    du->du_terminating = 0;
  }
  else /*  if (e == nua_r_unregister) */ {
    /* Expire all of our contacts */
    du->du_terminating = 1;
    register_expires_contacts(msg, sip);
  }

  if (du && msg)
    cr->cr_orq = 
      nta_outgoing_mcreate(nua->nua_nta,
			   process_response_to_register, nh, NULL,
			   msg,
			   SIPTAG_END(), 
			   TAG_IF(!registering, NTATAG_SIGCOMP_CLOSE(1)),
			   TAG_IF(registering, NTATAG_COMP("sigcomp")),
			   TAG_NEXT(tags));

  if (!cr->cr_orq) {
    msg_destroy(msg);
    msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  cr->cr_usage = du;

  return cr->cr_event = e;
}

static void 
register_expires_contacts(msg_t *msg, sip_t *sip)
{
  sip_contact_t *m;

  for (m = sip ? sip->sip_contact : NULL; m; m = m->m_next) {
    if (m->m_url->url_type == url_any) {
      if (m != sip->sip_contact || m->m_next) {
	/* Remove all contacts */
        msg_header_remove_all(msg, (msg_pub_t *)sip, (msg_header_t *)sip->sip_contact);
	/* Keep only the "any" contact */
	sip_header_insert(msg, sip, (sip_header_t *)m);	
      }
      sip_add_tl(msg, sip, SIPTAG_EXPIRES_STR("0"), TAG_END());
      break;
    }
    msg_params_replace(NULL, (msg_param_t **)&m->m_params, "expires=0");
    msg_fragment_clear(m->m_common);
  }

  /* Remove payload */
  while (sip->sip_payload)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_payload);
  while (sip->sip_content_type)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_content_type);
}

static void
restart_register(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_register, tags);
}

static
int process_response_to_register(nua_handle_t *nh,
				 nta_outgoing_t *orq,
				 sip_t const *sip)
{
  nua_t *nua = nh->nh_nua;
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  int status = sip->sip_status->st_status;

  assert(du && du->du_kind == nua_register_usage);

  if (du && status >= 200 && status < 300) {
    sip_t *req = sip_object(cr->cr_msg);

    du->du_ready = 1;

    if (!du->du_terminating && req && req->sip_contact && sip->sip_contact) {
      sip_time_t now = sip_now(), delta, mindelta;
      sip_contact_t const *m, *m0;

      /** Search for lowest delta of SIP contacts in sip->sip_contact */
      mindelta = 24 * 3600;	/* XXX */

      for (m = sip->sip_contact; m; m = m->m_next) {
	if (m->m_url->url_type != url_sip)
	  continue;
	for (m0 = req->sip_contact; m0; m0 = m0->m_next)
	  if (url_cmp(m->m_url, m0->m_url) == 0) {
	    delta = sip_contact_expires(m, sip->sip_expires, sip->sip_date,
					3600, /* XXX */
					now);
	    if (delta < mindelta)
	      mindelta = delta;
	    break;
	  }
      }

      dialog_usage_set_refresh(du, mindelta);
      du->du_pending = refresh_register;

      /*  RFC 3608 Section 6.1 Procedures at the UA

   The UA performs a registration as usual.  The REGISTER response may
   contain a Service-Route header field.  If so, the UA MAY store the
   value of the Service-Route header field in an association with the
   address-of-record for which the REGISTER transaction had registered a
   contact.  If the UA supports multiple addresses-of-record, it may be
   able to store multiple service routes, one per address-of-record.  If
   the UA refreshes the registration, the stored value of the Service-
   Route is updated according to the Service-Route header field of the
   latest 200 class response.  If there is no Service-Route header field
   in the response, the UA clears any service route for that address-
   of-record previously stored by the UA.  If the re-registration
   request is refused or if an existing registration expires and the UA
   chooses not to re-register, the UA SHOULD discard any stored service
   route for that address-of-record.
      */

      su_free(nua->nua_home, nua->nua_service_route);
      nua->nua_service_route =
	sip_service_route_dup(nua->nua_home, sip->sip_service_route);

      if (du->du_register->ru_msg)
	msg_destroy(du->du_register->ru_msg);
      du->du_register->ru_msg = msg_ref_create(cr->cr_msg);

#if HAVE_SIGCOMP
      {
	struct sigcomp_compartment *cc;
	cc = nta_outgoing_compartment(orq);
	sigcomp_compartment_unref(du->du_register->ru_compartment);
	du->du_register->ru_compartment = cc;
      }
#endif
    }

    if (du->du_terminating) {
      if (nua->nua_service_route)
	su_free(nua->nua_home, nua->nua_service_route);
      nua->nua_service_route = NULL;
      /* process_response() takes care of removing the dialog usage */
    }
  }
  else if (status >= 300) {
    if (crequest_check_restart(nh, cr, orq, sip, restart_register))
      return 0;
  }

  return process_response(nh, cr, orq, sip, TAG_END());
}


void 
refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
  nua_event_t e;
  msg_t *msg;
  sip_t *sip;

  if (cr->cr_msg) {
    /* Delay of 5 .. 15 seconds */
    dialog_usage_set_refresh(du, 5 + (unsigned)random() % 11U);
    du->du_pending = refresh_register;
    return;
  }

  if (now > 0)
    e = nua_r_register;
  else
    e = nua_r_destroy, du->du_terminating = 1;

  cr->cr_msg = msg_ref_create(du->du_register->ru_msg);

  msg = crequest_message(nua, nh, cr, 1,
			 SIP_METHOD_REGISTER,
			 NUTAG_USE_DIALOG(1),
			 TAG_END());
  sip = sip_object(msg);

  if (sip) {
    if (now == 0)
      register_expires_contacts(msg, sip);
    
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_register, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(NULL));
  }

  if (!cr->cr_orq) {
    if (du->du_terminating)
      dialog_usage_remove(nh, nh->nh_ds, du);
    msg_destroy(msg);
    msg_destroy(cr->cr_msg);
    UA_EVENT2(e, NUA_500_ERROR, TAG_END());
    return;
  }

  cr->cr_usage = du;
  cr->cr_event = e;
}


/* ======================================================================== */
/* INVITE and call (session) processing */

static int ua_invite2(nua_t *, nua_handle_t *, nua_event_t e,
		      int restarted, tagi_t const *tags);
static int process_response_to_invite(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip);
static int ua_ack(nua_t *nua, nua_handle_t *nh, tagi_t const *tags);
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

static int  use_session_timer(nua_t *, nua_handle_t *, 
			      int uas, msg_t *msg, sip_t *);
static int  init_session_timer(nua_t *nua, nua_handle_t *nh, sip_t const *);
static void set_session_timer(nua_handle_t *nh);

static int nh_referral_check(nua_t *nua, nua_handle_t *nh, tagi_t const *tags);
static void nh_referral_respond(nua_handle_t *, 
				unsigned status, char const *phrase);


int 
ua_invite(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  struct nua_client_request *cr = ss->ss_crequest;
  char const *what;

  if (nh_is_special(nh))
    what = "Invalid handle for INVITE";
  else if (cr->cr_orq) {
    what = "INVITE request already in progress";
  }
  else if (nh_referral_check(nua, nh, tags) < 0) {
    what = "Invalid referral";
  }
  else if (nh_init(nua, nh, nh_has_invite, NULL, TAG_NEXT(tags)) < 0) {
    what = "Handle initialization failed";
  }
  else
    return ua_invite2(nua, nh, e, 0, tags);

  UA_EVENT2(e, 500, what);
  signal_call_state_change(nh, 500, what, nua_callstate_init, 0, 0);

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

  du = dialog_usage_add(nh, nh->nh_ds, nua_session_usage, NULL);
  what = nua_500_error;		/* Internal error */

  msg = du ? crequest_message(nua, nh, cr, restarted,
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
    unsigned invite_timeout = NH_PGET(nh, invite_timeout);
    if (invite_timeout == 0)
      invite_timeout = SIP_TIME_MAX;
    /* Cancel if we don't get response */
    dialog_usage_set_refresh(du, invite_timeout); 

    /* Add session timer headers */
    use_session_timer(nua, nh, 0, msg, sip);

    ss->ss_100rel = NH_PGET(nh, early_media);
    ss->ss_precondition = sip_has_feature(sip->sip_require, "precondition");

    if (ss->ss_precondition)
      ss->ss_update_needed = ss->ss_100rel = 1;

    if (offer_sent > 0 &&
	session_include_description(nh, msg, sip) < 0)
      sip = NULL;
     
    if (sip && nh->nh_soa &&
	NH_PGET(nh, media_features) && !dialog_is_established(nh->nh_ds) && 
	!sip->sip_accept_contact && !sip->sip_reject_contact) {
      sip_accept_contact_t ac[1];
      sip_accept_contact_init(ac);

      ac->cp_params = (msg_param_t *)
	soa_media_features(nh->nh_soa, 1, msg_home(msg));
      
      if (ac->cp_params) {
	msg_params_replace(msg_home(msg), (msg_param_t **)&ac->cp_params, 
			   "explicit");
	sip_add_dup(msg, sip, (sip_header_t *)ac);
      }
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
      signal_call_state_change(nh, 0, "INVITE sent",
			       nua_callstate_calling, 0,
			       offer_sent ? "offer" : 0);
      return cr->cr_event = e;
    }
  }

  msg_destroy(msg);
  if (du && !du->du_ready) 
    dialog_usage_remove(nh, nh->nh_ds, du);

  UA_EVENT2(e, 500, what);
  signal_call_state_change(nh, 500, what, nua_callstate_init, 0, 0);

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
      if (crequest_check_restart(nh, cr, orq, sip, restart_invite))
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
    dialog_uac_route(nh, sip, 1); 
    dialog_get_peer_info(nh, sip);

    init_session_timer(nua, nh, sip);

    set_session_timer(nh);

    /* signal_call_state_change */
    if (session_process_response(nh, cr, orq, sip, &received) >= 0) {
      ss->ss_ack_needed = received ? received : "";

      if (NH_PGET(nh, auto_ack) || 
	  /* Auto-ACK response to re-INVITE unless auto_ack is set to 0 */
	  (ss->ss_state == nua_callstate_ready && 
	   !NH_PISSET(nh, auto_ack)))
	ua_ack(nua, nh, NULL);
      else
	signal_call_state_change(nh, status, phrase, 
				 nua_callstate_completing, received, 0);
      nh_referral_respond(nh, SIP_200_OK);
      return 0;
    }

    status = 500, phrase = "Malformed Session in Response";

    ua_ack(nua, nh, NULL);
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
  process_response(nh, cr, orq, sip, TAG_END());

  if (terminated)
    signal_call_state_change(nh, status, phrase, 
			     nua_callstate_terminated, 0, 0);

  if (terminated < 0) {
    dialog_terminated(nh, nh->nh_ds, status, phrase);
  }
  else if (terminated > 0) {
    dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (gracefully) {
    char *reason = 
      su_sprintf(NULL, "SIP;cause=%u;text=\"%s\"", status, phrase);

    signal_call_state_change(nh, status, phrase, 
			     nua_callstate_terminating, 0, 0);

    stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason), TAG_END());

    su_free(NULL, reason);
  }

  return 0;
}

int ua_ack(nua_t *nua, nua_handle_t *nh, tagi_t const *tags)
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
    return UA_EVENT2(nua_i_error, 500, "No response to ACK");

  ss->ss_ack_needed = 0;

  if (!received[0])
    received = NULL;

  if (tags) {
    ua_set_params(nua, nh, nua_r_ack, tags);
  }

  msg = crequest_message(nua, nh, cr, 0, 
			 SIP_METHOD_ACK, 
			 /* NUTAG_COPY(0), */
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip && nh->nh_soa) {
    if (tags)
      soa_set_params(nh->nh_soa, TAG_NEXT(tags));

    if (cr->cr_offer_recv && !cr->cr_answer_sent) {
      if (soa_generate_answer(nh->nh_soa, NULL) < 0 ||
	  session_include_description(nh, msg, sip) < 0) {
	reason = soa_error_as_sip_reason(nh->nh_soa);
	/* XXX */
	status = 500, phrase = "Internal media error";
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
      status = 488, phrase = "Incomplete offer/answer";
      reason = "SIP;cause=488;text=\"Incomplete offer/answer\"p";
    }
  }

  if (sip)
    ack = nta_outgoing_mcreate(nua->nua_nta, NULL, NULL, NULL, msg, 
			       SIPTAG_END(), TAG_NEXT(tags));

  if (!ack) {
    if (!reason) {
      status = 500, phrase = "Internal Error";
      reason = "SIP;cause=500;text=\"Internal Error\"";
    }
    msg_destroy(msg);
  }

  crequest_deinit(cr, NULL);	/* Destroy INVITE transaction */
  nta_outgoing_destroy(ack);	/* Timer keeps this around for T2 */

  if (status < 300) {
    signal_call_state_change(nh, status, phrase, nua_callstate_ready, 
			     received, sent);
  }
  else {
    signal_call_state_change(nh, status, phrase, nua_callstate_terminating, 0, 0);
    stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason), TAG_END());
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
  int offer_sent_in_prack = 0, answer_sent_in_prack = 0;

  su_home_t home[1] = { SU_HOME_INIT(home) };

  if (cr_prack->cr_orq) {
    SU_DEBUG_3(("nua(%p): cannot send PRACK because %s is pending\n", nh, 
		nta_outgoing_method_name(cr_prack->cr_orq)));
    return 0;			/* We have to wait! */
  }

  if (!dialog_is_established(nh->nh_ds)) {
    /* Tag the INVITE request */
    dialog_uac_route(nh, sip, 1);
    dialog_get_peer_info(nh, sip);

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
	session_make_description(nh, home, &cd, &ct, &pl) < 0)
      /* XXX */;
    else {
      answer_sent_in_prack = 1, sent = "answer";
      soa_activate(nh->nh_soa, NULL);
    }
  }
  else if (ss->ss_precondition) {
    if (soa_generate_offer(nh->nh_soa, 0, NULL) < 0 ||
	session_make_description(nh, home, &cd, &ct, &pl) < 0)
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
    ua_event(nh->nh_nua, nh, NULL, nua_i_error, 
	     500, "Cannot PRACK",
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

  SU_DEBUG_1(("nua: process_response_to_prack:\n"));

#if 0
  if (crequest_check_restart(nh, cr, orq, sip, restart_prack))
    return 0;
#endif

  if (status < 200)
    return 0;
  
  crequest_deinit(cr, orq);

  if (status < 300 && session_process_response(nh, cr, orq, sip, &recv) < 0) {
    status = 500, phrase = "Malformed Session in Response";
    reason = "SIP;status=400;phrase=\"Malformed Session in Response\"";
  }

  signal_call_state_change(nh, status, phrase, 
			   nua_callstate_proceeding, recv, NULL);

  if (status < 300 && nh->nh_ss->ss_update_needed)
    ua_update(nh->nh_nua, nh, nua_r_update, NULL);

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

  signal_call_state_change(nh, 408, "Session Timeout",
			   nua_callstate_init, NULL, NULL);

  ua_cancel(nh->nh_nua, nh, nua_r_destroy, timeout_tags);
}

void 
refresh_invite(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  if (now > 0 && NH_PGET(nh, update_refresh))
    ua_update(nh->nh_nua, nh, nua_r_update, NULL);
  else if (now > 0)
    ua_invite(nh->nh_nua, nh, nua_r_invite, NULL);
  else {
    signal_call_state_change(nh, 408, "Session Timeout",
			     nua_callstate_terminating, NULL, NULL);
    stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason_timeout), TAG_END());
  }
}

static void 
session_timeout(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  if (now > 1) {
    signal_call_state_change(nh, 408, "Session Timeout",
			     nua_callstate_terminating, NULL, NULL);
    stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason_timeout), TAG_END());
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
ua_cancel(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
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
      return ua_event(nua, nh, NULL, e, 400, "Internal error", TAG_END());

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
  return process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

static void respond_to_invite(nua_t *nua, nua_handle_t *nh,
			      int status, char const *phrase, 
			      tagi_t const *tags);

static int 
  process_invite1(nua_t *, nua_handle_t**, nta_incoming_t *, msg_t *, sip_t *),
  process_invite2(nua_t *, nua_handle_t *, nta_incoming_t *, sip_t *),
  process_ack_or_cancel(nua_handle_t *, nta_incoming_t *, sip_t const *),
  process_ack(nua_handle_t *, nta_incoming_t *, sip_t const *),
  process_prack(nua_handle_t *nh, nta_reliable_t *rel, 
		nta_incoming_t *irq, sip_t const *sip),
  process_cancel(nua_handle_t *, nta_incoming_t *, sip_t const *),
  process_timeout(nua_handle_t *, nta_incoming_t *);
  
/** Process incoming INVITE. */
int process_invite(nua_t *nua,
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

/** Preprocess incoming invite - sure we have a valid request. */
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
    if (uas_check_content(irq, sip, 
			  SIPTAG_USER_AGENT(user_agent),
			  TAG_END()))
      return 415;

    /* Make sure caller accepts application/sdp */
    if (uas_check_accept(irq, sip, 
			 nua->nua_invite_accept,
			 SIPTAG_USER_AGENT(user_agent),
			 TAG_END()))
      return 406;
  }

  if (sip->sip_session_expires) {
    unsigned min_se = nh ? nh->nh_ss->ss_min_se : DNH_PGET(dnh, min_se);
    if (uas_check_session_expires(irq, sip, 
				  min_se,
				  SIPTAG_USER_AGENT(user_agent),
				  TAG_END()))
      return 500;
  }

  if (!nh) {
    if (!DNH_PGET(dnh, invite_enable))
      return 403;

    if (!(nh = nh_create_from_incoming(nua, irq, sip, nh_has_invite, 1)))
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
      dialog_usage_add(nh, nh->nh_ds, nua_session_usage, NULL);
  if (!nh->nh_ss->ss_usage) {
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    return 500;
  }

  sr->sr_msg = msg;
  sr->sr_irq = irq;
  
  return 0;
}

/** Process incoming invite - initiate media, etc. */
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
  init_session_timer(nua, nh, sip);

  dialog_uas_route(nh, sip, 1);	/* Set route and tags */

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

    ua_event(nh->nh_nua, nh, sr->sr_msg,
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

/** Respond to an INVITE request.
 *
 * XXX - use tags to indicate when to use reliable responses.
 * XXX - change prototype.
 */
void respond_to_invite(nua_t *nua, nua_handle_t *nh,
		       int status, char const *phrase, 
		       tagi_t const *tags)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  msg_t *msg;
  sip_t *sip;
  int reliable;
  int original_status = status;
  nua_dialog_state_t *ds = nh->nh_ds;
  nua_session_state_t *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;

  int autoanswer = 0, offer = 0, answer = 0;

  enter; 

  if (ss->ss_srequest->sr_irq == NULL ||
      nta_incoming_status(ss->ss_srequest->sr_irq) >= 200) {
    ua_event(nh->nh_nua, nh, NULL,
	     nua_i_error, 500, "No INVITE request to response", TAG_END());
    return;
  }

  if (tags == AUTOANSWER)
    autoanswer = 1, tags = NULL;

  assert(ss->ss_usage);

  if (nh->nh_soa)
    soa_set_params(nh->nh_soa, TAG_NEXT(tags));

  reliable = 
    (status >= 200)
    || (status == 183 &&
	ds->ds_remote_ua->nr_supported && 
	sip_has_feature(ds->ds_remote_ua->nr_supported, "100rel"))
    || (status > 100 &&
	ds->ds_remote_ua->nr_require &&
	(sip_has_feature(ds->ds_remote_ua->nr_require, "100rel") ||
	 sip_has_feature(ds->ds_remote_ua->nr_require, "precondition")));

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
      if (soa_generate_answer(nh->nh_soa, NULL) < 0)
	status = soa_error_as_sip_response(nh->nh_soa, &phrase);
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
      if (session_include_description(nh, msg, sip) < 0)
	status = 500, phrase = sip_500_Internal_server_error;
    }
  }

  if (ss->ss_refresher && 200 <= status && status < 300)
    use_session_timer(nua, nh, 1, msg, sip);

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
    rel = nta_reliable_mreply(ss->ss_srequest->sr_irq, process_prack, nh, msg);
    if (!rel)
      status = 500, phrase = sip_500_Internal_server_error;
  }

  if (reliable && status < 200)
    /* we are done */;
  else if (status != original_status) {    /* Error responding */
    nta_incoming_treply(ss->ss_srequest->sr_irq, 
			status, phrase,
			TAG_END());
    msg_destroy(msg), msg = NULL;
  }
  else {
    nta_incoming_mreply(ss->ss_srequest->sr_irq, msg);
  }

  if (autoanswer) {
    ua_event(nh->nh_nua, nh, sr->sr_msg,
	     nua_i_invite, status, phrase,
	     NH_ACTIVE_MEDIA_TAGS(1, nh->nh_soa),
	     TAG_END());
    sr->sr_msg = NULL;
  }
  else if (status != original_status)
    ua_event(nua, nh, NULL, nua_i_error, status, phrase, TAG_END());

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
    ss->ss_srequest->sr_respond = NULL;
  }

  if (status >= 300) {
    if (nh->nh_soa)
      soa_init_offer_answer(nh->nh_soa);
    nta_incoming_destroy(ss->ss_srequest->sr_irq);
    ss->ss_srequest->sr_irq = NULL;
  }

  su_home_deinit(home);

  if (ss->ss_state == nua_callstate_init)
    nsession_destroy(nh);
}


/** Process ACK or CANCEL or timeout (no ACK) for incoming INVITE */
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

  if (sip == NULL) {    /* Timeout */
    SET_STATUS(504, "Reliable Response Timeout");

    respond_to_invite(nh->nh_nua, nh, status, phrase, NULL);

    ua_event(nh->nh_nua, nh, NULL,
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
	  session_make_description(nh, home, &cd, &ct, &pl);
	  sent = "answer";
	}
      }

      if (nta_incoming_treply(irq, status, phrase,
			      SIPTAG_CONTENT_DISPOSITION(cd),
			      SIPTAG_CONTENT_TYPE(ct),
			      SIPTAG_PAYLOAD(pl),
			      TAG_END()) < 0)
	/* Respond with 500 if nta_incoming_treply() failed */ 
	status = 500, phrase = sip_500_Internal_server_error;

      su_home_deinit(home);
    }

    msg_destroy(msg);
  }

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
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

static
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

      ua_event(nh->nh_nua, nh, msg, 
	       nua_i_ack, status, phrase, TAG_END());
      ua_event(nh->nh_nua, nh, NULL, 
	       nua_i_media_error, status, phrase, TAG_END());
      
      signal_call_state_change(nh, 488, "Offer-Answer Error", 
			       nua_callstate_terminating, recv, 0);
      stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason), TAG_END());

      return 0;
    }
  }

  soa_clear_remote_sdp(nh->nh_soa);

  ua_event(nh->nh_nua, nh, msg, nua_i_ack, SIP_200_OK, TAG_END());

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

  ua_event(nh->nh_nua, nh, msg, nua_i_cancel, SIP_200_OK, TAG_END());

  signal_call_state_change(nh, 0, "Received CANCEL", nua_callstate_init, 0, 0);

  if (nh->nh_soa && ss->ss_state < nua_callstate_ready)
    soa_terminate(nh->nh_soa, NULL);

  return 0;
}

/* Timeout (no ACK or PRACK received) */
static
int process_timeout(nua_handle_t *nh,
		    nta_incoming_t *irq)
{
  struct nua_session_state *ss = nh->nh_ss;

  ua_event(nh->nh_nua, nh, 0, nua_i_error,
	   408, "Response timeout",
	   TAG_END());

  soa_terminate(nh->nh_soa, NULL);

  if (ss->ss_state == nua_callstate_ready) {
    /* send BYE if 200 OK (or 183 to re-INVITE) timeouts  */
    signal_call_state_change(nh, 0, "Timeout", 
			     nua_callstate_terminating, 0, 0);
    stack_signal(nh, nua_r_bye, 
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
use_session_timer(nua_t *nua, nua_handle_t *nh, int uas, msg_t *msg, sip_t *sip)
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
init_session_timer(nua_t *nua, nua_handle_t *nh, sip_t const *sip)
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
    dialog_usage_set_refresh(du, ss->ss_session_timer);
    du->du_pending = refresh_invite; /* Set timer */
  }
  else if (ss->ss_refresher == nua_remote_refresher) {
    dialog_usage_set_refresh(du, ss->ss_session_timer + 32);
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
nh_referral_check(nua_t *nua, nua_handle_t *nh, tagi_t const *tags)
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
  
  if (!nh_validate(nua, ref_handle)) {
    SU_DEBUG_3(("nua: invalid NOTIFY_REFER handle\n"));
    return -1;
  }
  else if (!ref->ref_event) {
    SU_DEBUG_3(("nua: NOTIFY event missing\n"));
    return -1;
  }

  if (ref_handle != ref->ref_handle) {
    if (ref->ref_handle)
      nh_decref(ref->ref_handle);
    ref->ref_handle = nh_incref(ref_handle);
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
nh_referral_respond(nua_handle_t *nh, unsigned status, char const *phrase)
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

  stack_signal(ref->ref_handle,
	       nua_r_notify,
	       SIPTAG_EVENT(ref->ref_event),
	       SIPTAG_SUBSCRIPTION_STATE_STR(substate),
	       SIPTAG_CONTENT_TYPE_STR("message/sipfrag"),
	       SIPTAG_PAYLOAD_STR(payload),
	       TAG_END());

  if (status < 200)
    return;

  su_free(nh->nh_home, ref->ref_event), ref->ref_event = NULL;

  nh_decref(ref->ref_handle), ref->ref_handle = NULL;
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
    dialog_usage_remove(nh, nh->nh_ds, ss->ss_usage);
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
ua_info(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;

  if (nh_is_special(nh)) {
    return UA_EVENT2(e, 500, "Invalid handle for INFO");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count, 
			 SIP_METHOD_INFO ,
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_info, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(tags));
  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  return cr->cr_event = e;
}

void restart_info(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_info, tags);
}

static int process_response_to_info(nua_handle_t *nh,
				    nta_outgoing_t *orq,
				    sip_t const *sip)
{
  if (crequest_check_restart(nh, nh->nh_cr, orq, sip, restart_info))
    return 0;
  return process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

int process_info(nua_t *nua,
		 nua_handle_t *nh,
		 nta_incoming_t *irq,
		 sip_t const *sip)
{
  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_info, SIP_200_OK, TAG_END());

  return 200;		/* Respond automatically with 200 Ok */
}


/* ======================================================================== */
/* UPDATE */

static int process_response_to_update(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int
ua_update(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_session_state *ss = nh->nh_ss;
  struct nua_client_request *cr = nh->nh_cr;
  struct nua_client_request *cri = ss->ss_crequest;
  struct nua_server_request *sri = ss->ss_srequest;
  msg_t *msg;
  sip_t *sip;
  char const *offer_sent = 0;

  if (!nh_has_session(nh))
    return UA_EVENT2(e, 500, "Invalid handle for UPDATE");
  else if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
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
	  session_include_description(nh, msg, sip) < 0) {
	if (ss->ss_state < nua_callstate_ready) {
	  /* XXX */
	}
	msg_destroy(msg);
	return UA_EVENT2(e, 500, "Local media failed");
      }

      offer_sent = "offer";
    }

    if (is_session_timer_set(ss))
      /* Add session timer headers */
      use_session_timer(nua, nh, 0, msg, sip);

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
  return UA_EVENT1(e, NUA_500_ERROR);
}

void restart_update(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_update, tags);
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
	crequest_check_restart(nh, cr, orq, sip, restart_update)) {
      return 0;
    }
    /* XXX - if we have a concurrent INVITE, what we do with it? */
  }
  else if (status >= 200) {
    /* XXX - check remote tag, handle forks */
    dialog_uac_route(nh, sip, 1); /* Set (route), contact, (remote tag) */
    dialog_get_peer_info(nh, sip);

    if (is_session_timer_set(ss)) {
      init_session_timer(nua, nh, sip);
      set_session_timer(nh);
    }

    if (session_process_response(nh, cr, orq, sip, &recv) < 0) {
      ua_event(nua, nh, NULL, nua_i_error, 
	       400, "Bad Session Description", TAG_END());
    }

    signal_call_state_change(nh, status, phrase, ss->ss_state, recv, 0);

    return 0;
  }
  else
    gracefully = 0;

  process_response(nh, cr, orq, sip, TAG_END());

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
      stack_signal(nh, nua_r_cancel, TAG_END());
    else
#endif
      stack_signal(nh, nua_r_bye, TAG_END());
  }

  return 0;
}

int process_update(nua_t *nua,
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
			status = 405, phrase = sip_405_Method_not_allowed,
			TAG_IF(ds->ds_has_subscription,
			       SIPTAG_ALLOW_STR("NOTIFY")),
			TAG_IF(ds->ds_has_notifier,
			       SIPTAG_ALLOW_STR("SUBSCRIBE, REFER")),
			TAG_END());
  }

  /* Do session timer negotiation if there is no ongoing INVITE transaction */
  if (status < 300 && 
      sip->sip_session_expires &&
      is_session_timer_set(ss))
    do_timer = 1, init_session_timer(nua, nh, sip);

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
      /* XXX */
      status = 500, phrase = sip_500_Internal_server_error;
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

  if (answer_sent && session_include_description(nh, rmsg, rsip) < 0) {
    status = 500, phrase = sip_500_Internal_server_error;
    answer_sent = NULL;
  }

  if (do_timer && 200 <= status && status < 300) {
    use_session_timer(nua, nh, 1, rmsg, rsip);
    set_session_timer(nh);
  }

  if (status == original_status) {
    if (nta_incoming_mreply(irq, rmsg) < 0)
      status = 500, phrase = sip_500_Internal_server_error;
  }

  if (status != original_status) {
    ua_event(nua, nh, NULL, nua_i_error, status, phrase, TAG_END());
    nta_incoming_treply(irq, status, phrase, TAG_END());
    msg_destroy(rmsg), rmsg = NULL;
  }

  ua_event(nh->nh_nua, nh, msg, nua_i_update, status, phrase, TAG_END());

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
ua_bye(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cr = nh->nh_cr;
  nua_client_request_t *cr_invite = ss->ss_crequest;
  msg_t *msg;
  nta_outgoing_t *orq;
  
  if (nh_is_special(nh))
    return UA_EVENT2(e, 500, "Invalid handle for BYE");

  if (!dialog_is_established(nh->nh_ds)) {
    if (cr_invite->cr_orq == NULL)
      return UA_EVENT2(e, 400, "Internal error");

    /* No (early) dialog. BYE is invalid action, do CANCEL instead */
    orq = nta_outgoing_tcancel(cr_invite->cr_orq,
			       process_response_to_bye, nh,
			       TAG_NEXT(tags));
    if (!cr->cr_orq)
      cr->cr_orq = orq, cr->cr_event = e;

    return 0;
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
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
  crequest_restart(nh, nh->nh_cr, process_response_to_bye, tags);
}


static int process_response_to_bye(nua_handle_t *nh,
				   nta_outgoing_t *orq,
				   sip_t const *sip)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cr_invite = ss->ss_crequest;
  nua_client_request_t *cr = nh->nh_cr;
  int status = sip ? sip->sip_status->st_status : 400;

  if (crequest_check_restart(nh, cr, orq, sip, restart_bye))
    return 0;

  process_response(nh, cr, orq, sip, TAG_END());

  if (status >= 200 && cr_invite->cr_orq == NULL) {
    signal_call_state_change(nh, status, "to BYE", 
			     nua_callstate_terminated, 0, 0);
    nsession_destroy(nh);
  }

  return 0;
}



int process_bye(nua_t *nua,
		nua_handle_t *nh,
		nta_incoming_t *irq,
		sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_server_request_t *sr = ss->ss_srequest;
  int early = 0;

  assert(nh);

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
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

/* ======================================================================== */
/* OPTIONS */

static int process_response_to_options(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int
ua_options(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;

  if (nh_is_special(nh)) {
    return UA_EVENT2(e, 500, "Invalid handle for OPTIONS");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_OPTIONS, 
			 TAG_NEXT(tags));

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_options, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(tags));
  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  return cr->cr_event = e;
}

void restart_options(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_options, tags);
}

static int process_response_to_options(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip)
{
  if (crequest_check_restart(nh, nh->nh_cr, orq, sip, restart_options))
    return 0;
  return process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

int process_options(nua_t *nua,
		    nua_handle_t *nh,
		    nta_incoming_t *irq,
		    sip_t const *sip)
{
  msg_t *msg;

  int status = 200; char const *phrase = sip_200_OK;

  if (nh == NULL)
    nh = nua->nua_dhandle;

  msg = nh_make_response(nua, nh, irq, status, phrase,
			 SIPTAG_ALLOW(NH_PGET(nh, allow)),
			 SIPTAG_SUPPORTED(NH_PGET(nh, supported)),
			 SIPTAG_ACCEPT_STR(SDP_MIME_TYPE),
			 TAG_IF(NH_PGET(nh, path_enable),
				SIPTAG_SUPPORTED_STR("path")),
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

  ua_event(nh->nh_nua, nh, msg, nua_i_options, status, phrase, TAG_END());

  return status;
}


/* ======================================================================== */
/* PUBLISH */

static int process_response_to_publish(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

static void refresh_publish(nua_handle_t *nh, nua_dialog_usage_t *, sip_time_t now);

int
ua_publish(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_dialog_usage_t *du;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg = NULL;
  sip_t *sip;

  if (nh->nh_special && nh->nh_special != nua_r_publish) {
    return UA_EVENT2(e, 500, "Invalid handle for PUBLISH");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  du = dialog_usage_add(nh, nh->nh_ds, nua_publish_usage, NULL);

  if (!du)
    return UA_EVENT1(e, NUA_500_ERROR);

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_PUBLISH,
			 SIPTAG_IF_MATCH(du->du_publisher->pu_etag),
			 NUTAG_ADD_CONTACT(0),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  du->du_terminating = 
    e != nua_r_publish ||
    (sip && sip->sip_expires && sip->sip_expires->ex_delta == 0);

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_publish, nh, NULL,
				    msg,
				    TAG_IF(e != nua_r_publish,
					   SIPTAG_EXPIRES_STR("0")),
				    SIPTAG_END(), TAG_NEXT(tags));

  if (!cr->cr_orq) {
    msg_destroy(msg);
    if (!du->du_ready)
      dialog_usage_remove(nh, nh->nh_ds, du);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  nh->nh_special = nua_r_publish;
  cr->cr_usage = du;

  return cr->cr_event = e;
}


static void 
restart_publish(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_publish, tags);
}


static 
int process_response_to_publish(nua_handle_t *nh,
				nta_outgoing_t *orq,
				sip_t const *sip)
{
  int status = sip->sip_status->st_status;
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;

  if (crequest_check_restart(nh, cr, orq, sip, restart_publish))
    return 0;

  if (du && status >= 200) {
    if (du->du_publisher->pu_etag)
      su_free(nh->nh_home, du->du_publisher->pu_etag), 
	du->du_publisher->pu_etag = NULL;

    if (sip->sip_expires == 0 || sip->sip_expires->ex_delta == 0)
      du->du_terminating = 1;

    if (!du->du_terminating && status < 300) {
      du->du_publisher->pu_etag = sip_etag_dup(nh->nh_home, sip->sip_etag);
      dialog_usage_set_refresh(du, sip->sip_expires->ex_delta);
      du->du_pending = refresh_publish;
    }
  }

  return process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}


static
void refresh_publish(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  if (du)
    du->du_terminating = now == 0;

  if (now > 0)
    ua_publish(nh->nh_nua, nh, nua_r_publish, NULL);
  else
    ua_publish(nh->nh_nua, nh, nua_r_destroy, NULL);
}


static
int process_publish(nua_t *nua,
		    nua_handle_t *nh,
		    nta_incoming_t *irq,
		    sip_t const *sip)
{
  if (nh == NULL)
    if (!(nh = nh_create_from_incoming(nua, irq, sip, nh_has_nothing, 0)))
      return 500;

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_publish, SIP_501_NOT_IMPLEMENTED, TAG_END());

  return 501; /* Respond automatically with 501 Not Implemented */
}


/* ======================================================================== */
/* MESSAGE */

static int process_response_to_message(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

int 
ua_message(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{ 
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;
  sip_t *sip;

  if (nh_is_special(nh)) {
    return UA_EVENT2(e, 500, "Invalid handle for MESSAGE");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
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
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  return cr->cr_event = e;
}

void restart_message(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_message, tags);
}

static int process_response_to_message(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip)
{
  if (crequest_check_restart(nh, nh->nh_cr, orq, sip, restart_message))
    return 0;
  return process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

int process_message(nua_t *nua,
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
    if (!(nh = nh_create_from_incoming(nua, irq, sip, nh_has_nothing, 0)))
      return 500;

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

  ua_event(nh->nh_nua, nh, msg, nua_i_message, SIP_200_OK, TAG_END());

#if 0 /* XXX */
  if (nh->nh_nua->nua_messageRespond) {	
    nh->nh_irq = irq;
    return 0;
  }
#endif

  return 200;
}

/* ======================================================================== */
/* SUBSCRIBE and NOTIFY */

static void 
  refresh_subscribe(nua_handle_t *nh, nua_dialog_usage_t *, sip_time_t now),
  pending_unsubscribe(nua_handle_t *nh, nua_dialog_usage_t *, sip_time_t now);
static int process_response_to_subscribe(nua_handle_t *nh,
					 nta_outgoing_t *orq,
					 sip_t const *sip);

int
ua_subscribe(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_client_request_t *cr = nh->nh_cr;
  nua_dialog_usage_t *du;
  msg_t *msg;
  sip_t *sip;

  if (nh->nh_special && nh->nh_special != nua_r_subscribe)
    return UA_EVENT3(e, 500, "Invalid handle for SUBSCRIBE", 
		     NUTAG_SUBSTATE(nua_substate_terminated));
  else if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  /* Initialize allow and auth */
  nh_init(nua, nh, nh_has_subscribe, "NOTIFY", TAG_NEXT(tags));

  if (nh->nh_has_subscribe)
    /* We can re-use existing INVITE handle */
    nh->nh_special = nua_r_subscribe;

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_SUBSCRIBE,
			 NUTAG_USE_DIALOG(1),
			 /* Note:  this is overriden by application */
			 /* SIPTAG_EVENT_STR("presence"), */
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (e != nua_r_subscribe) {	/* Unsubscribe */
    sip_add_make(msg, sip, sip_expires_class, "0");
    du = dialog_usage_get(nh->nh_ds, nua_subscriber_usage, sip->sip_event);
    if (du == NULL && sip->sip_event == NULL) {
      du = dialog_usage_get(nh->nh_ds, nua_subscriber_usage, NONE);
      if (du)
	sip_add_dup(msg, sip, (sip_header_t *)du->du_event);
    }
  }
  else
    /* We allow here SUBSCRIBE without event */
    du = dialog_usage_add(nh, nh->nh_ds, nua_subscriber_usage, sip->sip_event);

  /* Store supported features (eventlist) */
  if (du && sip) {
    if (du->du_subscriber->de_msg)
      msg_destroy(du->du_subscriber->de_msg);
    du->du_subscriber->de_msg = msg_ref_create(cr->cr_msg);
  }

  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_subscribe, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));

  if (!cr->cr_orq) {
    int substate = nua_substate_terminated;

    if (du && du->du_ready)
      substate = du->du_subscriber->de_substate;
    else if (du)
      dialog_usage_remove(nh, nh->nh_ds, du);

    msg_destroy(msg);
    return UA_EVENT3(e, NUA_500_ERROR, NUTAG_SUBSTATE(substate), TAG_END());
  }

  du->du_terminating = e != nua_r_subscribe;
  if (sip->sip_expires && sip->sip_expires->ex_delta == 0)
    du->du_terminating = 1;

  if (du->du_subscriber->de_substate == nua_substate_terminated)
    du->du_subscriber->de_substate = nua_substate_embryonic;

  cr->cr_usage = du;
  return cr->cr_event = e;
}

static void restart_subscribe(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_subscribe, tags);
}

static int process_response_to_subscribe(nua_handle_t *nh,
					 nta_outgoing_t *orq,
					 sip_t const *sip)
{
  nua_client_request_t *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  int status = sip ? sip->sip_status->st_status : 408;
  int gracefully = 0;
  int substate = nua_substate_embryonic;

  assert(du); assert(du->du_kind == nua_subscriber_usage);

  if (status < 200)
    ;
  else if (du == NULL) {
    /* Unsubscribe, NOTIFY removing du? */
  }
  else if (status < 300) {
    int win_messenger_enable = NH_PGET(nh, win_messenger_enable);
    sip_time_t delta, now = sip_now();

    du->du_ready = 1;
    substate = du->du_subscriber->de_substate;
    
    if (cr->cr_event == nua_r_unsubscribe)
      delta = 0;
    else
      /* If no expires header, use default value (0) 
       * -> do not re-subscribe, wait for NOTIFY 
       *    (if no NOTIFY is received, unsubscribe after 32 seconds)
       */
      delta = sip_contact_expires(NULL, sip->sip_expires, sip->sip_date, 
				  0, now);

    /* We have not received notify. */
    if (!win_messenger_enable)
      dialog_uac_route(nh, sip, 1);
    dialog_get_peer_info(nh, sip);

    if (delta > 0) {
      dialog_usage_set_refresh(du, delta);
      du->du_pending = refresh_subscribe;
    }
    else if (substate == nua_substate_embryonic || 
	     cr->cr_event == nua_r_unsubscribe) {
      if (win_messenger_enable)
	/* Wait 4 minutes for NOTIFY from Messenger */
	du->du_refresh = now + 4 * 60; 
      else
	/* Wait 32 seconds for NOTIFY */
	du->du_refresh = now + 64 * NTA_SIP_T1 / 1000; 
      du->du_pending = pending_unsubscribe;
    }
  }
  else /* if (status >= 300) */ {
    int terminated;

    if (crequest_check_restart(nh, cr, orq, sip, restart_subscribe))
      return 0;

    cr->cr_usage = NULL; /* We take care of removing/not removing usage */

    substate = du->du_subscriber->de_substate;

    if (!sip || !sip->sip_retry_after)
      gracefully = 1;

    terminated = 
      sip_response_terminates_dialog(status, sip_method_subscribe, 
				     &gracefully);

    /* XXX - zap dialog if terminated < 0 ? */

    if (terminated || !du->du_ready || du->du_terminating) {
      substate = nua_substate_terminated;
      dialog_usage_remove(nh, nh->nh_ds, du);
    }
    else if (gracefully && substate != nua_substate_terminated) 
      /* Post un-subscribe event */
      stack_signal(nh, nua_r_unsubscribe, 
		   SIPTAG_EVENT(du->du_event), 
		   SIPTAG_EXPIRES_STR("0"),
		   TAG_END());
  }

  process_response(nh, cr, orq, sip, 
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

  if (cr->cr_msg) {
    /* Delay of 5 .. 15 seconds */
    dialog_usage_set_refresh(du, 5 + (unsigned)random() % 11U);
    du->du_pending = refresh_subscribe;
    return;
  }

  if (now > 0)
    e = nua_r_subscribe;
  else
    e = nua_r_destroy, du->du_terminating = 1;

  cr->cr_msg = msg_ref_create(du->du_subscriber->de_msg);

  msg = crequest_message(nua, nh, cr, 1,
			 SIP_METHOD_SUBSCRIBE,
			 NUTAG_USE_DIALOG(1),
			 NUTAG_ADD_CONTACT(1),
			 //SIPTAG_EVENT(du->du_event),
			 //SIPTAG_SUPPORTED(nh->nh_supported),
			 TAG_IF(du->du_terminating, 
				SIPTAG_EXPIRES_STR("0")),
			 TAG_END());

  sip = sip_object(msg);

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_subscribe, nh, NULL,
				    msg,
				    SIPTAG_END(), TAG_NEXT(NULL));

  if (!cr->cr_orq) {
    int substate = du->du_subscriber->de_substate;
    if (du->du_terminating)
      dialog_usage_remove(nh, nh->nh_ds, du);
    msg_destroy(msg);
    UA_EVENT3(e, NUA_500_ERROR, NUTAG_SUBSTATE(substate), TAG_END());
    return;
  }

  cr->cr_usage = du;
  cr->cr_event = e;
}


static void 
pending_unsubscribe(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  sip_event_t const *o = NULL;
  char const *id;

  if (!du) {
    SU_DEBUG_1(("nua(%p): pending_unsubscribe() without usage to remove\n", 
		nh));
    return;
  }

  o = du->du_event;
  id = o ? o->o_id : NULL;
  SU_DEBUG_3(("nua(%p): pending_unsubscribe() with event %s%s%s\n",
	      nh, o ? o->o_type : "(empty)",
	      id ? "; id=" : "", id ? id : ""));

  ua_event(nh->nh_nua, nh,  NULL,
	   nua_i_notify, 408, "Early Subscription Timeouts without NOTIFY", 
	   NUTAG_SUBSTATE(nua_substate_terminated),
	   SIPTAG_EVENT(o),
	   TAG_END());

  dialog_usage_remove(nh, nh->nh_ds, du);
}

/* ======================================================================== */
/* NOTIFY */

static int process_response_to_notify(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip);

int
ua_notify(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = NULL;
  msg_t *msg;
  sip_t *sip;

  if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_NOTIFY,
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));
  sip = sip_object(msg);
  if (sip) {
    du = dialog_usage_get(nh->nh_ds, nua_notifier_usage, sip->sip_event);
    if (du && du->du_event && !sip->sip_event)
      sip_add_dup(msg, sip, (sip_header_t *)du->du_event);
  }

  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_notify, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));
  if (!cr->cr_orq) {
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  cr->cr_usage = du;

  return cr->cr_event = e;
}

static
void restart_notify(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_notify, tags);
}

static int process_response_to_notify(nua_handle_t *nh,
				      nta_outgoing_t *orq,
				      sip_t const *sip)
{
  if (crequest_check_restart(nh, nh->nh_cr, orq, sip, restart_notify))
    return 0;
  return process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}

static int process_notify(nua_t *nua,
			  nua_handle_t *nh,
			  nta_incoming_t *irq,
			  sip_t const *sip)
{
  nua_dialog_state_t *ds = nh->nh_ds;
  nua_dialog_usage_t *du;
  sip_subscription_state_t *subs = sip ? sip->sip_subscription_state : NULL;
  sip_contact_t *m = NULL, m0[1];
  int retry = -1;
  char const *what = NULL, *why = NULL;
  sip_warning_t w[1];

  enter;

  if (nh == NULL ||
      /* XXX - support forking of subscriptions?... */
      (ds->ds_remote_tag && sip->sip_from->a_tag &&
       strcmp(ds->ds_remote_tag, sip->sip_from->a_tag))) {
    sip_warning_init(w);
    w->w_code = 399;
    w->w_host = nua->nua_contact->m_url->url_host;
    w->w_port = nua->nua_contact->m_url->url_host;
    w->w_text = "Forking SUBSCRIBEs are not supported";

    nta_incoming_treply(irq, 481, "Subscription Does Not Exist", 
			TAG_IF(nh, SIPTAG_WARNING(w)),
			TAG_END());
    return 481;
  }
  assert(nh);

  du = dialog_usage_get(nh->nh_ds, nua_subscriber_usage, sip->sip_event);

  if (du == NULL) {
    nta_incoming_treply(irq, 481, "Subscription Does Not Exist", TAG_END());
    return 481;
  }

  if (subs == NULL) {
    /* Do some compatibility stuff here */
    sip_subscription_state_t ss0[1];
    unsigned long delta = 3600;
    char expires[32];

    sip_subscription_state_init(subs = ss0);

    if (sip->sip_expires)
      delta = sip->sip_expires->ex_delta;

    if (delta == 0)
      subs->ss_substate = "terminated";
    else
      subs->ss_substate = "active";

    if (delta > 0) {
      snprintf(expires, sizeof expires, "%lu", delta);
      subs->ss_expires = expires;
    }
  }

  dialog_get_peer_info(nh, sip);
  dialog_uas_route(nh, sip, 1);

  if (strcasecmp(subs->ss_substate, what = "terminated") == 0) {
    du->du_subscriber->de_substate = nua_substate_terminated;

    if (str0casecmp(subs->ss_reason, why = "deactivated") == 0) {
      du->du_subscriber->de_substate = nua_substate_embryonic;
      retry = 0;
    } 
    else if (str0casecmp(subs->ss_reason, why = "probation") == 0) {
      char const *retry_after;
      du->du_subscriber->de_substate = nua_substate_embryonic;
      retry = 30;
      retry_after = msg_params_find(subs->ss_params, "retry-after=");
      if (retry_after)
	retry = strtoul(retry_after, NULL, 10);
    }
    else
      why = subs->ss_reason;
  }
  else if (strcasecmp(subs->ss_substate, what = "pending") == 0)
    du->du_subscriber->de_substate = nua_substate_pending;
  else /* if (strcasecmp(subs->ss_substate, "active") == 0) */ {
    what = subs->ss_substate ? subs->ss_substate : "active";
    /* XXX - any extended state is considered as active */
    du->du_subscriber->de_substate = nua_substate_active;
  }
  

  if (nta_incoming_url(irq)->url_type == url_sips && nua->nua_sips_contact)
    *m0 = *nua->nua_sips_contact, m = m0;
  else if (nua->nua_contact)
    *m0 = *nua->nua_contact, m = m0;
  m0->m_params = NULL;
    
  nta_incoming_treply(irq, SIP_200_OK, SIPTAG_CONTACT(m), NULL);

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_notify, SIP_200_OK, 
	   NUTAG_SUBSTATE(du->du_subscriber->de_substate),
	   TAG_END());

  nta_incoming_destroy(irq), irq = NULL;

  SU_DEBUG_5(("nua(%p): process_notify: %s (%s)\n", nh, what, why ? why : ""));

  if (du->du_subscriber->de_substate == nua_substate_terminated) {
    du->du_refresh = 0, du->du_pending = NULL;
    if (du != nh->nh_cr->cr_usage)
      dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (du->du_subscriber->de_substate == nua_substate_embryonic) {
    if (retry != -1 && !du->du_terminating) {
      dialog_usage_set_refresh(du, retry);
      du->du_pending = refresh_subscribe;
    }
    else if (du != nh->nh_cr->cr_usage)
      dialog_usage_remove(nh, nh->nh_ds, du);
  }
  else if (subs->ss_expires) {
    sip_time_t delta = strtoul(subs->ss_expires, NULL, 10);
    
    if (!du->du_terminating) {
      dialog_usage_set_refresh(du, delta);
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
ua_refer(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
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

  nh_init(nua, nh, nh_has_subscribe, "NOTIFY", TAG_NEXT(tags));
  if (nh->nh_has_subscribe)
    nh->nh_special = nua_r_subscribe;

  sip_referred_by_init(by);
  by->b_display = nua->nua_from->a_display;
  *by->b_url = *nua->nua_from->a_url;

  /* Now we create a REFER request message */
  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
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
    du = dialog_usage_add(nh, nh->nh_ds, nua_subscriber_usage, event);
  
  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_refer, nh, NULL,
				      msg,
				      SIPTAG_END(), TAG_NEXT(tags));
  
  if (!cr->cr_orq) {
    if (du)
      dialog_usage_remove(nh, nh->nh_ds, du);
    su_free(nh->nh_home, event);
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  /*
   * We send a 100 trying event so that application gets a event 
   * it can use to match NOTIFYs with its REFER
   */
  ua_event(nua, nh, NULL, e, SIP_100_TRYING, 
	   NUTAG_REFER_EVENT(event),
	   TAG_END());
  su_free(nh->nh_home, event);

  cr->cr_usage = du;

  return cr->cr_event = e;
}

void restart_refer(nua_handle_t *nh, tagi_t *tags)
{
  ua_refer(nh->nh_nua, nh, nh->nh_cr->cr_event, tags);
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
    dialog_uac_route(nh, sip, 1);
    dialog_get_peer_info(nh, sip);
  }
  else /* if (status >= 300) */ {
    if (cr->cr_usage)
      dialog_usage_remove(nh, nh->nh_ds, cr->cr_usage), cr->cr_usage = NULL;
    if (crequest_check_restart(nh, cr, orq, sip, restart_refer))
      return 0;
  }

  return process_response(nh, cr, orq, sip, TAG_END());
}

/*--------------------------------------------------*/
int process_refer(nua_t *nua,
		  nua_handle_t *nh,
		  nta_incoming_t *irq,
		  sip_t const *sip)
{
  nua_dialog_usage_t *du = NULL;
  sip_event_t *event;
  sip_referred_by_t *by = NULL;
  msg_t *response;
  int created = 0;

  if (nh == NULL) {
    if (!(nh = nh_create_from_incoming(nua, irq, sip, nh_has_notify, 1)))
      return 500;
    created = 1;
  }

  event = sip_event_format(nh->nh_home, "refer;id=%u", sip->sip_cseq->cs_seq);
  if (event)
    du = dialog_usage_add(nh, nh->nh_ds, nua_notifier_usage, event);
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
  dialog_uas_route(nh, sip, 1);	/* Set route and tags */

  if (!sip->sip_referred_by) {
    sip_referred_by_t b[1];
    sip_from_t *a = sip->sip_from;

    sip_referred_by_init(b);

    *b->b_url = *a->a_url;
    b->b_display = a->a_display;
    by = b;
  }

  response = nh_make_response(nua, nh, irq, 
			      SIP_202_ACCEPTED, 
			      NUTAG_ADD_CONTACT(1),
			      TAG_END());

  nta_incoming_mreply(irq, response);

  /* Immediate notify */
  stack_signal(nh,
	       nua_r_notify,
	       SIPTAG_EVENT(event),
	       SIPTAG_SUBSCRIPTION_STATE_STR("pending"),
	       SIPTAG_CONTENT_TYPE_STR("message/sipfrag"),
	       SIPTAG_PAYLOAD_STR("SIP/2.0 100 Trying\r\n"),
	       TAG_END());
  
  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_refer, SIP_202_ACCEPTED, 
	   NUTAG_REFER_EVENT(event),
	   TAG_IF(by, SIPTAG_REFERRED_BY(by)),
	   TAG_END());
  
  su_free(nh->nh_home, event);

  return 500;   
}

/* ======================================================================== */
/* Authentication */

void
ua_authenticate(nua_t *nua, nua_handle_t *nh, nua_event_t e, 
		tagi_t const *tags)
{
  int status = nh_authorize(nh, TAG_NEXT(tags));

  if (status > 0) {
    crequest_restart_f *restart = NULL;

    ua_event(nua, nh, NULL, e, SIP_200_OK, TAG_END());

    if (nh->nh_cr->cr_restart) {
      restart = nh->nh_cr->cr_restart;
      nh->nh_cr->cr_restart = NULL;
    }
    else if (nh->nh_ss->ss_crequest->cr_restart) {
      restart = nh->nh_ss->ss_crequest->cr_restart;
      nh->nh_ss->ss_crequest->cr_restart = NULL;
    }

    restart(nh, NULL);	/* Restart operation */

  }
  else if (status < 0) {
    ua_event(nua, nh, NULL, e, 500, "Cannot add credentials", TAG_END());
  }
  else {
    ua_event(nua, nh, NULL, e, 404, "No matching challenge", TAG_END());
  }
}


/* ======================================================================== */
/* Authorization */

void
ua_authorize(nua_t *nua, nua_handle_t *nh, nua_event_t e, 
	     tagi_t const *tags)
{
  nea_sub_t *sub = NULL;
  nea_state_t state = nea_extended;

  tl_gets(tags,
	  NEATAG_SUB_REF(sub),
	  NUTAG_SUBSTATE_REF(state),
	  TAG_END());

  if (sub && state > 0) {
    nea_sub_auth(sub, state, TAG_NEXT(tags));
    ua_event(nua, nh, NULL, e, SIP_200_OK, TAG_END());
  }
  else {
    ua_event(nua, nh, NULL, e, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
  }
  return;
}


/* ======================================================================== */
/* Event server */

static
nea_event_t *nh_notifier_event(nua_handle_t *nh, 
			       su_home_t *home, 
			       sip_event_t const *event,
			       tagi_t const *tags);

static
void authorize_watcher(nea_server_t *nes,
		       nua_handle_t *nh,
		       nea_event_t *ev,
		       nea_subnode_t *sn,
		       sip_t const *sip);

void
ua_notifier(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  sip_event_t const *event = NULL;
  sip_content_type_t const *ct = NULL;
  sip_payload_t const *pl = NULL;
  url_string_t const *url = NULL;
  char const *event_s = NULL, *ct_s = NULL, *pl_s = NULL;
  nea_event_t *ev;
  int status = 500;
  char const *phrase = "Internal NUA Error";

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  tl_gets(tags, 
	  NUTAG_URL_REF(url), 
	  SIPTAG_EVENT_REF(event),
	  SIPTAG_EVENT_STR_REF(event_s),
	  SIPTAG_CONTENT_TYPE_STR_REF(ct_s),
	  SIPTAG_PAYLOAD_REF(pl),
	  SIPTAG_PAYLOAD_STR_REF(pl_s),
	  TAG_END());

  if (!event && !event_s)
    status = 400, phrase = "Missing Event";

  else if (!ct && !ct_s) 
    status = 400, phrase = "Missing Content-Type";

  else if (!nh->nh_notifier &&
	   !(nh->nh_notifier = 
	     nea_server_create(nua->nua_nta, nua->nua_root,
			       url->us_url,
			       NH_PGET(nh, max_subscriptions), 
			       NULL, nh,
			       TAG_NEXT(tags)))) 
    status = 500, phrase = "Internal NUA Error";

  else if (!event && !(event = sip_event_make(home, event_s)))
    status = 500, phrase = "Could not create an event header";

  else if (!(ev = nh_notifier_event(nh, home, event, tags)))
    status = 500, phrase = "Could not create an event view";

  else if (nea_server_update(nh->nh_notifier, ev,  TAG_NEXT(tags)) < 0)
    status = 500, phrase = "No content for event";

  else if (nea_server_notify(nh->nh_notifier, ev) < 0)
    status = 500, phrase = "Error when notifying watchers";
  else 
    ua_event(nua, nh, NULL, e, status = SIP_200_OK, 
	     SIPTAG_EVENT(event),
	     SIPTAG_CONTENT_TYPE(ct),
	     TAG_END());
	     
  if (status != 200)
    ua_event(nua, nh, NULL, e, status, phrase, TAG_END());

  su_home_deinit(home);
}


/* Create a event view for notifier */
static
nea_event_t *nh_notifier_event(nua_handle_t *nh, 
			       su_home_t *home, 
			       sip_event_t const *event,
			       tagi_t const *tags)
{
  nea_event_t *ev = nea_event_get(nh->nh_notifier, event->o_type);
  sip_accept_t const *accept = NULL;
  char const  *accept_s = NULL;
  sip_content_type_t const *ct = NULL;
  char const *ct_s = NULL;

  if (ev == NULL) {
    char *o_type = su_strdup(home, event->o_type);
    char *o_subtype = strchr(o_type, '.');

    if (o_subtype)
      *o_subtype++ = '\0';

    tl_gets(tags, 
	    SIPTAG_ACCEPT_REF(accept),
	    SIPTAG_ACCEPT_STR_REF(accept_s),
	    SIPTAG_CONTENT_TYPE_REF(ct),
	    SIPTAG_CONTENT_TYPE_STR_REF(ct_s),
	    TAG_END());
      
    /*
     * XXX - We really should build accept header when we add new content
     * types
     */
    if (accept_s == NULL && accept)
      accept_s = sip_header_as_string(home, (sip_header_t *)accept);
    if (accept_s == NULL && ct)
      accept_s = ct->c_type;
    if (accept_s == NULL && ct_s)
      accept_s = ct_s;

    ev = nea_event_create(nh->nh_notifier, 
			  authorize_watcher, nh,
			  o_type, o_subtype,
			  ct ? ct->c_type : ct_s,
			  accept_s);
  }

  return ev;
}

/* Callback from nea_server asking nua to authorize subscription */
static
void authorize_watcher(nea_server_t *nes,
		       nua_handle_t *nh,
		       nea_event_t *ev,
		       nea_subnode_t *sn,
		       sip_t const *sip)
{
  nua_t *nua = nh->nh_nua;
  msg_t *msg = NULL;
  nta_incoming_t *irq = NULL;

  /* OK. In nhp (nua_handle_preferences_t) structure we have the
     current default action (or state) for incoming
     subscriptions. 
     Action can now be modified by the application with NUTAG_SUBSTATE(). 
  */
  int substate = NH_PGET(nh, substate);

  irq = nea_sub_get_request(sn->sn_subscriber);
  msg = nta_incoming_getrequest(irq);
  ua_event(nua, nh, msg, nua_i_subscription, SIP_200_OK,
           NEATAG_SUB(sn->sn_subscriber),
           TAG_END());

  if (sn->sn_state == nea_embryonic) {
    SU_DEBUG_7(("nua(%p): authorize_watcher: new watcher\n", nh)); 
    nea_sub_auth(sn->sn_subscriber, substate,
		 TAG_IF(substate != nua_substate_active,
			NEATAG_FAKE(1)),
		 TAG_END());
  }
  else if (sn->sn_state == nea_terminated || sn->sn_expires == 0) {
    nea_server_flush(nes, NULL);
    SU_DEBUG_7(("nua(%p): authorize_watcher: watcher is removed\n", nh)); 
  }
}


/** Shutdown notifier object */
int
nh_notifier_shutdown(nua_handle_t *nh, nea_event_t *ev,
		     tag_type_t t, tag_value_t v, ...)
{
  nea_server_t *nes = nh->nh_notifier;
  nea_subnode_t const **subs;
  int busy = 0;

  if (nes == NULL)
    return 0;

  subs = nea_server_get_subscribers(nes, ev);

  if (subs) {
    int i;
    ta_list ta;

    ta_start(ta, t, v);
    
    for (i = 0; subs[i]; i++)
      nea_sub_auth(subs[i]->sn_subscriber, nea_terminated, ta_tags(ta));
    
    ta_end(ta);

    busy++;
  }

  nea_server_free_subscribers(nes, subs);
  
  nea_server_flush(nh->nh_notifier, NULL);

  if (ev == NULL)
    nea_server_destroy(nh->nh_notifier), nh->nh_notifier = NULL;

  return busy;
}


/** Terminate notifier. */
void
ua_terminate(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  sip_event_t const *event = NULL;
  sip_content_type_t const *ct = NULL;
  sip_payload_t const *pl = NULL;
  char const *event_s = NULL, *ct_s = NULL, *pl_s = NULL;
  nea_event_t *nev = NULL;
  char const *reason = "noresource";

  if (nh->nh_notifier == NULL) {
    UA_EVENT2(e, 500, "No event server to terminate");
    return;
  }

  tl_gets(tags, 
	  SIPTAG_EVENT_REF(event),
	  SIPTAG_EVENT_STR_REF(event_s),
	  SIPTAG_CONTENT_TYPE_REF(ct),
	  SIPTAG_CONTENT_TYPE_STR_REF(ct_s),
	  SIPTAG_PAYLOAD_REF(pl),
	  SIPTAG_PAYLOAD_STR_REF(pl_s),
	  NEATAG_REASON_REF(reason),
	  TAG_END());

  nev = nea_event_get(nh->nh_notifier, 
		      event ? event->o_type : event_s);

  if (nev) {
    if ((pl || pl_s) && (ct || ct_s))
      nea_server_update(nh->nh_notifier, nev, 
			SIPTAG_CONTENT_TYPE(ct),
			SIPTAG_CONTENT_TYPE_STR(ct_s),
			SIPTAG_PAYLOAD(pl),
			SIPTAG_PAYLOAD_STR(pl_s),
			TAG_END());
  }

  if (!event || nev)
    nh_notifier_shutdown(nh, nev, NEATAG_REASON(reason), TAG_END());

  ua_event(nua, nh, NULL, e, SIP_200_OK, TAG_END());

  su_home_deinit(home);
}

/* ======================================================================== */
/*
 * Process incoming requests
 */

int process_request(nua_handle_t *nh,
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

  if (uas_check_method(irq, sip, allow, 
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

  if (uas_check_required(irq, sip, supported, 
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
    return process_invite(nua, nh, irq, sip);

  case sip_method_info:
    if (nh) return process_info(nua, nh, irq, sip);
    /*FALLTHROUGH*/

  case sip_method_update:
    if (nh) return process_update(nua, nh, irq, sip);
    /*FALLTHROUGH*/

  case sip_method_bye:
    if (nh) return process_bye(nua, nh, irq, sip);

    nta_incoming_treply(irq, 
			481, "No Such Call", 
			SIPTAG_ALLOW(allow),
			SIPTAG_SUPPORTED(supported), 
			SIPTAG_USER_AGENT(user_agent),
			TAG_END());
    return 481;

  case sip_method_message:
    return process_message(nua, nh, irq, sip);

  case sip_method_notify:
    return process_notify(nua, nh, irq, sip);

  case sip_method_options:
    return process_options(nua, nh, irq, sip);

  case sip_method_refer:
    return process_refer(nua, nh, irq, sip);

  case sip_method_publish:
    return process_publish(nua, nh, irq, sip);

  case sip_method_ack:
  case sip_method_cancel:
    SU_DEBUG_1(("nua(%p): strange %s from <" URL_PRINT_FORMAT ">\n", nh,
		sip->sip_request->rq_method_name,
		URL_PRINT_ARGS(sip->sip_from->a_url)));
    /* Send nua_i_error ? */
    return 481;

  default:
    return process_method(nua, nh, irq, sip);
  }
}

static void 
ua_respond(nua_t *nua, nua_handle_t *nh,
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
    
    SU_DEBUG_1(("nua: anonymous ua_respond %u %s\n", status, phrase));
    
    tl_gets(tags, NUTAG_ADD_CONTACT_REF(add_contact), TAG_END());
    nta_incoming_treply(nh->nh_irq, status, phrase, 
			TAG_IF(add_contact, SIPTAG_CONTACT(m)),
			TAG_NEXT(tags));
    if (status >= 200)
      nta_incoming_destroy(nh->nh_irq), nh->nh_irq = NULL;
  }
#endif

  else if (ss->ss_srequest->sr_irq) {
    ua_event(nua, nh, NULL, nua_i_error,
	     500, "Already Sent Final Response", TAG_END());
  }
  else {
    ua_event(nua, nh, NULL, nua_i_error,
	     500, "Responding to a Non-Existing Request", TAG_END());
  }
}

/* ======================================================================== */
/* Destroy a handle */
 
static void 
ua_destroy(nua_t *nua, nua_handle_t *nh, tagi_t const *tags)
{
  nh_call_pending(nh, 0);

  if (nh->nh_notifier)
    ua_terminate(nua, nh, 0, NULL);

  if (nh->nh_ref_by_user) {
    nh->nh_ref_by_user = 0;
    nh_decref(nh);
  }

  nh_destroy(nua, nh);
}
