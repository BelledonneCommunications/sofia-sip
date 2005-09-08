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
 * $Date: 2005/08/10 11:34:35 $
 */

#include "config.h"

const char _nua_stack_c_id[] =
"$Id: nua_stack.c,v 1.3 2005/08/10 11:34:35 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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

#if HAVE_HERBIE
#include "nua_herbie.h"
#endif

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

#if HAVE_SMIME 		/* Start NRC Boston */
#include "smimec.h"
#endif                  /* End NRC Boston */

#include <sdp.h>

#define MSS_EVENT_HANDLER_T nua_handle_t

/* XXX: */
#if HAVE_MSS
#include <mss.h>
#include <mss_event.h>
#include <mss_status.h>
#endif

#include <sl_utils.h>

#if HAVE_SIGCOMP
#include <sigcomp.h>
#include <nta_tport.h>
#endif

#include "nua_stack.h"

typedef unsigned longlong ull;

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

static inline int nmedia_is_enabled(struct nua_media_state *nm);
static inline int nmedia_is_ready(struct nua_media_state *nm);

static sdp_session_t *nmedia_describe(nua_t *nua,
				      struct nua_media_state *nm,
				      nua_handle_t *,
				      su_home_t *home);
static int nmedia_setup(nua_t *, 
			struct nua_media_state *nm,
			nua_handle_t *, 
			nua_event_t ee, 
			sdp_session_t const *, 
			char const *offer_answer, int required);
static int nmedia_play(nua_t *nua, struct nua_media_state *nm);
static int nmedia_record(nua_t *nua, struct nua_media_state *nm);
static int nmedia_pause(nua_t *nua, struct nua_media_state *nm, 
			char const *direction);
static int nmedia_teardown(nua_t *nua, struct nua_media_state *nm,
			   nua_handle_t *nh);
static int nmedia_features(su_home_t *, msg_param_t **, 
			     sdp_media_t *, int live);

static void nmedia_event_bind(nua_t *nua,
			      struct nua_media_state *nm,
			      nua_handle_t *nh);

/* XXX: */
#if HAVE_MSS
static void nmedia_event_handler(mss_t *mss, ms_t *mms, 
				 mss_event_handler_t *context,
				 char const *path,
				 char const *params[],
				 void const *data, int dlen);
#endif

static int nmedia_save_params(struct nua_media_state *nm,
			      su_home_t *home,
			      int copy,
			      tagi_t const *tags);


static int nmedia_set_param(struct nua_media_state *nm,
			    su_home_t *home,
			    char const *mss_name,
			    char const **pparam,
			    char const *value);

static
int nh_notifier_shutdown(nua_handle_t *nh, nea_event_t *ev,
			 tag_type_t t, tag_value_t v, ...);

static void ua_timer(nua_t *nua, su_timer_t *t, su_timer_arg_t *a);

static void ua_set_from(nua_t *nua, sip_from_t const *f);

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
"INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, INFO, "
"MESSAGE, SUBSCRIBE, NOTIFY, REFER, UPDATE";

/* ----------------------------------------------------------------------
 * Initialization & deinitialization
 */

int ua_init(su_root_t *root, nua_t *nua)
{
  su_home_t *home;
  void *sip_parser = NULL;
  url_string_t const *contact = NULL;
  url_string_t const *sips_contact = NULL;

  char const *certificate_dir = NULL;
  char const *media_address = NULL;
  char const *media_descs = NULL;
  char const *media_params = NULL;
  char const *uicc_name = "default";

  nua_handle_t *nh;
  int media_enable = 1;

  static int initialized_logs = 0;

  enter;

  if (!initialized_logs) {
/* XXX: */
#if HAVE_MSS
    extern su_log_t mss_log[];
#endif
    extern su_log_t tport_log[];
    extern su_log_t nta_log[];
    extern su_log_t nea_log[];
    extern su_log_t iptsec_log[];

/* XXX: */
#if HAVE_MSS
    su_log_init(mss_log);
#endif
    su_log_init(tport_log);
    su_log_init(nta_log);
    su_log_init(nea_log);
    su_log_init(iptsec_log);

    initialized_logs = 1;
  }

  home = nua->nua_home;

  nua->nua_root = root;

  nua->nua_handles_tail = &nua->nua_handles;
  
  if (!(nua->nua_handles = nh = nh_create(nua, TAG_END())))
    return -1;

  /* Set some defaults */
  nua->nua_handles->nh_auto_ack = 1;
  nua->nua_path_enable = 1;
  nua->nua_service_route_enable = 1;

  /* Set initial parameters */

  tl_gets(nua->nua_args,
	  NUTAG_URL_REF(contact),
	  NUTAG_SIPS_URL_REF(sips_contact),
	  NUTAG_CERTIFICATE_DIR_REF(certificate_dir),
	  NUTAG_SIP_PARSER_REF(sip_parser),
	  NUTAG_MEDIA_ADDRESS_REF(media_address),
	  NUTAG_MEDIA_DESCS_REF(media_descs),
	  NUTAG_MEDIA_PARAMS_REF(media_params),
	  NUTAG_MEDIA_ENABLE_REF(media_enable),
	  NUTAG_UICC_REF(uicc_name),
	  TAG_NULL());

#if HAVE_UICC_H
  if (uicc_name)
    nua->nua_uicc = uicc_create(root, uicc_name);
#endif

  if (!contact && sips_contact)
    contact = sips_contact, sips_contact = NULL;
  
  nua->nua_nta = nta_agent_create(root, contact, NULL, NULL, 
				  TPTAG_CERTIFICATE(certificate_dir),
				  NTATAG_TAG_3261(0),
				  TAG_END());

  if (!nua->nua_nta && !contact) {
    contact = (url_string_t const*)"sip:*:*";
    nua->nua_nta = nta_agent_create(root, contact, NULL, NULL, 
				    TPTAG_CERTIFICATE(certificate_dir),
				    NTATAG_TAG_3261(0),
				    TAG_END());
  }

  if (!nua->nua_nta)
    return -1;

  if (sips_contact) {
    nta_agent_add_tport(nua->nua_nta, sips_contact, 
			TPTAG_CERTIFICATE(certificate_dir),
			TAG_END());
  }

  nua->nua_invite_timer = 120;
  nua->nua_session_timer = 1800;
  nua->nua_min_se = 120;
  nua->nua_retry_count = 3;
  nua->nua_max_subscriptions = 20;
  nua->nua_media_enable = media_enable;
  nua->nua_messageRespond = getenv("PIMIW_HACK") != 0;

  nta_agent_set_params(nua->nua_nta,
		       NTATAG_UA(1),
		       NTATAG_MERGE_482(1),
		       NTATAG_RPORT(1),	/* XXX */
#if HAVE_SMIME
		       NTATAG_SMIME(nua->sm),
#endif
		       TAG_NEXT(nua->nua_args));

  nua->nua_sdp_content = sip_content_type_make(home, SDP_MIME_TYPE);

  nua->nua_invite_accept = sip_accept_make(home, SDP_MIME_TYPE);

  nua->nua_media_address = su_strdup(home, media_address);

/* XXX: */
#if HAVE_MSS
  nua->nua_media_descs = 
    su_sprintf(nua->nua_home, MSS_CREATE_DESCS "%s", media_descs);
  nua->nua_media_events = su_strlst_create(home);

  /* XXX: instantiate the media subsystem, and store
     a pointer to nua_mss */
#endif

  if (!nua->nua_media_path) {
    nua->nua_media_path = su_strdup(home, "/");
  }

  if (!nua->nua_media_cname) {
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
/* XXX: */
#if HAVE_MSS
    nua->nua_media_cname = 
      su_sprintf(home, MS_SETUP_EMAIL "=%s@%s", getenv("USER"), hostname);
#endif
  }

  nh->nh_ds->ds_leg = nta_leg_tcreate(nua->nua_nta, process_request, nh,
				      NTATAG_NO_DIALOG(1), 
				      TAG_END());

  if (!nua->nua_allow)
    nua->nua_allow = sip_allow_make(home, nua_allow_str);
  if (!nua->nua_supported)
    nua->nua_supported = sip_supported_make(home, "timer, 100rel");

  nua->nua_timer = su_timer_create(su_root_task(root), UA_INTERVAL * 1000);

  ua_init_contact(nua);

  ua_set_from(nua, NULL);

  if (!(nh->nh_ds->ds_leg &&
	nua->nua_allow &&
	nua->nua_supported &&
	(nua->nua_contact || nua->nua_sips_contact) &&
	nua->nua_from &&
	nua->nua_sdp_content &&
/* XXX: */
#if HAVE_MSS
	nua->nua_media_events &&
	nua->nua_mss &&
#endif
	nua->nua_timer))
    return -1;

  ua_timer(nua, nua->nua_timer, NULL);

#if HAVE_HERBIE
  /* Enable polyphonic ringing tones */
  nua->nua_herbie = nua_herbie_create(home, getenv("NUA_HERBIE_TONE"));
  if (!nua->nua_herbie);
#endif

  nua->nua_args = NULL;

  return 0;
}

void ua_deinit(su_root_t *root, nua_t *nua)
{
  enter;

#if HAVE_HERBIE
  if (nua->nua_herbie)
    nua_herbie_free(nua->nua_herbie), nua->nua_herbie = NULL;
#endif

  su_timer_destroy(nua->nua_timer), nua->nua_timer = NULL;
  nta_agent_destroy(nua->nua_nta), nua->nua_nta = NULL;
/* XXX: */
#if HAVE_MSS
  /* XXX: clean up media subsystem resources (nua->nua_mss) */
#endif
}


/** Set the default from field */
void ua_set_from(nua_t *nua, sip_from_t const *f)
{
  sip_param_t params[2] = { NULL, NULL };
  sip_from_t from[1] = { SIP_FROM_INIT() }, *f0 = NULL;

#if HAVE_UICC_H
  /* XXX: add */
#endif

  if (f) {
    from->a_display = f->a_display;
    *from->a_url = *f->a_url;
    if (f->a_params)
      from->a_params = f->a_params;
    else
      from->a_params = params;
  } 
  else {
    sip_contact_t *m;
    m = nua->nua_contact ? nua->nua_contact : nua->nua_sips_contact;
    from->a_display = m->m_display;
    *from->a_url = *m->m_url;
    from->a_params = params;
  }

  params[0] = nta_agent_newtag(NULL, "tag=%s", nua->nua_nta);

  nua->nua_from = sip_from_dup(nua->nua_home, from);

  su_free(NULL, (void *) params[0]);
  su_free(NULL, f0);
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
  msg_param_t **m_params = (msg_param_t **)&m->m_params;
  su_strlst_t *l = su_strlst_create(home);
  nua_handle_t *nh = nua->nua_default;
  sdp_session_t *sdp;
  int i;

  if (nh->nh_callee_caps) {
    if (nh->nh_allow) {
      char *methods;
      if (nh->nh_allow->k_items)
	for (i = 0; nh->nh_allow->k_items[i]; i++)
	  su_strlst_append(l, nh->nh_allow->k_items[i]);
      methods = su_strlst_join(l, home, ",");
      methods = su_sprintf(home, "methods=\"%s\"", methods);
      msg_params_replace(home, m_params, methods);
    }
    
    sdp = nmedia_describe(nua, nh->nh_nm, nh, home);
      
    if (sdp)
      nmedia_features(home, m_params, sdp->sdp_media, 0);
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

static void 
  ua_shutdown(nua_t *),
  ua_set_params(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_get_params(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_set_media_param(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_get_media_param(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_media_setup(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_media_describe(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *),
  ua_media_event(nua_t *, nua_handle_t *, nua_event_t, tagi_t const *);

static int
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
    e->e_nh = nh ? nh_incref(nh) : nua->nua_default;
    e->e_status = status;
    e->e_phrase = strcpy(end, phrase ? phrase : "");
    e->e_msg = msg;

    if (su_msg_send(sumsg) != 0)
      nh_decref(nh);
  }

  ta_end(ta);

  return event;
}

/** Get name for NUA event. */
char const *nua_event_name(nua_event_t event)
{
  switch (event) {
  case nua_i_error: return "nua_i_error";
  case nua_i_media_error: return "nua_i_media_error";
  case nua_i_invite: return "nua_i_invite";
  case nua_i_fork: return "nua_i_fork";
  case nua_i_active: return "nua_i_active";
  case nua_i_terminate: return "nua_i_terminate";
  case nua_i_cancel: return "nua_i_cancel";
  case nua_i_bye: return "nua_i_bye";
  case nua_i_options: return "nua_i_options";
  case nua_i_refer: return "nua_i_refer";
  case nua_i_publish: return "nua_i_publish";
  case nua_i_prack: return "nua_i_prack";
  case nua_i_info: return "nua_i_info";
  case nua_i_update: return "nua_i_update";
  case nua_i_message: return "nua_i_message";
  case nua_i_chat: return "nua_i_chat";
  case nua_i_subscribe: return "nua_i_subscribe";
  case nua_i_notify: return "nua_i_notify";
  case nua_i_method: return "nua_i_method";
  case nua_i_media_event: return "nua_i_media_event";
  case nua_i_terminated: return "nua_i_terminated";

  case nua_i_announce: return "nua_i_announce (rtsp)";
  case nua_i_describe: return "nua_i_describe (rtsp)";
  case nua_i_get_parameter: return "nua_i_get_parameter (rtsp)";
  case nua_i_pause: return "nua_i_pause (rtsp)";
  case nua_i_options2: return "nua_i_options (rtsp)";
  case nua_i_play: return "nua_i_play (rtsp)";
  case nua_i_record: return "nua_i_record (rtsp)";
  case nua_i_set_parameter: return "nua_i_set_parameter (rtsp)";
  case nua_i_setup: return "nua_i_setup (rtsp)";
  case nua_i_teardown: return "nua_i_teardown (rtsp)";

  /* Responses */
  case nua_r_get_params: return "nua_r_get_params";
  case nua_r_shutdown: return "nua_r_shutdown";
  case nua_r_set_media_param: return "nua_r_set_media_param";
  case nua_r_get_media_param: return "nua_r_get_media_param";
  case nua_r_media_setup: return "nua_r_media_setup";
  case nua_r_media_describe: return "nua_r_media_describe";
  case nua_r_media_event: return "nua_r_media_event";
  case nua_r_notifier: return "nua_r_notifier";
  case nua_r_terminate: return "nua_r_terminate";

  case nua_r_register: return "nua_r_register";
  case nua_r_unregister: return "nua_r_unregister";
  case nua_r_invite: return "nua_r_invite";
  case nua_r_bye: return "nua_r_bye";
  case nua_r_options: return "nua_r_options";
  case nua_r_refer: return "nua_r_refer";
  case nua_r_publish: return "nua_r_publish";
  case nua_r_info: return "nua_r_info";
  case nua_r_update: return "nua_r_update";
  case nua_r_message: return "nua_r_message";
  case nua_r_chat: return "nua_r_chat";
  case nua_r_subscribe: return "nua_r_subscribe";
  case nua_r_unsubscribe: return "nua_r_unsubscribe";
  case nua_r_notify: return "nua_r_notify";

  case nua_r_setup: return "nua_r_setup (rtsp)";
  case nua_r_play: return "nua_r_play (rtsp)";
  case nua_r_record: return "nua_r_record (rtsp)";
  case nua_r_pause: return "nua_r_pause (rtsp)";
  case nua_r_describe: return "nua_r_describe (rtsp)";
  case nua_r_teardown: return "nua_r_teardown (rtsp)";
  case nua_r_options2: return "nua_r_options2 (rtsp)";
  case nua_r_announce: return "nua_r_announce (rtsp)";
  case nua_r_get_parameter: return "nua_r_get_parameter (rtsp)";
  case nua_r_set_parameter: return "nua_r_set_parameter (rtsp)";

  case nua_r_method: return "nua_r_method";

  case nua_r_cancel: return "nua_r_cancel";
  case nua_r_authenticate: return "nua_r_authenticate";
  case nua_r_redirect: return "nua_r_redirect";
  case nua_r_destroy: return "nua_r_destroy";
  case nua_r_respond: return "nua_r_respond";
  case nua_r_set_params: return "nua_r_set_params";
  case nua_r_ack: return "nua_r_ack";
  default: return "NUA_UNKNOWN";
  }
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
    ua_get_params(nua, nh, e->e_event, tags);
    break;
  case nua_r_set_params:
    ua_set_params(nua, nh, e->e_event, tags);
    break;
  case nua_r_shutdown:
    ua_shutdown(nua);
    break;
  case nua_r_set_media_param:
    ua_set_media_param(nua, nh, e->e_event, tags);
    break;
  case nua_r_get_media_param:
    ua_get_media_param(nua, nh, e->e_event, tags);
    break;
  case nua_r_media_setup:
    ua_media_setup(nua, nh, e->e_event, tags);
    break;
  case nua_r_media_describe:
    ua_media_describe(nua, nh, e->e_event, tags);
    break;
  case nua_r_media_event:
    ua_media_event(nua, nh, e->e_event, tags);
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

  if (nh != nua->nua_default)
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

    if (ss->ss_respond_to_invite) {
      ss->ss_respond_to_invite(nua, nh, SIP_410_GONE, NULL);
      busy++;
    }

    busy += nh_call_pending(nh, 0);

    if (nmedia_is_ready(nh->nh_nm)) {
      nmedia_teardown(nua, nh->nh_nm, nh);
      busy++;
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

  ua_event(nua, NULL, NULL, nua_r_shutdown, status, phrase, TAG_END());
}

/* ----------------------------------------------------------------------
 * Parameters
 */
void ua_set_params(nua_t *nua, nua_handle_t *nh, nua_event_t e, 
		   tagi_t const *tags)
{
  su_home_t     tmphome[1] = { SU_HOME_INIT(tmphome) }; 

  int           af = nua->nua_media_af;
  int           autoAlert = nua->nua_autoAlert;
  int           autoAnswer = nua->nua_autoAnswer;
  int           autoACK = nua->nua_default->nh_auto_ack;
  int           enableInvite = nua->nua_enableInvite;
  int           enableMessage = nua->nua_enableMessage;
  int           enableMessenger = nua->nua_enableMessenger;
  int           early_media = nua->nua_default->nh_early_media;
#if HAVE_SMIME		/* Start NRC Boston */
  int           smime_enable = nua->sm->sm_enable;
  int           smime_opt = nua->sm->sm_opt;
  int           smime_protection_mode = nua->sm->sm_protection_mode;
  char const   *smime_message_digest = NONE;
  char const   *smime_signature = NONE;
  char const   *smime_key_encryption = NONE;
  char const   *smime_message_encryption = NONE;
  char const   *smime_path = NONE;
#endif			/* End NRC Boston */

  char const   *media_address = NONE;
  char const   *media_path = NONE;
  char const   *media_descs = NONE;
  char const   *media_params = NONE;
  unsigned      invite_timer = nua->nua_invite_timer;
  unsigned      session_timer = nua->nua_session_timer;
  unsigned      min_se = nua->nua_min_se;
  int           refresher = nua->nua_refresher;
  int           update_refresh = nua->nua_default->nh_update_refresh;
  int           media_features = nua->nua_default->nh_media_features;
  int           callee_caps = nua->nua_default->nh_callee_caps;
  int           path_enable = nua->nua_path_enable;
  int           service_route_enable = nua->nua_service_route_enable;
  url_string_t const *registrar = NONE;
  sip_from_t const *from = NONE;
  char const   *fromstr = NONE;
  char const   *allow_str = NONE, *supported_str = NONE;
  sip_allow_t const *allow = NONE;
  sip_supported_t const *supported = NONE;
  sip_organization_t const *organization = NONE;
  char const   *organization_str = NONE;
  char const   *user_agent = nua->nua_ua_name;
  char const   *media_event = NULL;

  enter;

  nta_agent_set_params(nua->nua_nta, TAG_NEXT(tags));

  if (!tl_gets(tags,
	       NUTAG_AF_REF(af),
	       NUTAG_MEDIA_ADDRESS_REF(media_address),
	       NUTAG_MEDIA_PATH_REF(media_path),
	       NUTAG_MEDIA_DESCS_REF(media_descs),
	       NUTAG_MEDIA_PARAMS_REF(media_params),
	       NUTAG_INVITE_TIMER_REF(invite_timer),
	       NUTAG_SESSION_TIMER_REF(session_timer),
	       NUTAG_MIN_SE_REF(min_se),
	       NUTAG_SESSION_REFRESHER_REF(refresher),
	       NUTAG_UPDATE_REFRESH_REF(update_refresh),
	       NUTAG_EARLY_MEDIA_REF(early_media),
	       NUTAG_AUTOALERT_REF(autoAlert),
	       NUTAG_AUTOANSWER_REF(autoAnswer),
	       NUTAG_AUTOACK_REF(autoACK),
	       NUTAG_ENABLEINVITE_REF(enableInvite),
	       NUTAG_ENABLEMESSAGE_REF(enableMessage),
	       NUTAG_ENABLEMESSENGER_REF(enableMessenger),
	       NUTAG_CALLEE_CAPS_REF(callee_caps),
	       NUTAG_PATH_ENABLE_REF(path_enable),
	       NUTAG_SERVICE_ROUTE_ENABLE_REF(service_route_enable),
#if HAVE_SMIME
	       NUTAG_SMIME_ENABLE_REF(smime_enable),
	       NUTAG_SMIME_OPT_REF(smime_opt),
	       NUTAG_SMIME_PROTECTION_MODE_REF(smime_protection_mode),
	       NUTAG_SMIME_MESSAGE_DIGEST_REF(smime_message_digest),
	       NUTAG_SMIME_SIGNATURE_REF(smime_signature),
	       NUTAG_SMIME_KEY_ENCRYPTION_REF(smime_key_encryption),
	       NUTAG_SMIME_MESSAGE_ENCRYPTION_REF(smime_message_encryption),
	       NUTAG_CERTIFICATE_DIR_REF(smime_path),
#endif
#if HAVE_SRTP
	       NUTAG_SRTP_ENABLE_REF(nua->srtp->srtp_enable),
	       NUTAG_SRTP_INTEGRITY_PROTECTION_REF(nua->srtp->srtp_integrity_protection),
	       NUTAG_SRTP_CONFIDENTIALITY_REF(nua->srtp->srtp_confidentiality),
#endif
	       NUTAG_REGISTRAR_REF(registrar),
	       SIPTAG_FROM_REF(from),
	       SIPTAG_FROM_STR_REF(fromstr),
	       SIPTAG_ORGANIZATION_REF(organization),
	       SIPTAG_ORGANIZATION_STR_REF(organization_str),
	       SIPTAG_SUPPORTED_REF(supported),
	       SIPTAG_SUPPORTED_STR_REF(supported_str),
	       SIPTAG_ALLOW_REF(allow),
	       SIPTAG_ALLOW_STR_REF(allow_str),
	       NUTAG_USER_AGENT_REF(user_agent),
	       NUTAG_MEDIA_FEATURES_REF(media_features),
	       NUTAG_MEDIA_EVENT_PATH_REF(media_event),
	       TAG_NULL()))
    return;

#if 0
  reinit_contact = 
    nua->nua_default->nh_callee_caps != callee_caps ||
    media_path != NONE ||
    allow != NONE || allow_str != NONE;
#endif

  if (af != nua->nua_media_af &&
      af >= NUTAG_AF_ANY && af <= NUTAG_AF_IP6_IP4)
    nua->nua_media_af = af;

  if (invite_timer > 0 && invite_timer < 30)
    invite_timer = 30;
  nua->nua_invite_timer = invite_timer;
  nua->nua_session_timer = session_timer;
  if (min_se > 0 && min_se < 30)
    min_se = 30;
  nua->nua_min_se = min_se;
  if (session_timer > 0) {
    if (session_timer < 30)
      session_timer = 30;
    if (session_timer < min_se)
      session_timer = min_se;
  }
  if (refresher >= nua_remote_refresher)
    nua->nua_refresher = nua_remote_refresher;
  else if (refresher <= nua_no_refresher)
    nua->nua_refresher = nua_no_refresher;
  else
    nua->nua_refresher = refresher;

  nua->nua_default->nh_update_refresh = update_refresh != 0;
  nua->nua_autoAlert = autoAlert != 0;
  nua->nua_autoAnswer = autoAnswer != 0;
  nua->nua_enableInvite = enableInvite != 0;
  nua->nua_enableMessage = enableMessage != 0;
  nua->nua_enableMessenger = enableMessenger != 0;
  nua->nua_default->nh_auto_ack = autoACK != 0;
  nua->nua_default->nh_early_media = early_media != 0;
  nua->nua_default->nh_media_features = media_features != 0;
  nua->nua_default->nh_callee_caps = callee_caps != 0;
  nua->nua_path_enable = path_enable != 0;
  nua->nua_service_route_enable = service_route_enable != 0;
  
#if HAVE_SMIME 		/* Start NRC Boston */
  /* XXX - all S/MIME other parameters? */
  sm_set_params(nua->sm, smime_enable, smime_opt, smime_protection_mode, smime_path);
#endif                  /* End NRC Boston */

#define update_header(nua, name, header, str) \
  if (header != NONE || str != NONE) { \
    sip_##name##_t *new_header; \
    if (header != NONE) \
      new_header = sip_##name##_dup(nua->nua_home, header); \
    else  \
      new_header = sip_##name##_make(nua->nua_home, str); \
    if (new_header != NULL || (header == NULL || str == NULL)) { \
      if (nua->nua_##name != NONE)  \
	su_free(nua->nua_home, nua->nua_##name); \
      nua->nua_##name = new_header; \
    } \
  }

  update_header(nua, supported, supported, supported_str);
  update_header(nua, allow, allow, allow_str);

  if (organization == NULL) {
    su_free(nua->nua_home, (void *)nua->nua_organization);
    nua->nua_organization = NULL;
  }
  else if (organization != NONE &&
	   str0cmp(organization->g_string, nua->nua_organization)) {
    su_free(nua->nua_home, (void *)nua->nua_organization);
    nua->nua_organization = su_strdup(nua->nua_home, organization->g_string);
  }
  else if (organization_str == NULL) {
    su_free(nua->nua_home, (void *)nua->nua_organization);
    nua->nua_organization = NULL;
  }
  else if (organization_str != NONE &&
	   str0cmp(organization_str, nua->nua_organization)) {
    su_free(nua->nua_home, (void *)nua->nua_organization);
    nua->nua_organization = su_strdup(nua->nua_home, organization_str);
  } 

  if (media_address != NONE &&
      str0casecmp(media_address, nua->nua_media_address)) {
    su_free(nua->nua_home, (void *)nua->nua_media_address);
    nua->nua_media_address = su_strdup(nua->nua_home, media_address);
  }

/* XXX: */
#if HAVE_MSS
  /* Media description */
#if 0
  // pp: check this
  if (nua->nua_mss == NULL) {
#endif

    if (media_descs != NONE) {
      su_free(nua->nua_home, (void *)nua->nua_media_descs);
      if (media_descs)
	nua->nua_media_descs = 	
	  su_sprintf(nua->nua_home, MSS_CREATE_DESCS "%s", media_descs);
      else
	 nua->nua_media_descs = NULL;
    }

    if (media_params != NONE) {
      su_free(nua->nua_home, (void *)nua->nua_media_params);
      nua->nua_media_params = su_strdup(nua->nua_home, media_params);
    }
#if 0
  }
#endif
#endif /* HAVE_MSS */

  if (media_path != NONE) {
    if (media_path == NULL) media_path = "/";
    su_free(nua->nua_home, (void *)nua->nua_media_path);
    nua->nua_media_path = su_strdup(nua->nua_home, media_path);
  }

  if (registrar != NONE) {
    if (registrar &&
	(url_string_p(registrar) ? 
	 strcmp(registrar->us_str, "*") == 0 :
	 registrar->us_url->url_type == url_any))
      registrar = NULL;
    su_free(nua->nua_home, nua->nua_registrar);
    nua->nua_registrar = url_hdup(nua->nua_home, registrar->us_url);
  }

  if (from != NONE) {
    /* XXX We leak here: su_free(nua->nua_home, nua->nua_from); */
    ua_set_from(nua, sip_from_dup(nua->nua_home, from));
  }
  else if (fromstr != NONE) {
    /* XXX su_free(nua->nua_home, nua->nua_from); */
    if (fromstr && fromstr[0])
      ua_set_from(nua, sip_from_make(nua->nua_home, fromstr));
    else
      ua_set_from(nua, NULL);
  }

  if (user_agent != nua->nua_ua_name) {
    char *me = su_strdup(nua->nua_home, user_agent);

    su_free(nua->nua_home, (void *)nua->nua_ua_name);
    nua->nua_ua_name = me;

    su_free(nua->nua_home, (void *)nua->nua_user_agent);
    nua->nua_user_agent = 
      sip_user_agent_format(nua->nua_home, "%s%snua/" NUA_VERSION " %s",
			    me ? me : "", me ? " " : "", 
			    nta_agent_version(nua->nua_nta));
  }

  if (media_event) {
    su_strlst_t *events = nua->nua_media_events;
    tagi_t const *tl;
    
    for (tl = (tagi_t *)tags; tl; tl = tl_next(tl)) {
      if ((tl = tl_find(tl, nutag_media_event_path))) {
	msg_param_t path = (msg_param_t)tl->t_value;
	size_t i, len = su_strlst_len(events);

	for (i = 0; i < len; i++) 
	  if (strcmp(path, su_strlst_item(events, i)) == 0)
	    break;

	if (i == len)
	  su_strlst_dup_append(events, path);
      }
    }
  }

  ua_init_contact(nua);

  su_home_deinit(tmphome);
}

void
ua_get_params(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  tagi_t *lst, *params;
  sip_from_t from[1];

  unsigned udp_mtu = 0, sip_t1 = 0, sip_t2 = 0, sip_t4 = 0, sip_t1x64 = 0;
  unsigned debug_drop_prob = 0;
  url_string_t const *proxy = NULL;
  sip_contact_t const *aliases = NULL;
  unsigned flags = 0;
  char const *media_descs;
  sip_organization_t organization[1];
  tagi_t *media_events;

  enter;

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

  *from = *nua->nua_from; from->a_params = NULL;
  media_descs = NULL;
/* XXX: */
#if HAVE_MSS
  if (nua->nua_media_descs)
    media_descs = nua->nua_media_descs + strlen(MSS_CREATE_DESCS);
  else
#endif

  sip_organization_init(organization)->g_string = nua->nua_organization;

  if (nua->nua_media_events) {
    su_strlst_t *events = nua->nua_media_events;
    size_t i, len = su_strlst_len(events);
    media_events = su_zalloc(NULL, (len + 1) * sizeof *media_events);
    if (media_events) {
      for (i = 0; i < len; i++) {
	media_events[i].t_tag = nutag_media_event_path;
	media_events[i].t_value = (tag_value_t)su_strlst_item(events, i);
      }
    }
  } 
  else {
    media_events = NULL;
  }

  params = tl_list(NUTAG_AF(nua->nua_media_af),
/* XXX: */
#if HAVE_MSS
		   NUTAG_MEDIA_SUBSYSTEM(nua->nua_mss),
#endif
		   NUTAG_MEDIA_ENABLE(nua->nua_media_enable),
		   NUTAG_MEDIA_FEATURES(nua->nua_default->nh_media_features),
		   NUTAG_MEDIA_ADDRESS(nua->nua_media_address),
		   NUTAG_MEDIA_PATH(nua->nua_media_path),
		   NUTAG_MEDIA_DESCS(media_descs),
		   NUTAG_MEDIA_PARAMS(nua->nua_media_params),
		   NUTAG_EARLY_MEDIA(nua->nua_default->nh_early_media),
		   NUTAG_INVITE_TIMER(nua->nua_invite_timer),
		   NUTAG_SESSION_TIMER(nua->nua_session_timer),
		   NUTAG_MIN_SE(nua->nua_min_se),
		   NUTAG_SESSION_REFRESHER(nua->nua_default->nh_ss->ss_refresher),
		   NUTAG_UPDATE_REFRESH(nua->nua_default->nh_update_refresh),
		   NUTAG_AUTOALERT(nua->nua_autoAlert),
		   NUTAG_AUTOANSWER(nua->nua_autoAnswer),
		   NUTAG_AUTOACK(nua->nua_default->nh_auto_ack),
		   NUTAG_ENABLEINVITE(nua->nua_enableInvite),
		   NUTAG_ENABLEMESSAGE(nua->nua_enableMessage),
		   NUTAG_ENABLEMESSENGER(nua->nua_enableMessenger),
		   NUTAG_CALLEE_CAPS(nua->nua_default->nh_callee_caps),
		   NUTAG_PATH_ENABLE(nua->nua_path_enable),
		   NUTAG_SERVICE_ROUTE_ENABLE(nua->nua_service_route_enable),
#if HAVE_SMIME		/* Start NRC Boston */
		   NUTAG_SMIME_ENABLE(nua->sm->sm_enable),
		   NUTAG_SMIME_OPT(nua->sm->sm_opt),
		   NUTAG_SMIME_PROTECTION_MODE(nua->sm->sm_protection_mode),
		   NUTAG_SMIME_MESSAGE_DIGEST(nua->sm->sm_message_digest),
		   NUTAG_SMIME_SIGNATURE(nua->sm->sm_signature),
		   NUTAG_SMIME_KEY_ENCRYPTION(nua->sm->sm_key_encryption),
		   NUTAG_SMIME_MESSAGE_ENCRYPTION(nua->sm->sm_message_encryption),
#endif                  /* End NRC Boston */
#if HAVE_SRTP
		   NUTAG_SRTP_ENABLE(nua->srtp->srtp_enable),
		   NUTAG_SRTP_CONFIDENTIALITY(nua->srtp->srtp_confidentiality),
		   NUTAG_SRTP_INTEGRITY_PROTECTION(nua->srtp->srtp_integrity_protection),
#endif
		   NUTAG_REGISTRAR(nua->nua_registrar),
		   NTATAG_CONTACT(nua->nua_contact ? nua->nua_contact :
				  nua->nua_sips_contact),
		   SIPTAG_FROM(from),
		   SIPTAG_ALLOW(nua->nua_allow),
		   SIPTAG_SUPPORTED(nua->nua_supported),
		   SIPTAG_ORGANIZATION(nua->nua_organization ? 
				       organization : NULL),
		   SIPTAG_ORGANIZATION_STR(nua->nua_organization),
		   NTATAG_UDP_MTU(udp_mtu),
		   NTATAG_SIP_T1(sip_t1),
		   NTATAG_SIP_T2(sip_t2),
		   NTATAG_SIP_T4(sip_t4),
		   NTATAG_SIP_T1X64(sip_t1x64),
		   NTATAG_DEBUG_DROP_PROB(debug_drop_prob),
		   NTATAG_DEFAULT_PROXY(proxy),
		   NTATAG_ALIASES(aliases),
		   NTATAG_SIPFLAGS(flags),
		   TAG_NEXT(media_events));

  lst = tl_afilter(NULL, tags, params);
  ua_event(nua, nh, NULL, nua_r_get_params, SIP_200_OK, TAG_NEXT(lst));
  su_free(NULL, lst);
  if (media_events)
    su_free(NULL, media_events);
  tl_vfree(params);
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
    nh->nh_ss->ss_state > init_session &&
    nh->nh_ss->ss_state < terminated_session;
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
  assert(nh); assert(nh != nua->nua_default);

  nh_enter;

  if (nh->nh_notifier)
    nea_server_destroy(nh->nh_notifier), nh->nh_notifier = NULL;

  crequest_deinit(nh->nh_cr, NULL);
  if (nh->nh_ss)
    crequest_deinit(nh->nh_ss->ss_crequest, NULL);

  if (nh->nh_ds->ds_leg) {
    nta_leg_destroy(nh->nh_ds->ds_leg), nh->nh_ds->ds_leg = NULL;
  }

  if (nh->nh_ss->ss_invite_irq) {
    nta_incoming_destroy(nh->nh_ss->ss_invite_irq);
    nh->nh_ss->ss_invite_irq = NULL;
  }

  if (nmedia_is_ready(nh->nh_nm))
    nmedia_teardown(nua, nh->nh_nm, nh);

  if (nh_is_inserted(nh))
    nh_remove(nua, nh);

  nh_decref(nh);
}

static
void crequest_deinit(struct nua_client_request *cr, nta_outgoing_t *orq)
{
  if (orq == NULL || orq == cr->cr_orq) {
    cr->cr_retry_count = 0;
    cr->cr_sent_offer = cr->cr_recv_answer = 0;

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

/** Initialize handle Allow and authentication info */
static
void nh_init(nua_t *nua, nua_handle_t *nh, 
	     enum nh_kind kind,
	     char const *default_allow,
	     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;

  nua_handle_t *nh_default = nua->nua_default;

  int media_enable = nua->nua_media_enable;
  int media_features = nh_default->nh_media_features;
  int autoACK = nh_default->nh_auto_ack;
  int early_media = nh_default->nh_early_media;
  int update_refresh = nh_default->nh_update_refresh;

  sip_allow_t const *allow = NULL;
  char const *allowstr = NULL;

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

  if (nh->nh_init)		  /* Already initialized? */
    return;

  ta_start(ta, tag, value);

  tl_gets(nh->nh_tags,
	  SIPTAG_ALLOW_REF(allow),
	  SIPTAG_ALLOW_STR_REF(allowstr),
	  NUTAG_ALLOW_REF(default_allow),
	  NUTAG_MEDIA_ENABLE_REF(media_enable),
	  NUTAG_MEDIA_FEATURES_REF(media_features),
	  NUTAG_AUTOACK_REF(autoACK),
	  NUTAG_EARLY_MEDIA_REF(early_media),
	  NUTAG_UPDATE_REFRESH_REF(update_refresh),
	  TAG_END());

  tl_gets(ta_args(ta),
	  SIPTAG_ALLOW_REF(allow),
	  SIPTAG_ALLOW_STR_REF(allowstr),
	  NUTAG_ALLOW_REF(default_allow),
	  NUTAG_MEDIA_ENABLE_REF(media_enable),
	  NUTAG_MEDIA_FEATURES_REF(media_features),
	  NUTAG_AUTOACK_REF(autoACK),
	  NUTAG_EARLY_MEDIA_REF(early_media),
	  NUTAG_UPDATE_REFRESH_REF(update_refresh),
	  TAG_END());

#if HAVE_UICC_H
  if (nh->nh_has_register && nua->nua_uicc)
    auc_with_uicc(&nh->nh_auth, nh->nh_home, nua->nua_uicc);
#endif

  if (nh->nh_tags)
    nh_authorize(nh, TAG_NEXT(nh->nh_tags));

  if (allow)
    nh->nh_allow = sip_allow_dup(nh->nh_home, allow);
  else if (allowstr)
    nh->nh_allow = sip_allow_make(nh->nh_home, allowstr);
  else if (default_allow)
    nh->nh_allow = sip_allow_make(nh->nh_home, default_allow);

  if (nh->nh_allow == NULL)
    nh->nh_allow = nua->nua_allow;

  nh->nh_ss->ss_min_se = nua->nua_min_se;
  nh->nh_ss->ss_session_timer = nua->nua_session_timer;
  nh->nh_ss->ss_refresher = nua->nua_refresher;

  nh->nh_early_media = early_media;
  nh->nh_media_features = media_features;
  nh->nh_update_refresh = update_refresh;
  nh->nh_auto_ack = autoACK != 0;

/* XXX: */
#if HAVE_MSS
  if (media_enable && nua->nua_mss) {
    struct nua_media_state *nm = nh->nh_nm;

    nm->nm_mss = nua->nua_mss;
    nm->nm_af = nua->nua_default->nh_nm->nm_af;
    nmedia_set_param(nm, nh->nh_home, MS_CONN_LIST,
		     &nm->nm_address, nua->nua_media_address);

    if (nh->nh_tags)
      nmedia_save_params(nm, nh->nh_home, 0, nh->nh_tags);
    nmedia_save_params(nm, nh->nh_home, 0, ta_args(ta));

    if (!nm->nm_path)
      nm->nm_path = su_strdup(nh->nh_home, nua->nua_media_path);
  }
#endif

  ta_end(ta);


  nh->nh_init = 1;
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

  if (nh) {
    nh_init(nh->nh_nua, nh, kind, default_allow, TAG_END());

    if (create_dialog) {
      struct nua_dialog_state *ds = nh->nh_ds;

      dialog_get_peer_info(nh, sip);

      ds->ds_leg = nta_leg_tcreate(nua->nua_nta, process_request, nh,
				   SIPTAG_CALL_ID(sip->sip_call_id),
				   SIPTAG_FROM(sip->sip_to),
				   SIPTAG_TO(sip->sip_from),
				   NTATAG_REMOTE_CSEQ(sip->sip_cseq->cs_seq),
				   TAG_END());

      nta_leg_tag(ds->ds_leg, nta_incoming_tag_3261(irq, NULL));

      if (!ds->ds_leg)
	nh_destroy(nua, nh), nh = NULL;
    }
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
	nta_msg_discard(nua->nua_nta, cr->cr_msg), cr->cr_msg = NULL;
    }
    msg = nta_msg_create(nua->nua_nta, 0);
    tl_gets(nh->nh_tags, NUTAG_URL_REF(url), TAG_END());
    sip_add_tl(msg, sip_object(msg), TAG_NEXT(nh->nh_tags));
  }

  if (msg) {
    ta_list ta;
    int use_leg = 0, add_contact = 0;

    sip = sip_object(msg);

    ta_start(ta, tag, value);

    tl_gets(ta_args(ta),
	    NUTAG_URL_REF(url),
	    NUTAG_USE_LEG_REF(use_leg),
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
	nta_msg_discard(nua->nua_nta, msg), msg = NULL;
    }
    else {
      // tl_gets(ta_args(ta), TAG_END());

      if ((sip_add_tl(msg, sip, 
		      TAG_IF(method != sip_method_register,
			     SIPTAG_ROUTE(nua->nua_service_route)),
		      ta_tags(ta)) < 0)
	  || (ds->ds_remote_tag && 
	      sip_to_tag(nh->nh_home, sip->sip_to, ds->ds_remote_tag) < 0) 
	  || nta_msg_request_complete(msg, nua->nua_default->nh_ds->ds_leg,
				      method, name, url) < 0 
	  || (sip->sip_from == NULL &&
	      sip_add_dup(msg, sip, (sip_header_t *)nua->nua_from) < 0))
	nta_msg_discard(nua->nua_nta, msg), msg = NULL;

      if (use_leg && msg) {
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

    if (!sip->sip_user_agent && nua->nua_user_agent) 
      sip_add_dup(msg, sip, (sip_header_t *)nua->nua_user_agent);      
    
    if (method != sip_method_ack) {
      if (!sip->sip_allow && !ds->ds_remote_tag) 
	sip_add_dup(msg, sip, (sip_header_t*)nua->nua_allow);

      if (!sip->sip_supported && nua->nua_supported)
	sip_add_dup(msg, sip, (sip_header_t *)nua->nua_supported);      

      if (method == sip_method_register && nua->nua_path_enable &&
	  !sip_has_feature(sip->sip_supported, "path") &&
	  !sip_has_feature(sip->sip_require, "path"))
	sip_add_make(msg, sip, sip_supported_class, "path");

      if (!sip->sip_organization && nua->nua_organization) 
	sip_add_make(msg, sip, sip_organization_class, nua->nua_organization);

      if (nh->nh_auth) {
	nh_authorize(nh, ta_tags(ta));
      
	if (method != sip_method_invite && 
	    method != sip_method_update &&
	    /* auc_authorize() removes existing authentication headers */
	    auc_authorize(&nh->nh_auth, msg, sip) < 0)
	  msg_destroy(msg), msg = NULL;
      }
    } else /* ACK */ {
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
  else if (sip_message_complete(msg) < 0)
    msg_destroy(msg);      
  else if (add_contact && !sip->sip_contact && sip_add_dup(msg, sip, m) < 0)
    msg_destroy(msg);
  else if (!sip->sip_supported && nua->nua_supported &&
	   sip_add_dup(msg, sip, (sip_header_t *)nua->nua_supported) < 0)
    msg_destroy(msg);
  else if (!sip->sip_user_agent && nua->nua_user_agent &&
	   sip_add_dup(msg, sip, (sip_header_t *)nua->nua_user_agent) < 0)
    msg_destroy(msg);
  else if (!sip->sip_organization && nua->nua_organization &&
	   sip_add_make(msg, sip, sip_organization_class, 
			nua->nua_organization) < 0)
    msg_destroy(msg);
  else if (!sip->sip_allow && nua->nua_allow &&
	   sip_add_dup(msg, sip, (sip_header_t *)nua->nua_allow) < 0)
    msg_destroy(msg);
  else
    return msg;
  
  return NULL;
}

/* ====================================================================== */
/* Default media handling */

static inline 
void *nmedia_set_status(struct nua_media_state *nm, 
			int status, char const *phrase);
static int nmedia_get_status(struct nua_media_state *nm, int except, ...);
static void nmedia_error_to_sip_response(struct nua_media_state *nm,
					 int *return_status,
					 char const **return_phrase);

static void nmedia_set_activity(struct nua_media_a *, 
				sdp_media_t const *, 
				int remote);

static char const ** nmedia_param_list(nua_t *nua,
				       struct nua_media_state *nm, 
				       nua_handle_t *nh,
				       su_strlst_t *l,
				       tagi_t const *tags);

static inline int nmedia_is_enabled(struct nua_media_state *nm)
{
/* XXX: */
#if HAVE_MSS
  return nm->nm_mss != NULL;
#else
  return 0;
#endif
}

static inline int nmedia_is_ready(struct nua_media_state *nm)
{
/* XXX: */
#if HAVE_MSS
  return nm->nm_session != NULL;
#else
  return 0;
#endif
}

sdp_session_t *nmedia_describe(nua_t *nua,
			       struct nua_media_state *nm,
			       nua_handle_t *nh, 
			       su_home_t *home)
{
  su_strlst_t *l;
  char const **params;
  sdp_session_t *sdp = NULL;

  assert(home);

  if (!nmedia_is_enabled(nm))
    return nmedia_set_status(nm, 500, "Media is disabled");

/* XXX: */
#if HAVE_MSS
  if (nm->nm_session == NULL || nm->nm_modified) {
    l = su_strlst_create(home); 
    if (!l)
      return nmedia_set_status(nm, 500, "Internal error");
    params = nmedia_param_list(nua, nm, nh, l, NULL);
  }
  else {
    l = NULL;
    params = NULL;
  }

  /* XXX: get the local SDP */

  if (l)
    su_strlst_destroy(l);

  if (nmedia_get_status(nm, 0) < 0)
    return NULL;

  if (!sdp) {
    nmedia_set_status(nm, 500, "Internal media error");
    return NULL;
  }

  if (nm->nm_session)
    nmedia_set_activity(nm->nm_active, sdp->sdp_media, 0);
#endif

  return sdp;
}

/**
 *
 * @retval 1 real mss_setup() done
 * @retval 0 no mss_setup()
 * @retval -1 error
 */
int nmedia_setup(nua_t *nua,
		 struct nua_media_state *nm,
		 nua_handle_t *nh,
		 nua_event_t ee,
		 sdp_session_t const *sdp, char const *offer_answer, 
		 int required)
{
/* XXX: */
#if HAVE_MSS
  ms_t *old_session = nm->nm_session;
  su_strlst_t *l;
  char const **params;

  if (!nmedia_is_enabled(nm))
    return 0;

  /* Can we avoid setup?? */
  if (!required && 
      ee == nua_i_media_error &&
      old_session != NULL &&
      !(sdp && offer_answer) &&
      !nm->nm_modified) {
    SU_DEBUG_5(("nua(%p): avoiding local media setup\n", nh));
    return 0;
  }

  l = su_strlst_create(nh->nh_home); if (!l) return -1;

  if (sdp && offer_answer)
    su_strlst_append(l, offer_answer);

  params = nmedia_param_list(nua, nm, nh, l, NULL);
  nua->nua_media_handle = nh;	/* used by callback */
  mss_setup(nm->nm_mss, &nm->nm_session, nm->nm_path, params, sdp);
  nua->nua_media_handle = NULL;
  su_strlst_destroy(l);

  if (nmedia_get_status(nm, 0) < 0) {
    /* XXX - warning header */
    assert(nm->nm_session == NULL || nm->nm_session == old_session);
    ua_event(nua, nh, NULL, ee,
	     nm->nm_status, nm->nm_phrase, 
	     NUTAG_MEDIA_SESSION(nm->nm_session),
	     TAG_END());
    return -1;
  } 
  assert(nm->nm_session != NULL);

  nmedia_set_status(nm, SIP_200_OK);

  nm->nm_clone = 0;
  nm->nm_modified = 0;  
  nm->nm_muted = nm->nm_hold_remote;

  if (sdp)
    nmedia_set_activity(nm->nm_active, sdp->sdp_media, 1);

  if (ee != nua_i_media_error)
    ua_event(nua, nh, NULL, ee,
	     nm->nm_status, nm->nm_phrase, 
	     NUTAG_MEDIA_SESSION(nm->nm_session),
	     TAG_END());
  
  if (old_session != nm->nm_session)
    nmedia_event_bind(nua, nm, nh);

#endif  
  return 1;
}

/** Start playing media 
 *
 * The function nmedia_play() starts to receive media and play it out to
 * user.
 */
int nmedia_play(nua_t *nua, struct nua_media_state *nm)
{
  if (!nmedia_is_enabled(nm))
    return 0;

/* XXX: */
#if HAVE_MSS
  /* XXX: activate media subsystem to process incoming streams */
#endif

  return nmedia_get_status(nm, 200, 405, 455, 0);
}

int nmedia_record(nua_t *nua, struct nua_media_state *nm)
{
  if (!nmedia_is_enabled(nm) || nm->nm_muted)
    return 0;

/* XXX: */
#if HAVE_MSS
  /* XXX: activate media subsystem to start generating outgoing streams */
#endif

  return nmedia_get_status(nm, 200, 405, 455, 0);
}

int nmedia_pause(nua_t *nua, struct nua_media_state *nm, char const *direction)
{
  char const *params[2] = { NULL };

  if (!nmedia_is_enabled(nm))
    return 0;
  
  params[1] = direction;

/* XXX: */
#if HAVE_MSS
  /* XXX: temporarily disable media subsystem operation */
#endif

  return nmedia_get_status(nm, 200, 405, 455, 0);
}

int nmedia_teardown(nua_t *nua, struct nua_media_state *nm,
		    nua_handle_t *nh)
{
  if (nm->nm_session == NULL) {
    nmedia_set_status(nm, SIP_200_OK);
    return 0;
  }

  nmedia_set_activity(nm->nm_active, NULL, 0);

  nua->nua_media_handle = nh;
/* XXX: */
#if HAVE_MSS
  /* XXX: close down media subsystem resources */
#endif
  nua->nua_media_handle = NULL;

  return nmedia_get_status(nm, 0);
}

void nmedia_event_bind(nua_t *nua,
		       struct nua_media_state *nm,
		       nua_handle_t *nh)
{
  su_strlst_t *eventlist;

  int i, len;

/* XXX: */
#if HAVE_MSS
  /* XXX: subscribe to events from the media subsystem */
#endif

  return;
}

void nmedia_event_handler(mss_t *mss, ms_t *mms, 
			  nua_handle_t *nh,
			  char const *path,
			  char const *params[],
			  void const *data, int dlen)
{
/* XXX: */
#if HAVE_MSS
  /* XXX: receive events from the media subsystem */
#endif
}

/** Send an event to mss.
 *
 * @retval 0 success
 * @retval -1 error
 */
int nmedia_event(nua_t *nua,
		 struct nua_media_state *nm,
		 nua_handle_t *nh,
		 tagi_t const *tags)
{
  char const *path = nm->nm_path;
  void *data = NULL;
  unsigned dlen = 0;

  if (!nmedia_is_enabled(nm))
    return 0;

/* XXX: */
#if HAVE_MSS
  
  /* XXX: send an event to media subsystem */
  nmedia_get_status(nm, 0);

#endif

  return 0;
}

static inline 
void *
nmedia_set_status(struct nua_media_state *nm, int status, char const *phrase)
{
  nm->nm_status = status, nm->nm_phrase = phrase;
  return NULL;
}

/**Get status from MSS.
 *
 * Store it in nua_media_state structure unless it is one 
 * of status numbers or classes listed as exceptions.
 *
 * @return 0 if status indicated success or it was an exception
 * @return -1 if status indicated failure
 */
static 
int nmedia_get_status(struct nua_media_state *nm,
		      int except, 
		      ...)
{
  int status; 
  char const *phrase;

/* XXX: */
#if HAVE_MSS

  /* XXX: query current status of media subsystem */

#endif

  if (status >= 200 && status < 300) 
    return 0;
  else
    return -1;
}
   
/**Convert MSS status to SIP status.
 *
 */
static 
void nmedia_error_to_sip_response(struct nua_media_state *nm,
				  int *return_status,
				  char const **return_phrase)
{
  int status = nm->nm_status;

  if (200 <= status && status < 300)
    return;
  else if (status == 406 || status == 412 || status == 415 || 
	   status == 451 || status == 456 || status == 461)
    *return_status = 488, *return_phrase = sip_488_Not_acceptable;
  else
    *return_status = 500, *return_phrase = "Internal Media Error";
}

/**Convert MSS status to SIP reason.
 *
 */
static 
char const *
nmedia_error_to_sip_reason(struct nua_media_state *nm)
{
  int status = nm->nm_status;

  if (200 <= status && status < 300)
    return NULL;
  else if (status == 406 || status == 412 || status == 415 || 
	   status == 451 || status == 456 || status == 461)
    return "SIP;cause=488;text=\"Not acceptable here\"";
  else
    return "SIP;cause=500;text=\"Internal media error\"";
}

   
static void nmedia_set_activity(struct nua_media_a *ma, 
				sdp_media_t const *m,
				int remote)
{
  sdp_connection_t const *c;
  int mode;

  remote = !!remote;

  ma->ma_audio = ma->ma_video = ma->ma_chat = ma->ma_image = 
    nua_active_disabled;
      
  for (; m; m = m->m_next) {
    if (m->m_rejected)
      continue;

    mode = m->m_mode;

    c = sdp_media_connections((sdp_media_t *)m);

    if (remote != (c && c->c_mcast))
      mode = ((mode << 1) & 2) | ((mode >> 1) & 1); 

    if (m->m_type == sdp_media_audio)
      ma->ma_audio |= mode;
    else if (m->m_type == sdp_media_video)
      ma->ma_video |= mode;
    else if (m->m_type == sdp_media_image)
      ma->ma_image |= mode;
    else if (strcasecmp(m->m_type_name, "message") == 0)
      ma->ma_chat |= mode;
  }
  
  if (ma->ma_audio != nua_active_disabled)
    ma->ma_audio &= ~nua_active_disabled;
  if (ma->ma_video != nua_active_disabled)
    ma->ma_video &= ~nua_active_disabled;
  if (ma->ma_image != nua_active_disabled)
    ma->ma_image &= ~nua_active_disabled;
  if (ma->ma_chat != nua_active_disabled)
    ma->ma_chat &= ~nua_active_disabled;
}

static
int nmedia_save_params(struct nua_media_state *nm,
		       su_home_t *home,
		       int copy,
		       tagi_t const *tags)
{
#if HAVE_MSS
  /* XXX: save media parameters described in */
  ms_t *session = nm->nm_session;
#if HAVE_SRTP
  unsigned srtp_enable = nm->nm_srtp_enable;
  unsigned srtp_confidentiality = nm->nm_srtp_confidentiality;
  unsigned srtp_integrity_protection = nm->nm_srtp_integrity_protection;
#endif
  int hold = nm->nm_hold_remote;
  int clone = nm->nm_clone;
  int af = nm->nm_af;

  if (!tags)
    return 0;

  if (tl_gets(tags, 
#if HAVE_SRTP
	      NUTAG_SRTP_ENABLE_REF(srtp_enable),
	      NUTAG_SRTP_INTEGRITY_PROTECTION_REF(srtp_integrity_protection),
	      NUTAG_SRTP_CONFIDENTIALITY_REF(srtp_confidentiality),
#endif
	      NUTAG_MEDIA_SESSION_REF(session),
	      NUTAG_AF_REF(af),
	      NUTAG_MEDIA_CLONE_REF(clone),
	      NUTAG_HOLD_REF(hold),
	      TAG_END())) {
    if (session != nm->nm_session
#if HAVE_SRTP
	|| srtp_enable != nm->nm_srtp_enable
	|| srtp_confidentiality != nm->nm_srtp_confidentiality
	|| srtp_integrity_protection != nm->nm_srtp_integrity_protection
#endif
	|| hold != nm->nm_hold_remote
	|| clone != nm->nm_clone
	|| af != nm->nm_af)
      nm->nm_modified = 1;
  }

#if HAVE_SRTP
  nm->nm_srtp_enable = srtp_enable;
  nm->nm_srtp_confidentiality = srtp_confidentiality;
  nm->nm_srtp_integrity_protection = srtp_integrity_protection;
#endif
  nm->nm_hold_remote = hold;
  nm->nm_clone = clone;
  nm->nm_af = af;

  if (session) {
    if (nm->nm_session == NULL || copy)
      nm->nm_session = session;
    else if (nm->nm_session != session) {
      SU_DEBUG_1(("nua: got media session %p, but already has session %p\n",
		  session, nm->nm_session));
    }
  }

  nmedia_save_param(nm, home, copy, tags, NULL, 
		    NUTAG_MEDIA_PATH_REF(nm->nm_path));
  nmedia_save_param(nm, home, copy, tags, MS_CONN_LIST, 
		    NUTAG_MEDIA_ADDRESS_REF(nm->nm_address));
  nmedia_save_param(nm, home, copy, tags, MS_VIDEO_LOCAL_WINDOW, 
		    NUTAG_VIDEO_LOCAL_REF(nm->nm_video_lw));
  nmedia_save_param(nm, home, copy, tags, MS_VIDEO_REMOTE_WINDOW, 
		    NUTAG_VIDEO_REMOTE_REF(nm->nm_video_rw));
  nmedia_save_param(nm, home, copy, tags, MS_TARGET_IMAGE_NAME, 
		    NUTAG_IMAGE_LOCAL_REF(nm->nm_image_lw));
  nmedia_save_param(nm, home, copy, tags, MS_TARGET_IMAGE_NAME, 
		    NUTAG_TARGET_IMAGE_NAME_REF(nm->nm_image_name));

  for (; tags; tags = tl_next(tags))
    if ((tags = tl_find(tags, nutag_media_event_path))) {
      su_strlst_t *el = nm->nm_event_list;
      if (el == NULL)
	el = nm->nm_event_list = su_strlst_create(home);
      if (el) {
	char *name = su_strdup(su_strlst_home(el), (void *)tags->t_value);
	if (name)
	  su_strlst_append(el, name);
      }
    }

#endif /* HAVE_MSS */

  return nm->nm_modified;
}

static int
nmedia_save_param(struct nua_media_state *nm,
		  su_home_t *home,
		  int copy,
		  tagi_t const *tags,
		  char const *mss_name,
		  tag_type_t tag,
		  tag_value_t tvalue)
{
  char const **pparam = (char const **)tvalue;
  char const *param = *pparam;
  char const *value = NULL;
  size_t prefix;
  
  if (tl_gets(tags, tag, (tag_value_t)&value, TAG_END()) != 1)
    return 0;

  if (param == value)
    return 0;

  prefix = mss_name ? strlen(mss_name) + 1 : 0;

  if (param && value && strcmp(param + prefix, value) == 0)
    return 0;

  if (value && 
      !(prefix
	? (value = su_sprintf(home, "%s=%s", mss_name, value))
	: (value = su_strdup(home, value))))
    return 0;

  if (!copy && param) 
    su_free(home, (void *)param); 

  SU_DEBUG_7(("nua(%p): %s %s\n", home, copy ? "setting" : "saving", value));

  *pparam = value; 

  return nm->nm_modified = 1;
}

static int
nmedia_set_param(struct nua_media_state *nm,
		 su_home_t *home,
		 char const *mss_name,
		 char const **pparam,
		 char const *value)
{
  char const *param = *pparam;
  size_t prefix;
  
  if (param == value)
    return 0;

  prefix = mss_name ? strlen(mss_name) + 1 : 0;

  if (param && value && strcmp(param + prefix, value) == 0)
    return 0;

  if (value && 
      !(prefix
	? (value = su_sprintf(home, "%s=%s", mss_name, value))
	: (value = su_strdup(home, value))))
    return 0;

  if (param) 
    su_free(home, (void *)param); 

  SU_DEBUG_7(("nua(%p): %s %s\n", home, "default", value));

  *pparam = value; 

  return nm->nm_modified = 1;
}

static
char const **nmedia_param_list(nua_t *nua,
			       struct nua_media_state *nm, 
			       nua_handle_t *nh,
			       su_strlst_t *l,
			       tagi_t const *tags)
{
  su_home_t *home;

#if HAVE_SRTP
  srtp_object_t *srtp = nm->nm_srtp;
#endif

#define PARAM(s) (su_strlst_append(l, (s)))

  if (l == NULL)
    return NULL;

  home = su_strlst_home(l);

  if (nm->nm_clone)
    su_strlst_append(l, MS_SETUP_CLONE);
  if (nm->nm_hold_remote)
    su_strlst_append(l, MS_HOLD_REMOTE);

  if (nm->nm_video_lw) PARAM(nm->nm_video_lw);
  if (nm->nm_video_rw) PARAM(nm->nm_video_rw);
#if HAVE_JPIP
  if (nm->nm_image_lw) PARAM(nm->nm_image_lw);
  if (nm->nm_target_image_name) PARAM(nm->nm_target_image_name);
#endif 
#if HAVE_SRTP && 0
  if (srtp->srtp_enable) PARAM(MS_SRTP_ENABLE);
  if (srtp->srtp_confidentiality) PARAM(MS_SRTP_CONFIDENTIALITY);
  if (srtp->srtp_integrity_protection) PARAM(MS_SRTP_INTEGRITY_PROTECTION);
#endif  

  if (nh && nh->nh_ds->ds_local)
    PARAM(su_sprintf(home, MS_LOCAL_URI "=" URL_PRINT_FORMAT,
		     URL_PRINT_ARGS(nh->nh_ds->ds_local->a_url)));
  if (nh && nh->nh_ds->ds_remote)
    PARAM(su_sprintf(home, MS_REMOTE_URI "=" URL_PRINT_FORMAT,
		     URL_PRINT_ARGS(nh->nh_ds->ds_remote->a_url)));
  if (nua->nua_contact) {
    sip_contact_t const *m = nua->nua_contact;
    PARAM(su_sprintf(home, MS_LOCAL_CONTACT"="URL_PRINT_FORMAT,
		     URL_PRINT_ARGS(m->m_url)));
  }
  if (nh && nh->nh_ds->ds_leg) {
    sip_contact_t const *m = NULL;
    nta_leg_get_route(nh->nh_ds->ds_leg, NULL, &m);
    if (m)
      PARAM(su_sprintf(home, MS_REMOTE_CONTACT"="URL_PRINT_FORMAT,
		       URL_PRINT_ARGS(m->m_url)));
  }

  if (nua->nua_media_cname)
    su_strlst_dup_append(l, nua->nua_media_cname);

  if (nm->nm_address) 
    PARAM(nm->nm_address);
  else switch (nm->nm_af) {
  case nutag_af_ip4_only:
    PARAM(MS_CONN_IN_IP4); break;
  case nutag_af_ip6_only:
    PARAM(MS_CONN_IN_IP6); break;
  case nutag_af_ip4_ip6:
    PARAM(MS_CONN_IN_IP4_IP6); break;
  case nutag_af_ip6_ip4:
    PARAM(MS_CONN_IN_IP6_IP4); break;
  default:
    break;
  }

  /* Search for all NUTAG_MEDIA_PARAMS instances */
  for (; tags; tags = tl_next(tags)) {
    tags = tl_find(tags, nutag_media_params);
    if (tags && tags->t_value) 
      PARAM((char const *)tags->t_value);
  }

#undef PARAM  

  return su_strlst_get_array(l);
}


/** Obtain a list of media features from SDP media */
static int
nmedia_features(su_home_t *home, 
		msg_param_t **m_params, 
		sdp_media_t *m,
		int live)
{
  char const *param;
  int retval = 0;

  for (; m; m = m->m_next) {
    if (live && m->m_port == 0)	/* Skip canceled media */
      continue;

    switch (m->m_type) {
    case sdp_media_audio:
    case sdp_media_video:
    case sdp_media_image:
    case sdp_media_data:
    case sdp_media_control:
    case sdp_media_application:
      param = su_strdup(home, m->m_type_name);
      break;
    default:
      param = su_sprintf(home, "+%s", m->m_type_name);
    }

    if (!msg_params_find(*m_params, param)) {
      msg_params_replace(home, m_params, param);
      retval++;
    } else {
      su_free(home, (char *)param);
    }
  }

  return retval;
}

/* ======================================================================== */

char const application_sdp[] = "application/sdp";

/** Get SDP from message payload.
 *
 * @retval pointer to SDP if there is non-duplicate SDP 
 * @retval NULL if there is no SDP or SDP is duplicate
 * @retval NONE upon an error
 */
sdp_session_t const *
nmedia_parse_sdp(nua_handle_t *nh,
		 msg_payload_t const *pl,
		 msg_content_type_t const *ct,
		 struct nua_media_a *ma)
{
  struct nua_media_state *nm = nh->nh_nm;
  sdp_session_t *sdp;

  if (pl == NULL)
    ;
  else if (pl->pl_len == 0)
    pl = NULL, SU_DEBUG_5(("nua: empty payload\n"));
  else if (ct == NULL)
    /* Be bug-compatible with our old gateways */
    SU_DEBUG_3(("nua: no %s, assuming %s\n", 
		"Content-Type", application_sdp));
  else if (ct->c_type == NULL)
    SU_DEBUG_3(("nua: empty %s, assuming %s\n", 
		"Content-Type", application_sdp));
  else if (strcasecmp(ct->c_type, SDP_MIME_TYPE))
    pl = NULL, 
    SU_DEBUG_3(("nua: unknown %s: %s\n", "Content-Type", ct->c_type));

  if (pl) {
    sdp_parser_t *sdp = sdp_parse(nh->nh_home, pl->pl_data, pl->pl_len, 
				  sdp_f_mode_0000);
    if (sdp_parsing_error(sdp)) {
      if (ct && ct->c_type) {
	SU_DEBUG_1(("nua: SDP parsing error: %s\n", sdp_parsing_error(sdp)));
	sdp_parser_free(sdp);
	nmedia_set_status(nm, 400, "Bad Session Description");
	return NONE;
      }
      sdp_parser_free(sdp);	/* This probably was not SDP after all */
    }
    else {
      if (nm->nm_sdp)
	sdp_parser_free(nm->nm_sdp);
      nm->nm_sdp = sdp;
    }
  }
  
  sdp = sdp_session(nm->nm_sdp);

  if (sdp && ma)
    nmedia_set_activity(ma, sdp->sdp_media, 1);

  return sdp;
}

void 
nmedia_clear_sdp(nua_handle_t *nh)
{
  if (nh->nh_nm->nm_sdp)
    sdp_parser_free(nh->nh_nm->nm_sdp), nh->nh_nm->nm_sdp = NULL;
}

/** Get application/sdp payload from sip.
 *    
 * @retval NULL no SDP in payload
 * @retval NONE error in processing SDP payload
 * @retval 493  encryption error
 * @retval other pointer to sdp_session_t structure
 */
sdp_session_t const *
nmedia_parse_sdp_from_sip(nua_handle_t *nh,
			  sip_t const *sip,
			  struct nua_media_a *ma)
{
  nmedia_clear_sdp(nh);

  return nmedia_parse_sdp(nh, 
			  sip->sip_payload, 
			  (msg_content_type_t *)sip->sip_content_type, 
			  ma);
}

int nh_sdp_insert(nua_handle_t *nh,
		  su_home_t *home,
		  msg_t *msg,
		  sip_t *sip,
		  sdp_session_t const *sdp)
{
  sdp_printer_t *printer;

  printer = sdp_print(home, sdp, NULL, 0, sdp_f_realloc);

  if (sdp_message(printer)) {
    sip_payload_t *pl;

    pl = sip_payload_create(msg_home(msg), 
			    (void *)sdp_message(printer),
			    sdp_message_size(printer));

    sdp_printer_free(printer);

    if (pl) {
      sip_header_insert(msg, sip, (sip_header_t *)pl);
      sip_add_dup(msg, sip, (sip_header_t *)nh->nh_nua->nua_sdp_content);
      // sip_add_make(msg, sip, sip_content_disposition_class, "session");
      return 0;
    }
  } else {
    SU_DEBUG_3(("nh_sdp_insert: sdp_print: %s\n",
		sdp_printing_error(printer)));
    sdp_printer_free(printer), printer = NULL;
  }
	     
  return -1;
}

/* ======================================================================== */
/* Update offer/answer states */

/** Initialize offer/answer state machine */
static inline
void nh_init_offer_answer(nua_handle_t *nh)
{
  nh->nh_ss->ss_complete = 0;
  nh->nh_ss->ss_offer_sent = 0;
  nh->nh_ss->ss_offer_recv = 0;
  nh->nh_ss->ss_answer_sent = 0;
  nh->nh_ss->ss_answer_recv = 0;
}

/**Updates O/A state with the received SDP.
 *
 * @param nh nua handle
 * @param sdp (NULL, if o= is identical to previous one)
 */
static
char const *nh_recv_offer_answer(nua_handle_t *nh, 
				 sdp_session_t const *sdp,
				 int *return_new_version)
{
  struct nua_session_state *ss = nh->nh_ss;
  char const *verdict;
  sdp_origin_t const *o;

  assert(sdp); assert(sdp->sdp_origin); assert(ss);

  o = sdp->sdp_origin; 

  if (ss->ss_offer_sent && ss->ss_answer_recv) {
    /* Ignore this for now? */
    verdict = NULL;
    sdp = NULL;
    *return_new_version = 0;
  }
  else if (ss->ss_offer_sent && !ss->ss_answer_recv) {
    verdict = "answer";
    ss->ss_oa_rounds++;
    ss->ss_complete = 1;
    ss->ss_answer_recv = 1;
  }
  else {
    verdict = "offer";
    ss->ss_complete = 0;
    ss->ss_offer_recv = 1; 
    ss->ss_answer_sent = 0;
  }

  if (sdp && sdp_origin_cmp(o, ss->ss_o_remote)) {
    *return_new_version = 1;
    if (ss->ss_o_remote)
      su_free(nh->nh_home, ss->ss_o_remote);
    ss->ss_o_remote = sdp_origin_dup(nh->nh_home, o);
  } else {
    *return_new_version = 0;
  }

  SU_DEBUG_5(("nua: %s: %s (o=%s "LLU" "LLU")\n",
	      "nh_recv_offer_answer", verdict ? verdict : "ignored",
	      o->o_username, (ull)o->o_id, (ull)o->o_version));
  
  return verdict;
}

/** Updates O/A state when sending SDP */
static
char const *nh_sent_offer_answer(nua_handle_t *nh, 
				 sdp_session_t const *sdp,
				 int reliable)
{
  struct nua_session_state *ss = nh->nh_ss;
  char const *verdict;
  sdp_origin_t const *o;

  assert(sdp); assert(ss);

  if (ss->ss_offer_recv && !ss->ss_answer_sent) {
    verdict = "answer";
    ss->ss_oa_rounds++;
    ss->ss_complete = 1;
    ss->ss_answer_sent = reliable ? 2 : 1;
  } 
  else {
    verdict = "offer";
    ss->ss_complete = 0;
    ss->ss_offer_sent = 1;
    ss->ss_answer_recv = 0;
  }

  o = sdp->sdp_origin; assert(o);
  
  if (sdp_origin_cmp(o, ss->ss_o_local)) {
    if (ss->ss_o_local)
      su_free(nh->nh_home, ss->ss_o_local);
    ss->ss_o_local = sdp_origin_dup(nh->nh_home, o);
  }

  SU_DEBUG_5(("nua: %s: %s (o=%s "LLU" "LLU")\n",
	      "nh_sent_offer_answer", verdict ? verdict : "ignored", 
	      o->o_username, (ull)o->o_id, (ull)o->o_version));

  return verdict;
}

/* ======================================================================== */

/** Store SDP from incoming response */
static
int session_process_response(nua_handle_t *nh,
			     struct nua_client_request *cr,
			     nta_outgoing_t *orq,
			     sip_t const *sip)
{
  sdp_session_t const *sdp;
  struct nua_media_a ma[1];

  if (!nmedia_is_enabled(nh->nh_nm))
    return process_response(nh, cr, orq, sip, TAG_END());

  sdp = nmedia_parse_sdp_from_sip(nh, sip, ma);

  if (sdp == NONE) {
    process_response(nh, cr, orq, sip, TAG_END());
    return -1;
  }

  if (sdp && cr->cr_sent_offer) {
    if (cr->cr_recv_answer) {
      /* Ignore spurious answers after completing O/A */
      SU_DEBUG_5(("nua: ignoring duplicate SDP in %u %s\n", 
		  sip->sip_status->st_status, sip->sip_status->st_phrase));
      nmedia_clear_sdp(nh);
      sdp = NULL;
    }
    else {
      cr->cr_recv_answer = 1;
    }
  }

  return process_response(nh, cr, orq, sip, 
			  NH_ACTIVE_MEDIA_TAGS(sdp != NULL, ma),
			  TAG_END());
}

/** Process remote sdp (offer/answer) for a session */
static
int 
session_offer_answer(nua_handle_t *nh,
		     su_home_t *home,
		     sip_content_disposition_t **return_disposition,
		     sip_content_type_t **return_type,
		     sip_payload_t **return_payload,
		     int should_send_offer)
{
  nua_t *nua = nh->nh_nua;
  struct nua_media_state *nm = nh->nh_nm;
  int new_sdp, setup;
  sdp_session_t *remote_sdp;
  char const *offer_answer;
  
  *return_disposition = NULL;
  *return_type = NULL;
  *return_payload = NULL;

  remote_sdp = sdp_session(nm->nm_sdp);

  if (!remote_sdp)
    return 0;

  offer_answer = nh_recv_offer_answer(nh, remote_sdp, &new_sdp);

  if (offer_answer || should_send_offer) 
    setup = nmedia_setup(nua, nm, 
			 nh, nua_i_media_error, 
			 remote_sdp, offer_answer, new_sdp);
  else
    setup = 0;

  if (setup < 0) {
    /* XXX */
    setup = 0;
    ua_event(nua, nh, NULL, nua_i_media_error, 
	     500, "Cannot setup local media",
	     TAG_END());
  }

  if (should_send_offer ||
      (nh->nh_ss->ss_offer_recv && !nh->nh_ss->ss_answer_sent)) {
    sdp_session_t *local_sdp = nmedia_describe(nua, nm, nh, home);

    if (local_sdp) {
      sdp_printer_t *printer = sdp_print(home, local_sdp, NULL, 0, 
					 sdp_f_realloc);
	  
      if (sdp_message(printer)) {
	sip_content_type_t *ct;
	sip_payload_t *pl;

	/* This is always sent reliably (ie. not in non-PRACKed 1XX) */
	nh_sent_offer_answer(nh, local_sdp, 1);

	ct = sip_content_type_dup(home, nua->nua_sdp_content);
	pl = sip_payload_create(home, 
				(void *)sdp_message(printer),
				sdp_message_size(printer));

	*return_type = ct;
	*return_payload = pl;
      }
      sdp_printer_free(printer);
    }
    else {
      ua_event(nua, nh, NULL, nua_i_media_error, 
	       nm->nm_status, nm->nm_phrase,
	       TAG_END());
      setup = -1;
    }
  }
      
  if (setup >= 0 && nmedia_play(nua, nm) < 0)
    setup = -1;
  if (setup >= 0 && nmedia_record(nua, nm) < 0)
    setup = -1;

  return setup;
}

/** Process remote sdp answer for a session */
static
int 
session_answer(nua_handle_t *nh)
{
  nua_t *nua = nh->nh_nua;
  struct nua_media_state *nm = nh->nh_nm;
  int new_sdp, setup;
  sdp_session_t *remote_sdp;
  char const *offer_answer;
  
  if (!nh->nh_ss->ss_offer_sent || nh->nh_ss->ss_answer_recv) 
    return 0;

  remote_sdp = sdp_session(nm->nm_sdp);

  if (!remote_sdp)
    return 0;

  offer_answer = nh_recv_offer_answer(nh, remote_sdp, &new_sdp);

  if (!offer_answer) 
    return 0;

  setup = nmedia_setup(nua, nm, 
		       nh, nua_i_media_error, 
		       remote_sdp, offer_answer, new_sdp);
  if (setup < 0) {
    ua_event(nua, nh, NULL, nua_i_media_error, 
	     500, "Cannot setup local media",
	     TAG_END());
  }

  if (setup >= 0 && nmedia_play(nua, nm) < 0)
    setup = -1;
  if (setup >= 0 && nmedia_record(nua, nm) < 0)
    setup = -1;

  return setup;
}


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
      SU_DEBUG_5(("nta(%p): adding already existing %s usage%s%s\n",
		  nh, dialog_usage_name(du), 
		  event ? " with event " : "", event ? event->o_type : ""));
      
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

      SU_DEBUG_5(("nta(%p): adding %s usage%s%s\n",
		  nh, dialog_usage_name(du), 
		  event ? "with event " : "", event ? event->o_type :""));

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

    SU_DEBUG_5(("nta(%p): removing %s usage%s%s\n",
		nh, dialog_usage_name(du), 
		o ? "with event " : "", o ? o->o_type :""));

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

  if (call)
    ua_event(nh->nh_nua, nh, NULL, nua_i_terminated, 
	     status, phrase, TAG_END());
}


/* ======================================================================== */
/* Request validation */

/** Check that all features UAC requires are also in supported */
static inline
int uas_check_required(nta_incoming_t *irq,
		       sip_t const *sip,
		       sip_supported_t *supported,
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
		     sip_allow_t *allow,
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

static void
crequest_invoke_restart(crequest_restart_f *f, 
			nua_handle_t *nh,
			TAG_LIST)
{
  ta_list ta;
  ta_start(ta, tag, value);
  f(nh, ta_args(ta));
  ta_end(ta);
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
  char const *phrase = sip->sip_status->st_phrase;
  sip_method_t method = nta_outgoing_method(orq);
  nua_t *nua = nh->nh_nua;
  int restarted = 0, removed = 0;

  nua_dialog_usage_t *du = cr->cr_usage;

  assert(f);

  if (orq == cr->cr_orq)
    removed = 1, cr->cr_orq = NULL;

  cr->cr_restart = NULL;

  if (cr->cr_msg == NULL || status < 200)
    ;
  else if (++cr->cr_retry_count > nua->nua_retry_count)
    ;
  else if (status == 302) {
    if (can_redirect(sip->sip_contact, method)) {
      url_t *url = sip->sip_contact->m_url;
      crequest_invoke_restart(f, nh, NUTAG_URL(url), TAG_END());
      restarted = 1; status = 100, phrase = "Redirected";
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

      crequest_invoke_restart(f, nh, SIPTAG_EXPIRES(ex), TAG_END());

      restarted = 1; 
      status = 100, phrase = "Re-Negotiating Subscription Expiration";
    }
  }
  else if (method != sip_method_ack && method != sip_method_cancel &&
	   (status == 401 || status == 407) && 
	   (sip->sip_proxy_authenticate || sip->sip_www_authenticate)) {
    sip_t *rsip;

    nh_challenge(nh, sip);

    rsip = sip_object(cr->cr_msg);

    /* XXX - check for instant restart */
    if (0 < auc_authorization(&nh->nh_auth, cr->cr_msg, (msg_pub_t*)rsip,
			      rsip->sip_request->rq_method_name,
			      rsip->sip_request->rq_url,
			      rsip->sip_payload)) {
      f(nh, NULL);

      status = 100, phrase = "Authorized request";
    }
    else {
      if (nmedia_is_ready(nh->nh_nm))
	nmedia_teardown(nh->nh_nua, nh->nh_nm, nh);
      cr->cr_restart = f;
    }

    restarted = 1;
  }
#if HAVE_SMIME		/* Start NRC Boston */
  else if (status == 493)     /* try detached signature */
    ;
#endif                  /* End NRC Boston */
  else if (status == 422 && method == sip_method_invite) {
    if (sip->sip_min_se && nua->nua_min_se < sip->sip_min_se->min_delta)
      nh->nh_ss->ss_min_se = sip->sip_min_se->min_delta;
    if (nh->nh_ss->ss_min_se > nh->nh_ss->ss_session_timer)
      nh->nh_ss->ss_session_timer = nh->nh_ss->ss_min_se;
    f(nh, NULL);
    status = 100, phrase = "Re-Negotiating Session Timer";
    restarted = 1;
  }
  
  if (restarted)   {
    msg_t *msg = nta_outgoing_getresponse_ref(orq);
    ua_event(nh->nh_nua, nh, msg, cr->cr_event, status, phrase, TAG_END());
    nta_outgoing_destroy(orq); 
  } 
  else {
    /** This was final response that cannot be restarted. */
    if (removed)
      cr->cr_orq = orq;

    if (du) {
      du->du_pending = NULL;
      du->du_refresh = 0;
    }

    cr->cr_retry_count = 0;

    if (cr->cr_msg)
      msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
  }

  return restarted;
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

  cr->cr_orq = nta_outgoing_mcreate(nh->nh_nua->nua_nta, cb, nh, NULL, msg);

  if (!cr->cr_orq) {
    msg_destroy(msg);
    return 0;
  }

  return 1;
}


/* ======================================================================== */
/* Media parameters */

void 
ua_set_media_param(nua_t *nua, nua_handle_t *nh, nua_event_t e, 
		   tagi_t const *tags)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  char const *path = nh->nh_nm->nm_path;
  msg_param_t *params = NULL;
  int status;
  char const *phrase;

#if HAVE_MSS

  if (!nh->nh_nm->nm_session) {
    ua_event(nua, nh, NULL, e, MSS_455_INVALID_METHOD, TAG_END());
    return;
  }

  tl_gets(tags,
	  NUTAG_MEDIA_PATH_REF(path),
	  TAG_END());

  /* Search for all NUTAG_MEDIA_PARAMS instances */
  for (; tags; tags = tl_next(tags)) {
    tags = tl_find(tags, nutag_media_params);
    if (tags) 
      msg_params_replace(home, &params, (msg_param_t)tags->t_value);
  }

  if (params) {
    struct nua_media_state *nm = nh->nh_nm;
    mss_set_param(nm->nm_mss, &nm->nm_session, path, params);
    mss_get_status(nm->nm_mss, &status, &phrase);
    ua_event(nua, nh, NULL, e, status, phrase, TAG_END());
  }
  else
    ua_event(nua, nh, NULL, e, 451, "No parameter to set", TAG_END());

#endif /* HAVE_MSS */

  su_home_deinit(home);
}

void
ua_get_media_param(nua_t *nua, nua_handle_t *nh, 
		   nua_event_t e, tagi_t const *tags)
{
  ua_event(nua, nh, NULL, e, SIP_501_NOT_IMPLEMENTED, TAG_END());
}


void
ua_media_event(nua_t *nua, nua_handle_t *nh, 
	       nua_event_t e, tagi_t const *tags)
{
  struct nua_media_state *nm = nh->nh_nm;

  if (nh_is_special(nh)) {
    ua_event(nua, nh, NULL, e, 500, "Invalid handle for media SETUP", 
	     TAG_END());
    return;
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags)); 

  if (!nmedia_is_enabled(nm)) {
    ua_event(nua, nh, NULL, e, 500, "Media is disabled", TAG_END());
    return;
  }

  if (!nm->nm_session) {
    ua_event(nua, nh, NULL, e, 500, "No active media session", TAG_END());
    return;
  }

  nmedia_event(nua, nm, nh, tags);

  ua_event(nua, nh, NULL, e, nm->nm_status, nm->nm_phrase, TAG_END());
}


void
ua_media_setup(nua_t *nua, nua_handle_t *nh, 
	       nua_event_t e, tagi_t const *tags)
{
  if (nh_is_special(nh)) {
    ua_event(nua, nh, NULL, e, 500, "Invalid handle for media SETUP", 
	     TAG_END());
    return;
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags)); 

  if (!nmedia_is_enabled(nh->nh_nm)) {
    ua_event(nua, nh, NULL, e, 500, "Media is disabled", TAG_END());
    return;
  }

  if (tags)
    nmedia_save_params(nh->nh_nm, nh->nh_home, 0, tags);

  nmedia_setup(nua, nh->nh_nm, nh, e, NULL, NULL, 1);
  /* That's it, nmedia_setup will send event e to application */
}


void
ua_media_describe(nua_t *nua, nua_handle_t *nh, 
		  nua_event_t e, tagi_t const *tags)
{
  struct nua_media_state *nm = nh->nh_nm;
  sdp_session_t *sdp;
  su_home_t home[1] = { SU_HOME_INIT(home) };

  if (nh_is_special(nh)) {
    ua_event(nua, nh, NULL, e, 500, "Invalid handle for media SETUP", 
	     TAG_END());
    return;
  }

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags)); 

  if (!nmedia_is_enabled(nm)) {
    ua_event(nua, nh, NULL, e, 500, "Media is disabled", TAG_END());
    return;
  }

  {
    struct nua_media_state nm0[1];
    *nm0 = *nm;

    if (tags)
      nmedia_save_params(nm0, home, 1, tags);

    sdp = nmedia_describe(nua, nm0, nh, home);
  }

  if (sdp) {
    ua_event(nua, nh, NULL, e, 200, "Ok", 
	     SDPTAG_SESSION(sdp),
	     NH_ACTIVE_MEDIA_TAGS(1, nm->nm_active),
	     TAG_END());
  }
  else {
    ua_event(nua, nh, NULL, e, nm->nm_status, nm->nm_phrase,
	     TAG_END());
  }

  su_home_deinit(home);
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
			   TAG_IF(!registering, NUTAG_USE_LEG(1)),
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
      nta_outgoing_tmcreate(nua->nua_nta,
			    process_response_to_register, nh, NULL,
			    msg,
			    TAG_IF(!registering, NTATAG_SIGCOMP_CLOSE(1)),
			    TAG_IF(registering, NTATAG_COMP("sigcomp")),
			    TAG_END());

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
	while (sip->sip_contact)	
	  sip_header_remove(msg, sip, (sip_header_t *)sip->sip_contact);
	/* Keep only the "any" contact */
	sip_header_insert(msg, sip, (sip_header_t *)m);	
      }
      sip_add_tl(msg, sip, SIPTAG_EXPIRES_STR("0"), TAG_END());
      break;
    }
    sip_params_replace(NULL, (sip_param_t **)&m->m_params, "expires=0");
    sip_fragment_clear(m->m_common);
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
			 NUTAG_USE_LEG(1), 
			 TAG_END());
  sip = sip_object(msg);

  if (sip) {
    if (now == 0)
      register_expires_contacts(msg, sip);
    
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_register, nh, NULL,
				      msg);
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

static int  use_session_timer(nua_t *, nua_handle_t *, msg_t *msg, sip_t *);
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
  else {
    nh_init(nua, nh, nh_has_invite, NULL, TAG_NEXT(tags)); 
    return ua_invite2(nua, nh, e, 0, tags);
  }

  UA_EVENT2(e, 500, what);
  if (ss->ss_state == init_session)
    UA_EVENT2(nua_i_terminated, 500, what);
  
  return e;
}

static int
ua_invite2(nua_t *nua, nua_handle_t *nh, nua_event_t e, int restarted, 
	   tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  struct nua_client_request *cr = ss->ss_crequest;
  nua_dialog_usage_t *du;
  int sent_offer = 0;

  msg_t *msg = crequest_message(nua, nh, cr, restarted,
				SIP_METHOD_INVITE,
				NUTAG_USE_LEG(1),
				NUTAG_ADD_CONTACT(1),
				TAG_NEXT(tags));
  sip_t *sip = sip_object(msg);

  char const *what;

  assert(cr->cr_orq == NULL);

  du = dialog_usage_add(nh, nh->nh_ds, nua_session_usage, NULL);
  what = (char const *)NUA_500_ERROR;	/* Internal error */

  if (du && sip) {
    struct nua_media_state *nm = nh->nh_nm;
    sdp_session_t const *sdp = NULL;
    int setup = 0, already = 0;

    if (use_session_timer(nua, nh, msg, sip))
      dialog_usage_set_refresh(du, 
			       nua->nua_invite_timer == 0 
			       ? SIP_TIME_MAX 
			       : nua->nua_invite_timer);

    ss->ss_precondition = sip_has_feature(sip->sip_require, "precondition");

    if (ss->ss_precondition)
      ss->ss_update_needed = nh->nh_early_media = 1;
    ss->ss_oa_rounds = 0;

    if (nmedia_is_enabled(nm) && !sip->sip_payload) {
      su_home_t home[1] = { SU_HOME_INIT(home) };

      already = nh->nh_ss->ss_complete;
	
      nh_init_offer_answer(nh);

      if (tags)
	nmedia_save_params(nm, nh->nh_home, 0, tags);
      
      if (restarted && nm->nm_session)
	setup = 0;
      else if (nmedia_setup(nua, nm, nh, nua_i_media_error, NULL, NULL, 0) < 0)
	setup = -1, what = "SETUP on Local Media Failed";
      else if (nmedia_play(nua, nm) < 0)
	setup = -1, what = "PLAY on Local Media Failed";
      else if (already && nmedia_record(nua, nm) < 0)
	setup = -1, what = "RECORD on Local Media Failed";
      else
	setup = 0;
      if (setup >= 0 && !(sdp = nmedia_describe(nua, nm, nh, home)))
	setup = -1, what = "DESCRIBE on Local Media Failed";

      if (!sdp) {
	su_home_deinit(home);
	goto error;
      }

      sent_offer = 1;

      nh_sent_offer_answer(nh, sdp, 1);
      nh_sdp_insert(nh, home, msg, sip, sdp);

      if (nh->nh_media_features && !dialog_is_established(nh->nh_ds) && 
	  !sip->sip_accept_contact && !sip->sip_reject_contact) {
	sip_accept_contact_t ac[1];

	sip_accept_contact_init(ac);
	  
	if (nmedia_features(msg_home(msg),
			    (msg_param_t **)&ac->cp_params,
			    sdp->sdp_media, 1)) {
	  msg_params_replace(msg_home(msg), (msg_param_t **)&ac->cp_params, 
			     "explicit");
	  sip_add_dup(msg, sip, (sip_header_t *)ac);
	}
      }

      su_home_deinit(home);
    }

    if (sip)
      cr->cr_orq = nta_outgoing_tmcreate(nua->nua_nta,
					 process_response_to_invite, nh, NULL,
					 msg,
					 NTATAG_REL100(nh->nh_early_media),
					 TAG_END());

    if (cr->cr_orq) {
      cr->cr_sent_offer = sent_offer;
      cr->cr_usage = du;
      du->du_pending = cancel_invite;
      if (nh->nh_ss->ss_state < ready_session)
	nh->nh_ss->ss_state = calling_session;
      return cr->cr_event = e;
    }
  }

 error:
  msg_destroy(msg);
  if (du && !du->du_ready) 
    dialog_usage_remove(nh, nh->nh_ds, du);

  UA_EVENT2(e, 500, what);
  if (ss->ss_state == init_session)
    UA_EVENT2(nua_i_terminated, 500, what);

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

  assert(du);

  if (status >= 300) {
    if (sip->sip_retry_after)
      gracefully = 0;

    terminated = sip_response_terminates_dialog(status, sip_method_invite, 
					       &gracefully);

    if (nh->nh_ss->ss_state < ready_session)
      nh->nh_ss->ss_state = init_session;

    if (!terminated) {
      if (crequest_check_restart(nh, cr, orq, sip, restart_invite))
	return 0;

      if (nh->nh_ss->ss_state < ready_session)
	terminated = 1;
    }
  }
  else if (status >= 200) {
    ss->ss_state = ready_session;
    ss->ss_ack_needed = 1;
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

#if HAVE_SMIME
    if (status < 300) {
      int sm_status;
      msg_t *response;

      /* decrypt sdp payload if it's S/MIME */
      /* XXX msg had a problem!!?? */
      response = nta_outgoing_getresponse_ref(orq);

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

    if (status < 300 && session_process_response(nh, cr, orq, sip) < -1)
      status = 400, phrase = "Bad Session Description";

    if (status < 300) {
      ss->ss_ack_needed = 2;
      if (nh->nh_auto_ack)
	ua_ack(nua, nh, NULL);
      nh_referral_respond(nh, SIP_200_OK);
      return 0;
    }

    ua_ack(nua, nh, NULL);

    gracefully = 1;
  }
  else if (sip->sip_rseq) {
    /* Reliable provisional response */
    if (ss->ss_state < ready_session)
      ss->ss_state = proceeding_session;

    nh_referral_respond(nh, status, phrase);

    return process_100rel(nh, orq, sip);
  }
  else {
    /* Provisional response */
    if (nh->nh_ss->ss_state < ready_session)
      nh->nh_ss->ss_state = proceeding_session;
    nh_referral_respond(nh, status, phrase);
    return process_response(nh, cr, orq, sip, TAG_END());
  }

  cr->cr_usage = NULL;

  nh_referral_respond(nh, status, phrase);
  process_response(nh, cr, orq, sip, TAG_END());

  if (terminated < 0) {
    dialog_terminated(nh, nh->nh_ds, status, phrase);
  }
  else if (terminated > 0) {
    dialog_usage_remove(nh, nh->nh_ds, du);
    ua_event(nua, nh, NULL, nua_i_terminated, status, phrase, TAG_END());
  }
  else if (gracefully) {
    char *reason = 
      su_sprintf(NULL, "SIP;cause=%u;text=\"%s\"", status, phrase);

    if (status != sip->sip_status->st_status)
      ua_event(nua, nh, NULL, nua_i_error, status, phrase, TAG_END());

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
  char const *reason = NULL;
  int needed = ss->ss_ack_needed;

  if (!needed) {
    return UA_EVENT2(nua_i_error, 500, "No response to ACK");
  }
  ss->ss_ack_needed = 0;

  if (tags) {
    int auto_ack = nh->nh_auto_ack;
    tl_gets(tags, NUTAG_AUTOACK_REF(auto_ack), TAG_END());
    nh->nh_auto_ack = auto_ack != 0;
  }

  msg = crequest_message(nua, nh, cr, 0, 
			 SIP_METHOD_ACK, 
			 /* NUTAG_COPY(0), */
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip && nmedia_is_enabled(nh->nh_nm)) {
    if (tags)
      nmedia_save_params(nh->nh_nm, nh->nh_home, 0, tags);

    if (needed > 1) {
      sip_content_disposition_t *cd;
      sip_content_type_t *ct;
      sip_payload_t *pl;

      if (session_offer_answer(nh, msg_home(msg), &cd, &ct, &pl, 0) < 0) {
	reason = nmedia_error_to_sip_reason(nh->nh_nm);
      }
      else {
	sip_header_insert(msg, sip, (sip_header_t *)cd);
	sip_header_insert(msg, sip, (sip_header_t *)ct);
	sip_header_insert(msg, sip, (sip_header_t *)pl);
      }
    }

    if (!reason && ss->ss_offer_sent && !ss->ss_answer_recv) {
      /* No SDP answer in 2XX response -> terminate call */
      reason = "SIP;cause=488;text=\"Incomplete offer/answer\"";
      UA_EVENT2(nua_i_media_error, 500, "Incomplete offer/answer");
    }
  }

  if (sip)
    ack = nta_outgoing_mcreate(nua->nua_nta, NULL, NULL, NULL, msg);

  if (!ack) {
    if (!reason)
      reason = "SIP;cause=500;text=\"Internal error\"";
    msg_destroy(msg);
    UA_EVENT2(nua_i_error, 500, "Cannot send ACK");
  }

  crequest_deinit(cr, NULL);	/* Destroy INVITE transaction */
  nta_outgoing_destroy(ack);	/* Timer keeps this around for T2 */

  if (reason) {
    stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason), TAG_END());
    return 0;
  }

  ss->ss_active = 1;

  return ua_event(nua, nh, NULL, nua_i_active, 
		  200, "Call is active", 
		  TAG_IF(nmedia_is_enabled(nh->nh_nm),
			 NMEDIA_ACTIVE_TAGS(nh->nh_nm)),
		  TAG_END());
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

  int sent_offer_in_prack = 0;		

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

  if (nmedia_is_enabled(nh->nh_nm)) {
    int offer_is_needed;

    session_process_response(nh, cr_invite, orq, sip);
    offer_is_needed = ss->ss_precondition && ss->ss_oa_rounds < 2;
    session_offer_answer(nh, home, &cd, &ct, &pl, offer_is_needed);

    sent_offer_in_prack = 
      pl && nh->nh_ss->ss_offer_sent && !nh->nh_ss->ss_answer_recv;
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
    cr_prack->cr_sent_offer = sent_offer_in_prack;
  }
  else {
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
  int status = sip ? sip->sip_status->st_status : 408;

  SU_DEBUG_1(("nua: process_response_to_prack\n"));

#if 0
  if (crequest_check_restart(nh, cr, orq, sip, restart_prack))
    return 0;
#endif

  if (status >= 200) {
    crequest_deinit(cr, orq);

    if (status < 300) {
      session_process_response(nh, cr, orq, sip);

      session_answer(nh);

      if (nh->nh_ss->ss_update_needed)
	ua_update(nh->nh_nua, nh, nua_r_update, NULL);
    }
  }

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

  ua_cancel(nh->nh_nua, nh, nua_r_destroy, timeout_tags);
}

void 
refresh_invite(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  nua_t *nua = nh->nh_nua;

  if (now > 0 && nh->nh_update_refresh)
    ua_update(nh->nh_nua, nh, nua_r_update, NULL);
  else if (now > 0)
    ua_invite(nh->nh_nua, nh, nua_r_invite, NULL);
  else {
    UA_EVENT2(nua_i_error, 408, "Session Timeout");
    stack_signal(nh, nua_r_bye, SIPTAG_REASON_STR(reason_timeout), TAG_END());
  }
}

static void 
session_timeout(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  if (now > 1)
    stack_signal(nh, nua_r_bye, TAG_END());
}

/** Restart invite (after 302 or 407) */
void 
restart_invite(nua_handle_t *nh, tagi_t *tags)
{
  ua_invite2(nh->nh_nua, nh, nua_r_invite, 1, tags);
}

/* CANCEL */
int
ua_cancel(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_session_state_t *ss = nh->nh_ss;
  nua_client_request_t *cr = ss->ss_crequest;
  
  if (nh && cr->cr_orq && cr->cr_usage && 
      cr->cr_usage->du_pending == cancel_invite) {
    nua_dialog_usage_t *du = cr->cr_usage;

    du->du_pending = NULL;

    nh_referral_respond(nh, SIP_487_REQUEST_TERMINATED);
     
    nta_outgoing_tcancel(cr->cr_orq, NULL, NULL, TAG_NEXT(tags));

    return ua_event(nua, nh, NULL, e, SIP_200_OK, TAG_END());
  }

  return UA_EVENT2(e, 481, "No transaction to CANCEL");
}

static void respond_to_invite(nua_t *nua, nua_handle_t *nh,
			      int status, char const *phrase, 
			      tagi_t const *tags);

static int 
  process_invite1(nua_t *, nua_handle_t**, nta_incoming_t *, 
		  msg_t *, sip_t *, struct nua_media_a ma[]),
  process_invite2(nua_t *, nua_handle_t *, nta_incoming_t *, 
		  msg_t *, sip_t *, struct nua_media_a ma[]),
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
  struct nua_media_a ma[1];
  int status;

  status = process_invite1(nua, &nh, irq, msg, (sip_t *)sip, ma);

  if (status) {
    msg_destroy(msg);
    if (nh && !nh0)
      nh_destroy(nua, nh);
    return status;
  }

  return process_invite2(nua, nh, irq, msg, (sip_t *)sip, ma);
}

/** Preprocess incoming invite - sure we have a valid request. */
static
int process_invite1(nua_t *nua,
		    nua_handle_t **return_nh,
		    nta_incoming_t *irq,
		    msg_t *msg,
		    sip_t *sip,
		    struct nua_media_a ma[])
{
  nua_handle_t *nh = *return_nh;

#if HAVE_SMIME 
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

  if (nh ? nmedia_is_enabled(nh->nh_nm) : nua->nua_media_enable) {
    /* Make sure caller uses application/sdp without compression */
    if (uas_check_content(irq, sip, 
			  SIPTAG_USER_AGENT(nua->nua_user_agent),
			  TAG_END()))
      return 415;

    /* Make sure caller accepts application/sdp */
    if (uas_check_accept(irq, sip, 
			 nua->nua_invite_accept,
			 SIPTAG_USER_AGENT(nua->nua_user_agent),
			 TAG_END()))
      return 406;
  }

  if (sip->sip_session_expires)
    if (uas_check_session_expires(irq, sip, 
				  nh ? nh->nh_ss->ss_min_se : nua->nua_min_se,
				  SIPTAG_USER_AGENT(nua->nua_user_agent),
				  TAG_END()))
      return 500;

  if (nh == NULL) {
    if (!nua->nua_enableInvite)
      return 403;

    if (!(nh = nh_create_from_incoming(nua, irq, sip, nh_has_invite, 1)))
      return 500;
  }
  else if (nh->nh_ss->ss_invite_irq) {
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
  else if (nh->nh_ss->ss_crequest->cr_orq) {
    /* Glare - RFC 3261 14.2 */
    nta_incoming_treply(irq, SIP_491_REQUEST_PENDING, TAG_END());
    return 491;
  }

  *return_nh = nh;
  nh_init_offer_answer(nh);
  nmedia_set_activity(ma, NULL, 0);

  if (nmedia_is_enabled(nh->nh_nm) &&
      nmedia_parse_sdp_from_sip(nh, sip, ma) == NONE) {
    nta_incoming_treply(irq, 400, "Bad Session Description", TAG_END());
    return 400;
  }

  /** Add a dialog usage */
  if (!nh->nh_ss->ss_usage) 
    nh->nh_ss->ss_usage = 
      dialog_usage_add(nh, nh->nh_ds, nua_session_usage, NULL);
  if (!nh->nh_ss->ss_usage) {
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    return 500;
  }

  nh->nh_ss->ss_invite_irq = irq;
  
  return 0;
}

/** Process incoming invite - initiate media, etc. */
static
int process_invite2(nua_t *nua,
		    nua_handle_t *nh,
		    nta_incoming_t *irq,
		    msg_t *msg,
		    sip_t *sip, 
		    struct nua_media_a ma[])
{
  nua_session_state_t *ss;

  ss = nh->nh_ss;
  ss->ss_precondition = sip_has_feature(sip->sip_require, "precondition");
  if (ss->ss_precondition)
    nh->nh_early_media = 1;

  /* Session Timer negotiation */
  init_session_timer(nua, nh, sip);

  dialog_uas_route(nh, sip, 1);	/* Set route and tags */

  nta_incoming_bind(irq, process_ack_or_cancel, nh);
	  
  if (ss->ss_state < ready_session) {
    assert(ss->ss_state == init_session);

    ss->ss_respond_to_invite = respond_to_invite;

    ua_event(nh->nh_nua, nh, msg, 
	     nua_i_invite, 0, NULL,
	     NH_ACTIVE_MEDIA_TAGS(nmedia_is_enabled(nh->nh_nm), ma),
	     TAG_END());
  }

  if (ss->ss_state == ready_session || nua->nua_autoAnswer)
    respond_to_invite(nua, nh, SIP_200_OK, NULL);
  else if (nua->nua_autoAlert) {
    if (nh->nh_early_media && 
	(sip_has_feature(nh->nh_ds->ds_remote_ua->nr_supported, "100rel") ||
	 sip_has_feature(nh->nh_ds->ds_remote_ua->nr_require, "100rel"))) {
      respond_to_invite(nua, nh, SIP_183_SESSION_PROGRESS, NULL);
      return 0;
    }

    respond_to_invite(nua, nh, SIP_180_RINGING, NULL);
  }
  else {
    if (ss->ss_state == init_session)
      ss->ss_state = received_session;
    nta_incoming_treply(irq, SIP_100_TRYING, TAG_END());
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
  sdp_session_t *sdp;
  msg_t *msg;
  sip_t *sip;
  int setup = 0, reliable;
  int original_status = status;
  nua_session_state_t *ss = nh->nh_ss;
  nua_dialog_state_t *ds = nh->nh_ds;
  nua_media_state_t *nm = nh->nh_nm;

  enter; 

  if (ss->ss_invite_irq == NULL ||
      nta_incoming_status(ss->ss_invite_irq) >= 200) {
    ua_event(nh->nh_nua, nh, NULL,
	     nua_i_error, 500, "No INVITE request to response", TAG_END());
    return;
  }

  assert(ss->ss_usage);

  reliable = 
    (status >= 200)
    || (status == 183 &&
	ds->ds_remote_ua->nr_supported && 
	sip_has_feature(ds->ds_remote_ua->nr_supported, "100rel"))
    || (status > 100 &&
	ds->ds_remote_ua->nr_require &&
	(sip_has_feature(ds->ds_remote_ua->nr_require, "100rel") ||
	 sip_has_feature(ds->ds_remote_ua->nr_require, "precondition")));

  sdp = NULL;

  if (!nmedia_is_enabled(nm))
    /* Xyzzy */;
  else if (status >= 300) {
    nmedia_clear_sdp(nh);
  }
  else if (status >= 200 || nh->nh_early_media) {
    char const *offer_answer = NULL;
    sdp_session_t *received_sdp ;
    int new_sdp = 0;

    if (tags)
      nmedia_save_params(nm, nh->nh_home, 0, tags);

    received_sdp = sdp_session(nm->nm_sdp);
    
    if (received_sdp)
      offer_answer = nh_recv_offer_answer(nh, received_sdp, &new_sdp);

    if (received_sdp || !nmedia_is_ready(nm))
      setup = nmedia_setup(nua, nm, nh, nua_i_media_error, 
			   received_sdp, offer_answer, new_sdp);

    nmedia_clear_sdp(nh);
    
    if (setup >= 0 &&
	((ss->ss_offer_recv && ss->ss_answer_sent < 2) ||
	 (reliable && !ss->ss_offer_recv && !ss->ss_offer_sent))) {
      sdp = nmedia_describe(nua, nm, nh, home);

      if (sdp) {
	nh_sent_offer_answer(nh, sdp, reliable);

	if (setup >= 0 && nmedia_play(nua, nm) < 0)
	  setup = -1;

	if (ss->ss_complete && setup >= 0 && nmedia_record(nua, nm) < 0)
	  setup = -1;

      } else {
	ua_event(nua, nh, NULL, nua_i_media_error, 
		 500, "Cannot describe local media",
		 TAG_END());
	setup = -1;
      }
    }

    if (setup < 0 && status)
      nmedia_error_to_sip_response(nm, &status, &phrase);
  }

  msg = nh_make_response(nua, nh, ss->ss_invite_irq, 
			 status, phrase, 
			 TAG_IF(status < 300, NUTAG_ADD_CONTACT(1)),
			 SIPTAG_SUPPORTED(nua->nua_supported),
			 TAG_NEXT(tags));
  sip = sip_object(msg); 

  assert(sip);			/* XXX */

  if (sdp && !sip->sip_payload)
    nh_sdp_insert(nh, home, msg, sip, sdp);

  if (ss->ss_refresher && 200 <= status && status < 300)
    use_session_timer(nua, nh, msg, sip);

#if HAVE_SMIME
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

  /* Update session state */
  if (ss->ss_state >= ready_session) {
    /* Does not modify state */;
  } else if (ss->ss_state == calling_session) {
    assert(ss->ss_state != calling_session);
  } else if (ss->ss_state == proceeding_session) {
    assert(ss->ss_state != proceeding_session);
  } else if (status >= 300) {
    ss->ss_state = init_session;
  } else if (status >= 200) {
    ss->ss_state = ready_session;
  } else if (status > 100) {
    ss->ss_state = early_session;
  } else if (status == 100 && ss->ss_state == init_session) {
    ss->ss_state = received_session;
  }

  if (status == 180) {
    ss->ss_alerting = 1;

#if HAVE_HERBIE
    if (nua->nua_herbie)
      nua_herbie_play(nua->nua_herbie);
#endif

  }
  else if (status >= 200)
    ss->ss_alerting = 0;

  if (reliable && status < 200) {
    nta_reliable_t *rel;
    rel = nta_reliable_mreply(ss->ss_invite_irq, process_prack, nh, msg);
    if (!rel)
      status = 500, phrase = sip_500_Internal_server_error;
  }
  else {
    nta_incoming_mreply(ss->ss_invite_irq, msg);
  }

  if (status >= 200) {
    ss->ss_usage->du_ready = 1;
    ss->ss_respond_to_invite = NULL;

#if HAVE_HERBIE
  if (nua->nua_herbie)
    nua_herbie_stop(nua->nua_herbie);
#endif
  }

  if (status >= 300) {
    nh_init_offer_answer(nh);
    nmedia_teardown(nua, nm, nh);
    nta_incoming_destroy(ss->ss_invite_irq), ss->ss_invite_irq = NULL;
  }

  su_home_deinit(home);

  if (status != original_status)
    ua_event(nua, nh, NULL, nua_i_error, status, phrase, TAG_END());

  if (ss->ss_state == init_session) {
    nsession_destroy(nh);
    ua_event(nua, nh, NULL, nua_i_terminated, 0, phrase, TAG_END());
  } 
}


/** Process ACK or CANCEL or timeout (no ACK) for incoming INVITE */
static
int process_ack_or_cancel(nua_handle_t *nh,
			  nta_incoming_t *irq,
			  sip_t const *sip)
{
  int retval;

  enter;

  if (sip && sip->sip_request->rq_method == sip_method_ack)
    retval = process_ack(nh, irq, sip);
  else if (sip && sip->sip_request->rq_method == sip_method_cancel)
    retval = process_cancel(nh, irq, sip);
  else
    retval = process_timeout(nh, irq);

  assert(nh->nh_ss->ss_invite_irq == irq);
  nta_incoming_destroy(nh->nh_ss->ss_invite_irq), nh->nh_ss->ss_invite_irq = NULL;

  return retval;
}

static
int process_prack(nua_handle_t *nh,
		  nta_reliable_t *rel,
		  nta_incoming_t *irq,
		  sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  sdp_session_t const *remote;
  int response = 200;

  nta_reliable_destroy(rel);

#if HAVE_HERBIE
  if (nh->nh_nua->nua_herbie)
    nua_herbie_stop(nh->nh_nua->nua_herbie);
#endif

  if (!ss->ss_invite_irq) /* XXX  */
    return 481;

  if (sip == NULL) {
    /* Timeout */ 
    respond_to_invite(nh->nh_nua, nh, 500, "Reliable Response Timeout", NULL);
    return 500;
  }

  if (nmedia_is_enabled(nh->nh_nm)) {
    remote = nmedia_parse_sdp_from_sip(nh, sip, NULL);

    if (remote) {
      /* Respond to PRACK */
      sip_content_disposition_t *cd = NULL;
      sip_content_type_t *ct = NULL;
      sip_payload_t *pl = NULL;

      su_home_t home[1] = { SU_HOME_INIT(home) };

      session_offer_answer(nh, home, &cd, &ct, &pl, 0);

      nta_incoming_treply(irq, SIP_200_OK,
			  SIPTAG_CONTENT_DISPOSITION(cd),
			  SIPTAG_CONTENT_TYPE(ct),
			  SIPTAG_PAYLOAD(pl),
			  TAG_END());

      su_home_deinit(home);

      /* Respond with 500 in case nta_incoming_treply() failed */ 
      response = 500; 
    }
  }

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_prack, 0, NULL, TAG_END());

  if (nh->nh_nua->nua_autoAlert 
      && !ss->ss_alerting 
      && !ss->ss_precondition)
    respond_to_invite(nh->nh_nua, nh, SIP_180_RINGING, NULL);

  return response;
}

static
int process_ack(nua_handle_t *nh,
		nta_incoming_t *irq,
		sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;

  if (ss && ss->ss_offer_sent && !ss->ss_answer_recv) {
    struct nua_media_state *nm = nh->nh_nm;
    sdp_session_t const *sdp;

    sdp = nmedia_parse_sdp_from_sip(nh, sip, NULL);

    if (sdp) {
      char const *offer_answer;
      int setup = 0, new_sdp;
      
      offer_answer = nh_recv_offer_answer(nh, sdp, &new_sdp);

      setup = nmedia_setup(nh->nh_nua, nm, nh, nua_i_media_error, 
			   sdp, offer_answer, new_sdp);

      if (setup >= 0 && nmedia_play(nh->nh_nua, nm) < 0)
	setup = -1;
      else if (setup >= 0 && nmedia_record(nh->nh_nua, nm) < 0)
	setup = -1;

      if (setup > 0) {
	su_home_t home[1] = { SU_HOME_INIT(home) };

	/* Get our current SDP, update nh accordingly */
	nmedia_describe(nh->nh_nua, nm, nh, home);
	
	su_home_deinit(home);
      }

      if (setup < 0) {
	ua_event(nh->nh_nua, nh, NULL, 
		 nua_i_media_error, 
		 nh->nh_nm->nm_status, nh->nh_nm->nm_phrase, 
		 TAG_END());
	/* XXX - what about call status, ua_bye()?? */
	return 0;
      } 
    }
  }

  nmedia_clear_sdp(nh);

  ss->ss_active = 1;

  ua_event(nh->nh_nua, nh, NULL, nua_i_active, 
	   200, "Call is active", 
	   NH_ACTIVE_MEDIA_TAGS(1, nh->nh_nm->nm_active),
	   TAG_END());

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

  if (ss->ss_state < ready_session) {
    nmedia_teardown(nh->nh_nua, nh->nh_nm, nh); /* XXX */
    ss->ss_active = 0;
    ss->ss_state = init_session;
    ua_event(nh->nh_nua, nh, NULL, nua_i_terminated,
	     0, "Caller canceled the call", TAG_END());
  }

  ua_event(nh->nh_nua, nh, msg, nua_i_cancel,
	   SIP_487_REQUEST_TERMINATED, 
	   TAG_END());

  return 0;
}

/* Timeout (no ACK or PRACK received) */
static
int process_timeout(nua_handle_t *nh,
		    nta_incoming_t *irq)
{
  struct nua_session_state *ss = nh->nh_ss;

  if (ss->ss_state < ready_session) {
    nmedia_teardown(nh->nh_nua, nh->nh_nm, nh); /* XXX */
    ss->ss_active = 0;
    ss->ss_state = init_session;
  }

  /* send BYE if 200 OK timeouts  */
  if (ss->ss_state == ready_session)
    stack_signal(nh, nua_r_bye, 
		 SIPTAG_REASON_STR("SIP;cause=408;text=\"ACK Timeout\""),
		 TAG_END());

  ua_event(nh->nh_nua, nh, NULL, nua_i_terminated,
	   500, "Response timeout", TAG_END());

  return 0;
}


/* ---------------------------------------------------------------------- */
/* Session timer */

/** Add timer featuretag and Session-Expires/Min-SE headers */
static int
use_session_timer(nua_t *nua, nua_handle_t *nh, msg_t *msg, sip_t *sip)
{
  struct nua_session_state *ss = nh->nh_ss;

  sip_min_se_t min_se[1];
  sip_session_expires_t session_expires[1];

  static sip_param_t const x_params_uac[] = {"refresher=uac", NULL};
  static sip_param_t const x_params_uas[] = {"refresher=uas", NULL};

  /* Session-Expires timer */
  if (!ss->ss_session_timer || 
      /* Check if feature is supported */
      !sip_has_supported(nua->nua_supported, "timer"))
    return 0;
    
  sip_min_se_init(min_se)->min_delta = ss->ss_min_se;
  sip_session_expires_init(session_expires)->x_delta = ss->ss_session_timer;
    
  if (ss->ss_refresher == nua_remote_refresher)
    session_expires->x_params = x_params_uas;
  else if (ss->ss_refresher == nua_local_refresher)
    session_expires->x_params = x_params_uac;
    
  sip_add_tl(msg, sip,  
	     SIPTAG_SESSION_EXPIRES(session_expires),
	     TAG_IF(ss->ss_min_se != 0 
		    /* Min-SE: 0 is optional with initial INVITE */
		    || ss->ss_state != init_session, 
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
      !sip_has_supported(nua->nua_supported, "timer")) {
    return 0;
  }
    
  ss->ss_session_timer = sip->sip_session_expires->x_delta;

  if (sip->sip_min_se != NULL 
      && sip->sip_min_se->min_delta > nua->nua_min_se)
    ss->ss_min_se = sip->sip_min_se->min_delta;

  server = sip->sip_request != NULL;

  if (!str0casecmp("uac", sip->sip_session_expires->x_refresher))
    ss->ss_refresher = server ? nua_remote_refresher : nua_local_refresher;
  else if (!str0casecmp("uas", sip->sip_session_expires->x_refresher))
    ss->ss_refresher = server ? nua_local_refresher : nua_remote_refresher;
  else if (!server)
    return 0;			/* XXX */
  /* User preferences */
  else if (nua->nua_refresher)
    ss->ss_refresher = nua->nua_refresher;
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

  if (pause) 
    /* Pause media on REFER handle */
    nmedia_pause(nua, ref_handle->nh_nm, NULL);

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
  ss->ss_state = init_session;

  /* Remove usage */
  if (ss->ss_usage)
    dialog_usage_remove(nh, nh->nh_ds, ss->ss_usage);
  ss->ss_usage = 0;

  nh->nh_has_invite = 0;

  nh_init_offer_answer(nh);

  if (ss->ss_o_remote)
    su_free(nh->nh_home, ss->ss_o_remote), ss->ss_o_remote = NULL;
  if (ss->ss_o_local)
    su_free(nh->nh_home, ss->ss_o_local), ss->ss_o_local = NULL;

  nmedia_teardown(nh->nh_nua, nh->nh_nm, nh);
  nmedia_clear_sdp(nh);

  ss->ss_respond_to_invite = NULL;

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
				    msg);
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
	   nua_i_info, 0, NULL, TAG_END());

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
  msg_t *msg;
  sip_t *sip;

  if (!nh_has_session(nh))
    return UA_EVENT2(e, 500, "Invalid handle for UPDATE");
  else if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_UPDATE,
			 NUTAG_USE_LEG(1),
			 NUTAG_ADD_CONTACT(1),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    su_home_t home[1] = { SU_HOME_INIT(home) };
    sdp_session_t const *sdp = NULL;
    int setup = 0, already = 0;
    struct nua_media_state *nm = nh->nh_nm;

    if (nmedia_is_enabled(nm) && !sip->sip_payload) {
      char const *what = "SETUP on Local Media Failed";

      already = ss->ss_complete;
	
      nh_init_offer_answer(nh);

      if (tags)
	nmedia_save_params(nm, nh->nh_home, 0, tags);
      
      setup = nmedia_setup(nua, nm, nh, nua_i_media_error, NULL, NULL, 0);

      if (setup >= 0 && nmedia_play(nua, nm) < 0)
	setup = -1, what = "PLAY on Local Media Failed";
      if (setup >= 0 && already && nmedia_record(nua, nm) < 0)
	setup = -1, what = "RECORD on Local Media Failed";
      if (setup >= 0 && !(sdp = nmedia_describe(nua, nm, nh, home)))
	setup = -1, what = "DESCRIBE on Local Media Failed";

      if (setup < 0) {
	if (ss->ss_state < ready_session) {
	  /* XXX */
	}

	msg_destroy(msg);
	return UA_EVENT2(e, 500, what);
      }      

      nh_sent_offer_answer(nh, sdp, 1);
      nh_sdp_insert(nh, home, msg, sip, sdp);
    }

    if (nh->nh_auth) {
      if (auc_authorize(&nh->nh_auth, msg, sip) < 0)
	/* xyzzy */;
    }

    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_update, nh, NULL,
				      msg);
    if (cr->cr_orq) {
      ss->ss_update_needed = 0;
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
  int terminated = 0;

  if (status >= 300) {
    int terminate, gracefully = 1;

    if (sip->sip_retry_after)
      gracefully = 0;

    terminate = sip_response_terminates_dialog(status, sip_method_invite, 
					       &gracefully);

    if (!terminate &&
	crequest_check_restart(nh, cr, orq, sip, restart_invite)) {
      return 0;
    }

    if (ss->ss_state < ready_session || terminate) { 
      nsession_destroy(nh);
      nh_referral_respond(nh, status, phrase);
      terminated = 1;
    }
    else if (gracefully) {
      nh_referral_respond(nh, status, phrase);
      if (nh->nh_ss->ss_crequest->cr_orq)
	stack_signal(nh, nua_r_cancel,TAG_END());
      else
	stack_signal(nh, nua_r_bye, TAG_END());
    }
  }
  else if (status >= 200) {
    /* XXX - check remote tag, handle forks */
    dialog_uac_route(nh, sip, 1);	/* Set route, contact, nh_ds->ds_remote_tag */
    dialog_get_peer_info(nh, sip);

    if (session_process_response(nh, cr, orq, sip) >= 0) {
      session_answer(nh);
    } 
    else {
      ua_event(nua, nh, NULL, nua_i_error, 
	       400, "Bad Session Description", TAG_END());
    }

    return 0;
  }

  process_response(nh, cr, orq, sip, TAG_END());

  if (terminated)
    ua_event(nua, nh, NULL, nua_i_terminated, 
	     sip->sip_status->st_status, sip->sip_status->st_phrase, 
	     TAG_END());

  return 0;
}

int process_update(nua_t *nua,
		   nua_handle_t *nh,
		   nta_incoming_t *irq,
		   sip_t const *sip)
{
  struct nua_session_state *ss = nh->nh_ss;
  nua_dialog_usage_t *du = ss->ss_usage;
  int response = 500;

  assert(nh);

  if (du && (du->du_pending == refresh_invite || 
	     du->du_pending == session_timeout))
    set_session_timer(nh);

  if (!du) {
    nua_dialog_state_t *ds = nh->nh_ds;

    /* No session */
    nta_incoming_treply(irq, response = SIP_405_METHOD_NOT_ALLOWED, 
			TAG_IF(ds->ds_has_subscription,
			       SIPTAG_ALLOW_STR("NOTIFY")),
			TAG_IF(ds->ds_has_notifier,
			       SIPTAG_ALLOW_STR("SUBSCRIBE, REFER")),
			TAG_END());
  }
  else if (nmedia_is_enabled(nh->nh_nm)) {
    sdp_session_t const *offer;
    nh_init_offer_answer(nh);

    offer = nmedia_parse_sdp_from_sip(nh, sip, NULL);

    if (offer) {
      /* Respond to UPDATE */
      sip_content_disposition_t *cd = NULL;
      sip_content_type_t *ct = NULL;
      sip_payload_t *pl = NULL;

      su_home_t home[1] = { SU_HOME_INIT(home) };

      session_offer_answer(nh, home, &cd, &ct, &pl, 0);

      nta_incoming_treply(irq, SIP_200_OK,
			  SIPTAG_CONTENT_DISPOSITION(cd),
			  SIPTAG_CONTENT_TYPE(ct),
			  SIPTAG_PAYLOAD(pl),
			  TAG_END());

      su_home_deinit(home);

      nmedia_clear_sdp(nh);
    }
  }
  else 
    nta_incoming_treply(irq, response = SIP_200_OK, TAG_END());
    
  if (nh->nh_nua->nua_autoAlert 
      && ss->ss_state < ready_session
      && !ss->ss_alerting 
      && ss->ss_precondition)
    respond_to_invite(nh->nh_nua, nh, SIP_180_RINGING, NULL);

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_update, 0, NULL, TAG_END());

  return response;
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
  
  if (nh_is_special(nh))
    return UA_EVENT2(e, 500, "Invalid handle for BYE");

  if (cr_invite->cr_orq) {
    /* XXX - if call has been established, must send BYE, too. */
    nta_outgoing_tcancel(cr_invite->cr_orq, NULL, NULL, TAG_NEXT(tags));
    nta_outgoing_destroy(cr_invite->cr_orq);
    cr->cr_orq = NULL;
  }

  if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  nh_init(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  msg = crequest_message(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_BYE, 
			 TAG_NEXT(tags));
  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_bye, nh, NULL,
				    msg);
  nsession_destroy(nh);

  if (!cr->cr_orq) {
    ss->ss_state = terminated_session;
    msg_destroy(msg);
    UA_EVENT2(e, 400, "Internal error");
    return UA_EVENT2(nua_i_terminated, 400, "Failure sending BYE");
  }
  else 
    ss->ss_state = terminating_session;

  return cr->cr_event = e;
}


void restart_bye(nua_handle_t *nh, tagi_t *tags)
{
  crequest_restart(nh, nh->nh_cr, process_response_to_bye, tags);
}


static int process_response_to_bye(nua_handle_t *nh,
				   nta_outgoing_t *orq,
				   sip_t const *sip)
{
  nua_dialog_usage_t *du = dialog_usage_get(nh->nh_ds, nua_session_usage, 0);
  struct nua_client_request *cr = nh->nh_cr;
  int status = sip ? sip->sip_status->st_status : 400;

  if (crequest_check_restart(nh, cr, orq, sip, restart_bye))
    return 0;

  process_response(nh, cr, orq, sip, TAG_END());

  if (status >= 200) {
    if (du)
      dialog_usage_remove(nh, nh->nh_ds, du);
    ua_event(nh->nh_nua, nh, NULL, nua_i_terminated, 0, "Sent BYE", TAG_END());
  }

  return 0;
}



int process_bye(nua_t *nua,
		nua_handle_t *nh,
		nta_incoming_t *irq,
		sip_t const *sip)
{
  assert(nh);

  ua_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
	   nua_i_bye, 0, NULL, TAG_END());
  nta_incoming_treply(irq, SIP_200_OK, TAG_END());
  nta_incoming_destroy(irq), irq = NULL;

  nsession_destroy(nh);

  UA_EVENT2(nua_i_terminated, 0, "Received BYE");

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
				    msg);
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

  if (nh == NULL)
    nh = nua->nua_default;

  msg = nta_incoming_getrequest(irq);

  ua_event(nh->nh_nua, nh, msg, nua_i_options, 0, NULL, TAG_END());

  msg = nh_make_response(nua, nh, irq, SIP_200_OK,
			 SIPTAG_ALLOW(nh->nh_allow),
			 SIPTAG_SUPPORTED(nua->nua_supported),
			 TAG_IF(nua->nua_path_enable,
				SIPTAG_SUPPORTED_STR("path")),
			 TAG_END());

  if (msg) {
    su_home_t home[1] = { SU_HOME_INIT(home) };
    sdp_session_t *sdp;
    sip_t *sip = sip_object(msg);

    if ((sdp = nmedia_describe(nua, nh->nh_nm, nh, home))) {
      nh_sdp_insert(nh, home, msg, sip, sdp);
    }

    nta_incoming_mreply(irq, msg);
    nta_incoming_destroy(irq);

    su_home_deinit(home);
  }

  return 0;
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

  cr->cr_orq = nta_outgoing_tmcreate(nua->nua_nta,
				     process_response_to_publish, nh, NULL,
				     msg,
				     TAG_IF(e != nua_r_publish,
					    SIPTAG_EXPIRES_STR("0")),
				     TAG_END());

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
	   nua_i_publish, 0, NULL, TAG_END());

  return 500;			/* Respond automatically with 500 */
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
			 NUTAG_ADD_CONTACT(nua->nua_enableMessenger),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

#if HAVE_SMIME_OLD 		/* Start NRC Boston */
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
#endif                   /* End NRC Boston */

  if (sip)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_message, nh, NULL,
				      msg);
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

  if (!nua->nua_enableMessage)
    return 403;

  if (nh == NULL)
    if (!(nh = nh_create_from_incoming(nua, irq, sip, nh_has_nothing, 0)))
      return 500;

  msg = nta_incoming_getrequest(irq);

#if HAVE_SMIME		/* Start NRC Boston */
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
#endif 			/* End NRC Boston */

  ua_event(nh->nh_nua, nh, msg, nua_i_message, 0, NULL, TAG_END());

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
			 NUTAG_USE_LEG(1), 
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
    if (sip->sip_supported && e == nua_r_subscribe)
      nh->nh_supported = sip_supported_dup(nh->nh_home, sip->sip_supported);
    if (du->du_subscriber->de_msg)
      msg_destroy(du->du_subscriber->de_msg);
    du->du_subscriber->de_msg = msg_ref_create(cr->cr_msg);
  }

  if (du)
    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_subscribe, nh, NULL,
				      msg);

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
    int enable_windows_messanger = nh->nh_nua->nua_enableMessenger;
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
    if (!enable_windows_messanger)
      dialog_uac_route(nh, sip, 1);
    dialog_get_peer_info(nh, sip);

    if (delta > 0) {
      dialog_usage_set_refresh(du, delta);
      du->du_pending = refresh_subscribe;
    }
    else if (substate == nua_substate_embryonic || 
	     cr->cr_event == nua_r_unsubscribe) {
      if (enable_windows_messanger)
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
			 NUTAG_USE_LEG(1), 
			 NUTAG_ADD_CONTACT(1),
			 //SIPTAG_EVENT(du->du_event),
			 //SIPTAG_SUPPORTED(nh->nh_supported),
			 TAG_IF(du->du_terminating, 
				SIPTAG_EXPIRES_STR("0")),
			 TAG_END());

  sip = sip_object(msg);

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_subscribe, nh, NULL,
				    msg);

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
	   nua_i_notify, 0, "no real NOTIFY received", 
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
				      msg);
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

  enter;

  if (nh == NULL ||
      /* XXX - support forking of subscriptions?... */
      (ds->ds_remote_tag && sip->sip_from->a_tag &&
       strcmp(ds->ds_remote_tag, sip->sip_from->a_tag))) {
    return 481;
  }
  assert(nh);

  du = dialog_usage_get(nh->nh_ds, nua_subscriber_usage, sip->sip_event);

  if (du == NULL)
    return 481;

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

  if (strcasecmp(subs->ss_substate, "terminated") == 0) {
    du->du_subscriber->de_substate = nua_substate_terminated;

    if (str0casecmp(subs->ss_reason, "deactivated") == 0) {
      du->du_subscriber->de_substate = nua_substate_embryonic;
      retry = 0;
    } 
    else if (str0casecmp(subs->ss_reason, "probation") == 0) {
      char const *retry_after;
      du->du_subscriber->de_substate = nua_substate_embryonic;
      retry = 30;
      retry_after = msg_params_find(subs->ss_params, "retry-after=");
      if (retry_after)
	retry = strtoul(retry_after, NULL, 10);
    } 
  }
  else if (strcasecmp(subs->ss_substate, "pending") == 0)
    du->du_subscriber->de_substate = nua_substate_pending;
  else /* if (strcasecmp(subs->ss_substate, "active") == 0) */
    /* XXX - any extended state is considered as active */
    du->du_subscriber->de_substate = nua_substate_active;

  ua_event(nh->nh_nua, nh,  nta_incoming_getrequest(irq),
	   nua_i_notify, 0, NULL, 
	   NUTAG_SUBSTATE(du->du_subscriber->de_substate),
	   TAG_END());

  if (nta_incoming_url(irq)->url_type == url_sips && nua->nua_sips_contact)
    *m0 = *nua->nua_sips_contact, m = m0;
  else if (nua->nua_contact)
    *m0 = *nua->nua_contact, m = m0;
  m0->m_params = NULL;
    
  nta_incoming_treply(irq, SIP_200_OK, SIPTAG_CONTACT(m), NULL);
  nta_incoming_destroy(irq), irq = NULL;

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
			 NUTAG_USE_LEG(1),
			 SIPTAG_EVENT(SIP_NONE->sh_event), /* remove event */
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
				      msg);
  
  if (!cr->cr_orq) {
    if (du)
      dialog_usage_remove(nh, nh->nh_ds, du);
    su_free(nh->nh_home, event);
    msg_destroy(msg);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

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
	   nua_i_refer, 0, NULL, 
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

  } else if (status < 0) {
    ua_event(nua, nh, NULL, e, 500, "Cannot add credentials", TAG_END());
  } else {
    ua_event(nua, nh, NULL, e, 404, "No matching challenge", TAG_END());
  }
}


/* ======================================================================== */
/* Event server */

static
nea_event_t *nh_notifier_event(nua_handle_t *nh, 
			       su_home_t *home, 
			       sip_event_t const *event,
			       tagi_t const *tags);

static
void authenticate_watcher(nea_server_t *nes,
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
	  SIPTAG_CONTENT_TYPE_REF(ct),
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
			       nua->nua_max_subscriptions, 
			       NULL, nh,
			       TAG_NEXT(tags)))) 
    status = 500, phrase = "Internal NUA Error";

  else if (!event && !(event = sip_event_make(home, event_s)))
    status = 500, phrase = "Could not create an event header";

  else if (!(ev = nh_notifier_event(nh, home, event, tags)))
    status = 500, phrase = "Could not create an event view";

  else if (nea_server_update(nh->nh_notifier, ev, 
			      SIPTAG_CONTENT_TYPE(ct),
			      SIPTAG_CONTENT_TYPE_STR(ct_s),
			      SIPTAG_PAYLOAD(pl),
			      SIPTAG_PAYLOAD_STR(pl_s),
			      TAG_END()) < 0) 
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
			  authenticate_watcher, nh,
			  o_type, o_subtype,
			  ct ? ct->c_type : ct_s,
			  accept_s);
  }

  return ev;
}


static
void authenticate_watcher(nea_server_t *nes,
			  nua_handle_t *nh,
			  nea_event_t *ev,
			  nea_subnode_t *sn,
			  sip_t const *sip)
{
  if (sn->sn_state == nea_embryonic) {
    SU_DEBUG_7(("nea: authenticate_watcher: new watcher\n")); 
    nea_server_auth(sn->sn_subscriber, nea_active, TAG_END());
  }
  else if (sn->sn_state == nea_terminated || sn->sn_expires == 0) {
    nea_server_flush(nes, NULL);
    SU_DEBUG_7(("nea: authenticate_watcher: watcher is removed\n")); 
  }
}


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
      nea_server_auth(subs[i]->sn_subscriber, nea_terminated, ta_tags(ta));
    
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

  enter;

  nta_incoming_tag_3261(irq, NULL);

  if (uas_check_method(irq, sip, nh->nh_allow, 
		       SIPTAG_SUPPORTED(nua->nua_supported), 
		       TAG_END()))
    return 405;

  switch (sip->sip_request->rq_url->url_type) {
  case url_sip:
  case url_sips:
  case url_im:
    break;
  default:
    nta_incoming_treply(irq, SIP_416_UNSUPPORTED_URI, TAG_END());
  }

  if (uas_check_required(irq, sip, 
			 nh->nh_supported 
			 ? nh->nh_supported 
			 : nua->nua_supported, 
			 TAG_END()))
    return 420;

  if (nh == nua->nua_default) {
    if (!sip->sip_to->a_tag)
      ;
    else if (nua->nua_enableMessenger && method == sip_method_message)
      ;
    else {
      nta_incoming_treply(irq, 481, "Initial transaction with a To tag", TAG_END());
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
			SIPTAG_USER_AGENT(nua->nua_user_agent),
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

  if (ss->ss_respond_to_invite) {
    ss->ss_respond_to_invite(nua, nh, status, phrase, tags);
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

  else if (ss->ss_invite_irq) {
    ua_event(nua, nh, NULL, nua_i_error,
	     500, "Already Sent Final Response", TAG_END());
  } else {
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
