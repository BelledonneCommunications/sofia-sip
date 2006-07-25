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

/**@CFILE nua_register.c
 * @brief REGISTER and registrations
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 11:48:49 EET 2006 ppessi
 */

#include "config.h"

#include <sofia-sip/string0.h>
#include <sofia-sip/su_strlst.h>
#include <sofia-sip/token64.h>
#include <sofia-sip/su_tagarg.h>

#include <sofia-sip/bnf.h>

#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/msg_parser.h>

#include "nua_stack.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <assert.h>

/* ====================================================================== */
/* Stack and handle parameters */

static int nua_stack_set_smime_params(nua_t *nua, tagi_t const *tags);

/** @internal Methods allowed by default. */
static char const nua_allow_str[] =
"INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, "
"MESSAGE, SUBSCRIBE, NOTIFY, REFER, UPDATE";

/** @internal Set default parameters */
int nua_stack_set_defaults(nua_handle_t *nh, 
			   nua_handle_preferences_t *nhp)
{
  su_home_t *home = (su_home_t *)nh;

  /* Set some defaults */
  NHP_SET(nhp, retry_count, 3);
  NHP_SET(nhp, max_subscriptions, 20);

  NHP_SET(nhp, invite_enable, 1);
  NHP_SET(nhp, auto_alert, 0);
  NHP_SET(nhp, early_media, 0);
  NHP_SET(nhp, only183_100rel, 0);
  NHP_SET(nhp, auto_answer, 0);
  NHP_SET(nhp, auto_ack, 1);
  NHP_SET(nhp, invite_timeout, 120);

  NHP_SET(nhp, session_timer, 1800);
  NHP_SET(nhp, min_se, 120);
  NHP_SET(nhp, refresher, nua_no_refresher);
  NHP_SET(nhp, update_refresh, 0);

  NHP_SET(nhp, message_enable, 1);
  NHP_SET(nhp, win_messenger_enable, 0);
  if (getenv("PIMIW_HACK") != 0)
    NHP_SET(nhp, message_auto_respond, 1);

  NHP_SET(nhp, media_features,  0);
  NHP_SET(nhp, callee_caps, 0);
  NHP_SET(nhp, service_route_enable, 1);
  NHP_SET(nhp, path_enable, 1);

  NHP_SET(nhp, refer_expires, 300);

  NHP_SET(nhp, substate, nua_substate_active);

  NHP_SET(nhp, allow, sip_allow_make(home, nua_allow_str));
  NHP_SET(nhp, supported, sip_supported_make(home, "timer, 100rel"));
  NHP_SET(nhp, user_agent,
	   sip_user_agent_make(home, PACKAGE_NAME "/" PACKAGE_VERSION));

  NHP_SET(nhp, outbound, su_strdup(home, "natify"));

  NHP_SET(nhp, keepalive, 120000);

  if (!nhp->nhp_allow ||
      !nhp->nhp_supported ||
      !nhp->nhp_user_agent ||
      !nhp->nhp_outbound)
    return -1;

  return 0;
}

/** @internal Set the default from field */
int nua_stack_set_from(nua_t *nua, int initial, tagi_t const *tags)
{
  sip_from_t const *from = NONE;
  char const *str = NONE;
  sip_from_t *f = NULL,  f0[1];

  char const *uicc_name = "default";

  tl_gets(tags,
	  /* By nua_stack_set_from() */
	  SIPTAG_FROM_REF(from),
	  SIPTAG_FROM_STR_REF(str),
	  NUTAG_UICC_REF(uicc_name),
	  TAG_END());

#if HAVE_UICC_H
  if (initial && uicc_name)
    nua->nua_uicc = uicc_create(root, uicc_name);
#endif

  if (!initial && from == NONE && str == NONE)
    return 0;

  sip_from_init(f0);

  if (from && from != NONE) {
    f0->a_display = from->a_display;
    *f0->a_url = *from->a_url;
    f = sip_from_dup(nua->nua_home, f0);
  }
  else if (str && str != NONE) {
    f = sip_from_make(nua->nua_home, str);
    if (f)
      *f0 = *f, f = f0, f->a_params = NULL;
  }
  else {
    sip_contact_t const *m;

    m = nua_stack_get_contact(nua->nua_registrations);
    
    if (m) {
      f0->a_display = m->m_display;
      *f0->a_url = *m->m_url;
      f = sip_from_dup(nua->nua_home, f0);
    }
  }

  if (!f)
    return -1;

  *nua->nua_from = *f;
  return 0;
}

/** @internal Initialize instance ID. */
int nua_stack_init_instance(nua_handle_t *nh, tagi_t const *tags)
{
  nua_handle_preferences_t *nhp = nh->nh_prefs;

  char const *instance = NONE;

  tl_gets(tags, NUTAG_INSTANCE_REF(instance), TAG_END());

  if (instance != NONE) {
    NHP_SET(nhp, instance, su_strdup(nh->nh_home, instance));
    if (instance && !nhp->nhp_instance)
      return -1;
  }

  return 0;
}

/**@fn void nua_set_params(nua_t *nua, tag_type_t tag, tag_value_t value, ...)
 *
 * Set NUA parameters.
 *
 * @param nua             Pointer to NUA stack object
 * @param tag, value, ... List of tagged parameters
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *   NUTAG_ALLOW() \n
 *   NUTAG_AUTOACK() \n
 *   NUTAG_AUTOALERT() \n
 *   NUTAG_AUTOANSWER() \n
 *   NUTAG_CALLEE_CAPS() \n
 *   NUTAG_CERTIFICATE_DIR() \n
 *   NUTAG_EARLY_MEDIA() \n
 *   NUTAG_ENABLEINVITE() \n
 *   NUTAG_ENABLEMESSAGE() \n
 *   NUTAG_ENABLEMESSENGER() \n
 *   NUTAG_INSTANCE() \n
 *   NUTAG_INVITE_TIMER() \n
 *   NUTAG_KEEPALIVE() \n
 *   NUTAG_KEEPALIVE_STREAM() \n
 *   NUTAG_MAX_SUBSCRIPTIONS() \n
 *   NUTAG_MEDIA_FEATURES() \n
 *   NUTAG_MIN_SE() \n
 *   NUTAG_OUTBOUND() \n
 *   NUTAG_PATH_ENABLE() \n
 *   NUTAG_REGISTRAR() \n
 *   NUTAG_SERVICE_ROUTE_ENABLE() \n
 *   NUTAG_SESSIONRESHER() \n
 *   NUTAG_SESSION_TIMER() \n
 *   NUTAG_SMIME_ENABLE() \n
 *   NUTAG_SMIME_KEY_ENCRYPTION() \n
 *   NUTAG_SMIME_MESSAGE_DIGEST() \n
 *   NUTAG_SMIME_MESSAGE_ENCRYPTION() \n
 *   NUTAG_SMIME_OPT() \n
 *   NUTAG_SMIME_PROTECTION_MODE() \n
 *   NUTAG_SMIME_SIGNATURE() \n
 *   NUTAG_SUBSTATE() \n
 *   NUTAG_UPDATERESH() \n
 *   NUTAG_USER_AGENT() \n
 *   SIPTAG_ALLOW() \n
 *   SIPTAG_ALLOW_STR() \n
 *   SIPTAG_FROM() \n
 *   SIPTAG_FROM_STR() \n
 *   SIPTAG_ORGANIZATION() \n
 *   SIPTAG_ORGANIZATION_STR() \n
 *   SIPTAG_SUPPORTED() \n
 *   SIPTAG_SUPPORTED_STR() \n
 *   SIPTAG_USER_AGENT() \n
 *   SIPTAG_USER_AGENT_STR() \n
 *   NUTAG_RETRY_COUNT() \n
 *
 * nua_set_params() also accepts any soa tags, defined in
 * <sofia-sip/soa_tag.h>, and nta tags, defined in <sofia-sip/nta_tag.h>.
 * 
 * @par Events:
 *     nua_r_set_params
 */

/**@fn void nua_set_hparams(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);
 * Set handle-specific parameters.
 *
 * @param nh              Pointer to a NUA handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *   NUTAG_ALLOW() \n
 *   NUTAG_AUTOACK() \n
 *   NUTAG_AUTOALERT() \n
 *   NUTAG_AUTOANSWER() \n
 *   NUTAG_CALLEE_CAPS() \n
 *   NUTAG_EARLY_MEDIA() \n
 *   NUTAG_ENABLEINVITE() \n
 *   NUTAG_ENABLEMESSAGE() \n
 *   NUTAG_ENABLEMESSENGER() \n
 *   NUTAG_INVITE_TIMER() \n
 *   NUTAG_KEEPALIVE() \n
 *   NUTAG_KEEPALIVE_STREAM() \n
 *   NUTAG_MAX_SUBSCRIPTIONS() \n
 *   NUTAG_MEDIA_FEATURES() \n
 *   NUTAG_MIN_SE() \n
 *   NUTAG_PATH_ENABLE() \n
 *   NUTAG_RETRY_COUNT() \n
 *   NUTAG_SERVICE_ROUTE_ENABLE() \n
 *   NUTAG_SESSIONRESHER() \n
 *   NUTAG_SESSION_TIMER() \n
 *   NUTAG_SUBSTATE() \n
 *   NUTAG_UPDATERESH() \n
 *   NUTAG_USER_AGENT() \n
 *   SIPTAG_ALLOW() \n
 *   SIPTAG_ALLOW_STR() \n
 *   SIPTAG_ORGANIZATION() \n
 *   SIPTAG_ORGANIZATION_STR() \n
 *   SIPTAG_SUPPORTED() \n
 *   SIPTAG_SUPPORTED_STR() \n
 *   SIPTAG_USER_AGENT() \n
 *   SIPTAG_USER_AGENT_STR() \n
 *
 * nua_set_hparams() also accepts any soa tags, defined in
 * <sofia-sip/soa_tag.h>.
 *
 * @par Events:
 *     none
 */


int nua_stack_set_params(nua_t *nua, nua_handle_t *nh, nua_event_t e,
			 tagi_t const *tags)
{
  nua_handle_t *dnh = nua->nua_dhandle;
  nua_handle_preferences_t nhp[1], *ohp = nh->nh_prefs;
  nua_handle_preferences_t const *dnhp = dnh->nh_prefs;

  su_home_t tmphome[1] = { SU_HOME_INIT(tmphome) };

  tagi_t const *t;

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

  char const *instance = NONE;
  char const *outbound = NONE;
  
  int error = 0;

  enter;

  *nhp = *ohp; NHP_UNSET_ALL(nhp);

  for (t = tags; t; t = tl_next(t)) {
    if (t->t_tag == NULL)
      break;
    /* NUTAG_RETRY_COUNT(retry_count) */
    else if (t->t_tag == nutag_retry_count) {
      NHP_SET(nhp, retry_count, (unsigned)t->t_value);
    }
    /* NUTAG_MAX_SUBSCRIPTIONS(max_subscriptions) */
    else if (t->t_tag == nutag_max_subscriptions) {
      NHP_SET(nhp, max_subscriptions, (unsigned)t->t_value);
    }
    /* NUTAG_ENABLEINVITE(invite_enable) */
    else if (t->t_tag == nutag_enableinvite) {
      NHP_SET(nhp, invite_enable, t->t_value != 0);
    }
    /* NUTAG_AUTOALERT(auto_alert) */
    else if (t->t_tag == nutag_autoalert) {
      NHP_SET(nhp, auto_alert, t->t_value != 0);
    }
    /* NUTAG_EARLY_MEDIA(early_media) */
    else if (t->t_tag == nutag_early_media) {
      NHP_SET(nhp, early_media, t->t_value != 0);
    }
    /* NUTAG_ONLY183_100REL(only183_100rel) */
    else if (t->t_tag == nutag_only183_100rel) {
      NHP_SET(nhp, only183_100rel, t->t_value != 0);
    }
    /* NUTAG_AUTOANSWER(auto_answer) */
    else if (t->t_tag == nutag_autoanswer) {
      NHP_SET(nhp, auto_answer, t->t_value != 0);
    }
    /* NUTAG_AUTOACK(auto_ack) */
    else if (t->t_tag == nutag_autoack) {
      NHP_SET(nhp, auto_ack, t->t_value != 0);
    }
    /* NUTAG_INVITE_TIMER(invite_timeout) */
    else if (t->t_tag == nutag_invite_timer) {
      NHP_SET(nhp, invite_timeout, (unsigned)t->t_value);
    }
    /* NUTAG_SESSION_TIMER(session_timer) */
    else if (t->t_tag == nutag_session_timer) {
      NHP_SET(nhp, session_timer, (unsigned)t->t_value);
    }
    /* NUTAG_MIN_SE(min_se) */
    else if (t->t_tag == nutag_min_se) {
      NHP_SET(nhp, min_se, (unsigned)t->t_value);
    }
    /* NUTAG_SESSION_REFRESHER(refresher) */
    else if (t->t_tag == nutag_session_refresher) {
      NHP_SET(nhp, refresher, (int)t->t_value);
    }
    /* NUTAG_UPDATE_REFRESH(update_refresh) */
    else if (t->t_tag == nutag_update_refresh) {
      NHP_SET(nhp, update_refresh, t->t_value != 0);
    }
    /* NUTAG_ENABLEMESSAGE(message_enable) */
    else if (t->t_tag == nutag_enablemessage) {
      NHP_SET(nhp, message_enable, t->t_value != 0);
    }
    /* NUTAG_ENABLEMESSENGER(win_messenger_enable) */
    else if (t->t_tag == nutag_enablemessenger) {
      NHP_SET(nhp, win_messenger_enable, t->t_value != 0);
    }
#if 0
    /* NUTAG_MESSAGE_AUTOANSWER(message_auto_respond) */
    else if (t->t_tag == nutag_message_autoanwer) {
      NHP_SET(nhp, message_auto_respond, t->t_value);
    }
#endif
    /* NUTAG_CALLEE_CAPS(callee_caps) */
    else if (t->t_tag == nutag_callee_caps) {
      NHP_SET(nhp, callee_caps, t->t_value != 0);
    }
    /* NUTAG_MEDIA_FEATURES(media_features) */
    else if (t->t_tag == nutag_media_features) {
      NHP_SET(nhp, media_features, t->t_value != 0);
    }
    /* NUTAG_SERVICE_ROUTE_ENABLE(service_route_enable) */
    else if (t->t_tag == nutag_service_route_enable) {
      NHP_SET(nhp, service_route_enable, t->t_value != 0);
    }
    /* NUTAG_PATH_ENABLE(path_enable) */
    else if (t->t_tag == nutag_path_enable) {
      NHP_SET(nhp, path_enable, t->t_value != 0);
    }
    /* NUTAG_SUBSTATE(substate) */
    else if (t->t_tag == nutag_substate) {
      NHP_SET(nhp, substate, (int)t->t_value);
    }
    /* NUTAG_KEEPALIVE(keepalive) */
    else if (t->t_tag == nutag_keepalive) {
      NHP_SET(nhp, keepalive, (unsigned)t->t_value);
    }
    /* NUTAG_KEEPALIVE_STREAM(keepalive_stream) */
    else if (t->t_tag == nutag_keepalive_stream) {
      NHP_SET(nhp, keepalive_stream, (unsigned)t->t_value);
    }

    /* SIPTAG_SUPPORTED_REF(supported) */
    else if (t->t_tag == siptag_supported) {
      supported = (void *)t->t_value;
    }
    /* SIPTAG_SUPPORTED_STR_REF(supported_str) */
    else if (t->t_tag == siptag_supported_str) {
      supported_str = (void *)t->t_value;
    }
    /* SIPTAG_ALLOW_REF(allow) */
    else if (t->t_tag == siptag_allow) {
      allow = (void *)t->t_value;
    }
    /* SIPTAG_ALLOW_STR_REF(allow_str) */
    else if (t->t_tag == siptag_allow_str) {
      allow_str = (void *)t->t_value;
    }
    /* NUTAG_ALLOW_REF(allowing) */
    else if (t->t_tag == nutag_allow) {
      allowing = (void *)t->t_value;
    }
    /* SIPTAG_USER_AGENT_REF(user_agent) */
    else if (t->t_tag == siptag_user_agent) {
      user_agent = (void *)t->t_value;
    }
    /* SIPTAG_USER_AGENT_STR_REF(user_agent_str) */
    else if (t->t_tag == siptag_user_agent_str) {
      user_agent_str = (void *)t->t_value;
    }
    /* NUTAG_USER_AGENT_REF(ua_name) */
    else if (t->t_tag == nutag_user_agent) {
      ua_name = (void *)t->t_value;
    }
    /* SIPTAG_ORGANIZATION_REF(organization) */
    else if (t->t_tag == siptag_organization) {
      organization = (void *)t->t_value;
    }
    /* SIPTAG_ORGANIZATION_STR_REF(organization_str) */
    else if (t->t_tag == siptag_organization_str) {
      organization_str = (void *)t->t_value;
    }
    /* NUTAG_REGISTRAR_REF(registrar) */
    else if (t->t_tag == nutag_registrar) {
      registrar = (void *)t->t_value;
    }
    /* NUTAG_INSTANCE_REF(instance) */
    else if (t->t_tag == nutag_instance) {
      instance = (void *)t->t_value;
    }
    /* NUTAG_OUTBOUND_REF(outbound) */
    else if (t->t_tag == nutag_outbound) {
      outbound = (void *)t->t_value;
    }
  }

  /* Sanitize values */
#if 0				/* OK, trust application... */
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
#endif

  if (NHP_ISSET(nhp, refresher)) {
    if (nhp->nhp_refresher >= nua_remote_refresher)
      nhp->nhp_refresher = nua_remote_refresher;
    else if (nhp->nhp_refresher <= nua_no_refresher)
      nhp->nhp_refresher = nua_no_refresher;
  }

  /* Set string in handle pref structure */
#define NHP_SET_STR(nhp, name, str)				 \
  if (str != NONE) {						 \
    char *new_str = su_strdup(tmphome, str);			 \
    NHP_SET(nhp, name, new_str);				 \
    error |= (new_str != NULL && str == NULL);			 \
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
      error = 1;						 \
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
	error = 1, allow = NONE;
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

  NHP_SET_STR(nhp, instance, instance);
  NHP_SET_STR(nhp, outbound, outbound);

  if (!error && NHP_IS_ANY_SET(nhp)) {
    /* Move allocations from tmphome to handle's home */
    if (nh != dnh && nh->nh_prefs == dnh->nh_prefs) {
      /* We have made changes to handle-specific settings
       * but we don't have a prefs structure owned by handle yet */
      nua_handle_preferences_t *ahp = su_alloc(nh->nh_home, sizeof *ahp);
      if (ahp && su_home_move(nh->nh_home, tmphome) >= 0) {
	memcpy(ahp, nhp, sizeof *ahp);

	/* Zap pointers which are not set */
#define NHP_ZAP_UNSET_PTR(nhp, pref) \
	(!(nhp)->nhp_set.set_bits.nhb_##pref ? (nhp)->nhp_##pref = NULL : NULL)

	NHP_ZAP_UNSET_PTR(ahp, supported);
	NHP_ZAP_UNSET_PTR(ahp, allow);
	NHP_ZAP_UNSET_PTR(ahp, user_agent);
	NHP_ZAP_UNSET_PTR(ahp, ua_name);
	NHP_ZAP_UNSET_PTR(ahp, organization);
	NHP_ZAP_UNSET_PTR(ahp, instance);
	NHP_ZAP_UNSET_PTR(ahp, outbound);

	nh->nh_prefs = ahp;
      }
      else {
	error = 1;
      }
    }
    else if (su_home_move(nh->nh_home, tmphome) >= 0) {
      /* Update prefs structure */
      nua_handle_preferences_t tbf[1];
      nhp->nhp_set.set_any |= ohp->nhp_set.set_any;
      *tbf = *ohp; *ohp = *nhp;

      /* Free changed items */
#define NHP_ZAP_OVERRIDEN(tbf, nhp, pref)			\
      ((tbf)->nhp_set.set_bits.nhb_##pref			\
       && (tbf)->nhp_##pref != (nhp)->nhp_##pref		\
       ? su_free(nh->nh_home, (void *)(tbf)->nhp_##pref) : (void)0)

      NHP_ZAP_OVERRIDEN(tbf, nhp, supported);
      NHP_ZAP_OVERRIDEN(tbf, nhp, allow);
      NHP_ZAP_OVERRIDEN(tbf, nhp, user_agent);
      NHP_ZAP_OVERRIDEN(tbf, nhp, ua_name);
      NHP_ZAP_OVERRIDEN(tbf, nhp, organization);
      NHP_ZAP_OVERRIDEN(tbf, nhp, instance);
      NHP_ZAP_OVERRIDEN(tbf, nhp, outbound);

    }
    else
      /* Fail miserably with ENOMEM */
      error = 1;
  }

  su_home_deinit(tmphome);

  if (error)
    return UA_EVENT2(e, 900, "Error storing parameters"), -1;

  if (nh->nh_soa && soa_set_params(nh->nh_soa, TAG_NEXT(tags)) < 0)
    return UA_EVENT2(e, 900, "Error setting SOA parameters"), -1;

#if 0
  reinit_contact =
    nua->nua_dhandle->nh_callee_caps != callee_caps ||
    media_path != NONE || allow != NONE || allow_str != NONE;
#endif

  if (nh != dnh)
    return e == nua_r_set_params ? UA_EVENT2(e, 200, "OK") : 0;

  if (nta_agent_set_params(nua->nua_nta, TAG_NEXT(tags)) < 0)
    return UA_EVENT2(e, 900, "Error setting NTA parameters"), -1;

  /* ---------------------------------------------------------------------- */
  /* Set stack-specific things below */

  if (registrar != NONE) {
    if (registrar &&
	(url_string_p(registrar) ?
	 strcmp(registrar->us_str, "*") == 0 :
	 registrar->us_url->url_type == url_any))
      registrar = NULL;
    su_free(nua->nua_home, nua->nua_registrar);
    nua->nua_registrar = url_hdup(nua->nua_home, registrar->us_url);
  }

  nua_stack_set_from(nua, 0, tags);

  nua_stack_set_smime_params(nua, tags);

  return e == nua_r_set_params ? UA_EVENT2(e, 200, "OK") : 0;
}

static
int nua_stack_set_smime_params(nua_t *nua, tagi_t const *tags)
{
#if HAVE_SOFIA_SMIME
  int           smime_enable = nua->sm->sm_enable;
  int           smime_opt = nua->sm->sm_opt;
  int           smime_protection_mode = nua->sm->sm_protection_mode;
  char const   *smime_message_digest = NONE;
  char const   *smime_signature = NONE;
  char const   *smime_key_encryption = NONE;
  char const   *smime_message_encryption = NONE;
  char const   *smime_path = NONE;

  int n;

  n = tl_gets(tags,
	      NUTAG_SMIME_ENABLE_REF(smime_enable),
	      NUTAG_SMIME_OPT_REF(smime_opt),
	      NUTAG_SMIME_PROTECTION_MODE_REF(smime_protection_mode),
	      NUTAG_SMIME_MESSAGE_DIGEST_REF(smime_message_digest),
	      NUTAG_SMIME_SIGNATURE_REF(smime_signature),
	      NUTAG_SMIME_KEY_ENCRYPTION_REF(smime_key_encryption),
	      NUTAG_SMIME_MESSAGE_ENCRYPTION_REF(smime_message_encryption),
	      NUTAG_CERTIFICATE_DIR_REF(smime_path),
	      TAG_NULL());
  if (n <= 0)
    return n;

  /* XXX - all other S/MIME parameters? */
  return sm_set_params(nua->sm, smime_enable, smime_opt, 
		       smime_protection_mode, smime_path);
#endif

  return 0;
}

/**@fn void nua_get_params(nua_t *nua, tag_type_t tag, tag_value_t value, ...)
 *
 * Get NUA parameters.
 *
 * Get values of NUA parameters in #nua_r_get_params event.
 *
 * @param nua             Pointer to NUA stack object
 * @param tag, value, ... List of tagged parameters
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     #TAG_ANY \n
 *     othervise same tags as nua_set_params()
 *
 * @par Events:
 *     #nua_r_get_params
 */

/**@fn void nua_get_hparams(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
 * 
 * Get values of handle-specific parameters in nua_r_get_params event.
 *
 * Application will specify either expilicit list of tags it is interested
 * in, or a filter (at the moment, TAG_ANY()). The values are returned as a
 * list of tags in the nua_r_get_params event.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * The handle-specific parameters will contain only the parameters actually
 * modified by application, either by nua_set_hparams() or some other
 * handle-specific call. Currently, no NTA parameters are returned. They are
 * returned only when application asks for user-agent-level parameters using
 * either nua_get_params() or using default handle, eg.
 * @code
 * nua_get_hparams(nua_default(nua), TAG_ANY())
 * @endcode
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     #TAG_ANY \n
 *     othervise same tags as nua_set_hparams()
 *
 * @par Events:
 *     #nua_r_get_hparams
 */

/**@internal
 * Send a list of NUA parameters to the application.
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

  m = nua_stack_get_contact(nua->nua_registrations);

  /* Include tag in list returned to user
   * if it has been earlier set (by user) */
#define TIF(TAG, pref) \
  TAG_IF(nhp->nhp_set.set_bits.nhb_##pref, TAG(nhp->nhp_##pref))

  /* Include string tag made out of SIP header
   * if it has been earlier set (by user) */
#define TIF_STR(TAG, pref)						\
  TAG_IF(nhp->nhp_set.set_bits.nhb_##pref,				\
	 TAG(nhp->nhp_set.set_bits.nhb_##pref && nhp->nhp_##pref	\
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
     TIF(NUTAG_ONLY183_100REL, only183_100rel),
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

     TIF(NUTAG_OUTBOUND, outbound),
     TIF(NUTAG_INSTANCE, instance),
     TIF(NUTAG_KEEPALIVE, keepalive),
     TIF(NUTAG_KEEPALIVE_STREAM, keepalive_stream),

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
