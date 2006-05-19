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

#ifndef NUA_PARAMS_H
/** Defined when <nua_params.h> has been included. */
#define NUA_PARAMS_H

/**@internal @file nua_params.h 
 * @brief Parameters and their handling
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 *
 * @date Created: Wed Mar  8 11:38:18 EET 2006  ppessi
 */

typedef struct nua_handle_preferences
{
  unsigned         nhp_retry_count;	/**< times to retry a request */
  unsigned         nhp_max_subscriptions;

  /* Session-related preferences */
  unsigned     	   nhp_invite_enable:1;
  unsigned     	   nhp_auto_alert:1;
  unsigned         nhp_early_media:1;/**< Establish early media session */
  unsigned         nhp_only183_100rel:1;/**< Only 100rel 183. */
  unsigned         nhp_auto_answer:1;
  unsigned         nhp_auto_ack:1; /**< Automatically ACK a final response */
  unsigned         :0;

  /** INVITE timeout. 
   *
   * If no response is received in nhp_invite_timeout seconds,
   * INVITE client transaction times out
   */
  unsigned         nhp_invite_timeout;

  /* REGISTER Keepalive intervals */
  unsigned         nhp_keepalive, nhp_keepalive_stream;
  
  /** Default session timer (in seconds, 0 disables) */
  unsigned         nhp_session_timer;
  /** Default Min-SE Delta value */
  unsigned         nhp_min_se;
  /** no (preference), local or remote */
  enum nua_session_refresher nhp_refresher; 
  unsigned         nhp_update_refresh:1; /**< Use UPDATE to refresh */
  
  /* Messaging preferences */
  unsigned     	   nhp_message_enable : 1;
  /** Be bug-compatible with Windows Messenger */
  unsigned     	   nhp_win_messenger_enable : 1;
  /** PIM-IW hack */
  unsigned         nhp_message_auto_respond : 1;

  /* Preferences for registration (and dialog establishment) */
  unsigned         nhp_callee_caps:1; /**< Add callee caps to contact */
  unsigned         nhp_media_features:1;/**< Add media features to caps*/
  /** Enable Service-Route */
  unsigned         nhp_service_route_enable:1;
  /** Enable Path */
  unsigned         nhp_path_enable:1;

  unsigned:0;

  /* Default lifetime for implicit subscriptions created by REFER */
  unsigned         nhp_refer_expires;

  /* Subscriber state, i.e. nua_substate_pending */
  unsigned         nhp_substate;

  sip_allow_t        *nhp_allow;
  sip_supported_t    *nhp_supported;
  sip_user_agent_t   *nhp_user_agent;
  char const         *nhp_ua_name;
  sip_organization_t *nhp_organization;

  char const         *nhp_instance;
  /**< Outbound OPTIONS */
  char const         *nhp_outbound; 

  /* A bit for each feature set by application */
  union {
    uint32_t set_any;
    struct {
      unsigned nhb_retry_count:1;
      unsigned nhb_max_subscriptions:1;
      unsigned nhb_invite_enable:1;
      unsigned nhb_auto_alert:1;
      unsigned nhb_early_media:1;
      unsigned nhb_only183_100rel:1;
      unsigned nhb_auto_answer:1;
      unsigned nhb_auto_ack:1;
      unsigned nhb_invite_timeout:1;
      unsigned nhb_keepalive:1;
      unsigned nhb_keepalive_stream:1;
      unsigned nhb_session_timer:1;
      unsigned nhb_min_se:1;
      unsigned nhb_refresher:1; 
      unsigned nhb_update_refresh:1;
      unsigned nhb_message_enable:1;
      unsigned nhb_win_messenger_enable:1;
      unsigned nhb_message_auto_respond:1;
      unsigned nhb_callee_caps:1;
      unsigned nhb_media_features:1;
      unsigned nhb_service_route_enable:1;
      unsigned nhb_path_enable:1;
      unsigned nhb_refer_expires:1;
      unsigned nhb_substate:1;
      unsigned nhb_allow:1;
      unsigned nhb_supported:1;
      unsigned nhb_user_agent:1;
      unsigned nhb_ua_name:1;
      unsigned nhb_organization:1;
      unsigned nhb_instance:1;
      unsigned nhb_outbound:1;
      unsigned :0;
    } set_bits;
  } nhp_set;
} nua_handle_preferences_t;

#define DNHP_GET(dnhp, pref) ((dnhp)->nhp_##pref)

#define NHP_GET(nhp, dnhp, pref)					\
  ((nhp)->nhp_set.set_bits.nhb_##pref					\
   ? (nhp)->nhp_##pref : (dnhp)->nhp_##pref)

#define NHP_SET(nhp, pref, value)					\
  ((nhp)->nhp_##pref = (value),						\
   (nhp)->nhp_set.set_bits.nhb_##pref = 1)

/* Check if preference is set */
#define NHP_ISSET(nhp, pref)						\
  ((nhp)->nhp_set.set_bits.nhb_##pref)

#define NHP_UNSET_ALL(nhp) ((nhp)->nhp_set.set_any = 0)
#define NHP_SET_ALL(nhp) ((nhp)->nhp_set.set_any = 0xffffffffU)
#define NHP_IS_ANY_SET(nhp) ((nhp)->nhp_set.set_any != 0)

/* Get preference from handle, if set, otherwise from default handle */
#define NH_PGET(nh, pref)						\
  NHP_GET((nh)->nh_prefs, (nh)->nh_nua->nua_dhandle->nh_prefs, pref)
/* Get preference from default handle */
#define DNH_PGET(dnh, pref)						\
  DNHP_GET((dnh)->nh_prefs, pref)
/* Check if preference is set in the handle */
#define NH_PISSET(nh, pref)						\
  (NHP_ISSET((nh)->nh_prefs, pref) &&					\
   (nh)->nh_nua->nua_dhandle->nh_prefs != (nh)->nh_prefs)

#endif /* NUA_PARAMS_H */
