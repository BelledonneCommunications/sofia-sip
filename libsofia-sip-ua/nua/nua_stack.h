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

#ifndef NUA_STACK_H /** Defined when <nua_stack.h> has been included. */
#define NUA_STACK_H
/**@file nua_stack.h 
 * @brief Sofia-SIP User Agent Engine - internal stack interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 *
 * @date Created: Wed Feb 14 17:09:44 2001 ppessi
 */

#ifndef SU_CONFIG_H
#include <su_config.h>
#endif

#if HAVE_UICC_H
#include <uicc.h>
#endif

#if SU_HAVE_PTHREADS
#include <pthread.h>
#endif

#ifndef SOA_H
#include "sofia-sip/soa.h"
#endif
#ifndef NTA_H
#include <sofia-sip/nta.h>
#endif
#ifndef AUTH_CLIENT_H
#include <sofia-sip/auth_client.h>
#endif
#ifndef NEA_H
#include <sofia-sip/nea.h>
#endif
#ifndef NUA_H
#include <sofia-sip/nua.h>
#endif

#define SU_LOG (nua_log)
#include <sofia-sip/su_debug.h>

#ifndef NUA_DIALOG_H
#define NUA_OWNER_T struct nua_handle_s
#include <nua_dialog.h>
#endif

SOFIA_BEGIN_DECLS

#if HAVE_SIGCOMP
#include <sigcomp.h>
#endif

typedef struct event_s event_t;

#define       NONE ((void *)-1)

enum nh_kind {
  nh_has_nothing,
  nh_has_invite,
  nh_has_subscribe,
  nh_has_notify,
  nh_has_register,
  nh_has_streaming
};

enum nh_oa_event {
  nua_sdp_none,
  nua_sdp_offer_sent,		/**< O/A-1 offer sent */
  nua_sdp_answer_recv,		/**< O/A-2 answer received */
  nua_sdp_offer_recv,		/**< O/A-3 offer received */
  nua_sdp_answer_sent		/**< O/A-4 answer sent */
};

typedef struct nua_chat_s nua_chat_t;

typedef struct nua_client_request nua_client_request_t; 
typedef struct nua_server_request nua_server_request_t; 

typedef void nua_creq_restart_f(nua_handle_t *, tagi_t *tags);

typedef struct register_usage nua_registration_t;

struct nua_client_request
{
  nua_event_t         cr_event;		/**< Request event */
  nua_creq_restart_f *cr_restart;
  nta_outgoing_t     *cr_orq;
  msg_t              *cr_msg;
  nua_dialog_usage_t *cr_usage;
  unsigned short      cr_retry_count;   /**< Retry count for this request */

  unsigned short      cr_answer_recv;   /**< Recv answer in response */
  unsigned            cr_offer_sent:1;  /**< Sent offer in this request */

  unsigned            cr_offer_recv:1;  /**< Recv offer in a response */
  unsigned            cr_answer_sent:1; /**< Sent answer in (PR)ACK */
};

typedef struct nua_session_state
{
  /** Session-related state */
  unsigned        ss_active:1;		/**< Session is currently active. */
  
  /* enum nua_callstate */
  unsigned        ss_state:4;		/**< Session status (enum nua_callstate) */
  
  unsigned        ss_100rel:1;	        /**< Use 100rel, send 183 */
  unsigned        ss_alerting:1;	/**< 180 is sent/received */
  
  unsigned        ss_update_needed:2;	/**< Send an UPDATE (do O/A if > 1) */

  unsigned        ss_precondition:1;	/**< Precondition required */

  unsigned        ss_hold_remote:1;	/**< We are holding remote */
  
  unsigned        : 0;
  
  unsigned        ss_session_timer;	/**< Value of Session-Expires (delta) */
  unsigned        ss_min_se;		/**< Minimum session expires */
  enum nua_session_refresher ss_refresher; /**< none, local or remote */

  char const     *ss_ack_needed;	/**< Send an ACK
					 * (do O/A, if "offer" or "answer")
					 */

  nua_dialog_usage_t *ss_usage;

  /* Outgoing invite */
  struct nua_client_request ss_crequest[1];

  /* Incoming invite */
  struct nua_server_request {

  /** Respond to an incoming INVITE transaction.
   *
   * When the application responds to an incoming INVITE transaction with
   * nua_respond(), the ss_respond_to_invite() is called (if non-NULL).
   */
    void (*sr_respond)(nua_t *nua, nua_handle_t *nh,
		       int status, char const *phrase, 
		       tagi_t const *tags);
    nta_incoming_t *sr_irq;
    msg_t *sr_msg;		/**< Request message */

    unsigned sr_offer_recv:1;	/**< We have received an offer */
    unsigned sr_answer_sent:2;	/**< We have answered (reliably, if >1) */

    unsigned sr_offer_sent:1;	/**< We have offered SDP */
    unsigned sr_answer_recv:1;	/**< We have received SDP answer */
  } ss_srequest[1];
} nua_session_state_t;

#define \
  NH_ACTIVE_MEDIA_TAGS(include, soa)					\
  TAG_IF((include) && (soa) && soa_is_audio_active(soa) >= 0,		\
	 SOATAG_ACTIVE_AUDIO(soa_is_audio_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_video_active(soa) >= 0,		\
	 SOATAG_ACTIVE_VIDEO(soa_is_video_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_image_active(soa) >= 0,		\
	 SOATAG_ACTIVE_IMAGE(soa_is_image_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_chat_active(soa) >= 0,		\
	 SOATAG_ACTIVE_CHAT(soa_is_chat_active(soa)))

#define \
  NH_REMOTE_MEDIA_TAGS(include, soa)					\
  TAG_IF((include) && (soa) && soa_is_remote_audio_active(soa) >= 0,	\
	 SOATAG_ACTIVE_AUDIO(soa_is_remote_audio_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_remote_video_active(soa) >= 0,	\
	 SOATAG_ACTIVE_VIDEO(soa_is_remote_video_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_remote_image_active(soa) >= 0,	\
	 SOATAG_ACTIVE_IMAGE(soa_is_remote_image_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_remote_chat_active(soa) >= 0,	\
	 SOATAG_ACTIVE_CHAT(soa_is_remote_chat_active(soa)))

typedef struct nua_handle_preferences
{
  unsigned         nhp_retry_count;	/**< times to retry a request */
  unsigned         nhp_max_subscriptions;

  /* Session-related preferences */
  unsigned     	   nhp_invite_enable:1;
  unsigned     	   nhp_auto_alert:1;
  unsigned         nhp_early_media:1;/**< Establish early media session */
  unsigned         nhp_auto_answer:1;
  unsigned         nhp_auto_ack:1; /**< Automatically ACK a final response */
  unsigned         nhp_natify:1;
  unsigned         nhp_gruuize:1;
  unsigned         nhp_check_register:1;
  unsigned         :0;

  /** INVITE timeout. 
   *
   * If no response is received in nhp_invite_timeout seconds,
   * INVITE client transaction times out
   */
  unsigned         nhp_invite_timeout;

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
  
  /* A bit for each feature set by application */
  union {
    uint32_t set_any;
    struct {
      unsigned nhp_retry_count:1;
      unsigned nhp_max_subscriptions:1;
      unsigned nhp_invite_enable:1;
      unsigned nhp_auto_alert:1;
      unsigned nhp_early_media:1;
      unsigned nhp_auto_answer:1;
      unsigned nhp_auto_ack:1;
      unsigned nhp_natify:1;
      unsigned nhp_gruuize:1;
      unsigned nhp_invite_timeout:1;
      unsigned nhp_session_timer:1;
      unsigned nhp_min_se:1;
      unsigned nhp_refresher:1; 
      unsigned nhp_update_refresh:1;
      unsigned nhp_message_enable:1;
      unsigned nhp_win_messenger_enable:1;
      unsigned nhp_message_auto_respond:1;
      unsigned nhp_callee_caps:1;
      unsigned nhp_media_features:1;
      unsigned nhp_service_route_enable:1;
      unsigned nhp_path_enable:1;
      unsigned nhp_refer_expires:1;
      unsigned nhp_substate:1;
      unsigned nhp_allow:1;
      unsigned nhp_supported:1;
      unsigned nhp_user_agent:1;
      unsigned nhp_ua_name:1;
      unsigned nhp_organization:1;
      unsigned nhp_instance;
      unsigned :0;
    } set_bits;
  } nhp_set;
} nua_handle_preferences_t;

/* Get preference from default handle */
#define DNH_PGET(dnh, pref)						\
  DNHP_GET((dnh)->nh_prefs, pref)
#define DNHP_GET(dnhp, pref) ((dnhp)->nhp_##pref)
#define DNHP_SET(dnhp, pref, value) \
  ((dnhp)->nhp_##pref = (value), (dnhp)->nhp_set.set_bits.nhp_##pref = 1)

/* Get preference from handle, if set, otherwise from default handle */
#define NH_PGET(nh, pref)						\
  NHP_GET((nh)->nh_prefs, (nh)->nh_nua->nua_dhandle->nh_prefs, pref)
#define NHP_GET(nhp, dnhp, pref)					\
  ((nhp)->nhp_set.set_bits.nhp_##pref					\
   ? (nhp)->nhp_##pref : (dnhp)->nhp_##pref)

/* Check if preference is set in the handle */
#define NH_PISSET(nh, pref)						\
  (NHP_ISSET((nh)->nh_prefs, pref) &&					\
   (nh)->nh_nua->nua_dhandle->nh_prefs != (nh)->nh_prefs)

/* Check if preference is set */
#define NHP_ISSET(nhp, pref)						\
  ((nhp)->nhp_set.set_bits.nhp_##pref)

#define NHP_UNSET_ALL(nhp) ((nhp)->nhp_set.set_any = 0)
#define NHP_SET_ALL(nhp) ((nhp)->nhp_set.set_any = 0xffffffffU)
#define NHP_IS_ANY_SET(nhp) ((nhp)->nhp_set.set_any != 0)

/** NUA handle. 
 *
 */
struct nua_handle_s 
{
  su_home_t       nh_home[1];	/**< Memory home  */
  nua_handle_t   *nh_next;
  nua_handle_t  **nh_prev;

  nua_t        	 *nh_nua;	/**< Pointer to NUA object  */
  void           *nh_valid;
  nua_hmagic_t 	 *nh_magic;	/**< Application context */

  tagi_t         *nh_tags;	/**< Default tags */

#if HAVE_PTHREAD_H
#if __CYGWIN__
  pthread_mutex_t  sup_reflock[1];
  int              sup_ref;
#else
  pthread_rwlock_t nh_refcount[1];  
#endif
#else
  unsigned        nh_refcount;
#endif

  nua_handle_preferences_t *nh_prefs; /**< Preferences */

  /* Handle state */
  nua_event_t     nh_special;	/**< Special event */

  unsigned        nh_ref_by_stack:1;	/**< Has stack used the handle? */
  unsigned        nh_ref_by_user:1;	/**< Has user used the handle? */
  unsigned        nh_init:1;

  unsigned        nh_has_invite:1;     /**< Has call */
  unsigned        nh_has_subscribe:1;  /**< Has watcher */
  unsigned        nh_has_notify:1;     /**< Has notifier */
  unsigned        nh_has_register:1;   /**< Has registration */
  unsigned        nh_has_streaming:1;  /**< Has RTSP-related session */

  struct nua_client_request nh_cr[1];

  nua_dialog_state_t nh_ds[1];
  nua_session_state_t nh_ss[1];

  auth_client_t  *nh_auth;	/**< Authorization objects */

  soa_session_t  *nh_soa;	/**< Media session */

  struct nua_referral {
    nua_handle_t  *ref_handle;	/**< Referring handle */
    sip_event_t   *ref_event;	/**< Event used with NOTIFY */
  } nh_referral[1];

  nea_server_t   *nh_notifier;	/**< SIP notifier */
};

#define NH_IS_VALID(nh) ((nh) && (nh)->nh_valid)

#define NH_STATUS(nh) \
  (nh)->nh_status, \
  (nh)->nh_phrase, \
  SIPTAG_WARNING_STR(nh->nh_warning)

#define NH_IS_DEFAULT(nh) ((nh) == (nh)->nh_nua->nua_handles)

static inline
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


extern char const nua_500_error[];

#define NUA_500_ERROR 500, nua_500_error

struct nua_s {
  su_home_t            nua_home[1];

  /* API (client) side */
  su_root_t    	      *nua_api_root;
  su_clone_r   	       nua_clone;
  su_task_r            nua_client;
  nua_callback_f       nua_callback;
  nua_magic_t         *nua_magic;

  nua_saved_event_t    nua_current[1];
  nua_saved_event_t    nua_signal[1];

  /* Engine state flags */
  unsigned             nua_shutdown_started:1; /**< Shutdown initiated */
  unsigned             nua_shutdown_final:1; /**< Shutdown is complete */
  unsigned :0;
  
  /**< Used by stop-and-wait args calls */
  tagi_t const        *nua_args;

  /**< Local SIP address. Contents are kept around for ever. */
  sip_from_t          nua_from[1];

  /* Protocol (server) side */

  nua_registration_t *nua_registrations; /**< Active registrations */

  sip_contact_t      *nua_contact;
  sip_contact_t      *nua_sips_contact;

  /* Constants */
  sip_accept_t       *nua_invite_accept; /* What we accept for invite */

  url_t        	     *nua_registrar;

  su_root_t          *nua_root;
  su_task_r           nua_server;
  nta_agent_t        *nua_nta;
  su_timer_t         *nua_timer;

#if HAVE_UICC_H
  uicc_t             *nua_uicc;
#endif

  void         	      *nua_sip_parser;

  sip_time_t           nua_shutdown;

  /* Route */
  sip_service_route_t *nua_service_route;

  /* User-agent parameters */
  unsigned             nua_media_enable:1;

  unsigned     	       :0;

#if HAVE_SMIME		/* Start NRC Boston */
  sm_object_t          *sm;
#endif                  /* End NRC Boston */

  nua_handle_t        *nua_handles;
  nua_handle_t       **nua_handles_tail;
};

#define nua_dhandle    nua_handles

#if HAVE_FUNC
#define enter (void)SU_DEBUG_9(("nua: %s: entering\n", __func__))
#define nh_enter (void)SU_DEBUG_9(("nua %s(%p): entering\n", __func__, nh))
#elif HAVE_FUNCTION
#define enter (void)SU_DEBUG_9(("nua: %s: entering\n", __FUNCTION__))
#define nh_enter (void)SU_DEBUG_9(("nua %s(%p): entering\n", __FUNCTION__, nh))
#define __func__ __FUNCTION__
#else
#define enter ((void)0)
#define nh_enter ((void)0)
#define __func__ "nua"
#endif

/* Internal prototypes */
int  nua_stack_init(su_root_t *root, nua_t *nua);
void nua_stack_deinit(su_root_t *root, nua_t *nua);
void nua_stack_signal(nua_t *nua, su_msg_r msg, event_t *e);

int nua_stack_registrations_init(nua_t *nua);

int register_usage_check_accept(sip_accept_t const *accept);

int register_usage_process_options(struct register_usage *usages,
				   nta_incoming_t *irq,
				   sip_t const *sip);

void nua_stack_post_signal(nua_handle_t *nh, nua_event_t event, 
			   tag_type_t tag, tag_value_t value, ...);

typedef int nua_stack_signal_handler(nua_t *, 
				     nua_handle_t *, 
				     nua_event_t, 
				     tagi_t const *);

nua_stack_signal_handler 
  nua_stack_set_params, nua_stack_get_params,
  nua_stack_register, 
  nua_stack_invite, nua_stack_ack, nua_stack_cancel, 
  nua_stack_bye, nua_stack_info, nua_stack_update, 
  nua_stack_options, nua_stack_publish, nua_stack_message, 
  nua_stack_subscribe, nua_stack_notify, nua_stack_refer,
  nua_stack_method;

#define UA_EVENT1(e, statusphrase) \
  nua_stack_event(nua, nh, NULL, e, statusphrase, TAG_END())

#define UA_EVENT2(e, status, phrase)			\
  nua_stack_event(nua, nh, NULL, e, status, phrase, TAG_END())

#define UA_EVENT3(e, status, phrase, tag)			\
  nua_stack_event(nua, nh, NULL, e, status, phrase, tag, TAG_END())

int nua_stack_event(nua_t *nua, nua_handle_t *nh, msg_t *msg,
		    nua_event_t event, int status, char const *phrase,
		    tag_type_t tag, tag_value_t value, ...);

nua_handle_t *nh_create_handle(nua_t *nua, nua_hmagic_t *hmagic,
			       tagi_t *tags);

nua_handle_t *nua_stack_incoming_handle(nua_t *nua, 
					nta_incoming_t *irq,
					sip_t const *sip,
					enum nh_kind kind,
					int create_dialog);

void nh_destroy(nua_t *nua, nua_handle_t *nh);

nua_handle_t *nh_validate(nua_t *nua, nua_handle_t *maybe);

int nua_stack_init_handle(nua_t *nua, nua_handle_t *nh, 
			  enum nh_kind kind,
			  char const *default_allow,
			  tag_type_t tag, tag_value_t value, ...);

int nua_stack_process_request(nua_handle_t *nh,
			      nta_leg_t *leg,
			      nta_incoming_t *irq,
			      sip_t const *sip);

int nua_stack_process_response(nua_handle_t *nh,
			       struct nua_client_request *cr,
			       nta_outgoing_t *orq,
			       sip_t const *sip,
			       tag_type_t tag, tag_value_t value, ...);

msg_t *nua_creq_msg(nua_t *nua, nua_handle_t *nh,
		    struct nua_client_request *cr,
		    int restart, 
		    sip_method_t method, char const *name,
		    tag_type_t tag, tag_value_t value, ...);

int nua_creq_check_restart(nua_handle_t *nh,
			   struct nua_client_request *cr,
			   nta_outgoing_t *orq,
			   sip_t const *sip,
			   nua_creq_restart_f *f);

int nua_creq_restart_with(nua_handle_t *nh,
			  struct nua_client_request *cr,
			  nta_outgoing_t *orq,
			  int status, char const *phrase,
			  nua_creq_restart_f *f, 
			  tag_type_t tag, tag_value_t value, ...);

int nua_creq_save_restart(nua_handle_t *nh,
			  struct nua_client_request *cr,
			  nta_outgoing_t *orq,
			  int status, char const *phrase,
			  nua_creq_restart_f *f);

int nua_creq_restart(nua_handle_t *nh,
		     struct nua_client_request *cr,
		     nta_response_f *cb,
		     tagi_t *tags);

void nua_creq_deinit(struct nua_client_request *cr, nta_outgoing_t *orq);

sip_contact_t const *nua_contact_by_aor(nua_t *nua, 
					url_t const *aor,
					int only_default);

msg_t *nh_make_response(nua_t *nua, nua_handle_t *nh, 
			nta_incoming_t *irq,
			int status, char const *phrase,
			tag_type_t tag, tag_value_t value, ...);


typedef int nua_stack_process_request_t(nua_t *nua,
					nua_handle_t *nh,
					nta_incoming_t *irq,
					sip_t const *sip);

nua_stack_process_request_t nua_stack_process_invite;
nua_stack_process_request_t nua_stack_process_info;
nua_stack_process_request_t nua_stack_process_update;
nua_stack_process_request_t nua_stack_process_bye;
nua_stack_process_request_t nua_stack_process_message;
nua_stack_process_request_t nua_stack_process_options;
nua_stack_process_request_t nua_stack_process_publish;
nua_stack_process_request_t nua_stack_process_subsribe;
nua_stack_process_request_t nua_stack_process_notify;
nua_stack_process_request_t nua_stack_process_refer;
nua_stack_process_request_t nua_stack_process_unknown;

#ifndef SDP_MIME_TYPE
#define SDP_MIME_TYPE nua_application_sdp
#endif

extern char const nua_application_sdp[];

/* ---------------------------------------------------------------------- */

#define SIP_METHOD_UNKNOWN sip_method_unknown, NULL

/* Private tags */
#define NUTAG_ADD_CONTACT(v) _nutag_add_contact, tag_bool_v(v)
extern tag_typedef_t _nutag_add_contact;

#define NUTAG_ADD_CONTACT_REF(v) _nutag_add_contact_ref, tag_bool_vr(&v)
extern tag_typedef_t _nutag_add_contact_ref;

#define NUTAG_COPY(v) _nutag_copy, tag_bool_v(v)
extern tag_typedef_t _nutag_copy;

#define NUTAG_COPY_REF(v) _nutag_copy_ref, tag_bool_vr(&v)
extern tag_typedef_t _nutag_copy_ref;

/* ---------------------------------------------------------------------- */

typedef unsigned longlong ull;

#define SET_STATUS(_status, _phrase) status = _status, phrase = _phrase

#define SET_STATUS2(_status, _phrase) status = _status, phrase = _phrase

/* This is an "interesting" macro:
 * x is a define expanding to <i>num, str</i>.
 * @a num is assigned to variable status, @a str to variable phrase.
 * Macro SET_STATUS1 expands to two comma-separated expressions that are
 * also usable as function arguments.
 */
#define SET_STATUS1(x) ((status = x), status), (phrase = ((void)x))

/* ---------------------------------------------------------------------- */
/* Application side prototypes */

void nua_signal(nua_t *nua, nua_handle_t *nh, msg_t *msg, int always,
		nua_event_t event, int status, char const *phrase,
		tag_type_t tag, tag_value_t value, ...);

void nua_event(nua_t *root_magic, su_msg_r sumsg, event_t *e);

SOFIA_END_DECLS

#endif /* NUA_STACK_H */
