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

/**@file nua_stack.h 
 * @brief  Nokia User Agent Library - internal stack interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 *
 * @date Created: Wed Feb 14 17:09:44 2001 ppessi
 * $Date: 2005/09/19 11:12:10 $
 */

#ifndef NUA_STACK_H
/** Defined when <nua_stack.h> has been included. */
#define NUA_STACK_H "$Id: nua_stack.h,v 1.3 2005/09/19 11:12:10 kaiv Exp $"

/* SOXXX: pthread doesn't seem to work...? */
#undef HAVE_PTHREAD_H

#if HAVE_UICC_H
#include <uicc.h>
#endif

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

#if HAVE_SIGCOMP
#include <sigcomp.h>
#endif

#include "soa.h"

typedef struct event_s event_t;

struct event_s {
  nua_handle_t *e_nh;
  int           e_event;
  short         e_always;
  short         e_status;
  char const   *e_phrase;
  msg_t        *e_msg;
  tagi_t        e_tags[1];
};

#define       NONE ((void *)-1)

enum nh_kind {
  nh_has_nothing,
  nh_has_invite,
  nh_has_subscribe,
  nh_has_notify,
  nh_has_register,
  nh_has_streaming
};

enum nh_session {
  init_session,			/**< Initial state */
  calling_session,		/**< INVITE sent */
  proceeding_session,		/**< 18X received */
  received_session,		/**< INVITE received */
  early_session,		/**< 18X sent (w/SDP) */
  ready_session,		/**< 2XX received or sent */
  terminating_session,		/**< BYE sent */
  terminated_session		/**< BYE complete */
};

typedef struct nua_chat_s nua_chat_t;
typedef struct nua_remote_s nua_remote_t;

typedef struct nua_dialog_state nua_dialog_state_t;
typedef union  nua_dialog_usage nua_dialog_usage_t;
typedef struct nua_client_request nua_client_request_t; 
typedef struct nua_server_request nua_server_request_t; 

typedef void nh_pending_f(nua_handle_t *nh, 
			  nua_dialog_usage_t *du,
			  sip_time_t now);

enum nua_dialog_usage_e
{
  nua_transaction_usage = 0,
  nua_session_usage,
  nua_notifier_usage,
  nua_subscriber_usage,
  nua_register_usage,
  nua_publish_usage
};

struct nua_common_usage {
  nua_dialog_usage_t *cu_next;
  unsigned     cu_kind:3;
  unsigned     cu_terminating:1;	/**< Trying to terminate */
  unsigned     cu_ready:1;	/**< Established usage */
  unsigned:0;
  /** Pending operation.
   *
   * The nh_pending() is called 
   * a) when current time sip_now() will soon exceed nh_refresh (now > 1)
   * b) when handle operation is restarted (now is 1)
   * c) when handle is destroyed (now is 0)
   */
  nh_pending_f   *cu_pending;
  sip_time_t      cu_refresh;	/**< When execute cu_pending */
};

struct nua_session_usage {
  struct nua_common_usage su_common[1];
};

struct nua_event_usage {
  struct nua_common_usage de_common[1];
  msg_t *de_msg;
  sip_event_t const *de_event;		/**< Event of usage */
  unsigned           de_substate:2;	/**< Subscription state */
  unsigned:0;
};

struct nua_register_usage {
  struct nua_common_usage ru_common[1];
  struct sigcomp_compartment *ru_compartment;
  msg_t *ru_msg;
};

struct nua_publish_usage {
  struct nua_common_usage pu_common[1];
  sip_etag_t *pu_etag;	/**< ETag */
  msg_t *pu_msg;
};


union nua_dialog_usage
{
  nua_dialog_usage_t *du_next;
  struct nua_common_usage du_common[1];
#define du_kind du_common->cu_kind
#define du_terminating du_common->cu_terminating
#define du_ready du_common->cu_ready
#define du_pending du_common->cu_pending
#define du_refresh du_common->cu_refresh

  struct nua_session_usage du_session[1];
#define du_event du_subscriber->de_event
  struct nua_event_usage du_subscriber[1];
  struct nua_event_usage du_notifier[1];
  struct nua_register_usage du_register[1];
  struct nua_publish_usage du_publisher[1];
};


struct nua_dialog_state
{
  /** Dialog usages. */
 nua_dialog_usage_t     *ds_usage;

  /* Dialog and subscription state */
  unsigned ds_route:1;		/**< We have route */
  unsigned ds_terminated:1;	/**< Being terminated */

  unsigned ds_has_session:1;	/**< We have session */
  unsigned ds_has_register:1;	/**< We have registration */
  unsigned ds_has_publish:1;	/**< We have publish */
  unsigned ds_has_events:1;	/**< We have some events */
  unsigned ds_has_subscription:1; /**< We have subscriptions */
  unsigned ds_has_notifier:1;	/**< We have notifiers */
  unsigned :0;

  sip_from_t const *ds_local;		/**< Local address */
  sip_to_t const *ds_remote;		/**< Remote address */
  nta_leg_t      *ds_leg;
  char const     *ds_remote_tag;	/**< Remote tag (if any). 
					 * Should be non-NULL 
					 * if dialog is established.
					 */

  struct nua_remote_s {
    sip_allow_t      *nr_allow;
    sip_accept_t     *nr_accept;
    sip_require_t    *nr_require;
    sip_supported_t  *nr_supported;
    sip_user_agent_t *nr_user_agent;
  } ds_remote_ua[1];
};

typedef void crequest_restart_f(nua_handle_t *, tagi_t *tags);

struct nua_client_request
{
  nua_event_t         cr_event;		/**< Request event */
  crequest_restart_f *cr_restart;
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
  
  /* enum nh_session */
  unsigned        ss_state:4;		/**< Session status (enum nh_session) */
  
  unsigned        ss_alerting:1;	/**< 180 is sent/received */
  
#if 0
  unsigned        ss_complete:1;	/**< Completed SDP offer-answer */

  unsigned        ss_offer_sent:1;	/**< We have offered SDP */
  unsigned        ss_answer_recv:1;	/**< We have received SDP answer */

  unsigned        ss_offer_recv:1;	/**< We have received an offer */
  unsigned        ss_answer_sent:2;	/**< We have answered (reliably, if >1) */
#endif
  unsigned        ss_ack_needed:2;	/**< Send an ACK (do O/A, if >1) */
  unsigned        ss_update_needed:2;	/**< Send an UPDATE (do O/A if > 1) */

  unsigned        ss_precondition:1;	/**< Precondition required */

  unsigned        ss_hold_remote:1;	/**< We are holding remote */
  
  unsigned        : 0;
  
  unsigned        ss_session_timer;	/**< Value of Session-Expires (delta) */
  unsigned        ss_min_se;		/**< Minimum session expires */
  enum nua_session_refresher ss_refresher; /**< none, local or remote */

#if 0
  unsigned        ss_oa_rounds;		/**< Number of O/A rounds completed */
  sdp_origin_t   *ss_o_remote;
  sdp_origin_t   *ss_o_local;
#endif

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

    unsigned sr_offer_recv:1;	/**< We have received an offer */
    unsigned sr_answer_sent:2;	/**< We have answered (reliably, if >1) */

    unsigned sr_offer_sent:1;	/**< We have offered SDP */
    unsigned sr_answer_recv:1;	/**< We have received SDP answer */
  } ss_srequest[1];
} nua_session_state_t;


typedef struct srtp_object_s
{
  int srtp_enable,
      srtp_confidentiality,
      srtp_integrity_protection;

} srtp_object_t;

#if !HAVE_MSS
typedef void ms_t;
typedef void mss_t;

/* XXX: Media subsystem parameters */

/* --cut-- for media subsystem parameters */
#define MS_SETUP_CLONE  "clone"
/** Sets the RTCP email parameter */ 
#define MS_SETUP_EMAIL  "email"
/** Provides the local SIP URI */
#define MS_LOCAL_URI  "local-uri"
/** Provides the remote SIP URI */
#define MS_REMOTE_URI  "remote-uri"
/** Provides the local SIP contact. */
#define MS_LOCAL_CONTACT  "local-contact"
/** Provides the remote SIP contact URI. */
#define MS_REMOTE_CONTACT  "remote-contact"
/** Sets the connection type */
#define MS_CONN_LIST       "connection-list"
#define MS_CONN_IN         "connection"
#define MS_CONN_IN_IP4     "connection=ip4"
#define MS_CONN_IN_IP6     "connection=ip6"
#define MS_CONN_IN_IP4_IP6 "connection=ip4+ip6"
#define MS_CONN_IN_IP6_IP4 "connection=ip6+ip4"
/** Hold mode */
#define MS_HOLD_NONE    "sendrecv"
#define MS_HOLD_REMOTE  "sendonly"
#define MS_HOLD_LOCAL   "recvonly"
#define MS_HOLD_BOTH    "inactive"
/* Offer-answer stage */
#define MS_OFFER        "offer"
#define MS_ANSWER       "answer"
/* Audio device */
#define MS_AUDIO_DEVICE   "audio-device"
/** Specifies window for local video. */
#define MS_VIDEO_LOCAL_WINDOW  "video-lw"
/** Specifies window for remote video. */
#define MS_VIDEO_REMOTE_WINDOW "video-rw"
/** Video device. */
#define MS_VIDEO_DEVICE   "video-device"
/* Specify window for local image */
#define MS_IMAGE_LOCAL_WINDOW "image-lw_image"
/** Whether to enable SRTP in RTP sessions. */
#define MS_SRTP_ENABLE "srtp-enable"
#define MS_SRTP_CONFIDENTIALITY "srtp-confidentiality"
#define MS_SRTP_INTEGRITY_PROTECTION "srtp-integrity-protection"
/* --cut-- for media subsystem parameters */
#endif

#if 0
/** Media-related state */
typedef struct nua_media_state
{
  /** Media subsystem.
   *
   * Local media is enabled if nm_mss is non-null
   */

#if HAVE_MSS
  mss_t          *nm_mss;	
  ms_t           *nm_session;	/**< Media session */
#else
  void           *nm_mss;
  void           *nm_session;
#endif

  struct nua_media_a
  {
    int ma_audio:3; /**< Audio activity (send/recv) */
    int ma_video:3; /**< Video activity (send/recv) */
    int ma_image:3; /**< Image activity (send/recv) for JPIP */
    int ma_chat:3;  /**< Chat activity (send/recv) */
  } nm_active[1];

  /* These two flags help us to avoid unnecessary setups */
  unsigned   nm_modified:1;    /**< Important media parameter(s) changed */
  unsigned   nm_setup_with_remote:1; /** Last setup was with remote */

  unsigned   nm_hold_remote:1; /**< We are holding remote */
  unsigned   nm_muted:1;	/**< We are muted */
  unsigned   nm_clone:1;
#if HAVE_SRTP
  unsigned   nm_srtp_enable:1;
  unsigned   nm_srtp_confidentiality:1;
  unsigned   nm_srtp_integrity_protection:1;
#endif /* HAVE_SRTP */
  unsigned:0;

  nua_chat_t     *nm_chat;	/**< Chat session */

  sdp_parser_t   *nm_sdp;  	/**< SDP from incoming request */

  int             nm_status;	/**< Status from last media operation */
  char const     *nm_phrase;	/**< Phrase from last media operation */
  char const     *nm_warning;	/**< Warnings from last media operation */

  /* Media parameters */
  char const     *nm_path;

  char const     *nm_address;
  enum nua_af     nm_af;

  char const     *nm_video_lw;
  char const     *nm_video_rw;

  char const     *nm_image_lw;
  char const     *nm_image_name; /**< JPIP target-id */
#define nm_target_image_name nm_image_name

  su_strlst_t    *nm_event_list;
} nua_media_state_t;

#define NMEDIA_ACTIVE_TAGS(nm) \
  NH_ACTIVE_MEDIA_TAGS((nm)->nm_mss != NULL, (nm)->nm_active)

#define \
  NH_ACTIVE_MEDIA_TAGS(include, ma) \
  TAG_IF((include) && (ma)->ma_audio >= 0, NUTAG_ACTIVE_AUDIO(ma->ma_audio)), \
  TAG_IF((include) && (ma)->ma_video >= 0, NUTAG_ACTIVE_VIDEO(ma->ma_video)), \
  TAG_IF((include) && (ma)->ma_image >= 0, NUTAG_ACTIVE_IMAGE(ma->ma_image)), \
  TAG_IF((include) && (ma)->ma_chat >= 0, NUTAG_ACTIVE_CHAT(ma->ma_chat))

#endif

#define \
  NH_ACTIVE_MEDIA_TAGS(include, soa)					\
  TAG_IF((include) && (soa) && soa_is_audio_active(soa) >= 0,		\
	 NUTAG_ACTIVE_AUDIO(soa_is_audio_active(soa))),			\
  TAG_IF((include) && (soa) && soa_is_video_active(soa) >= 0,		\
	 NUTAG_ACTIVE_VIDEO(soa_is_video_active(soa))),			\
  TAG_IF((include) && (soa) && soa_is_image_active(soa) >= 0,		\
	 NUTAG_ACTIVE_IMAGE(soa_is_image_active(soa))),			\
  TAG_IF((include) && (soa) && soa_is_chat_active(soa) >= 0,		\
	 NUTAG_ACTIVE_CHAT(soa_is_chat_active(soa)))

#define \
  NH_REMOTE_MEDIA_TAGS(include, soa)					\
  TAG_IF((include) && (soa) && soa_is_remote_audio_active(soa) >= 0,	\
	 NUTAG_ACTIVE_AUDIO(soa_is_remote_audio_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_remote_video_active(soa) >= 0,	\
	 NUTAG_ACTIVE_VIDEO(soa_is_remote_video_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_remote_image_active(soa) >= 0,	\
	 NUTAG_ACTIVE_IMAGE(soa_is_remote_image_active(soa))),		\
  TAG_IF((include) && (soa) && soa_is_remote_chat_active(soa) >= 0,	\
	 NUTAG_ACTIVE_CHAT(soa_is_remote_chat_active(soa)))

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
  pthread_rwlock_t nh_refcount[1];  
#else
  unsigned        nh_refcount;
#endif

  /* Handle state */
  unsigned        nh_ref_by_stack:1;	/**< Has stack used the handle? */
  unsigned        nh_ref_by_user:1;	/**< Has user used the handle? */
  unsigned        nh_init:1;

  unsigned        nh_has_invite:1;     /**< Has call */
  unsigned        nh_has_subscribe:1;  /**< Has watcher */
  unsigned        nh_has_notify:1;     /**< Has notifier */
  unsigned        nh_has_register:1;   /**< Has registration */
  unsigned        nh_has_streaming:1;  /**< Has RTSP-related session */

  /* Preferences */
  unsigned        nh_auto_ack:1; /**< Automatically ACK a final response */
  unsigned        nh_early_media:1;/**< Establish early media session */
  unsigned        nh_update_refresh:1; /**< Use UPDATE to refresh */
  unsigned        nh_media_features:1;/**< Add media features */
  unsigned        nh_callee_caps:1; /**< Add callee caps */

  unsigned:0;

  sip_allow_t    *nh_allow;
  sip_supported_t *nh_supported;

  nua_event_t     nh_special;	/**< Special event */

  struct nua_client_request nh_cr[1];

  nua_dialog_state_t nh_ds[1];
  nua_session_state_t nh_ss[1];

  auth_client_t  *nh_auth;	/**< Authorization objects */

  soa_session_t  *nh_soa;	/**< Media session */
#if 0
  nua_media_state_t nh_nm[1];

  url_t const   *nh_uri;
  sip_content_type_t
                 *nh_content_type; /**< Original Content-Type */
  sip_content_disposition_t
                 *nh_disposition; /**< Original Content-Disposition */
  sip_payload_t  *nh_payload;	/**< Original request payload */
#endif

  struct nua_referral {
    nua_handle_t  *ref_handle;	 /**< Referring handle */
    sip_event_t   *ref_event;	/**< Event used with NOTIFY */
  } nh_referral[1];

  nea_server_t   *nh_notifier;	/**< SIP notifier */
};

#define NH_IS_VALID(nh) ((nh) && (nh)->nh_valid)

#define NH_STATUS(nh) \
  (nh)->nh_status, \
  (nh)->nh_phrase, \
  SIPTAG_WARNING_STR(nh->nh_warning)

extern char const nua_500_error[];

#define NUA_500_ERROR 500, nua_500_error

#define SET_STATUS(_status, _phrase) status = _status, phrase = _phrase

#if HAVE_HERBIE
#include "nua_herbie.h"
#endif

struct nua_s {
  su_home_t            nua_home[1];

  /* API (client) side */
  su_root_t    	      *nua_api_root;
  su_clone_r   	       nua_clone;
  su_task_r            nua_client;
  nua_callback_f       nua_callback;
  nua_magic_t         *nua_magic;

  /**< Used by stop-and-wait args calls */
  tagi_t const        *nua_args;
  tagi_t              *nua_filter;

  /**< Local SIP address. This is never modified. */ 
  sip_from_t const   *nua_from;

  /* Protocol (server) side */
  sip_contact_t      *nua_contact;
  sip_contact_t      *nua_sips_contact;
  sip_content_type_t *nua_sdp_content;
  sip_accept_t       *nua_invite_accept; /* What we accept for invite */
  sip_supported_t    *nua_supported;
  char const         *nua_ua_name;
  sip_user_agent_t   *nua_user_agent;
  char const         *nua_organization;
  url_t        	     *nua_registrar;

  su_root_t          *nua_root;
  su_task_r           nua_server;
  nta_agent_t        *nua_nta;
  su_timer_t         *nua_timer;

#if HAVE_HERBIE
  nua_herbie_t       *nua_herbie;
#endif

#if 0
#if HAVE_MSS
  mss_t              *nua_mss;	/**< Media manager */
#else
  void               *nua_mss;
#endif
  char const         *nua_media_cname;
  char const         *nua_media_descs;
  char const         *nua_media_params;
  nua_handle_t       *nua_media_handle;
  su_strlst_t        *nua_media_events;
#endif

#if HAVE_UICC_H
  uicc_t             *nua_uicc;
#endif

  /**< Default time to wait until call is completed (in seconds) */
  unsigned             nua_invite_timer;
  /** Default session timer (in seconds, 0 disables) */
# define               nua_session_timer nua_default->nh_ss->ss_session_timer
  /** Default Min-SE Delta value */
# define               nua_min_se        nua_default->nh_ss->ss_min_se

  int                  nua_retry_count;	/**< times to retry a request */

  int                  nua_max_subscriptions;

  void         	      *nua_sip_parser;

  sip_time_t           nua_shutdown;

  /* Route */
  sip_service_route_t *nua_service_route;

  /* Parameters */
  unsigned             nua_media_enable:1;
  unsigned     	       nua_autoAlert : 1;
  unsigned     	       nua_autoAnswer : 1;
  unsigned     	       nua_enableInvite : 1;
  unsigned     	       nua_enableMessage : 1;
  /** Be bug-compatible with Windows Messenger */
  unsigned     	       nua_enableMessenger : 1;
  /** PIM-IW hack */
  unsigned             nua_messageRespond : 1;

  unsigned             nua_service_route_enable:1;
  unsigned             nua_path_enable:1;

  unsigned     	       :0;

#if HAVE_SMIME		/* Start NRC Boston */
  sm_object_t          *sm;
#endif                  /* End NRC Boston */
#if HAVE_SRTP
  srtp_object_t        srtp[1];   
#endif

  nua_handle_t        *nua_handles;
  nua_handle_t       **nua_handles_tail;
};

#define nua_default    nua_handles
#define nua_allow      nua_handles->nh_allow

#define nua_media_path     nua_handles->nh_nm->nm_path
#define nua_media_af       nua_handles->nh_nm->nm_af
#define nua_media_address  nua_handles->nh_nm->nm_address

#define nua_refresher  nua_handles->nh_ss->ss_refresher

#if HAVE_FUNC
#define enter (void)SU_DEBUG_9(("nua: %s: entering\n", __func__))
#define nh_enter (void)SU_DEBUG_9(("nua %s(%p): entering\n", __func__, nh))
#elif HAVE_FUNCTION
#define enter (void)SU_DEBUG_9(("nua: %s: entering\n", __FUNCTION__))
#define nh_enter (void)SU_DEBUG_9(("nua %s(%p): entering\n", __FUNCTION__, nh))
#else
#define enter ((void)0)
#define nh_enter ((void)0)
#endif

/*# Increase reference count by one.
 *
 * Reference conting works pretty simple. Currently, application can have a
 * single reference to a handle, stack can keep multiple references. When
 * application creates a handle, it gets a reference to it. When such a
 * handle is sent to stack, stack checks the nh_ref_by_stack and makes sure
 * that it has a reference. Likewise, when stack creates a handle, and it is
 * sent to application, the application side of nua checks nh_ref_by_appl
 * and increases the reference count if needed.
 *
 * When application calls nua_handle_destroy(), it marks the handle as
 * invalid, sends a nua_r_destroy signal to stack and decreases its
 * reference count.
 * 
 */
static inline
nua_handle_t *nh_incref(nua_handle_t *nh)
{
  nh_enter;

  if (nh) {
#if HAVE_PTHREAD_H
    pthread_rwlock_rdlock(nh->nh_refcount);
#else 
    nh->nh_refcount++;		/* XXX */
#endif
  }
  return nh;
}

/*# Decrease reference count by one, return false if no more references  */
static inline
int nh_decref(nua_handle_t *nh)
{
  nh_enter;

  if (nh == NULL) 
    return 1;

#if HAVE_PTHREAD_H
  pthread_rwlock_unlock(nh->nh_refcount);
  if (pthread_rwlock_trywrlock(nh->nh_refcount) == 0) {
    SU_DEBUG_9(("nua(%p): zapped\n", nh));
    su_home_zap(nh->nh_home);
    return 0;
  }
  return 1;
#else 
  if (--nh->nh_refcount == 0) {
    SU_DEBUG_9(("nua(%p): zapped\n", nh));
    su_home_zap(nh->nh_home);
  }
  return 1;
#endif  
}


/* Internal prototypes */
int  ua_init(su_root_t *root, nua_t *nua);
void ua_deinit(su_root_t *root, nua_t *nua);
void ua_signal(nua_t *nua, su_msg_r msg, event_t *e);
int ua_event(nua_t *nua, nua_handle_t *nh, msg_t *msg,
	     nua_event_t event, int status, char const *phrase,
	     tag_type_t tag, tag_value_t value, ...);

nua_handle_t *nh_create_handle(nua_t *nua, nua_hmagic_t *hmagic,
			       tagi_t *tags);

#if 0
sdp_session_t const *nmedia_parse_sdp(nua_handle_t *nh,
				    msg_payload_t const *pl,
				    msg_content_type_t const *ct,
				    struct nua_media_a *ma);
void nmedia_clear_sdp(nua_handle_t *nh);
#endif

/* Private prototypes (XXX: move to nua_priv.h; nua.c interface) */
void nua_signal(nua_t *nua, nua_handle_t *nh, msg_t *msg, int always,
		nua_event_t event, int status, char const *phrase,
		tag_type_t tag, tag_value_t value, ...);

/*  (XXX: move to nua_priv.h; nua.c interface) */
void nua_event(nua_t *root_magic, su_msg_r sumsg, event_t *e);

#define SIP_METHOD_UNKNOWN sip_method_unknown, NULL

#define UA_INTERVAL 5

#endif /* NUA_STACK_H */
