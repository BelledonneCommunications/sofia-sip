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

/**@file nua.h  @brief  Nokia User Agent Library
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Feb 14 17:09:44 2001 ppessi
 */

#ifndef NUA_H
/** Defined when @b <nua.h> has been included. */
#define NUA_H

#ifndef SU_WAIT_H
#include <su_wait.h>
#endif

#ifndef URL_H
#include <url.h>
#endif

#ifndef SIP_H
#include <sip.h>
#endif

/** NUA agent. */
typedef struct nua_s nua_t;

/** NUA transaction handle. */
typedef struct nua_handle_s nua_handle_t;

#ifndef NUA_MAGIC_T 
#define NUA_MAGIC_T void
#endif
/** Application context for NUA agent. */
typedef NUA_MAGIC_T nua_magic_t;

#ifndef NUA_HMAGIC_T 
#define NUA_HMAGIC_T void
#endif
/** Application context for NUA handle. */
typedef NUA_HMAGIC_T nua_hmagic_t;

#ifndef NUA_TAG_H
#include <nua_tag.h>
#endif

/** Events */
typedef enum nua_event_e {
  /* Indications */
  nua_i_error,			/**< Error indication */

  nua_i_invite,			/**< Incoming call */
  nua_i_cancel,			/**< Incoming INVITE has been cancelled */
  nua_i_ack,			/**< Response to INVITE has been ACKed */
  nua_i_fork,			/**< Outgoing call has been forked */
  nua_i_active,			/**< A call has been activated */
  nua_i_terminated,		/**< A call has been terminated */
  nua_i_state,		        /**< Call state has changed */

  nua_i_bye,			/**< Incoming call hangup */
  nua_i_options,		/**< Incoming options */
  nua_i_refer,			/**< Incoming call transfer */
  nua_i_publish,		/**< Incoming PUBLISH */
  nua_i_prack,			/**< Incoming PRACK */
  nua_i_info,			/**< Incoming session INFO */
  nua_i_update,			/**< Incoming session UPDATE */
  nua_i_message,		/**< Incoming MESSAGE */
  nua_i_chat,			/**< Incoming chat MESSAGE  */
  nua_i_subscribe,		/**< Incoming subscription */
  nua_i_notify,			/**< Incoming event */
  nua_i_method,			/**< Incoming, unknown method */

  nua_i_media_error,		/**< Offer-answer error indication */

  /* Responses */
  nua_r_set_params,		/**< Answer to nua_set_params() */
  nua_r_get_params,		/**< Answer to nua_get_params() or 
				 * nua_get_hparams(). */
  nua_r_shutdown,		/**< Answer to nua_shutdown() */
  nua_r_notifier,		/**< Answer to nua_notifier() */
  nua_r_terminate,		/**< Answer to nua_terminate() */

  /* SIP responses */
  nua_r_register,		/**< Answer to outgoing REGISTER */
  nua_r_unregister,		/**< Answer to outgoing un-REGISTER */
  nua_r_invite,		        /**< Answer to outgoing INVITE */
  nua_r_cancel,			/**< Answer to outgoing CANCEL */
  nua_r_bye,			/**< Answer to outgoing BYE */
  nua_r_options,		/**< Answer to outgoing OPTIONS */
  nua_r_refer,			/**< Answer to outgoing REFER */
  nua_r_publish,		/**< Answer to outgoing PUBLISH */
  nua_r_unpublish,		/**< Answer to outgoing un-PUBLISH */
  nua_r_info,		        /**< Answer to outgoing INFO */
  nua_r_update,		        /**< Answer to outgoing UPDATE */
  nua_r_message,		/**< Answer to outgoing MESSAGE */
  nua_r_chat,			/**< Answer to outgoing chat MESSAGE */
  nua_r_subscribe,		/**< Answer to outgoing SUBSCRIBE */
  nua_r_unsubscribe,		/**< Answer to outgoing un-SUBSCRIBE */
  nua_r_notify,			/**< Answer to outgoing NOTIFY */
  nua_r_method,			/**< Answer to unknown outgoing method */

  /* Internal events */
  nua_r_authenticate,
  nua_r_redirect,
  nua_r_destroy,
  nua_r_respond,
  nua_r_nit_respond,
  nua_r_ack,			/*#< Answer to ACK */


  /************************************
   * Obsolete events (to-be-removed): *
   ************************************/
  nua_i_media_event,		/**< Incoming media event */
  nua_r_set_media_param,	/**< Answer to nua_set_media_param() */
  nua_r_get_media_param,	/**< Answer to nua_get_media_param() */
  nua_r_media_setup,		/**< Answer to nua_media_setup() */
  nua_r_media_describe,		/**< Answer to nua_media_describe() */
  nua_r_media_event,		/**< Answer to nua_media_event() */
  /* RTSP methods (obsolete) */
  nua_i_announce,               /*#< Incoming RTSP record announce */
  nua_i_describe,               /*#< Incoming RTSP presentation description */
  nua_i_get_parameter,          /*#< Incoming RTSP server parameter fetch */
  nua_i_pause,                  /*#< Incoming RTSP pause  */
  nua_i_options2,               /*#< Incoming RTSP options */
  nua_i_play,                   /*#< Incoming RTSP play */
  nua_i_record,                 /*#< Incoming RTSP record  */
  nua_i_set_parameter,          /*#< Incoming RTSP server parameter setting  */
  nua_i_setup,                  /*#< Incoming RTSP setup */
  nua_i_teardown,               /*#< Incoming RTSP teardown the session */
  /* RTSP responses (obsolete) */
  nua_r_setup,                  /*#< Answer to outgoing SETUP */
  nua_r_play,                   /*#< Answer to outgoing PLAY */
  nua_r_record,                 /*#< Answer to outgoing RECORD */
  nua_r_pause,                  /*#< Answer to outgoing PAUSE */
  nua_r_describe,               /*#< Answer to outgoing DESCRIBE */
  nua_r_teardown,               /*#< Answer to outgoing TEARDOWN */
  nua_r_options2,               /*#< Answer to outgoing OPTIONS */
  nua_r_announce,               /*#< Answer to outgoing ANNOUNCE */
  nua_r_get_parameter,          /*#< Answer to outgoing GET_PARAMETER */
  nua_r_set_parameter           /*#< Answer to outgoing SET_PARAMETER */

} nua_event_t;

typedef struct event_s {
  nua_handle_t *e_nh;
  int           e_event;
  short         e_always;
  short         e_status;
  char const   *e_phrase;
  msg_t        *e_msg;
  tagi_t        e_tags[1];
} nua_event_data_t;

/** NUA API version */
#define NUA_VERSION "2.0"
/** NUA module version */
extern char const nua_version[];

typedef void (*nua_callback_f)(nua_event_t event,
			       int status, char const *phrase,
			       nua_t *nua, nua_magic_t *magic,
			       nua_handle_t *nh, nua_hmagic_t *hmagic,
			       sip_t const *sip,
			       tagi_t tags[]);

/** Create a NUA agent. */
nua_t *nua_create(su_root_t *root,
		  nua_callback_f callback,
		  nua_magic_t *magic,
		  tag_type_t tag, tag_value_t value,
		  ...);

/** Shutdown NUA stack. */
void nua_shutdown(nua_t *nua);

/** Destroy the NUA stack. */
void nua_destroy(nua_t *nua);

/** Set NUA parameters. */
void nua_set_params(nua_t *nua, tag_type_t tag, tag_value_t value, ...);

/** Get NUA parameters. */
void nua_get_params(nua_t *nua, tag_type_t tag, tag_value_t value, ...);

/** Obtain default operation handle of the NUA stack object. */
nua_handle_t *nua_default(nua_t *nua);

/** Create an operation handle */
nua_handle_t *nua_handle(nua_t *nua, nua_hmagic_t *hmagic,
			 tag_type_t tag, tag_value_t value, ...);

/** Destroy a handle */
void nua_handle_destroy(nua_handle_t *h);

/** Bind a callback context to an operation handle. */
void nua_handle_bind(nua_handle_t *nh, nua_hmagic_t *magic);

/** Set handle parameters. */
void nua_set_hparams(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Get handle parameters. */
void nua_get_hparams(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Check if operation handle is used for INVITE */
int nua_handle_has_invite(nua_handle_t const *nh);

/** Check if operation handle has been used with outgoing SUBSCRIBE of REFER request. */
int nua_handle_has_subscribe(nua_handle_t const *nh);

/** Check if operation handle has been used with nua_register() or nua_unregister(). */
int nua_handle_has_register(nua_handle_t const *nh);

/** Check if operation handle has an active call */
int nua_handle_has_active_call(nua_handle_t const *nh);

/** Check if operation handle has a call on hold */
int nua_handle_has_call_on_hold(nua_handle_t const *nh);

/** Check if handle has active event subscriptions (refers sent). */
int nua_handle_has_events(nua_handle_t const *nh);

/** Check if operation handle has active registrations */
int nua_handle_has_registrations(nua_handle_t const *nh);

/** Get the remote address (From/To header) of operation handle */
sip_to_t const *nua_handle_remote(nua_handle_t const *nh);

/** Get the local address (From/To header) of operation handle  */
sip_to_t const *nua_handle_local(nua_handle_t const *nh);

/** Get name for NUA event. */
char const *nua_event_name(nua_event_t event);

/** Send SIP REGISTER request to the registrar. */ 
void nua_register(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Unregister. */ 
void nua_unregister(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Place a call using SIP INVITE method. */
void nua_invite(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Acknowledge a succesfull response to INVITE request. */ 
void nua_ack(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Query capabilities from server */
void nua_options(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Send PUBLISH request to publication server. */
void nua_publish(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Send an instant message. */
void nua_message(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Send a chat message. */
void nua_chat(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Send an INFO request. */
void nua_info(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Subscribe a SIP event. */
void nua_subscribe(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/** Unsubscribe an event. */
void nua_unsubscribe(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Send a NOTIFY message. */
void nua_notify(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Create an event server. */
void nua_notifier(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Terminate an event server. */
void nua_terminate(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Transfer a call. */
void nua_refer(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Update a call */ 
void nua_update(nua_handle_t *, tag_type_t tag, tag_value_t value, ...);

/** Hangdown a call. */
void nua_bye(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Cancel an INVITE operation */
void nua_cancel(nua_handle_t *, tag_type_t, tag_value_t, ...);
 
/** Authenticate an operation. */
void nua_authenticate(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Redirect an operation. */
void nua_redirect(nua_handle_t *, tag_type_t, tag_value_t, ...);

/** Respond with given status. */
void nua_respond(nua_handle_t *nh, 
		 int status, char const *phrase,
		 tag_type_t tag, tag_value_t value, 
		 ...);

#define nua_handle_home(nh) ((su_home_t *)(nh))

#ifndef NUA_SAVED_EVENT_T
#define NUA_SAVED_EVENT_T struct nua_saved_event *
#endif
typedef NUA_SAVED_EVENT_T nua_saved_event_t;

/** Save last nua event */
int nua_save_event(nua_t *nua, nua_saved_event_t return_saved[1]);

/** Get information from saved event */
nua_event_data_t const *nua_event_data(nua_saved_event_t const saved[1]);

/** Destroy a save nua event */
void nua_destroy_event(nua_saved_event_t *saved);

/***************************************
 * Obsolete functions (to-be-removed): *
 ***************************************/

/** XXX/obsolete: Check for RTSP support. */ 
int nua_handle_has_streaming(nua_handle_t const *nh);

/** XXX/obsolete: Set media parameter. */ 
void nua_set_media_param(nua_handle_t *nh, tag_type_t, tag_value_t, ...);

/** XXX/obsolete: Get a media parameter. */ 
void nua_get_media_param(nua_handle_t *nh, tag_type_t, tag_value_t, ...);

/** XXX/obsolete: Setup a local media session. */
void nua_media_setup(nua_handle_t *nh, tag_type_t, tag_value_t, ...);

/** XXX/obsolete: Describe a media session using SDP. */
void nua_media_describe(nua_handle_t *nh, tag_type_t, tag_value_t, ...);

/** XXX/obsolete: Send an event to media subsystem. */
void nua_media_event(nua_handle_t *nh, tag_type_t, tag_value_t, ...);

/*# XXX/obsolete: Play. */ 
void nua_play(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Setup. */ 
void nua_setup(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Options2. */ 
void nua_options2(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Describe. */ 
void nua_describe(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Announce. */ 
void nua_announce(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Get RTSP parameter. */ 
void nua_get_parameter(nua_handle_t *nh, tag_type_t tag,
		       tag_value_t value, ...);

/*# XXX/obsolete: Set RTSP parameter. */ 
void nua_set_parameter(nua_handle_t *nh, tag_type_t tag,
		       tag_value_t value, ...);

/*# XXX/obsolete: Record. */ 
void nua_record(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Pause. */ 
void nua_pause(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

/*# XXX/obsolete: Teardown. */ 
void nua_teardown(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);

#endif
