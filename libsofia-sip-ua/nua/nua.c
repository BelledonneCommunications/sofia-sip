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

/**@CFILE nua.c Sofia-SIP User Agent Library API Implementation.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 * @author Pasi Rinne-Rahkola
 *
 * @date Created: Wed Feb 14 18:32:58 2001 ppessi
 *
 */

#include "config.h"

#include <sofia-sip/su_tag.h>
#include <sofia-sip/su_tag_class.h>
#include <sofia-sip/su_tagarg.h>

#include <sofia-sip/su_tag_io.h>

#define SU_LOG (nua_log)
#include <sofia-sip/su_debug.h>

#define SU_ROOT_MAGIC_T   struct nua_s
#define SU_MSG_ARG_T      struct event_s
#define NUA_SAVED_EVENT_T su_msg_t *

#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/nta.h>

#include "sofia-sip/nua.h"
#include "sofia-sip/nua_tag.h"
#include "nua_stack.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* From AM_INIT/AC_INIT in our "config.h" */
char const nua_version[] = VERSION;

/**@var NUA_DEBUG
 *
 * Environment variable determining the debug log level for @b nua module.
 *
 * The NUA_DEBUG environment variable is used to determine the debug logging
 * level for @b nua module. The default level is 3.
 * 
 * @sa <su_debug.h>, nua_log, SOFIA_DEBUG
 */
extern char const NUA_DEBUG[];

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif

/**Debug log for @b nua module. 
 * 
 * The nua_log is the log object used by @b nua module. The level of
 * #nua_log is set using #NUA_DEBUG environment variable.
 */
su_log_t nua_log[] = { SU_LOG_INIT("nua", "NUA_DEBUG", SU_DEBUG) };

/**Create a NUA agent.
 *
 * This function creates a Sofia-SIP User Agent stack object (nua) and
 * initializes its parameters by given tagged values.
 *
 * @param root            Pointer to a root object
 * @param callback        Pointer to event callback function
 * @param magic           Pointer to callback context
 * @param tag, value, ... List of tagged parameters
 *
 * @retval !=NULL a pointer to a NUA stack object \n
 * @retval NULL upon an error
 *
 * @par Related tags:
 *     NUTAG_MEDIA_ENABLE()     \n
 *     NUTAG_SOA_NAME()         \n
 *     NUTAG_PROXY()            \n
 *     NUTAG_URL()              \n
 *     NUTAG_SIPS_URL()         \n
 *     NUTAG_SIP_PARSER()       \n
 *     NUTAG_UICC()             \n
 *     NUTAG_CERTIFICATE_DIR()  \n
 *     all relevant NTATAG_* are passed to NTA 
 *
 * @note
 * Both the NUTAG_URL and NUTAG_SIPS_URL() are used to pass arguments to
 * nta_agent_add_tport(). 
 *
 * @par Events:
 *     none
 */
nua_t *nua_create(su_root_t *root,
		  nua_callback_f callback,
		  nua_magic_t *magic,
		  tag_type_t tag, tag_value_t value, ...)
{
  nua_t *nua = NULL;

  enter;

  if (callback == NULL)
    return (void)(errno = EFAULT), NULL;

  if (root == NULL)
    return (void)(errno = EFAULT), NULL;

  if ((nua = su_home_new(sizeof(*nua)))) {
    ta_list ta;

    su_home_threadsafe(nua->nua_home);
    nua->nua_api_root = root;

    ta_start(ta, tag, value);

    nua->nua_args = ta_args(ta);

    su_task_copy(nua->nua_client, su_root_task(root));

    /* XXX: where to put this in the nua_server case? */
#if HAVE_SMIME		/* Start NRC Boston */
      nua->sm = sm_create();
#endif                  /* End NRC Boston */

#ifndef NUA_SERVER
    if (su_clone_start(root,
		       nua->nua_clone,
		       nua,
		       nua_stack_init,
		       nua_stack_deinit) == SU_SUCCESS) {
      su_task_copy(nua->nua_server, su_clone_task(nua->nua_clone));
      nua->nua_callback = callback;
      nua->nua_magic = magic;
    }
    else {
      su_home_unref(nua->nua_home);
      nua = NULL;
    }
#endif

    ta_end(ta);
  }

  return nua;
}

/**Shutdown a NUA stack.
 *
 * Ongoing calls are released, registrations unregistered, and 
 * subscriptions terminated.  If the stack cannot terminate within 
 * 30 seconds, it sends the nua_r_shutdown event with status 500.
 *
 * @param nua         Pointer to NUA stack object
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     #nua_r_shutdown
 */
void nua_shutdown(nua_t *nua)
{
  enter;

  if (nua)
    nua->nua_shutdown_started = 1;
  nua_signal(nua, NULL, NULL, 1, nua_r_shutdown, 0, NULL, TAG_END());
}

/** Destroy the NUA stack.
 *
 * Before calling nua_destroy() the application 
 * should call nua_shutdown and wait for successful #nua_r_shutdown event.
 * Shuts down and destroys the NUA stack. Ongoing calls, registrations, 
 * and subscriptions are left as they are.
 *
 * @param nua         Pointer to NUA stack object
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
void nua_destroy(nua_t *nua)
{
  enter;

  if (nua) {
    if (!nua->nua_shutdown_final) {
      SU_DEBUG_0(("nua_destroy(%p): FATAL: nua_shutdown not completed\n", nua));
      assert(nua->nua_shutdown);
      return;
    }

    su_task_deinit(nua->nua_server);
    su_task_deinit(nua->nua_client);

    su_clone_wait(nua->nua_api_root, nua->nua_clone);
#if HAVE_SMIME		/* Start NRC Boston */
    sm_destroy(nua->sm);
#endif			/* End NRC Boston */
    su_home_unref(nua->nua_home);
  }
}

/** Obtain default operation handle of the NUA stack object.
 *
 * A default operation can be used for operations where the 
 * ultimate result is not important or can be discarded.
 *
 * @param nua         Pointer to NUA stack object
 *
 * @retval !=NULL Pointer to NUA operation handle
 * @retval NULL   No default operation exists
 *
 * @par Related tags:
 *    none
 *
 * @par Events:
 *    none
 *
 */
nua_handle_t *nua_default(nua_t *nua)
{
  return nua ? nua->nua_handles : NULL;
}

/** Create an operation handle 
 *
 * Allocates a new operation handle and associated storage.
 *
 * @param nua         Pointer to NUA stack object
 * @param hmagic      Pointer to callback context
 * @param tag, value, ... List of tagged parameters
 *
 * @retval !=NULL  Pointer to operation handle
 * @retval NULL    Creation failed
 *
 * @par Related tags:
 *     Creates a copy of provided tags and they will 
 *     be used with every operation.
 *
 * @par Events:
 *     none
 *
 */
nua_handle_t *nua_handle(nua_t *nua, nua_hmagic_t *hmagic,
			 tag_type_t tag, tag_value_t value, ...)
{
  nua_handle_t *nh = NULL;

  if (nua) {
    ta_list ta;

    ta_start(ta, tag, value);

    nh = nh_create_handle(nua, hmagic, ta_args(ta));
    
    if (nh)
      nh->nh_ref_by_user = 1;

    ta_end(ta);
  }

  return nh;
}

/** Bind a callback context to an operation handle. 
 *
 * @param nh          Pointer to operation handle
 * @param hmagic      Pointer to callback context
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
void nua_handle_bind(nua_handle_t *nh, nua_hmagic_t *hmagic)
{
  enter;

  if (NH_IS_VALID(nh))
    nh->nh_magic = hmagic;
}

/* ---------------------------------------------------------------------- */

/** Check if operation handle is used for INVITE
 *
 * Check if operation handle has been used with either outgoing or incoming
 * INVITE request.
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0 no invite in operation or operation handle is invalid 
 * @retval 1 operation has invite 
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
int nua_handle_has_invite(nua_handle_t const *nh)
{
  return nh ? nh->nh_has_invite : 0;
}

/**Check if operation handle has active event subscriptions. 
 *
 * Active subscription can be established either by nua_subscribe 
 * or nua_refer() calls. 
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0    no event subscriptions in operation or 
 *              operation handle is invalid 
 * @retval !=0  operation has event subscriptions
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
int nua_handle_has_events(nua_handle_t const *nh)
{
  return nh ? nh->nh_ds->ds_has_events : 0;
}

/** Check if operation handle has active registrations
 *
 * Either REGISTER operation is ongoing or NUA stack is expected to 
 * refresh in the future.
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0 no active registration in operation or 
 *           operation handle is invalid
 * @retval 1 operation has registration
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
int nua_handle_has_registrations(nua_handle_t const *nh)
{
  return nh && nh->nh_ds->ds_has_register;
}

/** Check if operation handle has been used with outgoing SUBSCRIBE of REFER request. 
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0 no active subscription in operation or 
 *           operation handle is invalid 
 * @retval 1 operation has subscription.
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
int nua_handle_has_subscribe(nua_handle_t const *nh)
{
  return nh ? nh->nh_has_subscribe : 0;
}

/** Check if operation handle has been used with nua_register() or nua_unregister().
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0 no active register in operation or operation handle is invalid
 * @retval 1 operation has been used with nua_register() or nua-unregister()
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none

 */
int nua_handle_has_register(nua_handle_t const *nh)
{
  return nh ? nh->nh_has_register : 0;
}

int nua_handle_has_streaming(nua_handle_t const *nh)
{
  return nh ? nh->nh_has_streaming : 0;
}

/** Check if operation handle has an active call 
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0 no active call in operation or operation handle is invalid
 * @retval 1 operation has established call or pending call request.
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
int nua_handle_has_active_call(nua_handle_t const *nh)
{
  return nh ? nh->nh_ss->ss_active : 0;
}

/** Check if operation handle has a call on hold 
 *
 * Please note that this status is not affected by remote end putting 
 * this end on hold. Remote end can put each media separately on hold 
 * and status is reflected on #SOATAG_ACTIVE_AUDIO, #SOATAG_ACTIVE_VIDEO 
 * and #SOATAG_ACTIVE_CHAT tag values in nua_i_active event.
 *
 * @param nh          Pointer to operation handle
 *
 * @retval 0  if no call on hold in operation or operation handle is invalid 
 * @retval 1  if operation has call on hold, for example nua_invite() or 
 *            nua_update() has been called with NUTAG_HOLD() with != 0 argument.
 *
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
int nua_handle_has_call_on_hold(nua_handle_t const *nh)
{
  return nh ? nh->nh_ss->ss_hold_remote : 0;
}

/** Get the remote address (From/To header) of operation handle
 *
 * Remote address is used as To header in outgoing operations and 
 * derived from From: header in incoming operations.
 *
 * @param nh          Pointer to operation handle
 *
 * @retval NULL   no remote address for operation or operation handle invalid
 * @retval !=NULL pointer to remote address for operation
 *     
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
sip_to_t const *nua_handle_remote(nua_handle_t const *nh)
{
  return nh ? nh->nh_ds->ds_remote : NULL;
}

/** Get the local address (From/To header) of operation handle
 *
 * Local address is used as From header in outgoing operations and 
 * derived from To: header in incoming operations.
 *
 * @param nh          Pointer to operation handle
 *
 * @retval NULL   no local address for operation or operation handle invalid
 * @retval !=NULL pointer to local address for operation
 *     
 * @par Related tags:
 *     none
 *
 * @par Events:
 *     none
 */
sip_to_t const *nua_handle_local(nua_handle_t const *nh)
{
  return nh ? nh->nh_ds->ds_local : NULL;
}

void nua_set_params(nua_t *nua, tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  ta_start(ta, tag, value);

  enter;

  nua_signal(nua, NULL, NULL, 0, nua_r_set_params, 0, NULL, ta_tags(ta));

  ta_end(ta);
}

void nua_get_params(nua_t *nua, tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  ta_start(ta, tag, value);

  enter;

  nua_signal(nua, NULL, NULL, 0, nua_r_get_params, 0, NULL, ta_tags(ta));

  ta_end(ta);
}

#define NUA_SIGNAL(nh, event, tag, value) \
  enter; \
  if (NH_IS_VALID((nh))) { \
    ta_list ta; \
    ta_start(ta, tag, value); \
    nua_signal((nh)->nh_nua, nh, NULL, 0, event, 0, NULL, ta_tags(ta));	\
    ta_end(ta); \
  } \
  else { \
    SU_DEBUG_1(("nua: " #event " with invalid handle %p\n", nh));	\
  }

void nua_set_hparams(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_set_params, tag, value);
}

void nua_get_hparams(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_get_params, tag, value);
}

/* Documented with nua_stack_register() */
void nua_register(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_register, tag, value);
}

void nua_unregister(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_unregister, tag, value);
}

/** Place a call using SIP INVITE method. 
 *
 * By default creates a media session, includes its description as 
 * SDP and send the request to the recipient. Upon receiving the 
 * response it will active the media session and establish the call. 
 * 
 * Incomplete call can be hung-up with nua_cancel(). Completed call can be
 * hung-up with nua_bye().
 *
 * Optionally 
 * - uses early media if NUTAG_EARLY_MEDIA() tag is used with non zero value
 * - media parameters can be set by NUTAG_MEDIA_* tags
 * - if NUTAG_MEDIA_ENABLE() tag is used with value zero then the soa is 
 *   not used and application must create the SDP
 * - nua_invite() can be used to change call status: 
 *   - #SOATAG_HOLD tag listing the media put on hold or with value "*" sets
 *     the call on hold
 *   - if new media path is given either new media parameters are taken in 
 *     use or new media is added to session.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_URL() \n
 *    NUTAG_HOLD() \n
 *    NUTAG_NOTIFY_REFER() \n
 *    NUTAG_REFER_PAUSE() \n
 *    NUTAG_INVITE_TIMER() \n
 *    NUTAG_MEDIA_FEATURES() \n
 *    NUTAG_MEDIA_ENABLE() \n
 *    SOATAG_HOLD() \n
 *    SOATAG_AF() \n
 *    SOATAG_ADDRESS() \n
 *    SOATAG_USER_SDP() or SOATAG_USER_SDP_STR() \n
 *    tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_invite \n
 *    #nua_i_state \n
 *    #nua_i_active \n
 *    #nua_i_media_error \n
 *    #nua_i_fork \n
 *
 * \sa nua_handle_has_active_call() \n
 *     nua_handle_has_call_on_hold()\n
 *     nua_handle_has_invite() \n
 *     nua_update() \n
 *     nua_info() \n 
 *     nua_cancel() \n
 *     nua_bye()
 */
void nua_invite(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_invite, tag, value);
}

/** Acknowledge a succesfull response to INVITE request.
 *
 * Acknowledge a successful response to INVITE request 
 * with SIP ACK message. This function is need only if 
 * NUTAG_AUTOACK() parameter has been cleared.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_i_media_error \n
 *    #nua_i_active
 */
void nua_ack(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_ack, tag, value);
}

/** Hangdown a call.
 *
 * Hangdown a call using SIP BYE method. Also the media session 
 * associated with the call is terminated. 
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    none
 *
 * @par Events:
 *    #nua_r_bye \n
 *    #nua_i_media_error
 */
void nua_bye(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_bye, tag, value);
}

/** Cancel an INVITE operation 
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_cancel
 */
void nua_cancel(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_cancel, tag, value);
}

/** Query capabilities from server 
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_options
 *
 */
void nua_options(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_options, tag, value);
}

/** Send an instant message. 
 *
 * Send an instant message using SIP MESSAGE method.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_message
 */
void nua_message(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_message, tag, value);
}

/** Send a chat message. 
 *
 * A chat channel can be established during call setup using "message" media. 
 * An active chat channel is indicated using nua_i_active event containing 
 * #SOATAG_ACTIVE_CHAT tag. Chat messages can be sent using this channel with 
 * nua_chat() function. Currently this is implemented using SIP MESSAGE 
 * requests but in future MSRP (message session protocol) will replace it.
*
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    #SIPTAG_CONTENT_TYPE \n
 *    #SIPTAG_PAYLOAD      \n
 *    #SIPTAG_FROM         \n
 *    #SIPTAG_TO           \n
 *    use of other SIP tags' is deprecated
 *
 * @par Events:
 *    #nua_r_chat
 */
void nua_chat(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_chat, tag, value);
}

/** Subscribe a SIP event. 
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
 */
void nua_subscribe(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_subscribe, tag, value);
}

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
 *    #SIPTAG_EVENT \n
 *    Tags in <sip_tag.h> except #SIPTAG_EXPIRES or #SIPTAG_EXPIRES_STR
 *
 * @par Events:
 *    #nua_r_unsubscribe 
 */
void nua_unsubscribe(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_unsubscribe, tag, value);
}

/** Send a SIP NOTIFY request message. 
 *
 * This function is used when the application implements itself 
 * the subscription state machine. The application must provide 
 * valid @b Subscription-State and @b Event headers using SIP tags.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_notify
 */
void nua_notify(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_notify, tag, value);
}

/** Create an event server. 
 *
 * This function create an event server taking care of sending NOTIFY 
 * requests and responding to further SUBSCRIBE requests. The event 
 * server can accept multiple subscriptions from several sources and 
 * takes care for distributing the notifications. Unlike other functions 
 * this call only accepts the SIP tags listed below.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_URL() \n
 *    #SIPTAG_EVENT or #SIPTAG_EVENT_STR \n
 *    #SIPTAG_CONTENT_TYPE or SIPTAG_CONTENT_TYPE_STR \n
 *    #SIPTAG_PAYLOAD or #SIPTAG_PAYLOAD_STR \n
 *    #SIPTAG_ACCEPT or #SIPTAG_ACCEPT_STR \n
 *
 * @par Events:
 *    #nua_r_notify
 */
void nua_notifier(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_notifier, tag, value);
}

/** Terminate an event server. 
 *
 * Terminate an event server with matching event and content type. The event
 * server was created earlier with nua_notifier() function.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    #SIPTAG_EVENT \n
 *    #SIPTAG_CONTENT_TYPE \n
 *    #SIPTAG_PAYLOAD \n
 *    #NEATAG_REASON
 *
 * @par Events:
 *    #nua_r_terminate
 */
void nua_terminate(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_terminate, tag, value);
}

/** Transfer a call. 
 * 
 * Send a REFER request asking the recipient to transfer the call. The REFER
 * request also establishes a subscription to the "refer" event. The "refer"
 * event will have an "id" parameter, which has the value of CSeq number in
 * the REFER request. After initiating the REFER request, the nua engine
 * sends application a nua_r_refer event with status 100 and tag
 * SIPTAG_EVENT() containing a matching event header.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_URL() \n
 *    Tags in <sip_tag.h>
 *
 * @par Events:
 *    #nua_r_refer \n
 *    #nua_i_notify
 *
 * @sa @RFC3515
 */
void nua_refer(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_refer, tag, value);
}

/* Documented with nua_stack_publish() */
void nua_publish(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_publish, tag, value);
}

/* Documented with nua_stack_publish() */
void nua_unpublish(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_unpublish, tag, value);
}

/** Send an INFO request. 
 *
 * INFO is used to send call related information like DTMF 
 * digit input events. See @RFC2976.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sip_tag.h>.
 *
 * @par Events:
 *    #nua_r_info
 */
void nua_info(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_info, tag, value);
}


/** Send a PRACK request. 
 *
 * PRACK is used to acknowledge receipt of 100rel responses. See @RFC3262.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    Tags in <sofia-sip/soa_tag.h>, <sofia-sip/sip_tag.h>.
 *
 * @par Events:
 *    #nua_r_prack
 */
void nua_prack(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_prack, tag, value);
}


/** Update a session. 
 * 
 * Update a session using SIP UPDATE method. See @RFC3311.
 *
 * Update method can be used when the session has been established with
 * INVITE. It's mainly used during the session establishment when
 * preconditions are used (@RFC3312). It can be also used during the call if
 * no user input is needed for offer/answer negotiation.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    same as nua_invite()
 *
 * @par Events:
 *    #nua_r_update \n
 *    #nua_i_media_error \n
 *    #nua_i_media_update
 */
void nua_update(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_update, tag, value);
}

/** Authenticate an operation.
 *
 * - 401 / 407 response with www-authenticate header/ proxy-authenticate header
 * - application should provide stack with username&password for each realm
 * with NUTAG_AUTH() tag
 * - restarts operation
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_AUTH()
 *
 * @par Events:
 *    (any operation events)
 */
void nua_authenticate(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_authenticate, tag, value);
}

/** Authorize a subscriber.
 *
 * After creating a local presence server by nua_notifier(), an
 * incoming subscriber launches nua_i_subscription event. Subscriber
 * can be authorized in this application callback.
 *
 * NUTAG_SUB() tag
 * NUTAG_SUBSTATE() tag
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    NUTAG_SUB()
 *    NUTAG_SUBSTATE()
 *
 * @par Events:
 *    (any operation events)
 */
void nua_authorize(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_authorize, tag, value);
}

/*# Redirect an operation. */
void nua_redirect(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...)
{
  NUA_SIGNAL(nh, nua_r_redirect, tag, value);
}

/** Respond with given status. 
 * 
 * The INVITE requests should be responded with 
 * #nua_intive_respond() function because there 
 * might be another request going on besides INVITE.
 *
 * @param nh              Pointer to operation handle
 * @param status          SIP response status (see RFCs of SIP)
 * @param phrase          free text (default response phrase used if NULL)
 * @param tag, value, ... List of tagged parameters
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    #SOATAG_ADDRESS \n
 *    #SOATAG_AF \n
 *    #SOATAG_HOLD \n
 *    Tags in <sip_tag.h>.
 *
 * @par Events:
 *    #nua_i_active \n
 *    #nua_i_media_error \n
 *    #nua_i_error
 */
void nua_respond(nua_handle_t *nh,
		 int status, char const *phrase,
		 tag_type_t tag, tag_value_t value,
		 ...)
{
  enter;

  if (NH_IS_VALID(nh)) {
    ta_list ta;
    ta_start(ta, tag, value);
    nua_signal(nh->nh_nua, nh, NULL, 0, nua_r_respond,
	       status, phrase, ta_tags(ta));
    ta_end(ta);
  }
  else {
    SU_DEBUG_1(("nua: respond with invalid handle %p\n", nh));
  }
}

/** Destroy a handle 
 *
 * Destroy an operation handle and asks stack to discard resources 
 * and ongoing sessions and transactions associated with this handle. 
 * For example calls are terminated with BYE request.
 *
 * @param nh              Pointer to operation handle
 *
 * @return 
 *    nothing
 *
 * @par Related Tags:
 *    none
 *
 * @par Events:
 *    none
 */
void nua_handle_destroy(nua_handle_t *nh)
{
  enter;

  if (NH_IS_VALID(nh) && !NH_IS_DEFAULT(nh)) {
    nh->nh_valid = NULL;	/* Events are no more delivered to appl. */
    nua_signal(nh->nh_nua, nh, NULL, 1, nua_r_destroy, 0, NULL, TAG_END());
  }
}


/*# Send a request to the protocol thread */
void nua_signal(nua_t *nua, nua_handle_t *nh, msg_t *msg, int always,
		nua_event_t event,
		int status, char const *phrase,
		tag_type_t tag, tag_value_t value, ...)
{
  su_msg_r sumsg = SU_MSG_R_INIT;
  int len, xtra, e_len, l_len = 0, l_xtra = 0;
  ta_list ta;

  if (nua == NULL || (nua->nua_shutdown_started && event != nua_r_shutdown))
    return;

  ta_start(ta, tag, value);

  e_len = offsetof(event_t, e_tags);
  len = tl_len(ta_args(ta));
  xtra = tl_xtra(ta_args(ta), len);

  if (su_msg_create(sumsg, nua->nua_server, nua->nua_client,
		    nua_stack_signal,
		    e_len + len + l_len + xtra + l_xtra) == 0) {
    event_t *e = su_msg_data(sumsg);
    tagi_t *t = e->e_tags;
    void *b = (char *)t + len + l_len;

    tagi_t *tend = (tagi_t *)b;
    char *bend = (char *)b + xtra + l_xtra;

    t = tl_dup(t, ta_args(ta), &b);

    assert(tend == t); assert(b == bend);

    e->e_always = always;
    e->e_event = event;
    e->e_nh = event == nua_r_destroy ? nh : nua_handle_ref(nh);
    e->e_status = status;
    e->e_phrase = phrase;

    if (su_msg_send(sumsg) != 0)
      nua_handle_unref(nh);
  } 
  else {
    assert(0);
  }

  ta_end(ta);
}

/*# Receive event from protocol machine and hand it over to application */
void nua_event(nua_t *root_magic, su_msg_r sumsg, event_t *e)
{
  nua_t *nua;
  nua_handle_t *nh = e->e_nh;

  enter;

  if (nh) {
    if (!nh->nh_ref_by_user && nh->nh_valid) {
      nh->nh_ref_by_user = 1;
      nua_handle_ref(nh);
    }
  }

  if (!nh || !nh->nh_valid) {	/* Handle has been destroyed */
    if (nh && !NH_IS_DEFAULT(nh) && nua_handle_unref(nh)) {
      SU_DEBUG_9(("nua(%p): freed by application\n", nh));
    }
    if (e->e_msg)
      msg_destroy(e->e_msg);
    return;
  }

  nua = nh->nh_nua; assert(nua);

  if (e->e_event == nua_r_shutdown && e->e_status >= 200)
    nua->nua_shutdown_final = 1;

  if (!nua->nua_callback)
    return;

  if (NH_IS_DEFAULT(nh))
    nh = NULL;

  su_msg_save(nua->nua_current, sumsg);

  e->e_nh = NULL;

  nua->nua_callback(e->e_event, e->e_status, e->e_phrase,
		    nua, nua->nua_magic,
		    nh, nh ? nh->nh_magic : NULL,
		    e->e_msg ? sip_object(e->e_msg) : NULL,
		    e->e_tags);

  if (nh && !NH_IS_DEFAULT(nh) && nua_handle_unref(nh)) {
    SU_DEBUG_9(("nua(%p): freed by application\n", nh));
  }

  if (!su_msg_is_non_null(nua->nua_current))
    return;

  if (e->e_msg)
    msg_destroy(e->e_msg);

  su_msg_destroy(nua->nua_current);
}

/** Save nua event and its arguments */
int nua_save_event(nua_t *nua, nua_saved_event_t return_saved[1])
{
  if (nua && return_saved) {
    su_msg_save(return_saved, nua->nua_current);
    if (su_msg_is_non_null(return_saved)) {
      /* Remove references to tasks */
      su_msg_remove_refs(return_saved);
      return 1;
    }
  }
  return 0;
}

/** Get event data */
nua_event_data_t const *nua_event_data(nua_saved_event_t const saved[1])
{
  return saved ? su_msg_data(saved) : NULL;
}

/** Destroy saved event */
void nua_destroy_event(nua_saved_event_t saved[1])
{
  if (su_msg_is_non_null(saved)) {
    event_t *e = su_msg_data(saved);
    nua_handle_t *nh = e->e_nh;

    if (e->e_msg)
      msg_destroy(e->e_msg);

    if (nh && !NH_IS_DEFAULT(nh) && nua_handle_unref(nh)) {
      SU_DEBUG_9(("nua(%p): freed by application\n", nh));
    }

    su_msg_destroy(saved);
  }
}
