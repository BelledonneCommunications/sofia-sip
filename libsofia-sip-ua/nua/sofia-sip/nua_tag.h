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

#ifndef NUA_TAG_H
/** Defined when <sofia-sip/nua_tag.h> has been included. */
#define NUA_TAG_H

/**@file sofia-sip/nua_tag.h
 * @brief Tags for Sofia-SIP User Agent Library
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Mon Feb 19 18:54:26 EET 2001 ppessi
 */

#ifndef SU_TAG_H
#include <sofia-sip/su_tag.h>
#endif
#ifndef SDP_TAG_H
#include <sofia-sip/sdp_tag.h>
#endif
#ifndef URL_TAG_H
#include <sofia-sip/url_tag.h>
#endif
#ifndef SIP_TAG_H
#include <sofia-sip/sip_tag.h>
#endif
#ifndef NTA_TAG_H
#include <sofia-sip/nta_tag.h>
#endif
#ifndef NEA_TAG_H
#include <sofia-sip/nea_tag.h>
#endif
#ifndef SOA_TAG_H
#include <sofia-sip/soa_tag.h>
#endif

SOFIA_BEGIN_DECLS

/** NUA agent. */
typedef struct nua_s nua_t;

/** NUA transaction handle. */
typedef struct nua_handle_s nua_handle_t;

/** List of all NUA tags. */
SOFIAPUBVAR tag_type_t nua_tag_list[];

/** Filter tag matching any nua tag. */
#define NUTAG_ANY()          nutag_any, ((tag_value_t)0)
SOFIAPUBVAR tag_typedef_t nutag_any;

/** URL address from application to NUA
 *
 * @par Used with
 *    nua_create() \n
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    other calls that create SIP request
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string \n
 *    Own address for nua_create(), nua_set_params() and nua_get_params(). \n
 *    Target address for other calls.
 *
 * Corresponding tag taking reference parameter is NUTAG_URL_REF
 */
#define NUTAG_URL(x)            nutag_url, urltag_url_v(x)
SOFIAPUBVAR tag_typedef_t nutag_url;

#define NUTAG_URL_REF(x)        nutag_url_ref, urltag_url_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_url_ref;

/** Address as a string
 *
 * @par Used with
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    String in form "name <url>"
 *
 * Corresponding tag taking reference parameter is NUTAG_ADDRESS_REF()
 */
#define NUTAG_ADDRESS(x)        nutag_address, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_address;

#define NUTAG_ADDRESS_REF(x)    nutag_address_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_address_ref;

/**Set request retry count.
 *
 * Retry count determines how many times stack will automatically retry
 * after an recoverable error response, like 302, 401 or 407.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    unsigned
 *
 * @par Values
 *    @c 0   Never retry automatically \n
 *
 * Corresponding tag taking reference parameter is NUTAG_RETRY_COUNT_REF()
 */
#define NUTAG_RETRY_COUNT(x)      nutag_retry_count, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_retry_count;

#define NUTAG_RETRY_COUNT_REF(x)  nutag_retry_count_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_retry_count_ref;

/**Set maximum number of simultaneous subscribers per single event server.
 *
 * Determines how many subscribers can simultaneously subscribe to a single
 * event.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    unsigned
 *
 * @par Values
 *    @c 0   Do not allow any subscriptions \n
 *
 * Corresponding tag taking reference parameter is NUTAG_MAX_SUBSCRIPTIONS_REF()
 */
#define NUTAG_MAX_SUBSCRIPTIONS(x)      nutag_max_subscriptions, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_max_subscriptions;

#define NUTAG_MAX_SUBSCRIPTIONS_REF(x) \
nutag_max_subscriptions_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_max_subscriptions_ref;

/** Intentionally undocumented. */
#define NUTAG_UICC(x)  nutag_uicc, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_uicc;

#define NUTAG_UICC_REF(x) nutag_uicc_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_uicc_ref;

/** Ask NUA to create dialog for this handle
 *
 * @par Used with nua calls that send a SIP request
 *
 * @par Parameter type
 *   int
 *
 * @par Values
 *    @c False (zero) \n
 *    @c True (nonzero)
 *
 * Corresponding tag taking reference parameter is NUTAG_USE_DIALOG_REF()
 */
#define NUTAG_USE_DIALOG(x)        nutag_use_dialog, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_use_dialog;

#define NUTAG_USE_DIALOG_REF(x)    nutag_use_dialog_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_use_dialog_ref;


/* Protocol engine parameters,
 * set by nua_set_params(), get by nua_get_params() */

#if 0

/**Pointer to a SDP Offer-Answer session object.
 *
 * Pointer to the media session object.
 *
 * @par Used with nua_create(), nua_handle().
 *
 * @par Parameter type
 *    void * (actually soa_session_t *)
 *
 * @par Values
 *    Pointer to MSS media session.
 *
 * Corresponding tag taking reference parameter is NUTAG_SOA_SESSION_REF.
 */
#define NUTAG_SOA_SESSION(x)  nutag_soa_session, tag_ptr_v(x)
SOFIAPUBVAR tag_typedef_t nutag_soa_session;

#define NUTAG_SOA_SESSION_REF(x) \
 nutag_soa_session_ref, tag_ptr_vr(&(x),(x))
SOFIAPUBVAR tag_typedef_t nutag_soa_session_ref;

#endif

/**Name for SDP Offer-Answer session object.
 *
 * SDP Offer-Answer session object name.
 *
 * @par Used with nua_create(), nua_handle().
 *
 * @par Parameter type
 *    void * (actually soa_session_t *)
 *
 * @par Values
 *    Pointer to MSS media session.
 *
 * Corresponding tag taking reference parameter is NUTAG_SOA_SESSION_REF.
 */
#define NUTAG_SOA_NAME(x)  nutag_soa_name, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_soa_name;

#define NUTAG_SOA_NAME_REF(x) \
 nutag_soa_name_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_soa_name_ref;

/**Establish early media session using 183 responses and PRACK requests.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   False \n
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is NUTAG_EARLY_MEDIA_REF()
*/
#define NUTAG_EARLY_MEDIA(x)    nutag_early_media, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_early_media;

#define NUTAG_EARLY_MEDIA_REF(x) nutag_early_media_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_early_media_ref;

/**Respond only 183 with 100rel.
 *
 * If this parameter is set, stack uses 100rel only with 183: otherwise, all
 * 1XX responses (except <i>100 Trying</i>) uses 100rel.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int (boolean)
 *
 * @par Values
 *    @c 0   False \n
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is NUTAG_ONLY183_100REL_REF()
*/
#define NUTAG_ONLY183_100REL(x)    nutag_only183_100rel, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_only183_100rel;

#define NUTAG_ONLY183_100REL_REF(x) nutag_only183_100rel_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_only183_100rel_ref;

/** Timer for outstanding INVITE in seconds.
 *
 * INVITE will be canceled if no answer is received before timer expires.
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int (enum nua_af)
 *
 * @par Values
 *    @c 0  no timer \n
 *    @c >0 timer in seconds
 *
 * Corresponding tag taking reference parameter is NUTAG_INVITE_TIMER_REF()
 */
#define NUTAG_INVITE_TIMER(x)  nutag_invite_timer, tag_uint_v((x))
SOFIAPUBVAR tag_typedef_t nutag_invite_timer;

#define NUTAG_INVITE_TIMER_REF(x) nutag_invite_timer_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_invite_timer_ref;

/**Default session timer in seconds.
 *
 * Set default session timer in seconds when using session timer extension.
 * Re-INVITE will be sent in given intervals.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    @c 0  disable \n
 *    @c >0 interval in seconds
 *
 * Corresponding tag taking reference parameter is NUTAG_SESSION_TIMER_REF()
 */
#define NUTAG_SESSION_TIMER(x)  nutag_session_timer, tag_uint_v((x))
SOFIAPUBVAR tag_typedef_t nutag_session_timer;

#define NUTAG_SESSION_TIMER_REF(x) nutag_session_timer_ref, tag_uint_vr((&(x)))
SOFIAPUBVAR tag_typedef_t nutag_session_timer_ref;

/** Minimum acceptable refresh interval for session.
 *
 * Specifies the value of Min-SE header in seconds.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    interval in seconds.
 *
 * Corresponding tag taking reference parameter is NUTAG_MIN_SE_REF()
*/
#define NUTAG_MIN_SE(x)         nutag_min_se, tag_uint_v((x))
SOFIAPUBVAR tag_typedef_t nutag_min_se;

#define NUTAG_MIN_SE_REF(x)     nutag_min_se_ref, tag_uint_vr((&(x)))
SOFIAPUBVAR tag_typedef_t nutag_min_se_ref;

enum nua_session_refresher {
  nua_no_refresher, nua_local_refresher, nua_remote_refresher, nua_any_refresher
};

/** Specify preferred refresher.
 *
 * Specify for session timer extension which party is the preferred refresher.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *   enum { #nua_no_refresher,  #nua_local_refresher, #nua_remote_refresher,
 *          #nua_any_refresher }
 *
 * @par Values
 *    @c nua_no_refresher (session timers are disabled) \n
 *    @c nua_local_refresher \n
 *    @c nua_remote_refresher \n
 *    @c nua_any_refresher (default) \n
 *
 * Corresponding tag taking reference parameter is NUTAG_SESSION_REFRESHER_REF()
 */
#define NUTAG_SESSION_REFRESHER(x)  nutag_session_refresher, tag_int_v((x))
SOFIAPUBVAR tag_typedef_t nutag_session_refresher;

#define NUTAG_SESSION_REFRESHER_REF(x) nutag_session_refresher_ref, tag_int_vr((&(x)))
SOFIAPUBVAR tag_typedef_t nutag_session_refresher_ref;

/** Use UPDATE as refresh method.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    boolean
 *
 * @par Values
 *    @c 1 Use UPDATE \n
 *    @c 0 Use INVITE
 *
 * Corresponding tag taking reference parameter is NUTAG_UPDATE_REFRESH_REF()
 */
#define NUTAG_UPDATE_REFRESH(x)  nutag_update_refresh, tag_bool_v((x))
SOFIAPUBVAR tag_typedef_t nutag_update_refresh;

#define NUTAG_UPDATE_REFRESH_REF(x) nutag_update_refresh_ref, tag_bool_vr((&(x)))
SOFIAPUBVAR tag_typedef_t nutag_update_refresh_ref;

/** Send alerting (180 Ringing) automatically
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   No automatic sending of "180 Ringing" \n
 *    @c !=0 "180 Ringing" sent automatically
 *
 * Corresponding tag taking reference parameter is NUTAG_AUTOALERT_REF()
 */
#define NUTAG_AUTOALERT(x)      nutag_autoalert, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_autoalert;

#define NUTAG_AUTOALERT_REF(x)  nutag_autoalert_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_autoalert_ref;

/** ACK automatically
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0    No automatic sending of ACK \n
 *    @c !=0 ACK sent automatically
 *
 * Corresponding tag taking reference parameter is NUTAG_AUTOACK_REF()
 */
#define NUTAG_AUTOACK(x)        nutag_autoack, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_autoack;

#define NUTAG_AUTOACK_REF(x)    nutag_autoack_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_autoack_ref;

/** Answer (200 Ok) automatically to incoming call
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0    No automatic sending of "200 Ok" \n
 *    @c !=0 "200 Ok" sent automatically
 *
 * Corresponding tag taking reference parameter is NUTAG_AUTOANSWER_REF()
 */
#define NUTAG_AUTOANSWER(x)     nutag_autoanswer, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_autoanswer;

#define NUTAG_AUTOANSWER_REF(x) nutag_autoanswer_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_autoanswer_ref;

/** Enable incoming INVITE
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   Incoming INVITE not enabled. NUA answers 403 Forbidden \n
 *    @c !=0 Incoming INVITE enabled
 *
 * Corresponding tag taking reference parameter is NUTAG_ENABLEINVITE_REF()
 */
#define NUTAG_ENABLEINVITE(x)   nutag_enableinvite, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_enableinvite;

#define NUTAG_ENABLEINVITE_REF(x) nutag_enableinvite_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_enableinvite_ref;

/** Enable incoming MESSAGE
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   Incoming MESSAGE not enabled. NUA answers 403 Forbidden \n
 *    @c !=0 Incoming MESSAGE enabled
 *
 * Corresponding tag taking reference parameter is NUTAG_ENABLEMESSAGE_REF()
 */
#define NUTAG_ENABLEMESSAGE(x)  nutag_enablemessage, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_enablemessage;

#define NUTAG_ENABLEMESSAGE_REF(x) nutag_enablemessage_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_enablemessage_ref;

/** Enable incoming MESSAGE with To tag.
 *
 * Set this parameter if you want to chat with Windows Messenger.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   False \n
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is NUTAG_ENABLEMESSENGER_REF()
 */
#define NUTAG_ENABLEMESSENGER(x)  nutag_enablemessenger, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_enablemessenger;

#define NUTAG_ENABLEMESSENGER_REF(x) \
  nutag_enablemessenger_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_enablemessenger_ref;

/* Start NRC Boston */

/** Enable S/MIME
 *
 * @par Used with
 *    nua_create() \n
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    boolean
 *
 * @par Values
 *    @c 0   S/MIME is Disabled \n
 *    @c !=0 S/MIME is Enabled
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_ENABLE_REF()
 */
#define NUTAG_SMIME_ENABLE(x)  nutag_smime_enable, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_enable;

#define NUTAG_SMIME_ENABLE_REF(x) nutag_smime_enable_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_smime_enable_ref;

/** S/MIME Options
 *
 * This tag specifies the type of S/MIME security services requested
 * by the user.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_message()
 *
 * @par Parameter type
 *   int
 *
 * @par Values
 *   @c -1 (SM_ID_NULL) No security service needed \n
 *   @c  0 (SM_ID_CLEAR_SIGN) Clear signing \n
 *   @c  1 (SM_ID_SIGN) S/MIME signing \n
 *   @c  2 (SM_ID_ENCRYPT) S/MIME encryption
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_OPT_REF()
 */
#define NUTAG_SMIME_OPT(x)  nutag_smime_opt, tag_int_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_opt;

#define NUTAG_SMIME_OPT_REF(x) nutag_smime_opt_ref, tag_int_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_smime_opt_ref;

/* End NRC Boston */

/** S/MIME protection mode
 *
 * This tag specifies the protection mode of the SIP message by
 * S/MIME as requested by the user
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *   unsigned int
 *
 * @par Values
 *   @c -1 (SM_MODE_NULL) Unspecified \n
 *   @c  0 (SM_MODE_PAYLOAD_ONLY) SIP payload only \n
 *   @c  1 (SM_MODE_TUNNEL) SIP tunneling mode \n
 *   @c  2 (SM_MODE_SIPFRAG) SIPfrag protection
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_PROTECTION_MODE_REF()
 */
#define NUTAG_SMIME_PROTECTION_MODE(x) nutag_smime_protection_mode, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_protection_mode;

#define NUTAG_SMIME_PROTECTION_MODE_REF(x) \
           nutag_smime_protection_mode_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_smime_protection_mode_ref;

/** S/MIME digest algorithm
 *
 * This tag specifies the message digest algorithm to be used in S/MIME.
 *
 * @par Used with
 *    To be implemented
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_MESSAGE_DIGEST_REF()
 */
#define NUTAG_SMIME_MESSAGE_DIGEST(x) nutag_smime_message_digest, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_message_digest;

#define NUTAG_SMIME_MESSAGE_DIGEST_REF(x) \
            nutag_smime_message_digest_ref, tag_str_vr((&x))
SOFIAPUBVAR tag_typedef_t nutag_smime_message_digest_ref;

/** S/MIME signature algorithm
 *
 * This tag specifies the signature algorithm to be used in S/MIME.
 *
 * @par Used with
 *    To be implemented.
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_SIGNATURE_REF()
 */
#define NUTAG_SMIME_SIGNATURE(x) nutag_smime_signature, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_signature;

#define NUTAG_SMIME_SIGNATURE_REF(x) \
            nutag_smime_signature_ref, tag_str_vr((&x))
SOFIAPUBVAR tag_typedef_t nutag_smime_signature_ref;

/** S/MIME key encryption algorithm
 *
 * This tag specifies the key encryption algorithm to be used by S/MIME.
 *
 * @par Used with
 *    To be implemented
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_KEY_ENCRYPTION_REF()
 */
#define NUTAG_SMIME_KEY_ENCRYPTION(x) nutag_smime_key_encryption, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_key_encryption;

#define NUTAG_SMIME_KEY_ENCRYPTION_REF(x) \
          nutag_smime_key_encryption_ref, tag_str_vr((&x))
SOFIAPUBVAR tag_typedef_t nutag_smime_key_encryption_ref;

/** S/MIME message encryption algorithm
 *
 * This tag specifies the message encryption algorithm to be used in S/MIME.
 *
 * @par Used with
 *    To be implemented.
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_SMIME_MESSAGE_ENCRYPTION_REF()
 */
#define NUTAG_SMIME_MESSAGE_ENCRYPTION(x) nutag_smime_message_encryption, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_smime_message_encryption;

#define NUTAG_SMIME_MESSAGE_ENCRYPTION_REF(x) \
           nutag_smime_message_encryption_ref, tag_str_vr((&x))
SOFIAPUBVAR tag_typedef_t nutag_smime_message_encryption_ref;

/** x.500 certificate directory
 *
 * @par Used with
 *    nua_create()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated pathname of directory containing agent.pem and cafile.pem files.
 *
 * Corresponding tag taking reference parameter is NUTAG_CERTIFICATE_DIR_REF()
 */
#define NUTAG_CERTIFICATE_DIR(x) nutag_certificate_dir, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_certificate_dir;

#define NUTAG_CERTIFICATE_DIR_REF(x) \
          nutag_certificate_dir_ref, tag_str_vr((&x))
SOFIAPUBVAR tag_typedef_t nutag_certificate_dir_ref;

/** Certificate phrase
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_CERTIFICATE_PHRASE_REF()
 */
#define NUTAG_CERTIFICATE_PHRASE(x) nutag_certificate_phrase, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_certificate_phrase;

#define NUTAG_CERTIFICATE_PHRASE_REF(x) \
          nutag_certificate_phrase_ref, tag_str_vr((&x))
SOFIAPUBVAR tag_typedef_t nutag_certificate_phrase_ref;

/** Local SIPS url
 *
 * The application can specify an alternative local address for
 * NUA user agent engine. Usually the alternative address is a
 * secure SIP URI (SIPS) used with TLS transport.
 *
 * @par Used with
 *    nua_create()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_SIPS_URL_REF()
 */
#define NUTAG_SIPS_URL(x)       nutag_sips_url, urltag_url_v(x)
SOFIAPUBVAR tag_typedef_t nutag_sips_url;

#define NUTAG_SIPS_URL_REF(x)   nutag_sips_url_ref, urltag_url_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_sips_url_ref;

/** Outbound proxy URL
 *
 * Same tag as NTATAG_DEFAULT_PROXY
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_create()
 *
 * @par Parameter type
 *    url_string_t const * (either char const * or url_t *)
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_PROXY_REF()
 */
#define NUTAG_PROXY(x)          NTATAG_DEFAULT_PROXY(x)
#define NUTAG_PROXY_REF(x)      NTATAG_DEFAULT_PROXY_REF(x)
#define nutag_proxy             ntatag_default_proxy

/** Registrar URL
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    url_string_t const * (either char const * or url_t *)
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_REGISTRAR_REF()
 */
#define NUTAG_REGISTRAR(x)      nutag_registrar, urltag_url_v(x)
SOFIAPUBVAR tag_typedef_t nutag_registrar;

#define NUTAG_REGISTRAR_REF(x)  nutag_registrar_ref, urltag_url_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_registrar_ref;

/** Outbound option string.
 *
 * The outbound option string can specify how the NAT traversal is handled.
 * The option tokens are as follows:
 * - "gruuize": try to generate a GRUU
 * - "outbound": use SIP outbound extension (off by default)
 * - "validate": validate registration behind a NAT by sending OPTIONS to self
 * - "natify": try to traverse NAT
 * - "use-rport": use rport to traverse NAT
 * - "options-keepalive": send periodic OPTIONS requests as keepalive messages
 *
 * An option token with "no-" or "not-" prefix turns the option off. For
 * example, if you want to try to traverse NATs but not to use OPTIONS
 * keepalive, use NUTAG_OUTBOUND("natify no-options-keepalive").
 *
 * @note
 * Options string is used so that no new tags need to be added when the
 * outbound functionality changes.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_OUTBOUND_REF()
 */
#define NUTAG_OUTBOUND(x)      nutag_outbound, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_outbound;

#define NUTAG_OUTBOUND_REF(x)  nutag_outbound_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_outbound_ref;

#if notyet

/** Outbound proxy set 1.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_OUTBOUND_SET1_REF()
 */
#define NUTAG_OUTBOUND_SET1(x)      nutag_outbound_set1, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_outbound_set1;

#define NUTAG_OUTBOUND_SET1_REF(x)  nutag_outbound_set1_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_outbound_set1_ref;

/** Outbound proxy set 2.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_OUTBOUND_SET2_REF()
 */
#define NUTAG_OUTBOUND_SET2(x)      nutag_outbound_set2, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_outbound_set2;

#define NUTAG_OUTBOUND_SET2_REF(x)  nutag_outbound_set2_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_outbound_set2_ref;

/** Outbound proxy set 3.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_OUTBOUND_SET3_REF()
 */
#define NUTAG_OUTBOUND_SET3(x)      nutag_outbound_set3, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_outbound_set3;

#define NUTAG_OUTBOUND_SET3_REF(x)  nutag_outbound_set3_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_outbound_set3_ref;

/** Outbound proxy set 4.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_OUTBOUND_SET4_REF()
 */
#define NUTAG_OUTBOUND_SET4(x)      nutag_outbound_set4, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_outbound_set4;

#define NUTAG_OUTBOUND_SET4_REF(x)  nutag_outbound_set4_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_outbound_set4_ref;

#endif	/* ...notyet */

/** Pointer to SIP parser structure
 *
 * @par Used with
 *    nua_create()
 *
 * @par Parameter type
 *    msg_mclass_t *
 *
 * @par Values
 *    Pointer to an extended SIP parser.
 *
 * @sa msg_mclass_clone(), msg_mclass_insert_header()
 *
 * Corresponding tag taking reference parameter is NUTAG_SIP_PARSER_REF().
 */
#define NUTAG_SIP_PARSER(x)     NTATAG_MCLASS(x)
#define NUTAG_SIP_PARSER_REF(x) NTATAG_MCLASS_REF(x)

/** Authentication data ("scheme" "realm" "user" "password")
 *
 * @par Used with
 *    nua_authenticate()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated string of format: \n
 *    basic digest scheme:"realm":user:password  \n
 *    @b NOTE the double quotes around realm!
 *    For example: \n
 *	\code Digest:"nokia proxy":xyz:secret \endcode
 *
 * Corresponding tag taking reference parameter is NUTAG_AUTH_REF()
 */
#define NUTAG_AUTH(x)		nutag_auth, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_auth;

#define NUTAG_AUTH_REF(x)	    nutag_auth_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_auth_ref;

/** Keepalive interval in milliseconds.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values 
 *   - 0 - disable keepalives
 *   - 120000 - default value (120000 milliseconds, 120 seconds)
 *
 * Corresponding tag taking reference parameter is
 * NUTAG_KEEPALIVE_REF()
 */
#define NUTAG_KEEPALIVE(x) nutag_keepalive, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_keepalive;

#define NUTAG_KEEPALIVE_REF(x) nutag_keepalive_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_keepalive_ref;

/** Transport-level keepalive interval for streams.
 *
 * @par Used with
 *    nua_register()   \n
 *    nua_set_params() \n
 *    nua_get_params()
 *    nua_set_hparams() \n
 *    nua_get_hparams()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values 
 *
 * Transport-level keepalive interval for streams in milliseconds. If this
 * parameter specified, it takes presedence over value given in
 * NUTAG_KEEPALIVE().
 *
 * Corresponding tag taking reference parameter is
 * NUTAG_KEEPALIVE_STREAM_REF()
 *
 * @todo Actually pass NUTAG_KEEPALIVE_STREAM() to transport layer.
 */
#define NUTAG_KEEPALIVE_STREAM(x) nutag_keepalive_stream, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_keepalive_stream;

#define NUTAG_KEEPALIVE_STREAM_REF(x) \
nutag_keepalive_stream_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_keepalive_stream_ref;

/** Lifetime of authentication data in seconds.
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    @c 0   Use authentication data only for this handle \n
 *    @c !=0 Lifetime in seconds
 *
 * Corresponding tag taking reference parameter is NUTAG_AUTHTIME_REF()
 */
#define NUTAG_AUTHTIME(x)	nutag_authtime, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_authtime;

#define NUTAG_AUTHTIME_REF(x)	nutag_authtime_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_authtime_ref;

/** Events
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    void *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_EVENT_REF()
 */
#define NUTAG_EVENT(x)          nutag_event, tag_ptr_v(x)
SOFIAPUBVAR tag_typedef_t nutag_event;

#define NUTAG_EVENT_REF(x)      nutag_event_ref, tag_ptr_vr(&(x),(x))
SOFIAPUBVAR tag_typedef_t nutag_event_ref;

/** Response status code
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 * 100 - preliminary response, request is being processed by next hop \n
 * 1XX - preliminary response, request is being processed by UAS \n
 * 2XX - successful final response \n
 * 3XX - redirection error response \n
 * 4XX - client error response \n
 * 5XX - server error response \n
 * 6XX - global error response \n
 *
 * Corresponding tag taking reference parameter is NUTAG_STATUS_REF()
 */
#define NUTAG_STATUS(x)         nutag_status, tag_uint_v(x)
SOFIAPUBVAR tag_typedef_t nutag_status;

#define NUTAG_STATUS_REF(x)     nutag_status_ref, tag_uint_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_status_ref;

/** Response phrase
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_PHRASE_REF()
 */
#define NUTAG_PHRASE(x)         nutag_phrase, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_phrase;

#define NUTAG_PHRASE_REF(x)     nutag_phrase_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_phrase_ref;

/** NUA Handle
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    nua_handle_t *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_HANDLE_REF()
 */
#define NUTAG_HANDLE(x)         nutag_handle, nutag_handle_v(x)
SOFIAPUBVAR tag_typedef_t nutag_handle;

#define NUTAG_HANDLE_REF(x)     nutag_handle_ref, nutag_handle_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_handle_ref;

/** Registration handle (used with requests and nua_respond())
 *
 * When a new request is made or new call is responded, a new identity can
 * be selected with NUTAG_IDENTITY(). The identity comprises of @b From
 * header, initial route set, local contact header and media tags associated
 * with it, soa handle and so on. User can make multiple registrations using
 * multiple identities.
 *
 * @par Used with
 *    nua_invite()
 *
 * @par Parameter type
 *    nua_handle_t *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_IDENTITY_REF()
*/
#define NUTAG_IDENTITY(x)   nutag_identity, nutag_handle_v(x)
SOFIAPUBVAR tag_typedef_t nutag_identity;

#define NUTAG_IDENTITY_REF(x) nutag_identity_ref, nutag_handle_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_identity_ref;

/**Intance identifier.
 *
 * @par Used with
 *    nua_create(), nua_set_params(), nua_get_params(), 
 *    nua_register()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Value
 *    urn:uuid string.
 *
 * Corresponding tag taking reference parameter is NUTAG_INSTANCE_REF()
 */
#define NUTAG_INSTANCE(x)        nutag_instance, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_instance;

#define NUTAG_INSTANCE_REF(x)    nutag_instance_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_instance_ref;

/** Refer reply handle (used with refer)
 *
 * When making a call in response to a REFER request [RFC3515] with
 * nua_invite(), the application can ask NUA to automatically generate
 * notifications about the call progress to the referrer. In order to
 * do that the application should pass to the stack the handle, which
 * it used to receive the REFER request. It should also pass the event
 * header object along with the handle using NUTAG_REFER_EVENT().
 *
 * @par Used with
 *    nua_invite()
 *
 * @par Parameter type
 *    nua_handle_t *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_NOTIFY_REFER_REF()
*/
#define NUTAG_NOTIFY_REFER(x)   nutag_notify_refer, nutag_handle_v(x)
SOFIAPUBVAR tag_typedef_t nutag_notify_refer;

#define NUTAG_NOTIFY_REFER_REF(x) nutag_notify_refer_ref, nutag_handle_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_notify_refer_ref;

/** Event used with automatic refer notifications.
 *
 * When creating a call in response to a REFER request [RFC3515]
 * the application can ask NUA to automatically generate notifications
 * about the call progress to the referrer. The #nua_i_refer event will
 * contain a suitable SIP event header for the notifications in the
 * NUTAG_REFER_EVENT() tag. The application should store the SIP event
 * header and when it makes the referred call, it should pass it back
 * to the stack again using the NUTAG_REFER_EVENT() tag.
 *
 * @par Used with
 *
 * @par Parameter type
 *    sip_event_t *
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_REFER_EVENT_REF()
 */
#define NUTAG_REFER_EVENT(x)   nutag_refer_event, siptag_event_v(x)
SOFIAPUBVAR tag_typedef_t nutag_refer_event;

#define NUTAG_REFER_EVENT_REF(x) nutag_refer_event_ref, siptag_event_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_refer_event_ref;

/** Invite pauses referrer's handle.
 *
 * When creating a call in response to a REFER [RFC3515] request,
 * the application can ask that the original call will be muted
 * when the new call is connected by specifying NUTAG_REFER_PAUSE()
 * along with NUTAG_NOTIFY_REFER() as a parameter to nua_invite() call.
 *
 * @par Used with
 *    nua_invite()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   False
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is NUTAG_REFER_PAUSE_REF()
 */
#define NUTAG_REFER_PAUSE(x)   nutag_refer_pause, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_refer_pause;

#define NUTAG_REFER_PAUSE_REF(x) nutag_refer_pause_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_refer_pause_ref;

/** User-Agent string
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    see
 *    <a href="http://www.ietf.org/rfc/rfc3261.txt">RFC 3261</a> \n
 *    default string is of format "nua/2.0"
 *
 * Corresponding tag taking reference parameter is NUTAG_USER_AGENT_REF()
 */
#define NUTAG_USER_AGENT(x)     nutag_user_agent, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_user_agent;

#define NUTAG_USER_AGENT_REF(x) nutag_user_agent_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_user_agent_ref;

/** Allow a method (or methods).
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_set_hparams() \n
 *    any handle-specific nua call
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    Valid method name, or comma-separated list of them.
 *
 * Corresponding tag taking reference parameter is NUTAG_ALLOW_REF()
 */
#define NUTAG_ALLOW(x)     nutag_allow, tag_str_v(x)
SOFIAPUBVAR tag_typedef_t nutag_allow;

#define NUTAG_ALLOW_REF(x) nutag_allow_ref, tag_str_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_allow_ref;

/** Call state
 *
 * @par Used with
 *    #nua_i_state
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 * - @c nua_callstate_init - Initial state
 * - @c nua_callstate_authenticating - 401/407 received
 * - @c nua_callstate_calling - INVITE sent
 * - @c nua_callstate_proceeding - 18X received
 * - @c nua_callstate_received - INVITE received
 * - @c nua_callstate_early - 18X sent (w/SDP)
 * - @c nua_callstate_ready        - 2XX received or sent
 * - @c nua_callstate_terminating - BYE sent
 * - @c nua_callstate_terminated  - BYE complete
 *
 * Corresponding tag taking reference parameter is NUTAG_CALLSTATE_REF()
 */
#define NUTAG_CALLSTATE(x) nutag_callstate, tag_int_v(x)
SOFIAPUBVAR tag_typedef_t nutag_callstate;

#define NUTAG_CALLSTATE_REF(x) nutag_callstate_ref, tag_int_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_callstate_ref;

enum nua_callstate {
  nua_callstate_init,		/**< Initial state */
  nua_callstate_authenticating, /**< 401/407 received */
  nua_callstate_calling,	/**< INVITE sent */
  nua_callstate_proceeding,	/**< 18X received */
  nua_callstate_completing,	/**< 2XX received */
  nua_callstate_received,	/**< INVITE received */
  nua_callstate_early,		/**< 18X sent (w/SDP) */
  nua_callstate_completed,	/**< 2XX sent */
  nua_callstate_ready,		/**< 2XX received, ACK sent, or vice versa */
  nua_callstate_terminating,	/**< BYE sent */
  nua_callstate_terminated	/**< BYE complete */
};

/** Get name for NUA call state */
SOFIAPUBFUN char const *nua_callstate_name(enum nua_callstate state);

/** Subscription state
 *
 * @par Used with
 *    #nua_r_subscribe \n
 *    #nua_i_notify
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *   @c nua_substate_embryonic (0) \n
 *   @c nua_substate_pending (1) \n
 *   @c nua_substate_active (2) \n
 *   @c nua_substate_terminated	(3) \n
 *
 * see
 * <a href="http://www.ietf.org/rfc/rfc3265.txt">RFC 3265</a>
 *
 * Corresponding tag taking reference parameter is NUTAG_SUBSTATE_REF()
*/
#define NUTAG_SUBSTATE(x) nutag_substate, tag_int_v(x)
SOFIAPUBVAR tag_typedef_t nutag_substate;

#define NUTAG_SUBSTATE_REF(x) nutag_substate_ref, tag_int_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_substate_ref;

enum nua_substate {
  nua_substate_extended = nea_extended,
  nua_substate_embryonic = nea_embryonic,
  nua_substate_pending = nea_pending,
  nua_substate_active = nea_active,
  nua_substate_terminated = nea_terminated
};

/**Default lifetime for implicit subscriptions created by REFER.
 *
 * Default expiration time in seconds for implicit subscriptions created by
 * REFER.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_set_hparams() \n
 *    nua_get_hparams() \n
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    @c 0  disable \n
 *    @c >0 interval in seconds
 *
 * Corresponding tag taking reference parameter is NUTAG_REFER_EXPIRES()
 */
#define NUTAG_REFER_EXPIRES(x)  nutag_refer_expires, tag_uint_v((x))
SOFIAPUBVAR tag_typedef_t nutag_refer_expires;

#define NUTAG_REFER_EXPIRES_REF(x) nutag_refer_expires_ref, tag_uint_vr((&(x)))
SOFIAPUBVAR tag_typedef_t nutag_refer_expires_ref;

/** Add media tags from our offer to Accept-Contact headers.
 *
 * Automatically generate Accept-Contact headers for caller
 * preference processing according to our current media capabilities.
 *
 * @par Used with
 *    nua_invite()  \n
 *    nua_update()  \n
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   Do not add media tags \n
 *    @c !=0 Add media tags
 *
 * Corresponding tag taking reference parameter is NUTAG_MEDIA_FEATURES_REF()
 */
#define NUTAG_MEDIA_FEATURES(x) nutag_media_features, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_media_features;

#define NUTAG_MEDIA_FEATURES_REF(x) \
          nutag_media_features_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_media_features_ref;

/** Add methods and media tags to Contact headers. */
#define NUTAG_CALLEE_CAPS(x) nutag_callee_caps, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_callee_caps;

#define NUTAG_CALLEE_CAPS_REF(x) \
          nutag_callee_caps_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_callee_caps_ref;

/** If true, add "path" to Supported in REGISTER.
 *
 * @sa <a href="http://www.ietf.org/rfc/rfc3327.txt">RFC 3327</a>,
 * <i>"SIP Extension Header Field for Registering Non-Adjacent Contacts"</i>,
 * D. Willis, B. Hoeneisen,
 * December 2002.
 */
#define NUTAG_PATH_ENABLE(x)   nutag_path_enable, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_path_enable;

#define NUTAG_PATH_ENABLE_REF(x) nutag_path_enable_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_path_enable_ref;

/** Use route from Service-Route header in response to REGISTER.
 *
 * @sa <a href="http://www.ietf.org/rfc/rfc3327.txt">RFC 3327</a>,
 * <i>"SIP Extension Header Field for Registering Non-Adjacent Contacts"</i>,
 * D. Willis, B. Hoeneisen,
 * December 2002.
 */
#define NUTAG_SERVICE_ROUTE_ENABLE(x) nutag_service_route_enable, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_service_route_enable;

#define NUTAG_SERVICE_ROUTE_ENABLE_REF(x) \
          nutag_service_route_enable_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_service_route_enable_ref;

/** Enable local media (MSS)
 *
 * @par Used with
 *    nua_create()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 0   False \n
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is NUTAG_MEDIA_ENABLE_REF()
*/
#define NUTAG_MEDIA_ENABLE(x) nutag_media_enable, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_media_enable;

#define NUTAG_MEDIA_ENABLE_REF(x) \
          nutag_media_enable_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_media_enable_ref;

/** Indicate that SDP offer has been received.
 *
 * @par Used with
 *    #nua_i_state
 *
 * @par Parameter type
 *    boolean
 *
 * Corresponding tag taking reference parameter is NUTAG_OFFER_RECV_REF()
 */
#define NUTAG_OFFER_RECV(x) nutag_offer_recv, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_offer_recv;

#define NUTAG_OFFER_RECV_REF(x) nutag_offer_recv_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_offer_recv_ref;

/** Indicate that SDP answer has been received.
 *
 * @par Used with
 *    #nua_i_state
 *
 * @par Parameter type
 *    boolean
 *
 * Corresponding tag taking reference parameter is NUTAG_ANSWER_RECV_REF()
 */
#define NUTAG_ANSWER_RECV(x) nutag_answer_recv, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_answer_recv;

#define NUTAG_ANSWER_RECV_REF(x) nutag_answer_recv_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_answer_recv_ref;

/** Indicate that SDP offer has been sent.
 *
 * @par Used with
 *    #nua_i_state
 *
 * @par Parameter type
 *    boolean
 *
 * Corresponding tag taking reference parameter is NUTAG_OFFER_SENT_REF()
 */
#define NUTAG_OFFER_SENT(x) nutag_offer_sent, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_offer_sent;

#define NUTAG_OFFER_SENT_REF(x) nutag_offer_sent_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_offer_sent_ref;

/** Indicate that SDP answer has been sent.
 *
 * @par Used with
 *    #nua_i_state
 *
 * @par Parameter type
 *    boolean
 *
 * Corresponding tag taking reference parameter is NUTAG_ANSWER_SENT_REF()
 */
#define NUTAG_ANSWER_SENT(x) nutag_answer_sent, tag_bool_v(x)
SOFIAPUBVAR tag_typedef_t nutag_answer_sent;

#define NUTAG_ANSWER_SENT_REF(x) nutag_answer_sent_ref, tag_bool_vr(&(x))
SOFIAPUBVAR tag_typedef_t nutag_answer_sent_ref;

#if SU_HAVE_INLINE
su_inline tag_value_t nutag_handle_v(nua_handle_t *v) { return (tag_value_t)v; }
su_inline tag_value_t nutag_handle_vr(nua_handle_t **vp) {return(tag_value_t)vp;}
#else
#define nutag_handle_v(v)   (tag_value_t)(v)
#define nutag_handle_vr(v)  (tag_value_t)(v)
#endif

/* Tags for compatibility */

#define NUTAG_USE_LEG(x) NUTAG_USE_DIALOG(x)
#define NUTAG_USE_LEG_REF(x) NUTAG_USE_DIALOG_REF(x)

#define NUTAG_AF(x) SOATAG_AF((x))
#define NUTAG_AF_REF(x) SOATAG_AF_REF((x))

enum nua_af {
  nutag_af_any = SOA_AF_ANY,
  nutag_af_ip4_only = SOA_AF_IP4_ONLY,
  nutag_af_ip6_only = SOA_AF_IP6_ONLY,
  nutag_af_ip4_ip6 = SOA_AF_IP4_IP6,
  nutag_af_ip6_ip4 = SOA_AF_IP6_IP4
};

#define NUTAG_AF_ANY      nutag_af_any
#define NUTAG_AF_IP4_ONLY nutag_af_ip4_only
#define NUTAG_AF_IP6_ONLY nutag_af_ip6_only
#define NUTAG_AF_IP4_IP6  nutag_af_ip4_ip6
#define NUTAG_AF_IP6_IP4  nutag_af_ip6_ip4

#define NUTAG_MEDIA_ADDRESS(x)  SOATAG_ADDRESS((x))
#define NUTAG_MEDIA_ADDRESS_REF(x)   SOATAG_ADDRESS_REF((x))

#define NUTAG_HOLD(x) SOATAG_HOLD((x) ? "*" : NULL)

#define NUTAG_ACTIVE_AUDIO(x) SOATAG_ACTIVE_AUDIO((x))
#define NUTAG_ACTIVE_AUDIO_REF(x) SOATAG_ACTIVE_AUDIO_REF((x))
#define NUTAG_ACTIVE_VIDEO(x) SOATAG_ACTIVE_VIDEO((x))
#define NUTAG_ACTIVE_VIDEO_REF(x) SOATAG_ACTIVE_VIDEO_REF((x))
#define NUTAG_ACTIVE_IMAGE(x) SOATAG_ACTIVE_IMAGE((x))
#define NUTAG_ACTIVE_IMAGE_REF(x) SOATAG_ACTIVE_IMAGE_REF((x))
#define NUTAG_ACTIVE_CHAT(x) SOATAG_ACTIVE_CHAT((x))
#define NUTAG_ACTIVE_CHAT_REF(x) SOATAG_ACTIVE_CHAT_REF((x))

enum {
  nua_active_rejected = SOA_ACTIVE_REJECTED,
  nua_active_disabled = SOA_ACTIVE_DISABLED,
  nua_active_inactive = SOA_ACTIVE_INACTIVE,
  nua_active_sendonly = SOA_ACTIVE_SENDONLY,
  nua_active_recvonly = SOA_ACTIVE_RECVONLY,
  nua_active_sendrecv = SOA_ACTIVE_SENDRECV
};

#define NUTAG_SRTP_ENABLE(x)  SOATAG_SRTP_ENABLE((x))
#define NUTAG_SRTP_ENABLE_REF(x) SOATAG_SRTP_ENABLE_REF((x))
#define NUTAG_SRTP_CONFIDENTIALITY(x)  SOATAG_SRTP_CONFIDENTIALITY((x))
#define NUTAG_SRTP_CONFIDENTIALITY_REF(x) SOATAG_SRTP_CONFIDENTIALITY_REF((x))
#define NUTAG_SRTP_INTEGRITY_PROTECTION(x)  SOATAG_SRTP_INTEGRITY((x))
#define NUTAG_SRTP_INTEGRITY_PROTECTION_REF(x) SOATAG_SRTP_INTEGRITY_REF((x))

SOFIA_END_DECLS

#endif
