/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * * This library is free software; you can redistribute it and/or
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

#ifndef NUA_TAG_H /** Defined when <nua_tag.h> has been included. */
#define NUA_TAG_H "$Id: nua_tag.h,v 1.6 2005/09/28 20:05:24 ppessi Exp $"

/**@file nua_tag.h
 * @brief Tags for Nokia User Agent Library
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Mon Feb 19 18:54:26 EET 2001 ppessi
 * $Date: 2005/09/28 20:05:24 $
 */

#ifndef SU_TAG_H
#include <su_tag.h>
#endif
#ifndef SDP_TAG_H
#include <sdp_tag.h>
#endif
#ifndef URL_TAG_H
#include <url_tag.h>
#endif
#ifndef SIP_TAG_H
#include <sip_tag.h>
#endif
#ifndef NTA_TAG_H
#include <nta_tag.h>
#endif
#ifndef SOA_TAG_H
#include <soa_tag.h>
#endif
#ifndef NUA_H
#include <nua.h>
#endif

/** List of all NUA tags. */
extern tag_type_t nua_tag_list[];

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
extern tag_typedef_t nutag_url;

#define NUTAG_URL_REF(x)        nutag_url_ref, urltag_url_vr(&(x))
extern tag_typedef_t nutag_url_ref;

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
extern tag_typedef_t nutag_address;

#define NUTAG_ADDRESS_REF(x)    nutag_address_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_address_ref;

#define NUTAG_UICC(x)  nutag_uicc, tag_str_v(x)
extern tag_typedef_t nutag_uicc;

#define NUTAG_UICC_REF(x) nutag_uicc_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_uicc_ref;

/** Ask NUA to create leg for this handle
 *
 * @par Used with
 *    calls that send a SIP request
 *
 * @par Parameter type
 *   int
 *
 * @par Values
 *    @c 0   False \n
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is NUTAG_USE_LEG_REF()
 */
#define NUTAG_USE_LEG(x)        nutag_use_leg, tag_bool_v(x)
extern tag_typedef_t nutag_use_leg;

#define NUTAG_USE_LEG_REF(x)    nutag_use_leg_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_use_leg_ref;

/** Create a session for this handle */
#define NUTAG_USE_SESSION(x)        nutag_use_session, tag_bool_v(x)
extern tag_typedef_t nutag_use_session;

#define NUTAG_USE_SESSION_REF(x)    nutag_use_session_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_use_session_ref;

/* Protocol engine parameters,
 * set by nua_set_params(), get by nua_get_params() */

#if 1

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
extern tag_typedef_t nutag_soa_session;

#define NUTAG_SOA_SESSION_REF(x) \
 nutag_soa_session_ref, tag_ptr_vr(&(x),(x))
extern tag_typedef_t nutag_soa_session_ref;

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
extern tag_typedef_t nutag_soa_name;

#define NUTAG_SOA_NAME_REF(x) \
 nutag_soa_name_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_soa_name_ref;

#else

/** Pointer to a media session.
 *
 * Pointer to MSS media session. Used with NUTAG_MEDIA_CLONE()
 * when multiple SIP calls share common media session.
 *
 * @par Used with
 *
 * @par Parameter type
 *    void * (actually ms_t*)
 *
 * @par Values
 *    Pointer to MSS media session.
 *
 * Corresponding tag taking reference parameter is NUTAG_MEDIA_SESSION_REF.
 */
#define NUTAG_MEDIA_SESSION(x)  nutag_media_session, tag_ptr_v(x)
extern tag_typedef_t nutag_media_session;

#define NUTAG_MEDIA_SESSION_REF(x) \
 nutag_media_session_ref, tag_ptr_vr(&(x),(x))
extern tag_typedef_t nutag_media_session_ref;

#endif

/** Establish early media session using 183 responses and PRACK requests.
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
extern tag_typedef_t nutag_early_media;

#define NUTAG_EARLY_MEDIA_REF(x) nutag_early_media_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_early_media_ref;

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
extern tag_typedef_t nutag_invite_timer;

#define NUTAG_INVITE_TIMER_REF(x) nutag_invite_timer_ref, tag_uint_vr(&(x))
extern tag_typedef_t nutag_invite_timer_ref;

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
extern tag_typedef_t nutag_session_timer;

#define NUTAG_SESSION_TIMER_REF(x) nutag_session_timer_ref, tag_uint_vr((&(x)))
extern tag_typedef_t nutag_session_timer_ref;

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
extern tag_typedef_t nutag_min_se;

#define NUTAG_MIN_SE_REF(x)     nutag_min_se_ref, tag_uint_vr((&(x)))
extern tag_typedef_t nutag_min_se_ref;

enum nua_session_refresher {
  nua_no_refresher, nua_local_refresher, nua_remote_refresher
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
 *    enum { nua_no_refresher,  nua_local_refresher, nua_remote_refresher }
 *
 * @par Values
 *    @c nua_no_refresher    \n
 *    @c nua_local_refresher \n
 *    @c nua_remote_refresher
 *
 * Corresponding tag taking reference parameter is NUTAG_SESSION_REFRESHER_REF()
 */
#define NUTAG_SESSION_REFRESHER(x)  nutag_session_refresher, tag_int_v((x))
extern tag_typedef_t nutag_session_refresher;

#define NUTAG_SESSION_REFRESHER_REF(x) nutag_session_refresher_ref, tag_int_vr((&(x)))
extern tag_typedef_t nutag_session_refresher_ref;

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
extern tag_typedef_t nutag_update_refresh;

#define NUTAG_UPDATE_REFRESH_REF(x) nutag_update_refresh_ref, tag_bool_vr((&(x)))
extern tag_typedef_t nutag_update_refresh_ref;

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
#define NUTAG_AUTOALERT(x)      nutag_autoAlert, tag_bool_v(x)
extern tag_typedef_t nutag_autoAlert;

#define NUTAG_AUTOALERT_REF(x)  nutag_autoAlert_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_autoAlert_ref;

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
#define NUTAG_AUTOACK(x)        nutag_autoACK, tag_bool_v(x)
extern tag_typedef_t nutag_autoACK;

#define NUTAG_AUTOACK_REF(x)    nutag_autoACK_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_autoACK_ref;

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
#define NUTAG_AUTOANSWER(x)     nutag_autoAnswer, tag_bool_v(x)
extern tag_typedef_t nutag_autoAnswer;

#define NUTAG_AUTOANSWER_REF(x) nutag_autoAnswer_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_autoAnswer_ref;

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
#define NUTAG_ENABLEINVITE(x)   nutag_enableInvite, tag_bool_v(x)
extern tag_typedef_t nutag_enableInvite;

#define NUTAG_ENABLEINVITE_REF(x) nutag_enableInvite_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_enableInvite_ref;

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
#define NUTAG_ENABLEMESSAGE(x)  nutag_enableMessage, tag_bool_v(x)
extern tag_typedef_t nutag_enableMessage;

#define NUTAG_ENABLEMESSAGE_REF(x) nutag_enableMessage_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_enableMessage_ref;

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
#define NUTAG_ENABLEMESSENGER(x)  nutag_enableMessenger, tag_bool_v(x)
extern tag_typedef_t nutag_enableMessenger;

#define NUTAG_ENABLEMESSENGER_REF(x) \
  nutag_enableMessenger_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_enableMessenger_ref;

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
extern tag_typedef_t nutag_smime_enable;

#define NUTAG_SMIME_ENABLE_REF(x) nutag_smime_enable_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_smime_enable_ref;

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
extern tag_typedef_t nutag_smime_opt;

#define NUTAG_SMIME_OPT_REF(x) nutag_smime_opt_ref, tag_int_vr(&(x))
extern tag_typedef_t nutag_smime_opt_ref;

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
extern tag_typedef_t nutag_smime_protection_mode;

#define NUTAG_SMIME_PROTECTION_MODE_REF(x) \
           nutag_smime_protection_mode_ref, tag_uint_vr(&(x))
extern tag_typedef_t nutag_smime_protection_mode_ref;

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
extern tag_typedef_t nutag_smime_message_digest;

#define NUTAG_SMIME_MESSAGE_DIGEST_REF(x) \
            nutag_smime_message_digest_ref, tag_str_vr((&x))
extern tag_typedef_t nutag_smime_message_digest_ref;

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
extern tag_typedef_t nutag_smime_signature;

#define NUTAG_SMIME_SIGNATURE_REF(x) \
            nutag_smime_signature_ref, tag_str_vr((&x))
extern tag_typedef_t nutag_smime_signature_ref;

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
extern tag_typedef_t nutag_smime_key_encryption;

#define NUTAG_SMIME_KEY_ENCRYPTION_REF(x) \
          nutag_smime_key_encryption_ref, tag_str_vr((&x))
extern tag_typedef_t nutag_smime_key_encryption_ref;

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
extern tag_typedef_t nutag_smime_message_encryption;

#define NUTAG_SMIME_MESSAGE_ENCRYPTION_REF(x) \
           nutag_smime_message_encryption_ref, tag_str_vr((&x))
extern tag_typedef_t nutag_smime_message_encryption_ref;

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
extern tag_typedef_t nutag_certificate_dir;

#define NUTAG_CERTIFICATE_DIR_REF(x) \
          nutag_certificate_dir_ref, tag_str_vr((&x))
extern tag_typedef_t nutag_certificate_dir_ref;

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
extern tag_typedef_t nutag_certificate_phrase;

#define NUTAG_CERTIFICATE_PHRASE_REF(x) \
          nutag_certificate_phrase_ref, tag_str_vr((&x))
extern tag_typedef_t nutag_certificate_phrase_ref;

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
extern tag_typedef_t nutag_sips_url;

#define NUTAG_SIPS_URL_REF(x)   nutag_sips_url_ref, urltag_url_vr(&(x))
extern tag_typedef_t nutag_sips_url_ref;

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
extern tag_typedef_t nutag_registrar;

#define NUTAG_REGISTRAR_REF(x)  nutag_registrar_ref, urltag_url_vr(&(x))
extern tag_typedef_t nutag_registrar_ref;

/** Allowed sip methods. If this tag is not used all methods are allowed by default.
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated string of allowed SIP methods separated by commas
 *
 * Corresponding tag taking reference parameter is NUTAG_ALLOW_REF()
 */
#define NUTAG_ALLOW(x)          nutag_allow, tag_str_v(x)
extern tag_typedef_t nutag_allow;

#define NUTAG_ALLOW_REF(x)      nutag_allow_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_allow_ref;

/** Pointer to SIP parser structure
 *
 * @par Used with
 *    nua_create()
 *
 * @par Parameter type
 *    void * (actually msg_mclass)
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_SIP_PARSER_REF()
 */
#define NUTAG_SIP_PARSER(x)     nutag_sip_parser, tag_ptr_v(x)
extern tag_typedef_t nutag_sip_parser;

#define NUTAG_SIP_PARSER_REF(x) \
          nutag_sip_parser_ref, tag_ptr_vr(&(x), (x))
extern tag_typedef_t nutag_sip_parser_ref;

/** Authentication data ("realm" "user" "password")
 *
 * @par Used with
 *    nua_authenticate()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated string of format: basic digest scheme:"realm":user:password  \n
 *    for example: \n
 *	@code Digest:"nokia proxy":xyz:secret \endcode
 *
 * Corresponding tag taking reference parameter is NUTAG_AUTH_REF()
 */
#define NUTAG_AUTH(x)		nutag_auth, tag_str_v(x)
extern tag_typedef_t nutag_auth;

#define NUTAG_AUTH_REF(x)	    nutag_auth_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_auth_ref;

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
extern tag_typedef_t nutag_authtime;

#define NUTAG_AUTHTIME_REF(x)	nutag_authtime_ref, tag_uint_vr(&(x))
extern tag_typedef_t nutag_authtime_ref;

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
extern tag_typedef_t nutag_event;

#define NUTAG_EVENT_REF(x)      nutag_event_ref, tag_ptr_vr(&(x),(x))
extern tag_typedef_t nutag_event_ref;

/** Response status code
 *
 * @par Used with
 *    Currently not processed by NUA
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *
 * Corresponding tag taking reference parameter is NUTAG_STATUS_REF()
 */
#define NUTAG_STATUS(x)         nutag_status, tag_uint_v(x)
extern tag_typedef_t nutag_status;

#define NUTAG_STATUS_REF(x)     nutag_status_ref, tag_uint_vr(&(x))
extern tag_typedef_t nutag_status_ref;

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
extern tag_typedef_t nutag_phrase;

#define NUTAG_PHRASE_REF(x)     nutag_phrase_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_phrase_ref;

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
extern tag_typedef_t nutag_handle;

#define NUTAG_HANDLE_REF(x)     nutag_handle_ref, nutag_handle_vr(&(x))
extern tag_typedef_t nutag_handle_ref;

/** Hold & unhold
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_update()
 *
 * @par Parameter type
 *    int (boolean)
 *
 * @par Values
 *    @c 1 hold call \n
 *    @c 0 unhold call
 *
 * Corresponding tag taking reference parameter is NUTAG_HOLD_REF()
 */
#define NUTAG_HOLD(x)           nutag_hold, tag_bool_v(x)
extern tag_typedef_t nutag_hold;

#define NUTAG_HOLD_REF(x)       nutag_hold_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_hold_ref;

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
extern tag_typedef_t nutag_notify_refer;

#define NUTAG_NOTIFY_REFER_REF(x) nutag_notify_refer_ref, nutag_handle_vr(&(x))
extern tag_typedef_t nutag_notify_refer_ref;

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
extern tag_typedef_t nutag_refer_event;

#define NUTAG_REFER_EVENT_REF(x) nutag_refer_event_ref, siptag_event_vr(&(x))
extern tag_typedef_t nutag_refer_event_ref;

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
extern tag_typedef_t nutag_refer_pause;

#define NUTAG_REFER_PAUSE_REF(x) nutag_refer_pause_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_refer_pause_ref;

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
extern tag_typedef_t nutag_user_agent;

#define NUTAG_USER_AGENT_REF(x) nutag_user_agent_ref, tag_str_vr(&(x))
extern tag_typedef_t nutag_user_agent_ref;

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
extern tag_typedef_t nutag_callstate;

#define NUTAG_CALLSTATE_REF(x) nutag_callstate_ref, tag_int_vr(&(x))
extern tag_typedef_t nutag_callstate_ref;

enum nua_callstate {
  nua_callstate_init,		/**< Initial state */
  nua_callstate_calling,	/**< INVITE sent */
  nua_callstate_proceeding,	/**< 18X received */
  nua_callstate_received,	/**< INVITE received */
  nua_callstate_early,		/**< 18X sent (w/SDP) */
  nua_callstate_ready,		/**< 2XX received or sent */
  nua_callstate_terminating,	/**< BYE sent */
  nua_callstate_terminated	/**< BYE complete */
};

/** Get name for NUA call state */
char const *nua_callstate_name(enum nua_callstate state);

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
extern tag_typedef_t nutag_substate;

#define NUTAG_SUBSTATE_REF(x) nutag_substate_ref, tag_int_vr(&(x))
extern tag_typedef_t nutag_substate_ref;

enum nua_substate {
  nua_substate_embryonic = 0,
  nua_substate_pending,
  nua_substate_active,
  nua_substate_terminated
};

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
extern tag_typedef_t nutag_media_features;

#define NUTAG_MEDIA_FEATURES_REF(x) \
          nutag_media_features_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_media_features_ref;

/** Add methods and media tags to Contact headers. */
#define NUTAG_CALLEE_CAPS(x) nutag_callee_caps, tag_bool_v(x)
extern tag_typedef_t nutag_callee_caps;

#define NUTAG_CALLEE_CAPS_REF(x) \
          nutag_callee_caps_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_callee_caps_ref;

/** If true, add "path" to Supported in REGISTER.
 *
 * @sa <a href="http://www.ietf.org/rfc/rfc3327.txt">RFC 3327</a>,
 * <i>"SIP Extension Header Field for Registering Non-Adjacent Contacts"</i>,
 * D. Willis, B. Hoeneisen,
 * December 2002.
 */
#define NUTAG_PATH_ENABLE(x)   nutag_path_enable, tag_bool_v(x)
extern tag_typedef_t nutag_path_enable;

#define NUTAG_PATH_ENABLE_REF(x) nutag_path_enable_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_path_enable_ref;

/** Use route from Service-Route header in response to REGISTER.
 *
 * @sa <a href="http://www.ietf.org/rfc/rfc3327.txt">RFC 3327</a>,
 * <i>"SIP Extension Header Field for Registering Non-Adjacent Contacts"</i>,
 * D. Willis, B. Hoeneisen,
 * December 2002.
 */
#define NUTAG_SERVICE_ROUTE_ENABLE(x) nutag_service_route_enable, tag_bool_v(x)
extern tag_typedef_t nutag_service_route_enable;

#define NUTAG_SERVICE_ROUTE_ENABLE_REF(x) \
          nutag_service_route_enable_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_service_route_enable_ref;

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
extern tag_typedef_t nutag_media_enable;

#define NUTAG_MEDIA_ENABLE_REF(x) \
          nutag_media_enable_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_media_enable_ref;

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
extern tag_typedef_t nutag_offer_recv;

#define NUTAG_OFFER_RECV_REF(x) nutag_offer_recv_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_offer_recv_ref;

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
extern tag_typedef_t nutag_answer_recv;

#define NUTAG_ANSWER_RECV_REF(x) nutag_answer_recv_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_answer_recv_ref;

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
extern tag_typedef_t nutag_offer_sent;

#define NUTAG_OFFER_SENT_REF(x) nutag_offer_sent_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_offer_sent_ref;

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
extern tag_typedef_t nutag_answer_sent;

#define NUTAG_ANSWER_SENT_REF(x) nutag_answer_sent_ref, tag_bool_vr(&(x))
extern tag_typedef_t nutag_answer_sent_ref;

#if SU_HAVE_INLINE
su_inline tag_value_t nutag_handle_v(nua_handle_t *v) { return (tag_value_t)v; }
su_inline tag_value_t nutag_handle_vr(nua_handle_t **vp) {return(tag_value_t)vp;}
#else
#define nutag_handle_v(v)   (tag_value_t)(v)
#define nutag_handle_vr(v)  (tag_value_t)(v)
#endif

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

#if HAVE_SOFIA_MSS

#include <soa_mss.h>

#define NUTAG_MEDIA_PATH(x)  SOATAG_MEDIA_PROFILE((x))
#define NUTAG_MEDIA_PATH_REF(x)   SOATAG_MEDIA_PROFILE_REF((x))

#define NUTAG_MEDIA_CLONE(x)  SOATAG_MEDIA_CLONE((x))
#define NUTAG_MEDIA_CLONE_REF(x) SOATAG_MEDIA_CLONE_REF((x))

#define NUTAG_MEDIA_PARAMS(x)  SOATAG_MSS_CFG((x))
#define NUTAG_MEDIA_PARAMS_REF(x) SOATAG_MSS_CFG_REF((x))

#define NUTAG_MEDIA_DESCS(x)  SOATAG_MSS_SDP((x))
#define NUTAG_MEDIA_DESCS_REF(x) SOATAG_MSS_SDP_REF((x))

#define NUTAG_IMAGE_LOCAL(x)   SOATAG_IMAGE_LOCAL((x))
#define NUTAG_IMAGE_LOCAL_REF(x) SOATAG_IMAGE_LOCAL_REF((x))
#define NUTAG_IMAGE_REMOTE(x)  SOATAG_IMAGE_REMOTE((x))
#define NUTAG_IMAGE_REMOTE_REF(x) SOATAG_IMAGE_REMOTE_REF((x))
#define NUTAG_TARGET_IMAGE_NAME(x) SOATAG_TARGET_IMAGE_NAME((x))
#define NUTAG_TARGET_IMAGE_NAME_REF(x) SOATAG_TARGET_IMAGE_NAME_REF((x))

#define NUTAG_VIDEO_LOCAL(x)   SOATAG_VIDEO_LOCAL((x))
#define NUTAG_VIDEO_LOCAL_REF(x) SOATAG_VIDEO_LOCAL_REF((x))
#define NUTAG_VIDEO_REMOTE(x)  SOATAG_VIDEO_REMOTE((x))
#define NUTAG_VIDEO_REMOTE_REF(x) SOATAG_VIDEO_REMOTE_REF((x))

#define NUTAG_MEDIA_EVENT_PATH(x) SOATAG_MEDIA_EVENT_PATH((x))
#define NUTAG_MEDIA_EVENT_PATH_REF(x) SOATAG_MEDIA_EVENT_PATH_REF((x))
#define NUTAG_MEDIA_EVENT_DATA(x) SOATAG_MEDIA_EVENT_DATA((x))
#define NUTAG_MEDIA_EVENT_DATA_REF(x) SOATAG_MEDIA_EVENT_DATA_REF((x))
#define NUTAG_MEDIA_EVENT_DLEN(x) SOATAG_MEDIA_EVENT_DLEN((x))
#define NUTAG_MEDIA_EVENT_DLEN_REF(x) SOATAG_MEDIA_EVENT_DLEN_REF((x))

#endif

#endif
