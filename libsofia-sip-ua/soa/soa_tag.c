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

/**@CFILE soa_tag.c  Tags and tag lists for Offer/Answer Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Aug  3 20:28:17 EEST 2005
 */

#include "config.h"

#include <sofia-sip/su.h>

#define TAG_NAMESPACE "soa"

#include <sofia-sip/soa.h>
#include <sofia-sip/su_tag_class.h>
#include <sofia-sip/sdp_tag.h>

/**@def SOATAG_ANY()
 * 
 * Filter tag matching any SOATAG_*() item.
 */
tag_typedef_t soatag_any = NSTAG_TYPEDEF(*);

/**@def SOATAG_CAPS_SDP(x)
 *  Pass parsed capability description to soa session object.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_create()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_CAPS_SDP_REF()
 */
tag_typedef_t soatag_caps_sdp = SDPTAG_TYPEDEF(caps_sdp);

/**@def SOATAG_CAPS_SDP_STR(x)
 *  Pass capability description to soa session object.
 *
 * Pass name of media description file that contains media templates
 * (normally mss.sdp) to the NUA stack.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_create()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_CAPS_SDP_STR_REF()
 */
tag_typedef_t soatag_caps_sdp_str = STRTAG_TYPEDEF(caps_sdp_str);

/**@def SOATAG_LOCAL_SDP(x)
 *  Get parsed local session description from soa session object.
 *
 * @par Used with
 *    soa_set_params(), soa_get_params(), soa_get_paramlist() \n
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    pointer to #sdp_session_t.
 *
 * Corresponding tag taking reference parameter is SOATAG_LOCAL_SDP_REF()
 */
tag_typedef_t soatag_local_sdp = SDPTAG_TYPEDEF(local_sdp);

/**@def SOATAG_LOCAL_SDP_STR(x)
 * Get local session description as a string from soa session object.
 *
 * @par Used with
 * soa_set_paramas(), soa_get_params(), soa_get_paramlist().
 *
 * @par Parameter type
 * char const *
 *
 * @par Values
 * NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_LOCAL_SDP_STR_REF()
 */
tag_typedef_t soatag_local_sdp_str = STRTAG_TYPEDEF(local_sdp_str);

/**@def SOATAG_REMOTE_SDP(x)
 *  Pass parsed remote session description to soa session object.
 *
 * @par Used with
 *    soa_set_params(), soa_get_params(), soa_get_paramlist() \n
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    pointer to #sdp_session_t.
 *
 * Corresponding tag taking reference parameter is SOATAG_REMOTE_SDP_REF()
 */
tag_typedef_t soatag_remote_sdp = SDPTAG_TYPEDEF(remote_sdp);

/**@def SOATAG_REMOTE_SDP_STR(x)
 *  Pass media description file name to the NUA stack.
 *
 * Pass name of media description file that contains media templates
 * (normally mss.sdp) to the NUA stack.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_create()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_REMOTE_SDP_STR_REF()
 */
tag_typedef_t soatag_remote_sdp_str = STRTAG_TYPEDEF(remote_sdp_str);

/**@def SOATAG_USER_SDP(x)
 *  Pass parsed user session description to soa session object.
 *
 * @par Used with
 *    soa_set_params(), soa_get_params(), soa_get_paramlist() \n
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    pointer to #sdp_session_t.
 *
 * Corresponding tag taking reference parameter is SOATAG_USER_SDP_REF()
 */
tag_typedef_t soatag_user_sdp = SDPTAG_TYPEDEF(user_sdp);

/**@def SOATAG_USER_SDP_STR(x)
 *  Pass media description file name to the NUA stack.
 *
 * Pass name of media description file that contains media templates
 * (normally mss.sdp) to the NUA stack.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_create()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_USER_SDP_STR_REF()
 */
tag_typedef_t soatag_user_sdp_str = STRTAG_TYPEDEF(user_sdp_str);

/**@def SOATAG_AF(x)
 *
 * Preferred address family for media.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    @c SOATAG_AF_ANY (default) (0) any address family \n
 *    @c SOATAG_AF_IP4_ONLY      (1) only IP version 4 \n
 *    @c SOATAG_AF_IP6_ONLY      (2) only IP version 6 \n
 *    @c SOATAG_AF_IP4_IP6       (3) either IP version 4 or 6,
 *                                  version 4 preferred \n
 *    @c SOATAG_AF_IP6_IP4       (4) either IP version 4 or 6,
 *                                  version 6 preferred
 *
 * Corresponding tag taking reference parameter is SOATAG_AF_REF()
 */
tag_typedef_t soatag_af = INTTAG_TYPEDEF(af);


/**@def SOATAG_ADDRESS(x)
 *
 * Pass media address.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string containing a domain name,
 *    IPv4 address, or IPv6 address.
 *
 * Corresponding tag taking reference parameter is SOATAG_ADDRESS_REF()
*/
tag_typedef_t soatag_address = STRTAG_TYPEDEF(address);


/**@def SOATAG_RTP_SELECT(x)
 *
 * When generating answer or second offer, soa can include all the supported
 * codec, only one codec, or only the codecs supported by both ends in the
 * list of payload types on the m= line.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_respond() \n
 *
 * @par Parameter type
 *    integer in range 0..2
 *
 * @par Values
 *    0 - select the best common codec        \n
 *    1 - select all common codecs            \n
 *    2 - select all local codecs             \n
 *
 * The default value is 0, only one RTP codec is selected. Note, however,
 * that if there is no common codec (no local codec is supported by remote
 * end), all the codecs are included in the list. In that case the media
 * line is rejected, too, unless SOATAG_RTP_MISMATCH(1) has been used.
 *
 * Corresponding tag taking a reference parameter is SOATAG_RTP_SELECT_REF()
*/
tag_typedef_t soatag_rtp_select = UINTTAG_TYPEDEF(rtp_select);


/**@def SOATAG_RTP_SORT(x)
 *
 * When selecting the common codecs, soa can either select first local codec
 * supported by remote end, or first remote codec supported by local codecs. 
 * The preference is indicated with ordering: the preferred codec is
 * first and so on.

 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_respond() \n
 *
 * @par Parameter type
 *    Boolean (int)
 *
 * @par Values
 *    0 - select by local preference if media is recvonly, 
 *        remote preference othewise \n
 *    1 - always select by local preference \n
 *    2 - always select by remote preference \n
 *
 * The default value is 0.
 *
 * Corresponding tag taking reference parameter is SOATAG_RTP_SORT_REF()
*/
tag_typedef_t soatag_rtp_sort = UINTTAG_TYPEDEF(rtp_sort);


/**@def SOATAG_RTP_MISMATCH(x)
 *
 * Accept media line even if the SDP negotation code determines that there
 * are no common codecs between local and remote media. Normally, if the soa
 * determines there are no common codecs, the media line is rejected.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_respond() \n
 *
 * @par Parameter type
 *    Boolean (int)
 *
 * @par Values
 *    0 - reject media if there are no common codecs \n
 *    1 (!= 0) - accept media even if there are no common codecs \n
 *
 * Default value is 0.
 *
 * Corresponding tag taking reference parameter is SOATAG_RTP_MISMATCH_REF()
*/
tag_typedef_t soatag_rtp_mismatch = BOOLTAG_TYPEDEF(rtp_mismatch);


/**@def SOATAG_ACTIVE_AUDIO(x)
 * 
 * Audio session status
 *
 * @par Used with
 *
 * @par Parameter type
 *    enum { #SOA_ACTIVE_DISABLED, #SOA_ACTIVE_REJECTED, 
 *           #SOA_ACTIVE_INACTIVE, #SOA_ACTIVE_SENDONLY, 
 *           #SOA_ACTIVE_RECVONLY, #SOA_ACTIVE_SENDRECV }
 *
 * @par Values
 *    @c #SOA_ACTIVE_REJECTED  (-8) \n
 *    @c #SOA_ACTIVE_INACTIVE  (0) \n
 *    @c #SOA_ACTIVE_SENDONLY  (1) \n
 *    @c #SOA_ACTIVE_RECVONLY  (2) \n
 *    @c #SOA_ACTIVE_SENDRECV  (3) \n
 *
 *  Corresponding tag taking reference parameter is SOATAG_ACTIVE_AUDIO_REF()
 *
 */
tag_typedef_t soatag_active_audio = INTTAG_TYPEDEF(active_audio);

/**@def SOATAG_ACTIVE_VIDEO(x)
 * 
 * Video session status
 *
 * @par Used with
 *
 * @par Parameter type
 *    enum { #SOA_ACTIVE_DISABLED, #SOA_ACTIVE_REJECTED, 
 *           #SOA_ACTIVE_INACTIVE, #SOA_ACTIVE_SENDONLY, 
 *           #SOA_ACTIVE_RECVONLY, #SOA_ACTIVE_SENDRECV }
 *
 * @par Values
 *    @c #SOA_ACTIVE_REJECTED  (-8) \n
 *    @c #SOA_ACTIVE_INACTIVE  (0) \n
 *    @c #SOA_ACTIVE_SENDONLY  (1) \n
 *    @c #SOA_ACTIVE_RECVONLY  (2) \n
 *    @c #SOA_ACTIVE_SENDRECV  (3) \n
 *
 * Corresponding tag taking reference parameter is SOATAG_ACTIVE_VIDEO_REF()
 */
tag_typedef_t soatag_active_video = INTTAG_TYPEDEF(active_video);

/**@def SOATAG_ACTIVE_IMAGE(x)
 * 
 * Active image session status
 *
 * @par Used with
 *    #nua_i_active \n
 *    #nua_i_state \n
 *
 * @par Parameter type
 *    enum { #SOA_ACTIVE_DISABLED, #SOA_ACTIVE_REJECTED, 
 *           #SOA_ACTIVE_INACTIVE, #SOA_ACTIVE_SENDONLY, 
 *           #SOA_ACTIVE_RECVONLY, #SOA_ACTIVE_SENDRECV }
 *
 * @par Values
 *    @c #SOA_ACTIVE_REJECTED  (-8) \n
 *    @c #SOA_ACTIVE_INACTIVE  (0) \n
 *    @c #SOA_ACTIVE_SENDONLY  (1) \n
 *    @c #SOA_ACTIVE_RECVONLY  (2) \n
 *    @c #SOA_ACTIVE_SENDRECV  (3) \n
 *
 * @par Parameter type
 *    enum { #SOA_ACTIVE_DISABLED, #SOA_ACTIVE_REJECTED, 
 *           #SOA_ACTIVE_INACTIVE, #SOA_ACTIVE_SENDONLY, 
 *           #SOA_ACTIVE_RECVONLY, #SOA_ACTIVE_SENDRECV }
 *
 * @par Values
 *    @c #SOA_ACTIVE_REJECTED  (-8) \n
 *    @c #SOA_ACTIVE_INACTIVE  (0) \n
 *    @c #SOA_ACTIVE_SENDONLY  (1) \n
 *    @c #SOA_ACTIVE_RECVONLY  (2) \n
 *    @c #SOA_ACTIVE_SENDRECV  (3) \n
 *
 * Corresponding tag taking reference parameter is SOATAG_ACTIVE_IMAGE_REF()
 */
tag_typedef_t soatag_active_image = INTTAG_TYPEDEF(active_image);

/**@def SOATAG_ACTIVE_CHAT(x)
 * 
 *  Active chat session status
 *
 * @par Used with
 *
 * @par Parameter type
 *    enum { #SOA_ACTIVE_DISABLED, #SOA_ACTIVE_REJECTED, 
 *           #SOA_ACTIVE_INACTIVE, #SOA_ACTIVE_SENDONLY, 
 *           #SOA_ACTIVE_RECVONLY, #SOA_ACTIVE_SENDRECV }
 *
 * @par Values
 *    @c #SOA_ACTIVE_REJECTED  (-8) \n
 *    @c #SOA_ACTIVE_INACTIVE  (0) \n
 *    @c #SOA_ACTIVE_SENDONLY  (1) \n
 *    @c #SOA_ACTIVE_RECVONLY  (2) \n
 *    @c #SOA_ACTIVE_SENDRECV  (3) \n
 *
 * Corresponding tag taking reference parameter is SOATAG_ACTIVE_CHAT_REF()
 */
tag_typedef_t soatag_active_chat = INTTAG_TYPEDEF(active_chat);

/**@def SOATAG_SRTP_ENABLE(x)
 *  
 * Enable SRTP
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    @c 1 hold call \n
 *    @c 0 unhold call
 *
 * Corresponding tag taking reference parameter is 
 * SOATAG_SRTP_ENABLE_REF()
 */
tag_typedef_t soatag_srtp_enable = BOOLTAG_TYPEDEF(srtp_enable);

/**@def SOATAG_SRTP_CONFIDENTIALITY(x)
 *  
 * Enable SRTP confidentiality
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c 1 hold call \n
 *    @c 0 unhold call
 *
 * Corresponding tag taking reference parameter is 
 * SOATAG_SRTP_CONFIDENTIALITY_REF()
 */
tag_typedef_t soatag_srtp_confidentiality = 
  BOOLTAG_TYPEDEF(srtp_confidentiality);

/**@def SOATAG_SRTP_INTEGRITY(x)
 *  
 * Enable SRTP integrity protection
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    int
 *
 * @par Values
 *    @c !=0 enable
 *    @c 0 disable
 *
 * Corresponding tag taking reference parameter is 
 * SOATAG_SRTP_INTEGRITY_REF()
 */
tag_typedef_t soatag_srtp_integrity = BOOLTAG_TYPEDEF(srtp_integrity);

/**@def SOATAG_HOLD(x)
 *  Hold & unhold
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_update()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    @c 1 hold call \n
 *    @c 0 unhold call
 *
 * Corresponding tag taking reference parameter is SOATAG_HOLD_REF()
 */
tag_typedef_t soatag_hold = STRTAG_TYPEDEF(hold);
