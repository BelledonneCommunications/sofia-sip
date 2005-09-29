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

/**@CFILE soa_tag.c  Tags and tag lists for Offer/Answer Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Aug  3 20:28:17 EEST 2005
 * $Date: 2005/09/28 20:05:24 $
 */

#include "config.h"

const char soa_tag_c_id[] =
"$Id: soa_tag.c,v 1.5 2005/09/28 20:05:24 ppessi Exp $";

#include <su.h>

#define TAG_NAMESPACE "soa"

#include <soa.h>
#include <su_tag_class.h>
#include <sdp_tag.h>

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


/**@def SOATAG_AF_REF(x)
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


/**@def SOATAG_MEDIA_PROFILE(x)
 * Name of the media template for the NUA stack.
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_MEDIA_PROFILE_REF()
*/
tag_typedef_t soatag_media_profile = STRTAG_TYPEDEF(media_profile);


/**@def SOATAG_MEDIA_SUBSYSTEM(x)
 *  Pointer to a media subsystem.
 *
 * Pointer to MSS media subsystem object. The mss object can be used to
 * customize the media with mss_config_add(), for example.
 *
 * @par Used with
 *    nua_get_param()
 *
 * @par Parameter type
 *    void * (actually mss_t*)
 *
 * @par Values
 *    Pointer to MSS media subsystem.
 *
 * Corresponding tag taking reference parameter is SOATAG_MEDIA_SUBSYSTEM_REF.
 */
tag_typedef_t soatag_media_subsystem = PTRTAG_TYPEDEF(media_subsystem);


/**@def SOATAG_MEDIA_SESSION(x)
 *  Pointer to a media session.
 *
 * Pointer to MSS media session. Used with SOATAG_MEDIA_CLONE()
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
 * Corresponding tag taking reference parameter is SOATAG_MEDIA_SESSION_REF.
 */
tag_typedef_t soatag_media_session = PTRTAG_TYPEDEF(media_session);


/**@def SOATAG_MEDIA_CLONE(x)
 *  Clone media session.
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
 *    @c 0   False \n
 *    @c !=0 True
 *
 * Corresponding tag taking reference parameter is SOATAG_MEDIA_CLONE_REF()
*/
tag_typedef_t soatag_media_clone = BOOLTAG_TYPEDEF(media_clone);


/**@def SOATAG_MSS_SDP(x)
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
 * Corresponding tag taking reference parameter is SOATAG_MSS_SDP_REF()
 */
tag_typedef_t soatag_mss_sdp = STRTAG_TYPEDEF(mss_sdp);


/**@def SOATAG_MSS_CFG(x)
 *  Media parameter file name to the NUA stack.
 *
 * Media parameter file name to the NUA stack (mss.cfg).
 * Used for debugging RTP and RTCP.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_update()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is SOATAG_MSS_CFG_REF()
 */
tag_typedef_t soatag_mss_cfg = STRTAG_TYPEDEF(mss_cfg);


/**@def SOATAG_MEDIA_EVENT_PATH(x)
 *  Media event path name
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_set_params() \n
 *    nua_get_params()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *
 * Corresponding tag taking reference parameter is
 * SOATAG_MEDIA_EVENT_PATH_REF()
 */
tag_typedef_t soatag_media_event_path = STRTAG_TYPEDEF(media_event_path);


/**@def SOATAG_MEDIA_EVENT_DATA(x)
 *  Media event data
 *
 * @par Used with
 *    nua_media_event() \n
 *    #nua_i_media_event \n
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_handle()
 *
 * @par Parameter type
 *    void *
 *
 * @par Values
 *    Free format data
 *
 * Corresponding tag taking reference parameter is
 * SOATAG_MEDIA_EVENT_DATA_REF()
 */
tag_typedef_t soatag_media_event_data = PTRTAG_TYPEDEF(media_event_data);


/**@def SOATAG_MEDIA_EVENT_DLEN(x)
 *  Media event data length
 *
 * @par Used with
 *    nua_media_event()   \n
 *    #nua_i_media_event \n
 *    nua_invite() \n
 *    nua_update() \n
 *    nua_handle()
 *
 * @par Parameter type
 *    unsigned int
 *
 * @par Values
 *    Length of media event data in octets
 *
 * Corresponding tag taking reference parameter is SOATAG_MEDIA_EVENT_DLEN_REF()
 */
tag_typedef_t soatag_media_event_dlen = INTTAG_TYPEDEF(media_event_dlen);

/**@def SOATAG_VIDEO_LOCAL(x)
 *  Local video window passed to mss_setup().
 *
 * The content of this tag is passed to media session
 * in parameters to mss_setup().
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string X window handle of
 *    drawing window. Pointer printed with printf \%p format string.
 *
 * Corresponding tag taking reference parameter is SOATAG_VIDEO_LOCAL_REF()
 */
tag_typedef_t soatag_video_local = STRTAG_TYPEDEF(video_local);

/**@def SOATAG_VIDEO_REMOTE(x)
 * Remote video window passed to mss_setup().
 *
 * The content of this tag is passed to media session
 * in parameters to mss_setup().
 *
 * @par Used with
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string
 *    X window handle of drawing window. Pointer printed with \%p
 *    format string of printf().
 *
 * Corresponding tag taking reference parameter is SOATAG_VIDEO_REMOTE_REF()
 */
tag_typedef_t soatag_video_remote = STRTAG_TYPEDEF(video_remote);

// Addition for JPIP - START
/**@def SOATAG_IMAGE_LOCAL(x)
 *  Local image window passed to mss_setup().
 *
 * The contents of tag item SOATAG_IMAGE_LOCAL() is passed to media session
 * as parameters to mss_setup().
 */
tag_typedef_t soatag_image_local = STRTAG_TYPEDEF(image_local);

/**@def SOATAG_IMAGE_REMOTE(x)
 * Remote image window passed to mss_setup().
 *
 * The contents of tag item SOATAG_IMAGE_REMOTE() is passed to media session
 * as parameters to mss_setup().
 */
tag_typedef_t soatag_image_remote = STRTAG_TYPEDEF(image_remote);

/**@def SOATAG_TARGET_IMAGE_NAME(x)
 *  Target image name used in JPIP session passed to mss_setup()
 *
 * The content of tag item SOATAG_TARGET_IMAGE_NAME() is passed to media
 * session as parameter to mss_setup().
 *
 */
tag_typedef_t soatag_target_image_name = STRTAG_TYPEDEF(target_image_name);

tag_typedef_t soatag_active_image = INTTAG_TYPEDEF(active_image);

// Addition for JPIP - END


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
tag_typedef_t soatag_hold = INTTAG_TYPEDEF(hold);
