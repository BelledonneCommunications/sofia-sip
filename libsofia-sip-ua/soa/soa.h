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

#ifndef SOA_H
#define SOA_H "$Id: soa.h,v 1.2 2005/08/17 14:51:22 ppessi Exp $"
/**@file soa.h  SDP Offer/Answer (RFC 3264) Interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Fri Jul 15 15:43:53 EEST 2005 ppessi
 * $Date: 2005/08/17 14:51:22 $
 */

#ifndef SU_WAIT_H
#include <su_wait.h>
#endif
#ifndef SU_TAG_H
#include <su_tag.h>
#endif

typedef struct soa_session soa_session_t;

#ifndef SOA_MAGIC_T
#define SOA_MAGIC_T void
#endif

typedef SOA_MAGIC_T soa_magic_t;

typedef int soa_callback_f(soa_magic_t *arg, soa_session_t *session);

soa_session_t *soa_create(su_root_t *, char const *name);

soa_session_t *soa_clone(soa_session_t *, su_root_t *);

void soa_destroy(soa_session_t *);

int soa_set_params(soa_session_t *ss, tag_type_t tag, tag_value_t value, ...);
int soa_get_params(soa_session_t const *ss, 
		   tag_type_t tag, tag_value_t value, ...);

tagi_t *soa_get_paramlist(soa_session_t const *ss);

int soa_error_as_sip_response(soa_session_t *soa, 
			      char const **return_phrase);

char const *soa_error_as_sip_reason(soa_session_t *soa);

int soa_parse_sdp(soa_session_t *ss, 
		  char const *sdp,
		  int len);

void soa_clear_sdp(soa_session_t *ss);

int soa_print_sdp(soa_session_t *ss, 
		  int live,
		  su_home_t *home,
		  char **sdp,
		  int *return_len);


char const * const * soa_sip_required(soa_session_t const *ss);
char const * const * soa_sip_support(soa_session_t const *ss);

int soa_remote_sip_features(soa_session_t *ss, 
			    char const * const * support,
			    char const * const * required);

char **soa_media_features(soa_session_t *ss, int live, su_home_t *home);

/* Run offer step */
int soa_offer(soa_session_t *, int always, soa_callback_f *completed); 

/* Run O/A step */
int soa_offer_answer(soa_session_t *, int always, soa_callback_f *completed); 

/* Run answer step */
int soa_answer(soa_session_t *, int always, soa_callback_f *completed); 

void soa_activate(soa_session_t *, char const *option);
void soa_terminate(soa_session_t *, char const *option);

int soa_is_complete(soa_session_t const *ss);

int soa_init_offer_answer(soa_session_t *ss);

enum {
  SOA_ACTIVE_DISABLED = -4,
  SOA_ACTIVE_INACTIVE = 0,
  SOA_ACTIVE_SENDONLY = 1,
  SOA_ACTIVE_RECVONLY = 2,
  SOA_ACTIVE_SENDRECV = SOA_ACTIVE_SENDONLY | SOA_ACTIVE_RECVONLY
};

int soa_is_audio_active(soa_session_t const *ss);
int soa_is_video_active(soa_session_t const *ss);
int soa_is_image_active(soa_session_t const *ss);
int soa_is_chat_active(soa_session_t const *ss);

int soa_is_remote_audio_active(soa_session_t const *ss);
int soa_is_remote_video_active(soa_session_t const *ss);
int soa_is_remote_image_active(soa_session_t const *ss);
int soa_is_remote_chat_active(soa_session_t const *ss);

/* SOA engine and media parameters
 * set by soa_set_params(), get by soa_get_params() 
 * or soa_get_paramlist() 
 */

#define SOATAG_AF(x)             soatag_af, tag_uint_v((x))
extern tag_typedef_t soatag_af;

#define SOATAG_AF_REF(x)         soatag_af_ref, tag_uint_vr(&(x))
extern tag_typedef_t soatag_af_ref;

enum soa_af {
  SOA_AF_ANY,
  SOA_AF_IP4_ONLY,
  SOA_AF_IP6_ONLY,
  SOA_AF_IP4_IP6,
  SOA_AF_IP6_IP4
};

#define SOA_AF_ANY      SOA_AF_ANY
#define SOA_AF_IP4_ONLY SOA_AF_IP4_ONLY
#define SOA_AF_IP6_ONLY SOA_AF_IP6_ONLY
#define SOA_AF_IP4_IP6  SOA_AF_IP4_IP6
#define SOA_AF_IP6_IP4  SOA_AF_IP6_IP4

#define SOATAG_ADDRESS(x)  soatag_address, tag_str_v(x)
extern tag_typedef_t soatag_address;
#define SOATAG_ADDRESS_REF(x) soatag_address_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_address_ref;

#define SOATAG_MEDIA_PROFILE(x)  soatag_media_profile, tag_str_v(x)
extern tag_typedef_t soatag_media_profile;
#define SOATAG_MEDIA_PROFILE_REF(x) soatag_media_profile_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_media_profile_ref;

#define SOATAG_MEDIA_CLONE(x)  soatag_media_clone, tag_bool_v(x)
extern tag_typedef_t soatag_media_clone;
#define SOATAG_MEDIA_CLONE_REF(x) soatag_media_clone_ref, tag_bool_vr(&(x))
extern tag_typedef_t soatag_media_clone_ref;

#define SOATAG_MSS_SDP(x)  soatag_mss_sdp, tag_str_v(x)
extern tag_typedef_t soatag_mss_sdp;
#define SOATAG_MSS_SDP_REF(x) soatag_mss_sdp_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_mss_sdp_ref;

#define SOATAG_MSS_CFG(x)  soatag_mss_cfg, tag_str_v(x)
extern tag_typedef_t soatag_mss_cfg;
#define SOATAG_MSS_CFG_REF(x) soatag_mss_cfg_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_mss_cfg_ref;

extern tag_typedef_t soatag_image_local;
#define SOATAG_IMAGE_LOCAL(x)   soatag_image_local, tag_str_v(x)
extern tag_typedef_t soatag_image_local_ref;
#define SOATAG_IMAGE_LOCAL_REF(x) soatag_image_local_ref, tag_str_vr(&(x))

extern tag_typedef_t soatag_image_remote;
#define SOATAG_IMAGE_REMOTE(x)  soatag_image_remote, tag_str_v(x)

extern tag_typedef_t soatag_image_remote_ref;
#define SOATAG_IMAGE_REMOTE_REF(x) soatag_image_remote_ref, tag_str_vr(&(x))

extern tag_typedef_t soatag_target_image_name;
#define SOATAG_TARGET_IMAGE_NAME(x) soatag_target_image_name, tag_str_v(x)
extern tag_typedef_t soatag_target_image_name_ref;
#define SOATAG_TARGET_IMAGE_NAME_REF(x) soatag_target_image_name_ref, tag_str_vr(&(x))

/* XXX - Active image call */
#define SOATAG_ACTIVE_IMAGE(x) soatag_active_image, tag_int_v(x)
extern tag_typedef_t soatag_active_image;

#define SOATAG_ACTIVE_IMAGE_REF(x) soatag_active_image_ref, tag_int_vr(&(x))
extern tag_typedef_t soatag_active_image_ref;

#define SOATAG_VIDEO_LOCAL(x)   soatag_video_local, tag_str_v(x)
extern tag_typedef_t soatag_video_local;

#define SOATAG_VIDEO_LOCAL_REF(x) soatag_video_local_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_video_local_ref;

#define SOATAG_VIDEO_REMOTE(x)  soatag_video_remote, tag_str_v(x)
extern tag_typedef_t soatag_video_remote;

#define SOATAG_VIDEO_REMOTE_REF(x) soatag_video_remote_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_video_remote_ref;

/** Enable SRTP */
#define SOATAG_SRTP_ENABLE(x)  soatag_srtp_enable, tag_bool_v(x)
extern tag_typedef_t soatag_srtp_enable;

#define SOATAG_SRTP_ENABLE_REF(x) soatag_srtp_enable_ref, tag_bool_vr(&(x))
extern tag_typedef_t soatag_srtp_enable_ref;

#define SOATAG_SRTP_CONFIDENTIALITY(x)  soatag_srtp_confidentiality, tag_bool_v(x)
extern tag_typedef_t soatag_srtp_confidentiality;
#define SOATAG_SRTP_CONFIDENTIALITY_REF(x) soatag_srtp_confidentiality_ref, tag_bool_vr(&(x))
extern tag_typedef_t soatag_srtp_confidentiality_ref;

/** Enable SRTP integrity protection */
#define SOATAG_SRTP_INTEGRITY(x)  soatag_srtp_integrity, tag_bool_v(x)
extern tag_typedef_t soatag_srtp_integrity;

#define SOATAG_SRTP_INTEGRITY_REF(x) \
  soatag_srtp_integrity_ref, tag_bool_vr(&(x))
extern tag_typedef_t soatag_srtp_integrity_ref;

#define SOATAG_HOLD(x)           soatag_hold, tag_uint_v(x)
extern tag_typedef_t soatag_hold;
#define SOATAG_HOLD_REF(x)       soatag_hold_ref, tag_uint_vr(&(x))
extern tag_typedef_t soatag_hold_ref;

#define SOATAG_MEDIA_EVENT_PATH(x) soatag_media_event_path, tag_str_v(x)
extern tag_typedef_t soatag_media_event_path;

#define SOATAG_MEDIA_EVENT_PATH_REF(x) \
          soatag_media_event_path_ref, tag_str_vr(&(x))
extern tag_typedef_t soatag_media_event_path_ref;

#define SOATAG_MEDIA_EVENT_DATA(x) \
          soatag_media_event_data, tag_ptr_v(x)
extern tag_typedef_t soatag_media_event_data;

#define SOATAG_MEDIA_EVENT_DATA_REF(x) \
          soatag_media_event_data_ref, tag_ptr_vr(&(x),(x))
extern tag_typedef_t soatag_media_event_data_ref;

#define SOATAG_MEDIA_EVENT_DLEN(x) soatag_media_event_dlen, tag_uint_v(x)
extern tag_typedef_t soatag_media_event_dlen;

#define SOATAG_MEDIA_EVENT_DLEN_REF(x) \
          soatag_media_event_dlen_ref, tag_uint_vr(&(x))
extern tag_typedef_t soatag_media_event_dlen_ref;

#define SOATAG_MEDIA_SUBSYSTEM(x)  soatag_media_subsystem, tag_ptr_v(x)
extern tag_typedef_t soatag_media_subsystem;
#define SOATAG_MEDIA_SUBSYSTEM_REF(x) \
 soatag_media_subsystem_ref, tag_ptr_vr(&(x),(x))
extern tag_typedef_t soatag_media_subsystem_ref;

#define SOATAG_MEDIA_SESSION(x)  soatag_media_session, tag_ptr_v(x)
extern tag_typedef_t soatag_media_session;
#define SOATAG_MEDIA_SESSION_REF(x) \
 soatag_media_session_ref, tag_ptr_vr(&(x),(x))
extern tag_typedef_t soatag_media_session_ref;

#endif
