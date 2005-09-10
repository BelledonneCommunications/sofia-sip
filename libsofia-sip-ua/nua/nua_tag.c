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

/**@CFILE nua_tag.c  Tags and tag lists for NUA
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Feb 21 10:13:29 2001 ppessi
 * $Date: 2005/09/09 10:56:31 $
 */

#include "config.h"

const char _nua_tag_c_id[] =
"$Id: nua_tag.c,v 1.4 2005/09/09 10:56:31 ppessi Exp $";

#define TAG_NAMESPACE "nua"

#include <string.h>
#include <su.h>
#include <nua_tag.h>
#include <msg_header.h>
#include <su_tag_class.h>
#include <url_tag_class.h>
#include <sip_tag_class.h>
#include <sip_hclasses.h>

const char _nua_tag_h_id[] = NUA_TAG_H;

tag_typedef_t nutag_url = URLTAG_TYPEDEF(url);
tag_typedef_t nutag_address = STRTAG_TYPEDEF(address);
tag_typedef_t nutag_uicc = STRTAG_TYPEDEF(uicc);
tag_typedef_t nutag_af = INTTAG_TYPEDEF(af);
tag_typedef_t nutag_media_features = BOOLTAG_TYPEDEF(media_features);
tag_typedef_t nutag_callee_caps = BOOLTAG_TYPEDEF(callee_caps);
tag_typedef_t nutag_early_media = BOOLTAG_TYPEDEF(early_media);
tag_typedef_t nutag_media_enable = BOOLTAG_TYPEDEF(media_enable);
tag_typedef_t nutag_media_address = STRTAG_TYPEDEF(media_address);

tag_typedef_t nutag_soa_session = PTRTAG_TYPEDEF(soa_session);

tag_typedef_t nutag_media_subsystem = PTRTAG_TYPEDEF(media_session);
tag_typedef_t nutag_media_session = PTRTAG_TYPEDEF(media_session);

tag_typedef_t nutag_media_clone = BOOLTAG_TYPEDEF(media_clone);
tag_typedef_t nutag_media_path = STRTAG_TYPEDEF(media_path);
tag_typedef_t nutag_media_params = STRTAG_TYPEDEF(media_params);
tag_typedef_t nutag_media_descs = STRTAG_TYPEDEF(media_descs);
tag_typedef_t nutag_media_event_path = STRTAG_TYPEDEF(media_event_path);
tag_typedef_t nutag_media_event_data = PTRTAG_TYPEDEF(media_event_data);
tag_typedef_t nutag_media_event_dlen = INTTAG_TYPEDEF(media_event_dlen);
tag_typedef_t nutag_video_local = STRTAG_TYPEDEF(video_local);
tag_typedef_t nutag_video_remote = STRTAG_TYPEDEF(video_remote);
// Addition for JPIP - START
tag_typedef_t nutag_image_local = STRTAG_TYPEDEF(image_local);
tag_typedef_t nutag_image_remote = STRTAG_TYPEDEF(image_remote);
tag_typedef_t nutag_target_image_name = STRTAG_TYPEDEF(target_image_name);
tag_typedef_t nutag_active_image = INTTAG_TYPEDEF(active_image);
// Addition for JPIP - END
tag_typedef_t nutag_active_audio = INTTAG_TYPEDEF(active_audio);
tag_typedef_t nutag_active_video = INTTAG_TYPEDEF(active_video);
tag_typedef_t nutag_active_chat = INTTAG_TYPEDEF(active_chat);
tag_typedef_t nutag_substate = INTTAG_TYPEDEF(substate);
tag_typedef_t nutag_invite_timer = INTTAG_TYPEDEF(invite_timer);
tag_typedef_t nutag_session_timer = INTTAG_TYPEDEF(session_timer);
tag_typedef_t nutag_min_se = INTTAG_TYPEDEF(min_se);
tag_typedef_t nutag_session_refresher = INTTAG_TYPEDEF(session_refresher);
tag_typedef_t nutag_update_refresh = BOOLTAG_TYPEDEF(update_refresh);
tag_typedef_t nutag_autoAlert = BOOLTAG_TYPEDEF(autoAlert);
tag_typedef_t nutag_autoAnswer = BOOLTAG_TYPEDEF(autoAnswer);
tag_typedef_t nutag_autoACK = BOOLTAG_TYPEDEF(autoACK);
tag_typedef_t nutag_enableInvite = BOOLTAG_TYPEDEF(enableInvite);
tag_typedef_t nutag_enableMessage = BOOLTAG_TYPEDEF(enableMessage);
tag_typedef_t nutag_enableMessenger = BOOLTAG_TYPEDEF(enableMessenger);

/* Start NRC Boston */
tag_typedef_t nutag_smime_enable = BOOLTAG_TYPEDEF(smime_enable);
tag_typedef_t nutag_smime_opt = INTTAG_TYPEDEF(smime_opt);
tag_typedef_t nutag_smime_protection_mode = 
  INTTAG_TYPEDEF(smime_protection_mode);
tag_typedef_t nutag_smime_message_digest = 
  STRTAG_TYPEDEF(smime_message_digest);
tag_typedef_t nutag_smime_signature = 
  STRTAG_TYPEDEF(smime_signature);
tag_typedef_t nutag_smime_key_encryption = 
  STRTAG_TYPEDEF(smime_key_encryption);
tag_typedef_t nutag_smime_message_encryption = 
  STRTAG_TYPEDEF(smime_message_encryption);
/* End NRC Boston */

tag_typedef_t nutag_srtp_enable = BOOLTAG_TYPEDEF(srtp_enable);
tag_typedef_t nutag_srtp_confidentiality = 
  BOOLTAG_TYPEDEF(srtp_confidentiality);
tag_typedef_t nutag_srtp_integrity_protection = 
  BOOLTAG_TYPEDEF(srtp_integrity_protection);

tag_typedef_t nutag_sips_url = URLTAG_TYPEDEF(sips_url);
tag_typedef_t nutag_certificate_dir = STRTAG_TYPEDEF(certificate_dir);
tag_typedef_t nutag_certificate_phrase = STRTAG_TYPEDEF(certificate_phrase);

tag_typedef_t nutag_registrar = URLTAG_TYPEDEF(registrar);
tag_typedef_t nutag_allow = STRTAG_TYPEDEF(allow);
tag_typedef_t nutag_sip_parser = PTRTAG_TYPEDEF(sip_parser);

tag_typedef_t nutag_use_leg = BOOLTAG_TYPEDEF(use_leg);
tag_typedef_t nutag_use_session = BOOLTAG_TYPEDEF(use_session);

tag_typedef_t nutag_auth = STRTAG_TYPEDEF(auth);
tag_typedef_t nutag_authtime = INTTAG_TYPEDEF(authtime);

tag_typedef_t nutag_event = INTTAG_TYPEDEF(event);
tag_typedef_t nutag_status = INTTAG_TYPEDEF(status);
tag_typedef_t nutag_phrase = STRTAG_TYPEDEF(phrase);

tag_typedef_t nutag_handle = PTRTAG_TYPEDEF(handle);

tag_typedef_t nutag_hold = BOOLTAG_TYPEDEF(hold);

tag_typedef_t nutag_notify_refer = PTRTAG_TYPEDEF(notify_refer);
tag_typedef_t nutag_refer_event = SIPHDRTAG_NAMED_TYPEDEF(refer_event, event);
tag_typedef_t nutag_refer_pause = BOOLTAG_TYPEDEF(refer_pause);
tag_typedef_t nutag_user_agent = STRTAG_TYPEDEF(user_agent);
tag_typedef_t nutag_path_enable = BOOLTAG_TYPEDEF(path_enable);
tag_typedef_t nutag_service_route_enable = 
  BOOLTAG_TYPEDEF(service_route_enable);

tag_typedef_t _nutag_add_contact = BOOLTAG_TYPEDEF(add_contact);
tag_typedef_t _nutag_copy = BOOLTAG_TYPEDEF(copy);
