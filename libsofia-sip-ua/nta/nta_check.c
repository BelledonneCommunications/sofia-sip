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

/**@CFILE nta.c
 * @brief Checks for features, MIME types, session timer.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Wed Mar  8 16:35:05 EET 2006 ppessi
 */

#include "config.h"

#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/nta.h>

/* ======================================================================== */
/* Request validation */

/** Check that all features UAC requires are also in supported */
int nta_check_required(nta_incoming_t *irq,
		       sip_t const *sip,
		       sip_supported_t const *supported,
		       tag_type_t tag, tag_value_t value, ...)
{
  if (sip->sip_require) {
    su_home_t home[1] = { SU_HOME_INIT(home) };
    sip_unsupported_t *us;

    us = sip_has_unsupported(home, supported, sip->sip_require);

    if (us) {
      ta_list ta;
      ta_start(ta, tag, value);
      nta_incoming_treply(irq,
			  SIP_420_BAD_EXTENSION,
			  SIPTAG_UNSUPPORTED(us),
			  SIPTAG_SUPPORTED(supported),
			  ta_tags(ta));
      ta_end(ta);
      su_home_deinit(home);
      return 420;
    }
  }
  return 0;
}

/** Check that all features we require are also supported by UAC */
int nta_check_supported(nta_incoming_t *irq,
			sip_t const *sip,
			sip_require_t *require,
			tag_type_t tag, tag_value_t value, ...)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  sip_unsupported_t *us;

  us = sip_has_unsupported(home, sip->sip_supported, require);

  if (us) {
    ta_list ta;
    ta_start(ta, tag, value);
    nta_incoming_treply(irq,
			SIP_421_EXTENSION_REQUIRED,
			SIPTAG_REQUIRE(require),
			ta_tags(ta));
    ta_end(ta);
    su_home_deinit(home);
    return 421;
  }

  return 0;
}

/** Check that we support the request method. */
int nta_check_method(nta_incoming_t *irq,
		     sip_t const *sip,
		     sip_allow_t const *allow,
		     tag_type_t tag, tag_value_t value, ...)
{
  /* Check extensions */
  char const *name = sip->sip_request->rq_method_name;
  sip_param_t const *allowed;
  int i = 0;
  int status;
  ta_list ta;

  if (allow && (allowed = allow->k_items))
    for (i = 0; allowed[i]; i++)
      if (strcasecmp(name, allowed[i]) == 0)
	return 0;

  ta_start(ta, tag, value);
  if (sip->sip_request->rq_method != sip_method_unknown)
    nta_incoming_treply(irq,
			status = SIP_405_METHOD_NOT_ALLOWED,
			SIPTAG_ALLOW(allow),
			ta_tags(ta));
  else
    nta_incoming_treply(irq,
			status = SIP_501_NOT_IMPLEMENTED,
			SIPTAG_ALLOW(allow),
			ta_tags(ta));
  ta_end(ta);

  return status;
}

static char const application_sdp[] = "application/sdp";

/* Check that we understand (session) content. */
int nta_check_session_content(nta_incoming_t *irq, 
			      sip_t const *sip,
			      sip_accept_t const *session_accepts,
			      tag_type_t tag, tag_value_t value, ...)
{
  sip_content_type_t const *c = sip->sip_content_type;
  sip_content_disposition_t const *cd = sip->sip_content_disposition;
  int acceptable_type = 0, acceptable_encoding = 0;
  ta_list ta;

  if (sip->sip_payload == NULL)
    return 0;

  if (cd == NULL || strcasecmp(cd->cd_type, "session") == 0) {
    sip_accept_t const *ab = session_accepts;
    char const *c_type;

    if (c)
      c_type = c->c_type;
    else if (sip->sip_payload->pl_len > 3 &&
	     strncasecmp(sip->sip_payload->pl_data, "v=0", 3) == 0)
      /* Missing Content-Type, but it looks like SDP  */
      c_type = application_sdp;
    else
      /* No chance */
      ab = NULL, c_type = NULL;

    for (; ab; ab = ab->ac_next) {
      if (strcasecmp(c_type, ab->ac_type) == 0)
	break;
    }

    if (ab)
      acceptable_type = 1;
  }
  else if (cd->cd_optional) 
    acceptable_type = 1;

  /* Empty or missing Content-Encoding */
  if (!sip->sip_content_encoding ||
      !sip->sip_content_encoding->k_items || 
      !sip->sip_content_encoding->k_items[0] ||
      !sip->sip_content_encoding->k_items[0][0])
    acceptable_encoding = 1;
    
  if (acceptable_type && acceptable_encoding)
    return 0;

  ta_start(ta, tag, value);
  nta_incoming_treply(irq,
		      SIP_415_UNSUPPORTED_MEDIA,
		      SIPTAG_ACCEPT(session_accepts),
		      ta_tags(ta));
  ta_end(ta);

  return 415;
}

  
/** Check that UAC accepts (application/sdp) */
int nta_check_accept(nta_incoming_t *irq,
		     sip_t const *sip,
		     sip_accept_t const *acceptable,
		     sip_accept_t const **return_acceptable,
		     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  sip_accept_t const *ac, *ab;
  sip_method_t method;

  if (!acceptable)
    return 0;

  if (sip->sip_request)
    method = sip->sip_request->rq_method;
  else /* if (sip->sip_cseq) */
    method = sip->sip_cseq->cs_method;

  /* Missing Accept header implies support for SDP in INVITE and OPTIONS
   * (and PRACK and UPDATE?) 
   */
  if (!sip->sip_accept && (method == sip_method_invite || 
			   method == sip_method_options ||
			   method == sip_method_prack ||
			   method == sip_method_update)) {
    for (ab = acceptable; ab; ab = ab->ac_next)
      if (strcasecmp(application_sdp, ab->ac_type) == 0) {
	if (return_acceptable) *return_acceptable = ab;
	return 0;
      }
  } 

  for (ac = sip->sip_accept; ac; ac = ac->ac_next) {
    if (sip_q_value(ac->ac_q) == 0 || !ac->ac_type)
      continue;

    for (ab = acceptable; ab; ab = ab->ac_next)
      if (strcasecmp(ac->ac_type, ab->ac_type) == 0) {
	if (return_acceptable) *return_acceptable = ab;
	return 0;
      }
  }

  ta_start(ta, tag, value);
  nta_incoming_treply(irq, 
		      SIP_406_NOT_ACCEPTABLE, 
		      SIPTAG_ACCEPT(acceptable),
		      ta_tags(ta));
  ta_end(ta);

  return 406;
}

/**Check Session-Expires header. 
 *
 * If the proposed session-expiration time is smaller than Min-SE or our
 * minimal session expiration time, respond with 422 containing our minimal
 * session expiration time in Min-SE header.
 */
int nta_check_session_expires(nta_incoming_t *irq,
			      sip_t const *sip,
			      sip_time_t my_min_se,
			      tag_type_t tag, tag_value_t value, ...)
{
  if ((sip->sip_min_se &&
       sip->sip_session_expires->x_delta < sip->sip_min_se->min_delta)
      || sip->sip_session_expires->x_delta < my_min_se) {
    ta_list ta;

    sip_min_se_t min_se[1];

    sip_min_se_init(min_se)->min_delta = my_min_se;

    ta_start(ta, tag, value);
    nta_incoming_treply(irq, 
			SIP_422_SESSION_TIMER_TOO_SMALL, 
			SIPTAG_MIN_SE(min_se),
			ta_tags(ta));
    ta_end(ta);
    return 422;
  }

  return 0;
}
