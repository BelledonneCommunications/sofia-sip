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

/**@CFILE sip_refer.c
 * @brief SIP REFER-related headers.
 *
 * The file @b sip_refer.c contains implementation of header classes for
 * REFER-related SIP headers @b Refer-To and @b Referred-By.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Jan 23 13:23:45 EET 2002 ppessi
 * @date Last modified: Wed Jul 20 20:35:42 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#include "sip_parser.h"

/* ====================================================================== */

/**@SIP_HEADER sip_refer_to Refer-To Header
 *
 * The Refer-To header provides a URI to reference. Its syntax is defined in
 * RFC 3515 section 2.1 as follows:
 *
 * @code
 *  Refer-To = ("Refer-To" / "r") HCOLON ( name-addr / addr-spec )
 *            *(SEMI generic-param)
 * @endcode
 *
 */

/**@ingroup sip_refer_to
 *
 * @typedef typedef struct sip_refer_to_s sip_refer_to_t;
 *
 * The structure sip_refer_to_t contains representation of @b Refer-To
 * header.
 *
 * The sip_refer_to_t is defined as follows:
 * @code
 * typedef struct sip_refer_to_s
 * {
 *   sip_common_t        r_common[1];   // Common fragment info
 *   sip_error_t        *r_next;	// Link to next (dummy)
 *   char const          r_display;     // Display name
 *   url_t               r_url[1];	// URI to reference
 *   sip_param_t const  *r_params;      // List of genric parameters
 * } sip_refer_to_t;
 * @endcode
 */

static msg_xtra_f sip_refer_to_dup_xtra;
static msg_dup_f sip_refer_to_dup_one;

msg_hclass_t sip_refer_to_class[] =
SIP_HEADER_CLASS(refer_to, "Refer-To", "r", r_params, single, refer_to);

int sip_refer_to_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_refer_to_t *r = h->sh_refer_to;

  return msg_name_addr_d(home, &s,
			 &r->r_display,
			 r->r_url,
			 &r->r_params,
			 NULL);
}

int sip_refer_to_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  sip_refer_to_t const *r = h->sh_refer_to;

  assert(sip_is_refer_to(h));

  return msg_name_addr_e(b, bsiz, flags,
			 r->r_display, MSG_IS_CANONIC(flags),
			 r->r_url,
			 r->r_params,
			 NULL);
}

int sip_refer_to_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_refer_to_t const *r = h->sh_refer_to;

  SIP_PARAMS_SIZE(rv, r->r_params);
  rv += SIP_STRING_SIZE(r->r_display);
  rv += url_xtra(r->r_url);

  return rv;
}

/** Duplicate one sip_refer_to_t object */
char *sip_refer_to_dup_one(sip_header_t *dst, sip_header_t const *src,
			   char *b, int xtra)
{
  sip_refer_to_t *r_dst = dst->sh_refer_to;
  sip_refer_to_t const *r_src = src->sh_refer_to;

  char *end = b + xtra;

  b = sip_params_dup(&r_dst->r_params, r_src->r_params, b, xtra);
  SIP_STRING_DUP(b, r_dst->r_display, r_src->r_display);
  URL_DUP(b, end, r_dst->r_url, r_src->r_url);

  assert(b <= end);

  return b;
}

/* ====================================================================== */

/**@SIP_HEADER sip_referred_by Referred-By Header
 *
 * The Referred-By header conveys the identity of the original referrer to
 * the referred-to party. Its syntax is defined in
 * draft-ietf-sip-referredby-03 section 3 as follows:
 *
 * @code
 *    Referred-By  =  ("Referred-By" / "b") HCOLON referrer-uri
 *                   *( SEMI (referredby-id-param / generic-param) )
 *
 *    referrer-uri = ( name-addr / addr-spec )
 *
 *    referredby-id-param = "cid" EQUAL sip-clean-msg-id
 *
 *    sip-clean-msg-id = LDQUOT dot-atom "@" (dot-atom / host) RDQUOT
 *
 *    dot-atom = atom *( "." atom )
 *
 *    atom     = 1*( alphanum / "-" / "!" / "%" / "*" /
 *                        "_" / "+" / "'" / "`" / "~"   )
 * @endcode
 *
 */

/**@ingroup sip_referred_by
 *
 * @typedef typedef struct sip_referred_by_s sip_referred_by_t;
 *
 * The structure sip_referred_by_t contains representation of @b Referred-By
 * header.
 *
 * The sip_referred_by_t is defined as follows:
 * @code
 * typedef struct sip_referred_by_s
 * {
 *   sip_common_t        b_common[1];   // Common fragment info
 *   sip_error_t        *b_next;	// Link to next (dummy)
 *   char const          b_display,
 *   url_t               b_url[1];	// Referrer-URI
 *   sip_param_t const  *b_params;      // List of parameters
 *   sip_param_t         b_cid;
 * } sip_referred_by_t;
 * @endcode
 */

static msg_xtra_f sip_referred_by_dup_xtra;
static msg_dup_f sip_referred_by_dup_one;

msg_hclass_t sip_referred_by_class[] =
SIP_HEADER_CLASS(referred_by, "Referred-By", "b", b_params, single,
		 referred_by);

int sip_referred_by_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_referred_by_t *b = h->sh_referred_by;

  if (msg_name_addr_d(home, &s,
		      &b->b_display,
		      b->b_url,
		      &b->b_params,
		      NULL) < 0)
    return -1;

  b->b_cid = msg_params_find(b->b_params, "cid=");

  return 0;
}

int sip_referred_by_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  assert(sip_is_referred_by(h));

  return msg_name_addr_e(b, bsiz, flags,
			 h->sh_referred_by->b_display,
			 MSG_IS_CANONIC(flags), h->sh_referred_by->b_url,
			 h->sh_referred_by->b_params,
			 NULL);
}

int sip_referred_by_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_referred_by_t const *b = h->sh_referred_by;

  SIP_PARAMS_SIZE(rv, b->b_params);
  rv += SIP_STRING_SIZE(b->b_display);
  rv += url_xtra(b->b_url);

  return rv;
}

char *sip_referred_by_dup_one(sip_header_t *dst, sip_header_t const *src,
			      char *b,
			      int xtra)
{
  sip_referred_by_t *nb = dst->sh_referred_by;
  sip_referred_by_t const *o = src->sh_referred_by;
  char *end = b + xtra;

  b = sip_params_dup(&nb->b_params, o->b_params, b, xtra);
  SIP_STRING_DUP(b, nb->b_display, o->b_display);
  URL_DUP(b, end, nb->b_url, o->b_url);

  nb->b_cid = msg_params_find(nb->b_params, "cid=");

  assert(b <= end);

  return b;
}

/* ====================================================================== */

/**@SIP_HEADER sip_replaces Replaces Header
 *
 * The Replaces header indicates that a single dialog identified by the
 * header field is to be shut down and logically replaced by the incoming
 * INVITE in which it is contained. Its syntax is defined in
 * draft-ietf-sip-replaces-04 section 6.1 as follows:
 *
 * @code
 *    Replaces        = "Replaces" HCOLON callid *(SEMI replaces-param)
 *    replaces-param  = to-tag / from-tag / early-flag / generic-param
 *    to-tag          = "to-tag" EQUAL token
 *    from-tag        = "from-tag" EQUAL token
 *    early-flag      = "early-only"
 * @endcode
 *
 */

/**@ingroup sip_replaces
 *
 * @typedef typedef struct sip_replaces_s sip_replaces_t;
 *
 * The structure sip_replaces_t contains representation of @b Replaces
 * header.
 *
 * The sip_replaces_t is defined as follows:
 * @code
 * typedef struct sip_replaces_s
 * {
 *   sip_common_t        rp_common[1];   // Common fragment info
 *   sip_error_t        *rp_next;	 // Link to next (dummy)
 *   char const         *rp_call_id;     // Call-ID
 *   sip_param_t const  *rp_params;      // List of parameters
 *   sip_param_t         rp_to_tag;      // to-tag parameter
 *   sip_param_t         rp_from_tag;    // from-tag parameter
 *   int                 rp_early_only;  // early-only parameter
 * } sip_replaces_t;
 * @endcode
 */

static msg_xtra_f sip_replaces_dup_xtra;
static msg_dup_f sip_replaces_dup_one;
inline static void sip_replaces_param_update(sip_replaces_t *rp);

msg_hclass_t sip_replaces_class[] =
SIP_HEADER_CLASS(replaces, "Replaces", "", rp_params, single, replaces);

/** Decode (parse) Replaces header */
int sip_replaces_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_replaces_t *rp = h->sh_replaces;

  rp->rp_call_id = sip_word_at_word_d(&s);
  if (!rp->rp_call_id)
    return -1;
  if (*s) {
    if (msg_params_d(home, &s, &rp->rp_params) == -1)
      return -1;
    sip_replaces_param_update(rp);
  }

  return s - rp->rp_call_id;
}

/** Encode (print) Replaces header */
int sip_replaces_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  char *b0 = b, *end = b + bsiz;
  sip_replaces_t const *rp = h->sh_replaces;

  assert(sip_is_replaces(h));
  MSG_STRING_E(b, end, rp->rp_call_id);
  MSG_PARAMS_E(b, end, rp->rp_params, flags);
  MSG_TERM_E(b, end);

  return b - b0;
}

/** Calculate extra storage used by Replaces header field */
int sip_replaces_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_replaces_t const *rp = h->sh_replaces;

  MSG_PARAMS_SIZE(rv, rp->rp_params);
  rv += MSG_STRING_SIZE(rp->rp_call_id);

  return rv;
}

/** Duplicate a Replaces header field */
char *sip_replaces_dup_one(sip_header_t *dst, sip_header_t const *src,
			   char *b, int xtra)
{
  sip_replaces_t *rp_dst = dst->sh_replaces;
  sip_replaces_t const *rp_src = src->sh_replaces;

  char *end = b + xtra;

  b = sip_params_dup(&rp_dst->rp_params, rp_src->rp_params, b, xtra);
  SIP_STRING_DUP(b, rp_dst->rp_call_id, rp_src->rp_call_id);

  assert(b <= end);

  sip_replaces_param_update(rp_dst);

  return b;
}


/**Update replaces parameters.
 *
 * The function sip_replaces_param_update() updates a @b Replaces parameter. 
 * Note that the parameter string may not contain space around @c =.
 *
 * @param rp pointer to a @c sip_replaces_t object
 */
inline static 
void sip_replaces_param_update(sip_replaces_t *rp)
{
  int i;

  rp->rp_from_tag = NULL, rp->rp_to_tag = NULL, rp->rp_early_only = 0;

  if (!rp->rp_params)
    return;

  for (i = 0; rp->rp_params[i]; i++) {
    sip_param_t p = rp->rp_params[i];
    switch (p[0]) {
    case 'e':
      SIP_PARAM_MATCH_P(rp->rp_early_only, p, "early-only");
      break;
    case 'f':
      SIP_PARAM_MATCH(rp->rp_from_tag, p, "from-tag");
      break;
    case 't':
      SIP_PARAM_MATCH(rp->rp_to_tag, p, "to-tag");
      break;
    }
  }
}

