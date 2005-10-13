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

/**@CFILE sip_session.c
 * @brief Session Timer SIP headers.
 *
 * The file @b sip_session.c contains implementation of header classes for
 * session-timer-related SIP headers @b Session-Expires and @b Min-SE.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Thu Sep 13 21:24:15 EEST 2001 ppessi
 * @date Last modified: Wed Jul 20 20:35:43 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#include <su_alloc.h>

#include "sip_parser.h"
#include <msg_date.h>

/* ====================================================================== */

/**@SIP_HEADER sip_session_expires Session-Expires Header
 *
 * The Session-Expires header is used to convey the lifetime of the session. 
 * Its syntax is defined in [SES 4] (draft-ietf-sip-session-timer-08.txt) as
 * follows:
 * 
 * @code
 *      Session-Expires  =  ("Session-Expires" | "x") ":" delta-seconds
 *                           [refresher]
 *      refresher        =  ";" "refresher" "=" "uas"|"uac"
 * @endcode
 * 
 * The sip_session_expires_t is defined as follows:
 * @code
 * typedef struct sip_session_expires_s
 * {
 *  sip_common_t    x_common[1];
 *  sip_unknown_t  *x_next;
 *  unsigned long   x_delta; //Delta Seconds
 *  sip_param_t    *x_params; 
 *  char const     *x_refresher; //Who will send the refresh UAS or UAC
 * } sip_session_expires_t;
 * @endcode
 */

static msg_xtra_f sip_session_expires_dup_xtra;
static msg_dup_f sip_session_expires_dup_one;

msg_hclass_t sip_session_expires_class[] =
SIP_HEADER_CLASS(session_expires, "Session-Expires", "x", x_params, single, 
		 session_expires);

int sip_session_expires_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_session_expires_t *x = h->sh_session_expires;

  if (msg_delta_d((char const **) &s, &x->x_delta) < 0)
    return -1;
  if (*s == ';') {
    if (msg_params_d(home, &s, &x->x_params) < 0 || *s)
      return -1;
     x->x_refresher = sip_params_find(x->x_params, "refresher");
  }
  return 0;
}

int sip_session_expires_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  char *end = b + bsiz, *b0 = b;
  int n = 0;
  sip_session_expires_t const *o = h->sh_session_expires;

  assert(sip_is_session_expires(h));
  n = snprintf(b, bsiz, "%lu", o->x_delta);
  b += n; 
  SIP_PARAMS_E(b, end, o->x_params, flags);

  return b - b0;
}

int sip_session_expires_dup_xtra(sip_header_t const *h, int offset)
{
  sip_session_expires_t const *o = h->sh_session_expires;

  SIP_PARAMS_SIZE(offset, o->x_params);
   
  return offset;
}

/** Duplicate one sip_session_expires_t object */ 
char *sip_session_expires_dup_one(sip_header_t *dst, sip_header_t const *src,
			char *b, int xtra)
{
  sip_session_expires_t *o_dst = dst->sh_session_expires;
  sip_session_expires_t const *o_src = src->sh_session_expires;

  char *end = b + xtra;
  b = sip_params_dup(&o_dst->x_params, o_src->x_params, b, xtra);
  o_dst->x_refresher = sip_params_find(o_dst->x_params, "refresher");
  o_dst->x_delta = o_src->x_delta;
  assert(b <= end);

  return b;
}


/**@SIP_HEADER sip_min_se Min-SE Header
 *
 * The Min-SE header is used to indicate the minimum value for the session
 * interval. Its syntax is defined in [session-timer-08]
 * (draft-ietf-sip-session-timer-08.txt) as follows:
 * 
 * @code
 *      Min-SE  =  "Min-SE" ":" delta-seconds
 * @endcode
 * 
 * The sip_min_se_t is defined as follows:
 * @code
 * typedef struct sip_min_se_s
 * {
 *  sip_common_t    min_common[1];
 *  sip_unknown_t  *min_next;
 *  unsigned long   min_delta; //Delta Seconds
 * } sip_min_se_t;
 * @endcode
 */

static msg_xtra_f sip_min_se_dup_xtra;
static msg_dup_f sip_min_se_dup_one;

msg_hclass_t sip_min_se_class[] =
SIP_HEADER_CLASS(min_se, "Min-SE", "", min_common, single, min_se);

int sip_min_se_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_min_se_t *min = h->sh_min_se;

  if (msg_delta_d((char const **) &s, &min->min_delta) < 0)
    return -1;

  return 0;
}

int sip_min_se_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  sip_min_se_t const *o = h->sh_min_se;

  assert(sip_is_min_se(h));

  return snprintf(b, bsiz, "%lu", o->min_delta);
}

int sip_min_se_dup_xtra(sip_header_t const *h, int offset)
{
  return offset;
}

/** Duplicate one sip_min_se_t object */ 
char *sip_min_se_dup_one(sip_header_t *dst, sip_header_t const *src,
			char *b, int xtra)
{
  sip_min_se_t *o_dst = dst->sh_min_se;
  sip_min_se_t const *o_src = src->sh_min_se;

  char *end = b + xtra;
  o_dst->min_delta = o_src->min_delta;
  assert(b <= end);

  return b;
}
