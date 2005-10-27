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

/**@CFILE sip_reason.c
 * @brief Reason header.
 *
 * The file @b sip_reason.c contains implementation of header classes for
 * SIP header @b Reason.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Thu Sep 13 21:24:15 EEST 2001 ppessi
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

/**@SIP_HEADER sip_reason Reason Header
 *
 * The Reason header is used to indicate why a SIP request was issued or why
 * a provisional response was sent. It can be used with HRPF scenarios. It
 * is defined in @RFC3326 as follows:
 * 
 * @code
 *   Reason            =  "Reason" HCOLON reason-value *(COMMA reason-value)
 *   reason-value      =  protocol *(SEMI reason-params)
 *   protocol          =  "SIP" / "Q.850" / token
 *   reason-params     =  protocol-cause / reason-text
 *                        / reason-extension
 *   protocol-cause    =  "cause" EQUAL cause
 *   cause             =  1*DIGIT
 *   reason-text       =  "text" EQUAL quoted-string
 *   reason-extension  =  generic-param
 * @endcode
 * 
 */

static msg_xtra_f sip_reason_dup_xtra;
static msg_dup_f sip_reason_dup_one;

msg_hclass_t sip_reason_class[] = 
SIP_HEADER_CLASS(reason, "Reason", "", re_params, append, reason);

static inline void sip_reason_update(sip_reason_t *re);

int sip_reason_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_header_t **hh = &h->sh_succ, *h0 = h;
  sip_reason_t *re = h->sh_reason;

  int n;

  for (;*s;) {
    /* Ignore empty entries (comma-whitespace) */
    if (*s == ',') { 
      *s++ = '\0'; skip_lws(&s); 
      continue; 
    }

    if (!h) {      /* Allocate next header structure */
      if (!(h = sip_header_alloc(home, h0->sh_class, 0)))
	return -1;
      *hh = h; h->sh_prev = hh; hh = &h->sh_succ;
      re = re->re_next = h->sh_reason;
    }

    if ((n = span_token(s)) == 0) 
      return -1;
    re->re_protocol = s; s += n; while (IS_LWS(*s)) *s++ = '\0'; 
    if (*s == ';' && msg_params_d(home, &s, &re->re_params) < 0)
      return -1;
    if (*s != '\0' && *s != ',')
      return -1;

    if (re->re_params)
      sip_reason_update(re);

    h = NULL;
  }

  if (h)			/* Empty list -> error */
     return -1;

  return 0;
}

int sip_reason_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  char *end = b + bsiz, *b0 = b;
  sip_reason_t const *re = h->sh_reason;

  assert(sip_is_reason(h));
  SIP_STRING_E(b, end, re->re_protocol);
  SIP_PARAMS_E(b, end, re->re_params, flags);

  return b - b0;
}

int sip_reason_dup_xtra(sip_header_t const *h, int offset)
{
  sip_reason_t const *re = h->sh_reason;

  SIP_PARAMS_SIZE(offset, re->re_params);
  offset += SIP_STRING_SIZE(re->re_protocol);

  return offset;
}

/** Duplicate one sip_reason_t object */ 
char *sip_reason_dup_one(sip_header_t *dst, sip_header_t const *src,
			char *b, int xtra)
{
  sip_reason_t *re_dst = dst->sh_reason;
  sip_reason_t const *re_src = src->sh_reason;

  char *end = b + xtra;
  b = sip_params_dup(&re_dst->re_params, re_src->re_params, b, xtra);
  SIP_STRING_DUP(b, re_dst->re_protocol, re_src->re_protocol);
  if (re_dst->re_params)
    sip_reason_update(re_dst);
  assert(b <= end);

  return b;
}

/* Update shortcuts */
static inline void sip_reason_update(sip_reason_t *re)
{
  int i;

  if (re->re_params)
    for (i = 0; re->re_params[i]; i++) {
      if (strncasecmp(re->re_params[i], "cause=", strlen("cause=")) == 0)
	re->re_cause = re->re_params[i] + strlen("cause=");
      else if (strncasecmp(re->re_params[i], "text=", strlen("text=")) == 0)
	re->re_text = re->re_params[i] + strlen("text=");
    }
}
