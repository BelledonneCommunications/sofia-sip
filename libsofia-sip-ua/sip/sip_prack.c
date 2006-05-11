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

/**@CFILE sip_prack.c
 * @brief SIP headers for Prack.
 *
 * The file @b sip_prack.c contains implementation of header classes for
 * PRACK-related SIP headers @b RAck and @b RSeq.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Thu Sep 13 21:24:15 EEST 2001 ppessi
 */

#include "config.h"

/* Avoid casting sip_t to msg_pub_t and sip_header_t to msg_header_t */
#define MSG_PUB_T       struct sip_s
#define MSG_HDR_T       union sip_header_u

#include "sofia-sip/sip_parser.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* ====================================================================== */

/**@SIP_HEADER sip_rack RAck Header
 *
 * The RAck header indicates the sequence number of the provisional response
 * which is being acknowledged.  Its syntax is defined in
 * draft-ietf-sip-100rel-04.txt section 5 as follows:
 * 
 * @code
 *    RAck          =  "RAck" ":" response-num CSeq-num Method
 *    response-num  =  1*DIGIT
 *    CSeq-num      =  1*DIGIT
 * @endcode
 *
 */

static msg_xtra_f sip_rack_dup_xtra;
static msg_dup_f sip_rack_dup_one;
#define sip_rack_update NULL

msg_hclass_t sip_rack_class[] = 
SIP_HEADER_CLASS(rack, "RAck", "", ra_common, single, rack);

int sip_rack_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_rack_t *ra = h->sh_rack;

  ra->ra_response = strtoul(s, &s, 10);

  if (IS_LWS(*s)) {
    skip_lws(&s);
    ra->ra_cseq = strtoul(s, &s, 10);

    if (IS_LWS(*s)) {
      skip_lws(&s);
      if ((ra->ra_method = sip_method_d(&s, &ra->ra_method_name)) >= 0) {
	return 0;
      }
    }
  }

  return -1;
}

int sip_rack_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  sip_rack_t const *ra = h->sh_rack;

  assert(sip_is_rack(h));

  return snprintf(b, bsiz, "%u %u %s", 
		  ra->ra_response, ra->ra_cseq, ra->ra_method_name);
}

int sip_rack_dup_xtra(sip_header_t const *h, int offset)
{
  sip_rack_t const *ra = h->sh_rack;

  if (ra->ra_method == sip_method_unknown)
    return offset + MSG_STRING_SIZE(ra->ra_method_name);
  else
    return offset;
}

/** Duplicate one sip_rack_t object */ 
char *sip_rack_dup_one(sip_header_t *dst, sip_header_t const *src,
			char *b, int xtra)
{
  sip_rack_t *ra_dst = dst->sh_rack;
  sip_rack_t const *ra_src = src->sh_rack;

  char *end = b + xtra;

  ra_dst->ra_response = ra_src->ra_response;
  ra_dst->ra_cseq     = ra_src->ra_cseq;
  ra_dst->ra_method   = ra_src->ra_method;

  if (ra_src->ra_method == sip_method_unknown)
    MSG_STRING_DUP(b, ra_dst->ra_method_name, ra_src->ra_method_name);
  else
    ra_dst->ra_method_name = ra_src->ra_method_name;

  assert(b <= end);

  return b;
}

/* ====================================================================== */

/**@SIP_HEADER sip_rseq RSeq Header
 *
 * The RSeq header identifies provisional responses within a transaction.
 * Its syntax is defined in draft-ietf-sip-100rel-04.txt section 5 as
 * follows:
 * 
 * @code
 *    RSeq          =  "RSeq" ":" response-num
 *    response-num  =  1*DIGIT
 * @endcode
 *
 */


msg_hclass_t sip_rseq_class[] = 
SIP_HEADER_CLASS(rseq, "RSeq", "", rs_common, single, any);

int sip_rseq_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return msg_numeric_d(home, h, s, slen);
}

int sip_rseq_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_is_rseq(h));
  return msg_numeric_e(b, bsiz, h, f);
}
