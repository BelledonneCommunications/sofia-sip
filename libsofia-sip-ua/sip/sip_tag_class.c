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

/**@SIP_TAG
 * 
 * @CFILE sip_tag_class.c  SIP Tag classes
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Fri Feb 23 12:46:42 2001 ppessi
 */

#include "config.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <su.h>

#include "sip_parser.h"

#include <su_tag_class.h>
#include <su_tag_inline.h>
#include <sip_tag_class.h>
#include <sip_tag.h>
#include <su_tagarg.h>

/** Tag class for SIP header tags. @HIDE */
tag_class_t siphdrtag_class[1] = 
  {{
    sizeof(siphdrtag_class),
    /* tc_next */     NULL,
    /* tc_len */      NULL,
    /* tc_move */     NULL,
    /* tc_xtra */     msghdrtag_xtra,
    /* tc_dup */      msghdrtag_dup,
    /* tc_free */     NULL,
    /* tc_find */     NULL,
    /* tc_snprintf */ msghdrtag_snprintf,
    /* tc_filter */   siptag_filter,
    /* tc_ref_set */  t_ptr_ref_set,
    /* tc_scan */     msghdrtag_scan,
  }};

/** Tag class for SIP header string tags. @HIDE */
tag_class_t sipstrtag_class[1] = 
  {{
    sizeof(sipstrtag_class),
    /* tc_next */     NULL,
    /* tc_len */      NULL,
    /* tc_move */     NULL,
    /* tc_xtra */     t_str_xtra,
    /* tc_dup */      t_str_dup,
    /* tc_free */     NULL,
    /* tc_find */     NULL,
    /* tc_snprintf */ t_str_snprintf,
    /* tc_filter */   NULL /* msgtag_str_filter */,
    /* tc_ref_set */  t_ptr_ref_set,
  }};

/** Tag class for SIP message tags. @HIDE */
tag_class_t sipmsgtag_class[1] = 
  {{
    sizeof(sipmsgtag_class),
    /* tc_next */     NULL,
    /* tc_len */      NULL,
    /* tc_move */     NULL,
    /* tc_xtra */     msgobjtag_xtra,
    /* tc_dup */      msgobjtag_dup,
    /* tc_free */     NULL,
    /* tc_find */     NULL,
    /* tc_snprintf */ msgobjtag_snprintf,
    /* tc_filter */   NULL /* siptag_sip_filter */,
    /* tc_ref_set */  t_ptr_ref_set,
  }};

/** Filter a SIP header structure. */
tagi_t *siptag_filter(tagi_t *dst,
		      tagi_t const f[],
		      tagi_t const *src, 
		      void **bb)
{
  tagi_t stub[2] = {{ NULL }};
  tag_type_t sctt, tt = f->t_tag;
  msg_hclass_t *hc = (msg_hclass_t *)tt->tt_magic;

  assert(src);

  sctt = src->t_tag;

  if (sctt && sctt->tt_class == sipmsgtag_class) {
    sip_t const *sip = (sip_t const *)src->t_value;
    sip_header_t const **hh = (sip_header_t const **)
      msg_hclass_offset((msg_mclass_t *)sip->sip_common->h_class, 
			(sip_t *)sip, hc);
    sip_header_t const *h;

    if (sip == NULL || 
	hh >= (sip_header_t const **)((char *)sip + sip->sip_size) ||
	hh < (sip_header_t const **)&sip->sip_request)
      return dst;

    h = *hh;

    if (h == NULL)
      return dst;

    stub[0].t_tag = tt;
    stub[0].t_value = (long)h;
    src = stub; sctt = tt;
  }

  if (tt != sctt)
    return dst;

  if (!src->t_value)
    return dst;
  else if (dst) {
    return t_dup(dst, src, bb);
  }
  else {
    *bb = (char *)*bb + t_xtra(src, (size_t)*bb);
    return dst + 1;
  }
}

/** Add duplicates of headers from taglist to the SIP message. */
int sip_add_tl(msg_t *msg, sip_t *sip,
	       tag_type_t tag, tag_value_t value, ...)
{
  tagi_t const *t;
  ta_list ta;

  ta_start(ta, tag, value);

  for (t = ta_args(ta); t; t = tl_next(t)) {
    if (!(tag = t->t_tag) || !(value = t->t_value))
      continue;

    if (SIPTAG_P(tag)) {
      msg_hclass_t *hc = (msg_hclass_t *)tag->tt_magic;
      sip_header_t *h = (sip_header_t *)value, **hh;

      if (h == SIP_NONE) {	/* Remove header */
	hh = msg_hclass_offset(msg_mclass(msg), sip, hc);
	while (*hh)
	  msg_header_remove(msg, sip, *hh);
	continue;
      } 

      if (tag == siptag_header)
	hc = h->sh_class;

      if (sip_add_dup_as(msg, sip, hc, h) < 0)
	break;
    }
    else if (SIPTAG_STR_P(tag)) {
      msg_hclass_t *hc = (msg_hclass_t *)tag->tt_magic;
      char const *s = (char const *)value;
      if (s && msg_header_add_make(msg, sip, hc, s) < 0)
	break;
    }
    else if (tag == siptag_header_str) {
      if (msg_header_add_str(msg, sip, (char const *)value) < 0)
	break;
    }
  }

  ta_end(ta);

  return t ? -1 : 0;
}
