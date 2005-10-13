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

/**@CFILE sip_rfc2543.c
 * @brief Deprecated SIP headers
 * 
 * This file contains implementation of @b Also, @b Hide, @b Encryption, and
 * @b Response-Key headers.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 * 
 * @date Created: Fri May 27 18:34:52 EEST 2005 ppessi
 * @date Last modified: Wed Jul 20 20:35:42 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <stdio.h>

#include "sip_parser.h"
#include "sip_rfc2543.h"

/* ====================================================================== */

/**@SIP_HEADER sip_also Also Header
 * 
 * The Also header is used only in BYE requests. It indicates to the
 * receiving UA that it should initiate an INVITE request to the addresses
 * indicated. Its syntax is defined in [RFC2543 Section 6.11] as follows:
 * 
 * @code
 *    Also  =  "Also" ":" 1# (( name-addr | addr-spec )
 * @endcode
 * 
 * @deprecated Use REFER instead
 */

msg_hclass_t sip_also_class[] = 
SIP_HEADER_CLASS(also, "Also", "", also_common, append, also);

int sip_also_d(su_home_t *home,
	       sip_header_t *h,
	       char *s,
	       int slen)
{
  sip_header_t **hh = &h->sh_succ, *h0 = h;
  sip_also_t *also = h->sh_also;

  assert(h);

  while (*s) {
    /* Ignore empty entries (comma-whitespace) */
    if (*s == ',') { s++, skip_lws(&s); continue; }

    if (!h) { /* Allocate next header structure */
      if (!(h = sip_header_alloc(home, h0->sh_class, 0)))
	break;
      *hh = h; h->sh_prev = hh; hh = &h->sh_succ;
      also = also->also_next = h->sh_also;
    }

    if (sip_name_addr_d(home, &s,
			&also->also_display,
			also->also_url,
			NULL,
			NULL) < 0 ||
	(*s != '\0' && *s != ','))
      goto error;

    h = NULL;
  }

  if (h == 0)		/* Empty list is an error */
    return 0;

 error:
  return -1;
}

/** Encode a sip_also_e() function */
int sip_also_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  return sip_name_addr_e(b, bsiz, flags,
			 h->sh_also->also_display,
			 MSG_IS_CANONIC(flags), h->sh_also->also_url,
			 NULL,
			 NULL);
}

/**Extra dup size of sip_also_t object.
 * 
 * This function calculates extra size required when duplicating also
 * sip_also_t object.
 * 
 * @param also pointer to also sip_also_t object
 * 
 * @return
 *   Size of strings related to sip_also_t object.
 */
int sip_also_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_also_t const *also = h->sh_also;

  rv += SIP_STRING_SIZE(also->also_display);
  rv += url_xtra(also->also_url);

  return rv;
}

/**@internal
 * Duplicate one sip_also_t object.
 */
char *sip_also_dup_one(msg_header_t *dst, msg_header_t const *src,
		       char *b, int xtra)
{
  sip_also_t *also = dst->sh_also;
  sip_also_t const *o = src->sh_also;
  char *end = b + xtra;

  SIP_STRING_DUP(b, also->also_display, o->also_display);
  URL_DUP(b, end, also->also_url, o->also_url);

  assert(b <= end);

  return b;
}

/* ====================================================================== */

/**@SIP_HEADER sip_hide Hide header
 * 
 * A client uses the Hide request header field to indicate that it wants the
 * path comprised of the Via header fields (Section 6.40) to be hidden from
 * subsequent proxies and user agents.  Its syntax is defined in [S6.22]
 * (RFC2543) as follows:
 * 
 * @code
 *    Hide  =  "Hide" ":" ( "route" | "hop" )
 * @endcode
 * 
 * @deprecated Hide is useless
 */

msg_hclass_t sip_hide_class[] = 
SIP_HEADER_CLASS_G(hide, "Hide", "", single);
SIP_HEADER_DUP(hide);
SIP_HEADER_COPY(hide);

int sip_hide_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_generic_d(home, h, s, slen);
}

int sip_hide_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_hide_p(h));
  return sip_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_encryption Encryption Header
 *
 * The Encryption header specifies that the content has been encrypted.  Its
 * syntax is defined in [S10.22, S19] as follows:
 *
 * @code
 *    Encryption         =  "Encryption" ":" encryption-scheme 1*SP
 *                          #encryption-params
 *    encryption-scheme  =  token
 *    encryption-params  =  generic-param
 * @endcode
 *
 */

msg_hclass_t sip_encryption_class[] =
SIP_HEADER_CLASS_AUTH(encryption, "Encryption", single);

int sip_encryption_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return msg_auth_d(home, h, s, slen);
}

int sip_encryption_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_is_encryption(h));
  return msg_auth_e(b, bsiz, h->sh_encryption, f);
}


/* ====================================================================== */

/* S6.36
        Response-Key  =  "Response-Key" ":" key-scheme 1*SP #key-param
        key-scheme    =  token
        key-param     =  generic-param
 */

/**@SIP_HEADER sip_response_key Response-Key Header
 *
 * The Response-Key header can be used by a client to request the key that
 * the called user agent can use to encrypt the response with.  Its syntax
 * is defined in [S10.36] as follows:
 *
 * @code
 *    Response-Key  =  "Response-Key" ":" key-scheme 1*SP #key-param
 *    key-scheme    =  token
 *    key-param     =  generic-param
 * @endcode
 */

msg_hclass_t sip_response_key_class[] =
SIP_HEADER_CLASS_AUTH(response_key, "Response-Key", single);

int sip_response_key_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return msg_auth_d(home, h, s, slen);
}

int sip_response_key_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_is_response_key(h));
  return msg_auth_e(b, bsiz, (msg_auth_t *)h, f);
}
