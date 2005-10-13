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

/**@CFILE sip_caller_prefs.c
 * @brief SIP headers related to Caller Preferences
 *
 * The file @b sip_caller_prefs.c contains implementation of header classes
 * for Caller-Preferences-related SIP headers @b Accept-Contact, @b
 * Reject-Contact, and @b Request-Disposition.
 *
 * @author Remeres Jacobs <remeres.jacobs@nokia.com>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Th 23.01.2003
 * @date Last modified: Wed Jul 20 20:35:41 2005 kaiv
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

/**@SIP_HEADER sip_request_disposition Request-Disposition Header 
 *
 * The Request-Disposition header syntax is defined in
 * draft-ietf-sip-callerprefs-08.txt section 10 as follows:
 * 
 * @code
 *      Request-Disposition  =  ( "Request-Disposition" | "d" ) HCOLON
 *                              directive *(COMMA directive)
 *      directive            =  proxy-directive / cancel-directive /
 *                              fork-directive / recurse-directive /
 *                              parallel-directive / queue-directive)
 *      proxy-directive      =  "proxy" / "redirect"
 *      cancel-directive     =  "cancel" / "no-cancel"
 *      fork-directive       =  "fork" / "no-fork"
 *      recurse-directive    =  "recurse" / "no-recurse"
 *      parallel-directive   =  "parallel" / "sequential"
 *      queue-directive      =  "queue" / "no-queue"
 * @endcode
 *
 */

/**@ingroup sip_request_disposition 
 *
 * @typedef typedef struct sip_request_disposition_s sip_request_disposition_t;
 * 
 * The structure sip_request_disposition_t contains representation of @b
 * Request-Disposition header.
 *
 * The sip_request_disposition_t is defined as follows:
 * @code
 * typedef struct sip_request_disposition_s
 * {
 *   sip_common_t        rd_common[1];   // Common fragment info
 *   sip_unknown_t      *rd_next;	 // Link to next (dummy)
 *   sip_param_t        *rd_items;
 * } sip_request_disposition_t;
 * @endcode
 */

static msg_xtra_f sip_request_disposition_dup_xtra;
static msg_dup_f sip_request_disposition_dup_one;
msg_hclass_t sip_request_disposition_class[] = 
SIP_HEADER_CLASS(request_disposition, "Request-Disposition", "d", rd_items, list, request_disposition);

int sip_request_disposition_d(su_home_t *home, sip_header_t *h, 
			      char *s, int slen)
{
  sip_request_disposition_t *rd = h->sh_request_disposition;
  
  return msg_commalist_d(home, &s, &rd->rd_items, msg_token_scan);
}


int sip_request_disposition_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  char *end = b + bsiz, *b0 = b;
  sip_request_disposition_t const *o = h->sh_request_disposition;

  assert(sip_is_request_disposition(h));

  MSG_COMMALIST_E(b, end, o->rd_items, flags); 

  return b - b0;
}


int sip_request_disposition_dup_xtra(sip_header_t const *h, int offset)
{
  sip_request_disposition_t const *o = h->sh_request_disposition;

  SIP_PARAMS_SIZE(offset, o->rd_items);

  return offset;
}


/** Duplicate one sip_request_disposition_t object */ 
char *sip_request_disposition_dup_one(sip_header_t *dst, sip_header_t const *src,
			   char *b, int xtra)
{
  char *end = b + xtra;
  sip_request_disposition_t *o_dst = dst->sh_request_disposition;
  sip_request_disposition_t const *o_src = src->sh_request_disposition;
  msg_param_t const **dst_items = (msg_param_t const **)&o_dst->rd_items;

  b = msg_params_dup(dst_items, o_src->rd_items, b, xtra);

  assert(b <= end);

  return b;
}

/* ====================================================================== */
static
void sip_caller_prefs_update_one(sip_caller_prefs_t *cp, char const *p)
{
  switch (p[0]) {
  case 'e':
    SIP_PARAM_MATCH_P(cp->cp_explicit, p, "explicit");
    break;
  case 'q':
    SIP_PARAM_MATCH(cp->cp_q, p, "q");
    break;
  case 'r':
    SIP_PARAM_MATCH_P(cp->cp_require, p, "require");
    break;
  }
}

static
void sip_caller_prefs_update(sip_header_t *h)
{
  sip_caller_prefs_t *cp = h->sh_caller_prefs;
  char const *p;
  char const *const *pp;

  /* Clear existing parameters */
  cp->cp_q = NULL;
  cp->cp_require = 0;
  cp->cp_explicit = 0;

  if ((pp = cp->cp_params))
    while ((p = pp++[0])) 
      sip_caller_prefs_update_one(cp, p);
}


/**@ingroup sip_caller_prefs 
 *
 * Add a parameter to a @b Contact header object
 *
 * The function sip_caller_prefs_add_param() adds a parameter to a contact
 * object. It does not copy the contents of the string @c param. 
 *
 * @note This function does not duplicate @p param.
 *
 * @param home   memory home
 * @param cp     sip_caller_prefs_t object
 * @param param  parameter string
 *
 * @return The function sip_caller_prefs_add_param() returns 0 when successful,
 * and -1 upon an error.  
 */
int sip_caller_prefs_add_param(su_home_t *home,
			       sip_caller_prefs_t *cp,
			       char const *param)
{
  sip_fragment_clear(cp->cp_common);

  if (sip_params_replace(home, (char const ***)&cp->cp_params, param) < 0)
    return -1;

  sip_caller_prefs_update_one(cp, param);

  return 0;
}

static
size_t span_attribute_value(char *s)
{
  size_t n;

  n = span_token_lws(s);
  if (n > 0 && s[n] == '=') {
    n += 1 + span_lws(s + n + 1);
    if (s[n] == '"')  
      n += span_quoted(s + n);
    else
      n += span_token(s + n);
    n += span_lws(s + n);
  }

  return n;
}

static
int sip_caller_prefs_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_header_t **hh = &h->sh_succ, *h0 = h;
  sip_caller_prefs_t *cp = h->sh_caller_prefs;
  url_t url[1];
  char const *ignore = NULL;
  int kludge;

  assert(h);
  
  for (;*s;) {
    /* Ignore empty entries (comma-whitespace) */
    if (*s == ',') { *s++ = '\0'; skip_lws(&s); continue; }

    if (!h) {
      if (!(h = sip_header_alloc(home, h0->sh_class, 0)))
	return -1;
      *hh = h; h->sh_prev = hh; hh = &h->sh_succ;
      cp = cp->cp_next = h->sh_caller_prefs;
    }

    kludge = 0;

    /* Kludge: support PoC IS spec with a typo... */
    if (strncasecmp(s, "*,", 2) == 0)
      s[1] = ';';
    else if (s[0] != '*' && s[0] != '<') {
      /* Kludge: missing URL -  */
      size_t n = span_attribute_value(s);
      kludge = n > 0 && (s[n] == '\0' || s[n] == ',' || s[n] == ';');
    }

    if (kludge) {
      if (msg_any_list_d(home, &s, (msg_param_t **)&cp->cp_params, 
			 msg_attribute_value_scanner, ';') == -1)
	return -1;
    }
    /* Parse params (and ignore display name and url) */
    else if (msg_name_addr_d(home, &s, &ignore, url, &cp->cp_params, NULL) 
	     == -1)
      return -1;
    /* Be liberal... */
    /* if (url->url_type != url_any) 
       return -1; */
    if (*s != '\0' && *s != ',')
      return -1;

    if (cp->cp_params) 
      sip_caller_prefs_update(h);

    h = NULL;
  }

  if (h) /* Empty list is an error */
    return -1;

  return 0;
}


int sip_caller_prefs_e(char b[], int bsiz, sip_header_t const *h, int flags)
{ 
  sip_caller_prefs_t const *cp = h->sh_caller_prefs;
  char *b0 = b, *end = b + bsiz;

  MSG_CHAR_E(b, end, '*');
  MSG_PARAMS_E(b, end, cp->cp_params, flags);
  MSG_TERM_E(b, end);

  return b - b0;
}


int sip_caller_prefs_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_caller_prefs_t const *cp = h->sh_caller_prefs;

  SIP_PARAMS_SIZE(rv, cp->cp_params);

  return rv;
}


char *sip_caller_prefs_dup_one(sip_header_t *dst, sip_header_t const *src, 
			      char *b, int xtra)
{
  char *end = b + xtra;
  sip_caller_prefs_t *cp = dst->sh_caller_prefs;
  sip_caller_prefs_t const *o = src->sh_caller_prefs;

  b = sip_params_dup(&cp->cp_params, o->cp_params, b, xtra);

  assert(b <= end);

  if (cp->cp_params) 
    sip_caller_prefs_update(dst);

  return b;
}



/**@SIP_HEADER sip_accept_contact Accept-Contact Header
 *
 * The Accept-Contact and Reject-Contact syntax is defined in
 * draft-ietf-sip-callerprefs-07.txt section 10 as follows:
 * 
 * @code
 *      Accept-Contact    =  ("Accept-Contact" / "a") HCOLON ac-value
 *                           *(COMMA ac-value)
 *      Reject-Contact    =  ("Reject-Contact" / "j") HCOLON rc-value
 *                           *(COMMA rc-value)
 *      ac-value          =  "*" *(SEMI ac-params)
 *      rc-value          =  "*" *(SEMI rc-params)
 *      ac-params         =  feature-param / c-p-q / req-param
 *                           / explicit-param / generic-param
 *      rc-params         =  feature-param / req-param
 *                           / explicit-param / generic-param
 *      feature-param     =  enc-feature-tag [EQUAL LDQUOT (tag-value-list
 *                           / string-value ) RDQUOT]
 *      enc-feature-tag   =  base-tags / other-tags
 *      base-tags         =  "attendant" / "audio" / "automata" /
 *                           "class" / "duplex" / "data" /
 *                           "control" / "mobility" / "description" /
 *                           "events" / "priority" / "methods" /
 *                           "schemes" / "application" / "video" /
 *                           "msgserver" / "language" / "type" /
 *                           "isfocus" / "uri-user" / "uri-domain"
 *      other-tags        =  "+" ftag-name
 *      ftag-name         =  ALPHA *( ALPHA / DIGIT / "!" / ""' /
 *                           "." / "-" / "%" )
 *      tag-value-list    =  tag-value *("," tag-value)
 *      tag-value         =  ["!"] (token-nobang / boolean / numeric)
 *      token-nobang      =  1*(alphanum / "-" / "." / "%" / "*"
 *                           / "_" / "+" / "`" / "'" / "~" )
 *      boolean           =  "TRUE" / "FALSE"
 *      numeric           =  "#" numeric-relation number
 *      numeric-relation  =  ">=" / "<=" / "=" / (number ":")
 *      number            =  [ "+" / "-" ] 1*DIGIT ["." 0*DIGIT]
 *      string-value      =  "<" qdtext ">"
 *      req-param         =  "require"
 *      explicit-param    =  "explicit"
 * @endcode
 *
 * The sip_accept_contact_t or sip_reject_contact_t is defined as follows:
 * @code
 * typedef struct sip_caller_prefs_s
 * {
 *   sip_common_t        cp_common[1];   // Common fragment info
 *   sip_caller_prefs_t *cp_next;	 // Link to next
 *   sip_param_t const  *cp_params;      
 *   sip_param_t         cp_q;           // Priority
 *   unsigned            cp_require;
 *   unsigned            cp_explicit;
 * } sip_accept_contact_t, sip_reject_contact_t;
 * @endcode
 */ 

msg_hclass_t sip_accept_contact_class[] = 
SIP_HEADER_CLASS(accept_contact, "Accept-Contact", "a", cp_params, append, 
		 caller_prefs);

int sip_accept_contact_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_caller_prefs_d(home, h, s, slen);
}


int sip_accept_contact_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  return sip_caller_prefs_e(b, bsiz, h, flags);
}

/**@SIP_HEADER sip_reject_contact Reject-Contact Header
 *
 * The Reject-Contact header syntax is shown with @ref sip_accept_contact
 * Accept-Contact header.
 * 
 * The sip_reject_contact_t struct is defined as follows:
 * @code
 * typedef struct sip_caller_prefs_s
 * {
 *   sip_common_t        cp_common[1];   // Common fragment info
 *   sip_caller_prefs_t *cp_next;	 // Link to next
 *   sip_param_t const  *cp_params;      
 *   sip_param_t         cp_q;           // Priority
 *   unsigned            cp_require;
 *   unsigned            cp_explicit;
 * } sip_reject_contact_t;
 * @endcode
 */

msg_hclass_t sip_reject_contact_class[] = 
SIP_HEADER_CLASS(reject_contact, "Reject-Contact", "j", cp_params, append, 
		 caller_prefs);

int sip_reject_contact_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_caller_prefs_d(home, h, s, slen);
}


int sip_reject_contact_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  return sip_caller_prefs_e(b, bsiz, h, flags);
}
