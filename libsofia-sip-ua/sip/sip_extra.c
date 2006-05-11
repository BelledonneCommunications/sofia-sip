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

/**@CFILE sip_extra.c
 * @brief Non-critical SIP headers
 * 
 * This file contains implementation of @b Call-Info, @b Error-Info,
 * @b Organization, @b Priority, @b Retry-After, @b Server, @b Subject,
 * @b Timestamp, and @b User-Agent headers.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 * 
 * @date Created: Tue Jun 13 02:57:51 2000 ppessi
 */

#include "config.h"

/* Avoid casting sip_t to msg_pub_t and sip_header_t to msg_header_t */
#define MSG_PUB_T       struct sip_s
#define MSG_HDR_T       union sip_header_u

#include "sofia-sip/sip_parser.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

/* ====================================================================== */

static int sip_info_d(su_home_t *home, sip_header_t *h, char *s, int slen);

static int sip_info_dup_xtra(sip_header_t const *h, int offset);
static char *sip_info_dup_one(sip_header_t *dst,
			      sip_header_t const *src,
			      char *b,
			      int xtra);

#define sip_info_update NULL

/* ====================================================================== */

/**@SIP_HEADER sip_call_info Call-Info Header
 * 
 * The Call-Info header provides additional information about the caller or
 * callee. Its syntax is defined in [S10.13] as follows:
 * 
 * @code
 *    Call-Info   =  "Call-Info" HCOLON info *(COMMA info)
 *    info        =  LAQUOT absoluteURI RAQUOT *( SEMI info-param)
 *    info-param  =  ( "purpose" EQUAL ( "icon" / "info"
 *                   / "card" / token ) ) / generic-param
 * @endcode
 * 
 */

/**@ingroup sip_call_info
 * @typedef struct sip_call_info_s sip_call_info_t;
 *
 * The structure sip_call_info_t contains representation of an @b
 * Call-Info header.
 *
 * The sip_call_info_t is defined as follows:
 * @code
 * struct sip_call_info_s
 * {
 *   sip_common_t        ci_common[1]; // Common fragment info
 *   sip_call_info_t    *ci_next;      // Link to next Call-Info
 *   url_t               ci_url[1];    // URI to call info
 *   msg_param_t const  *ci_params;    // List of parameters
 *   msg_param_t         ci_purpose;   // Value of @b purpose parameter
 * };
 * @endcode
 */

#define sip_call_info_dup_xtra  sip_info_dup_xtra
#define sip_call_info_dup_one   sip_info_dup_one
static msg_update_f sip_call_info_update;

msg_hclass_t sip_call_info_class[] =
SIP_HEADER_CLASS(call_info, "Call-Info", "",
		 ci_params, append, call_info);

int sip_call_info_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  int retval = sip_info_d(home, h, s, slen);

  if (retval == 0)
    for (;h; h = h->sh_next)
      msg_header_update_params(h->sh_common, 0);

  return retval;
}

int sip_call_info_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  sip_call_info_t *ci = (sip_call_info_t *)h;

  assert(sip_call_info_p(h));

  return sip_name_addr_e(b, bsiz, f, NULL, 1, ci->ci_url, ci->ci_params, NULL);
}

/** @internal
 * Update parameter in a Call-Info object.
 * 
 */
static
int sip_call_info_update(msg_common_t *h, 
			  char const *name, int namelen,
			  char const *value)
{
  sip_call_info_t *ci = (sip_call_info_t *)h;

  if (name == NULL) {
    ci->ci_purpose = NULL;
  }
  else if (namelen == strlen("purpose") && 
	   !strncasecmp(name, "purpose", namelen)) {
    ci->ci_purpose = value;
  }

  return 0;
}

/* ====================================================================== */

/**@SIP_HEADER sip_error_info Error-Info Header
 * 
 * The Error-Info header provides a pointer to additional information about
 * the error status response. Its syntax is defined in [S10.23] as follows:
 * 
 * @code
 *    Error-Info  =  "Error-Info" HCOLON error-uri *(COMMA error-uri)
 *    error-uri   =  LAQUOT absoluteURI RAQUOT *( SEMI generic-param )
 * @endcode
 * 
 */

/**@ingroup sip_error_info
 * @typedef struct sip_error_info_s sip_error_info_t;
 *
 * The structure sip_error_info_t contains representation of an @b
 * Error-Info header.
 *
 * The sip_error_info_t is defined as follows:
 * @code
 * struct sip_error_info_s
 * {
 *   sip_common_t        ei_common[1]; // Common fragment info
 *   sip_error_info_t   *ei_next;      // Link to next Error-Info
 *   url_t               ei_url[1];    // URI to error info
 *   msg_param_t const  *ei_params;    // List of parameters
 * };
 * @endcode
 */

msg_hclass_t sip_error_info_class[] = 
SIP_HEADER_CLASS(error_info, "Error-Info", "",
		 ei_params, append, info);

int sip_error_info_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_info_d(home, h, s, slen);
}

int sip_error_info_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  sip_error_info_t const *ei = h->sh_error_info;

  assert(sip_error_info_p(h));

  return sip_name_addr_e(b, bsiz, f,
			 NULL, 1, ei->ei_url, ei->ei_params, NULL);
}


/* ====================================================================== */

/**@SIP_HEADER sip_in_reply_to In-Reply-To Header
 * 
 * The @b In-Reply-To request header field enumerates the @b Call-IDs that
 * this call references or returns. Its syntax is defined in [S10.26] as
 * follows:
 * 
 * @code
 *    In-Reply-To  =  "In-Reply-To" HCOLON callid *(COMMA callid)
 * @endcode
 */

msg_hclass_t sip_in_reply_to_class[] = 
SIP_HEADER_CLASS_LIST(in_reply_to, "In-Reply-To", "", list);

int sip_in_reply_to_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return msg_list_d(home, h, s, slen);
}

int sip_in_reply_to_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_in_reply_to_p(h));
  return msg_list_e(b, bsiz, h, f);
}


/* ====================================================================== */

/**@SIP_HEADER sip_organization Organization Header
 * 
 * The Organization header field conveys the name of the organization to
 * which the entity issuing the request or response belongs. Its syntax is
 * defined in [S10.29] as follows:
 * 
 * @code
 *    Organization  =  "Organization" HCOLON [TEXT-UTF8-TRIM]
 * @endcode
 * 
 */

msg_hclass_t sip_organization_class[] = 
SIP_HEADER_CLASS_G(organization, "Organization", "", single);

int sip_organization_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_generic_d(home, h, s, slen);
}

int sip_organization_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_organization_p(h));
  return sip_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_priority Priority Header
 * 
 * The Priority request-header field indicates the urgency of the request as
 * perceived by the client. Its syntax is defined in [S10.30] as follows:
 * 
 * @code
 *    Priority        =  "Priority" HCOLON priority-value
 *    priority-value  =  "emergency" / "urgent" / "normal"
 *                       / "non-urgent" / other-priority
 *    other-priority  =  token
 * @endcode
 * 
 */

msg_hclass_t sip_priority_class[] = 
SIP_HEADER_CLASS_G(priority, "Priority", "", single);

int sip_priority_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_generic_d(home, h, s, slen);
}

int sip_priority_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_priority_p(h));
  return sip_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_server Server Header
 * 
 * The Server response-header field contains information about the software
 * used by the user agent server to handle the request. Its syntax is
 * defined in [H14.38, S10.39] as follows:
 * 
 * @code
 *    Server           =  "Server" HCOLON server-val *(LWS server-val)
 *    server-val       =  product / comment
 *    product          =  token [SLASH product-version]
 *    product-version  =  token
 * @endcode
 */

msg_hclass_t sip_server_class[] = 
SIP_HEADER_CLASS_G(server, "Server", "", single);

int sip_server_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_generic_d(home, h, s, slen);
}

int sip_server_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_server_p(h));
  return sip_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_subject Subject Header
 * 
 * The Subject header provides a summary or indicates the nature of the
 * request. Its syntax is defined in [S10.40] as follows:
 * 
 * @code
 *    Subject  =  ( "Subject" / "s" ) HCOLON [TEXT-UTF8-TRIM]
 * @endcode
 * 
 */

msg_hclass_t sip_subject_class[] = 
SIP_HEADER_CLASS_G(subject, "Subject", "s", single);

int sip_subject_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_generic_d(home, h, s, slen);
}

int sip_subject_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_subject_p(h));
  return sip_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_timestamp Timestamp Header
 * 
 * The Timestamp header describes when the client sent the request to the
 * server, and it is used by the client to adjust its retransmission
 * intervals. Its syntax is defined in [S10.42] as follows:
 * 
 * @code
 *    Timestamp  =  "Timestamp" HCOLON 1*(DIGIT)
 *                   [ "." *(DIGIT) ] [ LWS delay ]
 *    delay      =  *(DIGIT) [ "." *(DIGIT) ]
 * @endcode
 * 
 */

static int sip_timestamp_dup_xtra(sip_header_t const *h, int offset);
static char *sip_timestamp_dup_one(sip_header_t *dst,
			      sip_header_t const *src,
			      char *b,
			      int xtra);
#define sip_timestamp_update NULL

msg_hclass_t sip_timestamp_class[] = 
SIP_HEADER_CLASS(timestamp, "Timestamp", "", ts_common, single,
		 timestamp);

int sip_timestamp_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_timestamp_t *ts = (sip_timestamp_t*)h;
  
  ts->ts_stamp = s;
  skip_digit(&s); 
  if (s == ts->ts_stamp)
    return -1;
  if (*s == '.') { s++; skip_digit(&s); }

  if (IS_LWS(*s)) {
    *s++ = '\0';
    skip_lws(&s);
    ts->ts_delay = s;
    skip_digit(&s); if (*s == '.') { s++; skip_digit(&s); }
  }

  if (!*s || IS_LWS(*s))
    *s++ = '\0';
  else
    return -1;
  
  return 0;
}

int sip_timestamp_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  sip_timestamp_t const *ts = h->sh_timestamp;
  char *end = b + bsiz, *b0 = b;

  assert(sip_timestamp_p(h));

  MSG_STRING_E(b, end, ts->ts_stamp);
  if (ts->ts_delay) {
    MSG_CHAR_E(b, end, ' ');
    MSG_STRING_E(b, end, ts->ts_delay);
  }

  MSG_TERM_E(b, end);
    
  return b - b0;
}

int sip_timestamp_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_timestamp_t const *ts = h->sh_timestamp;

  rv += MSG_STRING_SIZE(ts->ts_stamp);
  rv += MSG_STRING_SIZE(ts->ts_delay);

  return rv;
}

char *sip_timestamp_dup_one(sip_header_t *dst,
			    sip_header_t const *src,
			    char *b,
			    int xtra)
{
  sip_timestamp_t *ts = dst->sh_timestamp;
  sip_timestamp_t const *o = src->sh_timestamp;
  char *end = b + xtra;

  MSG_STRING_DUP(b, ts->ts_stamp, o->ts_stamp);
  MSG_STRING_DUP(b, ts->ts_delay, o->ts_delay);

  assert(b <= end);

  return b;
}

/* ====================================================================== */

/**@SIP_HEADER sip_user_agent User-Agent Header
 * 
 * The User-Agent header contains information about the client user agent
 * originating the request. Its syntax is defined in [H14.43, S10.45] as
 * follows:
 * 
 * @code
 *    User-Agent       =  "User-Agent" HCOLON server-val *(LWS server-val)
 *    server-val       =  product / comment
 *    product          =  token [SLASH product-version]
 *    product-version  =  token
 * @endcode
 * 
 */

msg_hclass_t sip_user_agent_class[] = 
SIP_HEADER_CLASS_G(user_agent, "User-Agent", "", single);

int sip_user_agent_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_generic_d(home, h, s, slen);
}

int sip_user_agent_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_user_agent_p(h));
  return sip_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_etag SIP-ETag Header
 * 
 * The @b SIP-ETag header field identifies the published event state. Its
 * syntax is defined in @RFC3903 as follows:
 * 
 * @code
 *      SIP-ETag           = "SIP-ETag" HCOLON entity-tag
 *      entity-tag         = token
 * @endcode
 */

msg_hclass_t sip_etag_class[] = 
SIP_HEADER_CLASS_G(etag, "SIP-ETag", "", single);

int sip_etag_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_etag_t *etag = (sip_etag_t *)h;

  return msg_token_d(&s, &etag->g_value);
}

int sip_etag_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  return msg_generic_e(b, bsiz, h, f);
}

/* ====================================================================== */

/**@SIP_HEADER sip_if_match SIP-If-Match Header
 * 
 * The @b SIP-If-Match header field identifies the specific entity of event
 * state that the request is refreshing, modifying or removing. Its syntax
 * is defined in @RFC3903 as follows:
 * 
 * @code
 *      SIP-If-Match       = "SIP-If-Match" HCOLON entity-tag
 *      entity-tag         = token
 * @endcode
 */

msg_hclass_t sip_if_match_class[] = 
SIP_HEADER_CLASS_G(if_match, "SIP-If-Match", "", single);

int sip_if_match_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return sip_etag_d(home, h, s, slen);
}

int sip_if_match_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  return sip_etag_e(b, bsiz, h, f);
}

/* ====================================================================== */

int sip_info_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_call_info_t *ci = h->sh_call_info;
  char *end = s + slen;

  assert(h);

  while (*s == ',')
    s++, skip_lws(&s);

  if (sip_name_addr_d(home, &s,
		      NULL,
		      ci->ci_url,
		      &ci->ci_params,
		      NULL) < 0)
    return -1;

  if (*s && *s != ',')
    return -1;

  while (*s == ',')
    *s++ = '\0', skip_lws(&s);    /* Skip comma and following whitespace */

  if (*s == 0)
    return 0;

  if (!(h = sip_header_alloc(home, h->sh_class, 0)))
    return -1;

  return sip_info_d(home, h, s, end - s);
}

int sip_info_dup_xtra(sip_header_t const *h, int offset)
{
  int rv = offset;
  sip_call_info_t const *ci = h->sh_call_info;

  MSG_PARAMS_SIZE(rv, ci->ci_params);
  rv += url_xtra(ci->ci_url);

  return rv;
}

char *sip_info_dup_one(sip_header_t *dst,
		       sip_header_t const *src,
		       char *b,
		       int xtra)
{
  sip_call_info_t *ci = dst->sh_call_info;
  sip_call_info_t const *o = src->sh_call_info;
  char *end = b + xtra;

  b = msg_params_dup(&ci->ci_params, o->ci_params, b, xtra);
  URL_DUP(b, end, ci->ci_url, o->ci_url);

  assert(b <= end);

  return b;
}
