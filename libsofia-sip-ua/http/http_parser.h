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

#ifndef HTTP_PARSER_H /**Defined when http_parser.h has been included.*/
#define HTTP_PARSER_H 
/**@file http_parser.h
 * @brief Typedefs and prototypes used by HTTP parser.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Jun 13 02:58:26 2000 ppessi
 */

#ifndef SU_ALLOC_H
#include <su_alloc.h>
#endif

#ifndef MSG_H
#define MSG_PUB_T       struct http_s
#define MSG_HDR_T       union http_header_u
#include <msg.h>
#else
#error "<http_parser.h> must be included before <msg.h>"
#endif

#ifndef MSG_PARSER_H
#include <msg_parser.h>
#endif

#ifndef HTTP_H
#include <http.h>
#endif

#ifndef HTTP_HEADER_H
#include <http_header.h>
#endif

SOFIA_BEGIN_DECLS

/* ---------------------------------------------------------------------------
 * 1) Macros for defining boilerplate functions and structures for each header
 */

#define HTTP_HCLASS_TAG     HTTP_PROTOCOL_TAG
#define HTTP_HCLASS_TEST(x) ((x) && (x)->hc_tag == HTTP_PROTOCOL_TAG)
#define HTTP_HDR_TEST(x)    ((x)->sh_class && HTTP_HCLASS_TEST((x)->sh_class))

/** Define a header class for a HTTP header. */
#define HTTP_HEADER_CLASS(c, l, params, kind, dup) \
  MSG_HEADER_CLASS(http_, c, l, "", params, kind, http_ ## dup, http_no)

/** This is used by headers with no extra data in copy */
#define HTTP_HEADER_CLASS_G(c, l, kind) \
  MSG_HEADER_CLASS(http_, c, l, "", g_common, kind, msg_generic, http_no)

/** Define a header class for a msg_list_t kind of header */
#define HTTP_HEADER_CLASS_LIST(c, l, kind) \
  MSG_HEADER_CLASS(http_, c, l, "", k_items, kind, msg_list, http_no)

/** Define a authorization header class */
#define HTTP_HEADER_CLASS_AUTH(c, l, kind) \
  MSG_HEADER_CLASS(http_, c, l, "", au_params, kind, msg_auth, http_no)


/* ---------------------------------------------------------------------------
 * 2) Prototypes for HTTP-specific decoding/encoding functions
 */

/* Version strings */
int http_version_d(char **ss, char const **ver);
int http_version_xtra(char const *version);
void http_version_dup(char **pp, char const **dd, char const *s);

/* Method */
http_method_t http_method_d(char **ss, char const **nname);
char const *http_method_name(http_method_t method, char const *name);

/** Extract HTTP message body */
int http_extract_body(msg_t *msg, http_t *http, char b[], int bsiz, int eos);

/* ---------------------------------------------------------------------------
 * 3) Compatibility macros
 */

#define http_numeric_dup_xtra msg_default_dup_xtra
#define http_numeric_dup_one  msg_default_dup_one

#define http_default_dup_xtra msg_default_dup_xtra
#define http_default_dup_one  msg_default_dup_one

#define http_no_update NULL

SOFIA_END_DECLS

#endif /* !defined(HTTP_PARSER_H) */
