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

#ifndef HTTP_HEADER_H /** Defined when http_header.h has been included.*/
#define HTTP_HEADER_H

/**@file http_header.h 
 *
 * HTTP library prototypes.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date  Created: Tue Jun 13 02:58:26 2000 ppessi
 */

#ifndef SU_ALLOC_H
#include <su_alloc.h>
#endif

#ifndef SU_TAG_H
#include <su_tag.h>
#endif

#ifndef HTTP_H
#include <http.h>
#endif

#ifndef MSG_HEADER_H
#include <msg_header.h>
#endif

SOFIA_BEGIN_DECLS

/* ----------------------------------------------------------------------
 * 1) Macros
 */

/** Initialize a HTTP header structure. */
#define HTTP_HEADER_INIT(h, http_class, size) \
  (memset((h), 0, (size)), ((msg_common_t *)(h))->h_class = (http_class), (h))

#define HTTP_METHOD_NAME(method, name) \
 ((method) == http_method_unknown ? (name) : http_method_name(method, name))

/* ----------------------------------------------------------------------
 * 2) Variables
 */

HTTP_DLL extern char const http_method_name_get[];
HTTP_DLL extern char const http_method_name_post[];
HTTP_DLL extern char const http_method_name_head[];
HTTP_DLL extern char const http_method_name_options[];
HTTP_DLL extern char const http_method_name_put[];
HTTP_DLL extern char const http_method_name_delete[];
HTTP_DLL extern char const http_method_name_trace[];
HTTP_DLL extern char const http_method_name_connect[];

/** HTTP 0.9 */
HTTP_DLL extern char const http_version_0_9[];

/** HTTP 1.0 */
HTTP_DLL extern char const http_version_1_0[];

/** HTTP 1.1 version. */ 
HTTP_DLL extern char const http_version_1_1[];

#define HTTP_VERSION_CURRENT http_version_1_1

/* ----------------------------------------------------------------------
 * 3) Inlined functions 
 */

#if SU_HAVE_INLINE
/** Get HTTP structure from msg. */
su_inline
http_t *http_object(msg_t *msg)
{
  return (http_t *)msg_public(msg, HTTP_PROTOCOL_TAG);
}

/** Insert a (list of) header(s) to the header structure and fragment chain.
 *
 * The function @c http_header_insert() inserts header or list of headers
 * into a HTTP message.  It also inserts them into the the message fragment
 * chain, if it exists.
 *
 * When inserting headers into the fragment chain, a request (or status) is
 * inserted first and replaces the existing request (or status).  The Via
 * headers are inserted after the request or status, and rest of the headers
 * after request, status, or Via headers.
 *
 * If the header is a singleton, existing headers with the same class are
 * removed.
 *
 * @param msg message owning the fragment chain
 * @param http HTTP message structure to which header is added
 * @param h   list of header(s) to be added
 */
su_inline
int http_header_insert(msg_t *msg, http_t *http, http_header_t *h)
{
  return msg_header_insert(msg, (msg_pub_t *)http, (msg_header_t *)h);
}

/** Remove a header from a HTTP message. */ 
su_inline
int http_header_remove(msg_t *msg, http_t *http, http_header_t *h)
{
  return msg_header_remove(msg, (msg_pub_t *)http, (msg_header_t *)h);
}

/** Return name of the header. */
su_inline
char const *http_header_name(http_header_t const *h, int compact)
{
  if (compact && h->sh_class->hc_short[0])
    return h->sh_class->hc_short;
  else
    return h->sh_class->hc_name;
}

/** Return data after header structure. */
su_inline
void *http_header_data(http_header_t *h)
{
  return h && h != HTTP_NONE ? h->sh_class->hc_size + (char *)h : NULL;
}

su_inline 
http_content_length_t *http_content_length_create(su_home_t *home, uint32_t n)
{
  return msg_content_length_create(home, n);
}

su_inline 
http_payload_t *http_payload_create(su_home_t *home, void const *data, int len)
{
  return msg_payload_create(home, data, len);
}

su_inline 
http_separator_t *http_separator_create(su_home_t *home)
{
  return msg_separator_create(home);
}
#endif

/* ----------------------------------------------------------------------
 * 3) Prototypes 
 */

/** HTTP parser description. */
msg_mclass_t *http_default_mclass(void);

/** Complete a HTTP request. */
int http_request_complete(msg_t *msg);

/** Complete a HTTP message. */
int http_message_complete(msg_t *msg, http_t *http);

/** Add a duplicate of header object to a HTTP message. */
int http_add_dup(msg_t *, http_t *, http_header_t const *);

/** Add a header to the HTTP message. */
int http_add_make(msg_t *msg, http_t *http,
		  msg_hclass_t *hc, char const *s);

/** Add a header to the HTTP message. */
int http_add_format(msg_t *msg, http_t *http, msg_hclass_t *hc,
		    char const *fmt, ...);

/** Add tagged headers to the HTTP message */
int http_add_tl(msg_t *msg, http_t *http,
		tag_type_t tag, tag_value_t value, ...);

/** Remove schema, host, and port from URL */
int http_strip_hostport(url_t *url);

/** Add required headers to the response message */
int http_complete_response(msg_t *msg,
			   int status, char const *phrase, 
			   http_t const *request);

/** Return string corresponding to the method. */
char const *http_method_name(http_method_t method, char const *name);

/** Return enum corresponding to the method name */
http_method_t http_method_code(char const *name);

http_t *http_object(msg_t *msg);
int http_header_insert(msg_t *msg, http_t *http, http_header_t *h);
int http_header_remove(msg_t *msg, http_t *http, http_header_t *h);
char const *http_header_name(http_header_t const *h, int compact);
void *http_header_data(http_header_t *h);
http_content_length_t *http_content_length_create(su_home_t *home, uint32_t n);
http_payload_t *http_payload_create(su_home_t *home, void const *data, int len);
http_separator_t *http_separator_create(su_home_t *home);

http_header_t *http_header_format(su_home_t *home, msg_hclass_t *hc, char const *fmt,...);


/** Create a request line object. */
http_request_t *http_request_create(su_home_t *home,
				  http_method_t method, const char *name,
				  url_string_t const *url,
				  char const *version);

/** Create a status line object. */
http_status_t *http_status_create(su_home_t *home,
				  unsigned status,
				  char const *phrase,
				  char const *version);

/** Create an @b Host header object. */
http_host_t *http_host_create(su_home_t *home, 
			      char const *host, char const *port);

/** Create an @b Date header object. */
http_date_t *http_date_create(su_home_t *home, http_time_t t);

/** Create an @b Expires header object. */
http_expires_t *http_expires_create(su_home_t *home, http_time_t delta);

/** Compare two HTTP URLs. */
int http_url_cmp(url_t const *a, url_t const *b);

/** Parse query part in HTTP URL. */
int http_query_parse(char *query,
		     /* char const *key, char **return_value, */
		     ...);

#ifndef HTTP_PROTOS_H
#include <http_protos.h>
#endif

SOFIA_END_DECLS

#endif /* !defined(HTTP_HEADER_H) */
