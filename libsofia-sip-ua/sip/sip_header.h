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

#ifndef SIP_HEADER_H /**Defined when @b <sip_header.h> has been included.*/
#define SIP_HEADER_H 


/**@file sip_header.h 
 *
 * SIP parser library prototypes.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date  Created: Tue Jun 13 02:58:26 2000 ppessi
 * @date Last modified: Fri Sep 23 14:53:50 2005 ppessi
 */

#ifndef SU_ALLOC_H
#include <su_alloc.h>
#endif

#ifndef SU_TAG_H
#include <su_tag.h>
#endif

#ifndef SIP_H
#include <sip.h>
#endif

#ifndef MSG_HEADER_H
#include <msg_header.h>
#endif

#ifndef _STRING_H
#include <string.h>
#endif

#include <sip_dll.h>

/** @internal SIP parser description. */
msg_mclass_t *sip_default_mclass(void);

/** Check that sip_t is a SIP structure (not RTSP or HTTP). @HIDE */
#define sip_is_sip(sip) ((sip) && (sip)->sip_ident == SIP_PROTOCOL_TAG)

/** Initializer for a SIP header object. @HIDE */
#define SIP_HDR_INIT(name) {{{ 0, 0, sip_##name##_class }}}

/** Initialize a SIP header structure. @HIDE */
#define SIP_HEADER_INIT(h, sip_class, size) \
  (memset((h), 0, (size)), ((sip_common_t *)(h))->h_class = (sip_class), (h))

/** Serialize headers into the fragment chain. */
int sip_serialize(msg_t *msg, sip_t *sip);

/** Encode a SIP message. */
int sip_e(sip_t const *sip, int flags, char b[], int size);

/** Test if @a header is a pointer to a SIP header object. */
int sip_is_header(sip_header_t const *header);

/** Encode a SIP header field (name: contents CRLF). */
int sip_header_e(char b[], int bsiz, sip_header_t const *h, int flags);

/** Decode a SIP header string (name: contents CRLF?). */
sip_header_t *sip_header_d(su_home_t *home, msg_t const *msg, char const *b);

/** Encode contents of a SIP header field. */
int sip_header_field_e(char b[], int bsiz, sip_header_t const *h, int flags);

/** Decode the header string */
int sip_header_field_d(su_home_t *home, sip_header_t *h, char *s, int slen);

/** Convert the header @a h to a string allocated from @a home. */
char *sip_header_as_string(su_home_t *home, sip_header_t *h);

/** Calculate the size of a SIP header and associated memory areas. */
int sip_header_size(sip_header_t const *h);

/** Duplicate (deep copy) a SIP header or whole list. */ 
sip_header_t *sip_header_dup(su_home_t *home, sip_header_t const *h);

/** Copy a SIP header or whole list. */
sip_header_t *sip_header_copy(su_home_t *home, sip_header_t const *o);

/** Copy a complete message, keeping the header chain structure. */
int sip_copy_all(msg_t *msg, sip_t *dst, sip_t const *src);

/** Add a duplicate of header object to a SIP message. */
int sip_add_dup(msg_t *, sip_t *, sip_header_t const *);

/** Add a duplicate of header object to the SIP message. */
int sip_add_dup_as(msg_t *msg, sip_t *sip,
		   msg_hclass_t *hc, sip_header_t const *o);

/** Add duplicates of headers to the SIP message. */
int sip_add_headers(msg_t *msg, sip_t *sip, 
		    void const *extra, va_list headers);

/** Add duplicates of headers from taglist to the SIP message. */
int sip_add_tl(msg_t *msg, sip_t *sip,
	       tag_type_t tag, tag_value_t value, ...);

/** Add a header to the SIP message. */
int sip_add_make(msg_t *msg, sip_t *sip,
		 msg_hclass_t *hc, char const *s);

/** Complete SIP message. */
int sip_complete_message(msg_t *msg);

/** Clear encoded data. @HIDE */
#define sip_fragment_clear(a) ((a)->h_data = NULL, (a)->h_len = 0)

/* Use __attribute__ to allow argument checking for sip_header_format() */
#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(x) 
#endif

/** Make a SIP header with formatting provided. */
sip_header_t *sip_header_format(su_home_t *home, 
				msg_hclass_t *hc,
				char const *fmt,
				...)
     __attribute__((__format__ (printf, 3, 4)));

int sip_generic_xtra(sip_generic_t const *g);

sip_generic_t *sip_generic_dup(su_home_t *home, 
			       msg_hclass_t *hc, 
			       sip_generic_t const *u);

sip_generic_t *sip_generic_copy(su_home_t *home,
				msg_hclass_t *hc, 
				sip_generic_t const *o);

/** Return current time */
sip_time_t sip_now(void);

SIP_DLL extern char const sip_method_name_ack[];
SIP_DLL extern char const sip_method_name_bye[];
SIP_DLL extern char const sip_method_name_cancel[];
SIP_DLL extern char const sip_method_name_invite[];
SIP_DLL extern char const sip_method_name_options[];
SIP_DLL extern char const sip_method_name_register[];
SIP_DLL extern char const sip_method_name_info[];
SIP_DLL extern char const sip_method_name_prack[];
SIP_DLL extern char const sip_method_name_comet[];
SIP_DLL extern char const sip_method_name_message[];
SIP_DLL extern char const sip_method_name_subscribe[];
SIP_DLL extern char const sip_method_name_notify[];
SIP_DLL extern char const sip_method_name_refer[];

/** @internal UDP transport version string. */ 
SIP_DLL extern char const sip_transport_udp[];
/** @internal TCP transport version string. */ 
SIP_DLL extern char const sip_transport_tcp[];
/** @internal SCTP transport version string. */ 
SIP_DLL extern char const sip_transport_sctp[];
/** @internal TLS transport version string. */ 
SIP_DLL extern char const sip_transport_tls[];
/** @internal SIP version string. */ 
SIP_DLL extern char const sip_version_2_0[];

#define SIP_VERSION_CURRENT sip_version_2_0

/** SIP parser version */
SIP_DLL extern char const sip_parser_version[];

/** Get SIP service name */
#define SIP_PORT(s) ((s) ? (s) : "5060")

/** Get SIPS service name */
#define SIPS_PORT(s) ((s) ? (s) : "5061")

/** Return string corresponding to the method. */
char const *sip_method_name(sip_method_t method, char const *name);

/** Return code corresponding to the method code */
sip_method_t sip_method_code(char const *name);

SIP_DLL extern char const * const sip_method_names[];

#define SIP_METHOD_NAME(method, name) \
 ((method) == sip_method_unknown ? (name) : sip_method_name(method, name))

#if 1
#define sip_from_make_url     sip_from_create
#define sip_to_make_url       sip_to_create
#define sip_params_find       msg_params_find
#endif

#define sip_header_make(h, c, s) \
  ((sip_header_t *)msg_header_make((h), (c), (s)))
#define sip_header_vformat(h, c, f, a) \
  ((sip_header_t *)msg_header_vformat((h), (c), (f), (a)))

#include <sip_protos.h>

/** Create a request line object. */
sip_request_t *sip_request_create(su_home_t *home,
				  sip_method_t method, const char *name,
				  url_string_t const *url,
				  char const *version);

/** Create a status line object. */
sip_status_t *sip_status_create(su_home_t *home,
				unsigned status,
				char const *phrase,
				char const *version);

/** Add an event to Allow-Events header. */
int sip_allow_events_add(su_home_t *home, 
			 sip_allow_events_t *ae, 
			 char const *e);

/** Create a @b Call-ID header object. */
sip_call_id_t *sip_call_id_create(su_home_t *home, char const *domain);

/** Create a @b CSeq header object.  */
sip_cseq_t *sip_cseq_create(su_home_t *, 
			    sip_u32_t seq, unsigned method, char const *name);

/** Create a @b Contact header object. */
sip_contact_t * sip_contact_create(su_home_t *home, url_string_t const *url, 
				   sip_param_t p, ...);
/** Add a parameter to a @b Contact header object. */
int sip_contact_add_param(su_home_t *, sip_contact_t *, char const *param);

/** Calculate expiration time of a Contact header. */
sip_time_t sip_contact_expires(sip_contact_t const *m,
			       sip_expires_t const *ex,
			       sip_date_t const *date,
			       sip_time_t def,
			       sip_time_t now);

/** Create a @b Content-Length header object. */
sip_content_length_t *sip_content_length_create(su_home_t *home, sip_u32_t n);

/** Create an @b Date header object. */
sip_date_t *sip_date_create(su_home_t *home, sip_time_t t);

/** Create an @b Expires header object. */
sip_expires_t *sip_expires_create(su_home_t *home, sip_time_t delta);

/** Create a @b Route header object. */
sip_route_t *sip_route_create(su_home_t *home, url_t const *url, 
			      url_t const *maddr);

/** Create a @b Record-Route header object. */
sip_record_route_t *sip_record_route_create(su_home_t *,
					    url_t const *rq_url,
					    url_t const *m_url);

/** Create a @b From header object. */
sip_from_t *sip_from_create(su_home_t *home, url_string_t const *url);

int sip_from_add_param(su_home_t *, sip_from_t *, char const *param);

int sip_from_tag(su_home_t *home, sip_from_t *from, char const *tag);

/** Create a @b To header object. */
sip_to_t *sip_to_create(su_home_t *home, url_string_t const *url);

int sip_to_add_param(su_home_t *, sip_to_t *, char const *param);

int sip_to_tag(su_home_t *home, sip_to_t *to, char const *tag);

/** Create a Via object. */ 
sip_via_t *sip_via_create(su_home_t *h,
                          char const *host,
                          char const *port, 
                          char const *transport,
                          /* char const *params */
                          ...);

/** Add a parameter to a @b Via header object. */ 
int sip_via_add_param(su_home_t *, sip_via_t *, char const *);

/** Get transport protocol name. */
#if HAVE_INLINE
static inline
char const *sip_via_transport(sip_via_t const *v)
{
  char const *tp = v->v_protocol;
  if (tp) {
    tp = strchr(tp, '/'); 
    if (tp) {
      tp = strchr(tp + 1, '/');
      if (tp)
	return tp + 1;
    }
  }
  return NULL;
}
#endif
char const *sip_via_transport(sip_via_t const *v);

sip_payload_t *sip_payload_create(su_home_t *home, void const *data, int len);

/**@ingroup sip_payload
 *
 * Initialize a SIP payload structure with pointer to data and its length. 
 *
 * The SIP_PAYLOAD_INIT2() macro initializes a sip_payload_t header
 * structure with a pointer to data and its length in octets. For
 * instance,
 * @code 
 *  sip_payload_t txt_payload = SIP_PAYLOAD_INIT2(txt, strlen(txt));
 * @endcode
 *
 * The SIP_PAYLOAD_INIT2() macro can be used when creating a new payload
 * from heap is not required, for instance, when resulting payload structure
 * is immediately copied.
 *
 * @HIDE 
 */
#define SIP_PAYLOAD_INIT2(data, length) \
  {{{ 0, 0, sip_payload_class, data, length }, NULL, data, length }}

/** Create a SIP separator line structure. */
sip_separator_t *sip_separator_create(su_home_t *home);

/** Check that a required feature is supported. */
sip_unsupported_t *sip_has_unsupported(su_home_t *,
				       sip_supported_t const *support, 
				       sip_require_t const *require);

sip_unsupported_t *sip_has_unsupported2(su_home_t *home,
					sip_supported_t const *support,
					sip_require_t const *by_require,
					sip_require_t const *require);

sip_unsupported_t *
sip_has_unsupported_any(su_home_t *home,
			sip_supported_t const *support,
			sip_require_t const *by_require,
			sip_proxy_require_t const *by_proxy_require,
			sip_require_t const *require,
			sip_require_t const *require2,
			sip_require_t const *require3);

/** Check that a feature is supported. */
int sip_has_supported(sip_supported_t const *support, char const *feature);

/** Check that a feature is in the list. */
int sip_has_feature(msg_list_t const *supported, char const *feature);

/* ---------------------------------------------------------------------------
 * Bitmasks for header classifications
 */
enum {
  sip_mask_request = 1,
  sip_mask_response = 2,
  sip_mask_ua = 4,
  sip_mask_proxy = 8,
  sip_mask_registrar = 16,
  sip_mask_100rel = 32,
  sip_mask_events = 64,
  sip_mask_timer = 128,
  sip_mask_privacy = 256,
  sip_mask_pref = 512,
  sip_mask_publish = 1024
};

#endif 
