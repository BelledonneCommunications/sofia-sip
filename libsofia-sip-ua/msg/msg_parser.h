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

#ifndef MSG_PARSER_H /** Defined when msg_parser.h has been included. */
#define MSG_PARSER_H 

/**@ingroup msg_parser
 * @file msg_parser.h
 *
 * Message parser interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Aug 21 16:03:45 2001 ppessi
 *
 * @date Last modified: Wed Jul 20 20:35:25 2005 kaiv
 */

#ifndef SU_ALLOC_H
#include <su_alloc.h>
#endif

#ifndef MSG_H
#include <msg.h>
#endif

#ifndef MSG_HEADER_H
#include <msg_header.h>
#endif

#ifndef BNF_H
#include <bnf.h>
#endif

#ifndef URL_H
#include <url.h>
#endif

/* ---------------------------------------------------------------------------
 * 1) Header class definitions.
 */

#if HAVE_STRUCT_KEYWORDS
/** Define a header class */
#define MSG_HEADER_CLASS(pr, c, l, s, params, kind, dup) \
  {{ \
     hc_hash:    pr##c##_hash, \
     hc_parse:   pr##c##_d, \
     hc_print:   pr##c##_e, \
     hc_dxtra:   dup##_dup_xtra, \
     hc_dup_one: dup##_dup_one, \
     hc_name:    l, \
     hc_len:     sizeof(l) - 1, \
     hc_short:   s, \
     hc_size:    MSG_ALIGN(sizeof(pr##c##_t), sizeof(void*)), \
     hc_params:  offsetof(pr##c##_t, params), \
     hc_kind:    msg_kind_##kind, \
  }}
#else
#define MSG_HEADER_CLASS(pr, c, l, s, params, kind, dup) \
  {{ \
     pr##c##_hash, \
     pr##c##_d, \
     pr##c##_e, \
     dup##_dup_xtra, \
     dup##_dup_one, \
     l, \
     sizeof(l) - 1, \
     s, \
     MSG_ALIGN(sizeof(pr##c##_t), sizeof(void*)), \
     offsetof(pr##c##_t, params), \
     msg_kind_##kind, \
  }}
#endif

int msg_extract_header(msg_t *msg, msg_pub_t *mo, char b[], int bsiz, int eos);
int msg_extract_separator(msg_t *msg, msg_pub_t *mo, char b[], int bsiz, int eos);
int msg_extract_payload(msg_t *msg, msg_pub_t *mo, 
			msg_header_t **return_payload, unsigned body_len,
			char b[], int bsiz, int eos);

/* ---------------------------------------------------------------------------
 * 2) Header processing methods for common headers.
 */

int msg_firstline_d(char *s, char **ss2, char **ss3);

int msg_default_dup_xtra(msg_header_t const *header, int offset);
char *msg_default_dup_one(msg_header_t *dst, 
			  msg_header_t const *src,
			  char *b, 
			  int xtra);

int msg_numeric_d(su_home_t *home, msg_header_t *h, char *s, int slen);
int msg_numeric_e(char [], int, msg_header_t const *, int);

int msg_list_d(su_home_t *home, msg_header_t *h, char *s, int slen);
int msg_list_e(char [], int, msg_header_t const *, int);
int msg_list_dup_xtra(msg_header_t const *h, int offset);
char *msg_list_dup_one(msg_header_t *dst,
		       msg_header_t const *src,
		       char *b, 
		       int xtra);

int msg_generic_d(su_home_t *, msg_header_t *, char *, int n);
int msg_generic_e(char [], int, msg_header_t const *, int);
int msg_generic_dup_xtra(msg_header_t const *h, int offset);
char *msg_generic_dup_one(msg_header_t *dst,
			  msg_header_t const *src,
			  char *b, 
			  int xtra);

int msg_unknown_dup_xtra(msg_header_t const *h, int offset);
char *msg_unknown_dup_one(msg_header_t *dst, msg_header_t const *src,
			  char *b, int xtra);

int msg_error_dup_xtra(msg_header_t const *h, int offset);
char *msg_error_dup_one(msg_header_t *dst, msg_header_t const *src,
			char *b, int xtra);

int msg_payload_d(su_home_t *home, msg_header_t *h, char *s, int slen);
int msg_payload_e(char b[], int bsiz, msg_header_t const *h, int flags);
int msg_payload_dup_xtra(msg_header_t const *h, int offset);
char *msg_payload_dup_one(msg_header_t *dst, msg_header_t const *src,
			  char *b, int xtra);

int msg_separator_d(su_home_t *home, msg_header_t *h, char *s, int slen);
int msg_separator_e(char b[], int bsiz, msg_header_t const *h, int flags);

int msg_auth_d(su_home_t *home, msg_header_t *h, char *s, int slen);
int msg_auth_e(char b[], int bsiz, msg_header_t const *h, int f);
int msg_auth_dup_xtra(msg_header_t const *h, int offset);
char *msg_auth_dup_one(msg_header_t *dst, msg_header_t const *src, 
		       char *b, int xtra);

/* ---------------------------------------------------------------------------
 * 2) Macros and prototypes for building header decoding/encoding functions.
 */

#define MSG_HEADER_DATA(h) ((char *)(h) + (h)->sh_class->hc_size)

#define MSG_HEADER_TEST(h) ((h) && (h)->sh_class)

static inline void *msg_header_data(msg_frg_t *h);

int msg_hostport_d(char **ss, char const **hhost, char const **pport);

int msg_token_d(char **ss, char const **token);
int msg_uint32_d(char **ss, uint32_t *value);
int msg_comment_d(char **ss, char const **ccomment);
int msg_quoted_d(char **ss, char **unquoted);
int msg_unquoted_e(char *b, int bsiz, char const *s);

int msg_name_addr_d(su_home_t *home,
		    char **ss,
		    char const **ddisplay,
		    url_t *url,
		    msg_param_t const **pparams,
		    char const **ccomment);

int msg_name_addr_e(char b[], int bsiz, 
		    int flags, 
		    char const *display, 
		    int always_ltgt, url_t const url[],
		    msg_param_t const params[], 
		    char const *comment);

/** Terminate encoding. @HI */
#define MSG_TERM_E(p, e) ((p) < (e) ? (p)[0] = '\0' : '\0')

/** Encode a character. @HI */
#define MSG_CHAR_E(p, e, c) (++(p) < (e) ? ((p)[-1]=(c)) : (c)) 

/** Calculate separator and string length. @HI */
#define MSG_STRING_LEN(s, sep_size) ((s) ? (strlen(s) + sep_size) : 0)

/** Encode a string. @HI */
#define MSG_STRING_E(p, e, s) do { \
  int _n = strlen(s); if (p + _n+1 < e) memcpy(p, s, _n+1); p+= _n; } while(0)

/** Duplicate string. @HI */
#define MSG_STRING_DUP(p, d, s) \
  (void)((s)?((p)=memccpy((void *)((d)=(char*)p),(s),0,0x7fffffff)):((d)=NULL))

/** Calculate string size. @HI */
#define MSG_STRING_SIZE(s) ((s) ? (strlen(s) + 1) : 0)

int msg_commalist_d(su_home_t *home, char **ss, 
		    msg_param_t **pparams,
		    int (*scanner)(char *s));

/** Token scanner for msg_commalist_d(). 
 *
 * This accepts also empty entries.
 */
int msg_token_scan(char *start);

/** Attribute-value pair scanner */
int msg_attribute_value_scanner(char *s);

int msg_any_list_d(su_home_t *home, char **ss, 
		   msg_param_t **retval,
		   int (*scanner)(char *s), int sep);

/** Encode a comma-separated parameter list */
#define MSG_COMMALIST_E(b, end, params, compact) do { \
  char const * const *p_; char const * c_ = ""; \
  for (p_ = (params); p_ && *p_; p_++, c_ = (compact ? "," : ", ")) \
    { MSG_STRING_E(b, (end), c_); MSG_STRING_E(b, (end), *p_); } \
} while(0)

/* Parameter lists */

/** Match a parameter with any value. @HI */
#define MSG_PARAM_MATCH(v, s, name) \
  (strncasecmp(s, name "=", sizeof(name)) == 0 ? (v = s + sizeof(name)) : NULL)

/** Match a parameter with known value. @HI */
#define MSG_PARAM_MATCH_P(v, s, name) \
  ((strncasecmp((s), name "", sizeof(name) - 1) == 0 &&			\
    ((s)[sizeof(name) - 1] == '=' || (s)[sizeof(name) - 1] == '\0')) ? \
   ((v) = 1) : 0)

/** Calculate allocated number of items in parameter list. @HI */
#define MSG_PARAMS_NUM(n) ((((n) + MSG_N_PARAMS - 1 )&-MSG_N_PARAMS))

/** Parse a semicolon-separated attribute-value list. @HI */
int msg_avlist_d(su_home_t *home, char **ss, msg_param_t const **pparams);

/** Parse a semicolon-separated parameter list starting with semicolong. @HI */
int msg_params_d(su_home_t *home, char **ss, msg_param_t const **pparams);

/** Encode a list of parameters. */
int msg_params_e(char b[], int bsiz, msg_param_t const pparams[]);

/** Join list of parameters */
int msg_params_join(su_home_t *home,
		    msg_param_t **dst,
		    msg_param_t const *src,
		    unsigned prune,
		    int dup);

/** Encode a list of parameters. @HI */
#define MSG_PARAMS_E(b, end, params, flags) \
  b += msg_params_e(b, b < end ? end - b : 0, params)

/** Calculate extra size of parametes. @HI */
#define MSG_PARAMS_SIZE(rv, params) (rv = msg_params_dup_xtra(params, rv))

/** Duplicate a parameter list */
char *msg_params_dup(msg_param_t const **d, msg_param_t const *s, 
		     char *b, int xtra);

/** Count number of parameters in the list */
static inline int msg_params_count(msg_param_t const params[])
{
  if (params) {
    int n;
    for (n = 0; params[n]; n++)
      ;
    return n;
  }
  else {
    return 0;
  }
}

/** Calculate memory size required by parameter list */
static inline int msg_params_dup_xtra(msg_param_t const params[], int offset)
{
  int n = msg_params_count(params);
  if (n) {
    MSG_STRUCT_SIZE_ALIGN(offset);
    offset += MSG_PARAMS_NUM(n + 1) * sizeof(msg_param_t);
    for (n = 0; params[n]; n++)
      offset += strlen(params[n]) + 1;
  }
  return offset;
}

/** Return pointer to extra data after header structure */
static inline void *msg_header_data(msg_frg_t *h)
{
  if (h)
    return (char *)h + h->h_class->hc_size;
  else
    return NULL;
}

#endif /** MSG_PARSER_H */
