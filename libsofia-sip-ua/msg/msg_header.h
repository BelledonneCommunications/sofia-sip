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

#ifndef MSG_HEADER_H /** Defined when msg_header.h has been included. */
#define MSG_HEADER_H "$Id: msg_header.h,v 1.2 2005/08/03 17:17:54 ppessi Exp $"
/**@ingroup msg_headers
 * @file msg_header.h
 *
 * @brief Message headers.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Mon Aug 27 15:44:27 2001 ppessi
 * 
 * $Date: 2005/08/03 17:17:54 $
 */

#include <stdarg.h>

#ifndef MSG_H
#include <msg.h>
#endif
#ifndef SU_TYPES_H
#include <su_types.h>
#endif

typedef int msg_parse_f(su_home_t *, msg_header_t *, char *, int);
typedef int msg_print_f(char buf[], int bufsiz, 
			msg_header_t const *, int flags);
typedef char *msg_dup_f(msg_header_t *dst, msg_header_t const *src, 
			char *buf, int bufsiz);
typedef int msg_xtra_f(msg_header_t const *h, int offset);

/**Define how to handle existing headers 
 * when a new header is added to a message. 
 */
typedef enum {
  msg_kind_single,		/**< Only one header is allowed */
  msg_kind_append,		/**< New header is appended */
  msg_kind_list,		/**< A token list header, 
				 * new header is combined with old one. */
  msg_kind_apndlist,		/**< A complex list header. */
  msg_kind_prepend		/**< New header is prepended */
} msg_header_kind_t;

/** Factory object for a header. 
 * 
 * The #msg_hclass_t object, "header class", defines how a header is
 * handled. It has parsing and printing functions, functions used to copy
 * header objects, header name and other information used when parsing,
 * printing, removing, adding and replacing headers within a message.
 */
struct msg_hclass_s
{
  int               hc_hash;	/**< Header name hash or ID */
  msg_parse_f      *hc_parse;	/**< Parse header. */
  msg_print_f      *hc_print;	/**< Print header. */
  msg_xtra_f       *hc_dxtra;	/**< Calculate extra size for dup */
  msg_dup_f        *hc_dup_one;	/**< Duplicate one header. */
  char const 	   *hc_name;	/**< Full name. */
  short             hc_len;	/**< Length of hc_name. */
  char              hc_short[2];/**< Short name, if any. */
  unsigned char     hc_size;	/**< Size of header structure. */
  unsigned char     hc_params;	/**< Offset of parameters */
  msg_header_kind_t hc_kind:3;	/**< Kind of header: 
				 * single, append, list, apndlist, prepend. */
  unsigned          hc_critical:1; /**< True if header is critical */
  unsigned          /*pad*/:0;
};

/* These headers are critical for understanding the message */
#define msg_kind_single_critical msg_kind_single, 1
#define msg_kind_list_critical   msg_kind_list, 1

msg_header_t *msg_header_alloc(su_home_t *, msg_hclass_t *hc, int extra)
     __attribute__((__malloc__));
int msg_header_size(msg_header_t const *h);

msg_header_t **msg_header_offset(msg_t *, msg_pub_t *, msg_header_t const *);
msg_header_t **msg_hclass_offset(msg_mclass_t const *, 
				 msg_pub_t *, msg_hclass_t *);
msg_header_t *msg_header_access(msg_pub_t const *pub, msg_hclass_t *hc);

msg_header_t *msg_header_copy_as(su_home_t *home, 
				 msg_hclass_t *hc,
				 msg_header_t const *o)
     __attribute__((__malloc__));
msg_header_t *msg_header_copy(su_home_t *home, msg_header_t const *o)
     __attribute__((__malloc__));
msg_header_t *msg_header_copy_one(su_home_t *home, msg_header_t const *o)
     __attribute__((__malloc__));
msg_header_t *msg_header_dup_as(su_home_t *home, msg_hclass_t *hc,
				msg_header_t const *o)
     __attribute__((__malloc__));
msg_header_t *msg_header_dup(su_home_t *home, msg_header_t const *h)
     __attribute__((__malloc__));
msg_header_t *msg_header_dup_one(su_home_t *home, msg_header_t const *h)
     __attribute__((__malloc__));

msg_header_t *msg_header_d(su_home_t *home, msg_t const *msg, char const *b);
int msg_header_e(char b[], int bsiz, msg_header_t const *h, int flags);
int msg_object_e(char b[], int size, msg_pub_t const *mo, int flags);

int msg_header_field_e(char b[], int bsiz, msg_header_t const *h, int flags);

int msg_copy_all(msg_t *msg, msg_pub_t *dst, msg_pub_t const *src);
int msg_dup_all(msg_t *msg, msg_pub_t *dst, msg_pub_t const *src);
int msg_header_remove(msg_t *msg, msg_pub_t *mo, msg_header_t *h);
int msg_header_remove_all(msg_t *msg, msg_pub_t *mo, msg_header_t *h);

int msg_header_insert(msg_t *msg, msg_pub_t *mo, msg_header_t *h);

int msg_header_add_dup(msg_t *msg,
		       msg_pub_t *pub,
		       msg_header_t const *o);

int msg_header_add_str(msg_t *msg, 
		       msg_pub_t *pub,
		       char const *str);

int msg_header_add_dup_as(msg_t *msg,
			  msg_pub_t *pub,
			  msg_hclass_t *hc,
			  msg_header_t const *o);

int msg_header_add_make(msg_t *msg,
			msg_pub_t *pub,
			msg_hclass_t *hc,
			char const *s);

int msg_header_prepend(msg_t *msg, 
		       msg_pub_t *pub, 
		       msg_header_t **hh, 
		       msg_header_t *h);

msg_header_t *msg_header_make(su_home_t *home, 
			      msg_hclass_t *hc,
			      char const *s)
     __attribute__((__malloc__));

msg_header_t *msg_header_format(su_home_t *home, 
				msg_hclass_t *hc,
				char const *fmt,
				...)
     __attribute__ ((__malloc__, __format__ (printf, 3, 4)));

msg_header_t *msg_header_vformat(su_home_t *home, 
				 msg_hclass_t *hc,
				 char const *fmt,
				 va_list ap)
     __attribute__((__malloc__));

msg_payload_t *msg_payload_create(su_home_t *home, void const *data, int len)
     __attribute__((__malloc__));

msg_separator_t *msg_separator_create(su_home_t *home)
     __attribute__((__malloc__));

/* Chunk handling macros */

/** Get pointer to beginning of available buffer space */
#define MSG_CHUNK_BUFFER(pl) \
  ((char *)pl->pl_common->h_data + (pl)->pl_common->h_len)
/** Get size of available buffer space */
#define MSG_CHUNK_AVAIL(pl) \
  ((pl)->pl_len + ((pl)->pl_data - (char *)pl->pl_common->h_data) - \
   (pl)->pl_common->h_len)
/** Get next chunk in list */
#define MSG_CHUNK_NEXT(pl) \
  ((pl)->pl_next)

int msg_headers_prepare(msg_t *msg, msg_header_t *headers, int flags);

#ifdef SU_HAVE_INLINE
/** Clear encoded data from header structure. */
static inline void msg_fragment_clear(msg_common_t *h) 
{
  h->h_data = NULL, h->h_len = 0;
}
/** Pointer to header parameters. */
static inline 
msg_param_t **msg_header_params(msg_header_t *h0)
{
  msg_common_t *h = (msg_common_t *)h0;

  if (h && h->h_class->hc_params) {
    return (msg_param_t **)((char *)h + h->h_class->hc_params);
  }
  return NULL;
}
#else
#define msg_fragment_clear(h) ((h)->h_data = NULL, (h)->h_len = 0)
#define msg_header_params(h) (((h) && (h)->sh_class->hc_params) ? \
 (msg_param_t **)((char *)(h) + (h)->sh_class->hc_params) : NULL)
#endif

int msg_random_token(char token[], int tlen, void const *data, int dlen);

msg_param_t msg_params_find(msg_param_t const pp[], msg_param_t);
msg_param_t *msg_params_find_slot(msg_param_t params[], msg_param_t token);
msg_param_t msg_params_matching(msg_param_t const params[], 
				msg_param_t param);
int msg_params_add(su_home_t *sh, msg_param_t **pp, msg_param_t);
int msg_params_cmp(msg_param_t const a[], msg_param_t const b[]);
int msg_params_replace(su_home_t *, msg_param_t **pp, msg_param_t);
int msg_params_remove(msg_param_t *pparams, msg_param_t param);
size_t msg_params_length(msg_param_t const params[]);

/** Append a list of constant items to a list. */
MSG_DLL int msg_list_append_items(su_home_t *home, msg_list_t *k, 
				  msg_param_t const items[]);

/** Replace a list of constant items on a list */
MSG_DLL int msg_list_replace_items(su_home_t *home, msg_list_t *k, 
				   msg_param_t const items[]);

/** Unquote a string, return a duplicate. */
MSG_DLL char *msg_unquote_dup(su_home_t *home, char const *q)
     __attribute__((__malloc__));

MSG_DLL char *msg_unquote(char *dst, char const *s);

/** Calculate a hash over a string. */
MSG_DLL unsigned long msg_hash_string(char const *id);

/* Align pointer p for multiple of t (which must be a power of 2) */
#define MSG_ALIGN(p, t) (((t) - 1 + (long)(p))&-(long)(t))
#define MSG_STRUCT_SIZE_ALIGN(rv) ((rv) = MSG_ALIGN(rv, (int)sizeof(void *)))
#define MSG_STRUCT_ALIGN(p) ((p) = (void*)MSG_ALIGN(p, (int)sizeof(void *)))

enum {
 msg_n_params = 8,	/* allocation size of parameter string list */
#define MSG_N_PARAMS msg_n_params
};

/** Initialize a header structure. @HIDE */
#define MSG_HEADER_INIT(h, msg_class, size) \
  (memset((h), 0, (size)), ((msg_common_t *)(h))->h_class = (msg_class), (h))

/** No header. */
#define MSG_HEADER_NONE ((msg_header_t *)-1)

#ifndef MSG_PROTOS_H
#include <msg_protos.h>
#endif

#endif /** !defined(MSG_HEADER_H) */
