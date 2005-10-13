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

/**@CFILE sip_event.c
 * @brief Event SIP headers.
 *
 * The file @b sip_event.c contains implementation of header classes for
 * event-related SIP headers @b Event and @b Allow-Events.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Thu Sep 13 21:24:15 EEST 2001 ppessi
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

/**@SIP_HEADER sip_event Event Header
 *
 * The Event header is used to indicate the which event or class of events
 * the message contains or subscribes.  Its syntax is defined in
 * [Events4.2.1] (draft-ietf-sip-events-00.txt) as follows:
 * 
 * @code
 *   Event             =  ( "Event" / "o" ) HCOLON event-type
 *                         *( SEMI event-param )
 *   event-type        =  event-package *( "." event-template )
 *   event-package     =  token-nodot
 *   event-template    =  token-nodot
 *   token-nodot       =  1*( alphanum / "-"  / "!" / "%" / "*"
 *                             / "_" / "+" / "`" / "'" / "~" )
 *   event-param      =  generic-param / ( "id" EQUAL token )
 * @endcode
 *
 */

static msg_xtra_f sip_event_dup_xtra;
static msg_dup_f sip_event_dup_one;
msg_hclass_t sip_event_class[] = 
SIP_HEADER_CLASS(event, "Event", "o", o_params, single, event);

static inline void sip_event_update(sip_event_t *o);

int sip_event_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_event_t *o = h->sh_event;
  int n;

  n = span_token(s); if (n == 0) return -1;
  o->o_type = s; s += n;
  while (IS_LWS(*s)) { *s++ = '\0'; }
  if (*s == ';') {
    if (msg_params_d(home, &s, &o->o_params) < 0 || *s)
      return -1;
    sip_event_update(o);
  }
  return 0;
}

int sip_event_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  char *end = b + bsiz, *b0 = b;
  sip_event_t const *o = h->sh_event;

  assert(sip_is_event(h));
  SIP_STRING_E(b, end, o->o_type);
  SIP_PARAMS_E(b, end, o->o_params, flags);

  return b - b0;
}

int sip_event_dup_xtra(sip_header_t const *h, int offset)
{
  sip_event_t const *o = h->sh_event;

  SIP_PARAMS_SIZE(offset, o->o_params);
  offset += SIP_STRING_SIZE(o->o_type);

  return offset;
}

/** Duplicate one sip_event_t object */ 
char *sip_event_dup_one(sip_header_t *dst, sip_header_t const *src,
			char *b, int xtra)
{
  sip_event_t *o_dst = dst->sh_event;
  sip_event_t const *o_src = src->sh_event;

  char *end = b + xtra;
  b = sip_params_dup(&o_dst->o_params, o_src->o_params, b, xtra);
  SIP_STRING_DUP(b, o_dst->o_type, o_src->o_type);
  if (o_dst->o_params)
    sip_event_update(o_dst);
  assert(b <= end);

  return b;
}

static inline void sip_event_update(sip_event_t *o)
{
  int i;

  if (o->o_params)
    for (i = 0; o->o_params[i]; i++) {
      if (strncasecmp(o->o_params[i], "id=", 3) == 0)
	o->o_id = o->o_params[i] + 3;
    }
}

/* ====================================================================== */

/**@SIP_HEADER sip_allow_events Allow-Event Header
 *
 * The Allow-Event header is used to indicate which events or classes of
 * events the notifier supports.  Its syntax is defined in [Events4.2.2]
 * (draft-ietf-sip-events-00.txt) as follows:
 * 
 * @code
 *    Allow-Events = ( "Allow-Events" | "u" ) ":" 1#event-type
 * @endcode
 *
 */

msg_hclass_t sip_allow_events_class[] = 
SIP_HEADER_CLASS_LIST(allow_events, "Allow-Events", "u", list);

int sip_allow_events_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return msg_list_d(home, h, s, slen);
}

int sip_allow_events_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_is_allow_events(h));
  return msg_list_e(b, bsiz, h, f);
}

/** Append an event to a Allow-Events header. */
int sip_allow_events_add(su_home_t *home, 
			 sip_allow_events_t *ae, 
			 char const *e)
{
  e = su_strdup(home, e);
  if (!e)
    return -1;
  return msg_params_replace(home, (sip_param_t **)&ae->k_items, e);
}

/* ====================================================================== */

/**@SIP_HEADER sip_subscription_state Subscription-State Header
 *
 * The Subscription-State header is used to indicate which State a
 * Application, associated with a certain dialogue, is in. Its syntax is
 * defined in [Events4.2.4] (draft-ietf-sip-events-03.txt) as follows:
 * 
 * @code
 *    Subscription-State =  ( "Subscription-State" ) ":" substate-value
 *                         *( ";" subexp-params )
 *    substate-value     = "active" | "pending" | "terminated" 
 *                         | extension-substate
 *    extension-substate = token
 * 
 *    subexp-params      = ("reason" "=" reason-value) 
 *                         | ("expires" "=" delta-seconds)
 *                         | ("retry-after" "=" delta-seconds) | generic-param
 *    reason-value       = "deactivated" | "probation" | "rejected"
 *                         | "timeout" | "giveup" | reason-extension
 *    reason-extension   = token
 * @endcode
 * 
 *
 * The sip_subscription_state_t is defined as follows.
 * @code
 * typedef struct sip_subscription_state_s
 * {
 *  sip_common_t        ss_common[1];
 *  sip_unknown_t      *ss_next;
 *  char const         *ss_substate;
 *  sip_param_t const  *ss_params; 
 *  sip_param_t         ss_reason; 
 *  sip_param_t         ss_expires;
 *  sip_param_t         ss_retry_after;
 * } sip_subscription_state_t;
 * @endcode
 */

static msg_xtra_f sip_subscription_state_dup_xtra;
static msg_dup_f sip_subscription_state_dup_one;

msg_hclass_t sip_subscription_state_class[] = 
SIP_HEADER_CLASS(subscription_state, "Subscription-State", "", 
		 ss_params, single, 
		 subscription_state);

static void sip_subscription_state_update(sip_header_t *h);

int sip_subscription_state_d(su_home_t *home, sip_header_t *h, 
			     char *s, int slen)
{
   sip_subscription_state_t *ss = h->sh_subscription_state;
   ss->ss_substate = s;
   
   skip_token(&s); /* forwards the pointer to the end of substate-value */
   if (s == ss->ss_substate)
     return -1;
   if (IS_LWS(*s))		
     *s++ = '\0';/* NUL-terminate substate */
   skip_lws(&s); /* Skip any extra white space (advance pointer) */
   
   /* check if parameters are present and if so parse them */
   if (*s  == ';' && msg_params_d(home, &s, &ss->ss_params) < 0)
     return -1;
   
   if (ss->ss_params)
     sip_subscription_state_update(h);

   return 0;
}

int sip_subscription_state_e(char b[], int bsiz, sip_header_t const *h, int flags)
{
  char *end = b + bsiz, *b0 = b;
  sip_subscription_state_t const *ss = h->sh_subscription_state;
   
  assert(sip_is_subscription_state(h));
   
  SIP_STRING_E(b, end, ss->ss_substate);
  SIP_PARAMS_E(b, end, ss->ss_params, flags);   

  return b - b0;   
}

int sip_subscription_state_dup_xtra(sip_header_t const *h, int offset)
{
   sip_subscription_state_t const *ss = h->sh_subscription_state;
   
   /* Calculates memory size occupied */
   SIP_PARAMS_SIZE(offset, ss->ss_params);
   offset += SIP_STRING_SIZE(ss->ss_substate);
   
   return offset;   
}

/** Duplicate one sip_subscription_state_t object */ 
char *sip_subscription_state_dup_one(sip_header_t *dst, sip_header_t const *src,
				     char *b, int xtra)
{
  sip_subscription_state_t *ss_dst = dst->sh_subscription_state;
  sip_subscription_state_t const *ss_src = src->sh_subscription_state;
  char *end = b + xtra;
   
  b = sip_params_dup(&ss_dst->ss_params, ss_src->ss_params, b, xtra);
  SIP_STRING_DUP(b, ss_dst->ss_substate, ss_src->ss_substate);
   
   if (ss_dst->ss_params)
     sip_subscription_state_update(dst);
   
   assert(b <= end);

   return b;   
}

inline
static void 
sip_subscription_state_param_update(sip_subscription_state_t *ss, 
				    char const *p)
{
   
   switch(p[0]) {
    case 'r':
      if (strncasecmp(p, "reason", 6) == 0)
	SIP_PARAM_MATCH(ss->ss_reason, p, "reason");
      else if (strncasecmp(p, "retry-after", 11) == 0)   
	SIP_PARAM_MATCH(ss->ss_retry_after, p, "retry-after");	
      break;
    case 'e':
      SIP_PARAM_MATCH(ss->ss_expires, p, "expires");
      break;
   }
   
}

static void sip_subscription_state_update(sip_header_t *h)
{
   sip_subscription_state_t *ss = h->sh_subscription_state;
   char const *p;
   char const *const *pp;
   
   if ((pp = ss->ss_params)) {
     while ((p = pp++[0]))
	sip_subscription_state_param_update(ss, p);
   }
}

#if 0				/* More dead headers */

/* ====================================================================== */

/**@SIP_HEADER sip_publication Publication Header
 *
 * The Publication header is used to indicate the which publication or class
 * of publications the message contains. Its syntax is defined
 * in (draft-niemi-simple-publish-00.txt) as follows:
 * 
 * @code
 *   Publication          =  ( "Publication") HCOLON publish-package
 *                         *( SEMI publish-param )
 *   publish-package      =  token-nodot
 *   token-nodot          =  1*( alphanum / "-"  / "!" / "%" / "*"
 *                               / "_" / "+" / "`" / "'" / "~" )
 *   publish-param        = generic-param / pstream / ptype
 *   pstream              = "stream" EQUAL token
 *   ptype                = "type" EQUAL token
 * @endcode
 *
 */

/**@ingroup sip_publication
 * @brief Structure for Publication header.
 */
struct sip_publication_s 
{
  sip_common_t        pub_common;	    /**< Common fragment info */
  sip_error_t        *pub_next;	            /**< Link to next (dummy) */
  char const *        pub_package;          /**< Publication packaage */
  sip_param_t const  *pub_params;	    /**< List of parameters */
  sip_param_t         pub_type; 	    /**< Publication type */
  sip_param_t         pub_stream;	    /**< Publication stream */
};

static msg_xtra_f sip_publication_dup_xtra;
static msg_dup_f sip_publication_dup_one;

msg_hclass_t sip_publication_class[] = 
SIP_HEADER_CLASS(publication, "Publication", "", pub_params, single, 
		 publication);

static inline void sip_publication_update(sip_publication_t *pub);

int sip_publication_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  sip_publication_t *pub = h->sh_publication;
  int n;

  n = span_token(s); if (n == 0) return -1;
  pub->pub_package = s; s += n;
  while (IS_LWS(*s)) { *s++ = '\0'; }
  if (*s == ';') {
    if (msg_params_d(home, &s, &pub->pub_params) < 0 || *s)
      return -1;
    sip_publication_update(pub);
  }
  return 0;
}

int sip_publication_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  char *end = b + bsiz, *b0 = b;
  sip_publication_t const *pub = h->sh_publication;

  assert(sip_is_publication(h));
  SIP_STRING_E(b, end, pub->pub_package);
  SIP_PARAMS_E(b, end, pub->pub_params, flags);

  return b - b0;
}

int sip_publication_dup_xtra(sip_header_t const *h, int offset)
{
  sip_publication_t const *pub = h->sh_publication;

  SIP_PARAMS_SIZE(offset, pub->pub_params);
  offset += SIP_STRING_SIZE(pub->pub_package);

  return offset;
}

/** Duplicate one sip_publication_t object */ 
char *sip_publication_dup_one(sip_header_t *dst, sip_header_t const *src,
			char *b, int xtra)
{
  sip_publication_t *pub_dst = dst->sh_publication;
  sip_publication_t const *pub_src = src->sh_publication;

  char *end = b + xtra;
  b = sip_params_dup(&pub_dst->pub_params, pub_src->pub_params, b, xtra);
  SIP_STRING_DUP(b, pub_dst->pub_package, pub_src->pub_package);
  if (pub_dst->pub_params)
    sip_publication_update(pub_dst);
  assert(b <= end);

  return b;
}

static inline void sip_publication_update(sip_publication_t *pub)
{
  int i;

  if (pub->pub_params)
    for (i = 0; pub->pub_params[i]; i++) {
      if (strncasecmp(pub->pub_params[i], "stream=", strlen("stream=")) == 0)
	pub->pub_stream = pub->pub_params[i] + strlen("stream=");
      else if (strncasecmp(pub->pub_params[i], "type=", strlen("type=")) == 0)
	pub->pub_type = pub->pub_params[i] + strlen("type=");
    }
}

/* ====================================================================== */

/**@SIP_HEADER sip_allow_publications Allow-Publication Header
 *
 * The Allow-Publication header is used to indicate which publications or classes of
 * publications the server supports.  Its syntax is defined in [niemi]
 * (draft-niemi-simple-publish-00.txt) as follows:
 * 
 * @code
 *   Allow-Publications   = "Allow-Publications" HCOLON publish-type 
 *                          * ( COMMA publish-type )
 * @endcode
 *
 */

msg_hclass_t sip_allow_publications_class[] = 
SIP_HEADER_CLASS_LIST(allow_publications, "Allow-Publications", "", list);

int sip_allow_publications_d(su_home_t *home, sip_header_t *h, char *s, int slen)
{
  return msg_list_d(home, h, s, slen);
}

int sip_allow_publications_e(char b[], int bsiz, sip_header_t const *h, int f)
{
  assert(sip_is_allow_publications(h));
  return msg_list_e(b, bsiz, h, f);
}

/** Append an publication to a Allow-Publications header. */
int sip_allow_publications_add(su_home_t *home, 
			       sip_allow_publications_t *ae, 
			       char const *e)
{
  e = su_strdup(home, e);
  if (!e)
    return -1;
  return msg_params_replace(home, (sip_param_t **)&ae->k_items, e);
}

#endif
