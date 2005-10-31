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

#ifndef NEA_H /** Defined when <nea.h> has been included. */
#define NEA_H
/**@file nea.h
 * @brief Event API for SIP
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti.Mela@nokia.com>
 *
 * @date Created: Fri Feb  7 13:23:44 EET 2003 ppessi
 *
 * @date Last modified: Mon Aug  8 19:10:00 2005 ppessi
 * 
 */

#ifndef SU_ALLOC_H
#include <su_alloc.h>
#endif

#include <su_tag.h>
#include <su_tag.h>

#ifndef NTA_H
#include <nta.h>
#endif

#define NEA_VERSION      3.0
#define NEA_VERSION_STR "3.0"

#define NEA_DEFAULT_EXPIRES 3600

#ifndef NEA_DLL
#ifndef WIN32
#define NEA_DLL
#else
#define NEA_DLL __declspec(dllimport)
#endif
#endif

/** Event notifier object. */
typedef struct nea_server_s     nea_server_t;

/** Subscription object. */
typedef struct nea_sub_s        nea_sub_t;

/** Event. */
typedef struct nea_event_s      nea_event_t;

/** Event view. */
typedef struct nea_event_view_s nea_event_view_t;

#ifndef NEA_SMAGIC_T 
#define NEA_SMAGIC_T            struct nea_smagic_t
#endif
/** NEA server context */
typedef NEA_SMAGIC_T nea_smagic_t;

#ifndef NEA_EMAGIC_T 
#define NEA_EMAGIC_T            struct nea_emagic_t
#endif
/** NEA server event context */
typedef NEA_EMAGIC_T nea_emagic_t;

#ifndef NEA_EVMAGIC_T 
#define NEA_EVMAGIC_T           struct nea_evmagic_t
#endif
/** Event view context */
typedef NEA_EVMAGIC_T nea_evmagic_t;

/** Event states */
typedef enum {
  nea_extended = -1,
  nea_embryonic = 0,		/** Before first notify */
  nea_pending,
  nea_active,
  nea_terminated
} nea_state_t;

/** Description of subscription */
typedef struct nea_subnode_t {
  nea_state_t          sn_state;       	/**< Subscription state */
  unsigned             sn_fake;	       	/**< True if subscriber is given 
				       	 *   fake contents.
				       	 */
  unsigned             sn_eventlist;    /**< Subscriber supports eventlist */
  nea_sub_t           *sn_subscriber;  	/**< Pointer to subscriber object */
  nea_event_t         *sn_event;       	/**< Event */
  sip_from_t const    *sn_remote;      	/**< Identity of subscriber */
  sip_contact_t const *sn_contact;     	/**< Contact of subscriber */

  /** Content-Type of SUBSCRIBE body (filter). */
  sip_content_type_t const *sn_content_type; 
  sip_payload_t const *sn_payload;      /**< Body of subscribe*/

  unsigned             sn_expires;     	/**< When subscription expires */
  unsigned             sn_latest;      	/**< Latest notification version */
  unsigned             sn_throttle;    	/**< Throttle value */
  unsigned             sn_version;      /**< Version # by application */
  sip_time_t           sn_notified;     /**< When latest notify was sent */
  sip_time_t           sn_subscribed;   /**< When first SUBSCRIBE was recv */
  nea_event_view_t    *sn_view;		/**< Primary event view */
} nea_subnode_t;

/** Multiple content types per event. */
typedef struct nea_payloads_s   nea_payloads_t;

/**Unknown event callback.
 *
 * The event server invokes this callback function when it has received a
 * request for an unknown event or event with unknown content type.
 *
 * The callback may be called twice for one watcher, once for an unknown
 * event, another time for an unknown content type.
 *
 * @retval 1 application takes care of responding to request
 * @retval 0 application has added new event or payload format
 * @retval -1 nea server rejects request 
 */
typedef int (nea_new_event_f)(nea_smagic_t *context,
			      nea_server_t *nes,
			      nea_event_t **event_p,
			      nea_event_view_t **view_p,
			      nta_incoming_t *irq,
			      sip_t const *sip);

/** Create a notifier server */
nea_server_t *nea_server_create(nta_agent_t *agent,
				su_root_t *root,
				url_t const *url,
				int max_subs,
				nea_new_event_f *callback,
				nea_smagic_t *context,
				tag_type_t tag, tag_value_t value,
				...);

/** Specify the minimum duration of a subscription (by default, 15 minutes) */
#define NEATAG_MIN_EXPIRES(x) neatag_min_expires, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_min_expires;

#define NEATAG_MIN_EXPIRES_REF(x) neatag_min_expires_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_min_expires_ref;

#define NEATAG_MINSUB(x) neatag_min_expires, tag_uint_v((x))
#define NEATAG_MINSUB_REF(x) neatag_min_expires_ref, tag_uint_vr((&x))

/** Specify the default duration of a subscription (by default, 60 minutes) */
#define NEATAG_EXPIRES(x) neatag_expires, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_expires;

#define NEATAG_EXPIRES_REF(x) neatag_expires_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_expires_ref;

/** Specify the maximum duration of a subscription (by default, 24 hours) */
#define NEATAG_MAX_EXPIRES(x) neatag_max_expires, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_max_expires;

#define NEATAG_MAX_EXPIRES_REF(x) neatag_max_expires_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_max_expires_ref;

/** Indicate/require support for "eventlist" feature. */
#define NEATAG_EVENTLIST(x)  neatag_eventlist, tag_bool_v((x))
NEA_DLL extern tag_typedef_t neatag_eventlist;

#define NEATAG_EVENTLIST_REF(x) neatag_eventlist_ref, tag_bool_vr((&x))
NEA_DLL extern tag_typedef_t neatag_eventlist_ref;

/** Specify the default throttle value for subscription. */
#define NEATAG_THROTTLE(x) neatag_throttle, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_throttle;

#define NEATAG_THROTTLE_REF(x) neatag_throttle_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_throttle_ref;

/** Specify the minimum throttle value for subscription. */
#define NEATAG_MINTHROTTLE(x) neatag_minthrottle, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_minthrottle;

#define NEATAG_MINTHROTTLE_REF(x) neatag_minthrottle_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_minthrottle_ref;

/** Specify dialog handle */
#define NEATAG_DIALOG(x)     neatag_dialog, tag_ptr_v((x))
NEA_DLL extern tag_typedef_t neatag_dialog;

#define NEATAG_DIALOG_REF(x) neatag_dialog_ref, tag_ptr_vr((&x), (x))
NEA_DLL extern tag_typedef_t neatag_dialog_ref;

/** Shutdown an event server */
int nea_server_shutdown(nea_server_t *nes, int retry_after);

/** Destroy a server */
void nea_server_destroy(nea_server_t *nes);

/** Zap terminated subscribtions. */
void nea_server_flush(nea_server_t *nes, nea_event_t *event);

/** Update event information */
int nea_server_update(nea_server_t *nes,
		      nea_event_t *ev,
		      tag_type_t tag,
		      tag_value_t value,
		      ...);

/** Add a new subscriber to existing notifier */
int nea_server_add(nea_server_t *nes, 
		   sip_contact_t const *local_target,
		   msg_t *msg, 
		   sip_t *sip);

/** Add a new subscriber to existing notifier. */
int nea_server_add_irq(nea_server_t *nes,
		       nta_leg_t *leg,
		       sip_contact_t const *local_target,
		       nta_incoming_t *irq, 
		       sip_t const *sip);

/** QAUTH callback function type.
 *
 * The event server invokes this callback function upon each incoming
 * SUBSCRIBE transaction when the subscription has expired.  The @a sip is
 * NULL if the subscription has expired.
 *
 * The application determines if the subscription is authorized and relays
 * the decision to event server via nea_server_auth() function.
 */
typedef void (nea_watcher_f)(nea_server_t *nes,
			     nea_emagic_t *context,
			     nea_event_t *event,
			     nea_subnode_t *subnode,
			     sip_t const *sip);

/** Create a new event (or subevent) */
nea_event_t *nea_event_create(nea_server_t *nes,
			      nea_watcher_f *callback,
			      nea_emagic_t *context,
			      char const *name, 
			      char const *subname,
			      char const *default_content_type,
			      char const *accept);

/** Create a new event (or subevent) with tags */
nea_event_t *nea_event_tcreate(nea_server_t *nes,
			       nea_watcher_f *callback,
			       nea_emagic_t *context,
			       char const *name, 
			       char const *subname,
			       tag_type_t, tag_value_t, ...);

/** Return magic context bind to nea_event */
nea_emagic_t *nea_emagic_get(nea_event_t *event);

/** Find a nea event object with given event name */
nea_event_t *nea_event_get(nea_server_t const *nes, char const *name);

/** Get number of active subscribers */
int nea_server_active(nea_server_t *nes, nea_event_t const *ev);

/** Get number of (non-embryonic) subscribers. */
int nea_server_non_embryonic(nea_server_t *nes, nea_event_t const *ev);

/** Obtain a list of subscriptions. 
 */
nea_subnode_t const **nea_server_get_subscribers(nea_server_t *nes, 
						 nea_event_t const *ev);

/** Free a list of subscriptions. */
void nea_server_free_subscribers(nea_server_t *nes, nea_subnode_t const **);

/** Notify subscribers */
int nea_server_notify(nea_server_t *nes, 
		      nea_event_t *ev);

/** Notify a subscriber */
int nea_server_notify_one(nea_server_t *nes, 
			  nea_event_t *ev,
			  nea_sub_t *ns);

#define nea_server_auth nea_sub_auth

/** Authorize a subscription */
int nea_sub_auth(nea_sub_t *, nea_state_t state,
		 tag_type_t, tag_value_t, ...);

/** Set subscriber version sequence */
int nea_sub_version(nea_sub_t *, unsigned);

/** Return time until next notification can be sent */
unsigned nea_sub_pending(nea_sub_t const *);

/** Send fake content for this subscriber */
#define NEATAG_FAKE(x)    neatag_fake, tag_bool_v((x))
NEA_DLL extern tag_typedef_t neatag_fake;

#define NEATAG_FAKE_REF(x) neatag_fake_ref, tag_bool_vr((&x))
NEA_DLL extern tag_typedef_t neatag_fake_ref;

/** Specify reason for termination */
#define NEATAG_REASON(x)     neatag_reason, tag_str_v((x))
NEA_DLL extern tag_typedef_t neatag_reason;

#define NEATAG_REASON_REF(x) neatag_reason_ref, tag_str_vr((&x))
NEA_DLL extern tag_typedef_t neatag_reason_ref;

/** Specify retry-after for termination */
#define NEATAG_RETRY_AFTER(x)    neatag_retry_after, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_retry_after;

#define NEATAG_RETRY_AFTER_REF(x) neatag_retry_after_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_retry_after_ref;

/** Specify extended state for subscription-state */
#define NEATAG_EXSTATE(x)    neatag_exstate, tag_str_v((x))
NEA_DLL extern tag_typedef_t neatag_exstate;

#define NEATAG_EXSTATE_REF(x) neatag_exstate_ref, tag_str_vr((&x))
NEA_DLL extern tag_typedef_t neatag_exstate_ref;

/** Do not try to conform pre-3265 notifiers/watchers */
#define NEATAG_STRICT_3265(x)    neatag_strict_3265, tag_bool_v((x))
NEA_DLL extern tag_typedef_t neatag_strict_3265;

#define NEATAG_STRICT_3265_REF(x) neatag_strict_3265_ref, tag_bool_vr((&x))
NEA_DLL extern tag_typedef_t neatag_strict_3265_ref;

/** Version number of content */
#define NEATAG_VERSION(x) neatag_version, tag_uint_v((x))
NEA_DLL extern tag_typedef_t neatag_version;

#define NEATAG_VERSION_REF(x) neatag_version_ref, tag_uint_vr((&x))
NEA_DLL extern tag_typedef_t neatag_version_ref;

#if 0
/** Do a remote qauth.
 *
 * The function nea_server_qauth() is given as q_callback pointer 
 * to nea_server_create() if remote authentication from url is desired.
 */
void nea_server_qauth(nea_server_t *nes, 
		      nea_emagic_t *context,
		      nea_sub_t *subscriber, 
		      sip_t const *sip);
#endif

/** Get primary event view for given content type  */
nea_event_view_t *nea_event_view(nea_event_t *, char const *content_type);

/** Get a content type for event's payload */
sip_content_type_t const *nea_view_content_type(nea_event_view_t const *);

/** Get actual payload for an event */
sip_payload_t const *nea_view_payload(nea_event_view_t *);

/** Create a private event view */
nea_event_view_t *nea_view_create(nea_server_t *nes,
				  nea_event_t *ev,
				  nea_evmagic_t *magic,
				  tag_type_t tag,
				  tag_value_t value,
				  ...);

/** Destroy a private event view */
void nea_view_destroy(nea_server_t *nes, nea_event_view_t *ev);

nea_evmagic_t *nea_view_magic(nea_event_view_t const *);

void nea_view_set_magic(nea_event_view_t *evv, nea_evmagic_t *magic);

unsigned nea_view_version(nea_event_view_t const *);

/** Reliable notify */
#define NEATAG_RELIABLE(x)    neatag_reliable, tag_bool_v((x))
NEA_DLL extern tag_typedef_t neatag_reliable;

#define NEATAG_RELIABLE_REF(x) neatag_reliable_ref, tag_bool_vr((&x))
NEA_DLL extern tag_typedef_t neatag_reliable_ref;

/** Event view handle */
#define NEATAG_VIEW(x)     neatag_view, tag_ptr_v((x))
NEA_DLL extern tag_typedef_t neatag_view;

#define NEATAG_VIEW_REF(x) neatag_view_ref, tag_ptr_vr((&x), (x))
NEA_DLL extern tag_typedef_t neatag_view_ref;

/** Event view magic. */
#define NEATAG_EVMAGIC(x)     neatag_evmagic, tag_ptr_v((x))
NEA_DLL extern tag_typedef_t neatag_evmagic;

#define NEATAG_EVMAGIC_REF(x) neatag_evmagic_ref, tag_ptr_vr((&x), (x))
NEA_DLL extern tag_typedef_t neatag_evmagic_ref;

/* ====================================================================== */
/* Watcher side */

/** NEA Event Watcher */
typedef struct nea_s     nea_t;

#ifndef NEA_MAGIC_T 
#define NEA_MAGIC_T struct nea_magic_t
#endif

/** NEA Event Agent context */
typedef NEA_MAGIC_T          nea_magic_t;

/** Event notification callback type.
 * 
 * This callback is called also when initial or refresh subscribe transaction
 * completes with the transaction result in @a sip.
 */
typedef int (*nea_notify_f)(nea_t *nea,
			    nea_magic_t *context,
			    sip_t const *sip);

/* ====================================================================== */
/* Client side */

/** Create a subscription agent. */
nea_t *nea_create(nta_agent_t *agent,
		  su_root_t *root,
		  nea_notify_f no_callback,
		  nea_magic_t *context,
		  tag_type_t tag,
		  tag_value_t value,
		  ...);

/** Update SUBSCRIBE payload (filter rules) */
extern int nea_update(nea_t *nea, 
		      tag_type_t tag,
		      tag_value_t value,
		      ...);

/** Unsubscribe agent. */
void nea_end(nea_t *agent);

/** Destroy a subscription agent. */
void nea_destroy(nea_t *agent);

char const *nea_default_content_type(char const *event);

#endif /* !defined(NEA_H) */
