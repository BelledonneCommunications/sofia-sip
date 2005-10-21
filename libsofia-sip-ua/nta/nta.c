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

/**@CFILE nta.c
 * @brief Nokia SIP Transaction API implementation
 * 
 * This source file has been divided into sections as follows:
 * 1) agent
 * 2) tport handling
 * 3) dispatching messages received from network
 * 4) message creation, message utility
 * 5) stateless operation
 * 6) dialogs (legs)
 * 7) server transactions (incoming)
 * 8) client transactions (outgoing)
 * 9) resolving URLs for client transactions
 * 10) 100rel reliable responses (reliable)
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Tue Jun 13 02:57:51 2000 ppessi
 */

#include "config.h"

/* From AM_INIT/AC_INIT in our "config.h" */
char const nta_version[] = VERSION;

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>

#include <string0.h>

/** @internal SU message argument structure type */
#define SU_MSG_ARG_T   union sm_arg_u
/** @internal SU timer argument pointer type */
#define SU_TIMER_ARG_T struct nta_agent_s

#include <su_alloc.h>
#include <su.h>
#include <su_time.h>
#include <su_tagarg.h>

#include <base64.h>
#include <su_uniqueid.h>

#include <sip.h>
#include <sip_header.h>
#include <sip_util.h>
#include <sip_status.h>

#include <msg_addr.h>

#define nta_agent_create _public_nta_agent_create
#include "nta_internal.h"
#undef nta_agent_create
#include "url_tag.h"

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
static char const __func__[] = "nta";
#endif

#define NONE ((void *)-1)

/* Internal tags */

/** Delay sending of request */
#define NTATAG_DELAY_SENDING(x) ntatag_delay_sending, tag_bool_v((x))
#define NTATAG_DELAY_SENDING_REF(x) \
ntatag_delay_sending_ref, tag_bool_vr(&(x))

extern tag_typedef_t ntatag_delay_sending;
extern tag_typedef_t ntatag_delay_sending_ref;

/** Allow sending incomplete responses */
#define NTATAG_INCOMPLETE(x) ntatag_incomplete, tag_bool_v((x))
#define NTATAG_INCOMPLETE_REF(x) \
ntatag_incomplete_ref, tag_bool_vr(&(x))

extern tag_typedef_t ntatag_incomplete;
extern tag_typedef_t ntatag_incomplete_ref;

/* Agent */
static int agent_tag_init(nta_agent_t *self);
static int agent_timer_init(nta_agent_t *agent);
static void agent_timer(su_root_magic_t *rm, su_timer_t *, nta_agent_t *);
static int agent_launch_terminator(nta_agent_t *agent);
static void agent_kill_terminator(nta_agent_t *agent);
static int agent_set_params(nta_agent_t *agent, tagi_t *tags);
static void agent_set_udp_params(nta_agent_t *self, unsigned udp_mtu);
static int agent_get_params(nta_agent_t *agent, tagi_t *tags);

/* Transport interface */
static sip_via_t const *agent_tport_via(tport_t *tport);
static int agent_insert_via(nta_agent_t *, msg_t *, sip_via_t const *,
			    char const *branch, int user_via);
static int nta_tpn_by_via(tp_name_t *tpn, sip_via_t const *v, int *using_rport);

static msg_t *nta_msg_create_for_transport(nta_agent_t *agent, int flags,
					   char const data[], unsigned dlen);

#if HAVE_SIGCOMP
#include <sigcomp.h>

static int agent_sigcomp_options(nta_agent_t *agent, 
				 struct sigcomp_compartment *);

static
struct sigcomp_compartment *
agent_sigcomp_compartment(nta_agent_t *sa, tport_t *tp, tp_name_t const *tpn);

static
struct sigcomp_compartment *
agent_sigcomp_compartment_ref(nta_agent_t *sa, 
			      tport_t *tp,
			      tp_name_t const *tpn,
			      int create_if_needed);

static
int agent_sigcomp_accept(nta_agent_t *sa, tport_t *tp, msg_t *msg);

/* These macros are used in order to avoid #if HAVE_SIGCOMP #endif's */ 
#define IF_SIGCOMP_TPTAG_COMPARTMENT(cc)     TAG_IF(cc, TPTAG_COMPARTMENT(cc)),
#define IF_SIGCOMP_TPTAG_COMPARTMENT_REF(cc) TPTAG_COMPARTMENT_REF(cc),
#else
#define IF_SIGCOMP_TPTAG_COMPARTMENT(cc)
#define IF_SIGCOMP_TPTAG_COMPARTMENT_REF(cc)

#define agent_sigcomp_accept NULL
#endif

static sip_param_t stateful_branch(su_home_t *home, nta_agent_t *);
static sip_param_t stateless_branch(nta_agent_t *, msg_t *, sip_t const *,
				    tp_name_t const *tp);

#define NTA_BRANCH_PRIME SU_U64_C(0xB9591D1C361C6521)
#define NTA_TAG_PRIME    SU_U64_C(0xB9591D1C361C6521)

HTABLE_PROTOS(leg_htable, lht, nta_leg_t);
static nta_leg_t *leg_find(nta_agent_t const *sa,
			   char const *method_name,
			   url_t const *request_uri,
			   sip_call_id_t const *i,
			   char const *from_tag,
			   url_t const *from_uri,
			   char const *to_tag,
			   url_t const *to_uri);
static nta_leg_t *dst_find(nta_agent_t const *sa, url_t const *u0,
			   char const *method);
static void leg_recv(nta_leg_t *, msg_t *, sip_t *, tport_t *);
static void leg_free(nta_agent_t *sa, nta_leg_t *leg);

#define NTA_HASH(i, cs) ((i)->i_hash + 26839U * (uint32_t)(cs))

HTABLE_PROTOS(incoming_htable, iht, nta_incoming_t);
static nta_incoming_t *incoming_create(nta_agent_t *agent,
				       msg_t *request,
				       sip_t *sip,
				       tport_t *tport,
				       char const *tag);
static int incoming_callback(nta_leg_t *leg, nta_incoming_t *irq, sip_t *sip);
static void incoming_free(nta_incoming_t *irq);
static inline void incoming_cut_off(nta_incoming_t *irq);
static inline void incoming_reclaim(nta_incoming_t *irq);
static void incoming_queue_init(incoming_queue_t *, 
				unsigned timeout);
static void incoming_queue_adjust(nta_agent_t *sa, 
				  incoming_queue_t *queue, 
				  unsigned timeout);

static inline
nta_incoming_t *incoming_find(nta_agent_t const *agent, sip_t const *sip,
			      sip_via_t const *v,
			      nta_incoming_t **merge,
			      nta_incoming_t **ack);
static int incoming_reply(nta_incoming_t *irq, msg_t *msg, sip_t *sip);
static inline int incoming_recv(nta_incoming_t *irq, msg_t *msg, sip_t *sip,
				tport_t *tport);
static inline int incoming_ack(nta_incoming_t *irq, msg_t *msg, sip_t *sip,
			       tport_t *tport);
static inline int incoming_cancel(nta_incoming_t *irq, msg_t *msg, sip_t *sip,
				  tport_t *tport);
static inline int incoming_merge(nta_incoming_t *irq, msg_t *msg, sip_t *sip,
				 tport_t *tport);
static inline int incoming_timestamp(nta_incoming_t *, msg_t *, sip_t *);
static inline int incoming_timer(nta_agent_t *, su_duration_t);

static nta_reliable_t *reliable_mreply(nta_incoming_t *,
				       nta_prack_f *, nta_reliable_magic_t *,
				       msg_t *, sip_t *);
static int reliable_send(nta_incoming_t *, nta_reliable_t *, msg_t *, sip_t *);
static int reliable_final(nta_incoming_t *irq, msg_t *msg, sip_t *sip);
static msg_t *reliable_response(nta_incoming_t *irq);
static int reliable_recv(nta_incoming_t *, msg_t *, sip_t *, tport_t *);
static void reliable_flush(nta_incoming_t *irq);
static void reliable_timeout(nta_incoming_t *irq, int timeout);

HTABLE_PROTOS(outgoing_htable, oht, nta_outgoing_t);
static nta_outgoing_t *outgoing_create(nta_agent_t *agent,
				       nta_response_f *callback,
				       nta_outgoing_magic_t *magic,
				       url_string_t const *route_url,
				       tp_name_t const *tpn,
				       msg_t *msg,
				       tag_type_t tag, tag_value_t value, ...);
static void outgoing_queue_init(outgoing_queue_t *, 
				unsigned timeout);
static void outgoing_queue_adjust(nta_agent_t *sa, 
				  outgoing_queue_t *queue, 
				  unsigned timeout);
static void outgoing_free(nta_outgoing_t *orq);
static inline void outgoing_cut_off(nta_outgoing_t *orq);
static inline void outgoing_reclaim(nta_outgoing_t *orq);
static nta_outgoing_t *outgoing_find(nta_agent_t const *sa,
				     msg_t const *msg,
				     sip_t const *sip,
				     sip_via_t const *v);
static int outgoing_recv(nta_outgoing_t *orq, int status, msg_t *, sip_t *);
static inline int outgoing_timer(nta_agent_t *, su_duration_t);
static int outgoing_recv_reliable(nta_outgoing_t *orq, msg_t *msg, sip_t *sip);

/* Internal message passing */
union sm_arg_u {
  struct leg_recv_s {
    nta_leg_t    *leg;
    msg_t        *msg;
    tport_t      *tport;
  } a_leg_recv[1];

  struct outgoing_recv_s {
    nta_outgoing_t *orq;
    msg_t          *msg;
    sip_t          *sip;
    int             status;
  } a_outgoing_recv[1];

  incoming_queue_t a_incoming_queue[1];
  outgoing_queue_t a_outgoing_queue[1];
};

/* Global module data */

/**@var NTA_DEBUG
 *
 * Environment variable determining the default debug log level.
 *
 * The NTA_DEBUG environment variable is used to determine the default
 * debug logging level. The normal level is 3.
 * 
 * @sa <su_debug.h>, su_log_global, SOFIA_DEBUG
 */
extern char const NTA_DEBUG[];

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif

/**Debug log for @b nta module. 
 * 
 * The nta_log is the log object used by @b nta module. The level of
 * #nta_log is set using #NTA_DEBUG environment variable.
 */
su_log_t nta_log[] = { SU_LOG_INIT("nta", "NTA_DEBUG", SU_DEBUG) };

/* ====================================================================== */
/* 1) Agent */

/**
 * Create an NTA agent object.
 *
 * The function nta_agent_create() creates an NTA agent object.  The agent
 * object creates and binds a server socket with address specified in @e url.
 * If the @e host portion of the @e url is @c "*", the agent listens to all
 * addresses available on the host.
 *
 * When a message is received, the agent object parses it.  If the result is
 * a valid SIP message, the agent object passes the message to the
 * application by invoking the nta_message_f @e callback function.
 *
 * @note
 * The @e url can be either parsed url (of type url_t ()), or a valid
 * SIP URL as a string.
 *
 * @note
 * If @e url is @c NULL, the default @e url @c "sip:*" is used.
 * @par
 * If @p transport parameters are specified in @a url, agent uses only
 * specified transport type.
 *
 * @par
 * If an @p maddr parameter is specified in @e url, agent binds to the
 * specified address, but uses @e host part of @e url in @b Contact and @b
 * Via headers.  The @p maddr parameter is also included, unless it equals
 * to @c INADDR_ANY (@p 0.0.0.0 or @p [::]).
 *
 * @param root          pointer to a su_root_t used for synchronization
 * @param contact_url   URL that agent uses to bind the server sockets
 * @param callback      pointer to callback function
 * @param magic         pointer to user data
 * @param tag,value,... other arguments
 *
 * @note It is possible to provide -1 as @a contact_url.
 * 
 * @retval handle to the agent when successful,
 * @retval NULL upon an error.
 *
 */
nta_agent_t *nta_agent_create(su_root_t *root,
			      url_string_t const *contact_url,
			      nta_message_f *callback,
			      nta_agent_magic_t *magic,
			      /* tag and value are missing from public signature */
			      tag_type_t tag, tag_value_t value, ...)
{
  nta_agent_t *agent;
  ta_list ta;

  if (root == NULL)
    return su_seterrno(EINVAL), NULL;

  ta_start(ta, tag, value);

  if ((agent = su_home_new(sizeof(*agent)))) {
    agent->sa_root = root;
    agent->sa_callback = callback;
    agent->sa_magic = magic;
    agent->sa_flags = MSG_DO_CANONIC;

    agent->sa_maxsize         = 2 * 1024 * 1024;
    agent->sa_t1 	      = NTA_SIP_T1;
    agent->sa_t2 	      = NTA_SIP_T2;
    agent->sa_t4              = NTA_SIP_T4;
    agent->sa_t1x64 	      = 64 * NTA_SIP_T1;
    agent->sa_drop_prob       = 0;
    agent->sa_is_a_uas        = 0;
    agent->sa_progress        = 60 * 1000;
    agent->sa_user_via        = 0;
    agent->sa_extra_100       = 0;
    agent->sa_pass_100        = 0;
    agent->sa_timeout_408     = 1;
    agent->sa_pass_408        = 0;
    agent->sa_merge_482       = 0;
    agent->sa_cancel_2543     = 0;
    agent->sa_cancel_487      = 1;
    agent->sa_invite_100rel   = 0;
    agent->sa_timestamp       = 0;
    agent->sa_use_naptr       = 1;
    agent->sa_use_srv         = 1;
    agent->sa_auto_comp       = 0;
    agent->sa_server_rport    = 1;

    /* RFC 3261 section 8.1.1.6 */
    sip_max_forwards_init(agent->sa_max_forwards)->mf_count = 70;

    if (getenv("SIPCOMPACT"))
      agent->sa_flags |= MSG_DO_COMPACT;

    agent_set_params(agent, ta_args(ta));

    if (agent->sa_mclass == NULL)
      agent->sa_mclass = sip_default_mclass();

    agent->sa_in.re_t1 = &agent->sa_in.re_list;
    
    incoming_queue_init(agent->sa_in.proceeding, 0);
    incoming_queue_init(agent->sa_in.preliminary, agent->sa_t1x64); /* P1 */
    incoming_queue_init(agent->sa_in.inv_completed, agent->sa_t1x64); /* H */
    incoming_queue_init(agent->sa_in.inv_confirmed, agent->sa_t4); /* I */
    incoming_queue_init(agent->sa_in.completed, agent->sa_t1x64); /* J */
    incoming_queue_init(agent->sa_in.terminated, 0);
    incoming_queue_init(agent->sa_in.final_failed, 0); 

    agent->sa_out.re_t1 = &agent->sa_out.re_list;

    outgoing_queue_init(agent->sa_out.delayed, 0);
    outgoing_queue_init(agent->sa_out.resolving, 0);
    outgoing_queue_init(agent->sa_out.trying, agent->sa_t1x64); /* F */
    outgoing_queue_init(agent->sa_out.completed, agent->sa_t4); /* K */
    outgoing_queue_init(agent->sa_out.terminated, 0); 
    /* Special queues (states) for outgoing INVITE transactions */
    outgoing_queue_init(agent->sa_out.inv_calling, agent->sa_t1x64); /* B */
    outgoing_queue_init(agent->sa_out.inv_proceeding, 0); 
    outgoing_queue_init(agent->sa_out.inv_completed, 32000); /* Timer D */

    if (leg_htable_resize(agent->sa_home, agent->sa_dialogs, 0) < 0 ||
	leg_htable_resize(agent->sa_home, agent->sa_defaults, 0) < 0 ||
	outgoing_htable_resize(agent->sa_home, agent->sa_outgoing, 0) < 0 ||
	incoming_htable_resize(agent->sa_home, agent->sa_incoming, 0) < 0) {
      SU_DEBUG_0(("nta_agent_create: failure with %s\n", "hash tables"));
      goto deinit;
    }
    SU_DEBUG_9(("nta_agent_create: initialized %s\n", "hash tables"));

    if (contact_url != (url_string_t *)-1 &&
	nta_agent_add_tport(agent, contact_url, ta_tags(ta)) < 0) {
      SU_DEBUG_7(("nta_agent_create: failure with %s\n", "transport"));
      goto deinit;
    }
    SU_DEBUG_9(("nta_agent_create: initialized %s\n", "transports"));

    if (agent_tag_init(agent) < 0) {
      SU_DEBUG_3(("nta_agent_create: failure with %s\n", "random identifiers"));
      goto deinit;
    }
    SU_DEBUG_9(("nta_agent_create: initialized %s\n", "random identifiers"));

    if (agent_timer_init(agent) < 0) {
      SU_DEBUG_0(("nta_agent_create: failure with %s\n", "timer"));
      goto deinit;
    }
    SU_DEBUG_9(("nta_agent_create: initialized %s\n", "timer"));

    if (agent_launch_terminator(agent) == 0)
      SU_DEBUG_9(("nta_agent_create: initialized %s\n", "threads"));

#if HAVE_SOFIA_SRESOLV
    agent->sa_resolver = sres_resolver_create(root, NULL, ta_tags(ta));
    if (!agent->sa_resolver) {
      SU_DEBUG_0(("nta_agent_create: failure with %s\n", "resolver"));
    }
    SU_DEBUG_9(("nta_agent_create: initialized %s\n", "resolver"));
#endif

    ta_end(ta);

    return agent;

  deinit:
    nta_agent_destroy(agent);
  }

  ta_end(ta);

  return NULL;
}

/**
 * Destroy an NTA agent object.
 *
 * @param agent the NTA agent object to be destroyed.
 *
 */
void nta_agent_destroy(nta_agent_t *agent)
{
  if (agent) {
    size_t i;
    outgoing_htable_t *oht = agent->sa_outgoing;
    incoming_htable_t *iht = agent->sa_incoming;
    /* Currently, this is pretty pointless, as legs don't keep any resources */
    leg_htable_t *lht;
    nta_leg_t *leg;

    for (i = 0, lht = agent->sa_dialogs; i < lht->lht_size; i++) {
      if ((leg = lht->lht_table[i])) {
	SU_DEBUG_3(("nta_agent_destroy: destroying dialog with <"
		    URL_PRINT_FORMAT ">\n",
		    URL_PRINT_ARGS(leg->leg_remote->a_url)));
	leg_free(agent, leg);
      }
    }

    for (i = 0, lht = agent->sa_defaults; i < lht->lht_size; i++) {
      if ((leg = lht->lht_table[i])) {
	SU_DEBUG_3(("%s: destroying leg for <" 
		    URL_PRINT_FORMAT ">\n",
		    __func__, URL_PRINT_ARGS(leg->leg_url)));
	leg_free(agent, leg);
      }
    }

    if (agent->sa_default_leg)
      leg_free(agent, agent->sa_default_leg);

    for (i = iht->iht_size; i-- > 0; )
      while (iht->iht_table[i]) {
	nta_incoming_t *irq = iht->iht_table[i];

	if (!irq->irq_destroyed)
	  SU_DEBUG_3(("%s: destroying %s server transaction from <"
		      URL_PRINT_FORMAT ">\n",
		      __func__, irq->irq_rq->rq_method_name,
		      URL_PRINT_ARGS(irq->irq_from->a_url)));

	incoming_free(irq);
      }

    for (i = oht->oht_size; i-- > 0;)
      while (oht->oht_table[i]) {
	nta_outgoing_t *orq = oht->oht_table[i];

	if (!orq->orq_destroyed)
	  SU_DEBUG_3(("%s: destroying %s client transaction to <"
		      URL_PRINT_FORMAT ">\n",
		      __func__, orq->orq_method_name,
		      URL_PRINT_ARGS(orq->orq_to->a_url)));

	outgoing_free(orq);
      }

    su_timer_destroy(agent->sa_timer), agent->sa_timer = NULL;

#   if HAVE_SOFIA_SRESOLV
    sres_resolver_destroy(agent->sa_resolver), agent->sa_resolver = NULL;
#   endif

    tport_destroy(agent->sa_tports), agent->sa_tports = NULL;

    agent_kill_terminator(agent);

    su_home_unref(agent->sa_home);
  }
}

/** Return agent context. */
nta_agent_magic_t *nta_agent_magic(nta_agent_t const *agent)
{
  return agent ? agent->sa_magic : NULL;
}

/** Return @b Contact header.
 *
 * The function nta_agent_contact() returns a @b Contact header, which can be
 * used to reach @a agent.
 *
 * @param agent NTA agent object
 *
 * @return The function nta_agent_contact() returns a sip_contact_t object
 * corresponding to the @a agent.
 *
 * User agents can insert the @b Contact header in the outgoing REGISTER,
 * INVITE, and ACK requests and replies to incoming INVITE and OPTIONS
 * transactions.
 *
 * Proxies can use the @b Contact header to create appropriate @b Record-Route
 * headers:
 * @code
 * r_r = sip_record_route_create(msg_home(msg),
 *	 			 sip->sip_request->rq_url,
 *				 contact->m_url);
 * @endcode
 */
sip_contact_t *nta_agent_contact(nta_agent_t const *agent)
{
  return agent ? agent->sa_contact : NULL;
}

/** Return a list of @b Via headers.
 *
 * The function nta_agent_via() returns @b Via headers for all activated
 * transport.
 *
 * @param agent NTA agent object
 *
 * @return The function nta_agent_via() returns a list of sip_via_t objects
 * used by the @a agent.
 */
sip_via_t *nta_agent_via(nta_agent_t const *agent)
{
  return agent ? agent->sa_vias : NULL;
}

/** Return @b User-Agent header.
 *
 * The function nta_agent_name() returns a @b User-Agent information with
 * NTA version.
 *
 * @param agent NTA agent object
 *
 * @return The function nta_agent_contact() returns a string containing the
 * @a agent version.
 */
char const *nta_agent_version(nta_agent_t const *agent)
{
  return "nta" "/" VERSION;
}

/** Initialize default tag */
static int agent_tag_init(nta_agent_t *self)
{
  sip_contact_t *m = self->sa_contact;
  uint32_t hash = 1;

  if (m) {

    if (m->m_url->url_user)
      hash = 914715421U * hash + msg_hash_string(m->m_url->url_user);
    if (m->m_url->url_host)
      hash = 914715421U * hash + msg_hash_string(m->m_url->url_host);
    if (m->m_url->url_port)
      hash = 914715421U * hash + msg_hash_string(m->m_url->url_port);
    if (m->m_url->url_params)
      hash = 914715421U * hash + msg_hash_string(m->m_url->url_params);
  }

  if (hash == 0)
    hash = 914715421U;

  self->sa_branch = NTA_BRANCH_PRIME * su_ntp_now();
  self->sa_branch *= hash;

  self->sa_tags = NTA_TAG_PRIME * self->sa_branch;

  if (!self->sa_tag_3261) {
    if (!(self->sa_2543_tag = nta_agent_newtag(self->sa_home, "tag=%s", self)))
      return -1;
  }

  return 0;
}

/** Initialize agent timer. */
static
int agent_timer_init(nta_agent_t *agent)
{
  return su_timer_set(agent->sa_timer =
		      su_timer_create(su_root_task(agent->sa_root),
				      NTA_SIP_T1 / 8),
		      agent_timer,
		      agent);
}

/**
 * Agent timer routine.
 */
static
void agent_timer(su_root_magic_t *rm, su_timer_t *timer, nta_agent_t *agent)
{
  su_duration_t now = su_time_ms(agent->sa_now = su_now());
  int again;

  now += now == 0;

  agent->sa_millisec = now;

  again = outgoing_timer(agent, now);
  again = incoming_timer(agent, now) || again;

  agent->sa_millisec = 0;

  if (again)
    su_timer_set_at(timer, agent_timer, agent, su_time_add(su_now(), 1));
  else
    su_timer_set(timer, agent_timer, agent);
}

/** Calculate nonzero value for timer */
static inline
su_duration_t set_timeout(nta_agent_t const *agent, su_duration_t offset)
{
  su_duration_t now;

#if 0
  if (agent->sa_millisec)
    now = agent->sa_millisec;
  else
#endif
    now = (su_duration_t)su_time_ms(su_now());

  now += offset;

  return now ? now : 1;
}


/** Return current timeval. */
su_time_t agent_now(nta_agent_t const *agent)
{
  return agent->sa_millisec ? agent->sa_now : su_now();
}


/** Launch transaction terminator task */
static
int agent_launch_terminator(nta_agent_t *agent)
{
#ifdef TPTAG_THRPSIZE
  if (agent->sa_tport_threadpool) {
    su_home_threadsafe(agent->sa_home);
    return su_clone_start(agent->sa_root, 
			  agent->sa_terminator,
			  NULL,
			  NULL,
			  NULL);
  }
#endif
  return -1;
}

/** Kill transaction terminator task */
static
void agent_kill_terminator(nta_agent_t *agent)
{
  su_clone_wait(agent->sa_root, agent->sa_terminator);
}


/**Set NTA Parameters.
 *
 * The nta_agent_set_params() function sets the stack parameters. The
 * parameters determine the way NTA handles the retransmissions, how long
 * NTA keeps transactions alive, does NTA apply proxy or user-agent logic to
 * INVITE transactions, or how the @b Via headers are generated.
 *
 * @note 
 * Setting the parameters NTATAG_MAXSIZE(), NTATAG_UDP_MTU(),
 * NTATAG_SIP_T1X64(), NTATAG_SIP_T1(), NTATAG_SIP_T2(), NTATAG_SIP_T4() to
 * 0 selects the default value.
 *
 * @TAGS
 * NTATAG_ALIASES(), NTATAG_BAD_REQ_MASK(), NTATAG_BAD_RESP_MASK(),
 * NTATAG_CANCEL_2543(), NTATAG_CANCEL_487(), NTATAG_DEBUG_DROP_PROB(),
 * NTATAG_DEFAULT_PROXY(), NTATAG_EXTRA_100(), NTATAG_MAXSIZE(),
 * NTATAG_UDP_MTU(), NTATAG_MERGE_482(), NTATAG_PASS_100(),
 * NTATAG_PRELOAD(), NTATAG_REL100(), NTATAG_RPORT(), NTATAG_SERVER_RPORT(), 
 * NTATAG_SIPFLAGS(), NTATAG_SIP_T1X64(), NTATAG_SIP_T1(), NTATAG_SIP_T2(),
 * NTATAG_SIP_T4(), NTATAG_SMIME(), NTATAG_STATELESS(), NTATAG_TAG_3261(),
 * NTATAG_TIMEOUT_408(), NTATAG_PASS_408(), NTATAG_UA(), NTATAG_USER_VIA(),
 * and NTATAG_USE_TIMESTAMP().
 */
int nta_agent_set_params(nta_agent_t *agent,
			 tag_type_t tag, tag_value_t value, ...)
{
  int retval;

  if (agent) {
    ta_list ta;
    ta_start(ta, tag, value);
    retval = agent_set_params(agent, ta_args(ta));
    ta_end(ta);
  } else {
    su_seterrno(EINVAL);
    retval = -1;
  }

  return retval;
}

/** Internal function for setting tags */
static
int agent_set_params(nta_agent_t *agent, tagi_t *tags)
{
  int n, m;
  unsigned bad_req_mask = agent->sa_bad_req_mask;
  unsigned bad_resp_mask = agent->sa_bad_resp_mask;
  unsigned maxsize    = agent->sa_maxsize;
  unsigned udp_mtu    = agent->sa_udp_mtu;
  unsigned sip_t1     = agent->sa_t1;
  unsigned sip_t2     = agent->sa_t2;
  unsigned sip_t4     = agent->sa_t4;
  unsigned sip_t1x64  = agent->sa_t1x64;
  unsigned blacklist  = agent->sa_blacklist;
  int ua              = agent->sa_is_a_uas;
  unsigned progress   = agent->sa_progress;
  int stateless       = agent->sa_is_stateless;
  unsigned drop_prob  = agent->sa_drop_prob;
  int user_via        = agent->sa_user_via;
  int extra_100       = agent->sa_extra_100;
  int pass_100        = agent->sa_pass_100;
  int timeout_408     = agent->sa_timeout_408;
  int pass_408        = agent->sa_pass_408;
  int merge_482       = agent->sa_merge_482;
  int cancel_2543     = agent->sa_cancel_2543;
  int cancel_487      = agent->sa_cancel_487;
  int tag_3261        = agent->sa_tag_3261;
  int invite_100rel   = agent->sa_invite_100rel;
  int use_timestamp   = agent->sa_timestamp;
  int use_naptr       = agent->sa_use_naptr;
  int use_srv         = agent->sa_use_srv;
  void *smime         = agent->sa_smime;
  uint32_t flags      = agent->sa_flags;
  int rport           = agent->sa_rport;
  int server_rport    = agent->sa_server_rport;
  unsigned preload         = agent->sa_preload;
  unsigned threadpool      = agent->sa_tport_threadpool;
#if HAVE_SIGCOMP
  char const *sigcomp = agent->sa_sigcomp_options;
  char const *algorithm = NONE;
#endif
  msg_mclass_t *mclass = NONE;
  sip_contact_t const *aliases = NONE;
  url_string_t const *proxy = NONE;
  tport_t *tport;

  su_home_t *home = agent->sa_home;

  n = tl_gets(tags,
	      NTATAG_MCLASS_REF(mclass),
	      NTATAG_BAD_REQ_MASK_REF(bad_req_mask),
	      NTATAG_BAD_RESP_MASK_REF(bad_resp_mask),
	      NTATAG_ALIASES_REF(aliases),
	      NTATAG_UA_REF(ua),
	      NTATAG_STATELESS_REF(stateless),
	      NTATAG_MAXSIZE_REF(maxsize),
	      NTATAG_UDP_MTU_REF(udp_mtu),
	      NTATAG_SIP_T1_REF(sip_t1),
	      NTATAG_SIP_T2_REF(sip_t2),
	      NTATAG_SIP_T4_REF(sip_t4),
	      NTATAG_SIP_T1X64_REF(sip_t1x64),
	      NTATAG_PROGRESS_REF(progress),
	      NTATAG_BLACKLIST_REF(blacklist),
	      NTATAG_DEBUG_DROP_PROB_REF(drop_prob),
	      NTATAG_USER_VIA_REF(user_via),
	      NTATAG_EXTRA_100_REF(extra_100),
	      NTATAG_PASS_100_REF(pass_100),
	      NTATAG_TIMEOUT_408_REF(timeout_408),
	      NTATAG_PASS_408_REF(pass_408),
	      NTATAG_MERGE_482_REF(merge_482),
	      NTATAG_DEFAULT_PROXY_REF(proxy),
	      NTATAG_CANCEL_2543_REF(cancel_2543),
	      NTATAG_CANCEL_487_REF(cancel_487),
	      NTATAG_TAG_3261_REF(tag_3261),
	      NTATAG_REL100_REF(invite_100rel),
	      NTATAG_USE_TIMESTAMP_REF(use_timestamp),
	      NTATAG_USE_NAPTR_REF(use_naptr),
	      NTATAG_USE_SRV_REF(use_srv),
#if HAVE_SOFIA_SMIME
	      NTATAG_SMIME_REF(smime),
#endif
	      NTATAG_SIPFLAGS_REF(flags),
	      NTATAG_RPORT_REF(rport),
	      NTATAG_SERVER_RPORT_REF(server_rport),
	      NTATAG_PRELOAD_REF(preload),
#ifdef TPTAG_THRPSIZE
	      /* If threadpool is enabled, start a separate "reaper thread" */
	      TPTAG_THRPSIZE_REF(threadpool),
#endif
#if HAVE_SIGCOMP
	      NTATAG_SIGCOMP_OPTIONS_REF(sigcomp),
	      NTATAG_SIGCOMP_ALGORITHM_REF(algorithm),
#endif
	      TAG_END());

  if (mclass != NONE)
    agent->sa_mclass = mclass ? mclass : sip_default_mclass();

  m = 0;
  for (tport = agent->sa_tports; tport; tport = tport_next(tport)) {
    m = tport_set_params(tport, TAG_NEXT(tags));
  }

  if (n == 0 || m == -1)
    return m;

  n += m;

  if (aliases != NONE) {
    sip_contact_t const *m, *m_next;

    m = agent->sa_aliases;
    agent->sa_aliases = sip_contact_dup(home, aliases);

    for (; m; m = m_next) {	/* Free old aliases */
      m_next = m->m_next;
      su_free(home, (void *)m);
    }
  }

  if (proxy != NONE) {
    url_t *dp = url_hdup(home, proxy->us_url);

    url_sanitize(dp);

    if (dp == NULL || dp->url_type == url_sip || dp->url_type == url_sips) {
      if (agent->sa_default_proxy)
	su_free(home, agent->sa_default_proxy);
      agent->sa_default_proxy = dp;
    }
    else
      n = -1;
  }

#if HAVE_SIGCOMP
  if (algorithm != NONE)
    agent->sa_algorithm = sigcomp_algorithm_by_name(algorithm);

  if (str0cmp(sigcomp, agent->sa_sigcomp_options)) {
    int msg_avlist_d(su_home_t *home, char **ss, msg_param_t const **pparams);
    char const * const *l = NULL;
    char *s = su_strdup(home, sigcomp);
    char *s1 = su_strdup(home, s), *s2 = s1;

    if (s && s2 && msg_avlist_d(home, &s2, &l) == 0 && *s2 == '\0') {
      su_free(home, (void *)agent->sa_sigcomp_options);
      su_free(home, (void *)agent->sa_sigcomp_option_list);
      agent->sa_sigcomp_options = s;
      agent->sa_sigcomp_option_free = s1;
      agent->sa_sigcomp_option_list = l;
    } else {
      su_free(home, s);
      su_free(home, s1);
      su_free(home, (void *)l);
      n = -1;
    }
  }
#endif

  if (maxsize == 0) maxsize = 2 * 1024 * 1024;
  if (maxsize > NTA_TIME_MAX) maxsize = NTA_TIME_MAX;
  agent->sa_maxsize = maxsize;

  if (udp_mtu == 0) udp_mtu = 1300;
  if (udp_mtu > 65535) udp_mtu = 65535;
  if (agent->sa_udp_mtu != udp_mtu)
    agent_set_udp_params(agent, udp_mtu);

  if (sip_t1 == 0) sip_t1 = NTA_SIP_T1;
  if (sip_t1 > NTA_TIME_MAX) sip_t1 = NTA_TIME_MAX;
  agent->sa_t1 = sip_t1;

  if (sip_t2 == 0) sip_t2 = NTA_SIP_T2;
  if (sip_t2 > NTA_TIME_MAX) sip_t2 = NTA_TIME_MAX;
  agent->sa_t2 = sip_t2;

  if (sip_t4 == 0) sip_t4 = NTA_SIP_T4;
  if (sip_t4 > NTA_TIME_MAX) sip_t4 = NTA_TIME_MAX;
  if (agent->sa_t4 != sip_t4) {
    incoming_queue_adjust(agent, agent->sa_in.inv_confirmed, sip_t4);
    outgoing_queue_adjust(agent, agent->sa_out.completed, sip_t4);
  }
  agent->sa_t4 = sip_t4;

  if (sip_t1x64 == 0) sip_t1x64 = NTA_SIP_T1 * 64;
  if (sip_t1x64 > NTA_TIME_MAX) sip_t1x64 = NTA_TIME_MAX;
  if (agent->sa_t1x64 != sip_t1x64) {
    incoming_queue_adjust(agent, agent->sa_in.preliminary, sip_t1x64);
    incoming_queue_adjust(agent, agent->sa_in.completed, sip_t1x64);
    incoming_queue_adjust(agent, agent->sa_in.inv_completed, sip_t1x64);
    outgoing_queue_adjust(agent, agent->sa_out.trying, sip_t1x64);
    outgoing_queue_adjust(agent, agent->sa_out.inv_calling, sip_t1x64);
  }
  agent->sa_t1x64 = sip_t1x64;
  agent->sa_blacklist = blacklist;

  if (progress == 0)
    progress = 60 * 1000;
  agent->sa_progress = progress;

  agent->sa_bad_req_mask = bad_req_mask;
  agent->sa_bad_resp_mask = bad_resp_mask;

  agent->sa_is_a_uas = ua != 0;
  agent->sa_is_stateless = stateless != 0;
  agent->sa_drop_prob = drop_prob < 1000 ? drop_prob : 1000;
  agent->sa_user_via = user_via != 0;
  agent->sa_extra_100 = extra_100 != 0;
  agent->sa_pass_100 = pass_100 != 0;
  agent->sa_timeout_408 = timeout_408 != 0;
  agent->sa_pass_408 = pass_408 != 0;
  agent->sa_merge_482 = merge_482 != 0;
  agent->sa_cancel_2543 = cancel_2543 != 0;
  agent->sa_cancel_487 = cancel_487 != 0;
  agent->sa_invite_100rel = invite_100rel != 0;
  agent->sa_timestamp = use_timestamp != 0;
  agent->sa_use_naptr = use_naptr != 0;
  agent->sa_use_srv = use_srv != 0;
  agent->sa_smime = smime;
  agent->sa_flags = flags & MSG_FLG_USERMASK;
  agent->sa_rport = rport != 0;
  agent->sa_server_rport = server_rport != 0;
  agent->sa_preload = preload;
  agent->sa_tport_threadpool = threadpool;

  agent->sa_tag_3261 = tag_3261;

  if (!tag_3261 && !agent->sa_2543_tag)
    agent->sa_2543_tag = nta_agent_newtag(home, "tag=%s", agent);

  return n;
}

static 
void agent_set_udp_params(nta_agent_t *self, unsigned udp_mtu)
{
  tport_t *tp;

  self->sa_udp_mtu = udp_mtu;

  /* Set via fields for the tports */
  for (tp = tport_primaries(self->sa_tports); tp; tp = tport_next(tp)) {
    if (strcasecmp(tport_name(tp)->tpn_proto, "udp") == 0)
      tport_set_params(tp,
		       TPTAG_TIMEOUT(2 * self->sa_t1x64),
		       TPTAG_MTU(self->sa_udp_mtu),
		       TAG_END());
  }
}

/**Get NTA Parameters.
 *
 * The nta_agent_get_params() function retrieves the stack parameters. The
 * parameters determine the way NTA handles the retransmissions, how long
 * NTA keeps transactions alive, does NTA apply proxy or user-agent logic to
 * INVITE transactions, or how the @b Via headers are generated.
 *
 * @TAGS
 * NTATAG_ALIASES_REF(), NTATAG_CANCEL_2543_REF(), NTATAG_CANCEL_487_REF(),
 * NTATAG_CONTACT_REF(), NTATAG_DEBUG_DROP_PROB_REF(),
 * NTATAG_DEFAULT_PROXY_REF(), NTATAG_EXTRA_100_REF(), NTATAG_MAXSIZE_REF(),
 * NTATAG_MERGE_482_REF(), NTATAG_PASS_100_REF(), NTATAG_PRELOAD_REF(),
 * NTATAG_REL100_REF(), NTATAG_RPORT_REF(), NTATAG_SIPFLAGS_REF(),
 * NTATAG_SIP_T1X64_REF(), NTATAG_SIP_T1_REF(), NTATAG_SIP_T2_REF(),
 * NTATAG_SIP_T4_REF(), NTATAG_SMIME_REF(), NTATAG_STATELESS_REF(),
 * NTATAG_TAG_3261_REF(), NTATAG_TIMEOUT_408_REF(), NTATAG_PASS_408_REF(),
 * NTATAG_UA_REF(), NTATAG_USER_VIA_REF(), and NTATAG_USE_TIMESTAMP_REF().
 *
 */
int nta_agent_get_params(nta_agent_t *agent,
			 tag_type_t tag, tag_value_t value, ...)
{
  int n;
  ta_list ta;

  if (agent) {
    ta_start(ta, tag, value);
    n = agent_get_params(agent, ta_args(ta));
    ta_end(ta);
  } else {
    su_seterrno(EINVAL);
    n = -1;
  }

  return n;
}

/** Get NTA parameters */
static
int agent_get_params(nta_agent_t *agent, tagi_t *tags)
{
  return
    tl_tgets(tags,
	     NTATAG_MCLASS(agent->sa_mclass),
	     NTATAG_CONTACT(agent->sa_contact),
	     NTATAG_ALIASES(agent->sa_aliases),
	     NTATAG_UA(agent->sa_is_a_uas),
	     NTATAG_STATELESS(agent->sa_is_stateless),
	     NTATAG_MAXSIZE(agent->sa_maxsize),
	     NTATAG_UDP_MTU(agent->sa_udp_mtu),
	     NTATAG_SIP_T1(agent->sa_t1),
	     NTATAG_SIP_T2(agent->sa_t2),
	     NTATAG_SIP_T4(agent->sa_t4),
	     NTATAG_SIP_T1X64(agent->sa_t1x64),
	     NTATAG_BLACKLIST(agent->sa_blacklist),
	     NTATAG_DEBUG_DROP_PROB(agent->sa_drop_prob),
	     NTATAG_USER_VIA(agent->sa_user_via),
	     NTATAG_EXTRA_100(agent->sa_extra_100),
	     NTATAG_PASS_100(agent->sa_pass_100),
	     NTATAG_TIMEOUT_408(agent->sa_timeout_408),
	     NTATAG_PASS_408(agent->sa_pass_408),
	     NTATAG_MERGE_482(agent->sa_merge_482),
	     NTATAG_DEFAULT_PROXY(agent->sa_default_proxy),
	     NTATAG_CANCEL_2543(agent->sa_cancel_2543),
	     NTATAG_CANCEL_487(agent->sa_cancel_487),
	     NTATAG_TAG_3261(agent->sa_tag_3261),
	     NTATAG_REL100(agent->sa_invite_100rel),
	     NTATAG_USE_TIMESTAMP(agent->sa_timestamp),
	     NTATAG_USE_NAPTR(agent->sa_use_naptr),
	     NTATAG_USE_SRV(agent->sa_use_srv),
#if HAVE_SOFIA_SMIME
	     NTATAG_SMIME(agent->sa_smime),
#endif
	     NTATAG_SIPFLAGS(agent->sa_flags),
	     NTATAG_RPORT(agent->sa_rport),
	     NTATAG_PRELOAD(agent->sa_preload),
#if HAVE_SIGCOMP
	     NTATAG_SIGCOMP_OPTIONS(agent->sa_sigcomp_options ?
				    agent->sa_sigcomp_options :
				    "sip"),
#endif
	     TAG_END());
}

/**Get NTA statistics.
 *
 * The nta_agent_get_stats() function retrieves the stack statistics.
 *
 * @TAGS
 * @TAG NTATAG_S_*
 *
 */
int nta_agent_get_stats(nta_agent_t *agent,
			tag_type_t tag, tag_value_t value, ...)
{
  int n;
  ta_list ta;

  if (!agent)
    return su_seterrno(EINVAL), -1;

  ta_start(ta, tag, value);

  n = tl_tgets(ta_args(ta),
	       NTATAG_S_IRQ_HASH(agent->sa_incoming->iht_size),
	       NTATAG_S_ORQ_HASH(agent->sa_outgoing->oht_size),
	       NTATAG_S_LEG_HASH(agent->sa_dialogs->lht_size),
	       NTATAG_S_IRQ_HASH_USED(agent->sa_incoming->iht_used),
	       NTATAG_S_ORQ_HASH_USED(agent->sa_outgoing->oht_used),
	       NTATAG_S_LEG_HASH_USED(agent->sa_dialogs->lht_used),
	       NTATAG_S_RECV_MSG(agent->sa_stats->as_recv_msg),
	       NTATAG_S_RECV_REQUEST(agent->sa_stats->as_recv_request),
	       NTATAG_S_RECV_RESPONSE(agent->sa_stats->as_recv_response),
	       NTATAG_S_BAD_MESSAGE(agent->sa_stats->as_bad_message),
	       NTATAG_S_BAD_REQUEST(agent->sa_stats->as_bad_request),
	       NTATAG_S_BAD_RESPONSE(agent->sa_stats->as_bad_response),
	       NTATAG_S_DROP_REQUEST(agent->sa_stats->as_drop_request),
	       NTATAG_S_DROP_RESPONSE(agent->sa_stats->as_drop_response),
	       NTATAG_S_CLIENT_TR(agent->sa_stats->as_client_tr),
	       NTATAG_S_SERVER_TR(agent->sa_stats->as_server_tr),
	       NTATAG_S_DIALOG_TR(agent->sa_stats->as_dialog_tr),
	       NTATAG_S_ACKED_TR(agent->sa_stats->as_acked_tr),
	       NTATAG_S_CANCELED_TR(agent->sa_stats->as_canceled_tr),
	       NTATAG_S_TRLESS_REQUEST(agent->sa_stats->as_trless_request),
	       NTATAG_S_TRLESS_TO_TR(agent->sa_stats->as_trless_to_tr),
	       NTATAG_S_TRLESS_RESPONSE(agent->sa_stats->as_trless_response),
	       NTATAG_S_TRLESS_200(agent->sa_stats->as_trless_200),
	       NTATAG_S_MERGED_REQUEST(agent->sa_stats->as_merged_request),
	       NTATAG_S_SENT_MSG(agent->sa_stats->as_sent_msg),
	       NTATAG_S_SENT_REQUEST(agent->sa_stats->as_sent_request),
	       NTATAG_S_SENT_RESPONSE(agent->sa_stats->as_sent_response),
	       NTATAG_S_RETRY_REQUEST(agent->sa_stats->as_retry_request),
	       NTATAG_S_RETRY_RESPONSE(agent->sa_stats->as_retry_response),
	       NTATAG_S_RECV_RETRY(agent->sa_stats->as_recv_retry),
	       NTATAG_S_TOUT_REQUEST(agent->sa_stats->as_tout_request),
	       NTATAG_S_TOUT_RESPONSE(agent->sa_stats->as_tout_response),
	       TAG_END());

  ta_end(ta);

  return n;
}

/**Calculate a new unique tag.
 *
 * This function generates a series of 2**64 unique tags for @b From or @b To
 * headers. The start of the tag series is derived from the NTP time the NTA
 * agent was initialized.
 *
 */
sip_param_t nta_agent_newtag(su_home_t *home, char const *fmt, nta_agent_t *sa)
{
  char tag[(8 * 8 + 4)/ 5 + 1];

  if (sa == NULL)
    return su_seterrno(EINVAL), NULL;

  /* XXX - use a cryptographically safe func here? */
  sa->sa_tags += NTA_TAG_PRIME;

  msg_random_token(tag, sizeof(tag) - 1, &sa->sa_tags, sizeof(sa->sa_tags));

  if (fmt && fmt[0])
    return su_sprintf(home, fmt, tag);
  else
    return su_strdup(home, tag);
}

/**
 * Calculate branch value.
 */
static sip_param_t stateful_branch(su_home_t *home, nta_agent_t *sa)
{
  char branch[(8 * 8 + 4)/ 5 + 1];

  /* XXX - use a cryptographically safe func here? */
  sa->sa_branch += NTA_BRANCH_PRIME;

  msg_random_token(branch, sizeof(branch) - 1, 
		   &sa->sa_branch, sizeof(sa->sa_branch));

  return su_sprintf(home, "branch=z9hG4bK%s", branch);
}

#include <su_md5.h>

/**
 * Calculate branch value for stateless operation.
 * 
 * XXX - should include HMAC of previous Via line.
 */
static
sip_param_t stateless_branch(nta_agent_t *sa, 
			     msg_t *msg,
			     sip_t const *sip, 
			     tp_name_t const *tpn)
{
  su_md5_t md5[1];
  uint8_t digest[SU_MD5_DIGEST_SIZE];
  char branch[(SU_MD5_DIGEST_SIZE * 8 + 4)/ 5 + 1];
  sip_route_t const *r;

  assert(sip->sip_request);

  if (!sip->sip_via)
    return stateful_branch(msg_home(msg), sa);

  su_md5_init(md5);

  su_md5_str0update(md5, tpn->tpn_host);
  su_md5_str0update(md5, tpn->tpn_port);

  url_update(md5, sip->sip_request->rq_url);
  if (sip->sip_call_id) {
    su_md5_str0update(md5, sip->sip_call_id->i_id);
  }
  if (sip->sip_from) {
    url_update(md5, sip->sip_from->a_url);
    su_md5_stri0update(md5, sip->sip_from->a_tag);
  }
  if (sip->sip_to) {
    url_update(md5, sip->sip_to->a_url);
    // XXX - some broken implementations include To tag in CANCEL
    // su_md5_str0update(md5, sip->sip_to->a_tag);
  }
  if (sip->sip_cseq) {
    uint32_t cseq = htonl(sip->sip_cseq->cs_seq);
    su_md5_update(md5, &cseq, sizeof(cseq));
  }

  for (r = sip->sip_route; r; r = r->r_next)
    url_update(md5, r->r_url);

  su_md5_digest(md5, digest);

  msg_random_token(branch, sizeof(branch) - 1, digest, sizeof(digest));

  return su_sprintf(msg_home(msg), "branch=z9hG4bK.%s", branch);
}

/* ====================================================================== */
/* 2) Transport interface */

/* Local prototypes */
static int agent_init_via(nta_agent_t *self, int use_maddr);
static int agent_init_contact(nta_agent_t *self);
static void agent_recv_message(nta_agent_t *agent,
			       tport_t *tport,
			       msg_t *msg,
			       sip_via_t *tport_via,
			       su_time_t now);
static void agent_tp_error(nta_agent_t *agent,
			   tport_t *tport,
			   int errcode,
			   char const *remote);

/**For each transport, we have name used by tport module, SRV prefixes used
 * for resolving, and NAPTR service/conversion.
 */
static 
struct sipdns_tport {
  char name[6];			/**< Named used by tport module */
  char port[6];			/**< Default port number */
  char prefix[14];		/**< Prefix for SRV domains */
  char service[10];		/**< NAPTR service */
}
#define SIPDNS_TRANSPORTS (4)
const sipdns_tports[SIPDNS_TRANSPORTS] = {
  { "udp",  "5060", "_sip._udp.",  "SIP+D2U"  },
  { "tcp",  "5060", "_sip._tcp.",  "SIP+D2T"  },
  { "sctp", "5060", "_sip._sctp.", "SIP+D2S" },
  { "tls",  "5061", "_sips._tcp.", "SIPS+D2T"  },
};

static char const * const tports_sip[] =
  {
    "udp", "tcp", "sctp", NULL
  };

static char const * const tports_sips[] =
  {
    "tls", NULL
  };

static tp_agent_class_t nta_agent_class[1] =
  {{
    sizeof(nta_agent_class),
    agent_recv_message,
    agent_tp_error,
    (void *)nta_msg_create_for_transport,
    agent_sigcomp_accept
  }};


/** Add a transport to the agent.
 *
 * The function nta_agent_add_tport() creates a new transport and binds it
 * to the port specified by the @a uri. The @a uri must have sip: or sips:
 * scheme or be a wildcard uri ("*").
 *
 * @return
 * On success, zero is returned. On error, -1 is returned, and @a errno is
 * set appropriately.
 */
int nta_agent_add_tport(nta_agent_t *self,
			url_string_t const *uri,
			tag_type_t tag, tag_value_t value, ...)
{
  url_t *url;
  char tp[32];
  char maddr[256];
  char comp[32];
  tp_name_t tpn[1] = {{ NULL }};
  char const * const * tports = tports_sip;
  int error;
  ta_list ta;

  if (self == NULL) {
    su_seterrno(EINVAL);
    return -1;
  }

  if (uri == NULL)
    uri = (url_string_t *)"sip:*";
  else if (url_string_p(uri) ?
	   strcmp(uri->us_str, "*") == 0 :
	   uri->us_url->url_type == url_any) {
    uri = (url_string_t *)"sip:*:*";
  }

  if (!(url = url_hdup(self->sa_home, uri->us_url)) ||
      (url->url_type != url_sip && url->url_type != url_sips)) {
    if (url_string_p(uri))
      SU_DEBUG_1(("nta: %s: invalid bind URL\n", uri->us_str));
    else
      SU_DEBUG_1(("nta: invalid bind URL\n"));
    su_seterrno(EINVAL);
    return -1;
  }

  if (url->url_type == url_sip) {
    tpn->tpn_proto = "*";
    tports = tports_sip;
  }
  else {
    assert(url->url_type == url_sips);
    tpn->tpn_proto = "tls";
    tports = tports_sips;
  }

  tpn->tpn_canon = url->url_host;
  tpn->tpn_host = url->url_host;
  tpn->tpn_port = url_port(url);

  if (url->url_params) {
    if (url_param(url->url_params, "transport", tp, sizeof(tp)) > 0) {
      if (strchr(tp, ',')) {
	int i; char *t, *tps[9];

	/* Split tp into transports */
	for (i = 0, t = tp; t && i < 8; i++) {
	  tps[i] = t;
	  if ((t = strchr(t, ',')))
	    *t++ = '\0';
	}

	tps[i] = NULL;
	tports = (char const * const *)tps;
      } else {
	tpn->tpn_proto = tp;
      }
    }
    if (url_param(url->url_params, "maddr", maddr, sizeof(maddr)) > 0)
      tpn->tpn_host = maddr;
    if (url_param(url->url_params, "comp", comp, sizeof(comp)) > 0)
      tpn->tpn_comp = comp;
#if !HAVE_SIGCOMP
    if (str0casecmp(tpn->tpn_comp, "sigcomp") == 0) {
      SU_DEBUG_1(("nta(%p): sigcomp not supported for UA " 
		  URL_PRINT_FORMAT "\n",
		  self, URL_PRINT_ARGS(url)));
    }
#endif
  }

  ta_start(ta, tag, value);

  if (self->sa_tports == NULL) {
    /* Create master transport */
#if HAVE_SIGCOMP
    struct sigcomp_algorithm const *algorithm = self->sa_algorithm;

    if (algorithm == NULL)
      algorithm = sigcomp_algorithm_by_name(getenv("SIGCOMP_ALGORITHM"));

    self->sa_state_handler = sigcomp_state_handler_create();

    if (self->sa_state_handler)
      self->sa_compartment = 
	sigcomp_compartment_create(algorithm, self->sa_state_handler, 0,
				   "", 0, NULL, 0);

    if (self->sa_compartment) {
      agent_sigcomp_options(self, self->sa_compartment);
      sigcomp_compartment_option(self->sa_compartment, "stateless");
    }
    else
      SU_DEBUG_1(("nta: initializing SigComp: %s\n", strerror(errno)));
#endif

    if (!(self->sa_tports = 
	  tport_tcreate(self, nta_agent_class, self->sa_root,
			TPTAG_SDWN_ERROR(0),
			TPTAG_IDLE(1800000),
			TPTAG_DEBUG_DROP(self->sa_drop_prob),
			IF_SIGCOMP_TPTAG_COMPARTMENT(self->sa_compartment)
			ta_tags(ta)))) {
      error = su_errno();
      SU_DEBUG_9(("nta: cannot create master transport: %s\n",
		  su_strerror(error)));
      goto error;
    }
    else
      SU_DEBUG_9(("nta: master transport created\n"));
  }

  if (tport_tbind(self->sa_tports, tpn, tports, ta_tags(ta)) < 0) {
    error = su_errno();
    SU_DEBUG_1(("nta: bind(%s:%s;transport=%s%s%s%s%s): %s\n",
		tpn->tpn_canon, tpn->tpn_port, tpn->tpn_proto,
		tpn->tpn_canon != tpn->tpn_host ? ";maddr=" : "",
		tpn->tpn_canon != tpn->tpn_host ? tpn->tpn_host : "",
		tpn->tpn_comp ? ";comp=" : "",
		tpn->tpn_comp ? tpn->tpn_comp : "",
		su_strerror(error)));
    goto error;
  }
  else
    SU_DEBUG_5(("nta: bound to (%s:%s;transport=%s%s%s%s%s)\n",
		tpn->tpn_canon, tpn->tpn_port, tpn->tpn_proto,
		tpn->tpn_canon != tpn->tpn_host ? ";maddr=" : "",
		tpn->tpn_canon != tpn->tpn_host ? tpn->tpn_host : "",
		tpn->tpn_comp ? ";comp=" : "",
		tpn->tpn_comp ? tpn->tpn_comp : ""));

  /* XXX - when to use maddr? */
  if ((agent_init_via(self, 0)) < 0) {
    error = su_errno();
    SU_DEBUG_1(("nta: cannot create Via headers\n"));
    goto error;
  }
  else
    SU_DEBUG_9(("nta: Via fields initialized\n"));

  if ((agent_init_contact(self)) < 0) {
    error = su_errno();
    SU_DEBUG_1(("nta: cannot create Contact header\n"));
    goto error;
  }
  else
    SU_DEBUG_9(("nta: Contact header created\n"));

  su_free(self->sa_home, url);
  ta_end(ta);

  return 0;

 error:
  ta_end(ta);
  su_seterrno(error);
  return -1;
}


/** Initialize Via headers. */
static
int agent_init_via(nta_agent_t *self, int use_maddr)
{
  sip_via_t *v, **vv;
  tport_t *tp;

  for (vv = &self->sa_vias; *vv; vv = &(*vv)->v_next)
    ;

  self->sa_tport_ip4 = 0;
  self->sa_tport_ip6 = 0;
  self->sa_tport_udp = 0;
  self->sa_tport_tcp = 0;
  self->sa_tport_sctp = 0;
  self->sa_tport_tls = 0;

  /* Set via fields for the tports */
  for (tp = tport_primaries(self->sa_tports); tp; tp = tport_next(tp)) {
    int maddr;
    tp_name_t tpn[1];
    char const *comp = NULL;

    *tpn = *tport_name(tp);

    assert(tpn->tpn_proto);
    assert(tpn->tpn_canon);
    assert(tpn->tpn_host);
    assert(tpn->tpn_port);

#if 0
    if (getenv("SIP_UDP_CONNECT")
	&& strcmp(tpn->tpn_proto, "udp") == 0)
      tport_set_params(tp, TPTAG_CONNECT(1), TAG_END());
#endif

    if (tport_has_ip4(tp)) self->sa_tport_ip4 = 1;
    if (tport_has_ip6(tp)) self->sa_tport_ip6 = 1;

    if (strcasecmp(tpn->tpn_proto, "udp") == 0)
      self->sa_tport_udp = 1;
    else if (strcasecmp(tpn->tpn_proto, "tcp") == 0)
      self->sa_tport_tcp = 1;
    else if (strcasecmp(tpn->tpn_proto, "sctp") == 0)
      self->sa_tport_sctp = 1;

    if (tport_has_tls(tp)) self->sa_tport_tls = 1;

    if (tport_magic(tp))
      continue;

    if (strcmp(tpn->tpn_port, SIP_DEFAULT_SERV) == 0)
      tpn->tpn_port = NULL;

    maddr = use_maddr && strcasecmp(tpn->tpn_canon, tpn->tpn_host) != 0;

    comp = tpn->tpn_comp;

    v = sip_via_format(self->sa_home,
		       "%s/%s %s%s%s%s%s%s%s",
		       SIP_VERSION_CURRENT, tpn->tpn_proto,
		       tpn->tpn_canon,
		       tpn->tpn_port ? ":" : "",
		       tpn->tpn_port ? tpn->tpn_port : "",
		       maddr ? ";maddr=" : "", maddr ? tpn->tpn_host : "",
		       comp ? ";comp=" : "", comp ? comp : "");

    if (v == NULL)
      return -1;

    tport_set_magic(tp, v);

    /** Add a duplicate to the list shown to application */
    *vv = sip_via_dup(self->sa_home, v);
    if (*vv == NULL)
      return -1;
    vv = &(*vv)->v_next;
  }

  if (self->sa_tport_udp)
    agent_set_udp_params(self, self->sa_udp_mtu);

  return 0;
}


/** Initialize main contact header. */
static
int agent_init_contact(nta_agent_t *self)
{
  sip_via_t const *v1 = self->sa_vias, *v2;
  char const *tp;

  if (self->sa_contact)
    return 0;

  if (!v1) return -1;
  tp = strrchr(v1->v_protocol, '/');
  if (!tp++)
    return -1;

  v2 = v1->v_next;

  if (v2 && 
      strcasecmp(v1->v_host, v2->v_host) == 0 &&
      strcasecmp(v1->v_port, v2->v_port) == 0) {
    char const *p1 = v1->v_protocol, *p2 = v2->v_protocol;

    if (strcasecmp(p1, sip_transport_udp))
      p1 = v2->v_protocol, p2 = v1->v_protocol;

    if (strcasecmp(p1, sip_transport_udp) == 0 &&
	strcasecmp(p2, sip_transport_tcp) == 0)
      /* Do not include transport if we have both UDP and TCP */
      tp = NULL;
  }

  self->sa_contact = 
    sip_contact_create_from_via_with_transport(self->sa_home, v1, NULL, tp);

  if (!self->sa_contact)
    return -1;

  return 0;
}

/** Return Via line corresponging to tport. */
static
sip_via_t const *agent_tport_via(tport_t *tport)
{
  return tport_magic(tport);
}

/** Insert Via to a request message */
static
int agent_insert_via(nta_agent_t *self,
		     msg_t *msg,
		     sip_via_t const *via,
		     char const *branch,
		     int user_via)
{
  sip_t *sip = sip_object(msg);
  sip_via_t *v;
  sip_method_t method;
  int clear = 0;

  assert(sip); assert(via);

  if (user_via && sip->sip_via) {
    /* Use existing Via provided by application */
    v = sip->sip_via;
  }
  else if (msg && via && sip->sip_request &&
	   (v = sip_via_copy(msg_home(msg), via))) {
    sip_header_insert(msg, sip, (sip_header_t *)v);
  }
  else
    return -1;

  method = sip->sip_request ? sip->sip_request->rq_method : sip_method_options;

  if (method != sip_method_ack) {
    if (self->sa_rport && !sip_params_find(v->v_params, "rport=")) 
      clear = 1, sip_via_add_param(msg_home(msg), v, "rport");
  } else {
    /* msg_params_remove((msg_param_t *)&v->v_params, "comp="); */
  }

  if (branch && branch != v->v_branch)
    clear = 1, sip_via_add_param(msg_home(msg), v, branch);

  if (via->v_protocol != v->v_protocol &&
      strcasecmp(via->v_protocol, v->v_protocol))
    clear = 1, v->v_protocol = via->v_protocol;

  /* XXX - should we do this? */
  if (via->v_host != v->v_host &&
      str0cmp(via->v_host, v->v_host))
    clear = 1, v->v_host = via->v_host;

  if (via->v_port != v->v_port &&
      str0cmp(via->v_port, v->v_port))
    clear = 1, v->v_port = via->v_port;

  if (clear)
    msg_fragment_clear(v->v_common);

  return 0;
}

/** Get destination name from Via. 
 *
 * If using_rport is non-NULL, use value from rport.
 */
static
int nta_tpn_by_via(tp_name_t *tpn, sip_via_t const *v, int *using_rport)
{
  char const *rport;

  if (!v)
    return -1;

  tpn->tpn_proto = sip_via_transport(v);
  tpn->tpn_canon = v->v_host;

  if (v->v_maddr)
    tpn->tpn_host = v->v_maddr;
  else if (v->v_received)
    tpn->tpn_host = v->v_received;
  else
    tpn->tpn_host = v->v_host;

  if (v->v_maddr || !using_rport)
    rport = NULL;
  else if (strcasecmp(v->v_protocol, "SIP/2.0/UDP") == 0)
    rport = msg_params_find(v->v_params, "rport="), *using_rport = 0;
  else if (*using_rport)
    rport = msg_params_find(v->v_params, "rport=");
  else
    rport = NULL;

  if (rport && rport[0])
    tpn->tpn_port = rport;
  else
    tpn->tpn_port = SIP_PORT(v->v_port), using_rport ? *using_rport = 0 : 0;

  tpn->tpn_comp = sip_params_find(v->v_params, "comp=");

  tpn->tpn_ident = NULL;

  return 0;
}

/** Get transport name from URL. */
int nta_tpn_by_url(su_home_t *home,
		   tp_name_t *tpn,
		   char const **scheme,
		   char const **port,
		   url_string_t const *us)
{
  url_t url[1];
  int n;
  char *b;

  n = url_xtra(us->us_url);
  b = su_alloc(home, n);

  if (b == NULL || url_dup(b, n, url, us->us_url) < 0) {
    su_free(home, b);
    return -1;
  }

  if (url->url_type != url_sip && 
      url->url_type != url_sips &&
      url->url_type != url_im &&
      url->url_type != url_pres) {
    su_free(home, b);
    return -1;
  }

  SU_DEBUG_7(("nta: selecting scheme %s\n", url->url_scheme));

  *scheme = url->url_scheme;
  if (strcasecmp(url->url_scheme, "sips") == 0)
    tpn->tpn_proto = "tls";
  else
    tpn->tpn_proto = "*";
  tpn->tpn_canon = url->url_host;
  tpn->tpn_host = url->url_host;

  if (url->url_params) {
    for (b = (char *)url->url_params; b[0]; b += n) {
      n = strcspn(b, ";");

      if (n > 10 && strncasecmp(b, "transport=", 10) == 0)
	tpn->tpn_proto = b + 10;
      else if (n > 5 && strncasecmp(b, "comp=", 5) == 0)
	tpn->tpn_comp = b + 5;
      else if (n > 6 && strncasecmp(b, "maddr=", 6) == 0)
	tpn->tpn_host = b + 6;

      if (b[n])
	b[n++] = '\0';
    }
  }

  if ((*port = url->url_port))
    tpn->tpn_port = url->url_port;

  tpn->tpn_ident = NULL;

  return 0;
}

/** Handle transport errors. */
static
void agent_tp_error(nta_agent_t *agent,
		    tport_t *tport,
		    int errcode,
		    char const *remote)
{
  su_llog(nta_log, 1,
	  "nta_agent: tport: %s%s%s\n",
	  remote ? remote : "", remote ? ": " : "",
	  su_strerror(errcode));
}


/* ====================================================================== */
/* 3) Message dispatch */

static void agent_recv_request(nta_agent_t *agent,
			       msg_t *msg,
			       sip_t *sip,
			       tport_t *tport);
static int agent_check_request_via(nta_agent_t *agent,
				   msg_t *msg,
				   sip_t *sip,
				   sip_via_t *v,
				   tport_t *tport);
static int agent_aliases(nta_agent_t const *, url_t [], tport_t *);
static void agent_recv_response(nta_agent_t*, msg_t *, sip_t *,
				sip_via_t *, tport_t*);
static void agent_recv_garbage(nta_agent_t*, msg_t*, tport_t*);


/** Handle incoming message. */
static
void agent_recv_message(nta_agent_t *agent,
			tport_t *tport,
			msg_t *msg,
			sip_via_t *tport_via,
			su_time_t now)
{
  sip_t *sip = sip_object(msg);

  agent->sa_millisec = su_time_ms(agent->sa_now = now);

  if (sip && sip->sip_request) {
    agent_recv_request(agent, msg, sip, tport);
  }
  else if (sip && sip->sip_status) {
    agent_recv_response(agent, msg, sip, tport_via, tport);
  }
  else {
    agent_recv_garbage(agent, msg, tport);
  }

  agent->sa_millisec = 0;
}

/** @internal Handle incoming requests. */
static
void agent_recv_request(nta_agent_t *agent,
			msg_t *msg,
			sip_t *sip,
			tport_t *tport)
{
  nta_leg_t *leg;
  nta_incoming_t *irq, *merge = NULL, *ack = NULL;
  sip_method_t method = sip->sip_request->rq_method;
  char const *method_name = sip->sip_request->rq_method_name;
  url_t url[1];
  unsigned cseq = sip->sip_cseq ? sip->sip_cseq->cs_seq : 0;
  int insane, errors, stream;

  agent->sa_stats->as_recv_msg++;
  agent->sa_stats->as_recv_request++;

  SU_DEBUG_5(("nta: received %s " URL_PRINT_FORMAT " %s (CSeq %u)\n",
	      method_name,
	      URL_PRINT_ARGS(sip->sip_request->rq_url),
	      sip->sip_request->rq_version, cseq));

  stream = tport_is_stream(tport);

#if HAVE_SIGCOMP
  if (stream && 
      tport_can_send_sigcomp(tport) &&
      tport_name(tport)->tpn_comp == NULL && 
      msg_params_find(sip->sip_via->v_params, "comp=sigcomp") &&
      tport_has_compression(tport_parent(tport), "sigcomp")) {
    tport_set_compression(tport, "sigcomp");
  }
#endif

  if (sip->sip_flags & MSG_FLG_TOOLARGE) {
    SU_DEBUG_5(("nta: %s (%u) is %s\n", 
		method_name, cseq, sip_413_Request_too_large));
    agent->sa_stats->as_bad_request++;
    nta_msg_treply(agent, msg, SIP_413_REQUEST_TOO_LARGE,
		   NTATAG_TPORT(tport),
		   NTATAG_INCOMPLETE(1),		   
		   TPTAG_SDWN_AFTER(stream),
		   TAG_END());
    return;
  }

  insane = 0;

  if (agent->sa_bad_req_mask)
    errors = msg_extract_errors(msg) & agent->sa_bad_req_mask;
  else
    errors = sip->sip_error != NULL;

  if (errors ||
      (sip->sip_flags & MSG_FLG_ERROR) /* Fatal error */ || 
      (insane = (sip_sanity_check(sip) < 0))) {
    sip_header_t const *h;
    char const *badname = NULL, *phrase;
    
    agent->sa_stats->as_bad_message++;
    agent->sa_stats->as_bad_request++;

    if (insane)
      SU_DEBUG_5(("nta: %s (%u) %s\n", method_name, cseq,
		  "failed sanity check"));

    for (h = (sip_header_t const *)sip->sip_error; h; h = h->sh_next) {
      char const *bad;

      if (h->sh_class == sip_error_class)
	bad = h->sh_error->er_name;
      else 
	bad = h->sh_class->hc_name;

      if (bad)
	SU_DEBUG_5(("nta: %s has bad %s header\n", method_name, bad));
      
      if (!badname)
	badname = bad;
    }

    if (sip->sip_via && method != sip_method_ack) {
      msg_t *reply = nta_msg_create(agent, 0);
      
      if (reply) {
	agent_check_request_via(agent, msg, sip, sip->sip_via, tport);

	if (badname)
	  phrase = su_sprintf(msg_home(reply), "Bad %s Header", badname);
	else
	  phrase = sip_400_Bad_request;

	SU_DEBUG_5(("nta: %s (%u) is %s\n", method_name, cseq, phrase));
	
	nta_msg_tmreply(agent, reply, sip_object(reply),
			400, phrase,
			msg,
			NTATAG_TPORT(tport), 
			NTATAG_INCOMPLETE(1), 
			TPTAG_SDWN_AFTER(stream),
			TAG_END());
      }
    } else {
      nta_msg_discard(agent, msg);
      if (stream)		/* Send FIN */
	tport_shutdown(tport, 1);
    }

    return;
  }

  if (str0casecmp(sip->sip_request->rq_version, sip_version_2_0) != 0) {
    agent->sa_stats->as_bad_request++;
    agent->sa_stats->as_bad_message++;

    SU_DEBUG_5(("nta: bad version %s for %s (%u)\n",
		sip->sip_request->rq_version, method_name, cseq));

    nta_msg_treply(agent, msg, SIP_505_VERSION_NOT_SUPPORTED,
		   NTATAG_TPORT(tport), 
		   TPTAG_SDWN_AFTER(stream),
		   TAG_END());

    return;
  }

  if (agent_check_request_via(agent, msg, sip, sip->sip_via, tport) < 0) {
    agent->sa_stats->as_bad_message++;
    agent->sa_stats->as_bad_request++;
    SU_DEBUG_5(("nta: %s (%u) %s\n", method_name, cseq, "has invalid Via"));
    msg_destroy(msg);
    return;
  }

  /* First, try existing incoming requests */
  irq = incoming_find(agent, sip, sip->sip_via, &merge, &ack);
  if (irq) {
    /* Match - this is a retransmission */
    SU_DEBUG_5(("nta: %s (%u) going to existing %s transaction\n",
		method_name, cseq, irq->irq_rq->rq_method_name));
    if (incoming_recv(irq, msg, sip, tport) >= 0)
      return;
  }
  else if (ack) {
    /* Match - this is an ACK or CANCEL or PRACK */
    SU_DEBUG_5(("nta: %s (%u) is going to %s (%u)\n",
		method_name, cseq,
		ack->irq_rq->rq_method_name, ack->irq_cseq->cs_seq));
    if (method == sip_method_ack) {
      if (incoming_ack(ack, msg, sip, tport) >= 0)
	return;
    }
    else if (method == sip_method_cancel) {
      if (incoming_cancel(ack, msg, sip, tport) >= 0)
	return;
    }
    else if (method == sip_method_prack) {
      if (reliable_recv(ack, msg, sip, tport) >= 0)
	return;
    }
    else {
      assert(!method);
    }
  }
  else if (merge) {
    SU_DEBUG_5(("nta: %s (%u) %s\n",
		method_name, cseq, "is a merged request"));
    if (incoming_merge(merge, msg, sip, tport) >= 0)
      return;
  }

  *url = *sip->sip_request->rq_url;
  url->url_params = NULL;
  agent_aliases(agent, url, tport); /* canonize urls */

  if ((leg = leg_find(agent, 
		      method_name, url, 
		      sip->sip_call_id,
		      sip->sip_from->a_tag, sip->sip_from->a_url, 
		      sip->sip_to->a_tag, sip->sip_to->a_url))) {
    /* Try existing dialog */
    SU_DEBUG_5(("nta: %s (%u) %s\n",
		method_name, cseq, "going to existing leg"));
    leg_recv(leg, msg, sip, tport);
    return;
  }
  else if (!agent->sa_is_stateless &&
	   (leg = dst_find(agent, url, method_name))) {
    /* Dialogless legs - let application process transactions statefully */
    SU_DEBUG_5(("nta: %s (%u) %s\n",
		method_name, cseq, "going to a dialogless leg"));
    leg_recv(leg, msg, sip, tport);
  }
  else if (!agent->sa_is_stateless && (leg = agent->sa_default_leg)) {
    SU_DEBUG_5(("nta: %s (%u) %s\n",
		method_name, cseq, "going to a default leg"));
    leg_recv(leg, msg, sip, tport);
  }
  else if (agent->sa_callback) {
    /* Stateless processing for request */
    agent->sa_stats->as_trless_request++;
    SU_DEBUG_5(("nta: %s (%u) %s\n", 
		method_name, cseq, "to message callback"));
    (void)agent->sa_callback(agent->sa_magic, agent, msg, sip);
  }
  else {
    agent->sa_stats->as_trless_request++;
    SU_DEBUG_5(("nta: %s (%u) no place to go: %d %s\n",
		method_name, cseq, SIP_501_NOT_IMPLEMENTED));
    if (method != sip_method_ack)
      nta_msg_treply(agent, msg, SIP_501_NOT_IMPLEMENTED,
		     NTATAG_TPORT(tport),
		     TAG_END());
    else
      msg_destroy(msg);
  }
}

/** Check Via header.
 *
 */
static
int agent_check_request_via(nta_agent_t *agent,
			    msg_t *msg,
			    sip_t *sip,
			    sip_via_t *v,
			    tport_t *tport)
{
  enum { receivedlen = sizeof("received=") - 1 };
  char received[receivedlen + TPORT_HOSTPORTSIZE];
  char *hostport = received + receivedlen;
  char const *rport;
  su_sockaddr_t *from;
  sip_via_t *tpv = tport_magic(tport);

  assert(tport); assert(msg); assert(sip);
  assert(sip->sip_request); assert(tpv);

  from = (su_sockaddr_t *)msg_addr(msg);

  if (v == NULL) {
    /* Make up a via line */
    v = sip_via_format(msg_home(msg), "SIP/2.0/%s %s",
		       tport_name(tport)->tpn_proto,
		       tport_hostport(hostport, TPORT_HOSTPORTSIZE, from, 1));
    sip_header_insert(msg, sip, (sip_header_t *)v);

    return v ? 0 : -1;
  }

  if (str0casecmp(v->v_protocol, tpv->v_protocol)) {
    tport_hostport(hostport, TPORT_HOSTPORTSIZE, from, 1);
    SU_DEBUG_1(("nta: Via check: invalid transport \"%s\" from %s\n",
		v->v_protocol, hostport));
    return -1;
  }

  if (v->v_received) {
    /* Nasty, nasty */
    tport_hostport(hostport, TPORT_HOSTPORTSIZE, from, 1);
    SU_DEBUG_1(("nta: Via check: extra received=%s from %s\n",
		v->v_received, hostport));
    msg_params_remove((msg_param_t *)v->v_params, "received");
    sip_fragment_clear(v->v_common);
  }

  if (!tport_hostport(hostport, TPORT_HOSTPORTSIZE, from, 0))
    return -1;

  if (strcasecmp(hostport, v->v_host)) {
    int rlen;
    /* Add the "received" field */
    memcpy(received, "received=", receivedlen);

    if (hostport[0] == '[') {
      rlen = strlen(hostport + 1) - 1;
      memmove(hostport, hostport + 1, rlen);
      hostport[rlen] = '\0';
    }

    sip_via_add_param(msg_home(msg), v, su_strdup(msg_home(msg), received));
    SU_DEBUG_5(("nta: Via check: %s\n", received));
  }

  if (!agent->sa_server_rport) {
    /*Xyzzy*/;
  }
  else if ((rport = sip_params_find(v->v_params, "rport"))) {
    rport = su_sprintf(msg_home(msg), "rport=%u", ntohs(from->su_port));
    sip_via_add_param(msg_home(msg), v, rport);
  } 
  else if (tport_is_tcp(tport)) {
    rport = su_sprintf(msg_home(msg), "rport=%u", ntohs(from->su_port));
    sip_via_add_param(msg_home(msg), v, rport);
  }

  return 0;
}

/** @internal Handle aliases of local node. 
 *
 * Return true if @a url is modified.
 */
static
int agent_aliases(nta_agent_t const *agent, url_t url[], tport_t *tport)
{
  sip_contact_t *m;
  sip_via_t *lv;
  char const *tport_port = "";

  if (!url->url_host)
    return 0;

  if (tport)
    tport_port = tport_name(tport)->tpn_port;

  assert(tport_port);

  for (m = agent->sa_aliases ? agent->sa_aliases : agent->sa_contact;
       m;
       m = m->m_next) {
    if (url->url_type != m->m_url->url_type)
      continue;

    if (strcasecmp(url->url_host, m->m_url->url_host))
      continue;

    if (url->url_port == NULL)
      break;

    if (m->m_url->url_port) {
      if (strcmp(url->url_port, m->m_url->url_port))
	continue;
    } else {
      if (strcmp(url->url_port, tport_port))
	continue;
    }

    break;
  }

  if (!m)
    return 0;

  SU_DEBUG_7(("nta: canonizing " URL_PRINT_FORMAT " with %s\n",
	      URL_PRINT_ARGS(url),
	      agent->sa_aliases ? "aliases" : "contact"));

  url->url_host = "%";

  if (agent->sa_aliases) {
    url->url_type = agent->sa_aliases->m_url->url_type;
    url->url_scheme = agent->sa_aliases->m_url->url_scheme;
    url->url_port = agent->sa_aliases->m_url->url_port;
    return 1;
  }
  else {
    /* Canonize the request URL port */
    if (tport) {
      lv = tport_magic(tport_parent(tport)); assert(lv);
      if (lv->v_port)
	/* Add non-default port */
	url->url_port = lv->v_port;
      return 1;
    }
    if (url->url_port &&
	strcmp(url->url_port, url_port_default(url->url_type)) == 0)
      /* Remove default port */
      url->url_port = NULL;

    return 0;
  }
}

/** @internal Handle incoming responses. */
static
void agent_recv_response(nta_agent_t *agent,
                         msg_t *msg,
                         sip_t *sip,
                         sip_via_t *tport_via,
                         tport_t *tport)
{
  int status = sip->sip_status->st_status;
  int errors;
  char const *phrase = sip->sip_status->st_phrase;
  char const *method =
    sip->sip_cseq ? sip->sip_cseq->cs_method_name : "<UNKNOWN>";
  uint32_t cseq = sip->sip_cseq ? sip->sip_cseq->cs_seq : 0;
  nta_outgoing_t *orq;

  agent->sa_stats->as_recv_msg++;
  agent->sa_stats->as_recv_response++;

  SU_DEBUG_5(("nta: received %03d %s for %s (%u)\n", 
	      status, phrase, method, cseq));

  if (agent->sa_bad_resp_mask)
    errors = msg_extract_errors(msg) & agent->sa_bad_resp_mask;
  else
    errors = sip->sip_error != NULL;

  if (errors || 
      /* Drop response messages to ACK */
      sip_sanity_check(sip) < 0) {
    sip_header_t const *h;

    agent->sa_stats->as_bad_response++;
    agent->sa_stats->as_bad_message++;

    SU_DEBUG_5(("nta: %03d %s failed sanity check\n", status, phrase));

    for (h = (sip_header_t const *)sip->sip_error; h; h = h->sh_next) {
      if (h->sh_class->hc_name) {
	SU_DEBUG_5(("nta: %03d has bad %s header\n", status,
		    h->sh_class->hc_name));
      }
    }

    msg_destroy(msg);
    return;
  }

  if (str0casecmp(sip->sip_status->st_version, sip_version_2_0) != 0) {
    agent->sa_stats->as_bad_response++;
    agent->sa_stats->as_bad_message++;

    SU_DEBUG_5(("nta: bad version %s %03d %s\n",
		sip->sip_status->st_version, status, phrase));
    msg_destroy(msg);
    return;
  }

  if (sip->sip_cseq->cs_method == sip_method_ack) {
    agent->sa_stats->as_bad_response++;
    agent->sa_stats->as_bad_message++;
    SU_DEBUG_5(("nta: %03d %s is response to ACK\n", status, phrase));
    msg_destroy(msg);
    return;
  }

  /* XXX - should check if msg should be discarded based on via? */

  if ((orq = outgoing_find(agent, msg, sip, sip->sip_via))) {
    SU_DEBUG_5(("nta: %03d %s going to a transaction\n", status, phrase));
    if (outgoing_recv(orq, status, msg, sip) == 0)
      return;
  }

  agent->sa_stats->as_trless_response++;

  if (agent->sa_callback) {
    SU_DEBUG_5(("nta: %03d %s to message callback\n", status, phrase));
    /*
     * Store message and transport to hook for the duration of the callback
     * so that the transport can be obtained by nta_transport().
     */
    (void)agent->sa_callback(agent->sa_magic, agent, msg, sip);
    return;
  }

  if (sip->sip_cseq->cs_method == sip_method_invite
      && 200 <= sip->sip_status->st_status
      && sip->sip_status->st_status < 300) {
    agent->sa_stats->as_trless_200++;
    /* Orphan 200 Ok to INVITE. ACK and BYE it */
    SU_DEBUG_5(("nta: %03d %s must be ACK&BYE\n", status, phrase));
    if (nta_msg_ackbye(agent, msg) != -1)
      return;
  }

  SU_DEBUG_5(("nta: %03d %s was discarded\n", status, phrase));
  msg_destroy(msg);
}

/** @internal Agent receives garbage */
static
void agent_recv_garbage(nta_agent_t *agent,
			msg_t *msg,
			tport_t *tport)
{
  agent->sa_stats->as_recv_msg++;
  agent->sa_stats->as_bad_message++;

#if SU_DEBUG >= 3
  if (nta_log->log_level >= 3) {
    tp_name_t tpn[1];

    tport_delivered_from(tport, msg, tpn);

    SU_DEBUG_3(("nta_agent: received garbage from " TPN_FORMAT "\n",
		TPN_ARGS(tpn)));
  }
#endif

  msg_destroy(msg);
}

/* ====================================================================== */
/* 4) Message handling - create, complete, destroy */

/** Create a new message belonging to the agent */
msg_t *nta_msg_create(nta_agent_t *agent, int flags)
{
  msg_t *msg;

  if (agent == NULL)
    return su_seterrno(EINVAL), NULL;

  msg = msg_create(agent->sa_mclass, agent->sa_flags | flags);

  if (agent->sa_preload)
    su_home_preload(msg_home(msg), 1, agent->sa_preload);

  return msg;
}

/** Create a new message for transport */
msg_t *nta_msg_create_for_transport(nta_agent_t *agent, int flags,
				    char const data[], unsigned dlen)
{
  msg_t *msg = msg_create(agent->sa_mclass, agent->sa_flags | flags);

  msg_maxsize(msg, agent->sa_maxsize);

  if (agent->sa_preload)
    su_home_preload(msg_home(msg), 1, dlen + agent->sa_preload);

  return msg;
}

/** Complete a message. */
int nta_msg_complete(msg_t *msg)
{
  return sip_complete_message(msg);
}

/** Discard a message */
void nta_msg_discard(nta_agent_t *agent, msg_t *msg)
{
  msg_destroy(msg);
}

/** Check if the message is internally generated by NTA. */
int nta_is_internal_msg(msg_t const *msg)
{
  return msg_get_flags(msg, NTA_INTERNAL_MSG) == NTA_INTERNAL_MSG;
}

/* ====================================================================== */
/* 5) Stateless operation */

#include <nta_stateless.h>

/** Send a message. */
int nta_msg_tsend(nta_agent_t *agent, msg_t *msg, url_string_t const *u,
		  tag_type_t tag, tag_value_t value, ...)
{
  int retval = -1;
  ta_list ta;
  sip_t *sip = sip_object(msg);
  tp_name_t tpn[1] = {{ NULL }};
  char const *what;

  if (!sip) {
    msg_destroy(msg);
    return -1;
  }

  what = 
    sip->sip_status ? "nta_msg_tsend(response)" : 
    sip->sip_request ? "nta_msg_tsend(request)" :
    "nta_msg_tsend()";

  ta_start(ta, tag, value);

  if (sip_add_tl(msg, sip, ta_tags(ta)) < 0)
    SU_DEBUG_3(("%s: cannot add headers\n", what));
  else if (sip->sip_status) {
    tport_t *tport = NULL;
    int *use_rport = NULL;
    int retry_without_rport = 0;

    struct sigcomp_compartment *cc; cc = NONE;

    if (agent->sa_server_rport)
      use_rport = &retry_without_rport, retry_without_rport = 1;

    tl_gets(ta_args(ta),
	    NTATAG_TPORT_REF(tport),
	    IF_SIGCOMP_TPTAG_COMPARTMENT_REF(cc)
	    /* NTATAG_INCOMPLETE_REF(incomplete), */
	    TAG_END());

    if (!sip->sip_separator && 
	!(sip->sip_separator = sip_separator_create(msg_home(msg))))
      SU_DEBUG_3(("%s: cannot create sip_separator\n", what));
    else if (sip_serialize(msg, sip) != 0)
      SU_DEBUG_3(("%s: sip_serialize() failed\n", what));
    else if (!sip_via_remove(msg, sip))
      SU_DEBUG_3(("%s: cannot remove Via\n", what));
    else if (nta_tpn_by_via(tpn, sip->sip_via, use_rport) < 0)
      SU_DEBUG_3(("%s: bad via\n", what));
    else {
      if (!tport)
	tport = tport_by_name(agent->sa_tports, tpn);
      if (!tport)
	tport = tport_by_protocol(agent->sa_tports, tpn->tpn_proto);

      if (retry_without_rport)
	tpn->tpn_port = SIP_PORT(sip->sip_via->v_port);

#if HAVE_SIGCOMP
      if (tport && tpn->tpn_comp && cc == NONE)
	cc = agent_sigcomp_compartment(agent, tport, tpn);
#endif

      if (tport_tsend(tport, msg, tpn,
		      IF_SIGCOMP_TPTAG_COMPARTMENT(cc)
		      TPTAG_MTU(INT_MAX), ta_tags(ta), TAG_END())) {
	agent->sa_stats->as_sent_msg++;
	agent->sa_stats->as_sent_response++;
	retval = 0;
      }
      else {
	SU_DEBUG_3(("%s: send fails\n", what));
      }
    }
  }
  else {
    /* Send request */
    if (outgoing_create(agent, NULL, NULL, u, NULL, msg_ref_create(msg), 
			NTATAG_STATELESS(1),
			ta_tags(ta)))
      retval = 0;
  }

  if (retval == 0)
    SU_DEBUG_5(("%s\n", what));

  ta_end(ta);

  msg_destroy(msg);

  return retval;
}

/** Send the message (stdarg version of nta_msg_send()). */
int nta_msg_vsend(nta_agent_t *agent, msg_t *msg, url_string_t const *u,
		  void *extra, va_list headers)
{
  sip_t *sip = sip_object(msg);

  if (extra && sip_add_headers(msg, sip, extra, headers) < 0) {
    msg_destroy(msg);
    return -1;
  }

  return nta_msg_tsend(agent, msg, u, TAG_END());
}

/** Send the message. */
int nta_msg_send(nta_agent_t *agent, msg_t *msg, url_string_t const *u,
		 void *extra, ...)
{
  int retval;
  va_list headers;
  va_start(headers, extra);
  retval = nta_msg_vsend(agent, msg, u, extra, headers);
  va_end(headers);

  return retval;
}

/** Reply to the request message. */
int nta_msg_treply(nta_agent_t *agent,
		   msg_t *req_msg,
		   int status, char const *phrase,
		   tag_type_t tag, tag_value_t value, ...)
{
  int retval;
  ta_list ta;

  ta_start(ta, tag, value);

  retval =  nta_msg_tmreply(agent, NULL, NULL, status, phrase, req_msg,
			    ta_tags(ta));
  ta_end(ta);

  return retval;
}

/** Reply to the request message. */
int nta_msg_mreply(nta_agent_t *agent,
		   msg_t *reply, sip_t *sip,
		   int status, char const *phrase,
		   msg_t *req_msg)
{
  return 
    nta_msg_tmreply(agent, reply, sip, status, phrase, req_msg, TAG_END());
}

/** Reply to the request message. */
int nta_msg_tmreply(nta_agent_t *agent,
		    msg_t *reply, sip_t *sip,
		    int status, char const *phrase,
		    msg_t *req_msg,
		    tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  tp_name_t tpn[1];
  int retval = -1;
  tport_t *tport = NULL;
  struct sigcomp_compartment *cc = NONE;
  int *use_rport = NULL;
  int retry_without_rport = 0, incomplete = 0;

  if (!agent)
    return -1;

  if (agent->sa_server_rport)
    use_rport = &retry_without_rport, retry_without_rport = 1;

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta),
	  NTATAG_TPORT_REF(tport),
	  NTATAG_INCOMPLETE_REF(incomplete),
	  TPTAG_COMPARTMENT_REF(cc),
	  TAG_END());

  if (reply == NULL) {
    reply = nta_msg_create(agent, 0);
    sip = sip_object(reply);
  }

  if (!sip) {
    SU_DEBUG_3(("%s: no msg\n", __func__));
  }
  else if (sip_add_tl(reply, sip, ta_tags(ta)) < 0) {
    SU_DEBUG_3(("%s: cannot add user headers\n", __func__));
  }
  else if (sip_complete_response(reply, status, phrase,
				 sip_object(req_msg)) < 0 && 
	   !incomplete) {
    SU_DEBUG_3(("%s: cannot complete message\n", __func__));
  }
  else if (sip->sip_status && sip->sip_status->st_status > 100 &&
	   sip->sip_to && !sip->sip_to->a_tag &&
	   sip->sip_cseq && sip->sip_cseq->cs_method != sip_method_cancel &&
	   sip_to_tag(msg_home(reply), sip->sip_to,
		      nta_agent_newtag(msg_home(reply), "tag=%s", agent)) < 0) {
    SU_DEBUG_3(("%s: cannot add To tag\n", __func__));
  }
  else if (nta_tpn_by_via(tpn, sip->sip_via, use_rport) < 0) {
    SU_DEBUG_3(("%s: no Via\n", __func__));
  }
  else {
    if (tport == NULL)
      tport = tport_delivered_by(agent->sa_tports, req_msg);

    if (!tport) {
      tport_t *primary = tport_by_protocol(agent->sa_tports, tpn->tpn_proto);

      tport = tport_by_name(primary, tpn);

      if (!tport)
	tport = primary;
    }

    if (retry_without_rport)
      tpn->tpn_port = SIP_PORT(sip->sip_via->v_port);

#if HAVE_SIGCOMP
    if (tport && tpn->tpn_comp) {
      if (cc == NONE)
	cc = agent_sigcomp_compartment(agent, tport, tpn);

      if (cc != NULL && cc != NONE && 
	  tport_delivered_using_udvm(tport, req_msg, NULL, 0) != -1) {
	tport_sigcomp_accept(tport, cc, req_msg);
      }
    }
#endif

    if (tport_tsend(tport, reply, tpn, 
		    IF_SIGCOMP_TPTAG_COMPARTMENT(cc)
		    TPTAG_MTU(INT_MAX), ta_tags(ta))) {
      agent->sa_stats->as_sent_msg++;
      agent->sa_stats->as_sent_response++;
      retval = 0;			/* Success! */
    }
    else {
      SU_DEBUG_3(("%s: send fails\n", __func__));
    }
  }

  nta_msg_discard(agent, reply);
  nta_msg_discard(agent, req_msg);

  return retval;
}


/** ACK and BYE an unknown 200 OK */
int nta_msg_ackbye(nta_agent_t *agent, msg_t *msg)
{
  sip_t *sip = sip_object(msg);
  msg_t *amsg = nta_msg_create(agent, 0);
  sip_t *asip = sip_object(amsg);
  msg_t *bmsg = nta_msg_create(agent, 0);
  sip_t *bsip = sip_object(bmsg);
  url_string_t const *ruri;
  nta_outgoing_t *ack = NULL, *bye = NULL;
  sip_cseq_t *cseq;
  sip_request_t *rq;
  sip_route_t *route = NULL, *r, r0[1];
  su_home_t *home = msg_home(amsg);

  if (asip == NULL || bsip == NULL)
    goto err;

  sip_add_tl(amsg, asip,
	     SIPTAG_TO(sip->sip_to),
	     SIPTAG_FROM(sip->sip_from),
	     SIPTAG_CALL_ID(sip->sip_call_id),
	     TAG_END());

  if (sip->sip_contact) {
    ruri = (url_string_t const *)sip->sip_contact->m_url;
  } else {
    ruri = (url_string_t const *)sip->sip_to->a_url;
  }

  /* Reverse (and fix) record route */
  route = sip_route_reverse(home, sip->sip_record_route);

  if (route && !url_has_param(route->r_url, "lr")) {
    for (r = route; r->r_next; r = r->r_next)
      ;

    /* Append r-uri */
    *sip_route_init(r0)->r_url = *ruri->us_url;
    r->r_next = sip_route_dup(home, r0);
    
    /* Use topmost route as request-uri */
    ruri = (url_string_t const *)route->r_url;
    route = route->r_next;
  }

  sip_header_insert(amsg, asip, (sip_header_t *)route);

  if (bmsg) {
    msg_clone(bmsg, amsg);
    sip_copy_all(bmsg, bsip, asip);
  }

  if (!(cseq = sip_cseq_create(home, sip->sip_cseq->cs_seq, SIP_METHOD_ACK)))
    goto err;
  else
    sip_header_insert(amsg, asip, (sip_header_t *)cseq);

  if (!(rq = sip_request_create(home, SIP_METHOD_ACK, ruri, NULL)))
    goto err;
  else
    sip_header_insert(amsg, asip, (sip_header_t *)rq);

  if (!(ack = nta_outgoing_tmcreate(agent, NULL, NULL, NULL, amsg,
				    NTATAG_ACK_BRANCH(sip->sip_via->v_branch),
				    TAG_END())))
    goto err;
  else
    nta_outgoing_destroy(ack);

  home = msg_home(bmsg);

  if (!(cseq = sip_cseq_create(home, 0x7fffffff, SIP_METHOD_BYE)))
    goto err;
  else
    sip_header_insert(bmsg, bsip, (sip_header_t *)cseq);

  if (!(rq = sip_request_create(home, SIP_METHOD_BYE, ruri, NULL)))
    goto err;
  else
    sip_header_insert(bmsg, bsip, (sip_header_t *)rq);

  if (!(bye = nta_outgoing_mcreate(agent, NULL, NULL, NULL, bmsg)))
    goto err;

  msg_destroy(msg);
  return 0;

 err:
  msg_destroy(amsg);
  msg_destroy(bmsg);
  return -1;
}

/**Complete a request with values from dialog.
 *
 * The function nta_msg_request_complete() completes a request message @a
 * msg belonging to a dialog associated with @a leg. It increments the local
 * @b CSeq value, adds @b Call-ID, @b To, @b From and @b Route headers (if
 * there is such headers present in @a leg), and creates a new request line
 * object from @a method, @a method_name and @a request_uri.
 *
 * @param msg          pointer to a request message object
 * @param leg          pointer to a #nta_leg_t object
 * @param method       request method number or #sip_method_unknown
 * @param method_name  method name (if @a method == #sip_method_unknown)
 * @param request_uri  request URI
 *
 * @retval 0  when successful
 * @retval -1 upon an error
 */
int nta_msg_request_complete(msg_t *msg,
			     nta_leg_t *leg,
			     sip_method_t method,
			     char const *method_name,
			     url_string_t const *request_uri)
{
  su_home_t *home = msg_home(msg);
  sip_t *sip = sip_object(msg);
  sip_cseq_t *cseq;
  sip_u32_t seq;

  if (!leg || !msg)
    return -1;

  if (!sip->sip_max_forwards)
    sip_add_dup(msg, sip, (sip_header_t *)leg->leg_agent->sa_max_forwards);

  if (!sip->sip_call_id) {
    if (leg->leg_id)
      sip->sip_call_id = sip_call_id_dup(home, leg->leg_id);
    else
      sip->sip_call_id = sip_call_id_create(home, NULL);
  }

  if (!sip->sip_from)
    sip->sip_from = sip_from_dup(home, leg->leg_local);
  else if (leg->leg_local && leg->leg_local->a_tag &&
	   (!sip->sip_from->a_tag ||
	    strcasecmp(sip->sip_from->a_tag, leg->leg_local->a_tag)))
    sip_from_tag(home, sip->sip_from, leg->leg_local->a_tag);

  if (sip->sip_from && !sip->sip_from->a_tag) {
    sip_fragment_clear(sip->sip_from->a_common);
    sip_from_add_param(home, sip->sip_from,
		       nta_agent_newtag(home, "tag=%s", leg->leg_agent));
  }

  if (!sip->sip_to)
    sip->sip_to = sip_to_dup(home, leg->leg_remote);
  else if (leg->leg_remote && leg->leg_remote->a_tag)
    sip_to_tag(home, sip->sip_to, leg->leg_remote->a_tag);

  if (!sip->sip_route && leg->leg_route) {
    if (leg->leg_loose_route) {
      if (leg->leg_target) {
	request_uri = (url_string_t *)leg->leg_target->m_url;
      }
      sip->sip_route = sip_route_dup(home, leg->leg_route);
    }
    else {
      sip_route_t **rr;

      request_uri = (url_string_t *)leg->leg_route->r_url;
      sip->sip_route = sip_route_dup(home, leg->leg_route->r_next);

      for (rr = &sip->sip_route; *rr; rr = &(*rr)->r_next)
	;

      if (leg->leg_target)
	*rr = sip_route_dup(home, (sip_route_t *)leg->leg_target);
    }
  }
  else if (leg->leg_target)
    request_uri = (url_string_t *)leg->leg_target->m_url;

  if (!request_uri && sip->sip_request)
    request_uri = (url_string_t *)sip->sip_request->rq_url;
  if (!request_uri && sip->sip_to) {
    if (method != sip_method_register)
      request_uri = (url_string_t *)sip->sip_to->a_url;
    else {
      /* Remove user part from REGISTER requests */
      url_t reg_url[1];
      *reg_url = *sip->sip_to->a_url;
      reg_url->url_user = reg_url->url_password = NULL;
      request_uri = (url_string_t *)reg_url;
    }
  }
  if (!request_uri)
    return -1;
  if (method || method_name)
    sip->sip_request =
      sip_request_create(home, method, method_name, request_uri, NULL);

  if (!sip->sip_request)
    return -1;

  method = sip->sip_request->rq_method;
  method_name = sip->sip_request->rq_method_name;

  if (sip->sip_cseq &&
      (method == sip_method_ack || method == sip_method_cancel))
    seq = sip->sip_cseq->cs_seq;
  else if (method == sip_method_ack || method == sip_method_cancel)
    seq = leg->leg_seq;
  else
    seq = ++leg->leg_seq;

  if (!(cseq = sip_cseq_create(home, seq, method, method_name)) ||
      sip_header_insert(msg, sip, (sip_header_t *)cseq) < 0)
    return -1;

  return 0;
}

/** Complete a response message.
 *
 */
int nta_msg_response_complete(msg_t *msg,
			      nta_incoming_t *irq,
			      int status, char const *phrase)
{
  su_home_t *home = msg_home(msg);
  sip_t *sip = sip_object(msg);
  int clone = 0;

  if (sip == NULL || irq == NULL ||
      (status != 0 && (status < 100 || status > 699)))
    return su_seterrno(EINVAL), -1;

  if (status >= 200 && !irq->irq_tag)
    nta_incoming_tag(irq, NULL);

  if (!sip->sip_status)
    clone = 1, sip->sip_status = sip_status_create(home, status, phrase, NULL);
  if (!sip->sip_from)
    clone = 1, sip->sip_from = sip_from_copy(home, irq->irq_from);
  if (!sip->sip_to)
    clone = 1, sip->sip_to = sip_to_copy(home, irq->irq_to);
  if (sip->sip_status && sip->sip_status->st_status > 100 &&
      irq->irq_tag && sip->sip_to && !sip->sip_to->a_tag)
    sip_to_tag(home, sip->sip_to, irq->irq_tag);
  if (!sip->sip_call_id)
    clone = 1, sip->sip_call_id = sip_call_id_copy(home, irq->irq_call_id);
  if (!sip->sip_cseq)
    clone = 1, sip->sip_cseq = sip_cseq_copy(home, irq->irq_cseq);
  if (!sip->sip_via)
    clone = 1, sip->sip_via = sip_via_copy(home, irq->irq_via);
  if (status < 300 && 
      !sip->sip_record_route && irq->irq_record_route &&
      sip->sip_cseq && sip->sip_cseq->cs_method != sip_method_register)
    sip_add_dup(msg, sip, (sip_header_t *)irq->irq_record_route);

  if (clone)
    msg_clone(msg, (msg_t *)irq->irq_home);

  return 0;
}


/* ====================================================================== */
/* 6) Dialogs (legs) */

static void leg_insert(nta_agent_t *agent, nta_leg_t *leg);
static int leg_route(nta_leg_t *leg,
		     sip_record_route_t const *route,
		     sip_record_route_t const *reverse,
		     sip_contact_t const *contact);
static int leg_callback_default(nta_leg_magic_t*, nta_leg_t*,
				nta_incoming_t*, sip_t const *);
#define HTABLE_HASH_LEG(leg) ((leg)->leg_hash)
HTABLE_BODIES(leg_htable, lht, nta_leg_t, HTABLE_HASH_LEG);
static inline
hash_value_t hash_istring(char const *, char const *, hash_value_t);

/**@typedef nta_request_f
 *
 * Callback for incoming requests
 *
 * This is a callback function invoked by NTA for each incoming SIP request.
 *
 * @param lmagic call leg context
 * @param leg    call leg handle
 * @param ireq   incoming request
 * @param sip    incoming request contents
 *
 * @retval 100..699
 * NTA constructs a reply message with given error code and corresponding
 * standard phrase, then sends the reply.
 *
 * @retval 0
 * The application takes care of sending (or not sending) the reply.
 *
 * @retval other
 * All other return values will be interpreted as
 * @e 500 @e Internal @e server @e error.
 */


/**
 * Create a new leg object.
 *
 * The function nta_leg_tcreate() creates a leg object. A leg object is used
 * to represent dialogs, partial dialogs (for example, in case of REGISTER),
 * and destinations within a particular NTA object.
 *
 * When a leg is created, a callback pointer and a application context is
 * provided. All other parameters are optional.
 *
 * @param agent    agent object
 * @param callback function which is called for each
 *                 incoming request belonging to this leg
 * @param magic    call leg context
 * @param tag,value,... optional extra headers in taglist
 *
 * When a leg representing dialog is created, the tags SIPTAG_CALL_ID(),
 * SIPTAG_FROM(), SIPTAG_TO(), and SIPTAG_CSEQ() (for local CSeqs) are used
 * to establish dialog context. The SIPTAG_FROM() is used to pass local
 * address (@b From header when making a call, @b To header when answering
 * to a call) to the newly created leg. Respectively, the SIPTAG_TO() is
 * used to pass remote address (@b To header when making a call, @b From
 * header when answering to a call).
 *
 * If there is a (preloaded) route associated with the leg, SIPTAG_ROUTE()
 * and NTATAG_TARGET() can be used. A client or server can also set the
 * route using @b Record-Route and @b Contact headers from a response or
 * request message with the functions nta_leg_client_route() and
 * nta_leg_server_route(), respectively.
 *
 * When a leg representing a local destination is created, the tags
 * NTATAG_NO_DIALOG(1), NTATAG_METHOD(), and URLTAG_URL() are used. When a
 * request with matching request-URI (URLTAG_URL()) and method
 * (NTATAG_METHOD()) is received, it is passed to the callback function
 * provided with the leg.
 *
 * @sa nta_leg_stateful(), nta_leg_bind(),
 *     nta_leg_tag(), nta_leg_rtag(),
 *     nta_leg_client_route(), nta_leg_server_route(),
 *     nta_leg_destroy(), nta_outgoing_tcreate(), and nta_request_f().
 *
 * @TAGS 
 * NTATAG_NO_DIALOG(), NTATAG_STATELESS(), NTATAG_METHOD(),
 * URLTAG_URL(), SIPTAG_CALL_ID(), SIPTAG_CALL_ID_STR(), SIPTAG_FROM(),
 * SIPTAG_FROM_STR(), SIPTAG_TO(), SIPTAG_TO_STR(), SIPTAG_ROUTE(),
 * NTATAG_TARGET() and SIPTAG_CSEQ().
 *
 */
nta_leg_t *nta_leg_tcreate(nta_agent_t *agent,
			   nta_request_f *callback,
			   nta_leg_magic_t *magic,
			   tag_type_t tag, tag_value_t value, ...)
{
  sip_route_t const *route = NULL;
  sip_contact_t const *contact = NULL;
  sip_cseq_t const *cs = NULL;
  sip_call_id_t const *i = NULL;
  sip_from_t const *from = NULL;
  sip_to_t const *to = NULL;
  char const *method = NULL;
  char const *i_str = NULL, *to_str = NULL, *from_str = NULL, *cs_str = NULL;
  url_string_t const *url_string = NULL;
  int no_dialog = 0;
  unsigned rseq = 0;
  /* RFC 3261 section 12.2.1.1 */
  uint32_t seq = (sip_now() >> 1) & 0x7ffffff;
  ta_list ta;
  nta_leg_t *leg;
  su_home_t *home;
  url_t *url;

  if (agent == NULL)
    return su_seterrno(EINVAL), NULL;

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta),
	  NTATAG_NO_DIALOG_REF(no_dialog),
	  NTATAG_METHOD_REF(method),
	  URLTAG_URL_REF(url_string),
	  SIPTAG_CALL_ID_REF(i),
	  SIPTAG_CALL_ID_STR_REF(i_str),
	  SIPTAG_FROM_REF(from),
	  SIPTAG_FROM_STR_REF(from_str),
	  SIPTAG_TO_REF(to),
	  SIPTAG_TO_STR_REF(to_str),
	  SIPTAG_ROUTE_REF(route),
	  NTATAG_TARGET_REF(contact),
	  NTATAG_REMOTE_CSEQ_REF(rseq),
	  SIPTAG_CSEQ_REF(cs),
	  SIPTAG_CSEQ_STR_REF(cs_str),
	  TAG_END());

  ta_end(ta);

  if (cs)
    seq = cs->cs_seq;
  else if (cs_str)
    seq = strtoul(cs_str, (char **)&cs_str, 10);

  if (i == NONE) /* Magic value, used for compatibility */
    no_dialog = 1;

  if (!(leg = su_home_clone(agent->sa_home, sizeof(*leg))))
    return NULL;
  home = leg->leg_home;

  leg->leg_agent = agent;
  nta_leg_bind(leg, callback, magic);

  if (from) {
    /* Now this is kludge */
    leg->leg_local_is_to = sip_is_to((sip_header_t*)from); 
    leg->leg_local = sip_to_dup(home, from);
  }
  else if (from_str)
    leg->leg_local = sip_to_make(home, from_str);

  if (to && no_dialog) {
    /* Remove tag, if any */
    sip_to_t to0[1]; *to0 = *to; to0->a_params = NULL;
    leg->leg_remote = sip_from_dup(home, to0);
  }
  else if (to)
    leg->leg_remote = sip_from_dup(home, to);
  else if (to_str)
    leg->leg_remote = sip_from_make(home, to_str);

  if (route && route != NONE)
    leg->leg_route = sip_route_dup(home, route);

  if (contact && contact != NONE) {
    sip_contact_t m[1];
    sip_contact_init(m);
    *m->m_url = *contact->m_url;
    leg->leg_target = sip_contact_dup(home, m);
  }

  url = url_hdup(home, url_string->us_url);

  /* Match to local hosts */
  if (url && agent_aliases(agent, url, NULL)) {
    url_t *changed = url_hdup(home, url);
    su_free(home, url);
    url = changed;
  }	

  leg->leg_rseq = rseq;
  leg->leg_seq = seq;
  leg->leg_url = url;

  if (from && from != NONE && leg->leg_local == NULL) {
    SU_DEBUG_3(("nta_leg_tcreate(): cannot duplicate local address\n"));
    goto err;
  }
  else if (to && to != NONE && leg->leg_remote == NULL) {
    SU_DEBUG_3(("nta_leg_tcreate(): cannot duplicate remote address\n"));
    goto err;
  }
  else if (route && route != NONE && leg->leg_route == NULL) {
    SU_DEBUG_3(("nta_leg_tcreate(): cannot duplicate route\n"));
    goto err;
  }
  else if (contact && contact != NONE && leg->leg_target == NULL) {
    SU_DEBUG_3(("nta_leg_tcreate(): cannot duplicate target\n"));
    goto err;
  }
  else if (url_string && leg->leg_url == NULL) {
    SU_DEBUG_3(("nta_leg_tcreate(): cannot duplicate local destination\n"));
    goto err;
  }

  if (!no_dialog) {
    if (!leg->leg_local || !leg->leg_remote) {
      /* To and/or From header missing */
      SU_DEBUG_3(("nta_leg_tcreate(): missing%s%s header\n",
		  !leg->leg_remote ? " To" : "",
		  !leg->leg_local ? " From" : ""));
      goto err;
    }

    leg->leg_dialog = 1;

    if (i != NULL)
      leg->leg_id = sip_call_id_dup(home, i);
    else if (i_str != NULL)
      leg->leg_id = sip_call_id_make(home, i_str);
    else
      leg->leg_id = sip_call_id_create(home, NULL);

    if (!leg->leg_id) {
      SU_DEBUG_3(("nta_leg_tcreate(): cannot create Call-ID\n"));
      goto err;
    }

    leg->leg_hash = leg->leg_id->i_hash;
  }
  else if (url) {
    /* This is "default leg" with a destination URL. */
    hash_value_t hash = 0;

    if (method) {
      leg->leg_method = su_strdup(home, method);
    }
#if 0
    else if (url->url_params) {
      int len = url_param(url->url_params, "method", NULL, 0);
      if (len) {
	char *tmp = su_alloc(home, len);
	leg->leg_method = tmp;
	url_param(url->url_params, "method", tmp, len);
      }
    }
#endif

    if (url->url_user && strcmp(url->url_user, "") == 0)
      url->url_user = "%";	/* Match to any user */

    hash = hash_istring(url->url_scheme, ":", 0);
    hash = hash_istring(url->url_host, "", hash);
    hash = hash_istring(url->url_user, "@", hash);

    leg->leg_hash = hash;
  }
  else {
    /* This is "default leg" without a destination URL. */
    if (agent->sa_default_leg) {
      SU_DEBUG_1(("leg_create(): tried to create second default leg\n"));
      su_seterrno(EEXIST);
      goto err;
    }
    else {
      agent->sa_default_leg = leg;
    }
    return leg;
  }

  if (url) {
    /* Parameters are ignored when comparing incoming URLs */
    url->url_params = NULL;
  }

  leg_insert(agent, leg);

  SU_DEBUG_9(("nta_leg_create(%p)\n", leg));

  return leg;

 err:
  su_home_zap(leg->leg_home);

  return NULL;
}

/**
 * Insert a call leg to agent.
 */
static
void leg_insert(nta_agent_t *sa, nta_leg_t *leg)
{
  leg_htable_t *leg_hash;
  assert(leg);
  assert(sa);

  if (leg->leg_dialog)
    leg_hash = sa->sa_dialogs;
  else
    leg_hash = sa->sa_defaults;

  if (leg_htable_is_full(leg_hash)) {
    leg_htable_resize(sa->sa_home, leg_hash, 0);
    assert(leg_hash->lht_table);
    SU_DEBUG_7(("nta: resized%s leg hash to %d\n",
		leg->leg_dialog ? "" : " default", leg_hash->lht_size));
  }

  /* Insert entry into hash table (before other legs with same hash) */
  leg_htable_insert(leg_hash, leg);
}

/**
 * Destroy a leg.
 *
 * @param leg leg to be destroyed
 */
void nta_leg_destroy(nta_leg_t *leg)
{
  SU_DEBUG_9(("nta_leg_destroy(%p)\n", leg));

  if (leg) {
    leg_htable_t *leg_hash;
    nta_agent_t *sa = leg->leg_agent;

    assert(sa);

    if (leg->leg_dialog) {
      assert(sa->sa_dialogs);
      leg_hash = sa->sa_dialogs;
    }
    else if (leg != sa->sa_default_leg) {
      assert(sa->sa_defaults);
      leg_hash = sa->sa_defaults;
    }
    else {
      sa->sa_default_leg = NULL;
      leg_hash = NULL;
    }

    if (leg_hash)
      leg_htable_remove(leg_hash, leg);

    leg_free(sa, leg);
  }
}

static
void leg_free(nta_agent_t *sa, nta_leg_t *leg)
{
  su_free(sa->sa_home, leg);
}

/** Return application context for the leg */
nta_leg_magic_t *nta_leg_magic(nta_leg_t const *leg,
			       nta_request_f *callback)
{
  if (leg)
    if (!callback || leg->leg_callback == callback)
      return leg->leg_magic;

  return NULL;
}

/**Bind a callback function and context to a leg object.
 *
 * The function nta_leg_bind() is used to change the callback
 * and context pointer attached to a leg object.
 *
 * @param leg      leg object to be bound
 * @param callback new callback function (or NULL if no callback is desired)
 * @param magic    new context pointer
 */
void nta_leg_bind(nta_leg_t *leg,
		  nta_request_f *callback,
		  nta_leg_magic_t *magic)
{
  if (leg) {
    if (callback)
      leg->leg_callback = callback;
    else
      leg->leg_callback = leg_callback_default;
    leg->leg_magic = magic;
  }
}

/** Add a local tag to the leg.
 *
 * @param leg leg to be tagged
 * @param tag tag to be added (if NULL, a tag generated by @b NTA is added)
 *
 * @return The function nta_leg_tag() returns 0 if successful,
 * -1 otherwise.
 */
int nta_leg_tag(nta_leg_t *leg, char const *tag)
{
  nta_agent_t *sa;

  if (!leg || !leg->leg_local)
    return su_seterrno(EINVAL), -1;

  /* If there already is a tag, return -1 if it does not match with new one */
  if (leg->leg_local->a_tag) {
    if (tag && str0casecmp(tag, leg->leg_local->a_tag))
      return -1;
    else
      return 0;
  }
  
  if (tag)
    return sip_to_tag(leg->leg_home, leg->leg_local, tag);

  sa = leg->leg_agent;

  if (!sa->sa_tag_3261 &&
      /* Use default tag only if this is "reply leg" */
      (leg->leg_local_is_to || (leg->leg_remote && leg->leg_remote->a_tag)))
    return sip_to_tag(leg->leg_home, leg->leg_local, sa->sa_2543_tag);

  /* Use different tag */
  tag = nta_agent_newtag(leg->leg_home, "tag=%s", leg->leg_agent);

  if (tag)
    return sip_to_add_param(leg->leg_home, leg->leg_local, tag);  
  else
    return -1;
}

/** Get local tag. */
char const *nta_leg_get_tag(nta_leg_t const *leg)
{
  if (leg && leg->leg_local)
    return leg->leg_local->a_tag;
  else
    return NULL;
}

/** Add a remote tag to the leg.
 *
 * @param leg leg to be tagged
 * @param tag tag to be added (@b must be non-NULL)
 *
 * @return The function nta_leg_tag() returns 0 if successful,
 * -1 otherwise.
 */
int nta_leg_rtag(nta_leg_t *leg, char const *tag)
{
  assert(leg);

  /* Add a tag parameter, unless there already is a tag */
  if (leg && leg->leg_remote && tag) {
    return sip_from_tag(leg->leg_home, leg->leg_remote, tag);
  }

  return -1;
}

/** Get remote tag. */
char const *nta_leg_get_rtag(nta_leg_t const *leg)
{
  if (leg && leg->leg_remote)
    return leg->leg_remote->a_tag;
  else
    return NULL;
}

/** Add UAC route.
 *
 * bis04 section 16.1
 */
int nta_leg_client_route(nta_leg_t *leg,
			 sip_record_route_t const *route,
			 sip_contact_t const *contact)
{
  return leg_route(leg, NULL, route, contact);
}

/** Add UAS route.
 *
 * bis04 section 16.2
 */
int nta_leg_server_route(nta_leg_t *leg,
			 sip_record_route_t const *route,
			 sip_contact_t const *contact)
{
  return leg_route(leg, route, NULL, contact);
}

/** Get route components */
int nta_leg_get_route(nta_leg_t *leg, 
		      sip_route_t const **return_route, 
		      sip_contact_t const **return_target)
{
  if (!leg)
    return -1;

  if (return_route)
    *return_route = leg->leg_route;

  if (return_target)
    *return_target = leg->leg_target;

  return 0;
}

/** Calculate a simple case-insensitive hash over a string */
static inline
hash_value_t hash_istring(char const *s, char const *term, hash_value_t hash)
{
  if (s) {
    for (; *s; s++) {
      unsigned char c = *s;
      if ('A' <= c && c <= 'Z')
	c += 'a' - 'A';
      hash = 38501U * (hash + c);
    }
    for (s = term; *s; s++) {
      unsigned char c = *s;
      hash = 38501U * (hash + c);
    }
  }

  return hash;
}

static void sm_leg_recv(su_root_magic_t *rm,
			su_msg_r msg,
			union sm_arg_u *u);

/** Process msg statefully using the leg. */
int nta_leg_stateful(nta_leg_t *leg, msg_t *msg)
{
  su_msg_r su_msg = SU_MSG_RINITIALIZER;
  nta_agent_t *agent = leg->leg_agent;
  su_root_t *root = agent->sa_root;
  struct leg_recv_s *a;

  /* Create a su message that is passed to NTA network thread */
  if (su_msg_create(su_msg,
		    su_root_task(root),
		    su_root_task(root),
		    sm_leg_recv, /* Function to call */
		    sizeof(struct leg_recv_s)) == SU_FAILURE)
    return -1;

  agent->sa_stats->as_trless_to_tr++;

  a = su_msg_data(su_msg)->a_leg_recv;

  a->leg = leg;
  a->msg = msg;

  a->tport = tport_incref(tport_delivered_by(agent->sa_tports, msg));

  return su_msg_send(su_msg);
}

/** @internal Delayed leg_recv(). */
static
void sm_leg_recv(su_root_magic_t *rm,
		 su_msg_r msg,
		 union sm_arg_u *u)
{
  struct leg_recv_s *a = u->a_leg_recv;
  leg_recv(a->leg, a->msg, sip_object(a->msg), a->tport);
  tport_decref(&a->tport);
}

/** @internal Handle requests intended for this leg. */
static
void leg_recv(nta_leg_t *leg, msg_t *msg, sip_t *sip, tport_t *tport)
{
  nta_agent_t *agent = leg->leg_agent;
  nta_incoming_t *irq;
  sip_method_t method = sip->sip_request->rq_method;
  char const *method_name = sip->sip_request->rq_method_name;
  char const *tag = NULL;
  int status;

  if (leg->leg_local)
    tag = leg->leg_local->a_tag;

  if (leg->leg_dialog)
    agent->sa_stats->as_dialog_tr++;

  /* RFC-3262 section 3 (page 4) */
  if (agent->sa_is_a_uas && method == sip_method_prack) {
    nta_msg_treply(agent, msg,
		   481, "No such response", 
		   NTATAG_TPORT(tport),
		   TAG_END());
    return;
  }

  if (!(irq = incoming_create(agent, msg, sip, tport, tag))) {
    SU_DEBUG_3(("nta: leg_recv(%p): cannot create transaction for %s\n",
		leg, method_name));
    nta_msg_treply(agent, msg,
		   SIP_500_INTERNAL_SERVER_ERROR,
		   NTATAG_TPORT(tport),
		   TAG_END());
    return;
  }

  irq->irq_in_callback = 1;
  status = incoming_callback(leg, irq, sip);
  irq->irq_in_callback = 0;

  if (irq->irq_destroyed && irq->irq_terminated) {
    incoming_free(irq);
    return;
  }

  if (status == 0)
    return;

  if (status < 100 || status > 699) {
    SU_DEBUG_3(("nta_leg(%p): invalid status %03d from callback\n",
		leg, status));
    status = 500;
  }
  else if (method == sip_method_invite && status >= 200 && status < 300) {
    SU_DEBUG_3(("nta_leg(%p): invalid INVITE status %03d from callback\n",
		leg, status));
    status = 500;
  }

  if (status >= 100 && irq->irq_status < 200)
    nta_incoming_treply(irq, status, NULL, TAG_END());

  if (status >= 200)
    nta_incoming_destroy(irq);
}

/**Compare two SIP from/to fields.
 *
 * @retval nonzero if matching.
 * @retval zero if not matching.
 */
static inline
int addr_cmp(url_t const *a, url_t const *b)
{
  if (b == NULL)
    return 0;
  else
    return
      str0casecmp(a->url_host, b->url_host)
      || str0cmp(a->url_port, b->url_port)
      || str0cmp(a->url_user, b->url_user);
}

/** Get a leg by dialog.
 *
 * The function nta_leg_by_dialog() searches for a dialog leg from agent's
 * hash table. The matching rules are as follows:
 * - @b Call-ID header contents must match
 * - @b if there is remote tag associated with leg, it must match 
 * - @b if there is no remote tag, the remote URI must match
 * - @b if there is local tag associated with leg, it must math
 * - @b if there is no loca tag, the local URI must match
 * - @b if @a request_uri is non-NULL and there is destination URI
 *      associated with the leg, these URIs must match
 *
 */
nta_leg_t *nta_leg_by_dialog(nta_agent_t const *agent,
			     url_t const *request_uri,
			     sip_call_id_t const *call_id,
			     char const *remote_tag,
			     url_t const *remote_url,
			     char const *local_tag,
			     url_t const *local_url)
{
  void *to_be_freed = NULL;
  url_t *url;
  nta_leg_t *leg;

  if (!agent || !call_id)
    return su_seterrno(EINVAL), NULL;

  if (request_uri == NULL)
    url = NULL;
  else if (URL_IS_STRING(request_uri)) {
    to_be_freed = url = url_hdup(NULL, request_uri);
  } else {
    url_t url0[1];
    *url0 = *request_uri;
    url = url0;
  }

  if (url) {
    url->url_params = NULL;
    agent_aliases(agent, url, NULL); /* canonize url */
  }
  
  leg = leg_find(agent, 
		 NULL, url, 
		 call_id, 
		 remote_tag, remote_url,
		 local_tag, local_url);

  if (to_be_freed)
    su_free(NULL, to_be_freed);

  return leg;
}

/**@internal
 * Find a leg corresponding to the request message.
 *
 * A leg matches to message if leg_match_request() returns true ("Call-ID",
 * "To", and "From" match).
 */
static
nta_leg_t *leg_find(nta_agent_t const *sa,
		    char const *method_name,
		    url_t const *request_uri,
		    sip_call_id_t const *i,
		    char const *from_tag,
		    url_t const *from_uri,
		    char const *to_tag,
		    url_t const *to_uri)
{
  hash_value_t hash = i->i_hash;
  leg_htable_t const *lht = sa->sa_dialogs;
  nta_leg_t  **ll, *leg, *loose_match = NULL;

  for (ll = leg_htable_hash(lht, hash);
       (leg = *ll);
       ll = leg_htable_next(lht, ll)) {
    sip_call_id_t const *leg_i = leg->leg_id;
    url_t const *remote_uri = leg->leg_remote->a_url;
    char const *remote_tag = leg->leg_remote->a_tag;
    url_t const *local_uri = leg->leg_local->a_url;
    char const *local_tag = leg->leg_local->a_tag;
    url_t const *leg_url = leg->leg_url;
    char const *leg_method = leg->leg_method;

    if (leg->leg_hash != hash)
      continue;
    if (strcmp(leg_i->i_id, i->i_id) != 0)
      continue;
    /* Do not match if the incoming To has tag, but the local does not */
    if (!local_tag && to_tag)
      continue;
    /* Do not match if incoming From has no tag but remote has a tag */
    if (remote_tag && !from_tag)
      continue;
    /* Avoid matching with itself */
    if (!remote_tag != !from_tag && !local_tag != !to_tag)
      continue;

    if (local_tag && to_tag ? 
	strcasecmp(local_tag, to_tag) : addr_cmp(local_uri, to_uri))
      continue;
    if (remote_tag && from_tag ? 
	strcasecmp(remote_tag, from_tag) : addr_cmp(remote_uri, from_uri))
      continue;

    if (leg_url && request_uri && url_cmp(leg_url, request_uri))
      continue;
    if (leg_method && method_name && strcasecmp(method_name, leg_method))
      continue;

    /* Perfect match if both local and To have tag
     * or local does not have tag.
     */
    if ((!local_tag || to_tag))
      return leg;

    if (loose_match == NULL)
      loose_match = leg;
  }

  return loose_match;
}

/** Get leg by destination */
nta_leg_t *nta_leg_by_uri(nta_agent_t const *agent, url_string_t const *us)
{
  url_t *url;
  nta_leg_t *leg;

  if (!agent)
    return NULL;

  if (!us)
    return agent->sa_default_leg;

  url = url_hdup(NULL, us->us_url);

  agent_aliases(agent, url, NULL);

  leg = url ? dst_find(agent, url, NULL) : NULL;

  su_free(NULL, url);

  return leg;
}

/** Find a non-dialog leg corresponding to the request uri u0 */
static
nta_leg_t *dst_find(nta_agent_t const *sa,
		    url_t const *u0,
		    char const *method_name)
{
  hash_value_t hash, hash2;
  leg_htable_t const *lht = sa->sa_defaults;
  nta_leg_t **ll, *leg, *loose_match = NULL;
   int again;
  url_t url[1];

  *url = *u0;
  hash = hash_istring(url->url_scheme, ":", 0);
  hash = hash_istring(url->url_host, "", hash);
  hash2 = hash_istring("%", "@", hash);
  hash = hash_istring(url->url_user, "@", hash);

  /* First round, search with user name */
  /* Second round, search without user name */
  do {
    for (ll = leg_htable_hash(lht, hash);
	 (leg = *ll);
	 ll = leg_htable_next(lht, ll)) {
      if (leg->leg_hash != hash)
	continue;
      if (url_cmp(url, leg->leg_url))
	continue;
      if (!method_name) {
	if (leg->leg_method)
	  continue;
	return leg;
      }
      else if (leg->leg_method) {
	if (strcasecmp(method_name, leg->leg_method))
	  continue;
	return leg;
      }
      loose_match = leg;
    }
    if (loose_match)
      return loose_match;

    again = 0;

    if (url->url_user && strcmp(url->url_user, "%")) {
      url->url_user = "%";
      hash = hash2;
      again = 1;
    }
  } while (again);

  return NULL;
}

/** Set leg route and target URL.
 *
 * The function leg_route() sets the leg route and contact using the
 * Record-Route and Contact headers.
 */
static
int leg_route(nta_leg_t *leg,
	      sip_record_route_t const *route,
	      sip_record_route_t const *reverse,
	      sip_contact_t const *contact)
{
  su_home_t *home = leg->leg_home;
  sip_route_t *r, r0[1];

  if (!leg)
    return -1;

  if (route == NULL && reverse == NULL && contact == NULL)
    return 0;

  sip_route_init(r0);

  if (leg->leg_route) {
    r = leg->leg_route;
  }
  else if (route) {
    r = sip_route_fixdup(home, route); if (!r) return -1;
  }
  else if (reverse) {
    r = sip_route_reverse(home, reverse); if (!r) return -1;
  }
  else
    r = NULL;

#ifdef NTA_STRICT_ROUTING
  /*
   * Handle Contact according to the RFC2543bis04 sections 16.1, 16.2 and 16.4.
   */
  if (contact) {
    *r0->r_url = *contact->m_url;

    if (!(m_r = sip_route_dup(leg->leg_home, r0)))
      return -1;

    /* Append, but replace last entry if it was generated from contact */
    for (rr = &r; *rr; rr = &(*rr)->r_next)
      if (leg->leg_contact_set && (*rr)->r_next == NULL)
	break;
  }
  else
    rr = NULL;

  if (rr) {
    if (*rr)
      su_free(leg->leg_home, *rr);
    *rr = m_r;
  }
  if (m_r != NULL)
    leg->leg_contact_set = 1;

#else
  if (r && r->r_url->url_params)
    leg->leg_loose_route = url_param(r->r_url->url_params, "lr", NULL, 0);

  if (contact) {
    sip_contact_t m[1], *m0;

    m0 = leg->leg_target;

    sip_contact_init(m);
    *m->m_url = *contact->m_url;
    leg->leg_target = sip_contact_dup(leg->leg_home, m);

    if (m0)
      su_free(leg->leg_home, m0);
  }
#endif

  leg->leg_route = r;

  return 0;
}

/** @internal Default leg callback. */
static int
leg_callback_default(nta_leg_magic_t *magic,
		     nta_leg_t  *leg,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  nta_incoming_treply(irq,
		      SIP_501_NOT_IMPLEMENTED,
		      TAG_END());
  return 0;
}

/* ====================================================================== */
/* 7) Server-side (incoming) transactions */

#define HTABLE_HASH_IRQ(irq) ((irq)->irq_hash)
HTABLE_BODIES(incoming_htable, iht, nta_incoming_t, HTABLE_HASH_IRQ);

static void incoming_insert(nta_agent_t *agent, 
			    incoming_queue_t *queue, 
			    nta_incoming_t *irq);

static inline int incoming_is_queued(nta_incoming_t const *irq);
static inline void incoming_queue(incoming_queue_t *queue, nta_incoming_t *);
static inline void incoming_remove(nta_incoming_t *irq);
static inline void incoming_set_timer(nta_incoming_t *, unsigned interval);
static inline void incoming_reset_timer(nta_incoming_t *);
static inline int incoming_mass_destroy(nta_agent_t *sa, incoming_queue_t *q);

static int incoming_set_params(nta_incoming_t *irq, tagi_t const *tags);
#if HAVE_SIGCOMP
static inline
int incoming_set_compartment(nta_incoming_t *irq, tport_t *tport, msg_t *msg,
			     int create_if_needed);
#endif

static inline nta_incoming_t
  *incoming_call_callback(nta_incoming_t *, msg_t *, sip_t *);
static inline int incoming_final_failed(nta_incoming_t *irq, msg_t *);
static void incoming_retransmit_reply(nta_incoming_t *irq, tport_t *tport);

/** Create a server transaction. 
 *
 * The function nta_incoming_create() creates a server transaction for a
 * request message. This function is used when an element processing
 * requests statelessly wants to process a particular request statefully.
 *
 * @param agent pointer to agent object
 * @param leg  pointer to leg object (either @a agent or @a leg may be NULL)
 * @param msg  pointer to message object
 * @param sip  pointer to SIP structure (may be NULL)
 * @param tag,value,... optional tagged parameters
 *
 * @TAGS
 * @TAG NTATAG_TPORT() specifies the transport used to receive the request 
 *      and also default transport for sending the response.
 */
nta_incoming_t *nta_incoming_create(nta_agent_t *agent,
				    nta_leg_t *leg,
				    msg_t *msg,
				    sip_t *sip,
				    tag_type_t tag, tag_value_t value, ...)
{
  char const *to_tag = NULL;
  tport_t *tport = NULL;
  ta_list ta;

  if (agent == NULL && leg != NULL)
    agent = leg->leg_agent;

  if (sip == NULL)
    sip = sip_object(msg);

  if (agent == NULL || msg == NULL || sip == NULL)
    return NULL;

  if (!sip->sip_request || !sip->sip_cseq)
    return NULL;

  ta_start(ta, tag, value);
  
  tl_gets(ta_args(ta), 
	  NTATAG_TPORT_REF(tport), 
	  TAG_END());
  ta_end(ta);

  if (leg && leg->leg_local)
    to_tag = leg->leg_local->a_tag;

  if (tport == NULL)
    tport = tport_delivered_by(agent->sa_tports, msg);

  return incoming_create(agent, msg, sip, tport, to_tag);
}

/** @internal Create a new incoming transaction object. */
static
nta_incoming_t *incoming_create(nta_agent_t *agent,
				msg_t *msg,
				sip_t *sip,
				tport_t *tport,
				char const *tag)
{
  nta_incoming_t *irq = su_zalloc(msg_home(msg), sizeof(*irq));

  agent->sa_stats->as_server_tr++;

  if (irq) {
    su_home_t *home;
    incoming_queue_t *queue;
    sip_method_t method = sip->sip_request->rq_method;

    irq->irq_request = msg = msg_ref_create(msg); 
    irq->irq_home = home = msg_home(msg);
    irq->irq_agent = agent;

    irq->irq_received = agent_now(agent);

    irq->irq_method  = method;
    irq->irq_rq = sip_request_copy(home, sip->sip_request);
    irq->irq_from = sip_from_copy(home, sip->sip_from);
    irq->irq_to = sip_to_copy(home, sip->sip_to);
    irq->irq_call_id = sip_call_id_copy(home, sip->sip_call_id);
    irq->irq_cseq = sip_cseq_copy(home, sip->sip_cseq);
    irq->irq_via = sip_via_copy(home, sip->sip_via);
    irq->irq_record_route = sip_record_route_copy(home, sip->sip_record_route);
    irq->irq_branch  = irq->irq_via->v_branch;
    irq->irq_reliable_tp = tport_is_reliable(tport);

    if (sip->sip_timestamp)
      irq->irq_timestamp = sip_timestamp_copy(home, sip->sip_timestamp);

    /* Tag transaction */
    if (tag)
      sip_to_tag(home, irq->irq_to, tag);

    if (!(irq->irq_tag = irq->irq_to->a_tag) && !agent->sa_tag_3261) {
      sip_to_tag(home, irq->irq_to, agent->sa_2543_tag);
      irq->irq_tag = irq->irq_to->a_tag;
      irq->irq_tag_set = 1;
    }

    if (method != sip_method_ack) {
      int *use_rport = NULL;
      int retry_without_rport = 0;

      if (agent->sa_server_rport)
	use_rport = &retry_without_rport, retry_without_rport = 1;

      if (nta_tpn_by_via(irq->irq_tpn, irq->irq_via, use_rport) < 0)
	SU_DEBUG_1(("%s: bad via\n", __func__));
    }

#if HAVE_SIGCOMP
    incoming_set_compartment(irq, tport, msg, 0);
#endif

    if (method == sip_method_invite) {
      irq->irq_must_100rel =
	sip->sip_require && sip_has_feature(sip->sip_require, "100rel");

      if (irq->irq_must_100rel ||
	  (sip->sip_supported &&
	   sip_has_feature(sip->sip_supported, "100rel"))) {
	/* Initialize rseq */
	irq->irq_rseq = (random() & 0x7fffffff);
	irq->irq_rseq += irq->irq_rseq == 0;
      }

      queue = agent->sa_in.proceeding;

      if (irq->irq_reliable_tp)
	incoming_set_timer(irq, agent->sa_t2 / 2); /* N1 = T2 / 2 */
      else
	incoming_set_timer(irq, 200); /* N1 = 200 ms */

      irq->irq_tport = tport_incref(tport);
    }
    else if (method == sip_method_ack) {
      irq->irq_status = 700;	/* Never send reply to ACK */
      irq->irq_completed = 1;
      if (irq->irq_reliable_tp || !agent->sa_is_a_uas) {
	queue = agent->sa_in.terminated;
	irq->irq_terminated = 1;
      }
      else {
	queue = agent->sa_in.completed;	/* Timer J */
      }
    } 
    else {
      queue = agent->sa_in.proceeding;
	/* draft-sparks-sip-nit-actions-03:

   Blacklisting on a late response occurs even over reliable transports.
   Thus, if an element processing a request received over a reliable
   transport is delaying its final response at all, sending a 100 Trying
   well in advance of the timeout will prevent blacklisting.  Sending a
   100 Trying immediately will not harm the transaction as it would over
   UDP, but a policy of always sending such a message results in
   unneccessary traffic.  A policy of sending a 100 Trying after the
   period of time in which Timer E reaches T2 had this been a UDP hop is
   one reasonable compromise.

	 */	
      if (agent->sa_extra_100 && irq->irq_reliable_tp)
	incoming_set_timer(irq, agent->sa_t2 / 2); /* T2 / 2 */

      irq->irq_tport = tport_incref(tport);
    }

    irq->irq_hash = NTA_HASH(irq->irq_call_id, irq->irq_cseq->cs_seq);

    incoming_insert(agent, queue, irq);
  }

  return irq;
}

/** @internal
 * Insert incoming transaction to hash table.
 */
static void
incoming_insert(nta_agent_t *agent, 
		incoming_queue_t *queue,
		nta_incoming_t *irq)
{
  incoming_queue(queue, irq);

  if (incoming_htable_is_full(agent->sa_incoming))
    incoming_htable_resize(agent->sa_home, agent->sa_incoming, 0);

  if (irq->irq_method != sip_method_ack)
    incoming_htable_insert(agent->sa_incoming, irq);
  else
    /* ACK is appended - final response with tags match with it,
     * not with the original INVITE transaction */
    /* XXX - what about rfc2543 servers, which do not add tag? */
    incoming_htable_append(agent->sa_incoming, irq);
}

/** Call callback for incoming request */
static
int incoming_callback(nta_leg_t *leg, nta_incoming_t *irq, sip_t *sip)
{
  sip_method_t method = sip->sip_request->rq_method;
  char const *method_name = sip->sip_request->rq_method_name;

  /* RFC-3261 section 12.2.2 (page 76) */
  if (leg->leg_dialog && 
      irq->irq_agent->sa_is_a_uas && 
      method != sip_method_ack) {
    uint32_t seq = sip->sip_cseq->cs_seq;

    if (leg->leg_rseq > sip->sip_cseq->cs_seq) {
      SU_DEBUG_3(("nta_leg(%p): out-of-order %s (%u < %u)\n",
		  leg, method_name, seq, leg->leg_rseq));
      return 500;
    }

    leg->leg_rseq = seq;
  }

  return leg->leg_callback(leg->leg_magic, leg, irq, sip);
}

/**
 * Destroy an incoming transaction.
 *
 * This function does not actually free transaction object, but marks it as
 * disposable. The object is freed after a timeout.
 *
 * @param irq incoming request object to be destroyed
 */
void nta_incoming_destroy(nta_incoming_t *irq)
{
  if (irq) {
    irq->irq_callback = NULL;
    irq->irq_magic = NULL;
    irq->irq_destroyed = 1;
    if (irq->irq_terminated && !irq->irq_in_callback)
      incoming_free(irq);
  }
}

/** @internal
 * Initialize a queue for incoming transactions.
 */
static void
incoming_queue_init(incoming_queue_t *queue, unsigned timeout)
{
  memset(queue, 0, sizeof *queue);
  queue->q_tail = &queue->q_head;
  queue->q_timeout = timeout;
}

/** Change the timeout value of a queue */
static void
incoming_queue_adjust(nta_agent_t *sa, 
		      incoming_queue_t *queue, 
		      unsigned timeout)
{
  nta_incoming_t *irq;
  su_duration_t latest;

  if (timeout >= queue->q_timeout || !queue->q_head) {
    queue->q_timeout = timeout;
    return;
  }

  latest = set_timeout(sa, queue->q_timeout = timeout);

  for (irq = queue->q_head; irq; irq = irq->irq_next) {
    if (irq->irq_timeout - latest > 0)
      irq->irq_timeout = latest;
  }
}

/** @internal
 * Test if an incoming transaction is in a queue.
 */
static inline
int incoming_is_queued(nta_incoming_t const *irq)
{
  return irq && irq->irq_queue;
}

/** @internal
 * Insert an incoming transaction into a queue. 
 *
 * The function incoming_queue() inserts a server transaction into a queue,
 * and sets the corresponding timeout at the same time.
 */
static inline
void incoming_queue(incoming_queue_t *queue, 
		    nta_incoming_t *irq)
{
  if (irq->irq_queue == queue) {
    assert(queue->q_timeout == 0);
    return;
  }

  if (incoming_is_queued(irq))
    incoming_remove(irq);

  assert(*queue->q_tail == NULL);

  if (queue->q_timeout)
    irq->irq_timeout = set_timeout(irq->irq_agent, queue->q_timeout);
  else
    irq->irq_timeout = 0;

  irq->irq_queue = queue;
  irq->irq_prev = queue->q_tail; 
  *queue->q_tail = irq;
  queue->q_tail = &irq->irq_next;
  queue->q_length++;
}

/** @internal
 * Remove an incoming transaction from a queue.
 */
static inline
void incoming_remove(nta_incoming_t *irq)
{
  assert(incoming_is_queued(irq));
  assert(irq->irq_queue->q_length > 0);

  if ((*irq->irq_prev = irq->irq_next))
    irq->irq_next->irq_prev = irq->irq_prev;
  else
    irq->irq_queue->q_tail = irq->irq_prev, assert(!*irq->irq_queue->q_tail);

  irq->irq_queue->q_length--;
  irq->irq_next = NULL;
  irq->irq_prev = NULL;
  irq->irq_queue = NULL;
  irq->irq_timeout = 0;
}

static inline
void incoming_set_timer(nta_incoming_t *irq, unsigned interval)
{
  nta_incoming_t **rq;
  
  assert(irq);

  if (interval == 0) {
    incoming_reset_timer(irq);
    return;
  }

  if (irq->irq_rprev) {
    if ((*irq->irq_rprev = irq->irq_rnext)) 
      irq->irq_rnext->irq_rprev = irq->irq_rprev;
    if (irq->irq_agent->sa_in.re_t1 == &irq->irq_rnext)
      irq->irq_agent->sa_in.re_t1 = irq->irq_rprev;
  } else {
    irq->irq_agent->sa_in.re_length++;
  }

  irq->irq_retry = set_timeout(irq->irq_agent, irq->irq_interval = interval);

  rq = irq->irq_agent->sa_in.re_t1;

  if (!(*rq) || (*rq)->irq_retry - irq->irq_retry > 0)
    rq = &irq->irq_agent->sa_in.re_list;

  while (*rq && (*rq)->irq_retry - irq->irq_retry <= 0)
    rq = &(*rq)->irq_rnext;

  if ((irq->irq_rnext = *rq))
    irq->irq_rnext->irq_rprev = &irq->irq_rnext;
  *rq = irq;
  irq->irq_rprev = rq;

  /* Optimization: keep special place for transactions with T1 interval */
  if (interval == irq->irq_agent->sa_t1)
    irq->irq_agent->sa_in.re_t1 = rq;
}

static inline
void incoming_reset_timer(nta_incoming_t *irq)
{
  if (irq->irq_rprev) {
    if ((*irq->irq_rprev = irq->irq_rnext)) 
      irq->irq_rnext->irq_rprev = irq->irq_rprev;
    if (irq->irq_agent->sa_in.re_t1 == &irq->irq_rnext)
      irq->irq_agent->sa_in.re_t1 = irq->irq_rprev;
    irq->irq_agent->sa_in.re_length--;
  } 

  irq->irq_interval = 0, irq->irq_retry = 0;
  irq->irq_rnext = NULL, irq->irq_rprev = NULL;
}

/** @internal
 * Free an incoming transaction.
 */
static
void incoming_free(nta_incoming_t *irq)
{
  SU_DEBUG_9(("nta: incoming_free(%p)\n", irq));

  incoming_cut_off(irq);
  incoming_reclaim(irq);
}

/** Remove references to the irq */
static inline
void incoming_cut_off(nta_incoming_t *irq)
{
  nta_agent_t *agent = irq->irq_agent;

  assert(agent);

  if (incoming_is_queued(irq))
    incoming_remove(irq);

  incoming_reset_timer(irq);

  incoming_htable_remove(agent->sa_incoming, irq);

#if HAVE_SIGCOMP
  if (irq->irq_cc)
    sigcomp_compartment_unref(irq->irq_cc), irq->irq_cc = NULL;
#endif

  if (irq->irq_tport)
    tport_decref(&irq->irq_tport);
}

/** Reclaim the memory used by irq */
static inline
void incoming_reclaim(nta_incoming_t *irq)
{
  su_home_t *home = irq->irq_home;

  if (irq->irq_request)
    msg_destroy(irq->irq_request), irq->irq_request = NULL;
  if (irq->irq_request2)
    msg_destroy(irq->irq_request2), irq->irq_request2 = NULL;
  if (irq->irq_response)
    msg_destroy(irq->irq_response), irq->irq_response = NULL;

  irq->irq_home = NULL;

  su_free(home, irq);

  msg_ref_destroy((msg_ref_t *)home); 
}

/** Queue request to be freed */
static inline 
void incoming_free_queue(incoming_queue_t *q, nta_incoming_t *irq)
{
  incoming_cut_off(irq);
  incoming_queue(q, irq);
}

/** Reclaim memory used by queue of requests */
static 
void incoming_reclaim_queued(su_root_magic_t *rm,
			     su_msg_r msg,
			     union sm_arg_u *u)
{
  incoming_queue_t *q = u->a_incoming_queue;
  nta_incoming_t *irq, *irq_next;

  SU_DEBUG_9(("incoming_reclaim_all(%p, %p, %p)\n", rm, msg, u));

  for (irq = q->q_head; irq; irq = irq_next) {
    irq_next = irq->irq_next;
    incoming_reclaim(irq);
  }
}

/**Bind a callback and context to an incoming transaction object
 *
 * The function nta_incoming_bind() is used to set the callback and
 * context pointer attached to an incoming request object.  The callback
 * function will be invoked if the incoming request is cancelled, or if the
 * final response to an incoming @b INVITE request has been acknowledged.
 *
 * If the callback is NULL, or no callback has been bound, NTA invokes the
 * request callback of the call leg.
 *
 * @param irq      incoming transaction
 * @param callback callback function
 * @param magic    application context
 */
void nta_incoming_bind(nta_incoming_t *irq,
		       nta_ack_cancel_f *callback,
		       nta_incoming_magic_t *magic)
{
  irq->irq_callback = callback;
  irq->irq_magic = magic;
}

/** Set local tag to incoming request */
int nta_incoming_tag(nta_incoming_t *irq, char const *tag)
{
  nta_agent_t *sa;

  if (!irq)
    return -1;

  sa = irq->irq_agent;

  if (tag == NULL) {
    if (irq->irq_tag)
      tag = irq->irq_tag;
    else if (!sa->sa_tag_3261 && sa->sa_2543_tag)
      tag = sa->sa_2543_tag + strlen("tag=");
  }

  if (irq->irq_tag) {
    char const *value;
    if (!tag)
      return -1;
    value = strchr(tag, '=');
    if (!value++)
      value = tag;
    if (strcmp(value, irq->irq_tag) == 0)
      return 0;			/* Trying to set identical tag */
    else
      return -1;
  }
  else {
    if (tag)
      irq->irq_tag = su_strdup(irq->irq_home, tag);
    else
      irq->irq_tag = nta_agent_newtag(irq->irq_home, NULL, irq->irq_agent);
    if (irq->irq_tag) {
      irq->irq_tag_set = 1;
      return 0;
    }
  }
  return -1;
}

/** Set local tag to incoming request */
char const *nta_incoming_tag_3261(nta_incoming_t *irq, char const *tag)
{
  if (!irq)
    return NULL;

  if (!irq->irq_tag) {
    if (tag == NULL)
      tag = nta_agent_newtag(irq->irq_home, NULL, irq->irq_agent);
    else if (strchr(tag, '='))
      tag = strchr(tag, '=') + 1;

    irq->irq_tag = tag;
    irq->irq_tag_set = 1;
  }

  return irq->irq_tag;
}


/**Get request message.
 *
 * Retrieve the incoming request message of the incoming transaction. Note
 * that the message is not copied, but a new reference to it is created.
 *
 * @param irq incoming transaction handle
 *
 * @retval
 * A pointer to request message is returned.
 */
msg_t *nta_incoming_getrequest(nta_incoming_t *irq)
{
  msg_t *msg = NULL;

  if (irq)
    msg = msg_ref_create(irq->irq_request);

  return msg;
}

/**Get ACK or CANCEL message.
 *
 * Retrieve the incoming ACK or CANCEL request message of the incoming
 * transaction. Note that the ACK or CANCEL message is not copied, but a new
 * reference to it is created.
 *
 * @param irq incoming transaction handle
 *
 * @retval A pointer to request message is returned, or NULL if there is no
 * CANCEL or ACK received.
 */
msg_t *nta_incoming_getrequest_ackcancel(nta_incoming_t *irq)
{
  msg_t *msg = NULL;

  if (irq && irq->irq_request2)
    msg = msg_ref_create(irq->irq_request2);

  return msg;
}

/**Get response message.
 *
 * The function nta_incoming_getresponse() retrieves a copy of the latest
 * outgoing response message.  The response message is copied; the original
 * copy is kept by the transaction.
 *
 * @param irq incoming (server) transaction handle
 *
 * @retval
 * A pointer to the copy of the response message is returned, or NULL if an
 * error occurred.
 */
msg_t *nta_incoming_getresponse(nta_incoming_t *irq)
{
  if (irq && irq->irq_response) {
    msg_t *msg = nta_msg_create(irq->irq_agent, 0);
    sip_t *sip = sip_object(msg);

    msg_clone(msg, irq->irq_response);

    /* Copy the SIP headers from the old message */
    if (sip_copy_all(msg, sip, sip_object(irq->irq_response)) >= 0)
      return msg;

    msg_destroy(msg);
  }

  return NULL;
}

/** Get method of a server transaction.
 */
sip_method_t nta_incoming_method(nta_incoming_t const *irq)
{
  return irq ? irq->irq_method : sip_method_invalid;
}

/** Get Request-URI of a server transaction */
url_t const *nta_incoming_url(nta_incoming_t const *irq)
{
  return irq ? irq->irq_rq->rq_url : NULL;
}

/** Get sequence number of a server transaction.
 */
sip_u32_t nta_incoming_cseq(nta_incoming_t const *irq)
{
  return irq ? irq->irq_cseq->cs_seq : 0;
}

/** Get local tag for incoming request */
char const *nta_incoming_get_ltag(nta_incoming_t const *irq)
{
  return irq ? irq->irq_tag : 0;
}


/**
 * Get status code of a server transaction.
 */
int nta_incoming_status(nta_incoming_t const *irq)
{
  return irq ? irq->irq_status : 500;
}

/** Get context pointer for an incoming transaction */
nta_incoming_magic_t *nta_incoming_magic(nta_incoming_t *irq,
					 nta_ack_cancel_f *callback)
{
  return irq && irq->irq_callback == callback ? irq->irq_magic : NULL;
}

/** Find incoming transaction */
nta_incoming_t *nta_incoming_find(nta_agent_t const *agent,
				  sip_t const *sip,
				  sip_via_t const *v)
{
  return incoming_find(agent, sip, v, NULL, NULL);
}

static inline
int addr_match(sip_addr_t const *a, sip_addr_t const *b)
{
  if (a->a_tag && b->a_tag)
    return strcasecmp(a->a_tag, b->a_tag) == 0;
  else
    return
      str0casecmp(a->a_host, b->a_host) == 0 &&
      str0cmp(a->a_user, b->a_user) == 0;
}

/** Find a matching server transaction object.
 *
 *
 */
static inline
nta_incoming_t *incoming_find(nta_agent_t const *agent,
			      sip_t const *sip,
			      sip_via_t const *v,
			      nta_incoming_t **merge,
			      nta_incoming_t **ack)
{
  sip_cseq_t const *cseq = sip->sip_cseq;
  sip_call_id_t const *i = sip->sip_call_id;
  sip_to_t const *to = sip->sip_to;
  sip_from_t const *from = sip->sip_from;
  sip_request_t *rq = sip->sip_request;
  int is_uas_ack = ack && agent->sa_is_a_uas && rq->rq_method == sip_method_ack;
  incoming_htable_t const *iht = agent->sa_incoming;
  hash_value_t hash = NTA_HASH(i, cseq->cs_seq);

  nta_incoming_t **ii, *irq, *maybe;

  for (ii = incoming_htable_hash(iht, hash), maybe = NULL;
       (irq = *ii);
       ii = incoming_htable_next(iht, ii)) {
    if (hash != irq->irq_hash ||
	irq->irq_call_id->i_hash != i->i_hash ||
	strcmp(irq->irq_call_id->i_id, i->i_id))
      continue;
    if (irq->irq_cseq->cs_seq != cseq->cs_seq)
      continue;
    if (str0casecmp(irq->irq_from->a_tag, from->a_tag))
      continue;
    if (is_uas_ack) {
      if (!addr_match(irq->irq_to, to))
	continue;
    }
    else if (irq->irq_tag_set || !irq->irq_tag) {
      if (str0casecmp(irq->irq_to->a_host, to->a_host) != 0 ||
	  str0cmp(irq->irq_to->a_user, to->a_user) != 0)
	continue;
    }
    else if (str0casecmp(irq->irq_to->a_tag, to->a_tag))
      continue;

    if (str0casecmp(irq->irq_via->v_branch, v->v_branch) != 0) {
      if (!agent->sa_is_a_uas)
	continue;
      if (is_uas_ack && irq->irq_status >= 200 && irq->irq_status < 300)
	*ack = irq;
      /* RFC3261 - section 8.2.2.2 Merged Requests */
      else if (merge && !to->a_tag && agent->sa_merge_482)
	*merge = irq;
      continue;
    }
    if (!is_uas_ack && url_cmp(irq->irq_rq->rq_url, rq->rq_url))
      continue;

#if 0
    if (irq->irq_terminated)
      continue;
#endif

    if (irq->irq_method == rq->rq_method)
      break;		/* found */

    if (ack && rq->rq_method == sip_method_cancel)
      *ack = irq;
    else if (ack && rq->rq_method == sip_method_ack && 
	     irq->irq_method == sip_method_invite)
      *ack = irq;
  }

  if (irq)
    return irq;

  /* Check PRACKed requests */
  if (ack && rq->rq_method == sip_method_prack && sip->sip_rack) {
    sip_rack_t const *rack = sip->sip_rack;
    hash = NTA_HASH(i, rack->ra_cseq);

    for (ii = incoming_htable_hash(iht, hash);
	 (irq = *ii);
	 ii = incoming_htable_next(iht, ii)) {
      if (hash != irq->irq_hash)
	continue;
      if (irq->irq_call_id->i_hash != i->i_hash)
	continue;
      if (strcmp(irq->irq_call_id->i_id, i->i_id))
	continue;
      if (irq->irq_cseq->cs_seq != rack->ra_cseq)
	continue;
      if (!addr_match(irq->irq_to, to) ||
	  !addr_match(irq->irq_from, from))
	continue;
      if (!irq->irq_from->a_tag != !from->a_tag)
	continue;
      *ack = irq;

      return NULL;
    }
  }

  return irq;
}

/** Process retransmitted requests. */
static inline
int 
incoming_recv(nta_incoming_t *irq, msg_t *msg, sip_t *sip, tport_t *tport)
{
  nta_agent_t *agent = irq->irq_agent;

  agent->sa_stats->as_recv_retry++;

  if (irq->irq_status >= 100) {
    SU_DEBUG_5(("nta: re-received %s request, retransmitting %u reply\n",
		sip->sip_request->rq_method_name, irq->irq_status));
    incoming_retransmit_reply(irq, tport);
  }
  else if (irq->irq_agent->sa_extra_100) {
    /* Answer automatically with 100 Trying */
    if (irq->irq_method == sip_method_invite ||
	/*
	 * Send 100 trying to non-invite if at least half of T2 has expired
	 * since the transaction was created.
	 */
	su_duration(agent_now(irq->irq_agent), irq->irq_received) * 2 >
	irq->irq_agent->sa_t2) {
      SU_DEBUG_5(("nta: re-received %s request, sending 100 Trying\n",
		  sip->sip_request->rq_method_name));
      nta_incoming_treply(irq, SIP_100_TRYING, NTATAG_TPORT(tport), TAG_END());
    }
  }

  msg_destroy(msg);

  return 0;
}

static inline
int incoming_ack(nta_incoming_t *irq, msg_t *msg, sip_t *sip, tport_t *tport)
{
  nta_agent_t *agent = irq->irq_agent;

  /* Process ACK separately? */
  if (irq->irq_status >= 200 && irq->irq_status < 300 && !agent->sa_is_a_uas)
    return -1;

  if (irq->irq_queue == agent->sa_in.inv_completed) {
    if (!irq->irq_confirmed)
      agent->sa_stats->as_acked_tr++;

    irq->irq_confirmed = 1;
    incoming_reset_timer(irq); /* Reset timer G */

    if (!irq->irq_reliable_tp) {
      incoming_queue(agent->sa_in.inv_confirmed, irq); /* Timer I */
    }
    else {
      irq->irq_terminated = 1;
      incoming_queue(agent->sa_in.terminated, irq);
    }

    if (!irq->irq_destroyed) {
      if (!irq->irq_callback)	/* Process ACK normally */
	return -1;

      incoming_call_callback(irq, msg, sip); /* ACK callback */
    }
  } else if (irq->irq_queue == agent->sa_in.proceeding ||
	     irq->irq_queue == agent->sa_in.preliminary)
    return -1;
  else 
    assert(irq->irq_queue == agent->sa_in.inv_confirmed ||
	   irq->irq_queue == agent->sa_in.terminated);

  msg_destroy(msg);

  return 0;
}

static inline
int incoming_cancel(nta_incoming_t *irq, msg_t *msg, sip_t *sip,
		    tport_t *tport)
{
  nta_agent_t *agent = irq->irq_agent;

  /* Respond to the CANCEL */
  nta_msg_treply(agent, msg_ref_create(msg), SIP_200_OK, 
		 NTATAG_TPORT(tport),
		 TAG_END());

  if (irq->irq_completed || irq->irq_method != sip_method_invite)
    return 0;

  /* CANCEL */
  if (!irq->irq_canceled) {
    irq->irq_canceled = 1;
    agent->sa_stats->as_canceled_tr++;
    irq = incoming_call_callback(irq, msg, sip);
  }

  if (irq && !irq->irq_completed && agent->sa_cancel_487)
    /* Respond to the cancelled request */
    nta_incoming_treply(irq, SIP_487_REQUEST_CANCELLED, TAG_END());

  msg_destroy(msg);

  return 0;
}

/** Process merged requests */
static inline
int incoming_merge(nta_incoming_t *irq, msg_t *msg, sip_t *sip, tport_t *tport)
{
  nta_agent_t *agent = irq->irq_agent;

  agent->sa_stats->as_merged_request++;

  irq = incoming_create(irq->irq_agent, msg, sip, tport, irq->irq_tag);

  if (!irq) {
    SU_DEBUG_3(("nta: incoming_merge(): cannot create transaction for %s\n",
		sip->sip_request->rq_method_name));
    nta_msg_treply(agent, msg, 482, "Request merged", 
		   NTATAG_TPORT(tport),
		   TAG_END());
    return 0;
  }

  nta_incoming_treply(irq, 482, "Request merged", TAG_END());
  nta_incoming_destroy(irq);

  return 0;
}

/**@typedef nta_ack_cancel_f
 *
 * Callback function prototype for CANCELed/ACKed requests
 *
 * This is a callback function is invoked by NTA when an incoming request
 * has been cancelled or an response to an incoming INVITE request has been
 * acknowledged.
 *
 * @param magic   incoming request context
 * @param ireq    incoming request
 * @param sip     ACK/CANCEL message
 *
 * @retval 0
 * This callback function should return always 0.
 */

/** Call callback of incoming transaction */
static inline
nta_incoming_t *
incoming_call_callback(nta_incoming_t *irq, msg_t *msg, sip_t *sip)
{
  if (irq->irq_callback) {
    irq->irq_in_callback = 1;
    irq->irq_request2 = msg;
    irq->irq_callback(irq->irq_magic, irq, sip);
    irq->irq_request2 = NULL;
    irq->irq_in_callback = 0;

    if (irq->irq_terminated && irq->irq_destroyed)
      incoming_free(irq), irq = NULL;
  }
  return irq;
}

/**Set server transaction parameters.
 *
 * Sets the server transaction parameters. The parameters determine the way
 * the SigComp compression is handled.
 *
 * @TAGS
 * NTATAG_COMP(), and NTATAG_SIGCOMP_CLOSE().
 *
 * @retval number of set parameters when succesful
 * @retval -1 upon an error
 */
int nta_incoming_set_params(nta_incoming_t *irq,
			    tag_type_t tag, tag_value_t value, ...)
{
  int retval = -1;
  
  if (irq) {
    ta_list ta;
    ta_start(ta, tag, value);
    retval = incoming_set_params(irq, ta_args(ta));
    ta_end(ta);
  }
  else {
    su_seterrno(EINVAL);
  }

  return retval;
}

static
int incoming_set_params(nta_incoming_t *irq, tagi_t const *tags)
{
  int retval = 0;

#if HAVE_SIGCOMP

  tagi_t const *t;
  char const *comp = NONE;
  struct sigcomp_compartment *cc = NONE;

  for (t = tags; t; t = tl_next(t)) {
    tag_type_t tt = t->t_tag; 

    if (ntatag_comp == tt) 
      comp = (char const *)t->t_value, retval++;

    else if (ntatag_sigcomp_close == tt)
      irq->irq_sigcomp_zap = t->t_value != 0, retval++;

    else if (tptag_compartment == tt) 
      cc = (void *)t->t_value, retval++;
  }

  if (cc != NONE) {
    if (cc)
      tport_sigcomp_accept(irq->irq_tport, cc, irq->irq_request);
    if (irq->irq_cc)
      sigcomp_compartment_unref(irq->irq_cc);
    irq->irq_cc = sigcomp_compartment_ref(cc);
  }
  else if (comp != NULL && comp != NONE && irq->irq_cc == NULL) {
    incoming_set_compartment(irq, irq->irq_tport, irq->irq_request, 1);
  }

  else if (comp == NULL) {
    irq->irq_tpn->tpn_comp = NULL;
  }

#endif

  return retval; 
}

#if HAVE_SIGCOMP
static inline
int incoming_set_compartment(nta_incoming_t *irq, tport_t *tport, msg_t *msg,
			     int create_if_needed)
{
  if (irq->irq_cc == NULL 
      || irq->irq_tpn->tpn_comp
      || tport_delivered_using_udvm(tport, msg, NULL, 0) != -1) {
    struct sigcomp_compartment *cc;

    cc = agent_sigcomp_compartment_ref(irq->irq_agent, tport, irq->irq_tpn, 
				       create_if_needed);
    
    if (cc)
      tport_sigcomp_accept(tport, cc, msg);
    
    irq->irq_cc = cc;
  }

  return 0;
}
#else
static inline
int incoming_set_compartment(nta_incoming_t *irq, tport_t *tport, msg_t *msg)
{
  return 0;
}
#endif

/**Reply to an incoming transaction request.
 *
 * This function creates a response message to an incoming request and sends
 * it to the client.
 *
 * @note
 * It is possible to send several non-final (1xx) responses, but only one
 * final response.
 *
 * @param irq    incoming request
 * @param status status code
 * @param phrase status phrase (may be NULL if status code is well-known)
 * @param tag,value,... optional additional headers terminated by TAG_END()
 *
 * @retval 0 when succesful
 * @retval -1 upon an error
 */
int nta_incoming_treply(nta_incoming_t *irq,
			int status,
			char const *phrase,
			tag_type_t tag, tag_value_t value, ...)
{
  int retval = -1;

  if (irq->irq_status < 200 || status < 200 ||
      (irq->irq_method == sip_method_invite && status < 300)) {
    ta_list ta;
    msg_t *msg = nta_msg_create(irq->irq_agent, 0);
    sip_t *sip = sip_object(msg);

    ta_start(ta, tag, value);

    incoming_set_params(irq, ta_args(ta));

    if (!msg)
      ;
    else if (nta_msg_response_complete(msg, irq, status, phrase) < 0)
      msg_destroy(msg);
    else if (sip_add_tl(msg, sip, ta_tags(ta)) < 0)
      msg_destroy(msg);
    else
      retval = nta_incoming_mreply(irq, msg);

    ta_end(ta);

    if (retval < 0 && status >= 200)
      incoming_final_failed(irq, NULL);
  }

  return retval;
}

/**
 * Return a response message to client.
 *
 */
int nta_incoming_mreply(nta_incoming_t *irq, msg_t *msg) 
{
  sip_t *sip = sip_object(msg);

  int status;

  if (msg == irq->irq_response)
    return 0;

  if (!msg || !sip->sip_status || !sip->sip_via || !sip->sip_cseq)
    return incoming_final_failed(irq, msg);

  assert (sip->sip_cseq->cs_method == irq->irq_method);

  status = sip->sip_status->st_status;

  if (/* (irq->irq_confirmed && status >= 200) || */
      (irq->irq_completed && status >= 300)) {
    SU_DEBUG_3(("%s: already %s transaction\n", __func__,
		irq->irq_confirmed ? "confirmed" : "completed"));
    msg_destroy(msg);
    return -1;
  }

  if (irq->irq_must_100rel && !sip->sip_rseq && status > 100 && status < 200) {
    /* This nta_reliable_t object will be destroyed by PRACK or timeout */
    if (nta_reliable_mreply(irq, NULL, NULL, msg))
      return 0;

    return -1;
  }

  if (status >= 200 && irq->irq_reliable && irq->irq_reliable->rel_unsent) {
    if (reliable_final(irq, msg, sip) == 0)
      return 0;
  }

  return incoming_reply(irq, msg, sip);
}


/** Sends the response message. */
int incoming_reply(nta_incoming_t *irq, msg_t *msg, sip_t *sip)
{
  nta_agent_t *agent = irq->irq_agent;
  int status = sip->sip_status->st_status;
  int sending = 1;

  if (status == 408 && 
      irq->irq_method != sip_method_invite && 
      !agent->sa_pass_408) {
    /* draft-sparks-sip-nit-actions-03 Action 2:
       
   A transaction-stateful SIP element MUST NOT send a response with
   Status-Code of 408 to a non-INVITE request.  As a consequence, an
   element that can not respond before the transaction expires will not
   send a final response at all.
    */
    sending = 0;
  }

  if (irq->irq_status == 0 && irq->irq_timestamp && !sip->sip_timestamp)
    incoming_timestamp(irq, msg, sip);

  if (sip_complete_message(msg) < 0)
    SU_DEBUG_1(("%s: sip_message_complete() failed\n", __func__));
  else if (msg_serialize(msg, (msg_pub_t *)sip) < 0)
    SU_DEBUG_1(("%s: sip_serialize() failed\n", __func__));
  else if (!(irq->irq_tport) &&
	   !(tport_decref(&irq->irq_tport),
	     irq->irq_tport = tport_by_name(agent->sa_tports, irq->irq_tpn)))
    SU_DEBUG_1(("%s: no tport\n", __func__));
  else {
    int i, err = 0;
    tport_t *tp = NULL;
    incoming_queue_t *queue;

    if (sending) {
      for (i = 0; i < 3; i++) {
	tp = tport_tsend(irq->irq_tport, msg, irq->irq_tpn,
			 IF_SIGCOMP_TPTAG_COMPARTMENT(irq->irq_cc)
			 TPTAG_MTU(INT_MAX),
			 TAG_END());
	if (tp)
	  break;

	err = msg_errno(msg);
	SU_DEBUG_5(("%s: tport_tsend: %s%s\n",
		    __func__, su_strerror(err),
		    err == EPIPE ? "(retrying)" : ""));
	
	if (err != EPIPE && err != ECONNREFUSED)
	  break;
	tport_decref(&irq->irq_tport);
	irq->irq_tport =
	  tport_incref(tport_by_name(agent->sa_tports, irq->irq_tpn));
      }

      if (!tp) {
	SU_DEBUG_3(("%s: tport_tsend: "
		    "error (%s) while sending %u %s for %s (%u)\n",
		    __func__, su_strerror(err),
		    status, sip->sip_status->st_phrase,
		    irq->irq_rq->rq_method_name, irq->irq_cseq->cs_seq));
	if (status < 200)
	  msg_destroy(msg);
	else
	  incoming_final_failed(irq, msg);
	return 0;
      }

      agent->sa_stats->as_sent_msg++;
      agent->sa_stats->as_sent_response++;
    }

    SU_DEBUG_5(("nta: %s %u %s for %s (%u)\n",
		sending ? "sent" : "not sending",
		status, sip->sip_status->st_phrase,
		irq->irq_rq->rq_method_name, irq->irq_cseq->cs_seq));

    incoming_reset_timer(irq);

    if (status < 200) {
      queue = agent->sa_in.proceeding;
      
      if (irq->irq_method == sip_method_invite && status > 100 && 
	  agent->sa_progress != UINT_MAX && agent->sa_is_a_uas) {
	/* Retransmit preliminary responses in regular intervals */
	incoming_set_timer(irq, agent->sa_progress); /* N2 */
      }
    } 
    else {
      irq->irq_completed = 1;

#if HAVE_SIGCOMP
      /* XXX - we should do this only after message has actually been sent! */
      if (irq->irq_sigcomp_zap && irq->irq_cc)
	sigcomp_compartment_close(irq->irq_cc, SIGCOMP_CLOSE_COMP);
#endif

      if (irq->irq_method != sip_method_invite) {
	irq->irq_confirmed = 1;

	if (irq->irq_reliable_tp) {
	  irq->irq_terminated = 1;
	  queue = agent->sa_in.terminated ; /* J - set for 0 seconds */
	} else {
	  queue = agent->sa_in.completed; /* J */
	}

	tport_decref(&irq->irq_tport);
      }
      else if (status >= 300 || agent->sa_is_a_uas) {
	if (status < 300 || !irq->irq_reliable_tp) 
	  incoming_set_timer(irq, agent->sa_t1); /* G */
	queue = agent->sa_in.inv_completed; /* H */
      }
      else {
	irq->irq_terminated = 1;
	queue = agent->sa_in.terminated;
      }
    }

    if (irq->irq_queue != queue)
      incoming_queue(queue, irq);

    if (status >= 200 || irq->irq_status < 200) {
      if (irq->irq_response)
	msg_destroy(irq->irq_response);
      assert(msg_home(msg) != irq->irq_home);
      irq->irq_response = msg;
    }

    if (sip->sip_cseq->cs_method == irq->irq_method &&
	irq->irq_status < 200 && status > irq->irq_status)
      irq->irq_status = status;

    return 0;
  }

  /*
   *  XXX - handling error is very problematic.
   * Nobody checks return code from nta_incoming_*reply()
   */
  if (status < 200) {
    msg_destroy(msg);
    return -1;
  }

  /* We could not send final response. */
  return incoming_final_failed(irq, msg); 
}


/** @internal Sending final response has failed.
 *
 * Put transaction into its own queue, try later to send the response.
 */
static inline
int incoming_final_failed(nta_incoming_t *irq, msg_t *msg)
{
  irq->irq_final_failed = 1;
  msg_destroy(msg);
  incoming_queue(irq->irq_agent->sa_in.final_failed, irq);
  return -1;
}

/** @internal Retransmit the reply */
static
void incoming_retransmit_reply(nta_incoming_t *irq, tport_t *tport)
{
  msg_t *msg = NULL;

  if (irq->irq_final_failed)
    return;

  if (tport == NULL)
    tport = irq->irq_tport;

  /* Answer with existing reply */
  if (irq->irq_reliable && !irq->irq_reliable->rel_pracked)
    msg = reliable_response(irq);
  else
    msg = irq->irq_response;
  
  if (msg && tport) {
    irq->irq_retries++;

#if HAVE_SIGCOMP
    if (irq->irq_retries == 2 && irq->irq_tpn->tpn_comp) {
      irq->irq_tpn->tpn_comp = NULL;
      
      if (irq->irq_cc) {
	sigcomp_compartment_close(irq->irq_cc, SIGCOMP_CLOSE_COMP);
	sigcomp_compartment_unref(irq->irq_cc);
	irq->irq_cc = NULL;
      }
    }
#endif

    tport = tport_tsend(tport, msg, irq->irq_tpn, 
			IF_SIGCOMP_TPTAG_COMPARTMENT(irq->irq_cc)
			TPTAG_MTU(INT_MAX), TAG_END());
    irq->irq_agent->sa_stats->as_sent_msg++;
    irq->irq_agent->sa_stats->as_sent_response++;
  }
}

/** @internal Create timestamp header for response */
static
int incoming_timestamp(nta_incoming_t *irq, msg_t *msg, sip_t *sip)
{
  sip_timestamp_t ts[1];
  su_time_t now = su_now();
  char delay[32];
  double diff = su_time_diff(now, irq->irq_received);

  snprintf(delay, sizeof delay, "%.06f", diff);

  *ts = *irq->irq_timestamp;
  ts->ts_delay = delay;

  return sip_add_dup(msg, sip, (sip_header_t *)ts);
}

enum {
  timer_max_retransmit = 30,
  timer_max_terminate = 100000,
  timer_max_timeout = 100
};

/** @internal Timer routine for the incoming request. */
static inline
int incoming_timer(nta_agent_t *sa, su_duration_t now)
{
  nta_incoming_t *irq, *irq_next;
  unsigned retransmitted = 0, timeout = 0, terminated = 0, destroyed = 0;
  unsigned unconfirmed = 
    sa->sa_in.inv_completed->q_length + 
    sa->sa_in.preliminary->q_length;
  unsigned unterminated = 
    sa->sa_in.inv_confirmed->q_length + 
    sa->sa_in.completed->q_length;
  
  int total = sa->sa_incoming->iht_used;
  incoming_queue_t rq[1];

  incoming_queue_init(rq, 0);

  /* Handle retry queue */
  while ((irq = sa->sa_in.re_list)) {
    if ((irq->irq_retry && irq->irq_retry - now > 0) ||
	retransmitted >= timer_max_retransmit) 
      break;

    if (irq->irq_method == sip_method_invite && irq->irq_status >= 200) {
      /* Timer G */
      assert(irq->irq_queue == sa->sa_in.inv_completed);

      retransmitted++;

      SU_DEBUG_5(("nta: timer %s fired, retransmitting %u reply\n",
		  "G", irq->irq_status));

      incoming_retransmit_reply(irq, irq->irq_tport);

      if (2 * irq->irq_interval < sa->sa_t2)
	incoming_set_timer(irq, 2 * irq->irq_interval); /* G */
      else
	incoming_set_timer(irq, sa->sa_t2); /* G */
    } 
    else if (irq->irq_method == sip_method_invite && irq->irq_status >= 100) {
      if (irq->irq_queue == sa->sa_in.preliminary) {
	/* Timer P1 - PRACK timer */
	retransmitted++;
	SU_DEBUG_5(("nta: timer %s fired, retransmitting %u reply\n",
		    "P1", irq->irq_status));

	incoming_retransmit_reply(irq, irq->irq_tport);

	incoming_set_timer(irq, 2 * irq->irq_interval); /* P1 */
      }
      else {
	/* Retransmitting provisional responses */
	SU_DEBUG_5(("nta: timer %s fired, retransmitting %u reply\n",
		    "N2", irq->irq_status));
	incoming_set_timer(irq, sa->sa_progress);
	retransmitted++;
	incoming_retransmit_reply(irq, irq->irq_tport);
      }
    } else {
      /* Timer N1 */
      SU_DEBUG_5(("nta: timer N1 fired, sending %u %s\n", SIP_100_TRYING));
      incoming_reset_timer(irq);
      nta_incoming_treply(irq, SIP_100_TRYING, TAG_END());
    }
  }

  while ((irq = sa->sa_in.final_failed->q_head)) {
    incoming_remove(irq);
    irq->irq_final_failed = 0;

    /* Report error to application */
    SU_DEBUG_5(("nta: sending final response failed, timeout %u response\n",
		irq->irq_status));
    reliable_timeout(irq, 0);

    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());

    if (!irq->irq_final_failed)	/* We have taken care of the error... */
      continue;

    if (irq->irq_destroyed) {
      incoming_free_queue(rq, irq);
      continue;
    }

    incoming_reset_timer(irq);
    irq->irq_confirmed = 1;
    irq->irq_terminated = 1;
    incoming_queue(sa->sa_in.terminated, irq);
  }

  /* Timeouts.
   * For each state the request is in, there is always a queue of its own 
   */
  while ((irq = sa->sa_in.preliminary->q_head)) {
    assert(irq->irq_status < 200);
    assert(irq->irq_timeout);

    if (irq->irq_timeout - now > 0 
	|| timeout >= timer_max_timeout)
      break;

    timeout++;

    /* Timer P2 - PRACK timer */
    SU_DEBUG_5(("nta: timer %s fired, %s %u response\n",
		"P2", "timeout", irq->irq_status));
    incoming_reset_timer(irq);
    irq->irq_timeout = 0;
    reliable_timeout(irq, 1);
  }

  while ((irq = sa->sa_in.inv_completed->q_head)) {
    assert(irq->irq_status >= 200);
    assert(irq->irq_timeout);
    assert(irq->irq_method == sip_method_invite);

    if (irq->irq_timeout - now > 0 || 
	timeout >= timer_max_timeout || 
	terminated >= timer_max_terminate)
      break;

    /* Timer H */
    SU_DEBUG_5(("nta: timer %s fired, %s %u response\n",
		"H", "timeout and terminate", irq->irq_status));
    irq->irq_confirmed = 1;
    irq->irq_terminated = 1;
    incoming_reset_timer(irq);
    if (!irq->irq_destroyed) {
      timeout++; 
      incoming_queue(sa->sa_in.terminated, irq);
      /* report timeout error to user */
      incoming_call_callback(irq, NULL, NULL);
    } else {
      timeout++;
      terminated++;
      incoming_free_queue(rq, irq);
    }
  } 

  while ((irq = sa->sa_in.inv_confirmed->q_head)) {
    assert(irq->irq_timeout);
    assert(irq->irq_status >= 200);
    assert(irq->irq_method == sip_method_invite);

    if (irq->irq_timeout - now > 0 || 
	terminated >= timer_max_terminate)
      break;
    
    /* Timer I */
    SU_DEBUG_5(("nta: timer %s fired, %s %u response\n",
		"I", "terminate", irq->irq_status));

    terminated++;
    irq->irq_terminated = 1;

    if (!irq->irq_destroyed)
      incoming_queue(sa->sa_in.terminated, irq);
    else
      incoming_free_queue(rq, irq);
  }

  while ((irq = sa->sa_in.completed->q_head)) {
    assert(irq->irq_status >= 200);
    assert(irq->irq_timeout);
    assert(irq->irq_method != sip_method_invite);

    if (irq->irq_timeout - now > 0 || 
	terminated >= timer_max_terminate)
      break;

    /* Timer J */

    SU_DEBUG_5(("nta: timer %s fired, %s %u response\n",
		"J", "terminate", irq->irq_status));

    terminated++;
    irq->irq_terminated = 1;

    if (!irq->irq_destroyed)
      incoming_queue(sa->sa_in.terminated, irq);
    else
      incoming_free_queue(rq, irq);
  }

  for (irq = sa->sa_in.terminated->q_head; irq; irq = irq_next) {
    irq_next = irq->irq_next;
    if (irq->irq_destroyed)
      incoming_free_queue(rq, irq);
  }

  destroyed = incoming_mass_destroy(sa, rq);

  if (retransmitted || timeout || terminated || destroyed)
    SU_DEBUG_5(("nta_incoming_timer: "
		"%u/%u resent, %u/%u tout, %u/%u term, %u/%u free\n",
		retransmitted, unconfirmed, 
		timeout, unconfirmed,
		terminated, unterminated, 
		destroyed, total));

  return 
    retransmitted >= timer_max_retransmit
    || timeout >= timer_max_timeout
    || terminated >= timer_max_terminate;
}

/** Mass destroy server transactions */
static inline
int incoming_mass_destroy(nta_agent_t *sa, incoming_queue_t *q)
{
  unsigned destroyed = q->q_length;

  if (destroyed > 2 && *sa->sa_terminator) {
    su_msg_r m = SU_MSG_RINITIALIZER;

    if (su_msg_create(m,
		      su_clone_task(sa->sa_terminator),
		      su_root_task(sa->sa_root),
		      incoming_reclaim_queued,
		      sizeof(incoming_queue_t)) == SU_SUCCESS) {
      incoming_queue_t *mq = su_msg_data(m)->a_incoming_queue;

      *mq = *q;

      if (su_msg_send(m) == SU_SUCCESS)
	q->q_length = 0;
    }    
  } 

  if (q->q_length > 0)
    incoming_reclaim_queued(NULL, NULL, (void *)q);

  return destroyed;
}

/* ====================================================================== */
/* 8) Client-side (outgoing) transactions */

#define HTABLE_HASH_ORQ(orq) ((orq)->orq_hash)

HTABLE_BODIES(outgoing_htable, oht, nta_outgoing_t, HTABLE_HASH_ORQ);

static nta_outgoing_t *outgoing_create(nta_agent_t *agent,
				       nta_response_f *callback,
				       nta_outgoing_magic_t *magic,
				       url_string_t const *route_url,
				       tp_name_t const *tpn,
				       msg_t *msg,
				       tag_type_t tag, tag_value_t value, ...);
static int outgoing_features(nta_agent_t *agent, nta_outgoing_t *orq,
			      msg_t *msg, sip_t *sip,
			      tagi_t *tags);
static void outgoing_prepare_send(nta_outgoing_t *orq);
static void outgoing_send(nta_outgoing_t *orq, int retransmit);
static void outgoing_try_tcp_instead(nta_outgoing_t *orq);
static void outgoing_try_udp_instead(nta_outgoing_t *orq);
static void outgoing_tport_error(nta_agent_t *agent, nta_outgoing_t *orq,
				 tport_t *tp, msg_t *msg, int error);
static void outgoing_print_tport_error(nta_outgoing_t *orq, 
				       int level, char *todo,
				       tp_name_t const *, msg_t *, int error);
static void outgoing_insert(nta_agent_t *sa, nta_outgoing_t *orq);
static void outgoing_destroy(nta_outgoing_t *orq);
static inline int outgoing_is_queued(nta_outgoing_t const *orq);
static inline void outgoing_queue(outgoing_queue_t *queue, 
				  nta_outgoing_t *orq);
static inline void outgoing_remove(nta_outgoing_t *orq);
static inline void outgoing_set_timer(nta_outgoing_t *orq, unsigned interval);
static inline void outgoing_reset_timer(nta_outgoing_t *orq);
static int outgoing_timer_dk(outgoing_queue_t *q, 
			     char const *timer, 
			     su_duration_t now);
static int outgoing_timer_bf(outgoing_queue_t *q, 
			     char const *timer, 
			     su_duration_t now);

static void outgoing_ack(nta_outgoing_t *orq, msg_t *msg, sip_t *sip);
static msg_t *outgoing_ackmsg(nta_outgoing_t *, sip_method_t, char const *,
			      tagi_t const *tags);
static void outgoing_retransmit(nta_outgoing_t *orq);
static void outgoing_trying(nta_outgoing_t *orq);
static void outgoing_timeout(nta_outgoing_t *orq, su_duration_t now);
static int outgoing_complete(nta_outgoing_t *orq);
static int outgoing_terminate(nta_outgoing_t *orq);
static int outgoing_mass_destroy(nta_agent_t *sa, outgoing_queue_t *q);
static void outgoing_estimate_delay(nta_outgoing_t *orq, sip_t *sip);
static int outgoing_duplicate(nta_outgoing_t *orq,
			      msg_t *msg,
			      sip_t *sip);
static int outgoing_reply(nta_outgoing_t *orq,
			  int status, char const *phrase,
			  int delayed);

static int outgoing_default_cb(nta_outgoing_magic_t *magic,
			       nta_outgoing_t *request,
			       sip_t const *sip);

#if HAVE_SOFIA_SRESOLV
static void outgoing_resolve(nta_outgoing_t *orq);
static inline void outgoing_cancel_resolver(nta_outgoing_t *orq);
static inline void outgoing_destroy_resolver(nta_outgoing_t *orq);
static int outgoing_other_destinations(nta_outgoing_t const *orq);
static int outgoing_try_another(nta_outgoing_t *orq);
#else
#define outgoing_other_destinations(orq) (0)
#define outgoing_try_another(orq) (0) 
#endif

/**Create an outgoing request and client transaction belonging to the leg.
 *
 * The function nta_outgoing_tcreate() creates a request message and passes
 * the request message to an outgoing client transaction object. The request
 * is sent to the @a route_url (if non-NULL), default proxy (if defined by
 * NTATAG_DEFAULT_PROXY()), or to the address specified by @a request_uri.
 * If no @a request_uri is specified, it is taken from route-set target or
 * from the @b To header.
 *
 * When NTA receives response to the request, it invokes the @a callback
 * function.
 *
 * @param leg         call leg object
 * @param callback    callback function (may be @c NULL)
 * @param magic       application context pointer
 * @param route_url   optional URL used to route transaction requests
 * @param method      method type
 * @param name        method name
 * @param request_uri Request-URI
 * @param tag, value, ... list of extra arguments
 *
 * @return
 * The function nta_outgoing_tcreate() returns a pointer to newly created
 * outgoing transaction object if successful, and NULL otherwise.
 *
 * @sa
 * nta_outgoing_mcreate(), nta_outgoing_tcancel(), nta_outgoing_destroy().
 *
 * @TAGS
 * NTATAG_STATELESS(), NTATAG_DELAY_SENDING(), NTATAG_BRANCH_KEY(),
 * NTATAG_DEFAULT_PROXY(), NTATAG_PASS_100(), NTATAG_USE_TIMESTAMP(). All
 * SIP tags from <sip_tag.h> can be used to manipulate the message.
 */
nta_outgoing_t *nta_outgoing_tcreate(nta_leg_t *leg,
				     nta_response_f *callback,
				     nta_outgoing_magic_t *magic,
				     url_string_t const *route_url,
				     sip_method_t method,
				     char const *name,
				     url_string_t const *request_uri,
				     tag_type_t tag, tag_value_t value, ...)
{
  nta_agent_t *agent;
  msg_t *msg;
  sip_t *sip;
  nta_outgoing_t *orq = NULL;
  ta_list ta;

  if (leg == NULL)
    return NULL;

  agent = leg->leg_agent;
  msg = nta_msg_create(agent, 0);
  sip = sip_object(msg);

  if (route_url == NULL)
    route_url = (url_string_t *)agent->sa_default_proxy;

  ta_start(ta, tag, value);

  if (sip_add_tl(msg, sip, ta_tags(ta)) < 0)
    ;
  else if (route_url == NULL && leg->leg_route &&
	   leg->leg_loose_route &&
	   !(route_url = (url_string_t *)leg->leg_route->r_url))
    ;
  else if (nta_msg_request_complete(msg, leg, method, name, request_uri) < 0)
    ;
  else
    orq = outgoing_create(agent, callback, magic, route_url, NULL, msg,
			  ta_tags(ta));

  ta_end(ta);

  if (!orq)
    msg_destroy(msg);

  return orq;
}

/**Create an outgoing client transaction.
 *
 * The function nta_outgoing_tmcreate() creates an outgoing transaction
 * object. It passes the request message to the transaction object, which
 * sends the request to the network. The request is sent to the @a route_url
 * (if non-NULL), default proxy (if defined by NTATAG_DEFAULT_PROXY()), or
 * to the address specified by @a request_uri.
 *
 * When NTA receives response to the request, it invokes the @a callback
 * function.
 *
 * @param agent       NTA agent object
 * @param callback    callback function (may be @c NULL)
 * @param magic       application context pointer
 * @param route_url   optional URL used to route transaction requests
 * @param msg         request message
 * @param tag, value, ... list of extra arguments
 *
 * @return
 * The function nta_outgoing_tmcreate() returns a pointer to newly created
 * outgoing transaction object if successful, and NULL otherwise.
 *
 * @sa
 * nta_outgoing_tcreate(), nta_outgoing_mcreate(), nta_outgoing_tcancel(),
 * nta_outgoing_destroy().
 *
 * @TAGS
 * NTATAG_STATELESS(), NTATAG_DELAY_SENDING(), NTATAG_BRANCH_KEY(),
 * NTATAG_DEFAULT_PROXY(), NTATAG_PASS_100(), NTATAG_USE_TIMESTAMP(). All
 * SIP tags from <sip_tag.h> can be used to manipulate the message.
 */
nta_outgoing_t *nta_outgoing_tmcreate(nta_agent_t *agent,
				      nta_response_f *callback,
				      nta_outgoing_magic_t *magic,
				      url_string_t const *route_url,
				      msg_t *msg,
				      tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  nta_outgoing_t *orq = NULL;

  if (msg && agent) {
    ta_start(ta, tag, value);
    if (sip_add_tl(msg, sip_object(msg), ta_tags(ta)) >= 0)
      orq = outgoing_create(agent, callback, magic, route_url, NULL, msg,
			    ta_tags(ta));
    ta_end(ta);
  }

  return orq;
}

/**Create an outgoing client transaction.
 *
 * The function nta_outgoing_mcreate() creates an outgoing transaction
 * object.It passes the request message to the transaction object, which
 * sends the request to the network. The request is sent to the @a route_url
 * (if non-NULL), default proxy (if defined by NTATAG_DEFAULT_PROXY()), or
 * to the address specified by @a request_uri. If no @a request_uri is
 * specified, it is taken from route-set target or from the @b To header.
 *
 * When NTA receives response to the request, it invokes the @a callback
 * function.
 *
 * @param agent       NTA agent object
 * @param callback    callback function (may be @c NULL)
 * @param magic       application context pointer
 * @param route_url   optional URL used to route transaction requests
 * @param msg         request message
 *
 * @return
 * The function nta_outgoing_mcreate() returns a pointer to newly created
 * outgoing transaction object if successful, and NULL otherwise.
 *
 * @sa
 * nta_outgoing_tcreate(), nta_outgoing_tmcreate(), nta_outgoing_tcancel(),
 * nta_outgoing_destroy().
 */
nta_outgoing_t *nta_outgoing_mcreate(nta_agent_t *agent,
				     nta_response_f *callback,
				     nta_outgoing_magic_t *magic,
				     url_string_t const *route_url,
				     msg_t *msg)
{
  if (msg == NULL || agent == NULL)
    return NULL;
  return outgoing_create(agent, callback, magic, route_url, NULL, msg,
			 TAG_END());
}

/** Cancel the request. */
int nta_outgoing_cancel(nta_outgoing_t *orq)
{
  nta_outgoing_t *cancel =
    nta_outgoing_tcancel(orq, NULL, NULL, TAG_NULL());

  return (cancel != NULL) - 1;
}

/** Cancel the request.
 *
 * @todo Adding headers provided by caller to the CANCEL request.
 */
nta_outgoing_t *nta_outgoing_tcancel(nta_outgoing_t *orq,
				     nta_response_f *callback,
				     nta_outgoing_magic_t *magic,
				     tag_type_t tag, tag_value_t value, ...)
{
  msg_t *msg;
  int cancel_2543, cancel_408;
  ta_list ta;

  if (!orq)
    return NULL;

  if (orq->orq_destroyed) {
    SU_DEBUG_3(("%s: trying to cancel destroyed request\n", __func__));
    return NULL;
  }
  if (orq->orq_method != sip_method_invite) {
    SU_DEBUG_3(("%s: trying to cancel non-INVITE request\n", __func__));
    return NULL;
  }
  if (orq->orq_status >= 200
      /* && orq->orq_method != sip_method_invite ... !multicast */) {
    SU_DEBUG_3(("%s: trying to cancel completed request\n", __func__));
    return NULL;
  }
  if (orq->orq_canceled) {
    SU_DEBUG_3(("%s: trying to cancel cancelled request\n", __func__));
    return NULL;
  }
  orq->orq_canceled = 1;

#if HAVE_SOFIA_SRESOLV
  if (!orq->orq_resolved) {
    if (orq->orq_resolver)
      outgoing_cancel_resolver(orq);
    outgoing_reply(orq, SIP_487_REQUEST_CANCELLED, 1);
    return NULL;		/* XXX - Does anyone care about reply? */
  }
#endif

  cancel_408 = 0;		/* Don't really CANCEL, this is timeout. */
  cancel_2543 = orq->orq_agent->sa_cancel_2543;

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta), 
	  NTATAG_CANCEL_408_REF(cancel_408), 
	  NTATAG_CANCEL_2543_REF(cancel_2543),
	  TAG_END());

  if (cancel_2543 || cancel_408)
    outgoing_reply(orq, SIP_487_REQUEST_CANCELLED, 1);

  if (!cancel_408)
    msg = outgoing_ackmsg(orq, SIP_METHOD_CANCEL, ta_args(ta));
  else
    msg = NULL;

  ta_end(ta);

  if (msg) {
    nta_outgoing_t *cancel;
    /*
     * CANCEL may be sent only after a provisional response has been
     * received.
     */
    int delay_sending = orq->orq_status < 100;

    if (cancel_2543)		/* Follow RFC 2543 semantics for CANCEL */
      delay_sending = 0;

    cancel = outgoing_create(orq->orq_agent, callback, magic,
			     NULL, orq->orq_tpn, msg,
			     NTATAG_BRANCH_KEY(orq->orq_branch
					       + strlen("branch=")),
			     NTATAG_DELAY_SENDING(delay_sending),
			     NTATAG_USER_VIA(1),
			     TAG_END());

    if (delay_sending)
      orq->orq_cancel = cancel;

    if (cancel)
      return cancel;

    msg_destroy(msg);
  }

  return NULL;
}

/**
 * Destroy a request object.
 *
 * @note
 * This function does not actually free the object, but marks it as
 * disposable. The object is freed after a timeout.
 */
void nta_outgoing_destroy(nta_outgoing_t *orq)
{
  if (!orq || orq == NONE)
    return;

  if (orq->orq_destroyed) {
    SU_DEBUG_1(("nta_outgoing_destroy(%p): already destroyed\n", orq));
    return;
  }

  outgoing_destroy(orq);
}

/** Return the request URI */
url_t const *nta_outgoing_request_uri(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_url : NULL;
}

/** Return the URI used to route the request */
url_t const *nta_outgoing_route_uri(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_route : NULL;
}

/** Return method of the client transaction */
sip_method_t nta_outgoing_method(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_method : sip_method_invalid;
}

/** Return method name of the client transaction */
char const *nta_outgoing_method_name(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_method_name : NULL;
}

/** Get sequence number of a client transaction.
 */
sip_u32_t nta_outgoing_cseq(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_cseq->cs_seq : 0;
}

/**
 * Get the status code of a client transaction.
 */
int nta_outgoing_status(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_status : 500; /* Internal server error. */
}

/** Get the RTT delay from application */
unsigned nta_outgoing_delay(nta_outgoing_t const *orq)
{
  return orq ? orq->orq_delay : UINT_MAX;
}


/**Get latest response message.
 *
 * The function nta_outgoing_getresponse() retrieves the latest incoming
 * response message to the outgoing transaction.  Note that the message is
 * not copied, but removed from the transaction.
 *
 * @param orq outgoing transaction handle
 *
 * @retval
 * A pointer to response message is returned, or NULL if no response message
 * has been received or the response message has already been retrieved.
 */
msg_t *nta_outgoing_getresponse(nta_outgoing_t *orq)
{
  msg_t *msg = NULL;

  if (orq && orq->orq_response)
    msg = orq->orq_response, orq->orq_response = NULL;

  return msg;
}

/**Get reference to response message.
 *
 * The function nta_outgoing_getresponse_ref() retrieves the latest incoming
 * response message to the outgoing transaction.  Note that the message is
 * not copied, but a new reference to it is created instead.
 *
 * @param orq outgoing transaction handle
 *
 * @retval
 * A pointer to response message is returned, or NULL if no response message
 * has been received or the response message has already been retrieved.
 */
msg_t *nta_outgoing_getresponse_ref(nta_outgoing_t *orq)
{
  if (orq)
    return msg_ref_create(orq->orq_response);
  else
    return NULL;
}

/**Get request message.
 *
 * The function nta_outgoing_getrequest() retrieves the request message sent
 * to the network. The request message is copied; the original copy is kept
 * by the transaction.
 *
 * @param orq outgoing transaction handle
 *
 * @retval
 * A pointer to the copy of the request message is returned, or NULL if an
 * error occurred.
 */
msg_t *nta_outgoing_getrequest(nta_outgoing_t *orq)
{
  if (orq && orq->orq_request) {
    msg_t *msg = nta_msg_create(orq->orq_agent, 0);
    sip_t *sip = sip_object(msg);

    msg_clone(msg, orq->orq_request);

    /* Copy the SIP headers from the old message */
    if (sip_copy_all(msg, sip, sip_object(orq->orq_request)) >= 0)
      return msg;

    msg_destroy(msg);
  }

  return NULL;
}

/**Get request message.
 *
 * Retrieves the request message sent to the network. Note that the request
 * message is @b not copied, but a new reference to it is created.
 *
 * @retval
 * A pointer to the request message is returned, or NULL if an error
 * occurred.
 */
msg_t *nta_outgoing_getrequest_ref(nta_outgoing_t *orq)
{
  if (orq)
    return msg_ref_create(orq->orq_request);
  else
    return NULL;
}

/**Create an outgoing request.
 *
 * The function outgoing_create() creates an outgoing transaction object and
 * sends the request to the network. The request is sent to the @a route_url
 * (if non-NULL), default proxy (if defined by NTATAG_DEFAULT_PROXY()), or
 * to the address specified by @a sip->sip_request->rq_url.
 *
 * When NTA receives response to the request, it invokes the @a callback
 * function.
 *
 * @param agent       NTA agent object
 * @param callback    callback function (may be @c NULL)
 * @param magic       application context pointer
 * @param route_url   optional URL used to route transaction requests
 * @param msg         request message
 *
 * @return
 * The function nta_outgoing_mcreate() returns a pointer to newly created
 * outgoing transaction object if successful, and NULL otherwise.
 *
 * @sa
 * nta_outgoing_tcreate(), nta_outgoing_tcancel(), nta_outgoing_destroy().
 */
nta_outgoing_t *outgoing_create(nta_agent_t *agent,
				nta_response_f *callback,
				nta_outgoing_magic_t *magic,
				url_string_t const *route_url,
				tp_name_t const *tpn,
				msg_t *msg,
				tag_type_t tag, tag_value_t value, ...)
{
  nta_outgoing_t *orq;
  sip_t *sip;
  su_home_t *home;
  char const *comp = NONE;
  char const *branch = NONE;
  char const *ack_branch = NULL;
  char const *tp_ident;
  int delay_sending = 0, sigcomp_zap = 0;
  int pass_100 = agent->sa_pass_100, use_timestamp = agent->sa_timestamp;
  enum nta_res_order_e res_order = agent->sa_res_order;
  struct sigcomp_compartment *cc = NULL;
  ta_list ta;
  char const *scheme = NULL;
  char const *port = NULL;
  int invalid, resolved, stateless = 0, user_via = agent->sa_user_via;
  tagi_t const *t;

  if (!agent->sa_tport_ip6)
    res_order = nta_res_ip4_only;
  else if (!agent->sa_tport_ip4)
    res_order = nta_res_ip6_only;

  if (!callback)
    callback = outgoing_default_cb;
  if (!route_url)
    route_url = (url_string_t *)agent->sa_default_proxy;

  sip = sip_object(msg);
  home = msg_home(msg);

  if (!sip->sip_request || sip_complete_message(msg) < 0) {
    SU_DEBUG_3(("nta: outgoing_create: incomplete request\n"));
    return NULL;
  }

  if (!route_url && !tpn && sip->sip_route &&
      sip->sip_route->r_url->url_params &&
      url_param(sip->sip_route->r_url->url_params, "lr", NULL, 0))
    route_url = (url_string_t *)sip->sip_route->r_url;

  if (!(orq = su_zalloc(agent->sa_home, sizeof(*orq))))
    return NULL;

  tp_ident = tpn ? tpn->tpn_ident : NULL;

  ta_start(ta, tag, value);

  /* tl_gets() is a bit too slow here... */
  for (t = ta_args(ta); t; t = tl_next(t)) {
    tag_type_t tt = t->t_tag; 

    if (ntatag_stateless == tt) 
      stateless = t->t_value != 0; 
    else if (ntatag_delay_sending == tt) 
      delay_sending = t->t_value != 0; 
    else if (ntatag_branch_key == tt) 
      branch = (void *)t->t_value; 
    else if (ntatag_pass_100 == tt) 
      pass_100 = t->t_value != 0; 
    else if (ntatag_use_timestamp == tt) 
      use_timestamp = t->t_value != 0; 
    else if (ntatag_user_via == tt) 
      user_via = t->t_value != 0; 
    else if (ntatag_ack_branch == tt) 
      ack_branch = (void *)t->t_value; 
    else if (ntatag_default_proxy == tt) 
      route_url = (void *)t->t_value; 
    else if (tptag_ident == tt)
      tp_ident = (void *)t->t_value;
    else if (ntatag_comp == tt)
      comp = (char const *)t->t_value;
#if HAVE_SIGCOMP
    else if (ntatag_sigcomp_close == tt)
      sigcomp_zap = t->t_value != 0;
    else if (tptag_compartment == tt)
      cc = (void *)t->t_value;
#endif
  }

  orq->orq_agent    = agent;
  orq->orq_callback = callback;
  orq->orq_magic    = magic;
  orq->orq_method   = sip->sip_request->rq_method;
  orq->orq_method_name = sip->sip_request->rq_method_name;
  orq->orq_cseq     = sip->sip_cseq;
  orq->orq_to       = sip->sip_to;
  orq->orq_from     = sip->sip_from;
  orq->orq_call_id  = sip->sip_call_id;
  orq->orq_tags     = tl_afilter(home, tport_tags, ta_args(ta));
  orq->orq_delayed  = delay_sending != 0;
  orq->orq_pass_100 = pass_100 != 0;
  orq->orq_sigcomp_zap = sigcomp_zap;
  orq->orq_sigcomp_new = comp != NONE && comp != NULL;
  orq->orq_res_order = res_order;
  orq->orq_timestamp = use_timestamp;
  orq->orq_delay     = UINT_MAX;
  orq->orq_stateless = stateless != 0;
  orq->orq_user_via  = user_via != 0 && sip->sip_via;
#if HAVE_SIGCOMP
  if (cc)
    orq->orq_cc = sigcomp_compartment_ref(cc);
#else
  (void)cc;
#endif

  /* Add supported features */
  outgoing_features(agent, orq, msg, sip, ta_args(ta));

  ta_end(ta);

  if (route_url) {
    invalid = nta_tpn_by_url(home, orq->orq_tpn, &scheme, &port, route_url);
    resolved = tport_name_is_resolved(orq->orq_tpn);
    orq->orq_url = url_hdup(home, sip->sip_request->rq_url);
    if (route_url != (url_string_t *)agent->sa_default_proxy)
      orq->orq_route = url_hdup(home, route_url->us_url);
  }
  else if (tpn) {
    invalid = tport_name_dup(home, orq->orq_tpn, tpn);
#if HAVE_SOFIA_SRESOLV
    assert(tport_name_is_resolved(orq->orq_tpn));
#endif
    resolved = tport_name_is_resolved(orq->orq_tpn);
    orq->orq_url = url_hdup(home, sip->sip_request->rq_url);
    scheme = "sip";		/* XXX */
  }
  else {
    invalid = nta_tpn_by_url(home, orq->orq_tpn, &scheme, &port,
			     (url_string_t *)sip->sip_request->rq_url);
    resolved = tport_name_is_resolved(orq->orq_tpn);
    orq->orq_url = url_hdup(home, sip->sip_request->rq_url);
    sip_fragment_clear(sip->sip_request->rq_common);
  }

  orq->orq_tpn->tpn_ident = tp_ident;
  if (comp == NULL)
    orq->orq_tpn->tpn_comp = comp;

  if (orq->orq_user_via && str0cmp(orq->orq_tpn->tpn_proto, "*") == 0) {
    char const *proto = sip_via_transport(sip->sip_via);
    if (proto) orq->orq_tpn->tpn_proto = proto;
  }

  if (branch && branch != NONE) {
    if (strchr(branch, '='))
      branch = su_strdup(home, branch);
    else
      branch = su_sprintf(home, "branch=%s", branch);
  }
  else if (orq->orq_user_via && sip->sip_via->v_branch)
    branch = su_sprintf(home, "branch=%s", sip->sip_via->v_branch);
  else if (stateless)
    branch = stateless_branch(agent, msg, sip, orq->orq_tpn);
  else
    branch = stateful_branch(home, agent);

  orq->orq_branch = branch;
  orq->orq_via_branch = branch;

  if (orq->orq_method == sip_method_ack) {
    if (ack_branch) {
      orq->orq_branch = su_strdup(home, ack_branch);
    } else if (!stateless && agent->sa_is_a_uas) {
      /*
       * ACK redirect further 2XX messages to it.
       *
       * Use orq_branch from INVITE, but put a different branch in topmost Via.
       */
      nta_outgoing_t *invite = outgoing_find(agent, msg, sip, NULL);
      
      if (invite) {
	orq->orq_branch = su_strdup(home, invite->orq_branch);
      }
      else {
	SU_DEBUG_1(("outgoing_create: ACK without INVITE\n"));
	assert(!"INVITE found for ACK");
      }
    }
  }

#if HAVE_SOFIA_SRESOLV
  if (!resolved)
    orq->orq_tpn->tpn_port = port;
  orq->orq_resolved = resolved;
#else
  orq->orq_resolved = resolved = 1;
#endif
  orq->orq_scheme = scheme;

  if (invalid < 0 || !orq->orq_branch || sip_serialize(msg, sip) < 0) {
    SU_DEBUG_3(("nta outgoing create: %s\n",
		invalid < 0 ? "invalid URI" :
		!orq->orq_branch ? "no branch" : "invalid message"));
    outgoing_free(orq);
    return NULL;
  }

  /* Now we are committed in sending the transaction */
  orq->orq_request = msg;
  agent->sa_stats->as_client_tr++;
  orq->orq_hash = NTA_HASH(sip->sip_call_id, sip->sip_cseq->cs_seq);

  if (resolved)
    outgoing_prepare_send(orq);
#if HAVE_SOFIA_SRESOLV
  else
    outgoing_resolve(orq);
#endif

  if (stateless && 
      orq->orq_status >= 200 && 
      callback == outgoing_default_cb) {
    void *retval;

    if (orq->orq_status < 300) 
      retval = (void *)-1;
    else 
      retval = NULL, orq->orq_request = NULL;

    outgoing_free(orq);

    return retval;
  }

  assert(orq->orq_queue);

  outgoing_insert(agent, orq);

  return orq;
}

/** Prepare sending a request */
static void
outgoing_prepare_send(nta_outgoing_t *orq)
{
  nta_agent_t *sa = orq->orq_agent;
  tport_t *tp;
  tp_name_t *tpn = orq->orq_tpn;
  msg_t *msg = orq->orq_request;
  int sips = strcasecmp(orq->orq_scheme, "sips") == 0;

  /* Select transport by scheme */
  if (sips && strcmp(tpn->tpn_proto, "*") == 0)
    tpn->tpn_proto = "tls";

  if (!tpn->tpn_port)
    tpn->tpn_port = "";

  tp = tport_by_name(sa->sa_tports, tpn);
  orq->orq_tport = tport_incref(tp);

  if (tpn->tpn_port[0] == '\0') {
    if (sips || tport_has_tls(tp))
      tpn->tpn_port = "5061";
    else
      tpn->tpn_port = "5060";
  }

  if (!orq->orq_tport) {
    if (sips) {
      SU_DEBUG_3(("nta outgoing create: no secure transport\n"));
      outgoing_reply(orq, SIP_416_UNSUPPORTED_URI, 1);
    }
    else {
      SU_DEBUG_3(("nta outgoing create: no transport protocol\n"));
      outgoing_reply(orq, 503, "No transport", 1);
    }
    return;
  }

  if (agent_insert_via(sa, msg,
		       agent_tport_via(tp),
		       orq->orq_via_branch,
		       orq->orq_user_via) < 0) {
    SU_DEBUG_3(("nta outgoing create: cannot insert Via line\n"));
    outgoing_reply(orq, 503, "Cannot insert Via", 1);
    return;
  }

  orq->orq_user_via = 1;

#if HAVE_SOFIA_SMIME
  {
    sm_object_t *smime = sa->sa_smime;
    sip_t *sip = sip_object(orq->orq_request);

    if (sa->sa_smime &&
	(sip->sip_request->rq_method == sip_method_invite ||
	 sip->sip_request->rq_method == sip_method_message)) {
      msg_prepare(orq->orq_request);
      if (sm_encode_message(smime, msg, sip, SM_ID_NULL) < 0) {
	outgoing_tport_error(sa, orq, NULL,
			     orq->orq_request, su_errno());
	return;
      }
    }
  }
#endif

  orq->orq_prepared = 1;

  if (orq->orq_delayed) {
    SU_DEBUG_5(("nta: delayed sending %s (%u)\n",
		orq->orq_method_name, orq->orq_cseq->cs_seq));
    outgoing_queue(sa->sa_out.delayed, orq);
    return;
  }

  outgoing_send(orq, 0);
}

/** Send a request */
static void
outgoing_send(nta_outgoing_t *orq, int retransmit)
{
  int err;
  tp_name_t const *tpn = orq->orq_tpn;
  msg_t *msg = orq->orq_request;
  nta_agent_t *agent = orq->orq_agent;
  tport_t *tp;
  int once = 0;
  su_time_t now = su_now();
  tag_type_t tag = tag_skip;
  tag_value_t value = 0;
  struct sigcomp_compartment *cc; cc = NULL;

  if (!retransmit)
    orq->orq_sent = now;

  if (orq->orq_timestamp) {
    sip_t *sip = sip_object(msg);
    sip_timestamp_t *ts =
      sip_timestamp_format(msg_home(msg), "%lu.%06lu",
			   now.tv_sec, now.tv_usec);

    if (ts) {
      if (sip->sip_timestamp)
	sip_header_remove(msg, sip, (sip_header_t *)sip->sip_timestamp);
      sip_header_insert(msg, sip, (sip_header_t *)ts);
    }
  }

  for (;;) {
#if HAVE_SIGCOMP
    if (tpn->tpn_comp == NULL) {
      /* xyzzy */
    }
    else if (orq->orq_cc) {
      cc = orq->orq_cc, orq->orq_cc = NULL;
    }
    else {
      cc = agent_sigcomp_compartment_ref(agent, orq->orq_tport, tpn, 
					 orq->orq_sigcomp_new);
    }
#endif

    if (orq->orq_try_udp_instead)
      tag = tptag_mtu, value = 65535;

    tp = tport_tsend(orq->orq_tport, msg, tpn, 
		     tag, value,
		     IF_SIGCOMP_TPTAG_COMPARTMENT(cc)
		     TAG_NEXT(orq->orq_tags));
    if (tp)
      break;

    err = msg_errno(orq->orq_request);

#if HAVE_SIGCOMP
    if (cc)
      sigcomp_compartment_unref(cc), cc = NULL;
#endif

    /* RFC3261, 18.1.1 */
    if (err == EMSGSIZE && !orq->orq_try_tcp_instead) {
      if (strcasecmp(tpn->tpn_proto, "udp") == 0 ||
	  strcasecmp(tpn->tpn_proto, "*") == 0) {
	outgoing_try_tcp_instead(orq);
	continue;
      }
    }
    else if (err == ECONNREFUSED && orq->orq_try_tcp_instead) {
      if (strcasecmp(tpn->tpn_proto, "tcp") == 0 && msg_size(msg) <= 65535) {
	outgoing_try_udp_instead(orq);
	continue;
      }
    }
    else if (err == EPIPE) {
      /* Connection was closed */
      if (!once++) {
	orq->orq_retries++;
	continue;
      }
    }

    if (orq->orq_pending && orq->orq_tport)
      tport_release(orq->orq_tport, orq->orq_pending, orq->orq_request, 
		    NULL, orq, 0);

    orq->orq_pending = 0;

    outgoing_tport_error(agent, orq, NULL, orq->orq_request, err);

    return;
  }

  agent->sa_stats->as_sent_msg++;
  agent->sa_stats->as_sent_request++;
  if (retransmit)
    agent->sa_stats->as_retry_request++;

  SU_DEBUG_5(("nta: %ssent %s (%u) to " TPN_FORMAT "\n",
	      retransmit ? "re" : "",
	      orq->orq_method_name, orq->orq_cseq->cs_seq,
	      TPN_ARGS(tpn)));

#if HAVE_SIGCOMP
  if (cc) {
    if (orq->orq_cc)
      sigcomp_compartment_unref(orq->orq_cc);
    orq->orq_cc = cc;
  }
#endif

  if (orq->orq_pending) {
    assert(orq->orq_tport);
    tport_release(orq->orq_tport, orq->orq_pending, 
		  orq->orq_request, NULL, orq, 0);
    orq->orq_pending = 0;
  }

  if (orq->orq_stateless) {
    outgoing_reply(orq, 202, NULL, 202);
    return;
  }

  if (orq->orq_method != sip_method_ack) {
    orq->orq_pending = tport_pend(tp, orq->orq_request, 
				  outgoing_tport_error, orq);
    if (orq->orq_pending < 0)
      orq->orq_pending = 0;
  }

  if (tp != orq->orq_tport) {
    tport_decref(&orq->orq_tport);
    orq->orq_tport = tport_incref(tp);
  }

  orq->orq_reliable = tport_is_reliable(tp);

  if (retransmit)
    return;

  /* Set timers */
  if (orq->orq_method == sip_method_ack) {
    /* ACK */
    outgoing_complete(orq); /* Timer K */
    return;
  }

  outgoing_trying(orq);		/* Timer B / F */

  if (!orq->orq_reliable)
    outgoing_set_timer(orq, agent->sa_t1); /* Timer A/E */
}

static void
outgoing_try_tcp_instead(nta_outgoing_t *orq)
{
  tport_t *tp;
  tp_name_t tpn[1];

  *tpn = *orq->orq_tpn;
  tpn->tpn_proto = "tcp";
  orq->orq_try_tcp_instead = 1;

  tp = tport_by_name(orq->orq_agent->sa_tports, tpn);
  if (tp && tp != orq->orq_tport) {
    sip_t *sip = sip_object(orq->orq_request);
    sip_fragment_clear(sip->sip_via->v_common);
    sip->sip_via->v_protocol = sip_transport_tcp;

    SU_DEBUG_5(("nta: %s (%u) too large for UDP, trying TCP\n",
		orq->orq_method_name, orq->orq_cseq->cs_seq));

    orq->orq_tpn->tpn_proto = "tcp";
    tport_decref(&orq->orq_tport);
    orq->orq_tport = tport_incref(tp);
    return;
  }

  tpn->tpn_proto = "udp";
  orq->orq_try_udp_instead = 1;	/* Try again without SIP MTU limit */

  tp = tport_by_name(orq->orq_agent->sa_tports, tpn);
  if (tp && tp != orq->orq_tport) {
    SU_DEBUG_5(("nta: %s (%u) exceed normal UDP size limit\n",
		orq->orq_method_name, orq->orq_cseq->cs_seq));

    tport_decref(&orq->orq_tport);
    orq->orq_tport = tport_incref(tp);
  }
}

static void
outgoing_try_udp_instead(nta_outgoing_t *orq)
{
  tport_t *tp;
  tp_name_t tpn[1];

  *tpn = *orq->orq_tpn;
  tpn->tpn_proto = "udp";
  orq->orq_try_udp_instead = 1;
  
  tp = tport_by_name(orq->orq_agent->sa_tports, tpn);
  if (tp && tp != orq->orq_tport) {
    sip_t *sip = sip_object(orq->orq_request);

    sip_fragment_clear(sip->sip_via->v_common);
    sip->sip_via->v_protocol = sip_transport_udp;

    SU_DEBUG_5(("nta: %s (%u) TCP refused, trying UDP\n",
		orq->orq_method_name, orq->orq_cseq->cs_seq));

    orq->orq_tpn->tpn_proto = "udp";
    tport_decref(&orq->orq_tport);
    orq->orq_tport = tport_incref(tp);
  }
}


/** @internal Report transport errors. */
void
outgoing_tport_error(nta_agent_t *agent, nta_outgoing_t *orq,
		     tport_t *tp, msg_t *msg, int error)
{
  tp_name_t const *tpn = tp ? tport_name(tp) : orq->orq_tpn;

  if (orq->orq_pending) {
    assert(orq->orq_tport);
    tport_release(orq->orq_tport, orq->orq_pending, orq->orq_request, 
		  NULL, orq, 0);
    orq->orq_pending = 0;
  }

  if (error == EPIPE && orq->orq_retries++ == 0) {
    /* XXX - we should retry only if the transport is not newly created */
    outgoing_print_tport_error(orq, 5, "retrying once after ", 
			       tpn, msg, error);
    outgoing_send(orq, 1);
    return;
  }
  else if (error == ECONNREFUSED && orq->orq_try_tcp_instead) {
    /* RFC3261, 18.1.1 */
    if (strcasecmp(tpn->tpn_proto, "tcp") == 0 && msg_size(msg) <= 65535) {
      outgoing_print_tport_error(orq, 5, "retrying with UDP after ", 
				 tpn, msg, error);
      outgoing_try_udp_instead(orq);
      outgoing_remove(orq);	/* Reset state - this is no resend! */
      outgoing_send(orq, 0);	/* Send */
      return;
    }
  }

  if (outgoing_other_destinations(orq)) {
    outgoing_print_tport_error(orq, 5, "trying alternative server after ", 
			       tpn, msg, error);
    outgoing_try_another(orq);
    return;
  }

  outgoing_print_tport_error(orq, 3, "", tpn, msg, error);

  outgoing_reply(orq, SIP_503_SERVICE_UNAVAILABLE, 0);
}

static
void
outgoing_print_tport_error(nta_outgoing_t *orq, int level, char *todo,
			   tp_name_t const *tpn, msg_t *msg, int error)
{
  su_sockaddr_t *su = msg_addr(msg);
  char addr[SU_ADDRSIZE];

  su_llog(nta_log, level, 
	  "nta: %s (%u): %s%s (%u) with %s/[%s]:%u\n",
	  orq->orq_method_name, orq->orq_cseq->cs_seq,
	  todo, su_strerror(error), error, 
	  tpn->tpn_proto, 
	  inet_ntop(su->su_family, SU_ADDR(su), addr, sizeof(addr)),
	  htons(su->su_port));
}

/**@internal
 * Add features supported.
 */
static
int outgoing_features(nta_agent_t *agent, nta_outgoing_t *orq,
		      msg_t *msg, sip_t *sip,
		      tagi_t *tags)
{
  char const *supported[8];
  int i;

  if (orq->orq_method != sip_method_invite) /* fast path for now */
    return 0;

  supported[i = 0] = NULL;

  if (orq->orq_method == sip_method_invite) {
    int add_100rel = agent->sa_invite_100rel;
    int require_100rel = sip_has_feature(sip->sip_require, "100rel");

    tl_gets(tags,
	    NTATAG_REL100_REF(add_100rel),
	    TAG_END());
    if (add_100rel && !require_100rel &&
	!sip_has_feature(sip->sip_supported, "100rel"))
      supported[i++] = "100rel";

    orq->orq_must_100rel = require_100rel;
  }

  if (i) {
    supported[i] = NULL;

    if (sip->sip_supported) {
      su_home_t *home = msg_home(msg);
      return msg_list_append_items(home, sip->sip_supported, supported);
    }
    else {
      sip_supported_t s[1];
      sip_supported_init(s);
      s->k_items = supported;
      return sip_add_dup(msg, sip, (sip_header_t *)s);
    }
  }

  return 0;
}


/**@internal
 * Insert outgoing request to agent hash table
 */
static
void outgoing_insert(nta_agent_t *agent, nta_outgoing_t *orq)
{
  if (outgoing_htable_is_full(agent->sa_outgoing))
    outgoing_htable_resize(agent->sa_home, agent->sa_outgoing, 0);
  outgoing_htable_insert(agent->sa_outgoing, orq);
  orq->orq_inserted = 1;
}

/** @internal
 * Initialize a queue for outgoing transactions.
 */
static void
outgoing_queue_init(outgoing_queue_t *queue, unsigned timeout)
{
  memset(queue, 0, sizeof *queue);
  queue->q_tail = &queue->q_head;
  queue->q_timeout = timeout;
}

/** Change the timeout value of a queue */
static void
outgoing_queue_adjust(nta_agent_t *sa, 
		      outgoing_queue_t *queue, 
		      unsigned timeout)
{
  nta_outgoing_t *orq;
  su_duration_t latest;

  if (timeout >= queue->q_timeout || !queue->q_head) {
    queue->q_timeout = timeout;
    return;
  }

  latest = set_timeout(sa, queue->q_timeout = timeout);

  for (orq = queue->q_head; orq; orq = orq->orq_next) {
    if (orq->orq_timeout - latest > 0)
      orq->orq_timeout = latest;
  }
}

/** @internal
 * Test if an outgoing transaction is in a queue.
 */
static inline
int outgoing_is_queued(nta_outgoing_t const *orq)
{
  return orq && orq->orq_queue;
}

/** @internal
 * Insert an outgoing transaction into a queue. 
 *
 * The function outgoing_queue() inserts a client transaction into a queue,
 * and sets the corresponding timeout at the same time.
 */
static inline
void outgoing_queue(outgoing_queue_t *queue, 
		    nta_outgoing_t *orq)
{
  if (orq->orq_queue == queue) {
    assert(queue->q_timeout == 0);
    return;
  }

  if (outgoing_is_queued(orq))
    outgoing_remove(orq);

  assert(*queue->q_tail == NULL);

  orq->orq_timeout = set_timeout(orq->orq_agent, queue->q_timeout);
    
  orq->orq_queue = queue;
  orq->orq_prev = queue->q_tail; 
  *queue->q_tail = orq;
  queue->q_tail = &orq->orq_next;
  queue->q_length++;
}

/** @internal
 * Remove an outgoing transaction from a queue.
 */
static inline
void outgoing_remove(nta_outgoing_t *orq)
{
  assert(outgoing_is_queued(orq));
  assert(orq->orq_queue->q_length > 0);

  if ((*orq->orq_prev = orq->orq_next))
    orq->orq_next->orq_prev = orq->orq_prev;
  else
    orq->orq_queue->q_tail = orq->orq_prev, assert(!*orq->orq_queue->q_tail);

  orq->orq_queue->q_length--;
  orq->orq_next = NULL;
  orq->orq_prev = NULL;
  orq->orq_queue = NULL;
  orq->orq_timeout = 0;
}

/** Set retransmit timer (orq_retry).
 *
 * The function outgoing_set_timer() will set the retry timer (B/D) on
 * the outgoing request (client transaction). 
 */
static inline
void outgoing_set_timer(nta_outgoing_t *orq, unsigned interval)
{
  nta_outgoing_t **rq;
  
  assert(orq);

  if (interval == 0) {
    outgoing_reset_timer(orq);
    return;
  }

  /** The transaction will be removed from the retry dequeue. */
  if (orq->orq_rprev) {
    if ((*orq->orq_rprev = orq->orq_rnext)) 
      orq->orq_rnext->orq_rprev = orq->orq_rprev;
    if (orq->orq_agent->sa_out.re_t1 == &orq->orq_rnext)
      orq->orq_agent->sa_out.re_t1 = orq->orq_rprev;
  } else {
    orq->orq_agent->sa_out.re_length++;
  }

  orq->orq_retry = set_timeout(orq->orq_agent, orq->orq_interval = interval);

  rq = orq->orq_agent->sa_out.re_t1;

  if (!(*rq) || (*rq)->orq_retry - orq->orq_retry > 0)
    rq = &orq->orq_agent->sa_out.re_list;

  while (*rq && (*rq)->orq_retry - orq->orq_retry <= 0)
    rq = &(*rq)->orq_rnext;

  if ((orq->orq_rnext = *rq))
    orq->orq_rnext->orq_rprev = &orq->orq_rnext;
  *rq = orq;
  orq->orq_rprev = rq;

  if (interval == orq->orq_agent->sa_t1)
    orq->orq_agent->sa_out.re_t1 = rq;
}

static inline
void outgoing_reset_timer(nta_outgoing_t *orq)
{
  if (orq->orq_rprev) {
    if ((*orq->orq_rprev = orq->orq_rnext)) 
      orq->orq_rnext->orq_rprev = orq->orq_rprev;
    if (orq->orq_agent->sa_out.re_t1 == &orq->orq_rnext)
      orq->orq_agent->sa_out.re_t1 = orq->orq_rprev;
    orq->orq_agent->sa_out.re_length--;
  } 

  orq->orq_interval = 0, orq->orq_retry = 0;
  orq->orq_rnext = NULL, orq->orq_rprev = NULL;
}

/** @internal
 * Free resources associated with the request.
 */
static
void outgoing_free(nta_outgoing_t *orq)
{
  SU_DEBUG_9(("nta: outgoing_free(%p)\n", orq));
  outgoing_cut_off(orq);
  outgoing_reclaim(orq);
}

/** Remove outgoing request from hash tables */
static inline
void outgoing_cut_off(nta_outgoing_t *orq)
{
  nta_agent_t *agent = orq->orq_agent;

  if (orq->orq_inserted)
    outgoing_htable_remove(agent->sa_outgoing, orq), orq->orq_inserted = 0;

  if (outgoing_is_queued(orq))
    outgoing_remove(orq);

  outgoing_reset_timer(orq);

  if (orq->orq_pending) {
    tport_release(orq->orq_tport, orq->orq_pending, 
		  orq->orq_request, NULL, orq, 0);
  }
  orq->orq_pending = 0;

#if HAVE_SIGCOMP
  if (orq->orq_cc)
    sigcomp_compartment_unref(orq->orq_cc), orq->orq_cc = NULL;
#endif

  if (orq->orq_tport)
    tport_decref(&orq->orq_tport);
}

/** Reclaim outgoing request */
static inline
void outgoing_reclaim(nta_outgoing_t *orq)
{
  if (orq->orq_request)
    msg_destroy(orq->orq_request), orq->orq_request = NULL;
  if (orq->orq_response)
    msg_destroy(orq->orq_response), orq->orq_response = NULL;
#if HAVE_SOFIA_SRESOLV
  if (orq->orq_resolver)
    outgoing_destroy_resolver(orq);
#endif  
  su_free(orq->orq_agent->sa_home, orq);
}

/** Queue request to be freed */
static inline 
void outgoing_free_queue(outgoing_queue_t *q, nta_outgoing_t *orq)
{
  outgoing_cut_off(orq);
  outgoing_queue(q, orq);
}

/** Reclaim memory used by queue of requests */
static 
void outgoing_reclaim_queued(su_root_magic_t *rm,
			     su_msg_r msg,
			     union sm_arg_u *u)
{
  outgoing_queue_t *q = u->a_outgoing_queue;
  nta_outgoing_t *orq, *orq_next;

  SU_DEBUG_9(("outgoing_reclaim_all(%p, %p, %p)\n", rm, msg, u));

  for (orq = q->q_head; orq; orq = orq_next) {
    orq_next = orq->orq_next;
    outgoing_reclaim(orq);
  }
}

/** @internal Default callback for request */
int outgoing_default_cb(nta_outgoing_magic_t *magic,
			nta_outgoing_t *orq,
			sip_t const *sip)
{
  if (sip == NULL || sip->sip_status->st_status >= 200)
    outgoing_destroy(orq);
  return 0;
}

/** @internal Destroy an outgoing transaction */
void outgoing_destroy(nta_outgoing_t *orq)
{
  if (orq->orq_terminated) {
    outgoing_free(orq);
  }
  else {
    orq->orq_destroyed = 1;
    orq->orq_callback = outgoing_default_cb;
    orq->orq_magic = NULL;
  }
}

/** @internal Outgoing transaction timer routine. */
static
int outgoing_timer(nta_agent_t *sa, su_duration_t now)
{
  nta_outgoing_t *orq;
  outgoing_queue_t rq[1];
  int retransmitted = 0, terminated = 0, timeout = 0, destroyed;
  int total = sa->sa_outgoing->oht_used;
  int trying = sa->sa_out.re_length;
  int pending = sa->sa_out.trying->q_length + sa->sa_out.inv_calling->q_length;
  int completed = sa->sa_out.completed->q_length + 
    sa->sa_out.inv_completed->q_length;
  outgoing_queue_init(sa->sa_out.free = rq, 0);

  while ((orq = sa->sa_out.re_list)) {
    if ((orq->orq_retry && orq->orq_retry - now > 0)
	|| retransmitted >= timer_max_retransmit)
      break;

    retransmitted++;

    assert(!orq->orq_reliable && orq->orq_interval != 0);

    SU_DEBUG_5(("nta: timer %s fired, %s %s (%u)\n",
		orq->orq_method == sip_method_invite ? "A" : "E",
		"retransmit", orq->orq_method_name, orq->orq_cseq->cs_seq));

    outgoing_retransmit(orq);

    if (2 * orq->orq_interval < sa->sa_t2 ||
	orq->orq_method == sip_method_invite)
      outgoing_set_timer(orq, 2 * orq->orq_interval);
    else
      outgoing_set_timer(orq, sa->sa_t2);
  }

  terminated
    = outgoing_timer_dk(sa->sa_out.inv_completed, "D", now)
    + outgoing_timer_dk(sa->sa_out.completed, "K", now);

  timeout
    = outgoing_timer_bf(sa->sa_out.inv_calling, "B", now)
    + outgoing_timer_bf(sa->sa_out.trying, "F", now);

  destroyed = outgoing_mass_destroy(sa, rq);

  sa->sa_out.free = NULL;

  if (retransmitted || timeout || terminated || destroyed) {
    SU_DEBUG_5(("nta_outgoing_timer: "
		"%u/%u resent, %u/%u tout, %u/%u term, %u/%u free\n",
		retransmitted, trying,
		timeout, pending,
		terminated, completed, 
		destroyed, total));
  }

  return 
    retransmitted >= timer_max_retransmit || 
    terminated >= timer_max_terminate || 
    timeout >= timer_max_timeout;
}

/** @internal Retransmit the outgoing request. */
void outgoing_retransmit(nta_outgoing_t *orq)
{
  if (orq->orq_prepared && !orq->orq_delayed) {
    orq->orq_retries++;

#if HAVE_SIGCOMP
    if (orq->orq_retries >= 4 && orq->orq_cc) {
      orq->orq_tpn->tpn_comp = NULL;
      if (orq->orq_retries == 4) {
	sigcomp_compartment_close(orq->orq_cc, SIGCOMP_CLOSE_COMP);
	sigcomp_compartment_unref(orq->orq_cc), orq->orq_cc = NULL;
      }
    }
#endif

    outgoing_send(orq, 1);
  }
}

/** Trying a client transaction. */
static
void outgoing_trying(nta_outgoing_t *orq)
{
  if (orq->orq_method == sip_method_invite)
    outgoing_queue(orq->orq_agent->sa_out.inv_calling, orq);
  else
    outgoing_queue(orq->orq_agent->sa_out.trying, orq);
}

/** Handle timers B and F */
static
int outgoing_timer_bf(outgoing_queue_t *q, 
		       char const *timer, 
		       su_duration_t now)
{
  int timeout = 0;

  for (;;) {
    nta_outgoing_t *orq = q->q_head;

    if (!orq 
	|| !orq->orq_timeout
	|| orq->orq_timeout - now > 0 
	|| timeout >= timer_max_timeout)
      return timeout;

    timeout++;
    
    SU_DEBUG_5(("nta: timer %s fired, %s %s (%u)\n",
		timer, "timeout", 
		orq->orq_method_name, orq->orq_cseq->cs_seq));

    outgoing_timeout(orq, now);

    assert(q->q_head != orq || orq->orq_timeout - now > 0);
  }
}

/** @internal Signal transaction timeout to the application. */
void outgoing_timeout(nta_outgoing_t *orq, su_duration_t now)
{
  nta_outgoing_t *cancel;

  if (outgoing_other_destinations(orq)) {
    SU_DEBUG_5(("nta(%p): try next after timeout\n", orq));
    outgoing_try_another(orq);
    return;
  }

  cancel = orq->orq_cancel; orq->orq_cancel = NULL;
  orq->orq_agent->sa_stats->as_tout_request++;

  outgoing_reply(orq, SIP_408_REQUEST_TIMEOUT, 0);

  if (cancel)
    outgoing_timeout(cancel, now);
}

/** Complete a client transaction. 
 *
 * @return True if transaction was free()d.
 */
static
int outgoing_complete(nta_outgoing_t *orq)
{
  orq->orq_completed = 1;

  outgoing_reset_timer(orq); /* Timer A/E */

  if (orq->orq_stateless)
    return outgoing_terminate(orq);

  if (orq->orq_reliable && orq->orq_method != sip_method_ack)
    return outgoing_terminate(orq);

  if (orq->orq_method == sip_method_invite) {
    outgoing_queue(orq->orq_agent->sa_out.inv_completed, orq); /* Timer D */
  }
  else {
    outgoing_queue(orq->orq_agent->sa_out.completed, orq); /* Timer K */
  }

  return 0;
}

/** Handle timers D and K */
static
int outgoing_timer_dk(outgoing_queue_t *q, 
		      char const *timer, 
		      su_duration_t now)
{
  int terminated = 0;

  for (;;) {
    nta_outgoing_t *orq = q->q_head;

    if (!orq 
	|| !orq->orq_timeout 
	|| orq->orq_timeout - now > 0 
	|| terminated >= timer_max_terminate)
      return terminated;

    terminated++;

    SU_DEBUG_5(("nta: timer %s fired, %s %s (%u)\n", timer,
		"terminate", orq->orq_method_name, orq->orq_cseq->cs_seq));

    outgoing_terminate(orq);
  }
}

/** Terminate a client transaction. */
static
int outgoing_terminate(nta_outgoing_t *orq)
{
  orq->orq_terminated = 1;

  if (!orq->orq_destroyed) {
    outgoing_queue(orq->orq_agent->sa_out.terminated, orq);
    return 0;
  } else if (orq->orq_agent->sa_out.free) {
    outgoing_free_queue(orq->orq_agent->sa_out.free, orq);
    return 1;
  } else {
    outgoing_free(orq);
    return 1;
  }
}

/** Mass destroy client transactions */
static
int outgoing_mass_destroy(nta_agent_t *sa, outgoing_queue_t *q)
{
  int destroyed = q->q_length;

  if (destroyed > 2 && *sa->sa_terminator) {
    su_msg_r m = SU_MSG_RINITIALIZER;

    if (su_msg_create(m,
		      su_clone_task(sa->sa_terminator),
		      su_root_task(sa->sa_root),
		      outgoing_reclaim_queued,
		      sizeof(outgoing_queue_t)) == SU_SUCCESS) {
      outgoing_queue_t *mq = su_msg_data(m)->a_outgoing_queue;

      *mq = *q;

      if (su_msg_send(m) == SU_SUCCESS)
	q->q_length = 0;
    }    
  }
  
  if (q->q_length) 
    outgoing_reclaim_queued(NULL, NULL, (void*)q);

  return destroyed;
}

/** Find an outgoing request corresponging to a message and Via line.
 *
 * The function nta_outgoing_find() returns an outgoing request object based
 * on a message and the Via line given as argument.
 */
nta_outgoing_t *nta_outgoing_find(nta_agent_t const *sa,
				  msg_t const *msg,
				  sip_t const *sip,
				  sip_via_t const *v)
{
  if (sa == NULL || msg == NULL || sip == NULL || v == NULL) {
    su_seterrno(EINVAL);
    return NULL;
  }

  return outgoing_find(sa, msg, sip, v);
}

/**@internal
 *
 * Find an outgoing request corresponging to a message and Via line.
 *
 */
nta_outgoing_t *outgoing_find(nta_agent_t const *sa,
			      msg_t const *msg,
			      sip_t const *sip,
			      sip_via_t const *v)
{
  nta_outgoing_t **oo, *orq;
  outgoing_htable_t const *oht = sa->sa_outgoing;
  sip_cseq_t const *cseq = sip->sip_cseq;
  sip_call_id_t const *i = sip->sip_call_id;
  hash_value_t hash;
  sip_method_t method, method2;
  unsigned short status = sip->sip_status ? sip->sip_status->st_status : 0;

  if (cseq == NULL)
    return NULL;

  hash = NTA_HASH(i, cseq->cs_seq);

  method = cseq->cs_method;

  /* Get original invite when ACKing */
  if (sip->sip_request && method == sip_method_ack && v == NULL)
    method = sip_method_invite, method2 = sip_method_invalid;
  else if (sa->sa_is_a_uas && status >= 200 && method == sip_method_invite)
    method2 = sip_method_ack;
  else
    method2 = method;

  for (oo = outgoing_htable_hash(oht, hash);
       (orq = *oo);
       oo = outgoing_htable_next(oht, oo)) {
    if (orq->orq_stateless)
      continue;
    /* Accept terminated transactions when looking for original INVITE */
    if (orq->orq_terminated && method2 != sip_method_invalid)
      continue;
    if (hash != orq->orq_hash)
      continue;
    if (orq->orq_call_id->i_hash != i->i_hash ||
	strcmp(orq->orq_call_id->i_id, i->i_id))
      continue;
    if (orq->orq_cseq->cs_seq != cseq->cs_seq)
      continue;
    if (method == sip_method_unknown &&
	strcmp(orq->orq_cseq->cs_method_name, cseq->cs_method_name))
      continue;
    if (orq->orq_method != method && orq->orq_method != method2)
      continue;
    if (str0casecmp(orq->orq_from->a_tag, sip->sip_from->a_tag))
      continue;
    if (orq->orq_to->a_tag && sip->sip_to->a_tag
	? strcasecmp(orq->orq_to->a_tag, sip->sip_to->a_tag)
	: !addr_match(orq->orq_to, sip->sip_to))
      continue;
    if (orq->orq_method == method ?
	/* Don't match if request To has a tag and response has no To tag */
	orq->orq_to->a_tag && !sip->sip_to->a_tag :
	/* Don't (with ACK) if request/response tag mismatch */
	!orq->orq_to->a_tag != !sip->sip_to->a_tag)
      continue;

    if (orq->orq_method == sip_method_ack) {
      if (orq->orq_ack_error ? status < 300 : status >= 300)
	continue;
    }

    if (v && str0casecmp(orq->orq_branch + strlen("branch="), v->v_branch))
      continue;

    break;			/* match */
  }

  return orq;
}

/** Process a response message. */
int outgoing_recv(nta_outgoing_t *orq,
		  int status,
		  msg_t *msg,
		  sip_t *sip)
{
  nta_agent_t *sa = orq->orq_agent;
  short orq_status = orq->orq_status;

  if (status < 100) status = 100;

  if (sip && orq->orq_delay == UINT_MAX)
    outgoing_estimate_delay(orq, sip);

#if HAVE_SIGCOMP
  if (orq->orq_cc)
    tport_sigcomp_accept(orq->orq_tport, orq->orq_cc, msg);
#endif

  if (orq->orq_cancel) {
    nta_outgoing_t *cancel;

    cancel = orq->orq_cancel; orq->orq_cancel = NULL;

    cancel->orq_delayed = 0;

    if (status < 200)
      outgoing_send(cancel, 0);
    else
      outgoing_reply(cancel, SIP_481_NO_TRANSACTION, 0);
  }

  if (orq->orq_pending) {
    tport_release(orq->orq_tport, orq->orq_pending, orq->orq_request, 
		  msg, orq, status < 200);
    if (status >= 200)
      orq->orq_pending = 0;
  }

  /* The state machines */
  if (orq->orq_method == sip_method_invite) {
    if (orq->orq_destroyed && status > 100 && status < 300)
      return -1;		/* Proxy statelessly (Bis04 17.4) */

    outgoing_reset_timer(orq);

    if (status < 200) {
      if (orq->orq_queue == sa->sa_out.inv_calling) {
	orq->orq_status = status;
	outgoing_queue(sa->sa_out.inv_proceeding, orq);
      }

      /* Handle 100rel */
      if (sip && sip->sip_rseq)
	if (outgoing_recv_reliable(orq, msg, sip) < 0) {
	  msg_destroy(msg);
	  return 0;
	}
    }
    else {
      /* Final response */
      if (status >= 300)
	outgoing_ack(orq, msg, sip);

      if (!orq->orq_completed) {
	if (outgoing_complete(orq))
	  return 0;

	if (sip && sa->sa_is_a_uas) {
	  su_home_t *home = msg_home(orq->orq_request);
	  orq->orq_tag = su_strdup(home, sip->sip_to->a_tag);
	}
      }
      /* Retransmission or response from another fork */
      else {
	/* Once 2xx has been received, non-2xx will not be forwarded */
	if (status >= 300)
	  return outgoing_duplicate(orq, msg, sip);

	if (sa->sa_is_a_uas) {
	  if (str0cmp(sip->sip_to->a_tag, orq->orq_tag) == 0)
	    /* Catch retransmission */
	    return outgoing_duplicate(orq, msg, sip);
	}
      }

      orq->orq_status = status;
    }
  }
  else if (orq->orq_method != sip_method_ack) {
    /* Non-INVITE */
    if (orq->orq_queue == sa->sa_out.trying) {
      assert(orq_status < 200);

      if (status < 200) {
	if (!orq->orq_reliable)
	  outgoing_set_timer(orq, sa->sa_t2);
      } 
      else if (!outgoing_complete(orq)) {
#if HAVE_SIGCOMP
	if (orq->orq_sigcomp_zap && orq->orq_tport && orq->orq_cc)
	  sigcomp_compartment_close(orq->orq_cc, SIGCOMP_CLOSE_COMP_DECOMP);
#endif
      } 
      else /* outgoing_complete */ {
	msg_destroy(msg);
	return 0;
      }
    } else {
      /* Already completed or terminated */
      assert(orq->orq_queue == sa->sa_out.completed ||
	     orq->orq_queue == sa->sa_out.terminated);
      assert(orq->orq_status >= 200);
      return outgoing_duplicate(orq, msg, sip);
    }

    orq->orq_status = status;
  }
  else {
    /* ACK */
    if (sip && (sip->sip_flags & NTA_INTERNAL_MSG) == 0)
      /* Received re-transmitted final reply to INVITE, retransmit ACK */
      outgoing_retransmit(orq);
    msg_destroy(msg);
    return 0;
  }

  if (status + orq->orq_pass_100 > 100 && !orq->orq_destroyed) {
    if (orq->orq_response)
      msg_destroy(orq->orq_response);
    orq->orq_response = msg;
    /* Call callback */
    orq->orq_callback(orq->orq_magic, orq, sip);
  }
  else
    msg_destroy(msg);

  return 0;
}

static void outgoing_estimate_delay(nta_outgoing_t *orq, sip_t *sip)
{
  su_time_t now = su_now();
  double diff = 1000 * su_time_diff(now, orq->orq_sent);

  if (orq->orq_timestamp && sip->sip_timestamp) {
    double diff2, delay = 0.0;
    su_time_t timestamp = { 0, 0 };
    char const *bad;

    sscanf(sip->sip_timestamp->ts_stamp, "%lu.%lu",
	   &timestamp.tv_sec, &timestamp.tv_usec);

    diff2 = 1000 * su_time_diff(now, timestamp);

    if (diff2 < 0)
      bad = "negative";
    else if (diff2 > diff + 1e-3)
      bad = "too large";
    else {
      if (sip->sip_timestamp->ts_delay)
	sscanf(sip->sip_timestamp->ts_delay, "%lg", &delay);

      if (1000 * delay <= diff2) {
	diff = diff2 - 1000 * delay;
	orq->orq_delay = (unsigned)diff;
	SU_DEBUG_7(("nta_outgoing: RTT is %g ms, now is %lu.%06lu, "
		    "Timestamp was %s %s\n",
		    diff, now.tv_sec, now.tv_usec,
		    sip->sip_timestamp->ts_stamp,
		    sip->sip_timestamp->ts_delay ?
		    sip->sip_timestamp->ts_delay : ""));
	return;
      }
      bad = "delay";
    }

    SU_DEBUG_3(("nta_outgoing: %s Timestamp %lu.%06lu %g "
		"(sent %lu.%06lu, now is %lu.%06lu)\n",
		bad,
		timestamp.tv_sec, timestamp.tv_usec,
		delay,
		orq->orq_sent.tv_sec, orq->orq_sent.tv_usec,
		now.tv_sec, now.tv_usec));
  }

  if (diff >= 0 && diff < (double)UINT_MAX) {
    orq->orq_delay = (unsigned)diff;
    SU_DEBUG_7(("nta_outgoing: RTT is %g ms\n", diff));
  }
}

/**@typedef nta_response_f
 *
 * Callback for replies to outgoing requests.
 *
 * This is a callback function invoked by NTA when it has received a new
 * reply to an outgoing request.
 *
 * @param magic   request context
 * @param request request handle
 * @param sip     received status message
 *
 * @return
 * This callback function should return always 0.
 *
 */

/** Process duplicate responses */
static int outgoing_duplicate(nta_outgoing_t *orq,
			      msg_t *msg,
			      sip_t *sip)
{
  sip_via_t *v;

  if (sip && (sip->sip_flags & NTA_INTERNAL_MSG) == 0) {
    v = sip->sip_via;

    SU_DEBUG_5(("nta: %u %s is duplicate response to %d %s\n",
		sip->sip_status->st_status, sip->sip_status->st_phrase,
		orq->orq_cseq->cs_seq, orq->orq_cseq->cs_method_name));
    if (v)
      SU_DEBUG_5(("\tVia: %s %s%s%s%s%s%s%s%s%s\n",
		  v->v_protocol, v->v_host,
		  SIP_STRLOG(":", v->v_port),
		  SIP_STRLOG(" ;received=", v->v_received),
		  SIP_STRLOG(" ;maddr=", v->v_maddr),
		  SIP_STRLOG(" ;branch=", v->v_branch)));
  }

  msg_destroy(msg);
  return 0;
}

/** @internal ACK to a final response (300..699).
 * These messages are ACK'ed via the original URL (and tport)
 */
void outgoing_ack(nta_outgoing_t *orq, msg_t *msg, sip_t *sip)
{
  nta_outgoing_t *ack;
  msg_t *ackmsg;
  sip_t *acksip;

  assert(orq);

  /* Do not ack internally generated messages... */
  if (sip == NULL || sip->sip_flags & NTA_INTERNAL_MSG)
    return;

  assert(sip); assert(sip->sip_status);
  assert(sip->sip_status->st_status >= 300);
  assert(orq->orq_tport);

  ackmsg = outgoing_ackmsg(orq, SIP_METHOD_ACK, NULL);
  acksip = sip_object(ackmsg);

  if (acksip) {
    if (sip->sip_to->a_tag && !acksip->sip_to->a_tag)
      sip_to_tag(msg_home(ackmsg), acksip->sip_to, sip->sip_to->a_tag);

    if ((ack = outgoing_create(orq->orq_agent, NULL, NULL,
			       NULL, orq->orq_tpn, ackmsg,
			       NTATAG_BRANCH_KEY(sip->sip_via->v_branch),
			       NTATAG_USER_VIA(1),
			       NTATAG_STATELESS(1),
			       TAG_END())))
      ;
    else
      msg_destroy(msg);
  }
}

/** Generate messages for hop-by-hop ACK or CANCEL.
 */
msg_t *outgoing_ackmsg(nta_outgoing_t *orq, sip_method_t m, char const *mname,
		       tagi_t const *tags)
{
  msg_t *msg = nta_msg_create(orq->orq_agent, 0);
  su_home_t *home = msg_home(msg);
  sip_t *sip = sip_object(msg);
  sip_t *old = sip_object(orq->orq_request);
  sip_via_t via[1];

  if (!sip)
    return NULL;

  sip->sip_request =
    sip_request_create(home, m, mname, (url_string_t *)orq->orq_url, NULL);

  sip_add_dup(msg, sip, (sip_header_t *)old->sip_to);
  sip_add_dup(msg, sip, (sip_header_t *)old->sip_from);
  sip_add_dup(msg, sip, (sip_header_t *)old->sip_call_id);
  sip_add_dup(msg, sip, (sip_header_t *)old->sip_route);
  /* Bug #1326727. */
  sip_add_dup(msg, sip, (sip_header_t *)old->sip_accept_contact);
  sip_add_dup(msg, sip, (sip_header_t *)old->sip_reject_contact);
  sip_add_dup(msg, sip, (sip_header_t *)old->sip_request_disposition);

  if (old->sip_via) {
    /* Add only the topmost Via header */
    *via = *old->sip_via; via->v_next = NULL;
    sip_add_dup(msg, sip, (sip_header_t *)via);
  }

  sip->sip_cseq = sip_cseq_create(home, old->sip_cseq->cs_seq, m, mname);

  if (tags)
    sip_add_tl(msg, sip, TAG_NEXT(tags));

  if (!sip->sip_max_forwards)
    sip_add_dup(msg, sip, (sip_header_t *)orq->orq_agent->sa_max_forwards);

  if (sip->sip_request &&
      sip->sip_to &&
      sip->sip_from &&
      sip->sip_call_id &&
      (!old->sip_route || sip->sip_route) &&
      sip->sip_cseq)
    return msg;

  nta_msg_discard(orq->orq_agent, msg);
  return NULL;
}

static
void outgoing_delayed_recv(su_root_magic_t *rm,
			   su_msg_r msg,
			   union sm_arg_u *u);

/** Respond internally to a transaction. */
int outgoing_reply(nta_outgoing_t *orq, int status, char const *phrase,
		   int delayed)
{
  nta_agent_t *agent = orq->orq_agent;
  msg_t *msg = NULL;
  sip_t *sip = NULL;

  assert(status == 202 || status >= 400);

  if (orq->orq_pending)
    tport_release(orq->orq_tport, orq->orq_pending, 
		  orq->orq_request, NULL, orq, 0);
  orq->orq_pending = 0;

  orq->orq_delayed = 0;

  if (orq->orq_method == sip_method_ack) {
    if (status != delayed)
      SU_DEBUG_3(("nta(%p): responding %u %s to ACK!\n", orq, status, phrase));
    orq->orq_status = status;
    if (orq->orq_queue == NULL)
      outgoing_complete(orq);	/* Timer D/K */
    return 0;
  }
    
  if (orq->orq_destroyed) {
    if (orq->orq_status < 200)
      orq->orq_status = status;
    outgoing_complete(orq);	/* Timer D/K */
    return 0;
  }

  if (orq->orq_queue == NULL ||
      orq->orq_queue == orq->orq_agent->sa_out.resolving ||
      orq->orq_queue == orq->orq_agent->sa_out.delayed) 
    outgoing_trying(orq);

  /* Create response message, if needed */
  if (orq->orq_stateless || 
      orq->orq_callback == outgoing_default_cb ||
      (status == 408 && !orq->orq_agent->sa_timeout_408))
    ;
  else if ((msg = nta_msg_create(agent, NTA_INTERNAL_MSG))) {
    if (!orq->orq_prepared) {
      tport_t *tp = tport_primaries(orq->orq_agent->sa_tports);
      agent_insert_via(orq->orq_agent, orq->orq_request,
		       agent_tport_via(tp),
		       orq->orq_branch,
		       orq->orq_user_via);
    }

    sip = sip_object(msg);
    assert(sip->sip_flags & NTA_INTERNAL_MSG);
    if (sip_complete_response(msg, status, phrase,
			      sip_object(orq->orq_request)) < 0) {
      assert(!"complete message");
      return -1;
    } 
    else if (status > 100 &&
	     sip->sip_to && !sip->sip_to->a_tag &&
	     sip->sip_cseq->cs_method != sip_method_cancel &&
	     sip_to_tag(msg_home(msg), sip->sip_to,
			nta_agent_newtag(msg_home(msg), "tag=%s", agent)) < 0) {
      assert(!"adding tag");
      return -1;
    }
    if (status > 400 && agent->sa_blacklist) {
      sip_retry_after_t af[1];
      sip_retry_after_init(af)->af_delta = agent->sa_blacklist;

      sip_add_dup(msg, sip, (sip_header_t *)af);
    }
  }

  if (orq->orq_inserted && !delayed) {
    outgoing_recv(orq, status, msg, sip);
    return 0;
  }
  else if (orq->orq_stateless && orq->orq_callback == outgoing_default_cb) {
    /* Xyzzy */
    orq->orq_status = status;
    orq->orq_completed = 1;
  } else {
    /*
     * The thread creating outgoing transaction must return to application
     * before transaction callback can be invoked. Therefore processing an
     * internally generated response message must be delayed until
     * transaction creation is completed.
     *
     * The internally generated message is transmitted using su_msg_send()
     * and it is delivered back to NTA when the application next time
     * executes the su_root_t event loop.
     */
    nta_agent_t *agent = orq->orq_agent;
    su_root_t *root = agent->sa_root;
    su_msg_r su_msg = SU_MSG_RINITIALIZER;

    if (su_msg_create(su_msg,
		      su_root_task(root),
		      su_root_task(root),
		      outgoing_delayed_recv,
		      sizeof(struct outgoing_recv_s)) == SU_SUCCESS) {
      struct outgoing_recv_s *a = su_msg_data(su_msg)->a_outgoing_recv;

      a->orq = orq;
      a->msg = msg;
      a->sip = sip;
      a->status = status;

      if (su_msg_send(su_msg) == SU_SUCCESS) {
	return 0;
      }
    }
  }

  if (msg)
    msg_destroy(msg);

  return -1;
}

static
void outgoing_delayed_recv(su_root_magic_t *rm,
			   su_msg_r msg,
			   union sm_arg_u *u)
{
  struct outgoing_recv_s *a = u->a_outgoing_recv;
  if (outgoing_recv(a->orq, a->status, a->msg, a->sip) < 0 && a->msg)
    msg_destroy(a->msg);
}

/* ====================================================================== */
/* 9) Resolving (SIP) URL */

#if HAVE_SOFIA_SRESOLV

struct sipdns_query;

/** DNS resolving for (SIP) URLs */
struct sipdns_resolver
{
  tp_name_t             sr_tpn[1];     	/**< Copy of original transport name */
  sres_query_t         *sr_query;      	/**< Current DNS Query */
  char const           *sr_target;     	/**< Target for current query */

  struct sipdns_query  *sr_current;    	/**< Current query (with results) */
  char                **sr_results;    	/**< A/AAAA results to be used */

  struct sipdns_query  *sr_head;       	/**< List of intermediate results */
  struct sipdns_query **sr_tail;       	/**< End of intermediate result list */

  struct sipdns_query  *sr_done;       	/**< Completed intermediate results */

  /** Transports to consider for this request */
  struct sipdns_tport const *sr_tports[SIPDNS_TRANSPORTS + 1];

  uint16_t sr_a_aaaa1, sr_a_aaaa2;     /**< Order of A and/or AAAA queries. */

  unsigned 
    sr_use_naptr:1, 
    sr_use_srv:1,
    sr_use_a_aaaa:1;
};

/** Intermediate queries */
struct sipdns_query
{
  struct sipdns_query *sq_next;

  int32_t  sq_priority;		/* priority or preference  */
  uint16_t sq_weight;		/* preference or weight */
  uint16_t sq_type;

  char const *sq_proto;
  char const *sq_domain;
  char     sq_port[6];		/* port number */

};

static int outgoing_resolve_next(nta_outgoing_t *orq);
static int outgoing_resolving(nta_outgoing_t *orq);
static int outgoing_resolving_error(nta_outgoing_t *, 
				    int status, char const *phrase);
static int outgoing_query_naptr(nta_outgoing_t *orq, char const *domain);
static void outgoing_answer_naptr(sres_context_t *orq, sres_query_t *q,
				  sres_record_t *answers[]);

static int outgoing_make_srv_query(nta_outgoing_t *orq);
static int outgoing_make_a_aaaa_query(nta_outgoing_t *orq);

static void outgoing_query_all(nta_outgoing_t *orq);

static int outgoing_query_srv(nta_outgoing_t *orq, struct sipdns_query *);
static void outgoing_answer_srv(sres_context_t *orq, sres_query_t *q,
				sres_record_t *answers[]);

static int outgoing_query_aaaa(nta_outgoing_t *orq, struct sipdns_query *);
static void outgoing_answer_aaaa(sres_context_t *orq, sres_query_t *q,
				 sres_record_t *answers[]);

static int outgoing_query_a(nta_outgoing_t *orq, struct sipdns_query *);
static void outgoing_answer_a(sres_context_t *orq, sres_query_t *q,
			      sres_record_t *answers[]);

static void outgoing_query_results(nta_outgoing_t *orq,
				   struct sipdns_query *sq,
				   char *results[],
				   int rlen);


#define SIPDNS_503_ERROR 503, "DNS Error"

/** Resolve a request destination */
static void
outgoing_resolve(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = NULL;
  char const *tpname = orq->orq_tpn->tpn_proto;

  if (orq->orq_agent->sa_resolver)
    orq->orq_resolver = sr = su_zalloc(orq->orq_agent->sa_home, (sizeof *sr));

  if (!sr) {
    outgoing_resolving_error(orq, SIP_500_INTERNAL_SERVER_ERROR);
    return;
  } 

  *sr->sr_tpn = *orq->orq_tpn;
  sr->sr_use_srv = orq->orq_agent->sa_use_srv;
  sr->sr_use_naptr = orq->orq_agent->sa_use_naptr && sr->sr_use_srv;
  sr->sr_use_a_aaaa = 1;
  sr->sr_tail = &sr->sr_head;

  /* RFC 3263:
     If the TARGET was not a numeric IP address, but a port is present in
     the URI, the client performs an A or AAAA record lookup of the domain
     name.  The result will be a list of IP addresses, each of which can
     be contacted at the specific port from the URI and transport protocol
     determined previously.  The client SHOULD try the first record.  If
     an attempt should fail, based on the definition of failure in Section
     4.3, the next SHOULD be tried, and if that should fail, the next
     SHOULD be tried, and so on.
     
     This is a change from RFC 2543.  Previously, if the port was
     explicit, but with a value of 5060, SRV records were used.  Now, A
     or AAAA records will be used.
  */
  if (sr->sr_tpn->tpn_port)
    sr->sr_use_naptr = 0, sr->sr_use_srv = 0;
  /* RFC3263:
     If [...] a transport was specified explicitly, the client performs an
     SRV query for that specific transport,
  */
  else if (strcmp(tpname, "*") != 0)
    sr->sr_use_naptr = 0;

  if (sr->sr_use_srv || sr->sr_use_naptr) {
    /* Initialize sr_tports */
    tport_t *tport;
    char const *ident = sr->sr_tpn->tpn_ident;
    int i, j;

    for (tport = tport_primary_by_name(orq->orq_agent->sa_tports, orq->orq_tpn);
	 tport;
	 tport = tport_next(tport)) {
      tp_name_t const *tpn = tport_name(tport);
      if (strcmp(tpname, "*") && strcasecmp(tpn->tpn_proto, tpname))
	continue;
      if (ident && (tpn->tpn_ident == NULL || strcmp(ident, tpn->tpn_ident)))
	continue;

      for (j = 0; j < SIPDNS_TRANSPORTS; j++)
	if (strcasecmp(tpn->tpn_proto, sipdns_tports[j].name) == 0)
	  break;

      assert(j < SIPDNS_TRANSPORTS); 
      if (j == SIPDNS_TRANSPORTS)
	/* Someone added transport but did not update sipdns_tports */
	continue;

      for (i = 0; i < SIPDNS_TRANSPORTS; i++) {
	if (sipdns_tports + j == sr->sr_tports[i] || sr->sr_tports[i] == NULL)
	  break;
      }
      sr->sr_tports[i] = sipdns_tports + j;

      if (strcmp(tpname, "*")) /* Looking for only one transport */
	break;	
    }

    /* Nothing found */
    if (!sr->sr_tports[0]) {
      SU_DEBUG_3(("nta(%p): transport %s is not supported%s%s\n", orq, tpname,
		  ident ? " by interface " : "", ident ? ident : ""));
      outgoing_resolving_error(orq, SIPDNS_503_ERROR);
      return;
    }
  }

  switch (orq->orq_res_order) {
  default:
  case nta_res_ip6_ip4:
    sr->sr_a_aaaa1 = sres_type_aaaa, sr->sr_a_aaaa2 = sres_type_a;
    break;
  case nta_res_ip4_ip6:
    sr->sr_a_aaaa1 = sres_type_a, sr->sr_a_aaaa2 = sres_type_aaaa;
    break;
  case nta_res_ip6_only:
    sr->sr_a_aaaa1 = sres_type_aaaa, sr->sr_a_aaaa2 = sres_type_aaaa;
    break;
  case nta_res_ip4_only:
    sr->sr_a_aaaa1 = sres_type_a, sr->sr_a_aaaa2 = sres_type_a;
    break;
  }    

  outgoing_resolve_next(orq);
}

/** Resolve next destination. */
static int
outgoing_resolve_next(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;

  if (sr == NULL) {
    outgoing_resolving_error(orq, SIP_500_INTERNAL_SERVER_ERROR);
    return 0;
  }

  if (sr->sr_results) {
    /* Use existing A/AAAA results */
    su_free(msg_home(orq->orq_request), sr->sr_results[0]);
    sr->sr_results++;
    if (sr->sr_results[0]) {
      struct sipdns_query *sq = sr->sr_current; assert(sq);

      if (sq->sq_proto)
	orq->orq_tpn->tpn_proto = sq->sq_proto;
      if (sq->sq_port[0])
	  orq->orq_tpn->tpn_port = sq->sq_port;

      orq->orq_tpn->tpn_host = sr->sr_results[0];

      outgoing_reset_timer(orq);
      outgoing_queue(orq->orq_agent->sa_out.resolving, orq);
      outgoing_prepare_send(orq);
      return 1;
    }
    else {
      sr->sr_current = NULL;
      sr->sr_results = NULL;
    }
  }

  if (sr->sr_head)
    outgoing_query_all(orq);
  else if (sr->sr_use_naptr)
    outgoing_query_naptr(orq, sr->sr_tpn->tpn_host); /* NAPTR */
  else if (sr->sr_use_srv)
    outgoing_make_srv_query(orq);	/* SRV */
  else if (sr->sr_use_a_aaaa)
    outgoing_make_a_aaaa_query(orq);	/* A/AAAA */
  else
    return outgoing_resolving_error(orq, SIPDNS_503_ERROR);
  
  return 1;
}

/** Check if can we retry other destinations? */
static int
outgoing_other_destinations(nta_outgoing_t const *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;

  if (!sr)
    return 0;

  if (sr->sr_use_a_aaaa || sr->sr_use_srv || sr->sr_use_naptr) 
    return 1;

  if (sr->sr_results && sr->sr_results[1])
    return 1;

  if (sr->sr_head)
    return 1;

  return 0;
}

/** Resolve a request destination */
static int
outgoing_try_another(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;

  if (sr == NULL)
    return 0;

  *orq->orq_tpn = *sr->sr_tpn;
  orq->orq_try_tcp_instead = 0, orq->orq_try_udp_instead = 0;
  outgoing_reset_timer(orq);
  outgoing_queue(orq->orq_agent->sa_out.resolving, orq);

  return outgoing_resolve_next(orq);
}

/** Cancel resolver query */
static inline void outgoing_cancel_resolver(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  
  assert(orq->orq_resolver);

  if (sr->sr_query)    /* Cancel resolver query */
      sres_query_bind(sr->sr_query, NULL, NULL), sr->sr_query = NULL;
}

/** Destroy resolver */
static inline void outgoing_destroy_resolver(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;

  assert(orq->orq_resolver);

  if (sr->sr_query)    /* Cancel resolver query */
    sres_query_bind(sr->sr_query, NULL, NULL), sr->sr_query = NULL;

  su_free(orq->orq_agent->sa_home, sr);

  orq->orq_resolver = NULL;
}

/** Check if we are resolving. If not, return 503 response. */
static
int outgoing_resolving(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  
  assert(orq->orq_resolver);

  if (!sr->sr_query) {
    return outgoing_resolving_error(orq, SIPDNS_503_ERROR);
  } 
  else {
    outgoing_queue(orq->orq_agent->sa_out.resolving, orq);
    return 0;
  }
}

/** Return 503 response */
static 
int outgoing_resolving_error(nta_outgoing_t *orq, int status, char const *phrase) 
{
  orq->orq_resolved = 1;
  outgoing_reply(orq, status, phrase, 0);
  return -1;
}

/* Query SRV records (with the given tport). */
static
int outgoing_make_srv_query(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  su_home_t *home = msg_home(orq->orq_request);
  struct sipdns_query *sq;
  char const *host; 
  int i, hlen;
 
  sr->sr_use_srv = 0;

  host = sr->sr_tpn->tpn_host;
  hlen = strlen(host) + 1;

  for (i = 0; sr->sr_tports[i]; i++) {
    char const *prefix = sr->sr_tports[i]->prefix;
    int plen = strlen(prefix);

    sq = su_zalloc(home, (sizeof *sq) + plen + hlen);
    if (sq) {
      *sr->sr_tail = sq, sr->sr_tail = &sq->sq_next;
      sq->sq_domain = memcpy(sq + 1, prefix, plen);
      memcpy((char *)sq->sq_domain + plen, host, hlen);
      sq->sq_proto = sr->sr_tports[i]->name;
      sq->sq_type = sres_type_srv;
      sq->sq_priority = 1;
      sq->sq_weight = 1;
    }
  }

  outgoing_query_all(orq);

  return 0;
}

/* Query A/AAAA records.  */
static
int outgoing_make_a_aaaa_query(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  su_home_t *home = msg_home(orq->orq_request);
  tp_name_t *tpn = orq->orq_tpn;
  struct sipdns_query *sq;

  assert(sr);

  sr->sr_use_a_aaaa = 0;

  sq = su_zalloc(home, 2 * (sizeof *sq));
  if (!sq)
    return outgoing_resolving(orq);

  sq->sq_type = sr->sr_a_aaaa1;
  sq->sq_domain = tpn->tpn_host;
  sq->sq_priority = 1;

  /* Append */
  *sr->sr_tail = sq, sr->sr_tail = &sq->sq_next;

  outgoing_query_all(orq);

  return 0;
}


/** Start SRV/A/AAAA queries */
static
void outgoing_query_all(nta_outgoing_t *orq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  struct sipdns_query *sq = sr->sr_head;

  if (sq == NULL) {
    outgoing_resolving_error(orq, SIP_500_INTERNAL_SERVER_ERROR);
    return;
  }

  /* Remove from intermediate list */
  if (!(sr->sr_head = sq->sq_next))
    sr->sr_tail = &sr->sr_head;

  if (sq->sq_type == sres_type_srv)
    outgoing_query_srv(orq, sq);
  else if (sq->sq_type == sres_type_aaaa)
    outgoing_query_aaaa(orq, sq);
  else if (sq->sq_type == sres_type_a)
    outgoing_query_a(orq, sq);
  else
    outgoing_resolving_error(orq, SIP_500_INTERNAL_SERVER_ERROR);
}

/** Query NAPTR record. */
static
int outgoing_query_naptr(nta_outgoing_t *orq, char const *domain)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  sres_record_t **answers;

  sr->sr_use_naptr = 0;

  sr->sr_target = domain;

  answers = sres_cached_answers(orq->orq_agent->sa_resolver,
				sres_type_naptr, domain);

  SU_DEBUG_5(("nta: for \"%s\" query \"%s\" %s%s\n",
              orq->orq_tpn->tpn_host, domain, "NAPTR",
              answers ? " (cached)" : ""));

  if (answers) {
    outgoing_answer_naptr(orq, NULL, answers);
    return 0;
  }
  else {
    sr->sr_query = sres_query(orq->orq_agent->sa_resolver,
			      outgoing_answer_naptr, orq,
			      sres_type_naptr, domain);
    return outgoing_resolving(orq);
  }
}

/* Process NAPTR records */
static
void outgoing_answer_naptr(sres_context_t *orq,
			   sres_query_t *q,
			   sres_record_t *answers[])
{
  int i, j, order = -1, rlen;
  su_home_t *home = msg_home(orq->orq_request);
  nta_agent_t *agent = orq->orq_agent;
  struct sipdns_resolver *sr = orq->orq_resolver;
  tp_name_t tpn[1];
  struct sipdns_query *sq, *selected = NULL, **tail = &selected, **at;

  assert(sr);

  sr->sr_query = NULL;

  *tpn = *sr->sr_tpn;

  /* The NAPTR results are sorted first by Order then by Preference */
  sres_sort_answers(orq->orq_agent->sa_resolver, answers);

  for (i = 0; answers && answers[i]; i++) {
    sres_naptr_record_t const *na = answers[i]->sr_naptr;
    uint16_t type;

    if (na->na_record->r_status)
      continue;
    if (na->na_record->r_type != sres_type_naptr)
      continue;

    /* RFC 2915 p 4:
     * Order
     *    A 16-bit unsigned integer specifying the order in which the
     *    NAPTR records MUST be processed to ensure the correct ordering
     *    of rules. Low numbers are processed before high numbers, and
     *    once a NAPTR is found whose rule "matches" the target, the
     *    client MUST NOT consider any NAPTRs with a higher value for
     *    order (except as noted below for the Flags field).
     */
    if (order >= 0 && order != na->na_order)
      break;

    /* Check if NAPTR matches our target */
    if (strncasecmp(na->na_services, "SIP+", 4) && 
	strncasecmp(na->na_services, "SIPS+", 5))
      /* Not a SIP/SIPS service */
      continue;

    /* Use NAPTR results, don't try extra SRV/A/AAAA records */
    sr->sr_use_srv = 0, sr->sr_use_a_aaaa = 0;		
    
    /* Check if we have a transport mathing with service */
    for (j = 0; sr->sr_tports[j]; j++) {
      /*
       * Syntax of services is actually more complicated 
       * but comparing the values in the transport list 
       * match with those values that make any sense
       */
      if (strcasecmp(na->na_services, sr->sr_tports[j]->service) != 0)
	continue;

      tpn->tpn_proto = sr->sr_tports[j]->name;

      if (tport_primary_by_name(agent->sa_tports, tpn))
	break;
    }

    SU_DEBUG_5(("nta: %s IN NAPTR %u %u \"%s\" \"%s\" \"%s\" %s%s\n",
		na->na_record->r_name,
		na->na_order, na->na_prefer,
		na->na_flags, na->na_services,
		na->na_regexp, na->na_replace,
		!sr->sr_tports[j] ? " (not supported)" : ""));

    if (!sr->sr_tports[j])
      continue;

    /* OK, we found matching NAPTR */ 
    order = na->na_order;

    /*
     * The "S" flag means that the next lookup should be for SRV records
     * ... "A" means that the next lookup should be for either an A, AAAA,
     * or A6 record.
     */
    if (na->na_flags[0] == 's' || na->na_flags[0] == 'S')
      type = sres_type_srv; /* SRV */
    else if (na->na_flags[0] == 'a' || na->na_flags[0] == 'A')
      type = sr->sr_a_aaaa1; /* A / AAAA */
    else
      continue;

    rlen = strlen(na->na_replace) + 1;
    sq = su_zalloc(home, (sizeof *sq) + rlen);

    *tail = sq, tail = &sq->sq_next;    
    sq->sq_priority = na->na_prefer;
    sq->sq_weight = j;
    sq->sq_type = type;
    sq->sq_domain = memcpy(sq + 1, na->na_replace, rlen);
    sq->sq_proto = sr->sr_tports[j]->name;
  }

  sres_free_answers(orq->orq_agent->sa_resolver, answers);

  /* RFC2915: 
     Preference [...] specifies the order in which NAPTR
     records with equal "order" values SHOULD be processed, low
     numbers being processed before high numbers. */
  at = sr->sr_tail;
  while (selected) {
    sq = selected, selected = sq->sq_next;

    for (tail = at; *tail; tail = &(*tail)->sq_next) {
      if (sq->sq_priority < (*tail)->sq_priority)
	break;
      if (sq->sq_priority == (*tail)->sq_priority &&
	  sq->sq_weight < (*tail)->sq_weight)
	break;
    }
    /* Insert */
    sq->sq_next = *tail, *tail = sq;

    if (!sq->sq_next)		/* Last one */
      sr->sr_tail = &sq->sq_next;
  }

  outgoing_resolve_next(orq);
}

/* Query SRV records */
static
int outgoing_query_srv(nta_outgoing_t *orq, 
		       struct sipdns_query *sq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;

  sres_record_t **answers;

  sr->sr_target = sq->sq_domain;
  sr->sr_current = sq;

  answers = sres_cached_answers(orq->orq_agent->sa_resolver,
				sres_type_srv, sq->sq_domain);

  SU_DEBUG_5(("nta: for \"%s\" query \"%s\" %s%s\n",
              orq->orq_tpn->tpn_host, sq->sq_domain, "SRV",
              answers ? " (cached)" : ""));

  if (answers) {
    outgoing_answer_srv(orq, NULL, answers);
    return 0;
  }
  else {
    sr->sr_query = sres_query(orq->orq_agent->sa_resolver,
			      outgoing_answer_srv, orq,
			      sres_type_srv, sq->sq_domain);
    return outgoing_resolving(orq);
  }
}

/* Process SRV records */
static
void
outgoing_answer_srv(sres_context_t *orq, sres_query_t *q,
		    sres_record_t *answers[])
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  su_home_t *home = msg_home(orq->orq_request);
  struct sipdns_query *sq0, *sq, *selected = NULL, **tail = &selected, **at;
  int i, tlen;

  sr->sr_query = NULL;

  sq0 = sr->sr_current; 
  assert(sq0 && sq0->sq_type == sres_type_srv);
  assert(sq0->sq_domain); assert(sq0->sq_proto);

  /* Sort by priority, weight? */
  sres_sort_answers(orq->orq_agent->sa_resolver, answers);

  for (i = 0; answers && answers[i]; i++) {
    sres_srv_record_t const *srv = answers[i]->sr_srv;

    if (srv->srv_record->r_status /* There was an error */ ||
        srv->srv_record->r_type != sres_type_srv)
      continue;

    tlen = strlen(srv->srv_target) + 1;

    sq = su_zalloc(home, (sizeof *sq) + tlen);

    if (sq) {
      *tail = sq, tail = &sq->sq_next;

      sq->sq_type = sr->sr_a_aaaa1;
      sq->sq_proto = sq0->sq_proto;
      sq->sq_domain = memcpy(sq + 1, srv->srv_target, tlen);
      snprintf(sq->sq_port, sizeof(sq->sq_port), "%u", srv->srv_port);

      sq->sq_priority = srv->srv_priority;
      sq->sq_weight = srv->srv_weight;
    }
  }

  sres_free_answers(orq->orq_agent->sa_resolver, answers);

  at = &sr->sr_head;

  /* Insert sorted by priority, randomly select by weigth */
  while (selected) {
    unsigned long weight = 0;
    unsigned N = 0, priority = selected->sq_priority;

    /* Total weight of entries with same priority */
    for (sq = selected; sq && priority == sq->sq_priority; sq = sq->sq_next) {
      weight += sq->sq_weight;
      N ++;
    }

    tail = &selected;

    /* Select by weighted random. Entries with weight 0 are kept in order */
    if (N > 1 && weight > 0) {
      unsigned rand = su_randint(0,  weight - 1);

      while (weight > 0 && rand >= (*tail)->sq_weight) {
	rand -= (*tail)->sq_weight;
	tail = &(*tail)->sq_next;
      }
    }

    /* Remove selected */
    sq = *tail; *tail = sq->sq_next; assert(sq->sq_priority == priority);

    /* Append at *at */
    sq->sq_next = *at; *at = sq; at = &sq->sq_next; if (!*at) sr->sr_tail = at;

    SU_DEBUG_5(("nta: %s IN SRV %u %u  %s %s (%s)\n",
		sq0->sq_domain,
		sq->sq_priority, sq->sq_weight,
		sq->sq_port, sq->sq_domain, sq->sq_proto));
  }

  /* This is not needed anymore (?) */
  sr->sr_current = NULL; 
  sq0->sq_next = sr->sr_done; sr->sr_done = sq0; 

  outgoing_resolve_next(orq);
}

/* Query AAAA records */
static
int outgoing_query_aaaa(nta_outgoing_t *orq, struct sipdns_query *sq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  sres_record_t **answers;

  sr->sr_target = sq->sq_domain;
  sr->sr_current = sq;

  answers = sres_cached_answers(orq->orq_agent->sa_resolver,
				sres_type_aaaa, sq->sq_domain);

  SU_DEBUG_5(("nta: for \"%s\" query \"%s\" %s%s\n",
              orq->orq_tpn->tpn_host, sq->sq_domain, "AAAA", 
              answers ? " (cached)" : ""));

  if (answers) {
    outgoing_answer_aaaa(orq, NULL, answers);
    return 0;
  }

  sr->sr_query = sres_query(orq->orq_agent->sa_resolver,
			      outgoing_answer_aaaa, orq,
			      sres_type_aaaa, sq->sq_domain);

  return outgoing_resolving(orq);
}

/* Process AAAA records */
static
void outgoing_answer_aaaa(sres_context_t *orq, sres_query_t *q,
			  sres_record_t *answers[])
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  su_home_t *home = msg_home(orq->orq_request);
  struct sipdns_query *sq = sr->sr_current;

  int i, j, found;
  char *result, **results = NULL;

  assert(sq); assert(sq->sq_type == sres_type_aaaa);

  sr->sr_query = NULL;

  for (i = 0, found = 0; answers && answers[i]; i++) {
    sres_aaaa_record_t const *aaaa = answers[i]->sr_aaaa;
    if (aaaa->aaaa_record->r_status == 0 &&
        aaaa->aaaa_record->r_type == sres_type_aaaa)
      found++;
  }

  if (found > 1)
    results = su_zalloc(home, (found + 1) * (sizeof *results));
  else if (found)
    results = &result;

  for (i = j = 0; results && answers && answers[i]; i++) {
    char addr[SU_ADDRSIZE];
    sres_aaaa_record_t const *aaaa = answers[i]->sr_aaaa;

    if (aaaa->aaaa_record->r_status ||
        aaaa->aaaa_record->r_type != sres_type_aaaa)
      continue;			      /* There was an error */

    inet_ntop(AF_INET6, &aaaa->aaaa_addr, addr, sizeof(addr));

    if (j == 0)
      SU_DEBUG_5(("nta(%p): %s IN AAAA %s\n", orq, 
		  aaaa->aaaa_record->r_name, addr));
    else
      SU_DEBUG_5(("nta(%p):  AAAA %s\n", orq, addr));

    assert(j < found);
    results[j++] = su_strdup(home, addr);
  }

  sres_free_answers(orq->orq_agent->sa_resolver, answers);

  outgoing_query_results(orq, sq, results, found);
}

/* Query A records */
static
int outgoing_query_a(nta_outgoing_t *orq, struct sipdns_query *sq)
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  sres_record_t **answers;

  sr->sr_target = sq->sq_domain;
  sr->sr_current = sq;

  answers = sres_cached_answers(orq->orq_agent->sa_resolver,
				sres_type_a, sq->sq_domain);

  SU_DEBUG_5(("nta: for \"%s\" query \"%s\" %s%s\n",
	      orq->orq_tpn->tpn_host, sq->sq_domain, "A",
	      answers ? " (cached)" : ""));

  if (answers) {
    outgoing_answer_a(orq, NULL, answers);
    return 0;
  }

  sr->sr_query = sres_query(orq->orq_agent->sa_resolver,
			      outgoing_answer_a, orq,
			      sres_type_a, sq->sq_domain);

  return outgoing_resolving(orq);
}

/* Process A records */
static
void outgoing_answer_a(sres_context_t *orq, sres_query_t *q,
		       sres_record_t *answers[])
{
  struct sipdns_resolver *sr = orq->orq_resolver;
  su_home_t *home = msg_home(orq->orq_request);
  struct sipdns_query *sq = sr->sr_current;

  int i, j, found;
  char *result, **results = NULL;

  assert(sq); assert(sq->sq_type == sres_type_a);

  sr->sr_query = NULL;

  for (i = 0, found = 0; answers && answers[i]; i++) {
    sres_a_record_t const *a = answers[i]->sr_a;
    if (a->a_record->r_status == 0 &&
        a->a_record->r_type == sres_type_a)
      found++;
  }

  if (found > 1)
    results = su_zalloc(home, (found + 1) * (sizeof *results));
  else if (found)
    results = &result;

  for (i = j = 0; answers && answers[i]; i++) {
    char addr[SU_ADDRSIZE];
    sres_a_record_t const *a = answers[i]->sr_a;

    if (a->a_record->r_status ||
	a->a_record->r_type != sres_type_a)
      continue;			      /* There was an error */

    inet_ntop(AF_INET, &a->a_addr, addr, sizeof(addr));

    if (j == 0)
      SU_DEBUG_5(("nta: %s IN A %s\n", a->a_record->r_name, addr));
    else
      SU_DEBUG_5(("nta(%p):  A %s\n", orq, addr));

    assert(j < found);
    results[j++] = su_strdup(home, addr);
  }

  sres_free_answers(orq->orq_agent->sa_resolver, answers);

  outgoing_query_results(orq, sq, results, found);
}

/** Store A/AAAA query results */
static void
outgoing_query_results(nta_outgoing_t *orq,
		       struct sipdns_query *sq,
		       char *results[],
		       int rlen)
{
  struct sipdns_resolver *sr = orq->orq_resolver;

  if (sq->sq_type == sr->sr_a_aaaa1 &&
      sq->sq_type != sr->sr_a_aaaa2) {
    sq->sq_type = sr->sr_a_aaaa2;

    SU_DEBUG_7(("nta(%p): %s %s record still unresolved\n", orq,
		sq->sq_domain, sq->sq_type == sres_type_a ? "A" : "AAAA"));

    /*
     * Three possible policies: 
     * 1) try each host for AAAA/A, then A/AAAA
     * 2) try everything first for AAAA/A, then everything for A/AAAA
     * 3) try one SRV record results for AAAA/A, then for A/AAAA,
     *    then next SRV record 
     */

    /* We use now policy #1 */
    if (!(sq->sq_next = sr->sr_head))
      sr->sr_tail = &sq->sq_next;
    sr->sr_head = sq;
  }
  else {
    sq->sq_next = sr->sr_done, sr->sr_done = sq;
  }

  if (rlen > 1) 
    sr->sr_results = results;
  else
    sr->sr_current = NULL;

  if (rlen > 0) {
    orq->orq_resolved = 1;
    orq->orq_tpn->tpn_host = results[0];
    if (sq->sq_proto) orq->orq_tpn->tpn_proto = sq->sq_proto;
    if (sq->sq_port[0]) orq->orq_tpn->tpn_port = sq->sq_port;
    outgoing_prepare_send(orq);
  } else {
    outgoing_resolve_next(orq);
  }
}


#endif

/* ====================================================================== */
/* 10) Reliable responses */

static nta_prack_f nta_reliable_destroyed;

/**
 * Check that server transaction can be used to send reliable provisional
 * responses.
 */
static inline
int reliable_check(nta_incoming_t *irq)
{
  if (irq == NULL || irq->irq_status >= 200 || !irq->irq_agent)
    return 0;

  if (irq->irq_reliable && irq->irq_reliable->rel_status >= 200)
    return 0;

  /* RSeq is initialized to nonzero when request requires/supports 100rel */
  if (irq->irq_rseq == 0)
    return 0;

  if (irq->irq_rseq == 0xffffffffU) /* already sent >> 2**31 responses */
    return 0;

  return 1;
}

nta_reliable_t *nta_reliable_treply(nta_incoming_t *irq,
				    nta_prack_f *callback,
				    nta_reliable_magic_t *rmagic,
				    int status, char const *phrase,
				    tag_type_t tag,
				    tag_value_t value, ...)
{
  ta_list ta;
  msg_t *msg;
  sip_t *sip;
  nta_reliable_t *retval = NULL;

  if (!reliable_check(irq) || (status <= 100 || status >= 200))
    return NULL;

  msg = nta_msg_create(irq->irq_agent, 0);
  sip = sip_object(msg);

  if (!sip)
    return NULL;

  ta_start(ta, tag, value);

  if (nta_msg_response_complete(msg, irq, status, phrase) < 0)
    msg_destroy(msg);
  else if (sip_add_tl(msg, sip, ta_tags(ta)) < 0)
    msg_destroy(msg);
  else if (sip_message_complete(msg) < 0)
    msg_destroy(msg);
  else if (!(retval = reliable_mreply(irq, callback, rmagic, msg, sip)))
    msg_destroy(msg);

  ta_end(ta);

  return retval;
}

nta_reliable_t *nta_reliable_mreply(nta_incoming_t *irq,
				    nta_prack_f *callback,
				    nta_reliable_magic_t *rmagic,
				    msg_t *msg)
{
  sip_t *sip = sip_object(msg);

  if (!reliable_check(irq)) {
    msg_destroy(msg);
    return NULL;
  }

  if (sip == NULL || !sip->sip_status || sip->sip_status->st_status <= 100) {
    msg_destroy(msg);
    return NULL;
  }

  if (sip->sip_status->st_status >= 200) {
    incoming_final_failed(irq, msg);
    return NULL;
  }

  return reliable_mreply(irq, callback, rmagic, msg, sip);
}

static
nta_reliable_t *reliable_mreply(nta_incoming_t *irq,
				nta_prack_f *callback,
				nta_reliable_magic_t *rmagic,
				msg_t *msg,
				sip_t *sip)
{
  nta_reliable_t *rel;
  nta_agent_t *agent;

  agent = irq->irq_agent;

  if (callback == NULL)
    callback = nta_reliable_destroyed;

  rel = su_zalloc(agent->sa_home, sizeof(*rel));
  if (rel) {
    rel->rel_irq = irq;
    rel->rel_callback = callback;
    rel->rel_magic = rmagic;
    rel->rel_unsent = msg;
    rel->rel_status = sip->sip_status->st_status;
    rel->rel_precious = sip->sip_payload != NULL;
    rel->rel_next = irq->irq_reliable;

    /*
     * If there already is a un-pr-acknowledged response, queue this one
     * until at least one response is pr-acknowledged.
     */
    if (irq->irq_reliable &&
	(irq->irq_reliable->rel_next == NULL ||
	 irq->irq_reliable->rel_rseq == 0)) {
      rel->rel_response = msg_ref_create(msg);
      return irq->irq_reliable = rel;
    }

    rel->rel_response = msg_ref_create(msg);

    if (reliable_send(irq, rel, msg, sip) < 0) {
      msg_destroy(rel->rel_response), rel->rel_response = NULL;
      su_free(agent->sa_home, rel);
      return NULL;
    }

    irq->irq_reliable = rel;

    return callback ? rel : (nta_reliable_t *)-1;
  }

  msg_destroy(msg);
  return NULL;
}

static
int reliable_send(nta_incoming_t *irq,
		  nta_reliable_t *rel,
		  msg_t *msg,
		  sip_t *sip)
{
  nta_agent_t *sa = irq->irq_agent;
  su_home_t *home = msg_home(msg);
  sip_rseq_t rseq[1];
  sip_rseq_init(rseq);

  if (sip->sip_require)
    msg_params_replace(home, (sip_param_t **)&sip->sip_require, "100rel");
  else
    sip_add_make(msg, sip, sip_require_class, "100rel");

  rel->rel_rseq = rseq->rs_response = irq->irq_rseq;
  sip_add_dup(msg, sip, (sip_header_t *)rseq);

  if (!sip->sip_rseq) {
    msg_destroy(msg);
    return -1;
  }
  if (incoming_reply(irq, msg, sip) < 0)
    return -1;

  irq->irq_rseq++;

  if (irq->irq_queue == sa->sa_in.preliminary)
    /* Make sure we are moved to the tail */
    incoming_remove(irq);

  incoming_queue(sa->sa_in.preliminary, irq); /* P1 */
  incoming_set_timer(irq, sa->sa_t1); /* P2 */
  
  return 0;
}

/** Process final response */
static
int reliable_final(nta_incoming_t *irq, msg_t *msg, sip_t *sip)
{
  nta_reliable_t *r;

  /*
   * We delay sending final response if it's 2XX and
   * an unpracked reliable response contains session description
   */
  /* Get last unpracked response from queue */
  if (sip->sip_status->st_status < 300)
    for (r = irq->irq_reliable; r; r = r->rel_next)
      if (r->rel_unsent && r->rel_precious) {
	/* Delay sending 2XX */
	reliable_mreply(irq, NULL, NULL, msg, sip);
	return 0;
      }

  /* Flush unsent responses. */
  irq->irq_in_callback = 1;
  reliable_flush(irq);
  irq->irq_in_callback = 0;

  if (irq->irq_completed && irq->irq_destroyed) {
    incoming_free(irq);
    msg_destroy(msg);
    return 0;
  }

  return 1;
}

/** Get latest reliably sent response */
static
msg_t *reliable_response(nta_incoming_t *irq)
{
  nta_reliable_t *r, *rel;

  /* Get last unpracked response from queue */
  for (rel = NULL, r = irq->irq_reliable; r; r = r->rel_next)
    if (!r->rel_pracked)
      rel = r;

  assert(rel);

  return rel->rel_unsent;
}

/** Process incoming PRACK with matching RAck field */
static
int reliable_recv(nta_incoming_t *irq, msg_t *msg, sip_t *sip, tport_t *tp)
{
  sip_rack_t *rack = sip->sip_rack;
  nta_reliable_t *rel;
  nta_incoming_t *pr_irq;
  int status;

  for (rel = irq->irq_reliable; rel; rel = rel->rel_next)
    if (rel->rel_pracked)
      return -1;
    else if (rel->rel_rseq == rack->ra_response)
      break;

  if (!rel)
    return -1;			/* Process normally */

  rel->rel_pracked = 1;
  rel->rel_unsent = NULL;

  pr_irq = incoming_create(irq->irq_agent, msg, sip, tp, irq->irq_tag);
  if (!pr_irq) {
    nta_msg_treply(irq->irq_agent, msg,
		   SIP_500_INTERNAL_SERVER_ERROR, 
		   NTATAG_TPORT(tp),
		   TAG_END());
    return 0;
  }

  msg_ref_destroy(rel->rel_response), rel->rel_response = NULL;

  if (irq->irq_status < 200) {
    incoming_queue(irq->irq_agent->sa_in.proceeding, irq); /* Reset P1 */
    incoming_reset_timer(irq);	/* Reset P2 */
  }

  irq->irq_in_callback = pr_irq->irq_in_callback = 1;
  status = rel->rel_callback(rel->rel_magic, rel, pr_irq, sip); rel = NULL;
  irq->irq_in_callback = pr_irq->irq_in_callback = 0;

  if (pr_irq->irq_destroyed && pr_irq->irq_terminated) {
    incoming_free(pr_irq);
  }
  else if (status != 0) {
    if (status < 200 || status > 299) {
      SU_DEBUG_3(("nta_reliable(): invalid status %03d from callback\n",
		  status));
      status = 200;
    }
    nta_incoming_treply(pr_irq, status, "OK", TAG_END());
    nta_incoming_destroy(pr_irq);
  } 

  /* If there are queued unsent reliable responses, send them all. */
  while (irq->irq_reliable && irq->irq_reliable->rel_rseq == 0) {
    nta_reliable_t *r;

    for (r = irq->irq_reliable; r; r = r->rel_next)
      if (r->rel_rseq == 0)
	rel = r;

    msg = rel->rel_unsent, sip = sip_object(msg);

    if (sip->sip_status->st_status < 200) {
      if (reliable_send(irq, rel, msg_ref_create(msg), sip) < 0) {
	msg_ref_destroy(msg);
	assert(!"send reliable response");
      }
    } else {
      /*
       * XXX
       * Final response should be delayed until a reliable provisional
       * response has been pracked
       */
      rel->rel_rseq = (uint32_t)-1;
      if (incoming_reply(irq, msg_ref_create(msg), sip) < 0) {
	msg_ref_destroy(msg);
	assert(!"send delayed final response");
      }
    }
  }

  return 0;
}

/** Flush unacknowledged and unsent reliable responses */
void reliable_flush(nta_incoming_t *irq)
{
  nta_reliable_t *r, *rel;

  do {
    for (r = irq->irq_reliable, rel = NULL; r; r = r->rel_next)
      if (r->rel_unsent)
	rel = r;

    if (rel) {
      rel->rel_pracked = 1;
      rel->rel_unsent = NULL;
      msg_ref_destroy(rel->rel_response), rel->rel_response = NULL;
      rel->rel_callback(rel->rel_magic, rel, NULL, NULL);
    }
  } while (rel);
}

void reliable_timeout(nta_incoming_t *irq, int timeout)
{
  if (timeout)
    SU_DEBUG_5(("nta: response timeout with %u\n", irq->irq_status));

  irq->irq_in_callback = 1;

  reliable_flush(irq);

  if (irq->irq_callback)
    irq->irq_callback(irq->irq_magic, irq, NULL);

  irq->irq_in_callback = 0;

  if (irq->irq_completed && irq->irq_destroyed)
    incoming_free(irq), irq = NULL;

  if (timeout && irq && irq->irq_status < 200)
    nta_incoming_treply(irq, 503, "Reliable Response Time-Out", TAG_END());
}

#if 0 /* Not needed, yet. */
/** Use this callback when normal leg callback is supposed to
 *  process incoming PRACK requests
 */
int nta_reliable_leg_prack(nta_reliable_magic_t *magic,
			   nta_reliable_t *rel, 
			   nta_incoming_t *irq, 
			   sip_t const *sip)
{
  nta_agent_t *agent;
  nta_leg_t *leg;
  char const *method_name;
  url_t url[1];
  int retval;

  if (irq == NULL || sip == NULL || rel == NULL || 
      sip_object(irq->irq_request) != sip)
    return 500;

  agent = irq->irq_agent;
  method_name = sip->sip_request->rq_method_name;
  *url = *sip->sip_request->rq_url; url->url_params = NULL;
  agent_aliases(agent, url, irq->irq_tport); /* canonize urls */

  if ((leg = leg_find(irq->irq_agent, 
		      method_name, url, 
		      sip->sip_call_id,
		      sip->sip_from->a_tag, sip->sip_from->a_url, 
		      sip->sip_to->a_tag, sip->sip_to->a_url))) {
    /* Use existing dialog */
    SU_DEBUG_5(("nta: %s (%u) %s\n",
		method_name, sip->sip_cseq->cs_seq, 
		"PRACK processed by default callback, too"));
    retval = leg->leg_callback(leg->leg_magic, leg, irq, sip);
  } else {
    retval = 500;
  }

  nta_reliable_destroy(rel);

  return retval;
}
#endif

/** Destroy a reliable response.
 *
 * The function nta_reliable_destroy() marks a reliable response object for
 * destroyal, and frees it if possible.
 */
void nta_reliable_destroy(nta_reliable_t *rel)
{
  if (!rel)
    return;

  if (rel->rel_callback == nta_reliable_destroyed)
    SU_DEBUG_1(("%s(%p): already destroyed\n", __func__, rel));

  rel->rel_callback = nta_reliable_destroyed;

  if (rel->rel_response)
    return;

  nta_reliable_destroyed(NULL, rel, NULL, NULL);
}

/** Free and unallocate the nta_reliable_t structure. */
static
int nta_reliable_destroyed(nta_reliable_magic_t *rmagic,
			   nta_reliable_t *rel,
			   nta_incoming_t *prack,
			   sip_t const *sip)
{
  nta_reliable_t **prev;

  assert(rel); assert(rel->rel_irq);

  for (prev = &rel->rel_irq->irq_reliable; *prev; prev = &(*prev)->rel_next)
    if (*prev == rel)
      break;

  if (!*prev) {
    assert(*prev);
    SU_DEBUG_1(("%s(%p): not linked\n", __func__, rel));
    return 200;
  }

  *prev = rel->rel_next;

  su_free(rel->rel_irq->irq_agent->sa_home, rel);

  return 200;
}

/** Validate a reliable response. */
int outgoing_recv_reliable(nta_outgoing_t *orq,
			   msg_t *msg,
			   sip_t *sip)
{
  short status = sip->sip_status->st_status;
  char const *phrase = sip->sip_status->st_phrase;
  uint32_t rseq = sip->sip_rseq->rs_response;

  SU_DEBUG_7(("nta: %03u %s is reliably received with RSeq: %u\n",
	      status, phrase, rseq));

  /* Cannot handle reliable responses unless we have a full dialog */
  if (orq->orq_rseq == 0 && !orq->orq_to->a_tag) {
    SU_DEBUG_5(("nta: %03u %s with initial RSeq: %u outside dialog\n",
		status, phrase, rseq));
    return 0;
  }

  if (rseq <= orq->orq_rseq) {
    SU_DEBUG_3(("nta: %03u %s already received (RSeq: %u, expecting %u)\n",
		status, phrase, rseq, orq->orq_rseq + 1));
    return -1;
  }

  if (orq->orq_rseq && orq->orq_rseq + 1 != rseq) {
    SU_DEBUG_3(("nta: %03d %s is not expected (RSeq: %u, expecting %u)\n",
		status, sip->sip_status->st_phrase,
		rseq, orq->orq_rseq + 1));
    return -1;
  }

  return 0;
}

/** Create a tagged fork of outgoing request. */
nta_outgoing_t *nta_outgoing_tagged(nta_outgoing_t *orq,
				    nta_response_f *callback,
				    nta_outgoing_magic_t *magic,
				    sip_param_t to_tag,
				    sip_rseq_t const *rseq)
{
  nta_agent_t *agent;
  su_home_t *home;
  nta_outgoing_t *tagged;
  sip_to_t *to;

  if (orq == NULL || to_tag == NULL)
    return NULL;
  if (orq->orq_to->a_tag) {
    SU_DEBUG_1(("%s: transaction %p already in dialog\n", __func__, orq));
    return NULL;
  }

  assert(orq->orq_agent); assert(orq->orq_request);

  agent = orq->orq_agent;
  tagged = su_alloc(agent->sa_home, sizeof(*tagged));
  home = msg_home((msg_t *)orq->orq_request);

  *tagged = *orq;
  tagged->orq_callback = callback;
  tagged->orq_magic = magic;

  tagged->orq_prev = NULL, tagged->orq_next = NULL, tagged->orq_queue = NULL;
  tagged->orq_rprev = NULL, tagged->orq_rnext = NULL;

#if HAVE_SIGCOMP
  if (tagged->orq_cc)
    sigcomp_compartment_ref(tagged->orq_cc);
#endif

  sip_to_tag(home, to = sip_to_copy(home, orq->orq_to), to_tag);

  tagged->orq_to 	   = to;
  tagged->orq_tport        = tport_incref(orq->orq_tport);
  tagged->orq_request      = (msg_t *)msg_ref_create(orq->orq_request);
  tagged->orq_response     = NULL;
  tagged->orq_cancel       = NULL;

  tagged->orq_pending = tport_pend(orq->orq_tport, 
				   orq->orq_request, 
				   outgoing_tport_error, 
				   tagged);
  if (tagged->orq_pending < 0)
    tagged->orq_pending = 0;

  tagged->orq_rseq = 0;

  outgoing_queue(orq->orq_queue, tagged);
  outgoing_insert(agent, tagged);

  return tagged;
}

/**PRACK a provisional response.
 *
 * The function nta_outgoing_prack() creates and sends a PRACK request used
 * to acknowledge a provisional response. 
 *
 * The request is sent using the route of the original request @a orq.
 *
 * When NTA receives response to the prack request, it invokes the @a
 * callback function.
 *
 * @param leg         dialog object
 * @param oorq        original transaction request
 * @param callback    callback function (may be @c NULL)
 * @param magic       application context pointer
 * @param route_url   optional URL used to route transaction requests
 * @param resp        response message to be acknowledged
 * @param tag,value,... optional
 *
 * @return
 * If successful, the function nta_outgoing_prack() returns a pointer
 * to newly created client transaction object for PRACK request, NULL
 * otherwise.
 *
 * @sa
 * nta_outgoing_tcreate(), nta_outgoing_tcancel(), nta_outgoing_destroy().
 */
nta_outgoing_t *nta_outgoing_prack(nta_leg_t *leg,
				   nta_outgoing_t *oorq,
				   nta_response_f *callback,
				   nta_outgoing_magic_t *magic,
				   url_string_t const *route_url,
				   sip_t const *resp,
				   tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  msg_t *msg;
  su_home_t *home;
  sip_t *sip;
  sip_route_t *route = NULL;
  nta_outgoing_t *orq = NULL;
  sip_rack_t rack[1];

  if (!leg || !oorq || !resp || !resp->sip_status) {
    SU_DEBUG_1(("%s: invalid arguments\n", __func__));
    return NULL;
  }

  if (resp->sip_status->st_status <= 100 ||
      resp->sip_status->st_status >= 200) {
    SU_DEBUG_1(("%s: %u response cannot be PRACKed\n",
		__func__, resp->sip_status->st_status));
    return NULL;
  }

  if (!resp->sip_rseq) {
    SU_DEBUG_1(("%s: %u response missing RSeq\n",
		__func__, resp->sip_status->st_status));
    return NULL;
  }

  if (resp->sip_rseq->rs_response <= oorq->orq_rseq) {
    SU_DEBUG_1(("%s: %u response RSeq does not match received RSeq\n",
		__func__, resp->sip_status->st_status));
    return NULL;
  }
  if (!oorq->orq_must_100rel &&
      !sip_has_feature(resp->sip_require, "100rel")) {
    SU_DEBUG_1(("%s: %u response does not require 100rel\n",
		__func__, resp->sip_status->st_status));
    return NULL;
  }

  if (!resp->sip_to->a_tag) {
    SU_DEBUG_1(("%s: %u response has no To tag\n",
		__func__, resp->sip_status->st_status));
    return NULL;
  }
  if (str0casecmp(resp->sip_to->a_tag, leg->leg_remote->a_tag) ||
      str0casecmp(resp->sip_to->a_tag, oorq->orq_to->a_tag)) {
    SU_DEBUG_1(("%s: %u response To tag does not agree with dialog tag\n",
		__func__, resp->sip_status->st_status));
    return NULL;
  }

  msg = nta_msg_create(leg->leg_agent, 0);
  sip = sip_object(msg); home = msg_home(msg);

  if (!sip)
    return NULL;

  if (!leg->leg_route) {
    sip_route_t r0[1];

    sip_route_init(r0);

    /* Insert contact */
    if (resp->sip_contact) {
      *r0->r_url = *resp->sip_contact->m_url;
      route = sip_route_dup(home, r0);
    }

    /* Reverse record route */
    if (resp->sip_record_route) {
      sip_route_t *r, *r_next;
      for (r = sip_route_dup(home, resp->sip_record_route); r; r = r_next) {
	r_next = r->r_next, r->r_next = route, route = r;
      }
    }
  }

  sip_rack_init(rack);
  rack->ra_response    = resp->sip_rseq->rs_response;
  rack->ra_cseq        = resp->sip_cseq->cs_seq;
  rack->ra_method      = resp->sip_cseq->cs_method;
  rack->ra_method_name = resp->sip_cseq->cs_method_name;

  ta_start(ta, tag, value);

  if (sip_add_tl(msg, sip,
		 SIPTAG_RACK(rack),
		 SIPTAG_TO(resp->sip_to),
		 ta_tags(ta)) < 0)
    ;
  else if (route && sip_add_dup(msg, sip, (sip_header_t *)route) < 0)
    ;
  else if (nta_msg_request_complete(msg, leg,
				    SIP_METHOD_PRACK,
				    (url_string_t *)oorq->orq_url) < 0)
    ;
  else
    orq = outgoing_create(leg->leg_agent, callback, magic,
			  route_url, NULL, msg, ta_tags(ta));

  ta_end(ta);

  if (!orq)
    msg_destroy(msg);
  else
    oorq->orq_rseq = rack->ra_response;

  return orq;
}

/* ------------------------------------------------------------------------ */
/* 9) Transport handling */

#include <nta_tport.h>

static inline tport_t *
nta_transport_(nta_agent_t *agent,
	       nta_incoming_t *irq,
	       msg_t *msg)
{
  if (irq)
    return irq->irq_tport;
  else if (agent && msg)
    return tport_delivered_by(agent->sa_tports, msg);

  errno = EINVAL;
  return NULL;
}


tport_t *
nta_incoming_transport(nta_agent_t *agent,
		       nta_incoming_t *irq,
		       msg_t *msg)
{
  return tport_incref(nta_transport_(agent, irq, msg));
}


#if HAVE_SIGCOMP
struct sigcomp_compartment *
nta_incoming_compartment(nta_incoming_t *irq)
{
  return irq ? sigcomp_compartment_ref(irq->irq_cc) : NULL;
}


struct sigcomp_compartment *
nta_outgoing_compartment(nta_outgoing_t *orq)
{
  return orq ? sigcomp_compartment_ref(orq->orq_cc) : NULL;
}

void
nta_compartment_decref(struct sigcomp_compartment **pcc)
{
  if (pcc && *pcc) sigcomp_compartment_unref(*pcc), *pcc = NULL;
}

static
struct sigcomp_compartment *
agent_sigcomp_compartment(nta_agent_t *sa, 
			  tport_t *tp,
			  tp_name_t const *tpn)
{
  char name[256];
  int namesize;

  namesize = snprintf(name, sizeof name, "SIP:%s:%s",
		      tpn->tpn_host, tpn->tpn_port);

  if (namesize <= 0 || namesize >= sizeof name)
    return NULL;

  return sigcomp_compartment_access(sa->sa_state_handler, 0, 
				    name, namesize, NULL, 0);
}

static
struct sigcomp_compartment *
agent_sigcomp_compartment_ref(nta_agent_t *sa, 
			      tport_t *tp,
			      tp_name_t const *tpn,
			      int create_if_needed)
{
  struct sigcomp_compartment *cc;
  char name[256];
  int namesize;

  namesize = snprintf(name, sizeof name, "SIP:%s:%s",
		      tpn->tpn_host, tpn->tpn_port);

  if (namesize <= 0 || namesize >= sizeof name)
    return NULL;

  cc = sigcomp_compartment_access(sa->sa_state_handler, 0, 
				  name, namesize, NULL, 0);
  if (cc || !create_if_needed) 
    return sigcomp_compartment_ref(cc);

  cc = sigcomp_compartment_create(sa->sa_algorithm, sa->sa_state_handler, 0, 
				  name, namesize, NULL, 0);
  if (cc)
    agent_sigcomp_options(sa, cc);

  return cc;
}

/** Accept/reject early SigComp message */
static
int agent_sigcomp_accept(nta_agent_t *sa, tport_t *tp, msg_t *msg)
{
  struct sigcomp_compartment *cc = NULL;

  cc = agent_sigcomp_compartment(sa, tp, tport_name(tp));

  if (cc)
    tport_sigcomp_assign(tp, cc);

  return tport_sigcomp_accept(tp, cc, msg);
}

/** Set SigComp options.
 *
 * This is a callback invoked by tport whenever it has created a new
 * compartment.
 */
static int agent_sigcomp_options(nta_agent_t *agent, 
				 struct sigcomp_compartment *cc)
{
  char const * const * l = agent->sa_sigcomp_option_list;

  if (l) {
    for (;*l;l++)
      sigcomp_compartment_option(cc, *l);
    return 0;
  } 
  else {
    return sigcomp_compartment_option(cc, "sip");
  }
}

#else

struct sigcomp_compartment *
nta_incoming_compartment(nta_incoming_t *irq)
{
  return NULL;
}


struct sigcomp_compartment *
nta_outgoing_compartment(nta_outgoing_t *orq)
{
  return NULL;
}

void
nta_compartment_decref(struct sigcomp_compartment **pcc)
{
  if (pcc) *pcc = NULL;
}

#endif
