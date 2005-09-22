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

/**@internal
 * @CFILE nta_test.c
 *
 * Test functions for NTA.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Aug 21 15:18:26 2001 ppessi
 * $Date: 2005/09/19 11:12:10 $
 */

#include "config.h"

const char _nta_test_c_rcs_id[] =
"$Id: nta_test.c,v 1.6 2005/09/19 11:12:10 kaiv Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>

typedef struct agent_t agent_t;

#define SU_ROOT_MAGIC_T      agent_t

#include <su_wait.h>

#define NTA_AGENT_MAGIC_T    agent_t
#define NTA_LEG_MAGIC_T      agent_t
#define NTA_OUTGOING_MAGIC_T agent_t
#define NTA_INCOMING_MAGIC_T agent_t
#define NTA_RELIABLE_MAGIC_T agent_t

#include "nta.h"
#include "nta_internal.h"
#include <sip_header.h>
#include <sip_tag.h>
#include <sip_status.h>
#include <tport.h>
#include <htable.h>
#include <sresolv.h>
#include <su_log.h>

#include "string0.h"

extern su_log_t nta_log[];
extern su_log_t tport_log[];

int tstflags = 0;
#define TSTFLAGS tstflags

#include <tstdef.h>

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
#define __func__ name
#endif

struct sigcomp_compartment;

char const name[] = "nta_test";

struct agent_t {
  su_home_t       ag_home[1];
  int             ag_flags;
  su_root_t      *ag_root;
  msg_mclass_t   *ag_mclass;
  nta_agent_t    *ag_agent;

  url_string_t   *ag_obp;	/**< Outbound proxy. */

  nta_leg_t      *ag_server_leg; /**< Leg for sip:%@% */
  nta_leg_t      *ag_default_leg; /**< Leg for rest */

  unsigned        ag_drop;

  nta_outgoing_t *ag_orq;
  int             ag_status;

  char const     *ag_comp;
  struct sigcomp_compartment *ag_client_compartment;

  /* Server side */
  int             ag_response;	/**< What we answer by default */
  nta_incoming_t *ag_irq;

  struct sigcomp_compartment *ag_server_compartment;

  char const     *ag_m;

  sip_contact_t const *ag_contact;
  sip_from_t     *ag_alice;
  sip_to_t       *ag_bob;

  sip_contact_t  *ag_m_alice;
  sip_contact_t  *ag_m_bob;
  sip_contact_t  *ag_aliases;

  nta_leg_t      *ag_alice_leg;
  nta_leg_t      *ag_bob_leg;

  msg_t          *ag_request;

  nta_leg_t      *ag_expect_leg;
  nta_leg_t      *ag_latest_leg;
  nta_leg_t      *ag_call_leg;
  nta_leg_t      *ag_tag_remote; /**< If this is set, outgoing_callback()
				  *   tags it with the tag from remote.
				  */
  int             ag_tag_status; /**< Which response established dialog */
  sip_param_t     ag_call_tag;	 /**< Tag used to establish dialog */

  nta_reliable_t *ag_reliable;

  sip_via_t      *ag_out_via;	/**< Outgoing via */
  sip_via_t      *ag_in_via;	/**< Incoming via */

  sip_content_type_t *ag_content_type;
  sip_payload_t  *ag_payload;

  /* Dummy servers */
  char const     *ag_sink_port;
  int             ag_sink_socket;
  int             ag_down_socket;
};

static int test_init(agent_t *ag, char const *resolv_conf);
static int test_deinit(agent_t *ag);
static int test_routing(agent_t *ag);
static int test_tports(agent_t *ag);
static int test_resolv(agent_t *ag, char const *resolv_conf);
static int test_dialog(agent_t *ag);
static int test_call(agent_t *ag);
static int test_prack(agent_t *ag);
static int test_fix_467(agent_t *ag);
static int test_nta(agent_t *ag);
static int test_api_errors(void);
static int test_dialog_matching(void);

int agent_callback(agent_t *ag,
		   nta_agent_t *nta,
		   msg_t *msg,
		   sip_t *sip)
{
  if (tstflags & tst_verbatim) {
    if (sip->sip_request) {
      printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	     name, __func__, sip->sip_request->rq_method_name, 
	     URL_PRINT_ARGS(sip->sip_request->rq_url),
	     sip->sip_request->rq_version);
    }
    else {
      printf("%s: %s: %s %03d %s\n", name, __func__, 
	     sip->sip_status->st_version, 
	     sip->sip_status->st_status, 
	     sip->sip_status->st_phrase);
    }
  }

  nta_msg_discard(nta, msg);
  return 0;
}

static
void leg_match(agent_t *ag, nta_leg_t *leg, int always, char const *func)
{
  char const *match = "unknown leg";

  if (!always && (tstflags & tst_verbatim) != tst_verbatim)
    return;

  if (leg == ag->ag_default_leg)
    match = "ag_default_leg";
  else if (leg == ag->ag_server_leg) 
    match = "ag_server_leg";
  else if (leg == ag->ag_alice_leg)
    match = "ag_alice_leg";
  else if (leg == ag->ag_bob_leg)
    match = "ag_bob_leg";

  printf("%s: %s: %smatched with %s\n", name, func, 
	 always ? "mis" : "", match);
}

static
void leg_zap(agent_t *ag, nta_leg_t *leg)
{
  if (leg == ag->ag_default_leg)
    ag->ag_default_leg = NULL;
  else if (leg == ag->ag_server_leg) 
    ag->ag_server_leg = NULL;
  else if (leg == ag->ag_alice_leg)
    ag->ag_alice_leg = NULL;
  else if (leg == ag->ag_bob_leg)
    ag->ag_bob_leg = NULL;
  else 
     printf("%s:%u: %s: did not exist\n", 
	    __FILE__, __LINE__, __func__);

  nta_leg_destroy(leg);
}

int leg_callback_200(agent_t *ag,
		     nta_leg_t *leg,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  BEGIN();

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  TEST_1(sip->sip_content_length);
  TEST_1(sip->sip_via);
  TEST_1(sip->sip_from && sip->sip_from->a_tag);

  if (ag->ag_in_via == NULL)
    ag->ag_in_via = sip_via_dup(ag->ag_home, sip->sip_via);

  if (ag->ag_request == NULL)
    ag->ag_request = nta_incoming_getrequest(irq);

  ag->ag_latest_leg = leg;

  if (ag->ag_expect_leg && leg != ag->ag_expect_leg) {
    leg_match(ag, leg, 1, __func__);
    return 500;
  }
  leg_match(ag, leg, 0, __func__);

  if (sip->sip_request->rq_method == sip_method_bye) {
    leg_zap(ag, leg);
  }

  return 200;

  END();
}

int leg_callback_500(agent_t *ag,
		     nta_leg_t *leg,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  return 500;
}

int new_leg_callback_200(agent_t *ag,
			 nta_leg_t *leg,
			 nta_incoming_t *irq,
			 sip_t const *sip)
{
  BEGIN();

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  TEST_1(sip->sip_content_length);
  TEST_1(sip->sip_via);
  TEST_1(sip->sip_from && sip->sip_from->a_tag);

  ag->ag_latest_leg = leg;

  if (ag->ag_expect_leg && leg != ag->ag_expect_leg) {
    leg_match(ag, leg, 1, __func__);
    return 500;
  }
  leg_match(ag, leg, 0, __func__);

  ag->ag_bob_leg = nta_leg_tcreate(ag->ag_agent,
				   leg_callback_200,
				   ag,
				   URLTAG_URL(sip->sip_request->rq_url),
				   SIPTAG_CALL_ID(sip->sip_call_id),
				   SIPTAG_FROM(sip->sip_to),
				   SIPTAG_TO(sip->sip_from),
				   TAG_END());
  TEST_1(ag->ag_bob_leg);
  TEST(nta_leg_tag(ag->ag_bob_leg, NULL), 0);
  TEST_1(nta_leg_get_tag(ag->ag_bob_leg));
  TEST(nta_incoming_tag(irq, nta_leg_get_tag(ag->ag_bob_leg)), 0);

  return 200;

  END();
}


int outgoing_callback(agent_t *ag,
		      nta_outgoing_t *orq,
		      sip_t const *sip)
{
  BEGIN();

  int status = sip->sip_status->st_status;

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s %03d %s\n", name, __func__, 
	   sip->sip_status->st_version, 
	   sip->sip_status->st_status, 
	   sip->sip_status->st_phrase);
  }

  TEST(orq, ag->ag_orq);

  ag->ag_status = status;

  if (status < 200)
    return 0;

  if (ag->ag_comp) {
    nta_compartment_decref(&ag->ag_client_compartment);
    ag->ag_client_compartment = nta_outgoing_compartment(orq);
  }

  if (ag->ag_out_via == NULL)
    ag->ag_out_via = sip_via_dup(ag->ag_home, sip->sip_via);

  if (ag->ag_tag_remote) {
    TEST(nta_leg_rtag(ag->ag_tag_remote, sip->sip_to->a_tag), 0);
    ag->ag_tag_remote = NULL;
  }

  TEST_1(sip->sip_to && sip->sip_to->a_tag);

  nta_outgoing_destroy(orq);
  ag->ag_orq = NULL;
  return 0;

  END();
}


/* */
int outgoing_callback_with_api_test(agent_t *ag,
				    nta_outgoing_t *orq,
				    sip_t const *sip)
{
  msg_t *msg;
  int status;

  BEGIN();

  status = sip->sip_status->st_status;

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s %03d %s\n", name, __func__, 
	   sip->sip_status->st_version, 
	   sip->sip_status->st_status, 
	   sip->sip_status->st_phrase);
  }

  ag->ag_status = status;

  if (status < 200)
    return 0;

  if (ag->ag_out_via == NULL)
    ag->ag_out_via = sip_via_dup(ag->ag_home, sip->sip_via);

  if (ag->ag_tag_remote) {
    TEST(nta_leg_rtag(ag->ag_tag_remote, sip->sip_to->a_tag), 0);
    ag->ag_tag_remote = NULL;
  }

  TEST_1(sip->sip_to && sip->sip_to->a_tag);

  /* Test API functions */
  TEST(nta_outgoing_status(orq), status);
  TEST_1(nta_outgoing_request_uri(orq));
  TEST(nta_outgoing_route_uri(orq) != NULL, ag->ag_obp != NULL);
  TEST(nta_outgoing_method(orq), sip->sip_cseq->cs_method);
  TEST(nta_outgoing_cseq(orq), sip->sip_cseq->cs_seq);
  TEST_1(nta_outgoing_delay(orq) < UINT_MAX);
  
  TEST_1(msg = nta_outgoing_getresponse(orq));
  nta_msg_discard(ag->ag_agent, msg);
  
  TEST_1(msg = nta_outgoing_getrequest(orq));
  nta_msg_discard(ag->ag_agent, msg);
  nta_outgoing_destroy(orq);
  nta_outgoing_destroy(orq);

  ag->ag_orq = NULL;

  END();
}

static
int test_magic_branch(agent_t *ag, sip_t const *sip) 
{
  BEGIN();
  
  if (sip) {
    TEST_1(sip->sip_via);
    TEST_S(sip->sip_via->v_branch, "MagicalBranch");
  }

  END();
}

static
int magic_callback(agent_t *ag,
		   nta_outgoing_t *orq,
		   sip_t const *sip)
{
  test_magic_branch(ag, sip);
  return outgoing_callback(ag, orq, sip);
}

#include <time.h>

void 
nta_test_run(agent_t *ag)
{
  time_t now = time(NULL);

  for (ag->ag_status = 0; ag->ag_status < 200;) {
    if (tstflags & tst_verbatim) {
      fputs(".", stdout); fflush(stdout);
    }
    su_root_step(ag->ag_root, 500L);

    if (!getenv("NTA_TEST_DEBUG") && time(NULL) > now + 5) {
      fprintf(stderr, "nta_test_run: timeout\n");
      return;
    }
  }
}

#include <msg_mclass.h>

int test_init(agent_t *ag, char const *resolv_conf)
{
  char const *contact = "sip:*:*;comp=sigcomp";
  su_sockaddr_t su;
  socklen_t sulen;
  int s, af, sulen0;

  BEGIN();

  TEST_1(ag->ag_root = su_root_create(ag));

  TEST_1(ag->ag_mclass = msg_mclass_clone(sip_default_mclass(), 0, 0));

  if (str0cmp(getenv("ipv6"), "true") == 0) {
    contact = "sip:*:*;comp=sigcomp";
    af = AF_INET6, sulen0 = sizeof (struct sockaddr_in6);
  }
  else {
    af = AF_INET, sulen0 = sizeof (struct sockaddr_in);
    contact = "sip:0.0.0.0:*;comp=sigcomp";
  }

  if (ag->ag_m)
    contact = ag->ag_m;
  else if (getenv("SIPCONTACT"))
    contact = getenv("SIPCONTACT");

  /* Sink server */
  s = socket(af, SOCK_DGRAM, 0); TEST_1(s != -1);
  memset(&su, 0, sulen = sulen0);
  su.su_family = af;
  if (getenv("sink")) {
    su.su_port = htons(atoi(getenv("sink")));
  }
  TEST_1(bind(s, &su.su_sa, sulen) == 0);
  TEST_1(getsockname(s, &su.su_sa, &sulen) == 0);

  ag->ag_sink_port = su_sprintf(ag->ag_home, "%u", ntohs(su.su_sin.sin_port));
  ag->ag_sink_socket = s;

  /* Down server */
  s = socket(AF_INET, SOCK_STREAM, 0); TEST_1(s != -1);
  memset(&su, 0, sulen = sulen0);
  su.su_family = af;
  if (getenv("down")) {
    su.su_port = htons(atoi(getenv("down")));
  }
  TEST_1(bind(s, &su.su_sa, sulen) == 0);
  ag->ag_down_socket = s;
  
  /* Create agent */
  TEST_1(ag->ag_agent = nta_agent_create(ag->ag_root,
					 (url_string_t *)contact,
					 NULL,
					 NULL,
					 NTATAG_MCLASS(ag->ag_mclass),
					 NTATAG_USE_TIMESTAMP(1),
					 SRESTAG_RESOLV_CONF(resolv_conf),
					 NTATAG_USE_NAPTR(0),
					 NTATAG_USE_SRV(0),
					 TAG_END()));
  /* Create a default leg */
  TEST_1(ag->ag_default_leg = nta_leg_tcreate(ag->ag_agent, 
					     leg_callback_200,
					     ag,
					     NTATAG_NO_DIALOG(1),
					     TAG_END()));

  {
    /* Get and check parameters */
    sip_contact_t const *aliases = (void *)-1;
    msg_mclass_t *mclass = (void *)-1;
    unsigned retry_timer_ini = -1;
    unsigned retry_timer_max = -1;
    unsigned linger_timer    = -1;
    unsigned debug_drop_prob = -1;
    int ua              = -1;
    int user_via        = -1;
    int extra_100       = -1;
    int pass_100        = -1;
    int timeout_408     = -1;
    int pass_408        = -1;
    int merge_482       = -1;
    int cancel_2543     = -1;
    int cancel_487      = -1;
    int rel100          = -1;
    int use_timestamp   = -1;
    int use_naptr       = -1;
    int use_srv         = -1;

    TEST(nta_agent_get_params(ag->ag_agent,
			      NTATAG_MCLASS_REF(mclass),
			      NTATAG_ALIASES_REF(aliases),
			      NTATAG_SIP_T1_REF(retry_timer_ini),
			      NTATAG_SIP_T2_REF(retry_timer_max),
			      NTATAG_SIP_T4_REF(linger_timer),
			      NTATAG_DEBUG_DROP_PROB_REF(debug_drop_prob),
			      NTATAG_UA_REF(ua),
			      NTATAG_USER_VIA_REF(user_via),
			      NTATAG_EXTRA_100_REF(extra_100),
			      NTATAG_PASS_100_REF(pass_100),
			      NTATAG_TIMEOUT_408_REF(timeout_408),
			      NTATAG_PASS_408_REF(pass_408),
			      NTATAG_MERGE_482_REF(merge_482),
			      NTATAG_CANCEL_2543_REF(cancel_2543),
			      NTATAG_CANCEL_487_REF(cancel_487),
			      NTATAG_REL100_REF(rel100),
			      NTATAG_USE_TIMESTAMP_REF(use_timestamp),
			      NTATAG_USE_NAPTR_REF(use_naptr),
			      NTATAG_USE_SRV_REF(use_srv),
			      TAG_END()), 
	 /* Number of parameters */ 19);

    TEST(mclass, ag->ag_mclass);
    TEST(aliases,         NULL);
    TEST(retry_timer_ini, NTA_SIP_T1);
    TEST(retry_timer_max, NTA_SIP_T2);
    TEST(linger_timer,    NTA_SIP_T4);
    TEST(debug_drop_prob, 0);
    TEST(ua,              0);
    TEST(user_via,        0);
    TEST(extra_100,       0);
    TEST(pass_100,        0);
    TEST(timeout_408,     1);
    TEST(pass_408,        0);
    TEST(merge_482,       0);
    TEST(cancel_2543,     0);
    TEST(cancel_487,      1);
    TEST(rel100,          0);
    TEST(use_timestamp,   1);
    TEST(use_naptr,       0);
    TEST(use_srv,         0);
  }

  {
    /* Initialize our headers */
    // sip_param_t from_params[2] = { "tag=fdeadbeef", NULL };
    sip_from_t from[1];
    sip_to_t to[1];
    sip_contact_t m[1];

    sip_from_init(from);
    sip_to_init(to);
    sip_contact_init(m);

    TEST_1(ag->ag_contact = nta_agent_contact(ag->ag_agent));

    *m->m_url = *ag->ag_contact->m_url;
    m->m_url->url_user = "bob";
    TEST_1(ag->ag_m_bob = sip_contact_dup(ag->ag_home, m));

    to->a_display = "Bob";
    *to->a_url = *ag->ag_contact->m_url;
    to->a_url->url_user = "bob";
    to->a_url->url_port = NULL;
    TEST_1(ag->ag_bob = sip_to_dup(ag->ag_home, to));

    // url_strip_transport(ag->ag_bob->a_url);

    *m->m_url = *ag->ag_contact->m_url;
    m->m_url->url_user = "alice";
    TEST_1(ag->ag_m_alice = sip_contact_dup(ag->ag_home, m));

    from->a_display = "Alice";
    *from->a_url = *ag->ag_contact->m_url;
    from->a_url->url_user = "alice";
    from->a_url->url_port = NULL;
    // from->a_params = from_params;
    TEST_1(ag->ag_alice = sip_from_dup(ag->ag_home, from));

    // url_strip_transport(ag->ag_alice->a_url);
  }
  {
    char const data[] = 
      "v=0\r\n"
      "o=- 425432 423412 IN IP4 127.0.0.1\r\n"
      "s= \r\n"
      "c=IN IP4 127.0.0.1\r\n"
      "m=5004 audio 8 0\r\n";

    ag->ag_content_type = sip_content_type_make(ag->ag_home, "application/sdp");
    ag->ag_payload = sip_payload_make(ag->ag_home, data);
  }

  {
    sip_contact_t *m;

    ag->ag_aliases = 
      sip_contact_make(ag->ag_home, "sip:127.0.0.1, sip:localhost, sip:[::1]");
    TEST_1(ag->ag_aliases);
    TEST_1(ag->ag_aliases->m_next);
    TEST_1(ag->ag_aliases->m_next->m_next);
    TEST(ag->ag_aliases->m_next->m_next->m_next, NULL);

    for (m = ag->ag_aliases; m; m = m->m_next)
      m->m_url->url_port = ag->ag_contact->m_url->url_port;

    TEST_1(m = sip_contact_dup(ag->ag_home, ag->ag_contact));

    m->m_next = ag->ag_aliases;
    ag->ag_aliases = m;

    TEST(nta_agent_set_params(ag->ag_agent, 
			      NTATAG_ALIASES(ag->ag_aliases),
			      NTATAG_REL100(1),
			      NTATAG_UA(1), 
			      NTATAG_USE_NAPTR(1),
			      NTATAG_USE_SRV(1),
			      TAG_END()),
	 5);

    TEST(nta_agent_set_params(ag->ag_agent, 
			      NTATAG_ALIASES(ag->ag_aliases),
			      NTATAG_DEFAULT_PROXY("sip:127.0.0.1"),
			      TAG_END()), 2);

    TEST(nta_agent_set_params(ag->ag_agent, 
			      NTATAG_ALIASES(ag->ag_aliases),
			      NTATAG_DEFAULT_PROXY(NULL),
			      TAG_END()), 2);

    TEST(nta_agent_set_params(ag->ag_agent, 
			      NTATAG_DEFAULT_PROXY("tel:+35878008000"),
			      TAG_END()), -1);

  }
  
  {
    url_t url[1];

    /* Create the server leg */
    *url = *ag->ag_aliases->m_url;
    url->url_user = "%";
    TEST_1(ag->ag_server_leg = nta_leg_tcreate(ag->ag_agent, 
					       leg_callback_200,
					       ag,
					       NTATAG_NO_DIALOG(1),
					       URLTAG_URL(url),
					       TAG_END()));
  }

  END();
}  

int test_deinit(agent_t *ag)
{
  BEGIN();

  nta_leg_destroy(ag->ag_alice_leg);
  nta_leg_destroy(ag->ag_bob_leg);
  nta_leg_destroy(ag->ag_default_leg);
  nta_leg_destroy(ag->ag_server_leg);

  nta_agent_destroy(ag->ag_agent);
  su_root_destroy(ag->ag_root);

  END();
}  


static unsigned char const code[] = 
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#include <su_uniqueid.h>

sip_payload_t *test_payload(su_home_t *home, int size)
{
  sip_payload_t *pl = sip_payload_create(home, NULL, size);

  if (pl) {
    int i;
    char *data = (char *)pl->pl_data;
    
    for (i = 0; i < size; i++) {
      if ((i & 63) != 63)
	data[i] = code[su_randint(0, 63)];
      else
	data[i] = '\n';
    }
  }

  return pl;
}

/* Test transports */

int test_tports(agent_t *ag)
{
  int udp = 0, tcp = 0, sctp = 0, tls = 0;
  sip_via_t const *v, *v_udp_only = NULL;
  char const *udp_comp = NULL;
  char const *tcp_comp = NULL;

  url_t url[1];

  BEGIN();

  *url = *ag->ag_contact->m_url;
  url->url_port = "*";
  url->url_params = "transport=udp";

  TEST_1(nta_agent_add_tport(ag->ag_agent, (url_string_t *)url, 
			     TAG_END()) == 0);

  TEST_1(v = nta_agent_via(ag->ag_agent));

  for (; v; v = v->v_next) {
    if (strcasecmp(v->v_protocol, sip_transport_udp) == 0) {
      if (udp)
	v_udp_only = v;
      udp = 1;
      if (udp_comp == NULL)
	udp_comp = msg_params_find(v->v_params, "comp=");
    }
    else if (strcasecmp(v->v_protocol, sip_transport_tcp) == 0) {
      tcp = 1;
      if (tcp_comp == NULL)
	tcp_comp = msg_params_find(v->v_params, "comp=");
    }
    else if (strcasecmp(v->v_protocol, sip_transport_sctp) == 0) {
      sctp = 1;
    }
    else if (strcasecmp(v->v_protocol, sip_transport_tls) == 0) {
      tls = 1;
    }
  }

  *url = *ag->ag_aliases->m_url;
  url->url_user = "bob";

  if (udp_comp || tcp_comp)
    ag->ag_comp = "sigcomp";

  {
    /* Test 0.1
     * Send a message from default leg to default leg 
     */
    char const p_acid[] = "P-Access-Network-Info: IEEE-802.11g\n";
    msg_t *msg;

    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, 
			       outgoing_callback_with_api_test, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)ag->ag_contact->m_url,
			       SIPTAG_SUBJECT_STR("Test 0.1"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       SIPTAG_HEADER_STR(p_acid),
			       TAG_END()));

    TEST(nta_outgoing_getresponse_ref(ag->ag_orq), NULL);
    TEST_1(msg = nta_outgoing_getrequest_ref(ag->ag_orq));
    TEST_S(nta_outgoing_method_name(ag->ag_orq), "MESSAGE");

    TEST(nta_outgoing_delay(ag->ag_orq), UINT_MAX);
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    TEST_1(ag->ag_request);

    msg_destroy(msg);
  }

#if HAVE_SIGCOMP
  /* Test 0.1.1
   * Send a message from Bob to Alice using SIGCOMP and TCP
   */
  if (tcp_comp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
    if (url->url_params)
      url->url_params = su_sprintf(NULL, "%s;transport=tcp", url->url_params);
    else
      url->url_params = "transport=tcp";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
	   nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
				ag->ag_obp,
				SIP_METHOD_MESSAGE,
				(url_string_t *)url,
				NTATAG_COMP("sigcomp"),
				SIPTAG_SUBJECT_STR("Test 0.1.1"),
				SIPTAG_FROM(ag->ag_bob),
				SIPTAG_TO(ag->ag_alice),
				SIPTAG_CONTACT(ag->ag_m_bob),
				SIPTAG_PAYLOAD(pl),
				TAG_END()));
    
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST_1(ag->ag_client_compartment);
    nta_compartment_decref(&ag->ag_client_compartment);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }
#endif

  /* Test 0.2
   * Send a message from Bob to Alice
   * This time specify a TCP URI, and include a large payload 
   * of 512 kB
   */
  if (tcp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 512 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
#if 0
    if (url->url_params)
      url->url_params = su_sprintf(NULL, "%s;transport=tcp", url->url_params);
    else
#endif
      url->url_params = "transport=tcp";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       NULL,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.2"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       NTATAG_DEFAULT_PROXY(ag->ag_obp),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.3
   * Send a message from Bob to Alice
   * This time include a large payload of 512 kB, let NTA choose transport.
   */
  if (tcp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 512 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.3"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.4.1:
   * Send a message from Bob to Alice
   * This time include a payload of 2 kB, let NTA choose transport.
   */
  {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 2 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));
    su_free(ag->ag_home, (void *)ag->ag_out_via), ag->ag_out_via = NULL;

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.4.1"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
    TEST_1(ag->ag_out_via);
    TEST_1(strcasecmp(ag->ag_out_via->v_protocol, "SIP/2.0/TCP") == 0 ||
	   strcasecmp(ag->ag_out_via->v_protocol, "SIP/2.0/SCTP") == 0);
  }

  /* Test 0.4.2:
   * Send a message from Bob to Alices UDP-only address
   * This time include a payload of 2 kB, let NTA choose transport.
   */
  if (v_udp_only) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 2 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
    url->url_host = v_udp_only->v_host;
    url->url_port = v_udp_only->v_port;
    url->url_params = NULL;	/* No sigcomp */

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_default_leg;

    su_free(ag->ag_home, ag->ag_in_via), ag->ag_in_via = NULL;

    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.4.2"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    TEST_1(ag->ag_in_via);
    TEST_1(strcasecmp(ag->ag_in_via->v_protocol, "SIP/2.0/UDP") == 0);
  }

  /* Test 0.5:
   * Send a message from Bob to Alice
   * This time include a payload of 2 kB, try to use UDP.
   */
  if (udp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 2 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    su_free(ag->ag_home, (void *)ag->ag_out_via), ag->ag_out_via = NULL;

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.5"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TPTAG_MTU(0xffffffff),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
    TEST_1(ag->ag_out_via);
    TEST_S(ag->ag_out_via->v_protocol, "SIP/2.0/UDP");
  }

  if (udp) {
    /* Send a message from default leg to server leg 
     * using a prefilled Via header
     */
    sip_via_t via[1];

    sip_via_init(via);

    via->v_protocol = sip_transport_udp;
    
    via->v_host = ag->ag_contact->m_url->url_host;
    via->v_port = ag->ag_contact->m_url->url_port;
    
    sip_via_add_param(ag->ag_home, via, "branch=MagicalBranch");

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_ALIASES(ag->ag_aliases),
			 NTATAG_USER_VIA(1),
			 TAG_END());

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, 
			       magic_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.6"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       SIPTAG_VIA(via),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_USER_VIA(0),
			 TAG_END());
  }

  /* Test 0.7
   * Send a message from Bob to Alice using SCTP 
   */
  if (sctp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 16 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
#if 0
    if (url->url_params)
      url->url_params = su_sprintf(NULL, "%s;transport=sctp", url->url_params);
    else
#endif
      url->url_params = "transport=sctp";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.7"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.8: Send a too large message */
  if (tcp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 128 * 1024;

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_MAXSIZE(65536),
			 TAG_END());

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    ag->ag_latest_leg = NULL;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.8"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 413);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, NULL);

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_MAXSIZE(2 * 1024 * 1024),
			 TAG_END());
  }

  /* Test 0.9: Timeout */
  {
    url_t url[1];

    printf("%s: starting MESSAGE timeout test, completing in 4 seconds\n",
	   name);

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_TIMEOUT_408(1),
			 NTATAG_SIP_T1(25), 
			 NTATAG_SIP_T1X64(64 * 25), 
			 NTATAG_SIP_T2(8 * 25),
			 NTATAG_SIP_T4(10 * 25),
			 TAG_END());

    *url = *ag->ag_aliases->m_url;
    url->url_user = "timeout";
    url->url_port = ag->ag_sink_port;

    ag->ag_expect_leg = ag->ag_server_leg;
    ag->ag_latest_leg = NULL;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.9"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       TAG_END()));

    nta_test_run(ag);
    TEST(ag->ag_status, 408);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, NULL);

    nta_agent_set_params(ag->ag_agent,
			 NTATAG_SIP_T1(500),
			 NTATAG_SIP_T1X64(64 * 500),
			 NTATAG_SIP_T2(NTA_SIP_T2),
			 NTATAG_SIP_T4(NTA_SIP_T4),
			 TAG_END());
  }
  

  END();
}

int test_resolv(agent_t *ag, char const *resolv_conf)
{
  int udp = 0, tcp = 0, sctp = 0, tls = 0;
  sip_via_t const *v;

  url_t *url;

  if (!resolv_conf)
    return 0;

  BEGIN();

  TEST_1(v = nta_agent_via(ag->ag_agent));
  for (; v; v = v->v_next) {
    if (strcasecmp(v->v_protocol, sip_transport_udp) == 0)
      udp = 1;
    else if (strcasecmp(v->v_protocol, sip_transport_tcp) == 0)
      tcp = 1;
    else if (strcasecmp(v->v_protocol, sip_transport_sctp) == 0)
      sctp = 1;
    else if (strcasecmp(v->v_protocol, sip_transport_tls) == 0)
      tls = 1;
  }

  url = url_hdup(ag->ag_home, (void *)"sip:example.org"); TEST_1(url);

  {
    /* Test 1.1
     * Send a message to sip:example.org
     */
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.1"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.2
     * Send a message to sip:srv.example.org
     */
    url->url_host = "srv.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.2"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.3
     * Send a message to sip:ipv.example.org
     */
    url->url_host = "ipv.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.3"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.4.1
     * Send a message to sip:down.example.org
     */
    url->url_host = "down.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.4.1"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.4.2
     * Send a message to sip:na503.example.org
     */
    url->url_host = "na503.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.4.2"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 503);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.4.3
     * Send a message to sip:nona.example.org
     */
    url->url_host = "nona.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.4.3"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.4.4
     * Send a message to sip:nosrv.example.org
     * After failing to find _sip._udp.nosrv.example.org,
     * second SRV with _sip._udp.srv.example.org succeeds
     */
    url->url_host = "nosrv.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.4.4"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.5.1 
     * Send a message to sip:srv.example.org;transport=tcp
     * Test outgoing_make_srv_query()
     */
    url->url_host = "srv.example.org";
    url->url_params = "transport=tcp";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.5.1: outgoing_make_srv_query()"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    url->url_params = NULL;
  }

  {
    /* Test 1.5.2
     * Send a message to sip:srv.example.org;transport=udp
     * Test outgoing_make_srv_query()
     */
    url->url_host = "srv.example.org";
    url->url_params = "transport=udp";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.5.2: outgoing_make_srv_query()"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    url->url_params = NULL;
  }

  {
    /* Test 1.5.3
     * Send a message to sip:srv2.example.org;transport=udp
     * Test outgoing_query_srv_a()
     */
    url->url_host = "srv2.example.org";
    url->url_params = "transport=udp";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.5: outgoing_query_srv_a()"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    url->url_params = NULL;
  }

  {
    /* Test 1.6.1
     * Send a message to sip:srv.example.org:$port
     * Test outgoing_make_a_aaaa_query()
     */
    url->url_host = "srv.example.org";
    url->url_port = ag->ag_contact->m_url->url_port;
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.6.1: outgoing_make_a_aaaa_query()"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 503);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  {
    /* Test 1.6.2
     * Send a message to sip:a.example.org:$port
     * Test outgoing_make_a_aaaa_query()
     */
    url->url_host = "a.example.org";
    url->url_port = ag->ag_contact->m_url->url_port;
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.6.2: outgoing_make_a_aaaa_query()"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    url->url_port = NULL;
  }

#if 0				/* This must be run on host *without* proxy */
  {
    /* Test 1.6c
     * Send a message to sip:na.example.org
     * Test outgoing_query_all() with NAPTR "A" flag
     */
    url->url_host = "na.example.org";
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.6c"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 503);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }
#endif

  {
    /* Test 1.7
     * Send a message to sip:down2.example.org:$port
     * Test A record failover.
     */
    url->url_host = "down2.example.org";
    url->url_port = ag->ag_contact->m_url->url_port;
    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.7: outgoing_make_a_aaaa_query()"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
    url->url_params = NULL;
  }

  return 0;

#if 0
  /* Test 0.1.1
   * Send a message from Bob to Alice using SIGCOMP and TCP
   */
  if (tcp_comp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
    if (url->url_params)
      url->url_params = su_sprintf(NULL, "%s;transport=tcp", url->url_params);
    else
      url->url_params = "transport=tcp";

    TEST_1(pl = test_payload(ag->ag_home, size));


    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
	   nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
				ag->ag_obp,
				SIP_METHOD_MESSAGE,
				(url_string_t *)url,
				SIPTAG_SUBJECT_STR("Test 0.1.1"),
				SIPTAG_FROM(ag->ag_bob),
				SIPTAG_TO(ag->ag_alice),
				SIPTAG_CONTACT(ag->ag_m_bob),
				SIPTAG_PAYLOAD(pl),
				TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.2
   * Send a message from Bob to Alice
   * This time specify a TCP URI, and include a large payload 
   * of 512 kB
   */
  if (tcp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 512 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
#if 0
    if (url->url_params)
      url->url_params = su_sprintf(NULL, "%s;transport=tcp", url->url_params);
    else
#endif
      url->url_params = "transport=tcp";


    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.2"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.3
   * Send a message from Bob to Alice
   * This time include a large payload of 512 kB, let NTA choose transport.
   */
  if (tcp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 512 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.3"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.4:
   * Send a message from Bob to Alice
   * This time include a payload of 2 kB, let NTA choose transport.
   */
  {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 2 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    su_free(ag->ag_home, (void *)ag->ag_out_via), ag->ag_out_via = NULL;

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.4"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
    TEST_1(ag->ag_out_via);
    TEST_1(strcasecmp(ag->ag_out_via->v_protocol, "SIP/2.0/TCP") == 0 ||
	   strcasecmp(ag->ag_out_via->v_protocol, "SIP/2.0/SCTP") == 0);
  }

  /* Test 0.5:
   * Send a message from Bob to Alice
   * This time include a payload of 2 kB, try to use UDP.
   */
  if (udp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 2 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    su_free(ag->ag_home, (void *)ag->ag_out_via), ag->ag_out_via = NULL;

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.5"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TPTAG_MTU(0xffffffff),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
    TEST_1(ag->ag_out_via);
    TEST_S(ag->ag_out_via->v_protocol, "SIP/2.0/UDP");
  }

  if (udp) {
    /* Send a message from default leg to server leg 
     * using a prefilled Via header
     */
    sip_via_t via[1];

    sip_via_init(via);

    via->v_protocol = sip_transport_udp;
    
    via->v_host = ag->ag_contact->m_url->url_host;
    via->v_port = ag->ag_contact->m_url->url_port;
    
    sip_via_add_param(ag->ag_home, via, "branch=MagicalBranch");

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_USER_VIA(1),
			 TAG_END());

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, 
			       magic_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.6"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       SIPTAG_VIA(via),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_USER_VIA(0),
			 TAG_END());
  }

  /* Test 0.7
   * Send a message from Bob to Alice using SCTP 
   */
  if (sctp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 16 * 1024;

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";
#if 0
    if (url->url_params)
      url->url_params = su_sprintf(NULL, "%s;transport=sctp", url->url_params);
    else
#endif
      url->url_params = "transport=sctp";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.7"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_server_leg);
  }

  /* Test 0.8: Send a too large message */
  if (tcp) {
    url_t url[1];
    sip_payload_t *pl;
    unsigned size = 128 * 1024;

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_MAXSIZE(65536),
			 TAG_END());

    *url = *ag->ag_aliases->m_url;
    url->url_user = "alice";

    TEST_1(pl = test_payload(ag->ag_home, size));

    ag->ag_expect_leg = ag->ag_server_leg;
    ag->ag_latest_leg = NULL;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.8"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       SIPTAG_PAYLOAD(pl),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 413);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, NULL);

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_MAXSIZE(2 * 1024 * 1024),
			 TAG_END());
  }

  /* Test 0.9: Timeout */
  {
    url_t url[1];

    printf("%s: starting MESSAGE timeout test, test will complete in 4 seconds\n",
	   name);

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_TIMEOUT_408(1),
			 NTATAG_SIP_T1(25), 
			 NTATAG_SIP_T1X64(64 * 25), 
			 TAG_END());

    *url = *ag->ag_aliases->m_url;
    url->url_user = "timeout";
    url->url_port = ag->ag_sink_port;

    ag->ag_expect_leg = ag->ag_server_leg;
    ag->ag_latest_leg = NULL;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 0.9"),
			       SIPTAG_FROM(ag->ag_bob),
			       SIPTAG_TO(ag->ag_alice),
			       SIPTAG_CONTACT(ag->ag_m_bob),
			       TAG_END()));

    nta_test_run(ag);
    TEST(ag->ag_status, 408);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, NULL);

    nta_agent_set_params(ag->ag_agent,
			 NTATAG_SIP_T1(500),
			 NTATAG_SIP_T1X64(64 * 500),
			 TAG_END());
  }
#endif  

  END();
}

/* Test default routing */

int test_routing(agent_t *ag)
{
  url_t url[1];

  *url = *ag->ag_aliases->m_url;
  url->url_user = "bob";

  nta_agent_set_params(ag->ag_agent, 
		       NTATAG_MAXSIZE(2 * 1024 * 1024),
		       TAG_END());

  BEGIN();

  {
    /* 
     * Send a message from default leg to default leg 
     *
     * We are now using url with an explicit port that does not match with
     * our own port number.
     */
    url_t url2[1];

    *url2 = *url;
    url2->url_port = "9";	/* discard service */

    ag->ag_expect_leg = ag->ag_default_leg;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       (url_string_t *)url,
			       SIP_METHOD_MESSAGE,
			       (url_string_t *)url2,
			       SIPTAG_SUBJECT_STR("Test 1.2"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_default_leg);
  }

  END();
}

/* Test dialogs and the tag handling */

int test_dialog(agent_t *ag)
{
  BEGIN();

  /*
   * Test establishing a dialog
   *
   * Alice sends a message to Bob, then Bob back to the Alice, and again
   * Alice to Bob.
   */
  TEST_1(ag->ag_alice_leg = nta_leg_tcreate(ag->ag_agent, 
					   leg_callback_200,
					   ag,
					   SIPTAG_FROM(ag->ag_alice),
					   SIPTAG_TO(ag->ag_bob),
					   TAG_END()));
  TEST(nta_leg_tag(ag->ag_alice_leg, NULL), 0);
  nta_leg_bind(ag->ag_server_leg, new_leg_callback_200, ag);

  /* Send message from Alice to Bob establishing the dialog */
  ag->ag_expect_leg = ag->ag_server_leg;
  ag->ag_tag_remote = ag->ag_alice_leg;
  TEST_1(ag->ag_orq = 
        nta_outgoing_tcreate(ag->ag_alice_leg, outgoing_callback, ag,
			     ag->ag_obp,
			     SIP_METHOD_MESSAGE,
			     (url_string_t *)ag->ag_m_bob->m_url,
			     SIPTAG_SUBJECT_STR("Test 2.1"),
			     SIPTAG_FROM(ag->ag_alice),
			     SIPTAG_TO(ag->ag_bob),
			     SIPTAG_CONTACT(ag->ag_m_alice),
			     TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_server_leg);
  TEST_1(ag->ag_bob_leg != NULL);

  nta_leg_bind(ag->ag_server_leg, leg_callback_200, ag);

  /* Send message from Bob to Alice */
  ag->ag_expect_leg = ag->ag_alice_leg;
  TEST_1(ag->ag_orq = 
        nta_outgoing_tcreate(ag->ag_bob_leg, outgoing_callback, ag,
      		       NULL,
      		       SIP_METHOD_MESSAGE,
      		       (url_string_t *)ag->ag_m_alice->m_url,
      		       SIPTAG_SUBJECT_STR("Test 2.2"),
      		       TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_alice_leg);

  /* Send again message from Alice to Bob */
  ag->ag_expect_leg = ag->ag_bob_leg;
  TEST_1(ag->ag_orq = 
        nta_outgoing_tcreate(ag->ag_alice_leg, outgoing_callback, ag,
      		       NULL,
      		       SIP_METHOD_MESSAGE,
      		       (url_string_t *)ag->ag_m_bob->m_url,
      		       SIPTAG_SUBJECT_STR("Test 2.3"),
      		       TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_bob_leg);

  /* Send message from Bob to Alice
   * This time, however, specify request URI 
   */
  {
    ag->ag_expect_leg = ag->ag_alice_leg;
    TEST_1(ag->ag_orq = 
          nta_outgoing_tcreate(ag->ag_bob_leg, outgoing_callback, ag,
      			 NULL,
      			 SIP_METHOD_MESSAGE,
      			 (url_string_t *)ag->ag_m_alice->m_url,
      			 SIPTAG_SUBJECT_STR("Test 2.4"),
      			 TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 200);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, ag->ag_alice_leg);
  }

  nta_leg_destroy(ag->ag_alice_leg), ag->ag_alice_leg = NULL;
  nta_leg_destroy(ag->ag_bob_leg), ag->ag_bob_leg = NULL;

  END();
}

/* ---------------------------------------------------------------------- */
/* Test INVITE, dialogs */

static
int test_for_ack(agent_t *ag,
		 nta_incoming_t *irq, 
		 sip_t const *sip)
{
  sip_method_t method;

  BEGIN();

  method = sip ? sip->sip_request->rq_method : sip_method_unknown;

  nta_incoming_destroy(irq);
  TEST(irq, ag->ag_irq);
  ag->ag_irq = NULL;

  TEST(method, sip_method_ack);
  
  ag->ag_status = 200;

  END();
}

static
int test_for_prack(agent_t *ag,
		   nta_reliable_t *rel,
		   nta_incoming_t *prack,
		   sip_t const *sip)
{
  sip_method_t method = sip ? sip->sip_request->rq_method : sip_method_unknown;

  nta_incoming_treply(ag->ag_irq, 
		      SIP_200_OK, 
		      SIPTAG_CONTACT(ag->ag_m_alice),
		      TAG_END());

  TEST(method, sip_method_prack);
		     
  return 200;
}

int alice_leg_callback(agent_t *ag,
		       nta_leg_t *leg,
		       nta_incoming_t *irq,
		       sip_t const *sip)
{
  BEGIN();

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  TEST_1(sip->sip_content_length);
  TEST_1(sip->sip_via);
  TEST_1(sip->sip_from && sip->sip_from->a_tag);

  if (sip->sip_request->rq_method == sip_method_prack)
    return 481;

  ag->ag_latest_leg = leg;

  if (leg != ag->ag_alice_leg) {
    leg_match(ag, leg, 1, __func__);
    return 500;
  }

  if (sip->sip_request->rq_method == sip_method_invite) {
    TEST_1(sip_has_feature(sip->sip_supported, "100rel"));
    nta_incoming_bind(irq, test_for_ack, ag);
    nta_incoming_treply(irq, SIP_100_TRYING, TAG_END());

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_DEBUG_DROP_PROB(ag->ag_drop),
			 TAG_END());

    ag->ag_reliable = 
      nta_reliable_treply(irq,
			  NULL, NULL,
			  SIP_183_SESSION_PROGRESS,
			  SIPTAG_CONTENT_TYPE(ag->ag_content_type),
			  SIPTAG_PAYLOAD(ag->ag_payload),
			  SIPTAG_CONTACT(ag->ag_m_alice),
			  TAG_END());
    TEST_1(ag->ag_reliable);
    ag->ag_reliable = 
      nta_reliable_treply(irq,
			  NULL, NULL,
			  184, "Next",
			  SIPTAG_CONTACT(ag->ag_m_alice),
			  TAG_END());
    TEST_1(ag->ag_reliable);
    ag->ag_reliable = 
      nta_reliable_treply(irq,
			  test_for_prack, ag,
			  185, "Last",
			  SIPTAG_CONTACT(ag->ag_m_alice),
			  TAG_END());
    TEST_1(ag->ag_reliable);
    ag->ag_irq = irq;
    return 0;
  } 

  if (sip->sip_request->rq_method == sip_method_bye) {
    leg_zap(ag, leg);
  }

  return 200;

  END();
}


int bob_leg_callback(agent_t *ag,
		     nta_leg_t *leg,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  BEGIN();

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  TEST_1(sip->sip_content_length);
  TEST_1(sip->sip_via);
  TEST_1(sip->sip_from && sip->sip_from->a_tag);

  if (sip->sip_request->rq_method == sip_method_prack)
    return 481;

  ag->ag_latest_leg = leg;

  if (ag->ag_bob_leg && leg != ag->ag_bob_leg) {
    leg_match(ag, leg, 1, __func__);
    return 500;
  }

  if (ag->ag_bob_leg == NULL) {
    nta_leg_bind(leg, leg_callback_500, ag);
    ag->ag_bob_leg = nta_leg_tcreate(ag->ag_agent,
				     bob_leg_callback,
				     ag,
				     SIPTAG_CALL_ID(sip->sip_call_id),
				     SIPTAG_FROM(sip->sip_to),
				     SIPTAG_TO(sip->sip_from),
				     TAG_END());
    TEST_1(ag->ag_bob_leg);
    TEST(nta_leg_tag(ag->ag_bob_leg, NULL), 0);
    TEST_1(nta_leg_get_tag(ag->ag_bob_leg));
    TEST(nta_incoming_tag(irq, nta_leg_get_tag(ag->ag_bob_leg)), 0);
    TEST(nta_leg_server_route(ag->ag_bob_leg, 
			      sip->sip_record_route, 
			      sip->sip_contact), 0);
  }

  if (sip->sip_request->rq_method == sip_method_invite) {
    nta_incoming_bind(irq, test_for_ack, ag); 
    nta_incoming_treply(irq,
			SIP_200_OK,
			SIPTAG_CONTENT_TYPE(ag->ag_content_type),
			SIPTAG_PAYLOAD(ag->ag_payload),
			SIPTAG_CONTACT(ag->ag_m_bob),
			TAG_END());
    ag->ag_irq = irq;
    return 0;
  } else {
    return 200;
  }

  END();
}

int outgoing_invite_callback(agent_t *ag,
			     nta_outgoing_t *orq,
			     sip_t const *sip)
{
  BEGIN();

  int status = sip->sip_status->st_status;

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s %03d %s\n", name, __func__, 
	   sip->sip_status->st_version, 
	   sip->sip_status->st_status, 
	   sip->sip_status->st_phrase);
  }

  if (status < 200) {
    if (sip->sip_require && sip_has_feature(sip->sip_require, "100rel")) {
      TEST_1(sip->sip_rseq);
      orq = nta_outgoing_prack(ag->ag_call_leg, orq, NULL, NULL,
			       NULL,
			       sip, 
			       TAG_END());
      TEST_1(orq);
      nta_outgoing_destroy(orq);
    }
    return 0;
  }

  if (status < 300) {
    nta_outgoing_t *ack;

    TEST(nta_leg_rtag(ag->ag_call_leg, sip->sip_to->a_tag), 0);
    
    TEST(nta_leg_client_route(ag->ag_call_leg, 
			      sip->sip_record_route,
			      sip->sip_contact), 0);

    ack = nta_outgoing_tcreate(ag->ag_call_leg, NULL, NULL,
			       NULL,
			       SIP_METHOD_ACK,
			       NULL,
			       SIPTAG_CSEQ(sip->sip_cseq),
			       TAG_END());
    TEST_1(ack);
    nta_outgoing_destroy(ack);
  }
  else {
    ag->ag_status = status;
  }

  TEST_1(sip->sip_to && sip->sip_to->a_tag);

  nta_outgoing_destroy(orq);
  ag->ag_orq = NULL;
  ag->ag_call_leg = NULL;
  return 0;

  END();
}


int test_call(agent_t *ag)
{
  sip_content_type_t *c = ag->ag_content_type;
  sip_payload_t      *sdp = ag->ag_payload;
  nta_leg_t *old_leg;

  BEGIN();

  /*
   * Test establishing a call
   *
   * Alice sends a INVITE to Bob, then Bob sends 200 Ok.
   */
  TEST_1(ag->ag_alice_leg = nta_leg_tcreate(ag->ag_agent, 
					   alice_leg_callback,
					   ag,
					   SIPTAG_FROM(ag->ag_alice),
					   SIPTAG_TO(ag->ag_bob),
					   TAG_END()));
  TEST(nta_leg_tag(ag->ag_alice_leg, NULL), 0);
  nta_leg_bind(ag->ag_server_leg, bob_leg_callback, ag);
  
  /* Send INVITE */
  ag->ag_expect_leg = ag->ag_server_leg;
  TEST_1(ag->ag_orq = 
	 nta_outgoing_tcreate(ag->ag_call_leg = ag->ag_alice_leg, 
			      outgoing_invite_callback, ag,
			      ag->ag_obp,
			      SIP_METHOD_INVITE,
			      (url_string_t *)ag->ag_m_bob->m_url,
			      SIPTAG_SUBJECT_STR("Call 1"),
			      SIPTAG_CONTACT(ag->ag_m_alice),
			      SIPTAG_CONTENT_TYPE(c),
			      SIPTAG_PAYLOAD(sdp),
			      NTATAG_USE_TIMESTAMP(1),
			      NTATAG_PASS_100(1),
			      TAG_END()));

  /* Try to CANCEL it immediately */
  TEST_1(nta_outgoing_cancel(ag->ag_orq) == 0);
  /* As Bob immediately answers INVITE with 200 Ok, 
     cancel should be answered with 487. */

  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_server_leg);
  TEST_1(ag->ag_bob_leg != NULL);

  /* Re-INVITE from Bob to Alice.
   *
   * Alice first sends 183, waits for PRACK, then sends 184 and 185,
   * waits for PRACKs, then sends 200, waits for ACK.
   */
  ag->ag_expect_leg = ag->ag_alice_leg;
  TEST_1(ag->ag_orq = 
	nta_outgoing_tcreate(ag->ag_call_leg = ag->ag_bob_leg, 
			     outgoing_invite_callback, ag,
			     NULL,
			     SIP_METHOD_INVITE,
			     NULL,
			     SIPTAG_SUBJECT_STR("Re-INVITE"),
			     SIPTAG_CONTACT(ag->ag_m_bob),
			     SIPTAG_SUPPORTED_STR("foo"),
			     SIPTAG_CONTENT_TYPE(c),
			     SIPTAG_PAYLOAD(sdp),
			     TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_alice_leg);

  nta_agent_set_params(ag->ag_agent, 
		       NTATAG_DEBUG_DROP_PROB(0),
		       TAG_END());

  /* Send BYE from Bob to Alice */
  old_leg = ag->ag_expect_leg = ag->ag_alice_leg;
  TEST_1(ag->ag_orq = 
	nta_outgoing_tcreate(ag->ag_bob_leg, outgoing_callback, ag,
			     NULL,
			     SIP_METHOD_BYE,
			     NULL,
			     SIPTAG_SUBJECT_STR("Hangup"),
			     SIPTAG_FROM(ag->ag_alice),
			     SIPTAG_TO(ag->ag_bob),
			     SIPTAG_CONTACT(ag->ag_m_alice),
			     SIPTAG_CONTENT_TYPE(c),
			     SIPTAG_PAYLOAD(sdp),
			     TAG_END()));

  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, old_leg);
  TEST(ag->ag_alice_leg, NULL);

  nta_leg_destroy(ag->ag_bob_leg), ag->ag_bob_leg = NULL;
  ag->ag_latest_leg = NULL;
  ag->ag_call_leg = NULL;

  END();
}

/* ============================================================================ */
/* Test early dialogs, PRACK */

int test_for_ack_or_timeout(agent_t *ag,
			    nta_incoming_t *irq, 
			    sip_t const *sip)
{
  BEGIN();

  sip_method_t method = sip ? sip->sip_request->rq_method : sip_method_unknown;

  nta_incoming_destroy(irq);
  TEST(irq, ag->ag_irq);
  ag->ag_irq = NULL;

  if (sip) {
    TEST(method, sip_method_ack);
  
    ag->ag_status = 200;
  }
  else {
    if (ag->ag_bob_leg) {
      nta_leg_destroy(ag->ag_bob_leg), ag->ag_bob_leg = NULL;
    }
  }
  return 0;

  END();
}

int bob_leg_callback2(agent_t *ag,
		     nta_leg_t *leg,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  BEGIN();

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  TEST_1(sip->sip_content_length);
  TEST_1(sip->sip_via);
  TEST_1(sip->sip_from && sip->sip_from->a_tag);

  ag->ag_latest_leg = leg;

  if (ag->ag_bob_leg && leg != ag->ag_bob_leg) {
    leg_match(ag, leg, 1, __func__);
    return 500;
  }

  if (ag->ag_bob_leg == NULL) {
    nta_leg_bind(leg, leg_callback_500, ag);
    ag->ag_bob_leg = nta_leg_tcreate(ag->ag_agent,
				     bob_leg_callback,
				     ag,
				     SIPTAG_CALL_ID(sip->sip_call_id),
				     SIPTAG_FROM(sip->sip_to),
				     SIPTAG_TO(sip->sip_from),
				     TAG_END());
    TEST_1(ag->ag_bob_leg);
    TEST(nta_leg_tag(ag->ag_bob_leg, NULL), 0);
    TEST_1(nta_leg_get_tag(ag->ag_bob_leg));
    TEST(nta_incoming_tag(irq, nta_leg_get_tag(ag->ag_bob_leg)), 0);
    TEST(nta_leg_server_route(ag->ag_bob_leg, 
			      sip->sip_record_route, 
			      sip->sip_contact), 0);
  }

  if (sip->sip_request->rq_method == sip_method_invite) {
    nta_incoming_bind(irq, test_for_ack_or_timeout, ag); 
    nta_incoming_treply(irq,
			SIP_183_SESSION_PROGRESS,
			SIPTAG_CONTENT_TYPE(ag->ag_content_type),
			SIPTAG_PAYLOAD(ag->ag_payload),
			SIPTAG_CONTACT(ag->ag_m_bob),
			TAG_END());
    nta_incoming_treply(irq,
			SIP_200_OK,
			SIPTAG_CONTACT(ag->ag_m_bob),
			TAG_END());
    ag->ag_irq = irq;
    return 0;
  } else {
    return 200;
  }

  END();
}

int invite_prack_callback(agent_t *ag,
			 nta_outgoing_t *orq,
			 sip_t const *sip)
{
  BEGIN();

  int status = sip->sip_status->st_status;

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s %03d %s\n", name, __func__, 
	   sip->sip_status->st_version, 
	   sip->sip_status->st_status, 
	   sip->sip_status->st_phrase);
  }

  if (!ag->ag_call_tag && (status >= 200 || (status > 100 && sip->sip_rseq))) {
    nta_outgoing_t *tagged;
    TEST_1(sip->sip_to->a_tag);
    ag->ag_tag_status = status;
    ag->ag_call_tag = su_strdup(ag->ag_home, sip->sip_to->a_tag);
    TEST_S(ag->ag_call_tag, sip->sip_to->a_tag);
    TEST(nta_leg_rtag(ag->ag_call_leg, ag->ag_call_tag), 0);
    TEST(nta_leg_client_route(ag->ag_call_leg, 
			      sip->sip_record_route,
			      sip->sip_contact), 0);
    tagged = nta_outgoing_tagged(orq, 
				 invite_prack_callback,
				 ag,
				 ag->ag_call_tag,
				 sip->sip_rseq);
    TEST_1(tagged);
    nta_outgoing_destroy(orq);
    orq = tagged;
  }

  if (status > 100 && status < 200 && sip->sip_rseq) {
    nta_outgoing_t *prack;
    prack = nta_outgoing_prack(ag->ag_call_leg, orq, NULL, NULL,
			       NULL,
			       sip, 
			       TAG_END());
    TEST_1(prack);
    nta_outgoing_destroy(prack);

    return 0;
  }

  if (status < 200)
    return 0;

  if (status < 300) {
    nta_outgoing_t *ack;
    msg_t *msg;
    sip_t *osip;

    TEST_1(msg = nta_outgoing_getrequest_ref(orq));
    TEST_1(osip = sip_object(msg));

    TEST(nta_leg_rtag(ag->ag_call_leg, sip->sip_to->a_tag), 0);
    
    TEST(nta_leg_client_route(ag->ag_call_leg, 
			      sip->sip_record_route,
			      sip->sip_contact), 0);

    ack = nta_outgoing_tcreate(ag->ag_call_leg, NULL, NULL,
			       NULL,
			       SIP_METHOD_ACK,
			       NULL,
			       SIPTAG_CSEQ(sip->sip_cseq),
			       NTATAG_ACK_BRANCH(osip->sip_via->v_branch),
			       TAG_END());
    TEST_1(ack);
    nta_outgoing_destroy(ack);
  }
  else {
    ag->ag_status = status;
  }

  TEST_1(sip->sip_to && sip->sip_to->a_tag);

  nta_outgoing_destroy(orq);
  ag->ag_orq = NULL;
  ag->ag_call_leg = NULL;

  END();
}


/*
 * Test establishing a call with an early dialog / 100 rel / timeout
 *
 * Alice sends a INVITE to Bob, then Bob sends 183, Alice sends PRACK,
 * Bob sends 200 to PRACK, Bob sends 200 to INVITE.
 * Bob sends BYE, Alice 200.
 */

int test_prack(agent_t *ag)
{
  sip_content_type_t *c = ag->ag_content_type;
  sip_payload_t      *sdp = ag->ag_payload;
  nta_leg_t *old_leg;

  BEGIN();

  {
    /* Send a PRACK from default leg, NTA responds to it with error */
    url_t url[1];

    *url = *ag->ag_aliases->m_url;
    url->url_user = "bob";

    ag->ag_expect_leg = ag->ag_server_leg;
    ag->ag_latest_leg = NULL;
    TEST_1(ag->ag_orq = 
	  nta_outgoing_tcreate(ag->ag_default_leg, outgoing_callback, ag,
			       ag->ag_obp,
			       SIP_METHOD_PRACK,
			       (url_string_t *)url,
			       SIPTAG_SUBJECT_STR("Test 1.1"),
			       SIPTAG_FROM(ag->ag_alice),
			       SIPTAG_TO(ag->ag_bob),
			       SIPTAG_CONTACT(ag->ag_m_alice),
			       SIPTAG_RACK_STR("1432432 42332432 INVITE"),
			       TAG_END()));
    nta_test_run(ag);
    TEST(ag->ag_status, 481);
    TEST(ag->ag_orq, NULL);
    TEST(ag->ag_latest_leg, NULL);
  }

  TEST_1(ag->ag_alice_leg = nta_leg_tcreate(ag->ag_agent, 
					   alice_leg_callback,
					   ag,
					   SIPTAG_FROM(ag->ag_alice),
					   SIPTAG_TO(ag->ag_bob),
					   TAG_END()));
  TEST(nta_leg_tag(ag->ag_alice_leg, NULL), 0);

  /* Send INVITE */
  nta_leg_bind(ag->ag_server_leg, bob_leg_callback2, ag);
  ag->ag_expect_leg = ag->ag_server_leg;
  TEST_1(ag->ag_orq = 
	nta_outgoing_tcreate(ag->ag_call_leg = ag->ag_alice_leg, 
			     invite_prack_callback, ag,
			     ag->ag_obp,
			     SIP_METHOD_INVITE,
			     (url_string_t *)ag->ag_m_bob->m_url,
			     SIPTAG_SUBJECT_STR("Call 2"),
			     SIPTAG_CONTACT(ag->ag_m_alice),
			     SIPTAG_REQUIRE_STR("100rel"),
			     SIPTAG_CONTENT_TYPE(c),
			     SIPTAG_PAYLOAD(sdp),
			     TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_tag_status, 183);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_server_leg);
  TEST_1(ag->ag_bob_leg != NULL);

  /* Send BYE from Bob to Alice */
  old_leg = ag->ag_expect_leg = ag->ag_alice_leg;
  TEST_1(ag->ag_orq = 
	nta_outgoing_tcreate(ag->ag_bob_leg, outgoing_callback, ag,
			     NULL,
			     SIP_METHOD_BYE,
			     NULL,
			     SIPTAG_SUBJECT_STR("Hangup"),
			     SIPTAG_FROM(ag->ag_alice),
			     SIPTAG_TO(ag->ag_bob),
			     SIPTAG_CONTACT(ag->ag_m_alice),
			     SIPTAG_CONTENT_TYPE(c),
			     SIPTAG_PAYLOAD(sdp),
			     TAG_END()));

  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, old_leg);
  TEST(ag->ag_alice_leg, NULL);

  nta_leg_destroy(ag->ag_bob_leg), ag->ag_bob_leg = NULL;
  ag->ag_latest_leg = NULL;
  ag->ag_call_leg = NULL;

  printf("%s: starting 100rel timeout test, test will complete in 4 seconds\n",
	 name);
  
  TEST(nta_agent_set_params(ag->ag_agent,
			    NTATAG_SIP_T1(25),
			    NTATAG_SIP_T1X64(64 * 25),
			    TAG_END()), 2);

  TEST_1(ag->ag_alice_leg = nta_leg_tcreate(ag->ag_agent, 
					   alice_leg_callback,
					   ag,
					   SIPTAG_FROM(ag->ag_alice),
					   SIPTAG_TO(ag->ag_bob),
					   TAG_END()));
  TEST(nta_leg_tag(ag->ag_alice_leg, NULL), 0);

  /* Send INVITE, 
   * send precious provisional response
   * do not send PRACK, 
   * timeout (after 64 * t1 ~ 3.2 seconds),
   */
  nta_leg_bind(ag->ag_server_leg, bob_leg_callback2, ag);
  ag->ag_expect_leg = ag->ag_server_leg;
  TEST_1(ag->ag_orq = 
	 nta_outgoing_tcreate(ag->ag_call_leg = ag->ag_alice_leg, 
			      outgoing_callback, ag,
			      ag->ag_obp,
			      SIP_METHOD_INVITE,
			      (url_string_t *)ag->ag_m_bob->m_url,
			      SIPTAG_SUBJECT_STR("Call 3"),
			      SIPTAG_CONTACT(ag->ag_m_alice),
			      SIPTAG_REQUIRE_STR("100rel"),
			      SIPTAG_CONTENT_TYPE(c),
			      SIPTAG_PAYLOAD(sdp),
			      TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 503);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_server_leg);
  TEST_1(ag->ag_bob_leg == NULL);

  TEST(nta_agent_set_params(ag->ag_agent, 
			    NTATAG_SIP_T1(500), 
			    NTATAG_SIP_T1X64(64 * 500), 
			    TAG_END()), 2);

  END();

  nta_leg_destroy(ag->ag_bob_leg), ag->ag_bob_leg = NULL;
  ag->ag_latest_leg = NULL;
  ag->ag_call_leg = NULL;
  ag->ag_call_tag = NULL;
}

int alice_leg_callback2(agent_t *ag,
			nta_leg_t *leg,
			nta_incoming_t *irq,
			sip_t const *sip)
{
  BEGIN();

  if (tstflags & tst_verbatim) {
    printf("%s: %s: %s " URL_PRINT_FORMAT " %s\n",
	   name, __func__, sip->sip_request->rq_method_name, 
	   URL_PRINT_ARGS(sip->sip_request->rq_url),
	   sip->sip_request->rq_version);
  }

  TEST_1(sip->sip_content_length);
  TEST_1(sip->sip_via);
  TEST_1(sip->sip_from && sip->sip_from->a_tag);

  if (sip->sip_request->rq_method == sip_method_prack)
    return 481;

  ag->ag_latest_leg = leg;

  if (leg != ag->ag_alice_leg) {
    leg_match(ag, leg, 1, __func__);
    return 500;
  }

  if (sip->sip_request->rq_method == sip_method_invite) {
    TEST_1(sip_has_feature(sip->sip_supported, "100rel"));
    nta_incoming_bind(irq, test_for_ack, ag);
    nta_incoming_treply(irq, SIP_100_TRYING, TAG_END());

    nta_agent_set_params(ag->ag_agent, 
			 NTATAG_DEBUG_DROP_PROB(ag->ag_drop),
			 TAG_END());
    ag->ag_reliable = 
      nta_reliable_treply(irq,
			  NULL, NULL,
			  SIP_183_SESSION_PROGRESS,
			  SIPTAG_CONTENT_TYPE(ag->ag_content_type),
			  SIPTAG_PAYLOAD(ag->ag_payload),
			  SIPTAG_CONTACT(ag->ag_m_alice),
			  TAG_END());
    TEST_1(ag->ag_reliable);
    ag->ag_reliable = 
      nta_reliable_treply(irq,
			  NULL, NULL,
			  184, "Next",
			  SIPTAG_CONTACT(ag->ag_m_alice),
			  TAG_END());
    TEST_1(ag->ag_reliable);
    ag->ag_reliable = 
      nta_reliable_treply(irq,
			  NULL, NULL,
			  185, "Last",
			  SIPTAG_CONTACT(ag->ag_m_alice),
			  TAG_END());
    TEST_1(ag->ag_reliable);
    TEST(nta_incoming_treply(irq, SIP_200_OK, TAG_END()), 0);
    ag->ag_irq = irq;
    return 0;
  } 

  if (sip->sip_request->rq_method == sip_method_bye) {
    leg_zap(ag, leg);
  }

  return 200;

  END();
}
/*
 * Test establishing a call with an early dialog / 100 rel / timeout
 *
 * Alice sends a INVITE to Bob, then Bob sends 183, 184, 185, and 200.
 * Bob sends BYE, Alice 200.
 *
 * See bug #467.
 */
int test_fix_467(agent_t *ag)
{
  sip_content_type_t *c = ag->ag_content_type;
  sip_payload_t      *sdp = ag->ag_payload;
  nta_leg_t *old_leg;

  BEGIN();

  TEST_1(ag->ag_alice_leg = nta_leg_tcreate(ag->ag_agent, 
					    alice_leg_callback2,
					    ag,
					    SIPTAG_FROM(ag->ag_alice),
					    SIPTAG_TO(ag->ag_bob),
					    TAG_END()));
  TEST(nta_leg_tag(ag->ag_alice_leg, NULL), 0);
  ag->ag_bob_leg = NULL;
  ag->ag_call_tag = NULL;

  /* Send INVITE */
  nta_leg_bind(ag->ag_server_leg, bob_leg_callback2, ag);
  ag->ag_expect_leg = ag->ag_server_leg;
  TEST_1(ag->ag_orq = 
	nta_outgoing_tcreate(ag->ag_call_leg = ag->ag_alice_leg, 
			     invite_prack_callback, ag,
			     ag->ag_obp,
			     SIP_METHOD_INVITE,
			     (url_string_t *)ag->ag_m_bob->m_url,
			     SIPTAG_SUBJECT_STR("Call 5"),
			     SIPTAG_CONTACT(ag->ag_m_alice),
			     SIPTAG_REQUIRE_STR("100rel"),
			     SIPTAG_CONTENT_TYPE(c),
			     SIPTAG_PAYLOAD(sdp),
			     TAG_END()));
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_tag_status, 183);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, ag->ag_server_leg);
  TEST_1(ag->ag_bob_leg != NULL);

  /* Send BYE from Bob to Alice */
  old_leg = ag->ag_expect_leg = ag->ag_alice_leg;
  TEST_1(ag->ag_orq = 
	nta_outgoing_tcreate(ag->ag_bob_leg, outgoing_callback, ag,
			     NULL,
			     SIP_METHOD_BYE,
			     NULL,
			     SIPTAG_SUBJECT_STR("Hangup"),
			     SIPTAG_FROM(ag->ag_alice),
			     SIPTAG_TO(ag->ag_bob),
			     SIPTAG_CONTACT(ag->ag_m_alice),
			     SIPTAG_CONTENT_TYPE(c),
			     SIPTAG_PAYLOAD(sdp),
			     TAG_END()));

  
  nta_test_run(ag);
  TEST(ag->ag_status, 200);
  TEST(ag->ag_orq, NULL);
  TEST(ag->ag_latest_leg, old_leg);
  TEST(ag->ag_alice_leg, NULL);

  END();

  nta_leg_destroy(ag->ag_bob_leg), ag->ag_bob_leg = NULL;
  ag->ag_latest_leg = NULL;
  ag->ag_call_leg = NULL;
}

int test_nta(agent_t *ag)
{
  BEGIN();
  END();
}

static int test_dialog_matching(void)
{
  nta_agent_t *nta;
  su_root_t *root;
  su_home_t home[1];
  nta_leg_t *leg, *dialog1, *dialog2, *dst, *defdst;
  sip_from_t *a1, *a2;
  sip_call_id_t *i;

  BEGIN();

  memset(home, 0, sizeof home);
  home->suh_size = sizeof home;
  su_home_init(home);

  TEST_1(root = su_root_create(NULL));

  TEST_1(nta = nta_agent_create(root,
				(url_string_t *)"sip:*:*",
				NULL,
				NULL,
				TAG_END()));

  TEST_1(dst = nta_leg_tcreate(nta, NULL, NULL, 
				NTATAG_NO_DIALOG(1),
				URLTAG_URL("sip:joe@localhost"),
				TAG_END()));

  TEST_1(defdst = nta_leg_tcreate(nta, NULL, NULL, 
				  NTATAG_NO_DIALOG(1),
				  TAG_END()));

  TEST_1(dialog1 = 
	 nta_leg_tcreate(nta, NULL, NULL, 
			 URLTAG_URL("sip:pc.al.us"),
			 SIPTAG_CALL_ID_STR("foobarbaz"),
			 /* local */
			 SIPTAG_FROM_STR("<sip:me.myself.i@foo.com>;tag=foo"),
			 /* remote */
			 SIPTAG_TO_STR("<sip:joe.boy@al.us>"),
			 TAG_END()));

  TEST_1(a1 = sip_from_make(home, "<sip:me.myself.i@foo.com>;tag=foo"));
  TEST_1(a2 = sip_from_make(home, "<sip:joe.boy@al.us>;tag=al"));
  TEST_1(i = sip_call_id_make(home, "foobarbaz"));

  TEST_1(dialog2 = 
	 nta_leg_tcreate(nta, NULL, NULL, 
			 SIPTAG_CALL_ID(i),
			 /* local */
			 SIPTAG_FROM(a2),
			 /* remote */
			 SIPTAG_TO(a1),
			 TAG_END()));

  TEST_1(!nta_leg_by_dialog(nta, NULL, NULL, 
			    a1->a_tag, a1->a_url, a2->a_tag, a2->a_url));
  TEST_1(!nta_leg_by_dialog(NULL, NULL, i, 
			    a1->a_tag, a1->a_url, a2->a_tag, a2->a_url));
  TEST_1(!nta_leg_by_dialog(nta, (void *)"sip:no.such.url", i, 
			    a2->a_tag, a2->a_url, a1->a_tag, a1->a_url));
  TEST_1(!nta_leg_by_dialog(nta, a2->a_url, i, 
			    a2->a_tag, a2->a_url, a1->a_tag, a1->a_url));

  TEST(leg = nta_leg_by_dialog(nta, NULL, i, 
			       /* local */ a1->a_tag, a1->a_url, 
			       /* remote */ a2->a_tag, a2->a_url),
       dialog2);
  TEST(leg = nta_leg_by_dialog(nta, (void *)"sip:no.such.url", i, 
			       /* local */ a1->a_tag, a1->a_url, 
			       /* remote */ a2->a_tag, a2->a_url),
       dialog2);
  TEST(leg = nta_leg_by_dialog(nta, a2->a_url, i, 
			       a1->a_tag, a1->a_url, a2->a_tag, a2->a_url),
       dialog2);

  TEST(leg = nta_leg_by_dialog(nta, NULL, i, 
			       a2->a_tag, a2->a_url, a1->a_tag, a1->a_url),
       dialog1);
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, a1->a_tag, a1->a_url),
       dialog1);
  /* local tag is required because there is tag */
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, "xyzzy", a1->a_url),
       NULL);
  /* local URI is ignored because we have tag */
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, a1->a_tag, a2->a_url),
       dialog1);

  /* remote tag is ignored because there is no tag */
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       "xyzzy", a2->a_url, a1->a_tag, a1->a_url),
       dialog1);
  /* remote url is required */
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a1->a_url, a1->a_tag, a1->a_url),
       NULL);
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, NULL, a1->a_tag, a1->a_url),
       dialog1);

  /* local url is used if there is no local tag */
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, NULL, NULL),
       NULL);

  nta_leg_tag(dialog1, "al");
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, a1->a_tag, a1->a_url),
       dialog1);
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, "xyzzy", a1->a_url),
       NULL);
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, a1->a_tag, a1->a_url),
       dialog1);
  TEST(leg = nta_leg_by_dialog(nta, (url_t *)"sip:pc.al.us", i, 
			       a2->a_tag, a2->a_url, NULL, a1->a_url),
       NULL);
		
  nta_leg_destroy(defdst);
  nta_leg_destroy(dst);
  nta_leg_destroy(dialog1);
  nta_leg_destroy(dialog2);
	    
  TEST_VOID(nta_agent_destroy(nta)); 
  TEST_VOID(su_root_destroy(root));
  TEST_VOID(su_home_deinit(home));

  END();

}

/** Test API for errors */
static int test_api_errors(void)
{
  nta_agent_t *nta;
  su_root_t *root;
  su_home_t home[1];

  BEGIN();

  memset(home, 0, sizeof home);
  home->suh_size = sizeof home;
  su_home_init(home);

  TEST(nta_agent_create(NULL,
			(url_string_t *)"sip:*:*",
			NULL,
			NULL,
			TAG_END()), NULL);

  TEST_1(root = su_root_create(NULL));

  TEST(nta_agent_create(root,
			(url_string_t *)"http://localhost:*/invalid/bind/url",
			NULL,
			NULL,
			TAG_END()), NULL);

  TEST(nta_agent_create(root,
			(url_string_t *)"sip:*:*;transport=XXX",
			NULL,
			NULL,
			TAG_END()), NULL);

  TEST_1(nta = nta_agent_create(root,
				(url_string_t *)"sip:*:*",
				NULL,
				NULL,
				TAG_END()));

  TEST_VOID(nta_agent_destroy(NULL));
  TEST_VOID(nta_agent_destroy(nta));

  TEST_1(nta = nta_agent_create(root,
				(url_string_t *)"sip:*:*",
				NULL,
				(void *)test_api_errors,
				TAG_END()));

  TEST(nta_agent_contact(NULL), NULL);
  TEST(nta_agent_via(NULL), NULL);
  TEST_S(nta_agent_version(nta), nta_agent_version(NULL));
  TEST(nta_agent_magic(NULL), NULL);
  TEST(nta_agent_magic(nta), (void *)test_api_errors);
  TEST(nta_agent_add_tport(NULL, NULL, TAG_END()), -1);
  TEST(nta_agent_newtag(home, "tag=%s", NULL), NULL);
  TEST_1(nta_agent_newtag(home, "tag=%s", nta));
  {
    unsigned preload = 0;
    char const *s = NULL;
#if HAVE_SIGCOMP
    int have_sigcomp = 1;
#else
    int have_sigcomp = 0;
#endif

    TEST(nta_agent_set_params(NULL, 
			      NTATAG_PRELOAD(2048),
			      TAG_END()), -1);
    TEST(nta_agent_set_params(nta, 
			      NTATAG_PRELOAD(2048),
			      TAG_END()), 1);

    TEST(nta_agent_set_params(nta, 
			      NTATAG_SIGCOMP_OPTIONS("sip"),
			      TAG_END()), have_sigcomp);
    TEST(nta_agent_set_params(nta, 
			      NTATAG_SIGCOMP_OPTIONS(","),
			      TAG_END()), -have_sigcomp);

    TEST(nta_agent_get_params(NULL, 
			      NTATAG_PRELOAD_REF(preload),
			      TAG_END()), -1);
    TEST(nta_agent_get_params(nta, 
			      NTATAG_PRELOAD_REF(preload),
			      TAG_END()), 1);
    TEST(preload, 2048);
    TEST(nta_agent_set_params(nta, 
			      NTATAG_SIGCOMP_OPTIONS("sip;dms=16384"),
			      TAG_END()), have_sigcomp);
    TEST(nta_agent_get_params(nta, 
			      NTATAG_SIGCOMP_OPTIONS_REF(s),
			      TAG_END()), have_sigcomp);
    if (have_sigcomp)
      TEST_S(s, "sip;dms=16384");
  }

  {
    uint32_t irq_hash = -1, orq_hash = -1, leg_hash = -1;
    uint32_t recv_msg = -1, sent_msg = -1;
    uint32_t recv_request = -1, recv_response = -1;
    uint32_t bad_message = -1, bad_request = -1, bad_response = -1;
    uint32_t drop_request = -1, drop_response = -1;
    uint32_t client_tr = -1, server_tr = -1, dialog_tr = -1;
    uint32_t acked_tr = -1, canceled_tr = -1;
    uint32_t trless_request = -1, trless_to_tr = -1, trless_response = -1;
    uint32_t trless_200 = -1, merged_request = -1;
    uint32_t sent_request = -1, sent_response = -1;
    uint32_t retry_request = -1, retry_response = -1, recv_retry = -1;
    uint32_t tout_request = -1, tout_response = -1;

    TEST(nta_agent_get_stats(NULL,
			     NTATAG_S_TOUT_REQUEST_REF(tout_request),
			     NTATAG_S_TOUT_RESPONSE_REF(tout_response),
			     TAG_END()), -1);

    TEST(nta_agent_get_stats(nta,
			     NTATAG_S_IRQ_HASH_REF(irq_hash),
			     NTATAG_S_ORQ_HASH_REF(orq_hash),
			     NTATAG_S_LEG_HASH_REF(leg_hash),
			     NTATAG_S_RECV_MSG_REF(recv_msg),
			     NTATAG_S_SENT_MSG_REF(sent_msg),
			     NTATAG_S_RECV_REQUEST_REF(recv_request),
			     NTATAG_S_RECV_RESPONSE_REF(recv_response),
			     NTATAG_S_BAD_MESSAGE_REF(bad_message),
			     NTATAG_S_BAD_REQUEST_REF(bad_request),
			     NTATAG_S_BAD_RESPONSE_REF(bad_response),
			     NTATAG_S_DROP_REQUEST_REF(drop_request),
			     NTATAG_S_DROP_RESPONSE_REF(drop_response),
			     NTATAG_S_CLIENT_TR_REF(client_tr),
			     NTATAG_S_SERVER_TR_REF(server_tr),
			     NTATAG_S_DIALOG_TR_REF(dialog_tr),
			     NTATAG_S_ACKED_TR_REF(acked_tr),
			     NTATAG_S_CANCELED_TR_REF(canceled_tr),
			     NTATAG_S_TRLESS_REQUEST_REF(trless_request),
			     NTATAG_S_TRLESS_TO_TR_REF(trless_to_tr),
			     NTATAG_S_TRLESS_RESPONSE_REF(trless_response),
			     NTATAG_S_TRLESS_200_REF(trless_200),
			     NTATAG_S_MERGED_REQUEST_REF(merged_request),
			     NTATAG_S_SENT_REQUEST_REF(sent_request),
			     NTATAG_S_SENT_RESPONSE_REF(sent_response),
			     NTATAG_S_RETRY_REQUEST_REF(retry_request),
			     NTATAG_S_RETRY_RESPONSE_REF(retry_response),
			     NTATAG_S_RECV_RETRY_REF(recv_retry),
			     NTATAG_S_TOUT_REQUEST_REF(tout_request),
			     NTATAG_S_TOUT_RESPONSE_REF(tout_response),
			     TAG_END()), 29);
    TEST_1(irq_hash == HTABLE_MIN_SIZE);
    TEST_1(orq_hash == HTABLE_MIN_SIZE);
    TEST_1(leg_hash == HTABLE_MIN_SIZE);
    TEST_1(recv_msg == 0);
    TEST_1(sent_msg == 0);
    TEST_1(recv_request == 0);
    TEST_1(recv_response == 0);
    TEST_1(bad_message == 0);
    TEST_1(bad_request == 0);
    TEST_1(bad_response == 0);
    TEST_1(drop_request == 0);
    TEST_1(drop_response == 0);
    TEST_1(client_tr == 0);
    TEST_1(server_tr == 0);
    TEST_1(dialog_tr == 0);
    TEST_1(acked_tr == 0);
    TEST_1(canceled_tr == 0);
    TEST_1(trless_request == 0);
    TEST_1(trless_to_tr == 0);
    TEST_1(trless_response == 0);
    TEST_1(trless_200 == 0);
    TEST_1(merged_request == 0);
    TEST_1(sent_request == 0);
    TEST_1(sent_response == 0);
    TEST_1(retry_request == 0);
    TEST_1(retry_response == 0);
    TEST_1(recv_retry == 0);
    TEST_1(tout_request == 0);
    TEST_1(tout_response == 0);
  }			     

  {
    msg_t *msg;
    TEST_1(nta_msg_create(NULL, 0) == NULL);
    TEST_VOID(nta_msg_discard(NULL, NULL));
    TEST(nta_msg_complete(NULL), -1);

    TEST(nta_msg_response_complete(NULL, NULL, 800, "foo"), -1);
    TEST(nta_msg_request_complete(NULL, NULL, sip_method_unknown, "FOO", NULL), -1);
    TEST_1(msg = nta_msg_create(nta, 0));
    TEST(nta_msg_complete(msg), -1);
    TEST(nta_msg_response_complete(msg, NULL, 800, "foo"), -1);
    TEST(nta_msg_request_complete(msg, NULL, sip_method_unknown, "FOO", NULL), -1);
    TEST(nta_is_internal_msg(NULL), 0);
    TEST(nta_is_internal_msg(msg), 0);
    TEST_1(msg_set_flags(msg, NTA_INTERNAL_MSG));
    TEST(nta_is_internal_msg(msg), 1);
    TEST_VOID(nta_msg_discard(nta, msg));
  }

  TEST(nta_leg_tcreate(NULL, NULL, NULL, TAG_END()), NULL);
  TEST_VOID(nta_leg_destroy(NULL));
  TEST(nta_leg_magic(NULL, NULL), NULL);
  TEST_VOID(nta_leg_bind(NULL, NULL, NULL));
  TEST(nta_leg_tag(NULL, "fidsafsa"), -1);
  TEST(nta_leg_get_tag(NULL), NULL);
  TEST(nta_leg_client_route(NULL, NULL, NULL), -1);
  TEST(nta_leg_server_route(NULL, NULL, NULL), -1);
  TEST(nta_leg_by_uri(NULL, NULL), NULL);
  TEST(nta_leg_by_dialog(NULL,  NULL, NULL, NULL, NULL, NULL, NULL), NULL);
  TEST(nta_leg_by_dialog(nta, NULL, NULL, NULL, NULL, NULL, NULL), NULL);

  TEST(nta_outgoing_tmcreate(NULL, NULL, NULL, NULL, NULL, TAG_END()), NULL);
  TEST(nta_outgoing_tcancel(NULL, NULL, NULL, TAG_END()), NULL);
  TEST(nta_outgoing_method_name(NULL), NULL);
  TEST(nta_outgoing_getresponse_ref(NULL), NULL);
  TEST(nta_outgoing_getrequest(NULL), NULL);
  TEST(nta_outgoing_getrequest_ref(NULL), NULL);

#if 0
void nta_incoming_bind(nta_incoming_t *irq, 
		       nta_ack_cancel_f *callback,
		       nta_incoming_magic_t *imagic);

nta_incoming_magic_t *nta_incoming_magic(nta_incoming_t *irq, 
					 nta_ack_cancel_f *callback);

nta_incoming_t *nta_incoming_find(nta_agent_t const *agent, 
				  sip_t const *sip,
				  sip_via_t const *v);

int nta_incoming_tag(nta_incoming_t *irq, char const *tag);

int nta_incoming_status(nta_incoming_t const *irq);
sip_method_t nta_incoming_method(nta_incoming_t const *irq);
url_t const *nta_incoming_url(nta_incoming_t const *irq);
sip_u32_t nta_incoming_cseq(nta_incoming_t const *irq);

msg_t *nta_incoming_getrequest(nta_incoming_t *irq);
msg_t *nta_incoming_getresponse(nta_incoming_t *irq);

int nta_incoming_treply(nta_incoming_t *ireq, 
			int status, char const *phrase, 
			tag_type_t tag, tag_value_t value, ...);

int nta_incoming_mreply(nta_incoming_t *irq, msg_t *msg);

void nta_incoming_destroy(nta_incoming_t *irq);

/* ----------------------------------------------------------------------
 * 7) Prototypes for outgoing transactions
 */
typedef int nta_response_f(nta_outgoing_magic_t *magic,
			   nta_outgoing_t *request,
			   sip_t const *sip);

nta_outgoing_t *nta_outgoing_tcreate(nta_leg_t *leg,
				     nta_response_f *callback,
				     nta_outgoing_magic_t *magic,
				     url_string_t const *route_url,
				     sip_method_t method,
				     char const *method_name,
				     url_string_t const *request_uri,
				     tag_type_t tag, tag_value_t value, ...);

nta_outgoing_t *nta_outgoing_tmcreate(nta_agent_t *agent,
				      nta_response_f *callback,
				      nta_outgoing_magic_t *magic,
				      url_string_t const *route_url,
				      msg_t *msg,
				      tag_type_t tag, tag_value_t value, ...);

nta_outgoing_t *nta_outgoing_mcreate(nta_agent_t *agent,
				     nta_response_f *callback,
				     nta_outgoing_magic_t *magic,
				     url_string_t const *route_url, 
				     msg_t *msg);

int nta_outgoing_status(nta_outgoing_t const *orq);
sip_method_t nta_outgoing_method(nta_outgoing_t const *orq);
sip_u32_t nta_outgoing_cseq(nta_outgoing_t const *orq);

unsigned nta_outgoing_delay(nta_outgoing_t const *orq);

url_t const *nta_outgoing_request_uri(nta_outgoing_t const *orq);
url_t const *nta_outgoing_route_uri(nta_outgoing_t const *orq);

msg_t *nta_outgoing_getresponse(nta_outgoing_t *orq);
msg_t *nta_outgoing_getrequest(nta_outgoing_t *orq);

nta_outgoing_t *nta_outgoing_tagged(nta_outgoing_t *orq, 
				    nta_response_f *callback,
				    nta_outgoing_magic_t *magic,
				    sip_param_t to_tag,
				    sip_rseq_t const *rseq);

int nta_outgoing_cancel(nta_outgoing_t *);

nta_outgoing_t *nta_outgoing_tcancel(nta_outgoing_t *orq, 
				     nta_response_f *callback,
				     nta_outgoing_magic_t *magic,
				     tag_type_t, tag_value_t, ...);

void nta_outgoing_destroy(nta_outgoing_t *);

nta_outgoing_t *nta_outgoing_find(nta_agent_t const *sa,
				  msg_t const *msg,
				  sip_t const *sip, 
				  sip_via_t const *v);

nta_outgoing_t *nta_outgoing_prack(nta_leg_t *leg,
				   nta_outgoing_t *oorq,
				   nta_response_f *callback,
				   nta_outgoing_magic_t *magic,
				   url_string_t const *route_url,
				   sip_t const *response_to_prack,
				   tag_type_t, tag_value_t, ...);

nta_reliable_t *nta_reliable_treply(nta_incoming_t *ireq,
				    nta_prack_f *callback,
				    nta_reliable_magic_t *rmagic,
				    int status, char const *phrase, 
				    tag_type_t tag, 
				    tag_value_t value, ...);

nta_reliable_t *nta_reliable_mreply(nta_incoming_t *irq, 
				    nta_prack_f *callback,
				    nta_reliable_magic_t *rmagic,
				    msg_t *msg);

void nta_reliable_destroy(nta_reliable_t *);

#endif  

  TEST_VOID(nta_agent_destroy(nta)); 
  TEST_VOID(su_root_destroy(root));
  TEST_VOID(su_home_deinit(home));

  END();
}

void usage(void)
{
  fprintf(stderr, 
	  "usage: %s [-v|-q] [-l level] [-p outbound-proxy-uri]\n", 
	  name);
  exit(1);
}

int main(int argc, char *argv[])
{
  int retval = 0, quit_on_single_failure = 0;
  int i, o_attach = 0;

  agent_t ag[1] = {{ { SU_HOME_INIT(ag) }, 0, NULL }};

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-q") == 0)
      tstflags &= ~tst_verbatim;
    else if (strcmp(argv[i], "-1") == 0)
      quit_on_single_failure = 1;
    else if (strncmp(argv[i], "-l", 2) == 0) {
      int level = 3;
      char *rest = NULL;

      if (argv[i][2])
	level = strtol(argv[i] + 2, &rest, 10);
      else if (argv[i + 1])
	level = strtol(argv[i + 1], &rest, 10), i++;
      else
	level = 3, rest = "";

      if (rest == NULL || *rest)
	usage();
      
      su_log_set_level(nta_log, level);
      su_log_set_level(tport_log, level);
    }
    else if (strncmp(argv[i], "-p", 2) == 0) {
      if (argv[i][2])
	ag->ag_obp = (url_string_t *)(argv[i] + 2);
      else if (argv[i + 1])
	ag->ag_obp = (url_string_t *)(argv[++i]);
      else
	usage();
    }
    else if (strncmp(argv[i], "-m", 2) == 0) {
      if (argv[i][2])
	ag->ag_m = argv[i] + 2;
      else if (argv[i + 1])
	ag->ag_m = argv[++i];
      else
	usage();
    }
    else if (strcmp(argv[i], "--attach") == 0) {
      o_attach = 1;
    }
    else if (strcmp(argv[i], "-") == 0) {
      i++; break;
    }
    else if (argv[i][0] != '-') {
      break;
    }
    else
      usage();
  }

  if (o_attach) {
    char line[10];
    printf("nua_test: pid %u\n", getpid());
    printf("<Press RETURN to continue>\n");
    fgets(line, sizeof line, stdin);
  }

  su_init();

  if (!(TSTFLAGS & tst_verbatim)) {
    su_log_soft_set_level(nta_log, 0);
    su_log_soft_set_level(tport_log, 0);
  }

#define SINGLE_FAILURE_CHECK()						\
  do { if (retval && quit_on_single_failure) { su_deinit(); return retval; } \
  } while(0)

  retval |= test_api_errors(); SINGLE_FAILURE_CHECK();
  retval |= test_dialog_matching(); SINGLE_FAILURE_CHECK();

  retval |= test_init(ag, argv[i]); fflush(stdout); SINGLE_FAILURE_CHECK();
  if (retval == 0) {
    retval |= test_tports(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_resolv(ag, argv[i]); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_routing(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_dialog(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_call(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_prack(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_fix_467(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
    retval |= test_nta(ag); fflush(stdout); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ag); fflush(stdout); 

  su_deinit();

  return retval;
}
