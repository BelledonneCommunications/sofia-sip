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

/**@CFILE test_proxy.c
 * @brief Extremely simple proxy and registrar for testing nua
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Thu Nov  3 22:49:46 EET 2005
 */

#include "config.h"

#include <string.h>

struct proxy;
struct proxy_transaction;
struct registration_entry;

#define SU_ROOT_MAGIC_T struct proxy
#define NTA_LEG_MAGIC_T struct proxy
#define NTA_OUTGOING_MAGIC_T struct proxy_transaction
#define NTA_INCOMING_MAGIC_T struct proxy_transaction

#include <sofia-sip/su_wait.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/auth_module.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/msg_addr.h>

#include <stdlib.h>
#include <assert.h>

#define LIST_PROTOS(STORAGE, PREFIX, T)			 \
STORAGE void PREFIX ##_insert(T **list, T *node),	 \
        PREFIX ##_remove(T *node)			 

#define LIST_BODIES(STORAGE, PREFIX, T, NEXT, PREV)	  \
STORAGE void PREFIX ##_insert(T **list, T *node)   \
{							 \
  if ((node->NEXT = *list)) {				 \
    node->PREV = node->NEXT->PREV;			 \
    node->NEXT->PREV = &node->NEXT;			 \
  }							 \
  else							 \
    node->PREV = list;					 \
  *list = node;						 \
}							 \
STORAGE void PREFIX ##_remove(T *node)			 \
{							 \
  if (node->PREV)					 \
    if ((*node->PREV = node->NEXT))			 \
      node->NEXT->PREV = node->PREV;			 \
  node->PREV = NULL;					 \
}							 \
extern int LIST_DUMMY_VARIABLE

#include <test_proxy.h>

struct proxy {
  su_home_t    home[1];
  su_root_t   *parent;
  su_clone_r   clone;
  tagi_t      *tags;

  su_root_t   *root;
  auth_mod_t  *auth;
 
  nta_agent_t *agent;
  url_t const *uri;
  
  nta_leg_t *defleg;

  nta_leg_t *example_net;
  nta_leg_t *example_org;
  nta_leg_t *example_com;

  sip_contact_t *transport_contacts;

  struct proxy_transaction *stateless;
  struct proxy_transaction *transactions;
  struct registration_entry *entries;
};

LIST_PROTOS(static, registration_entry, struct registration_entry);
static struct registration_entry *
registration_entry_new(struct proxy *, url_t const *);
static void registration_entry_destroy(struct registration_entry *e);

struct registration_entry
{
  struct registration_entry *next, **prev;
  struct proxy *proxy;		/* backpointer */
  url_t *aor;			/* address-of-record */
  sip_contact_t *binding;	/* bindings */
};

LIST_PROTOS(static, proxy_transaction, struct proxy_transaction);
struct proxy_transaction *proxy_transaction_new(struct proxy *);
static void proxy_transaction_destroy(struct proxy_transaction *t);

struct proxy_transaction
{
  struct proxy_transaction *next, **prev;

  struct proxy *proxy;		/* backpointer */
  sip_request_t *rq;		/* request line */
  nta_incoming_t *server;	/* server transaction */
  nta_outgoing_t *client;	/* client transaction */
};

static sip_contact_t *create_transport_contacts(struct proxy *p);

static int proxy_request(struct proxy *proxy,
			 nta_leg_t *leg,
			 nta_incoming_t *irq,
			 sip_t const *sip);

static int proxy_ack_cancel(struct proxy_transaction *t,
			    nta_incoming_t *irq,
			    sip_t const *sip);

static int proxy_response(struct proxy_transaction *t,
			  nta_outgoing_t *client,
			  sip_t const *sip);

static int process_register(struct proxy *proxy,
			    nta_incoming_t *irq,
			    sip_t const *sip);

static int domain_request(struct proxy *proxy,
			  nta_leg_t *leg,
			  nta_incoming_t *irq,
			  sip_t const *sip);

static int process_options(struct proxy *proxy,
			   nta_incoming_t *irq,
			   sip_t const *sip);

static struct registration_entry *
registration_entry_find(struct proxy const *proxy, url_t const *uri);

static
auth_challenger_t registrar_challenger[1];

/* Proxy entry point */
static int 
test_proxy_init(su_root_t *root, struct proxy *proxy)
{
  struct proxy_transaction *t;

  auth_challenger_t _registrar_challenger[1] = 
  {{ 
      SIP_401_UNAUTHORIZED,
      sip_www_authenticate_class,
      sip_authentication_info_class
    }};
  *registrar_challenger = *_registrar_challenger;

  proxy->root = root;

  proxy->auth = auth_mod_create(root, TAG_NEXT(proxy->tags));

  proxy->agent = nta_agent_create(root,
				  URL_STRING_MAKE("sip:0.0.0.0:*"),
				  NULL, NULL,
				  NTATAG_UA(0),
				  NTATAG_SERVER_RPORT(1),
				  NTATAG_CLIENT_RPORT(1),
				  TAG_END());

  proxy->transport_contacts = create_transport_contacts(proxy);

  proxy->defleg = nta_leg_tcreate(proxy->agent,
				  proxy_request,
				  proxy,
				  NTATAG_NO_DIALOG(1),
				  TAG_END());

  proxy->example_net = nta_leg_tcreate(proxy->agent,
				       domain_request,
				       proxy,
				       NTATAG_NO_DIALOG(1),
				       URLTAG_URL("sip:example.net"),
				       TAG_END());
  proxy->example_org = nta_leg_tcreate(proxy->agent,
				       domain_request,
				       proxy,
				       NTATAG_NO_DIALOG(1),
				       URLTAG_URL("sip:example.org"),
				       TAG_END());
  proxy->example_com = nta_leg_tcreate(proxy->agent,
				       domain_request,
				       proxy,
				       NTATAG_NO_DIALOG(1),
				       URLTAG_URL("sip:example.com"),
				       TAG_END());

  if (!proxy->defleg || 
      !proxy->example_net || !proxy->example_org || !proxy->example_com)
    return -1;

  t = su_zalloc(proxy->home, sizeof *t); 

  if (!t)
    return -1;

  proxy->stateless = t;
  t->proxy = proxy;
  t->server = nta_incoming_default(proxy->agent);
  t->client = nta_outgoing_default(proxy->agent, proxy_response, t);

  if (!t->client || !t->server)
    return -1;

  proxy->uri = nta_agent_contact(proxy->agent)->m_url;
				  
  return 0;
}

static void
test_proxy_deinit(su_root_t *root, struct proxy *proxy)
{
  struct proxy_transaction *t;
  
  auth_mod_destroy(proxy->auth);

  if ((t = proxy->stateless)) {
    nta_incoming_destroy(t->server), t->server = NULL;
    nta_outgoing_destroy(t->client), t->client = NULL;
  }

  nta_agent_destroy(proxy->agent);

  free(proxy->tags);
}

/* Create tst proxy object */
struct proxy *test_proxy_create(su_root_t *root,
				tag_type_t tag, tag_value_t value, ...)
{
  struct proxy *p = su_home_new(sizeof *p);

  if (p) {
    ta_list ta;

    p->parent = root;

    ta_start(ta, tag, value);
    p->tags = tl_llist(ta_tags(ta));
    ta_end(ta);
    
    if (su_clone_start(root,
		       p->clone,
		       p,
		       test_proxy_init,
		       test_proxy_deinit) == -1)
      su_home_unref(p->home), p = NULL;
  }

  return p;
}

/* Destroy the proxy object */
void test_proxy_destroy(struct proxy *p)
{
  if (p) {
    su_clone_wait(p->parent, p->clone);
    su_home_unref(p->home);
  }
}

/* Return the proxy URI */
url_t const *test_proxy_uri(struct proxy const *p)
{
  return p ? p->uri : NULL;
}

/* ---------------------------------------------------------------------- */

static sip_contact_t *create_transport_contacts(struct proxy *p)
{
  su_home_t *home = p->home;
  sip_via_t *v;
  sip_contact_t *retval = NULL, **mm = &retval;

  if (!p->agent)
    return NULL;

  for (v = nta_agent_via(p->agent); v; v = v->v_next) {
    char const *proto = v->v_protocol;

    if (v->v_next && 
	strcasecmp(v->v_host, v->v_next->v_host) == 0 &&
	str0cmp(v->v_port, v->v_next->v_port) == 0 &&
	((proto == sip_transport_udp &&
	  v->v_next->v_protocol == sip_transport_tcp) ||
	 (proto == sip_transport_tcp &&
	  v->v_next->v_protocol == sip_transport_udp)))
      /* We have udp/tcp pair, insert URL without tport parameter */
      *mm = sip_contact_create_from_via_with_transport(home, v, NULL, NULL);
    if (*mm) mm = &(*mm)->m_next;

    *mm = sip_contact_create_from_via_with_transport(home, v, NULL, proto);

    if (*mm) mm = &(*mm)->m_next;
  }

  return retval;
}

/* ---------------------------------------------------------------------- */

/** Forward request */
static
int proxy_request(struct proxy *proxy,
		  nta_leg_t *leg,
		  nta_incoming_t *irq,
		  sip_t const *sip)
{
  url_t const *request_uri, *target;
  struct proxy_transaction *t = NULL;
  sip_request_t *rq = NULL;

  /* We don't do any route processing */
  request_uri = sip->sip_request->rq_url;

  if (!request_uri->url_host || 
      (strcasecmp(request_uri->url_host, "example.org") &&
       strcasecmp(request_uri->url_host, "example.net") &&
       strcasecmp(request_uri->url_host, "example.com"))) {
    target = request_uri;
  }
  else {
    struct registration_entry *e;

    if (sip->sip_request->rq_method == sip_method_register) 
      return process_register(proxy, irq, sip);

    e = registration_entry_find(proxy, request_uri);
    if (e == NULL) {
      nta_incoming_treply(irq, SIP_404_NOT_FOUND, TAG_END());
      return 404;
    }
    target = e->binding->m_url;
  }

  t = proxy_transaction_new(proxy);
  if (t == NULL) {
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    return 500;
  }
  nta_incoming_bind(t->server = irq, proxy_ack_cancel, t);
  
  rq = sip_request_create(proxy->home,
			  sip->sip_request->rq_method,
			  sip->sip_request->rq_method_name,
			  (url_string_t *)target,
			  NULL);
  if (rq == NULL) {
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    proxy_transaction_destroy(t);
    return 500;
  }
  t->rq = rq;

  /* Forward request */
  t->client = nta_outgoing_mcreate(proxy->agent, proxy_response, t, NULL,
				   nta_incoming_getrequest(irq),
				   /* rewrite request */
				   SIPTAG_REQUEST(rq),
				   TAG_END());
  if (t->client == NULL) {
    proxy_transaction_destroy(t);
    nta_incoming_treply(irq, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    return 500;
  }
  else if (sip->sip_request->rq_method == sip_method_ack)
    proxy_transaction_destroy(t);

  return 0;
}

int proxy_ack_cancel(struct proxy_transaction *t,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  if (sip == NULL) {
    proxy_transaction_destroy(t);
    return 0;
  }

  if (sip->sip_request->rq_method == sip_method_cancel) {
    /* We don't care about response to CANCEL (or ACK)
     * so we give NULL as callback pointer (and nta immediately 
     * destroys transaction object or marks it disposable)
     */
    if (nta_outgoing_tcancel(t->client, NULL, NULL, TAG_END()))
      return 200;
    else
      return 500;
  }
  else {
    return 500;
  }
}

int proxy_response(struct proxy_transaction *t,
		   nta_outgoing_t *client,
		   sip_t const *sip)
{
  int final;

  if (sip) {
    msg_t *response = nta_outgoing_getresponse(client);
    final = sip->sip_status->st_status >= 200;
    sip_via_remove(response, sip_object(response));
    nta_incoming_mreply(t->server, response);
  }
  else {
    final = 1;
    nta_incoming_treply(t->server, SIP_408_REQUEST_TIMEOUT, TAG_END());
  }

  if (final)
    proxy_transaction_destroy(t);

  return 0;
}

struct proxy_transaction *
proxy_transaction_new(struct proxy *proxy)
{
  struct proxy_transaction *t;

  t = su_zalloc(proxy->home, sizeof *t);
  if (t) {
    t->proxy = proxy;
    proxy_transaction_insert(&proxy->transactions, t);
  }
  return t;
}

static
void proxy_transaction_destroy(struct proxy_transaction *t)
{
  if (t == t->proxy->stateless)
    return;
  proxy_transaction_remove(t);
  nta_incoming_destroy(t->server);
  nta_outgoing_destroy(t->client);
  su_free(t->proxy->home, t->rq);
  su_free(t->proxy->home, t);
}

LIST_BODIES(static, proxy_transaction, struct proxy_transaction, next, prev);

/* ---------------------------------------------------------------------- */

static

int domain_request(struct proxy *proxy,
		   nta_leg_t *leg,
		   nta_incoming_t *irq,
		   sip_t const *sip)
{
  sip_method_t method = sip->sip_request->rq_method;

  if (method == sip_method_register)
    return process_register(proxy, irq, sip);

  if (method == sip_method_options) 
    return process_options(proxy, irq, sip);

  return 501;
}

static
int process_options(struct proxy *proxy,
		    nta_incoming_t *irq,
		    sip_t const *sip)
{
  nta_incoming_treply(irq, SIP_200_OK,
		      SIPTAG_CONTACT(proxy->transport_contacts),
		      TAG_END());
  return 200;
}

/* ---------------------------------------------------------------------- */

static int check_unregister(sip_t const *sip);

int process_register(struct proxy *proxy,
		     nta_incoming_t *irq,
		     sip_t const *sip)
{
  auth_status_t *as;
  struct registration_entry *e;
  sip_contact_t *old_binding, *new_binding;
  int unregister;

  as = su_home_clone(proxy->home, (sizeof *as));
  as->as_status = 500, as->as_phrase = sip_500_Internal_server_error;

  as->as_method = sip->sip_request->rq_method_name;
  {
    msg_t *msg;
    msg = nta_incoming_getrequest(irq);
    as->as_source = msg_addrinfo(msg);
    msg_destroy(msg);
  }

  as->as_user_uri = sip->sip_from->a_url;
  as->as_display = sip->sip_from->a_display;

  if (sip->sip_payload)
    as->as_body = sip->sip_payload->pl_data,
      as->as_bodylen = sip->sip_payload->pl_len;

  auth_mod_check_client(proxy->auth, as, sip->sip_authorization,
			registrar_challenger);

  if (as->as_status != 0) {
    assert(as->as_status >= 300);
    nta_incoming_treply(irq,
			as->as_status, as->as_phrase,
			SIPTAG_HEADER((void *)as->as_info),
			SIPTAG_HEADER((void *)as->as_response),
			TAG_END());
    return as->as_status;
  }

  unregister = check_unregister(sip);

  e = registration_entry_find(proxy, sip->sip_to->a_url);

  if (unregister < 0)
    return 400;

  if (!e && unregister)
    return 200;
  
  if (unregister) {
    registration_entry_destroy(e);
    return 200;
  }

  if (!sip->sip_contact) {
    nta_incoming_treply(irq, SIP_200_OK,
			SIPTAG_CONTACT(e ? e->binding : NULL),
			TAG_END());
    return 200;
  }

  new_binding = sip_contact_dup(proxy->home, sip->sip_contact);
  if (!new_binding)
    return 500;

  if (!e) 
    e = registration_entry_new(proxy, sip->sip_to->a_url);

  old_binding = e->binding;
  e->binding = new_binding;

  msg_header_free(proxy->home, old_binding->m_common);
    
  nta_incoming_treply(irq, SIP_200_OK,
		      SIPTAG_CONTACT(new_binding),
		      TAG_END());
  return 200;
}

static
int check_unregister(sip_t const *sip)
{
  sip_time_t now = sip_now();
  sip_contact_t const *m;

  for (m = sip->sip_contact; m; m = m->m_next) {
    if (m->m_url->url_type == url_any) {
      /* "*" should be only contact, with Expires: 0 header */
      if (sip->sip_expires && 
	  sip->sip_expires->ex_delta == 0 && 
	  sip->sip_expires->ex_time == 0 &&
	  m == sip->sip_contact && m->m_next == NULL)
	return 1;		/* Unregister OK */
      else
	return -1;		/* Bad unregister */
    }

    if (!m->m_expires && !sip->sip_expires)
      return 0;
    else if (sip_contact_expires(m, sip->sip_expires, sip->sip_date,
				 3600, now) > 0)
      return 0;
  }
  
  return 1;
}

static struct registration_entry *
registration_entry_find(struct proxy const *proxy, url_t const *uri)
{
  struct registration_entry *e;

  /* Our routing table */
  for (e = proxy->entries; e; e = e->next) {
    if (url_cmp(uri, e->aor) == 0)
      return e;
  }
  return NULL;
}

static struct registration_entry *
registration_entry_new(struct proxy *proxy, url_t const *aor)
{
  struct registration_entry *e;

  e = su_zalloc(proxy->home, sizeof *e); 
  if (!e) 
    return NULL;

  e->proxy = proxy;
  e->aor = url_hdup(proxy->home, aor);
  if (!e->aor) {
    su_free(proxy->home, e);
    return NULL;
  }

  registration_entry_insert(&proxy->entries, e);

  return e;
}

static void
registration_entry_destroy(struct registration_entry *e)
{
  if (e) {
    registration_entry_remove(e);
    su_free(e->proxy->home, e->aor);
    msg_header_free(e->proxy->home, e->binding->m_common);
    su_free(e->proxy->home, e);
  }
}

LIST_BODIES(static, registration_entry, struct registration_entry, next, prev);
