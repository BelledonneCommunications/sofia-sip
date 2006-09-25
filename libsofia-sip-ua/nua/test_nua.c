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

/**@CFILE test_nua.c
 * @brief High-level tester for Sofia SIP User Agent Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti Mela@nokia.com>
 *
 * @date Created: Wed Aug 17 12:12:12 EEST 2005 ppessi
 */

#include "config.h"

#include "test_nua.h"

#if HAVE_ALARM
#include <signal.h>
#endif

#if defined(_WIN32)
#include <fcntl.h>
#endif

SOFIAPUBVAR su_log_t nua_log[];
SOFIAPUBVAR su_log_t soa_log[];
SOFIAPUBVAR su_log_t nea_log[];
SOFIAPUBVAR su_log_t nta_log[];
SOFIAPUBVAR su_log_t tport_log[];
SOFIAPUBVAR su_log_t su_log_default[];

extern void *memmem(const void *haystack, size_t haystacklen,
		    const void *needle, size_t needlelen);

char const name[] = "test_nua";
int print_headings = 1;
int tstflags = 0;

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
#define __func__ name
#endif

int save_events(CONDITION_PARAMS)
{
  return save_event_in_list(ctx, event, ep, ep->call) == event_is_normal;
}

int until_final_response(CONDITION_PARAMS)
{ 
  return status >= 200;
}

int save_until_final_response(CONDITION_PARAMS)
{
  save_event_in_list(ctx, event, ep, ep->call);
  return event >= nua_r_set_params && status >= 200;
}

/** Save events.
 *
 * Terminate when a event is saved.
 */
int save_until_received(CONDITION_PARAMS)
{
  return save_event_in_list(ctx, event, ep, ep->call) == event_is_normal;
}

/** Save events until nua_i_outbound is received.  */
int save_until_special(CONDITION_PARAMS)
{
  return save_event_in_list(ctx, event, ep, ep->call) == event_is_special;
}

/* Return call state from event tag list */
int callstate(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, nutag_callstate);
  return ti ? ti->t_value : -1;
}

/* Return true if offer is sent */
int is_offer_sent(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, nutag_offer_sent);
  return ti ? ti->t_value : 0;
}

/* Return true if answer is sent */
int is_answer_sent(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, nutag_answer_sent);
  return ti ? ti->t_value : 0;
}

/* Return true if offer is recv */
int is_offer_recv(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, nutag_offer_recv);
  return ti ? ti->t_value : 0;
}

/* Return true if answer is recv */
int is_answer_recv(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, nutag_answer_recv);
  return ti ? ti->t_value : 0;
}

/* Return true if offer/answer is sent/recv */
int is_offer_answer_done(tagi_t const *tags)
{
  tagi_t const *ti;

  return 
    ((ti = tl_find(tags, nutag_answer_recv)) && ti->t_value) ||
    ((ti = tl_find(tags, nutag_offer_sent)) && ti->t_value) ||
    ((ti = tl_find(tags, nutag_offer_recv)) && ti->t_value) ||
    ((ti = tl_find(tags, nutag_answer_sent)) && ti->t_value);
}

/* Return audio state from event tag list */
int audio_activity(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, soatag_active_audio);
  return ti ? ti->t_value : -1;
}

/* Return video state from event tag list */
int video_activity(tagi_t const *tags)
{
  tagi_t const *ti = tl_find(tags, soatag_active_video);
  return ti ? ti->t_value : -1;
}

static
void print_event(nua_event_t event,
		 char const *operation,
		 int status, char const *phrase,
		 nua_t *nua, struct context *ctx,
		 struct endpoint *ep,
		 nua_handle_t *nh, struct call *call,
		 sip_t const *sip,
		 tagi_t tags[])
{
  if (event == nua_i_state) {
    fprintf(stderr, "%s.nua(%p): event %s %s\n",
	    ep->name, nh, nua_event_name(event),
	    nua_callstate_name(callstate(tags)));
  }
  else if ((int)event >= nua_r_set_params) {
    fprintf(stderr, "%s.nua(%p): event %s status %u %s\n",
	    ep->name, nh, nua_event_name(event), status, phrase);
  }
  else if ((int)event >= 0) {
    fprintf(stderr, "%s.nua(%p): event %s %s\n",
	    ep->name, nh, nua_event_name(event), phrase);
  }
  else if (status > 0) {
    fprintf(stderr, "%s.nua(%p): call %s() with status %u %s\n",
	    ep->name, nh, operation, status, phrase);
  }
  else {
    tagi_t const *t;
    t = tl_find(tags, siptag_subject_str);
    if (t && t->t_value) {
      char const *subject = (char const *)t->t_value;
      fprintf(stderr, "%s.nua(%p): call %s() \"%s\"\n",
	      ep->name, nh, operation, subject);
    }
    else
      fprintf(stderr, "%s.nua(%p): call %s()\n",
	      ep->name, nh, operation);
  }

  if ((tstflags & tst_verbatim) && tags)
    tl_print(stderr, "", tags);
}

void ep_callback(nua_event_t event,
		 int status, char const *phrase,
		 nua_t *nua, struct context *ctx,
		 struct endpoint *ep,
		 nua_handle_t *nh, struct call *call,
		 sip_t const *sip,
		 tagi_t tags[])
{
  if (ep->printer)
    ep->printer(event, "", status, phrase, nua, ctx, ep, nh, call, sip, tags);

  if (call == NULL && nh) {
    for (call = ep->call; call; call = call->next) {
      if (!call->nh)
	break;
      if (nh == call->nh)
	break;
    }

    if (call && call->nh == NULL) {
      call->nh = nh;
      nua_handle_bind(nh, call);
    }
  }

  if ((ep->next_event == -1 || ep->next_event == event) &&
      (ep->next_condition == NULL ||
       ep->next_condition(event, status, phrase,
			  nua, ctx, ep, nh, call, sip, tags)))
    ep->running = 0;

  ep->last_event = event;

  if (call == NULL && nh)
    nua_handle_destroy(nh);
}

void a_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, struct call *call,
		sip_t const *sip,
		tagi_t tags[])
{
  ep_callback(event, status, phrase, nua, ctx, &ctx->a, nh, call, sip, tags);
}

void b_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, struct call *call,
		sip_t const *sip,
		tagi_t tags[])
{
  ep_callback(event, status, phrase, nua, ctx, &ctx->b, nh, call, sip, tags);
}

void c_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, struct call *call,
		sip_t const *sip,
		tagi_t tags[])
{
  ep_callback(event, status, phrase, nua, ctx, &ctx->c, nh, call, sip, tags);
}

void run_abc_until(struct context *ctx,
		   nua_event_t a_event, condition_function *a_condition,
		   nua_event_t b_event, condition_function *b_condition,
		   nua_event_t c_event, condition_function *c_condition)
{
  struct endpoint *a = &ctx->a, *b = &ctx->b, *c = &ctx->c;

  a->next_event = a_event;
  a->next_condition = a_condition;
  a->last_event = -1;
  a->running = a_condition != NULL && a_condition != save_events;
  a->running |= a_event != -1;
  a->flags.n = 0;

  b->next_event = b_event;
  b->next_condition = b_condition;
  b->last_event = -1;
  b->running = b_condition != NULL && b_condition != save_events;
  b->running |= b_event != -1;
  b->flags.n = 0;

  c->next_event = c_event;
  c->next_condition = c_condition;
  c->last_event = -1;
  c->running = c_condition != NULL && c_condition != save_events;
  c->running |= c_event != -1;
  c->flags.n = 0;

  for (; a->running || b->running || c->running;) {
    su_root_step(ctx->root, 1000);
  }
}

void run_ab_until(struct context *ctx,
		  nua_event_t a_event, condition_function *a_condition,
		  nua_event_t b_event, condition_function *b_condition)
{
  run_abc_until(ctx, a_event, a_condition, b_event, b_condition, -1, NULL);
}

void run_bc_until(struct context *ctx,
		  nua_event_t b_event, condition_function *b_condition,
		  nua_event_t c_event, condition_function *c_condition)
{
  run_abc_until(ctx, -1, NULL, b_event, b_condition, c_event, c_condition);
}

int run_a_until(struct context *ctx,
		nua_event_t a_event,
		condition_function *a_condition)
{
  run_abc_until(ctx, a_event, a_condition, -1, NULL, -1, NULL);
  return ctx->a.last_event;
}

int run_b_until(struct context *ctx,
		nua_event_t b_event,
		condition_function *b_condition)
{
  run_abc_until(ctx, -1, NULL, b_event, b_condition, -1, NULL);
  return ctx->b.last_event;
}

int run_c_until(struct context *ctx,
		nua_event_t event,
		condition_function *condition)
{
  run_abc_until(ctx, -1, NULL, -1, NULL, event, condition);
  return ctx->c.last_event;
}

#define OPERATION(X, x)	   \
int X(struct endpoint *ep, \
      struct call *call, nua_handle_t *nh, \
      tag_type_t tag, tag_value_t value, \
      ...) \
{ \
  ta_list ta; \
  ta_start(ta, tag, value); \
\
  if (ep->printer) \
    ep->printer(-1, "nua_" #x, 0, "", ep->nua, ep->ctx, ep, \
		nh, call, NULL, ta_args(ta)); \
\
  nua_##x(nh, ta_tags(ta)); \
\
  ta_end(ta); \
  return 0; \
} extern int dummy

OPERATION(INVITE, invite);
OPERATION(ACK, ack);
OPERATION(BYE, bye);
OPERATION(CANCEL, cancel);
OPERATION(AUTHENTICATE, authenticate);
OPERATION(UPDATE, update);
OPERATION(INFO, info);
OPERATION(PRACK, prack);
OPERATION(REFER, refer);
OPERATION(MESSAGE, message);
OPERATION(OPTIONS, options);
OPERATION(PUBLISH, publish);
OPERATION(UNPUBLISH, unpublish);
OPERATION(REGISTER, register);
OPERATION(UNREGISTER, unregister);
OPERATION(SUBSCRIBE, subscribe);
OPERATION(UNSUBSCRIBE, unsubscribe);
OPERATION(NOTIFY, notify);
OPERATION(NOTIFIER, notifier);
OPERATION(TERMINATE, terminate);
OPERATION(AUTHORIZE, authorize);

/* Respond via endpoint and handle */
int RESPOND(struct endpoint *ep,
	    struct call *call,
	    nua_handle_t *nh,
	    int status, char const *phrase,
	    tag_type_t tag, tag_value_t value,
	    ...)
{
  ta_list ta;

  ta_start(ta, tag, value);

  if (ep->printer)
    ep->printer(-1, "nua_respond", status, phrase, ep->nua, ep->ctx, ep,
		nh, call, NULL, ta_args(ta));

  nua_respond(nh, status, phrase, ta_tags(ta));
  ta_end(ta);

  return 0;
}

/* Destroy an handle */
int DESTROY(struct endpoint *ep,
	    struct call *call,
	    nua_handle_t *nh)
{
  if (ep->printer)
    ep->printer(-1, "nua_handle_destroy", 0, "", ep->nua, ep->ctx, ep,
		nh, call, NULL, NULL);

  nua_handle_destroy(nh);

  if (call->nh == nh)
    call->nh = NULL;

  return 0;
}


/* Reject all but currently used handles */
struct call *check_handle(struct endpoint *ep,
			  struct call *call,
			  nua_handle_t *nh,
			  int status, char const *phrase)
{
  if (call)
    return call;

  if (status)
    RESPOND(ep, call, nh, status, phrase, TAG_END());

  nua_handle_destroy(nh);
  return NULL;
}

/* Save nua event in call-specific list */
int save_event_in_list(struct context *ctx,
		       nua_event_t nevent,
		       struct endpoint *ep,
		       struct call *call)

{
  struct eventlist *list;
  struct event *e;
  int action = ep->is_special(nevent);

  if (action == event_is_extra)
    return 0;
  else if (action == event_is_special || call == NULL)
    list = ep->specials;
  else if (call->events)
    list = call->events;
  else
    list = ep->events;

  e = su_zalloc(ctx->home, sizeof *e);

  if (!e) { perror("su_zalloc"), abort(); }

  if (!nua_save_event(ep->nua, e->saved_event)) {
    su_free(ctx->home, e);
    return -1;
  }

  *(e->prev = list->tail) = e; list->tail = &e->next;

  e->call = call;
  e->data = nua_event_data(e->saved_event);

  return action;
}

/* Save nua event in endpoint list */
void free_events_in_list(struct context *ctx,
			 struct eventlist *list)
{
  struct event *e;

  while ((e = list->head)) {
    if ((*e->prev = e->next))
      e->next->prev = e->prev;
    nua_destroy_event(e->saved_event);
    su_free(ctx->home, e);
  }

  list->tail = &list->head;
}

int is_special(nua_event_t e)
{
  if (e == nua_i_active || e == nua_i_terminated)
    return event_is_extra;
  if (e == nua_i_outbound)
    return event_is_special;

  return event_is_normal;
}

void
endpoint_init(struct context *ctx, struct endpoint *e, char id)
{
  e->name[0] = id;
  e->ctx = ctx;

  e->is_special = is_special;

  call_init(e->call);
  call_init(e->reg);
  eventlist_init(e->events);
  eventlist_init(e->specials);
}

void nolog(void *stream, char const *fmt, va_list ap) {}

/* ======================================================================== */

static char passwd_name[] = "tmp_sippasswd.XXXXXX";

static void remove_tmp(void)
{
  if (passwd_name[0])
    unlink(passwd_name);
}

static char const passwd[] =
  "alice:secret:\n"
  "bob:secret:\n"
  "charlie:secret:\n";

int test_nua_init(struct context *ctx,
		  int start_proxy,
		  url_t const *o_proxy,
		  int start_nat,
		  tag_type_t tag, tag_value_t value, ...)
{
  BEGIN();
  struct event *e;
  sip_contact_t const *m = NULL;
  sip_from_t const *sipaddress = NULL;
  url_t const *p_uri, *a_uri;		/* Proxy URI */
  char const *a_bind, *a_bind2;

  a_bind = a_bind2 = "sip:0.0.0.0:*";

  ctx->root = su_root_create(NULL); TEST_1(ctx->root);

  /* Disable threading by command line switch? */
  su_root_threading(ctx->root, ctx->threading);

  if (start_proxy && !o_proxy) {
    int temp;

    if (print_headings)
      printf("TEST NUA-2.1.1: init proxy P\n");

#ifndef _WIN32
    temp = mkstemp(passwd_name);
#else
    temp = open(passwd_name, O_WRONLY|O_CREAT|O_TRUNC, 666);
#endif
    TEST_1(temp != -1);
    atexit(remove_tmp);		/* Make sure temp file is unlinked */

    TEST(write(temp, passwd, strlen(passwd)), strlen(passwd));

    TEST_1(close(temp) == 0);

    ctx->p = test_proxy_create(ctx->root,
			       AUTHTAG_METHOD("Digest"),
			       AUTHTAG_REALM("test-proxy"),
			       AUTHTAG_OPAQUE("kuik"),
			       AUTHTAG_DB(passwd_name),
			       AUTHTAG_QOP("auth-int"),
			       AUTHTAG_ALGORITHM("md5-sess"),
			       TAG_END());

    ctx->proxy_tests = ctx->p != NULL;

    if (print_headings)
      printf("TEST NUA-2.1.1: PASSED\n");
  }

  p_uri = a_uri = test_proxy_uri(ctx->p);

  if (start_nat && p_uri == NULL)
    p_uri = url_hdup(ctx->home, (void *)o_proxy);

  if (start_nat && p_uri != NULL) {
    int family = 0;
    su_sockaddr_t su[1];
    socklen_t sulen = sizeof su;
    char b[64];
    int len;
    ta_list ta;

    if (print_headings)
      printf("TEST NUA-2.1.2: creating test NAT\n");

    /* Try to use different family than proxy. */
    if (p_uri->url_host[0] == '[')
      family = AF_INET;
#if defined(SU_HAVE_IN6)
    else
      family = AF_INET6;
#endif

    ta_start(ta, tag, value);
    ctx->nat = test_nat_create(ctx->root, family, ta_tags(ta));
    ta_end(ta);

    /*
     * NAT thingy works so that we set the outgoing proxy URI to point
     * towards its "private" address and give the real address of the proxy
     * as its "public" address. If we use different IP families here, we may
     * even manage to test real connectivity problems as proxy and endpoint
     * can not talk to each other.
     */

    if (test_nat_private(ctx->nat, su, &sulen) < 0) {
      printf("%s:%u: NUA-2.1.2: failed to get private NAT address\n",
	     __FILE__, __LINE__);
    }

#if defined(SU_HAVE_IN6)
    else if (su->su_family == AF_INET6) {
      a_uri = (void *)
	su_sprintf(ctx->home, "sip:[%s]:%u",
		   inet_ntop(su->su_family, SU_ADDR(su), b, sizeof b),
		   ntohs(su->su_port));
      a_bind = "sip:[::]:*";
    }
#endif
    else if (su->su_family == AF_INET) {
      a_uri = (void *)
	su_sprintf(ctx->home, "sip:%s:%u",
		   inet_ntop(su->su_family, SU_ADDR(su), b, sizeof b),
		   ntohs(su->su_port));
    }

#if defined(SU_HAVE_IN6)
    if (p_uri->url_host[0] == '[') {
      su->su_len = sulen = (sizeof su->su_sin6), su->su_family = AF_INET6;
      len = strcspn(p_uri->url_host + 1, "]"); assert(len < sizeof b);
      memcpy(b, p_uri->url_host + 1, len); b[len] = '\0';
      inet_pton(su->su_family, b, SU_ADDR(su));
    }
    else {
      su->su_len = sulen = (sizeof su->su_sin), su->su_family = AF_INET;
      inet_pton(su->su_family, p_uri->url_host, SU_ADDR(su));
    }
#else
    su->su_len = sulen = (sizeof su->su_sin), su->su_family = AF_INET;
    inet_pton(su->su_family, p_uri->url_host, SU_ADDR(su));
#endif

    su->su_port = htons(strtoul(url_port(p_uri), NULL, 10));

    if (test_nat_public(ctx->nat, su, sulen) < 0) {
      printf("%s:%u: NUA-2.1.2: failed to set public address\n",
	     __FILE__, __LINE__);
      a_uri = NULL;
    }

    if (print_headings) {
      if (ctx->nat && a_uri) {
	printf("TEST NUA-2.1.2: PASSED\n");
      } else {
	printf("TEST NUA-2.1.2: FAILED\n");
      }
    }
  }

  if (print_headings)
    printf("TEST NUA-2.2.1: init endpoint A\n");

  if (a_uri == NULL)
    a_uri = p_uri;

  ctx->a.instance = nua_generate_instance_identifier(ctx->home);

  ctx->a.nua = nua_create(ctx->root, a_callback, ctx,
			  NUTAG_PROXY(a_uri ? a_uri : o_proxy),
			  SIPTAG_FROM_STR("sip:alice@example.com"),
			  NUTAG_URL(a_bind),
			  TAG_IF(a_bind != a_bind2, NUTAG_SIPS_URL(a_bind2)),
			  SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
			  NTATAG_SIP_T1X64(4000),
			  NUTAG_INSTANCE(ctx->a.instance),
			  TAG_END());
  TEST_1(ctx->a.nua);

  nua_get_params(ctx->a.nua, TAG_ANY(), TAG_END());
  run_a_until(ctx, nua_r_get_params, save_until_final_response);
  TEST_1(e = ctx->a.events->head);
  TEST(tl_gets(e->data->e_tags,
	       NTATAG_CONTACT_REF(m),
	       SIPTAG_FROM_REF(sipaddress),
	       TAG_END()), 2); TEST_1(m);
  TEST_1(ctx->a.contact = sip_contact_dup(ctx->home, m));
  TEST_1(ctx->a.to = sip_to_dup(ctx->home, sipaddress));

  free_events_in_list(ctx, ctx->a.events);

  if (print_headings)
    printf("TEST NUA-2.2.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.2.2: init endpoint B\n");

  ctx->b.instance = nua_generate_instance_identifier(ctx->home);

  ctx->b.nua = nua_create(ctx->root, b_callback, ctx,
			  NUTAG_PROXY(p_uri ? p_uri : o_proxy),
			  SIPTAG_FROM_STR("sip:bob@example.org"),
			  NUTAG_URL("sip:0.0.0.0:*"),
			  SOATAG_USER_SDP_STR("m=audio 5006 RTP/AVP 8 0"),
			  NUTAG_INSTANCE(ctx->b.instance),
			  TAG_END());
  TEST_1(ctx->b.nua);

  nua_get_params(ctx->b.nua, TAG_ANY(), TAG_END());
  run_b_until(ctx, nua_r_get_params, save_until_final_response);
  TEST_1(e = ctx->b.events->head);
  TEST(tl_gets(e->data->e_tags,
	       NTATAG_CONTACT_REF(m),
	       SIPTAG_FROM_REF(sipaddress),
	       TAG_END()), 2); TEST_1(m);
  TEST_1(ctx->b.contact = sip_contact_dup(ctx->home, m));
  TEST_1(ctx->b.to = sip_to_dup(ctx->home, sipaddress));
  free_events_in_list(ctx, ctx->b.events);

  if (print_headings)
    printf("TEST NUA-2.2.2: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.2.3: init endpoint C\n");

  /* ctx->c.instance = nua_generate_instance_identifier(ctx->home); */

  ctx->c.nua = nua_create(ctx->root, c_callback, ctx,
			  NUTAG_PROXY(p_uri ? p_uri : o_proxy),
			  SIPTAG_FROM_STR("sip:charlie@example.net"),
			  NUTAG_URL("sip:0.0.0.0:*"),
			  SOATAG_USER_SDP_STR("m=audio 5400 RTP/AVP 8 0"),
			  NUTAG_INSTANCE(ctx->c.instance),
			  TAG_END());
  TEST_1(ctx->c.nua);

  nua_get_params(ctx->c.nua, TAG_ANY(), TAG_END());
  run_c_until(ctx, nua_r_get_params, save_until_final_response);
  TEST_1(e = ctx->c.events->head);
  TEST(tl_gets(e->data->e_tags,
	       NTATAG_CONTACT_REF(m),
	       SIPTAG_FROM_REF(sipaddress),
	       TAG_END()), 2); TEST_1(m);
  TEST_1(ctx->c.contact = sip_contact_dup(ctx->home, m));
  TEST_1(ctx->c.to = sip_to_dup(ctx->home, sipaddress));
  free_events_in_list(ctx, ctx->c.events);

  if (print_headings)
    printf("TEST NUA-2.2.3: PASSED\n");

  END();
}


/* ====================================================================== */

int test_deinit(struct context *ctx)
{
  BEGIN();

  struct call *call;

  if (!ctx->threading)
    su_root_step(ctx->root, 100);

  if (ctx->a.nua) {
    for (call = ctx->a.call; call; call = call->next)
      nua_handle_destroy(call->nh), call->nh = NULL;

    nua_shutdown(ctx->a.nua);
    run_a_until(ctx, nua_r_shutdown, until_final_response);
    nua_destroy(ctx->a.nua), ctx->a.nua = NULL;
  }

  if (ctx->b.nua) {
    for (call = ctx->b.call; call; call = call->next)
      nua_handle_destroy(call->nh), call->nh = NULL;

    nua_shutdown(ctx->b.nua);
    run_b_until(ctx, nua_r_shutdown, until_final_response);
    nua_destroy(ctx->b.nua), ctx->b.nua = NULL;
  }

  if (ctx->c.nua) {
    for (call = ctx->c.call; call; call = call->next)
      nua_handle_destroy(call->nh), call->nh = NULL;

    nua_shutdown(ctx->c.nua);
    run_c_until(ctx, nua_r_shutdown, until_final_response);
    nua_destroy(ctx->c.nua), ctx->c.nua = NULL;
  }

  test_proxy_destroy(ctx->p), ctx->p = NULL;

  test_nat_destroy(ctx->nat), ctx->nat = NULL;

  su_root_destroy(ctx->root);

  END();
}

#if HAVE_ALARM
static RETSIGTYPE sig_alarm(int s)
{
  fprintf(stderr, "%s: FAIL! test timeout!\n", name);
  exit(1);
}
#endif

static char const options_usage[] =
  "   -v | --verbose    be verbose\n"
  "   -q | --quiet      be quiet\n"
  "   -s                use only single thread\n"
  "   -l level          set logging level (0 by default)\n"
  "   -e | --events     print nua events\n"
  "   -A                print nua events for A\n"
  "   -B                print nua events for B\n"
  "   -C                print nua events for C\n"
  "   --attach          print pid, wait for a debugger to be attached\n"
  "   --no-proxy        do not use internal proxy\n"
  "   --no-nat          do not use internal \"nat\"\n"
  "   --symmetric       run internal \"nat\" in symmetric mode\n"
  "   -N                print events from internal \"nat\"\n"
  "   --no-alarm        don't ask for guard ALARM\n"
  "   -p uri            specify uri of outbound proxy (implies --no-proxy)\n"
  "   --proxy-tests     run tests involving proxy, too\n"
  "   -k                do not exit after first error\n"
  ;

void usage(int exitcode)
{
  fprintf(stderr, "usage: %s OPTIONS\n   where OPTIONS are\n%s",
	    name, options_usage);
  exit(exitcode);
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i, o_quiet = 0, o_attach = 0, o_alarm = 1;
  int o_events_init = 0, o_events_a = 0, o_events_b = 0, o_events_c = 0;
  int o_iproxy = 1, o_inat = 1;
  int o_inat_symmetric = 0, o_inat_logging = 0, o_expensive = 0;
  url_t const *o_proxy = NULL;
  int level = 0;

  struct context ctx[1] = {{{ SU_HOME_INIT(ctx) }}};

  if (getenv("EXPENSIVE_CHECKS"))
    o_expensive = 1;

  ctx->threading = 1;
  ctx->quit_on_single_failure = 1;

  endpoint_init(ctx, &ctx->a, 'a');
  endpoint_init(ctx, &ctx->b, 'b');
  endpoint_init(ctx, &ctx->c, 'c');

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
      tstflags &= ~tst_verbatim, o_quiet = 1;
    else if (strcmp(argv[i], "-k") == 0)
      ctx->quit_on_single_failure = 0;
    else if (strncmp(argv[i], "-l", 2) == 0) {
      char *rest = NULL;

      if (argv[i][2])
	level = strtol(argv[i] + 2, &rest, 10);
      else if (argv[i + 1])
	level = strtol(argv[i + 1], &rest, 10), i++;
      else
	level = 3, rest = "";

      if (rest == NULL || *rest)
	usage(1);

      su_log_set_level(nua_log, level);
      su_log_soft_set_level(soa_log, level);
      su_log_soft_set_level(nea_log, level);
      su_log_soft_set_level(nta_log, level);
      su_log_soft_set_level(tport_log, level);
    }
    else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--events") == 0) {
      o_events_init = o_events_a = o_events_b = o_events_c = 1;
    }
    else if (strcmp(argv[i], "-I") == 0) {
      o_events_init = 1;
    }
    else if (strcmp(argv[i], "-A") == 0) {
      o_events_a = 1;
    }
    else if (strcmp(argv[i], "-B") == 0) {
      o_events_b = 1;
    }
    else if (strcmp(argv[i], "-C") == 0) {
      o_events_c = 1;
    }
    else if (strcmp(argv[i], "-s") == 0) {
      ctx->threading = 0;
    }
    else if (strcmp(argv[i], "--attach") == 0) {
      o_attach = 1;
    }
    else if (strncmp(argv[i], "-p", 2) == 0) {
      if (argv[i][2])
	o_proxy = URL_STRING_MAKE(argv[i] + 2)->us_url;
      else if (!argv[++i] || argv[i][0] == '-')
	usage(1);
      else
	o_proxy = URL_STRING_MAKE(argv[i])->us_url;
    }
    else if (strcmp(argv[i], "--proxy-tests") == 0) {
      ctx->proxy_tests = 1;
    }
    else if (strcmp(argv[i], "--no-proxy") == 0) {
      o_iproxy = 0;
    }
    else if (strcmp(argv[i], "--no-nat") == 0) {
      o_inat = 0;
    }
    else if (strcmp(argv[i], "--nat") == 0) {
      o_inat = 1;
    }
    else if (strcmp(argv[i], "--symmetric") == 0) {
      o_inat_symmetric = 1;
    }
    else if (strcmp(argv[i], "-N") == 0) {
      o_inat_logging = 1;
    }
    else if (strcmp(argv[i], "--expensive") == 0) {
      o_expensive = 1;
    }
    else if (strcmp(argv[i], "--no-alarm") == 0) {
      o_alarm = 0;
    }
    else if (strcmp(argv[i], "-") == 0) {
      i++; break;
    }
    else if (argv[i][0] != '-') {
      break;
    }
    else
      usage(1);
  }

  if (o_attach) {
    char line[10];
    printf("%s: pid %lu\n", name, (unsigned long)getpid());
    printf("<Press RETURN to continue>\n");
    fgets(line, sizeof line, stdin);
  }
#if HAVE_ALARM
  else if (o_alarm) {
    alarm(o_expensive ? 60 : 120);
    signal(SIGALRM, sig_alarm);
  }
#endif

  su_init();

  if (!(TSTFLAGS & tst_verbatim)) {
    if (level == 0 && !o_quiet)
      level = 1;
    su_log_soft_set_level(nua_log, level);
    su_log_soft_set_level(soa_log, level);
    su_log_soft_set_level(nea_log, level);
    su_log_soft_set_level(nta_log, level);
    su_log_soft_set_level(tport_log, level);
  }

  if (!o_quiet || (TSTFLAGS & tst_verbatim)
      || o_events_a || o_events_b || o_events_c)
    print_headings = 1;

#define SINGLE_FAILURE_CHECK()						\
  do { fflush(stdout);							\
    if (retval && ctx->quit_on_single_failure) {			\
      su_deinit(); return retval; }					\
  } while(0)

  ctx->a.printer = o_events_init ? print_event : NULL;

  retval |= test_nua_api_errors(ctx); SINGLE_FAILURE_CHECK();
  retval |= test_tag_filter(); SINGLE_FAILURE_CHECK();
  retval |= test_nua_params(ctx); SINGLE_FAILURE_CHECK();

  retval |= test_nua_init(ctx, o_iproxy, o_proxy, o_inat,
			  TESTNATTAG_SYMMETRIC(o_inat_symmetric),
			  TESTNATTAG_LOGGING(o_inat_logging),
			  TAG_END());

  ctx->expensive = o_expensive;

  if (retval == 0) {
    ctx->a.printer = o_events_a ? print_event : NULL;
    if (o_events_b)
      ctx->b.printer = print_event;
    if (o_events_c)
      ctx->c.printer = print_event;

    retval |= test_stack_errors(ctx); SINGLE_FAILURE_CHECK();

    if (ctx->proxy_tests)
      retval |= test_register(ctx);

    if (retval == 0)
      retval |= test_connectivity(ctx);

    if (retval == 0 && o_inat)
      retval |= test_nat_timeout(ctx);

    if (retval == 0) {
      retval |= test_basic_call(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_reject_a(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_reject_b(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_reject_302(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_reject_401(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_mime_negotiation(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_reject_401_aka(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_call_cancel(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_call_destroy(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_early_bye(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_call_hold(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_session_timer(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_refer(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_100rel(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_simple(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_events(ctx); SINGLE_FAILURE_CHECK();
    }

    if (ctx->proxy_tests && (retval == 0 || !ctx->p))
      retval |= test_unregister(ctx); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ctx);

  su_home_deinit(ctx->home);

  su_deinit();

  return retval;
}
