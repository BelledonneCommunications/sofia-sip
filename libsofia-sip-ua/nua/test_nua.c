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

struct context;
#define NUA_MAGIC_T struct context

struct call;
#define NUA_HMAGIC_T struct call

#include "sofia-sip/nua.h"
#include "sofia-sip/sip_status.h"

#include <sofia-sip/sdp.h>
#include <sofia-sip/sip_header.h>

#include <sofia-sip/su_log.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/su_tag_io.h>

#include <test_proxy.h>
#include <test_nat.h>
#include <sofia-sip/auth_module.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <unistd.h>

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
#define TSTFLAGS tstflags

#include <sofia-sip/tstdef.h>

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
#define __func__ name
#endif

#define NONE ((void*)-1)

#define TEST_E(a, b) TEST_S(nua_event_name(a), nua_event_name(b))

struct endpoint;

typedef
int condition_function(nua_event_t event,
		       int status, char const *phrase,
		       nua_t *nua, struct context *ctx,
		       struct endpoint *ep,
		       nua_handle_t *nh, struct call *call,
		       sip_t const *sip,
		       tagi_t tags[]);

typedef
void printer_function(nua_event_t event,
		      char const *operation,
		      int status, char const *phrase,
		      nua_t *nua, struct context *ctx,
		      struct endpoint *ep,
		      nua_handle_t *nh, struct call *call,
		      sip_t const *sip,
		      tagi_t tags[]);

struct proxy_transaction;
struct registration_entry;

enum { event_is_extra, event_is_normal, event_is_special };

struct eventlist {
  nua_event_t kind;
  struct event *head, **tail;
};

struct event
{
  struct event *next, **prev;
  struct call *call;
  nua_saved_event_t saved_event[1];
  nua_event_data_t const *data;
};


struct context
{
  su_home_t home[1];
  su_root_t *root;

  int threading, proxy_tests, expensive;
  char const *external_proxy;

  struct endpoint {
    char name[4];
    struct context *ctx;	/* Backpointer */

    int running;

    condition_function *next_condition;
    nua_event_t next_event, last_event;
    nua_t *nua;
    sip_contact_t *contact;
    sip_from_t *to;

    printer_function *printer;

    char const *instance;

    /* Per-call stuff */
    struct call {
      struct call *next;
      nua_handle_t *nh;
      char const *sdp;
      struct eventlist *events;
    } call[1], reg[1];

    int (*is_special)(nua_event_t e);

    /* Normal events are saved here */
    struct eventlist events[1];
    /* Special events are saved here */
    struct eventlist specials[1];

    /* State flags for complex scenarios */
    union {
      struct {
	unsigned bit0:1, bit1:1, bit2:1, bit3:1;
	unsigned bit4:1, bit5:1, bit6:1, bit7:1;
      } b;
      unsigned n;
    } flags;

  } a, b, c;

  struct proxy *p;
  struct nat *nat;
};

static int save_event_in_list(struct context *,
			      nua_event_t nevent,
			      struct endpoint *,
			      struct call *);
static void free_events_in_list(struct context *,
				struct eventlist *);

#define CONDITION_PARAMS			\
  nua_event_t event,				\
  int status, char const *phrase,		\
  nua_t *nua, struct context *ctx,		\
  struct endpoint *ep,				\
  nua_handle_t *nh, struct call *call,		\
  sip_t const *sip,				\
  tagi_t tags[]

int until_final_response(CONDITION_PARAMS){ return status >= 200; }
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

int save_events(CONDITION_PARAMS)
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
  a->running = a_condition != NULL || a_event != -1;
  a->flags.n = 0;

  b->next_event = b_event;
  b->next_condition = b_condition;
  b->last_event = -1;
  b->running = b_condition != NULL || b_event != -1;
  b->flags.n = 0;

  c->next_event = c_event;
  c->next_condition = c_condition;
  c->last_event = -1;
  c->running = c_condition != NULL || c_event != -1;
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
static
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
static
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

static
int is_special(nua_event_t e)
{
  if (e == nua_i_active || e == nua_i_terminated)
    return event_is_extra;
  if (e == nua_i_outbound)
    return event_is_special;

  return event_is_normal;
}

static void
eventlist_init(struct eventlist *list)
{
  list->tail = &list->head;
}

static void
call_init(struct call *call)
{
}

static void
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

int check_set_status(int status, char const *phrase)
{
  return status == 200 && strcmp(phrase, sip_200_OK) == 0;
}

int test_nua_api_errors(struct context *ctx)
{
  BEGIN();

  /* Invoke every API function with invalid arguments */

  int level;

  int status; char const *phrase;

  if (print_headings)
    printf("TEST NUA-1.0: test API\n");

  /* This is a nasty macro. Test it. */
#define SET_STATUS1(x) ((status = x), status), (phrase = ((void)x))
  TEST_1(check_set_status(SET_STATUS1(SIP_200_OK)));
  TEST(status, 200); TEST_S(phrase, sip_200_OK);

  su_log_init(nua_log);

  level = nua_log->log_level;
  if (!(tstflags & tst_verbatim))
    su_log_set_level(nua_log, 0);

  TEST_1(!nua_create(NULL, NULL, NULL, TAG_END()));
  TEST_VOID(nua_shutdown(NULL));
  TEST_VOID(nua_destroy(NULL));
  TEST_VOID(nua_set_params(NULL, TAG_END()));
  TEST_VOID(nua_get_params(NULL, TAG_END()));
  TEST_1(!nua_default(NULL));
  TEST_1(!nua_handle(NULL, NULL, TAG_END()));
  TEST_VOID(nua_handle_destroy(NULL));
  TEST_VOID(nua_handle_bind(NULL, NULL));
  TEST_1(!nua_handle_has_invite(NULL));
  TEST_1(!nua_handle_has_subscribe(NULL));
  TEST_1(!nua_handle_has_register(NULL));
  TEST_1(!nua_handle_has_active_call(NULL));
  TEST_1(!nua_handle_has_call_on_hold(NULL));
  TEST_1(!nua_handle_has_events(NULL));
  TEST_1(!nua_handle_has_registrations(NULL));
  TEST_1(!nua_handle_remote(NULL));
  TEST_1(!nua_handle_local(NULL));
  TEST_S(nua_event_name(-1), "NUA_UNKNOWN");
  TEST_VOID(nua_register(NULL, TAG_END()));
  TEST_VOID(nua_unregister(NULL, TAG_END()));
  TEST_VOID(nua_invite(NULL, TAG_END()));
  TEST_VOID(nua_ack(NULL, TAG_END()));
  TEST_VOID(nua_prack(NULL, TAG_END()));
  TEST_VOID(nua_options(NULL, TAG_END()));
  TEST_VOID(nua_publish(NULL, TAG_END()));
  TEST_VOID(nua_message(NULL, TAG_END()));
  TEST_VOID(nua_chat(NULL, TAG_END()));
  TEST_VOID(nua_info(NULL, TAG_END()));
  TEST_VOID(nua_subscribe(NULL, TAG_END()));
  TEST_VOID(nua_unsubscribe(NULL, TAG_END()));
  TEST_VOID(nua_notify(NULL, TAG_END()));
  TEST_VOID(nua_notifier(NULL, TAG_END()));
  TEST_VOID(nua_terminate(NULL, TAG_END()));
  TEST_VOID(nua_refer(NULL, TAG_END()));
  TEST_VOID(nua_update(NULL, TAG_END()));
  TEST_VOID(nua_bye(NULL, TAG_END()));
  TEST_VOID(nua_cancel(NULL, TAG_END()));
  TEST_VOID(nua_authenticate(NULL, TAG_END()));
  TEST_VOID(nua_redirect(NULL, TAG_END()));
  TEST_VOID(nua_respond(NULL, 0, "", TAG_END()));

  TEST_1(!nua_handle_home(NULL));
  TEST_1(!nua_save_event(NULL, NULL));
  TEST_1(!nua_event_data(NULL));
  TEST_VOID(nua_destroy_event(NULL));

  {
    nua_saved_event_t event[1];

    memset(event, 0, sizeof event);

    TEST_1(!nua_save_event(NULL, event));
    TEST_1(!nua_event_data(event));
    TEST_VOID(nua_destroy_event(event));
  }

  su_log_set_level(nua_log, level);

  if (print_headings)
    printf("TEST NUA-1.0: PASSED\n");

  END();
}

#include <sofia-sip/su_tag_class.h>

int test_tag_filter(void)
{
  BEGIN();

#undef TAG_NAMESPACE
#define TAG_NAMESPACE "test"
  tag_typedef_t tag_a = STRTAG_TYPEDEF(a);
#define TAG_A(s)      tag_a, tag_str_v((s))
  tag_typedef_t tag_b = STRTAG_TYPEDEF(b);
#define TAG_B(s)      tag_b, tag_str_v((s))

  tagi_t filter[2] = {{ NUTAG_ANY() }, { TAG_END() }};

  tagi_t *lst, *result;

  lst = tl_list(TAG_A("X"),
		TAG_SKIP(2),
		NUTAG_URL((void *)"urn:foo"),
		TAG_B("Y"),
		NUTAG_URL((void *)"urn:bar"),
		TAG_NULL());

  TEST_1(lst);

  result = tl_afilter(NULL, filter, lst);

  TEST_1(result);
  TEST(result[0].t_tag, nutag_url);
  TEST(result[1].t_tag, nutag_url);

  tl_vfree(lst);
  free(result);

  END();
}

int test_nua_params(struct context *ctx)
{
  BEGIN();

  char const Alice[] = "Alice <sip:a@wonderland.org>";
  sip_from_t const *from;
  su_home_t tmphome[SU_HOME_AUTO_SIZE(16384)];
  nua_handle_t *nh;

  su_home_auto(tmphome, sizeof(tmphome));

  if (print_headings)
    printf("TEST NUA-1.1: PARAMETERS\n");

  ctx->root = su_root_create(NULL); TEST_1(ctx->root);

  /* Disable threading by command line switch? */
  su_root_threading(ctx->root, ctx->threading);

  ctx->a.nua = nua_create(ctx->root, a_callback, ctx,
			  SIPTAG_FROM_STR("sip:alice@example.com"),
			  NUTAG_URL("sip:0.0.0.0:*;transport=udp"),
			  TAG_END());

  TEST_1(ctx->a.nua);

  nh = nua_handle(ctx->a.nua, NULL, TAG_END()); TEST_1(nh);
  nua_handle_unref(nh);

  nh = nua_handle(ctx->a.nua, NULL, TAG_END()); TEST_1(nh);
  nua_handle_destroy(nh);

  from = sip_from_make(tmphome, Alice);

  nh = nua_handle(ctx->a.nua, NULL, TAG_END());

  nua_set_hparams(nh, NUTAG_INVITE_TIMER(90), TAG_END());
  run_a_until(ctx, nua_r_set_params, until_final_response);

  /* Modify all pointer values */
  nua_set_params(ctx->a.nua,
		 SIPTAG_FROM_STR(Alice),

		 SIPTAG_SUPPORTED_STR("test"),
		 SIPTAG_ALLOW_STR("DWIM, OPTIONS, INFO"),
		 SIPTAG_USER_AGENT_STR("test_nua/1.0"),

		 SIPTAG_ORGANIZATION_STR("Te-Ras y.r."),

		 NUTAG_REGISTRAR("sip:openlaboratory.net"),

		 TAG_END());

  run_a_until(ctx, nua_r_set_params, until_final_response);

  /* Modify everything from their default value */
  nua_set_params(ctx->a.nua,
		 SIPTAG_FROM(from),
		 NUTAG_RETRY_COUNT(9),
		 NUTAG_MAX_SUBSCRIPTIONS(6),

		 NUTAG_ENABLEINVITE(0),
		 NUTAG_AUTOALERT(1),
		 NUTAG_EARLY_MEDIA(1),
		 NUTAG_AUTOANSWER(1),
		 NUTAG_AUTOACK(0),
		 NUTAG_INVITE_TIMER(60),

		 NUTAG_SESSION_TIMER(600),
		 NUTAG_MIN_SE(35),
		 NUTAG_SESSION_REFRESHER(nua_remote_refresher),
		 NUTAG_UPDATE_REFRESH(1),

		 NUTAG_ENABLEMESSAGE(0),
		 NUTAG_ENABLEMESSENGER(1),
		 /* NUTAG_MESSAGE_AUTOANSWER(0), */

		 NUTAG_CALLEE_CAPS(1),
		 NUTAG_MEDIA_FEATURES(1),
		 NUTAG_SERVICE_ROUTE_ENABLE(0),
		 NUTAG_PATH_ENABLE(0),
		 NUTAG_SUBSTATE(nua_substate_pending),

		 NUTAG_KEEPALIVE(66),
		 NUTAG_KEEPALIVE_STREAM(33),

		 NUTAG_OUTBOUND("foo"),
		 NUTAG_INSTANCE("urn:uuid:97701ad9-39df-1229-1083-dbc0a85f029c"),

		 SIPTAG_SUPPORTED(sip_supported_make(tmphome, "humppaa,kuole")),
		 SIPTAG_ALLOW(sip_allow_make(tmphome, "OPTIONS, INFO")),
		 SIPTAG_USER_AGENT(sip_user_agent_make(tmphome, "test_nua")),

		 SIPTAG_ORGANIZATION(sip_organization_make(tmphome, "Pussy Galore's Flying Circus")),

		 NUTAG_MEDIA_ENABLE(0),
		 NUTAG_REGISTRAR(url_hdup(tmphome, (url_t *)"sip:sip.wonderland.org")),

		 TAG_END());

  run_a_until(ctx, nua_r_set_params, until_final_response);

  /* Modify something... */
  nua_set_params(ctx->a.nua,
		 NUTAG_RETRY_COUNT(5),
		 TAG_END());
  run_a_until(ctx, nua_r_set_params, until_final_response);

  {
    sip_from_t const *from = NONE;
    char const *from_str = "NONE";

    unsigned retry_count = -1;
    unsigned max_subscriptions = -1;

    int invite_enable = -1;
    int auto_alert = -1;
    int early_media = -1;
    int auto_answer = -1;
    int auto_ack = -1;
    unsigned invite_timeout = -1;

    unsigned session_timer = -1;
    unsigned min_se = -1;
    int refresher = -1;
    int update_refresh = -1;

    int message_enable = -1;
    int win_messenger_enable = -1;
    int message_auto_respond = -1;

    int callee_caps = -1;
    int media_features = -1;
    int service_route_enable = -1;
    int path_enable = -1;
    int substate = -1;

    sip_allow_t const *allow = NONE;
    char const *allow_str = "NONE";
    sip_supported_t const *supported = NONE;
    char const *supported_str = "NONE";
    sip_user_agent_t const *user_agent = NONE;
    char const *user_agent_str = "NONE";
    sip_organization_t const *organization = NONE;
    char const *organization_str = "NONE";

    char const *outbound = "NONE";
    char const *instance = "NONE";
    
    unsigned keepalive = -1, keepalive_stream = -1;

    url_string_t const *registrar = NONE;

    int n;
    struct event *e;

    nua_get_params(ctx->a.nua, TAG_ANY(), TAG_END());
    run_a_until(ctx, nua_r_get_params, save_until_final_response);

    TEST_1(e = ctx->a.events->head);
    TEST_E(e->data->e_event, nua_r_get_params);

    n = tl_gets(e->data->e_tags,
	       	SIPTAG_FROM_REF(from),
	       	SIPTAG_FROM_STR_REF(from_str),

	       	NUTAG_RETRY_COUNT_REF(retry_count),
	       	NUTAG_MAX_SUBSCRIPTIONS_REF(max_subscriptions),

	       	NUTAG_ENABLEINVITE_REF(invite_enable),
	       	NUTAG_AUTOALERT_REF(auto_alert),
	       	NUTAG_EARLY_MEDIA_REF(early_media),
	       	NUTAG_AUTOANSWER_REF(auto_answer),
	       	NUTAG_AUTOACK_REF(auto_ack),
	       	NUTAG_INVITE_TIMER_REF(invite_timeout),

	       	NUTAG_SESSION_TIMER_REF(session_timer),
	       	NUTAG_MIN_SE_REF(min_se),
	       	NUTAG_SESSION_REFRESHER_REF(refresher),
	       	NUTAG_UPDATE_REFRESH_REF(update_refresh),

	       	NUTAG_ENABLEMESSAGE_REF(message_enable),
	       	NUTAG_ENABLEMESSENGER_REF(win_messenger_enable),
	       	/* NUTAG_MESSAGE_AUTOANSWER(message_auto_respond), */

	       	NUTAG_CALLEE_CAPS_REF(callee_caps),
	       	NUTAG_MEDIA_FEATURES_REF(media_features),
	       	NUTAG_SERVICE_ROUTE_ENABLE_REF(service_route_enable),
	       	NUTAG_PATH_ENABLE_REF(path_enable),
	       	NUTAG_SUBSTATE_REF(substate),

	       	SIPTAG_SUPPORTED_REF(supported),
	       	SIPTAG_SUPPORTED_STR_REF(supported_str),
	       	SIPTAG_ALLOW_REF(allow),
	       	SIPTAG_ALLOW_STR_REF(allow_str),
	       	SIPTAG_USER_AGENT_REF(user_agent),
	       	SIPTAG_USER_AGENT_STR_REF(user_agent_str),

	       	SIPTAG_ORGANIZATION_REF(organization),
	       	SIPTAG_ORGANIZATION_STR_REF(organization_str),

		NUTAG_OUTBOUND_REF(outbound),
		NUTAG_INSTANCE_REF(instance),

		NUTAG_KEEPALIVE_REF(keepalive),
		NUTAG_KEEPALIVE_STREAM_REF(keepalive_stream),

	       	NUTAG_REGISTRAR_REF(registrar),

		TAG_END());
    TEST(n, 34);

    TEST_S(sip_header_as_string(tmphome, (void *)from), Alice);
    TEST_S(from_str, Alice);

    TEST(retry_count, 5);
    TEST(max_subscriptions, 6);

    TEST(invite_enable, 0);
    TEST(auto_alert, 1);
    TEST(early_media, 1);
    TEST(auto_answer, 1);
    TEST(auto_ack, 0);
    TEST(invite_timeout, 60);

    TEST(session_timer, 600);
    TEST(min_se, 35);
    TEST(refresher, nua_remote_refresher);
    TEST(update_refresh, 1);

    TEST(message_enable, 0);
    TEST(win_messenger_enable, 1);
    TEST(message_auto_respond, -1); /* XXX */

    TEST(callee_caps, 1);
    TEST(media_features, 1);
    TEST(service_route_enable, 0);
    TEST(path_enable, 0);
    TEST(substate, nua_substate_pending);

    TEST_S(sip_header_as_string(tmphome, (void *)allow), "OPTIONS, INFO");
    TEST_S(allow_str, "OPTIONS, INFO");
    TEST_S(sip_header_as_string(tmphome, (void *)supported), "humppaa, kuole");
    TEST_S(supported_str, "humppaa, kuole");
    TEST_S(sip_header_as_string(tmphome, (void *)user_agent), "test_nua");
    TEST_S(user_agent_str, "test_nua");
    TEST_S(sip_header_as_string(tmphome, (void *)organization),
	   "Pussy Galore's Flying Circus");
    TEST_S(organization_str, "Pussy Galore's Flying Circus");

    TEST(keepalive, 66);
    TEST(keepalive_stream, 33);

    TEST_S(outbound, "foo");
    TEST_S(instance, "urn:uuid:97701ad9-39df-1229-1083-dbc0a85f029c");

    TEST_S(url_as_string(tmphome, registrar->us_url),
	   "sip:sip.wonderland.org");

    free_events_in_list(ctx, ctx->a.events);
  }

  /* Test that only those tags that have been set per handle are returned by nua_get_hparams() */

  {
    sip_from_t const *from = NONE;
    char const *from_str = "NONE";

    unsigned retry_count = -1;
    unsigned max_subscriptions = -1;

    int invite_enable = -1;
    int auto_alert = -1;
    int early_media = -1;
    int auto_answer = -1;
    int auto_ack = -1;
    unsigned invite_timeout = -1;

    unsigned session_timer = -1;
    unsigned min_se = -1;
    int refresher = -1;
    int update_refresh = -1;

    int message_enable = -1;
    int win_messenger_enable = -1;
    int message_auto_respond = -1;

    int callee_caps = -1;
    int media_features = -1;
    int service_route_enable = -1;
    int path_enable = -1;
    int substate = -1;

    sip_allow_t const *allow = NONE;
    char const   *allow_str = "NONE";
    sip_supported_t const *supported = NONE;
    char const *supported_str = "NONE";
    sip_user_agent_t const *user_agent = NONE;
    char const *user_agent_str = "NONE";
    sip_organization_t const *organization = NONE;
    char const *organization_str = "NONE";

    url_string_t const *registrar = NONE;

    int n;
    struct event *e;

    nua_get_hparams(nh, TAG_ANY(), TAG_END());
    run_a_until(ctx, nua_r_get_params, save_until_final_response);

    TEST_1(e = ctx->a.events->head);
    TEST_E(e->data->e_event, nua_r_get_params);

    n = tl_gets(e->data->e_tags,
	       	SIPTAG_FROM_REF(from),
	       	SIPTAG_FROM_STR_REF(from_str),

	       	NUTAG_RETRY_COUNT_REF(retry_count),
	       	NUTAG_MAX_SUBSCRIPTIONS_REF(max_subscriptions),

	       	NUTAG_ENABLEINVITE_REF(invite_enable),
	       	NUTAG_AUTOALERT_REF(auto_alert),
	       	NUTAG_EARLY_MEDIA_REF(early_media),
	       	NUTAG_AUTOANSWER_REF(auto_answer),
	       	NUTAG_AUTOACK_REF(auto_ack),
	       	NUTAG_INVITE_TIMER_REF(invite_timeout),

	       	NUTAG_SESSION_TIMER_REF(session_timer),
	       	NUTAG_MIN_SE_REF(min_se),
	       	NUTAG_SESSION_REFRESHER_REF(refresher),
	       	NUTAG_UPDATE_REFRESH_REF(update_refresh),

	       	NUTAG_ENABLEMESSAGE_REF(message_enable),
	       	NUTAG_ENABLEMESSENGER_REF(win_messenger_enable),
	       	/* NUTAG_MESSAGE_AUTOANSWER(message_auto_respond), */

	       	NUTAG_CALLEE_CAPS_REF(callee_caps),
	       	NUTAG_MEDIA_FEATURES_REF(media_features),
	       	NUTAG_SERVICE_ROUTE_ENABLE_REF(service_route_enable),
	       	NUTAG_PATH_ENABLE_REF(path_enable),
	       	NUTAG_SUBSTATE_REF(substate),

	       	SIPTAG_SUPPORTED_REF(supported),
	       	SIPTAG_SUPPORTED_STR_REF(supported_str),
	       	SIPTAG_ALLOW_REF(allow),
	       	SIPTAG_ALLOW_STR_REF(allow_str),
	       	SIPTAG_USER_AGENT_REF(user_agent),
	       	SIPTAG_USER_AGENT_STR_REF(user_agent_str),

	       	SIPTAG_ORGANIZATION_REF(organization),
	       	SIPTAG_ORGANIZATION_STR_REF(organization_str),

	       	NUTAG_REGISTRAR_REF(registrar),

		TAG_END());
    TEST(n, 3);

    TEST(invite_timeout, 90);

    TEST_1(from != NULL && from != NONE);
    TEST_1(strcmp(from_str, "NONE"));

    /* Nothing else should be set */
    TEST(retry_count, (unsigned)-1);
    TEST(max_subscriptions, (unsigned)-1);

    TEST(invite_enable, -1);
    TEST(auto_alert, -1);
    TEST(early_media, -1);
    TEST(auto_answer, -1);
    TEST(auto_ack, -1);

    TEST(session_timer, (unsigned)-1);
    TEST(min_se, (unsigned)-1);
    TEST(refresher, -1);
    TEST(update_refresh, -1);

    TEST(message_enable, -1);
    TEST(win_messenger_enable, -1);
    TEST(message_auto_respond, -1); /* XXX */

    TEST(callee_caps, -1);
    TEST(media_features, -1);
    TEST(service_route_enable, -1);
    TEST(path_enable, -1);
    TEST(substate, -1);

    TEST(allow, NONE);
    TEST_S(allow_str, "NONE");
    TEST(supported, NONE);
    TEST_S(supported_str, "NONE");
    TEST(user_agent, NONE);
    TEST_S(user_agent_str, "NONE");
    TEST(organization, NONE);
    TEST_S(organization_str, "NONE");

    TEST(registrar->us_url, NONE);

    free_events_in_list(ctx, ctx->a.events);
  }

  nua_handle_destroy(nh);

  nua_shutdown(ctx->a.nua);
  run_a_until(ctx, nua_r_shutdown, until_final_response);
  nua_destroy(ctx->a.nua), ctx->a.nua = NULL;

  su_root_destroy(ctx->root), ctx->root = NULL;

  su_home_deinit(tmphome);

  if (print_headings)
    printf("TEST NUA-1.1: PASSED\n");

  END();
}

/* ======================================================================== */

int test_stack_errors(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call;
  struct event *e;

  int internal_error = 900;

  if (print_headings)
    printf("TEST NUA-1.2: Stack error handling\n");

  if (print_headings)
    printf("TEST NUA-1.2.1: CANCEL without INVITE\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  CANCEL(a, a_call, a_call->nh, TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_cancel);
  TEST(e->data->e_status, 481);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-1.2.1: PASSED\n");

  /* -BYE without INVITE--------------------------------------------------- */

  if (print_headings)
    printf("TEST NUA-1.2.2: BYE without INVITE\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  BYE(a, a_call, a_call->nh, TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST(e->data->e_status, internal_error);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-1.2.2: PASSED\n");

  if (!ctx->proxy_tests)
    goto nua_1_2_5;

  /* -Un-register without REGISTER--------------------------------------- */

  if (print_headings)
    printf("TEST NUA-1.2.3: unregister without register\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(a->to), TAG_END()));

  UNREGISTER(a, a_call, a_call->nh, TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_unregister);
  TEST(e->data->e_status, 401);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-1.2.3: PASSED\n");

  /* -Un-publish without publish--------------------------------------- */

  if (print_headings)
    printf("TEST NUA-1.2.4: unpublish without publish\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  UNPUBLISH(a, a_call, a_call->nh, TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_unpublish);
  TEST(e->data->e_status, 404);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-1.2.4: PASSED\n");

  /* -terminate without notifier--------------------------------------- */

 nua_1_2_5:
  if (print_headings)
    printf("TEST NUA-1.2.5: terminate without notifier\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  TERMINATE(a, a_call, a_call->nh, TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_terminate);
  TEST(e->data->e_status, internal_error);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  AUTHORIZE(a, a_call, a_call->nh, TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_authorize);
  TEST(e->data->e_status, internal_error);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-1.2.5: PASSED\n");

  if (print_headings)
    printf("TEST NUA-1.2: PASSED\n");

  END();
}

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

/* ======================================================================== */
/* Test REGISTER */

int test_register(struct context *ctx)
{
  if (!ctx->proxy_tests)
    return 0;			/* No proxy */

  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b, *c = &ctx->c;
  struct call *a_reg = a->reg, *b_reg = b->reg, *c_reg = c->reg;
  struct event *e;
  sip_t const *sip;
  sip_cseq_t cseq[1];

  if (ctx->p)
    test_proxy_set_expiration(ctx->p, 5, 5, 10);

  if (print_headings)
    printf("TEST NUA-2.3.0.1: un-REGISTER a\n");

  TEST_1(a_reg->nh = nua_handle(a->nua, a_reg, TAG_END()));
  UNREGISTER(a, a_reg, a_reg->nh, SIPTAG_TO(a->to), 
	     SIPTAG_CONTACT_STR("*"),
	     TAG_END());
  run_a_until(ctx, -1, until_final_response);  
  AUTHENTICATE(a, a_reg, a_reg->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":alice:secret"), TAG_END());
  run_a_until(ctx, -1, until_final_response);
  nua_handle_destroy(a_reg->nh);

  if (print_headings)
    printf("TEST NUA-2.3.0.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.3.0.2: un-REGISTER b\n");

  TEST_1(b_reg->nh = nua_handle(b->nua, b_reg, TAG_END()));
  UNREGISTER(b, b_reg, b_reg->nh, SIPTAG_TO(b->to), 
	     SIPTAG_CONTACT_STR("*"),
	     TAG_END());
  run_b_until(ctx, -1, until_final_response);  
  AUTHENTICATE(b, b_reg, b_reg->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":bob:secret"), TAG_END());
  run_b_until(ctx, -1, until_final_response);
  nua_handle_destroy(b_reg->nh);

  if (print_headings)
    printf("TEST NUA-2.3.0.2: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.3.0.3: un-REGISTER c\n");

  TEST_1(c_reg->nh = nua_handle(c->nua, c_reg, TAG_END()));
  UNREGISTER(c, c_reg, c_reg->nh, SIPTAG_TO(c->to), 
	     SIPTAG_CONTACT_STR("*"),
	     TAG_END());
  run_c_until(ctx, -1, until_final_response);  
  AUTHENTICATE(c, c_reg, c_reg->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":charlie:secret"), TAG_END());
  run_c_until(ctx, -1, until_final_response);
  nua_handle_destroy(c_reg->nh);

  if (print_headings)
    printf("TEST NUA-2.3.0.3: PASSED\n");


/* REGISTER test

   A			B
   |------REGISTER----->|
   |<-------401---------|
   |------REGISTER----->|
   |<-------200---------|
   |			|

*/

  if (print_headings)
    printf("TEST NUA-2.3.1: REGISTER a\n");

  TEST_1(a_reg->nh = nua_handle(a->nua, a_reg, TAG_END()));

  sip_cseq_init(cseq)->cs_seq = 12;
  cseq->cs_method = sip_method_register;
  cseq->cs_method_name = sip_method_name_register;

  REGISTER(a, a_reg, a_reg->nh, SIPTAG_TO(a->to),
	   NUTAG_OUTBOUND("natify options-keepalive validate"),
	   NUTAG_KEEPALIVE(1000),
	   SIPTAG_CSEQ(cseq),
	   TAG_END());
  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(e->data->e_status, 401);
  TEST(sip->sip_status->st_status, 401);
  TEST(sip->sip_cseq->cs_seq, 13);
  TEST_1(!sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  AUTHENTICATE(a, a_reg, a_reg->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":alice:secret"), TAG_END());
  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_contact);
  TEST(sip->sip_cseq->cs_seq, 14);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  if (ctx->nat) {
    TEST_1(e = a->specials->head);
  }

  if (print_headings)
    printf("TEST NUA-2.3.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.3.2: REGISTER b\n");

  TEST_1(b_reg->nh = nua_handle(b->nua, b_reg, TAG_END()));

  REGISTER(b, b_reg, b_reg->nh, SIPTAG_TO(b->to), TAG_END());
  run_b_until(ctx, -1, save_until_final_response);

  TEST_1(e = b->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(e->data->e_status, 401);
  TEST(sip->sip_status->st_status, 401);
  TEST_1(!sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  AUTHENTICATE(b, b_reg, b_reg->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":bob:secret"), TAG_END());
  run_b_until(ctx, -1, save_until_final_response);

  TEST_1(e = b->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-2.3.2: PASSED\n");

  if (ctx->p)
    test_proxy_set_expiration(ctx->p, 30, 3600, 36000);

  if (print_headings)
    printf("TEST NUA-2.3.3: REGISTER c\n");

  TEST_1(c_reg->nh = nua_handle(c->nua, c_reg, TAG_END()));

  REGISTER(c, c_reg, c_reg->nh, SIPTAG_TO(c->to), 
	   SIPTAG_EXPIRES_STR("5"), /* Test 423 negotiation */
	   TAG_END());
  run_c_until(ctx, -1, save_until_final_response);

  TEST_1(e = c->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(e->data->e_status, 401);
  TEST(sip->sip_status->st_status, 401);
  TEST_1(!sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, c->events);

  AUTHENTICATE(c, c_reg, c_reg->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":charlie:secret"), TAG_END());
  run_c_until(ctx, -1, save_until_final_response);

  TEST_1(e = c->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST(e->data->e_status, 100);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(sip->sip_status->st_status, 423);
  TEST_1(e = e->next);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, c->events);

  if (print_headings)
    printf("TEST NUA-2.3.3: PASSED\n");

  if (!ctx->p)
    return 0;

  if (print_headings)
    printf("TEST NUA-2.3.4: refresh REGISTER\n");

  /* Wait for A and B to refresh their registrations */
  run_ab_until(ctx, -1, save_until_final_response, 
	       -1, save_until_final_response);
  
  TEST_1(e = a->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_contact);
  TEST_S(sip->sip_contact->m_expires, "3600");
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  TEST_1(e = b->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_contact);
  TEST_S(sip->sip_contact->m_expires, "3600");
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-2.3.4: PASSED\n");

  END();
}

int test_connectivity(struct context *ctx)
{
  if (!ctx->proxy_tests)
    return 0;			/* No proxy */

  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b, *c = &ctx->c;
  struct call *a_call = a->call, *b_call = b->call, *c_call = c->call;
  struct event *e;
  sip_t const *sip;

  /* Connectivity test using OPTIONS */

  if (print_headings)
    printf("TEST NUA-2.4.1: OPTIONS from A to B\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  OPTIONS(a, a_call, a_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	  TAG_END());

  run_ab_until(ctx, -1, save_until_final_response, -1, save_until_received);

  /* Client events: nua_options(), nua_r_options */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_options);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_allow); TEST_1(sip->sip_accept); TEST_1(sip->sip_supported);
  /* TEST_1(sip->sip_content_type); */
  /* TEST_1(sip->sip_payload); */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  /* Server events: nua_i_options */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_options);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-2.4.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.4.2: OPTIONS from B to C\n");

  TEST_1(b_call->nh = nua_handle(b->nua, b_call, SIPTAG_TO(c->to), TAG_END()));

  OPTIONS(b, b_call, b_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(c->contact->m_url)),
	  TAG_END());

  run_abc_until(ctx, -1, NULL,
		-1, save_until_final_response,
		-1, save_until_received);

  /* Client events: nua_options(), nua_r_options */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_options);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_allow); TEST_1(sip->sip_accept); TEST_1(sip->sip_supported);
  /* TEST_1(sip->sip_content_type); */
  /* TEST_1(sip->sip_payload); */
  TEST_1(!e->next);

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  /* Server events: nua_i_options */
  TEST_1(e = c->events->head); TEST_E(e->data->e_event, nua_i_options);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  free_events_in_list(ctx, c->events);
  nua_handle_destroy(c_call->nh), c_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-2.4.2: PASSED\n");

  if (print_headings)
    printf("TEST NUA-2.4.3: OPTIONS from C to A\n");

  TEST_1(c_call->nh = nua_handle(c->nua, c_call, SIPTAG_TO(a->to), TAG_END()));

  OPTIONS(c, c_call, c_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(a->contact->m_url)),
	  TAG_END());

  if (ctx->proxy_tests) {
    run_abc_until(ctx, -1, NULL, -1, NULL, -1, save_until_final_response);

    /* Client events: nua_options(), nua_r_options */
    TEST_1(e = c->events->head); TEST_E(e->data->e_event, nua_r_options);
    TEST(e->data->e_status, 407);
    TEST_1(!e->next);

    free_events_in_list(ctx, c->events);

    AUTHENTICATE(c, c_call, c_call->nh,
		 NUTAG_AUTH("Digest:\"test-proxy\":charlie:secret"),
		 TAG_END());
  }

  run_abc_until(ctx, -1, save_until_received,
		-1, NULL,
		-1, save_until_final_response);

  /* Client events: nua_options(), nua_r_options */
  TEST_1(e = c->events->head); TEST_E(e->data->e_event, nua_r_options);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_allow); TEST_1(sip->sip_accept); TEST_1(sip->sip_supported);
  /* TEST_1(sip->sip_content_type); */
  /* TEST_1(sip->sip_payload); */
  TEST_1(!e->next);

  free_events_in_list(ctx, c->events);
  nua_handle_destroy(c_call->nh), c_call->nh = NULL;

  /* Server events: nua_i_options */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_options);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-2.4.3: PASSED\n");

  END();
}

int test_nat_timeout(struct context *ctx)
{
  if (!ctx->proxy_tests || !ctx->nat)
    return 0;			/* No proxy */

  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b, *c = &ctx->c;
  struct event *e;
  sip_t const *sip;

  /* Test what happens when NAT bindings go away */

  if (print_headings)
    printf("TEST NUA-2.5.1: NAT binding change\n");

  free_events_in_list(ctx, a->specials);

  test_nat_flush(ctx->nat);	/* Break our connections */

  /* Run until we get final response to REGISTER */
  run_a_until(ctx, -1, save_until_final_response);

  TEST_1(e = a->specials->head);
  TEST_E(e->data->e_event, nua_i_outbound);
  TEST(e->data->e_status, 102);
  TEST_S(e->data->e_phrase, "NAT binding changed");
  TEST_1(!e->next);

  free_events_in_list(ctx, a->specials);

  TEST_1(e = a->events->head);
  TEST_E(e->data->e_event, nua_r_register);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-2.5.1: PASSED\n");
  
  (void)b; (void)c; (void)sip;

  END();
}

int test_unregister(struct context *ctx)
{
  if (!ctx->proxy_tests)
    return 0;			/* No proxy */

  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b, *c = &ctx->c;
  struct event *e;
  sip_t const *sip;

/* un-REGISTER test

   A			B
   |----un-REGISTER---->|
   |<-------200---------|
   |			|

*/
  if (print_headings)
    printf("TEST NUA-13.1: un-REGISTER a\n");

  if (a->reg->nh) {
    UNREGISTER(a, NULL, a->reg->nh, TAG_END());
    run_a_until(ctx, -1, save_until_final_response);
    TEST_1(e = a->events->head);
    TEST_E(e->data->e_event, nua_r_unregister);
    TEST(e->data->e_status, 200);
    TEST_1(sip = sip_object(e->data->e_msg));
    TEST_1(!sip->sip_contact);
    TEST_1(!e->next);
    free_events_in_list(ctx, a->events);
    nua_handle_destroy(a->reg->nh), a->reg->nh = NULL;
  }

  if (print_headings)
    printf("TEST NUA-13.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-13.2: un-REGISTER b\n");

  if (b->reg->nh) {
    UNREGISTER(b, NULL, b->reg->nh, TAG_END());
    run_b_until(ctx, -1, save_until_final_response);
    TEST_1(e = b->events->head);
    TEST_E(e->data->e_event, nua_r_unregister);
    TEST(e->data->e_status, 200);
    TEST_1(sip = sip_object(e->data->e_msg));
    TEST_1(!sip->sip_contact);
    TEST_1(!e->next);
    free_events_in_list(ctx, b->events);
    nua_handle_destroy(b->reg->nh), b->reg->nh = NULL;
  }
  if (print_headings)
    printf("TEST NUA-13.2: PASSED\n");

  if (print_headings)
    printf("TEST NUA-13.3: un-REGISTER c\n");

  /* Unregister using another handle */
  TEST_1(c->call->nh = nua_handle(c->nua, c->call, TAG_END()));
  UNREGISTER(c, c->call, c->call->nh, SIPTAG_TO(c->to), TAG_END());
  run_c_until(ctx, -1, save_until_final_response);

  TEST_1(e = c->events->head);
  TEST_E(e->data->e_event, nua_r_unregister);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(e->data->e_status, 401);
  TEST(sip->sip_status->st_status, 401);
  TEST_1(!sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, c->events);

  AUTHENTICATE(c, c->call, c->call->nh,
	       NUTAG_AUTH("Digest:\"test-proxy\":charlie:secret"), TAG_END());
  run_c_until(ctx, -1, save_until_final_response);

  TEST_1(e = c->events->head);
  TEST_E(e->data->e_event, nua_r_unregister);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(!sip->sip_contact);
  TEST_1(!e->next);
  free_events_in_list(ctx, c->events);
  nua_handle_destroy(c->call->nh), c->call->nh = NULL;

  if (c->reg->nh) {
    UNREGISTER(c, NULL, c->reg->nh, TAG_END());
    run_c_until(ctx, -1, save_until_final_response);
    TEST_1(e = c->events->head);
    TEST_E(e->data->e_event, nua_r_unregister);
    TEST(e->data->e_status, 200);
    TEST_1(sip = sip_object(e->data->e_msg));
    TEST_1(!sip->sip_contact);
    TEST_1(!e->next);
    free_events_in_list(ctx, c->events);
    nua_handle_destroy(c->reg->nh), c->reg->nh = NULL;
  }

  if (print_headings)
    printf("TEST NUA-13.3: PASSED\n");

  END();
}


/* ======================================================================== */

int until_terminated(CONDITION_PARAMS)
{
  if (!check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  return event == nua_i_state && callstate(tags) == nua_callstate_terminated;
}

/*
 X     accept_call    ep
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<----180 Ringing----|
 |                    |
 |<--------200--------|
 |---------ACK------->|
*/
int accept_call(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    RESPOND(ep, call, nh, SIP_200_OK,
	    TAG_IF(call->sdp, SOATAG_USER_SDP_STR(call->sdp)),
	    TAG_END());
    return 0;
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

/*
 accept_call_immediately
                      X
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<--------200--------|
 |---------ACK------->|
*/
int accept_call_immediately(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_200_OK,
	    TAG_IF(call->sdp, SOATAG_USER_SDP_STR(call->sdp)),
	    TAG_END());
    return 0;
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

/*
 X      INVITE
 |                    |
 |-------INVITE------>|
 |<--------200--------|
 |---------ACK------->|
*/
int until_ready(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}


/*
 INVITE without auto-ack
 X
 |                    |
 |-------INVITE------>|
 |<--------200--------|
 |                    |
 |---------ACK------->|
*/
int ack_when_completing(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_completing:
    ACK(ep, call, nh, TAG_END());
    return 0;
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}


/* ======================================================================== */

/* Basic call:

   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |<------200 OK-------|
   |--------ACK-------->|
   |			|
   |<-------BYE---------|
   |-------200 OK------>|
   |			|

   Client transitions:
   INIT -(C1)-> CALLING -(C2a)-> PROCEEDING -(C3+C4)-> READY
   Server transitions:
   INIT -(S1)-> RECEIVED -(S2a)-> EARLY -(S3b)-> COMPLETED -(S4)-> READY

   B sends BYE:
   READY -(T2)-> TERMINATING -(T3)-> TERMINATED
   A receives BYE:
   READY -(T1)-> TERMINATED

   See @page nua_call_model in nua.docs for more information
*/

int test_basic_call(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  if (print_headings)
    printf("TEST NUA-3.1: Basic call\n");

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  TEST_1(!nua_handle_has_active_call(a_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(a_call->nh));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, accept_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  TEST_1(nua_handle_has_active_call(a_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(a_call->nh));

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  TEST_1(nua_handle_has_active_call(b_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(b_call->nh));

  BYE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /* B transitions:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events->head);  TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  TEST_1(!nua_handle_has_active_call(b_call->nh));

  /* A transitions:
     READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  TEST_1(!nua_handle_has_active_call(a_call->nh));

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-3.1: PASSED\n");

  END();
}

/* ======================================================================== */
/* Tests NUA-4: Call rejections */

/*
 A      reject-1      B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<--------486--------|
 |---------ACK------->|
*/
int reject_1(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_486_BUSY_HERE, TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}


int test_reject_a(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  if (print_headings)
    printf("TEST NUA-4.1: reject before ringing\n");

  /*
   A      reject-1      B
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<--------486--------|
   |---------ACK------->|
  */

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));
  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-1"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, reject_1);

  /*
   Client transitions in reject-1:
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 486);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions in reject-1:
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-4.1: PASSED\n");

  END();
}

/*
 A      reject-2      B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<----180 Ringing----|
 |                    |
 |<--------602--------|
 |---------ACK------->|
*/
int reject_2(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    RESPOND(ep, call, nh, 602, "Rejected 2", TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

int test_reject_b(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  /* ------------------------------------------------------------------------ */
  /*
   A      reject-2      B
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |<--------602--------|
   |---------ACK------->|
  */

  if (print_headings)
    printf("TEST NUA-4.2: reject after ringing\n");

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  /* Make call reject-2 */
  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));
  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-2"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, reject_2);

  /*
   Client transitions in reject-2:
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(C6b)-> TERMINATED
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 602);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions in reject-2:
   INIT -(S1)-> RECEIVED -(S2)-> EARLY -(S6a)-> TERMINATED
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-4.2: PASSED\n");

  END();
}

/* ------------------------------------------------------------------------ */

int reject_302(CONDITION_PARAMS);
int reject_604(CONDITION_PARAMS);

/*
 A     reject-302     B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<-----302 Other-----|
 |--------ACK-------->|
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<----180 Ringing----|
 |                    |
 |<---604 Nowhere-----|
 |--------ACK-------->|
*/
int reject_302(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    {
      sip_contact_t m[1];
      *m = *ep->contact;
      m->m_url->url_user = "302";
      RESPOND(ep, call, nh, SIP_302_MOVED_TEMPORARILY,
	      SIPTAG_CONTACT(m), TAG_END());
    }
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    ep->next_condition = reject_604;
    return 0;
  default:
    return 0;
  }
}

int reject_604(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    RESPOND(ep, call, nh, SIP_604_DOES_NOT_EXIST_ANYWHERE, TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

int test_reject_302(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  /* Make call reject-3 */
  if (print_headings)
    printf("TEST NUA-4.3: redirect then reject\n");

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));
  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-3"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, reject_302);

  /*
   A      reject-3      B
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<-----302 Other-----|
   |--------ACK-------->|
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |<---604 Nowhere-----|
   |--------ACK-------->|
  */

  /*
   Client transitions in reject-3:
   INIT -(C1)-> PROCEEDING -(C6a)-> TERMINATED/INIT
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(C6b)-> TERMINATED
  */

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 100);
  TEST(sip_object(e->data->e_msg)->sip_status->st_status, 302);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 604);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED/INIT
   INIT -(S1)-> RECEIVED -(S2)-> EARLY -(S6b)-> TERMINATED
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-4.3: PASSED\n");

  END();
}

/* ------------------------------------------------------------------------ */

/* Reject call with 407, then 401 */

int reject_407(CONDITION_PARAMS);
int reject_401(CONDITION_PARAMS);
int authenticate_call(CONDITION_PARAMS);
int reject_403(CONDITION_PARAMS);

/*
 A     reject-401     B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |<--------407--------|
 |---------ACK------->|
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<----180 Ringing----|
 |                    |
 |<--------401--------|
 |---------ACK------->|
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |<-------403---------|
 |--------ACK-------->|
*/

int reject_407(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_407_PROXY_AUTH_REQUIRED,
	    SIPTAG_PROXY_AUTHENTICATE_STR("Digest realm=\"test_nua\", "
					  "nonce=\"nsdhfuds\", algorithm=MD5, "
					  "qop=\"auth-int\""),
	    TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    ep->next_condition = reject_401;
    return 0;
  default:
    return 0;
  }
}

int reject_401(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    RESPOND(ep, call, nh, SIP_401_UNAUTHORIZED,
	    SIPTAG_WWW_AUTHENTICATE_STR("Digest realm=\"test_nua\", "
					"nonce=\"nsdhfuds\", algorithm=MD5, "
					"qop=\"auth\""),
	    TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    ep->next_condition = reject_403;
    return 0;
  default:
    return 0;
  }
}

int reject_403(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_403_FORBIDDEN, TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    ep->next_condition = NULL;
    return 1;
  default:
    return 0;
  }
}

int authenticate_call(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  if (event == nua_r_invite && status == 401) {
    AUTHENTICATE(ep, call, nh, NUTAG_AUTH("Digest:\"test_nua\":jaska:secret"),
		 SIPTAG_SUBJECT_STR("Got 401"),
		 TAG_END());
    return 0;
  }

  if (event == nua_r_invite && status == 407) {
    AUTHENTICATE(ep, call, nh, NUTAG_AUTH("Digest:\"test_nua\":erkki:secret"),
		 SIPTAG_SUBJECT_STR("Got 407"),
		 TAG_END());
    return 0;
  }

  switch (callstate(tags)) {
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

int test_reject_401(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event const *e;
  sip_t const *sip;

  if (print_headings)
    printf("TEST NUA-4.4: challenge then reject\n");

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));
  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-401"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());
  run_ab_until(ctx, -1, authenticate_call, -1, reject_407);

  /*
   Client transitions in reject-3:
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(C6b)-> TERMINATED/INIT
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(sip_object(e->data->e_msg)->sip_status->st_status, 407);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 401);
  TEST(sip_object(e->data->e_msg)->sip_status->st_status, 401);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 403);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED/INIT
   INIT -(S1)-> RECEIVED -(S2)-> EARLY -(S6b)-> TERMINATED/INIT
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_subject);
  TEST_S(sip->sip_subject->g_value, "reject-401");
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_invite);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_subject);
  TEST_S(sip->sip_subject->g_value, "Got 407");
  TEST_1(sip->sip_proxy_authorization);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_invite);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_subject);
  TEST_S(sip->sip_subject->g_value, "Got 401");
  TEST_1(sip->sip_authorization);
  TEST_1(sip->sip_proxy_authorization);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, b->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-4.4: PASSED\n");

  END();
}

/* ------------------------------------------------------------------------ */

/* Reject call with 401 and bad challenge */

/*
 A   reject-401-aka   B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |<--------401--------|
 |---------ACK------->|
*/

int reject_401_aka(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_401_UNAUTHORIZED,
	    /* Send a challenge that we do not grok */
	    SIPTAG_WWW_AUTHENTICATE_STR("Digest realm=\"test_nua\", "
					"nonce=\"nsdhfuds\", algorithm=SHA0-AKAv6, "
					"qop=\"auth\""),
	    TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

int test_reject_401_aka(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event const *e;
  sip_t const *sip;

  if (print_headings)
    printf("TEST NUA-4.6: invalid challenge \n");

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));
  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-401-aka"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, until_terminated, -1, reject_401_aka);

  /*
   Client transitions
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED/INIT
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(sip_object(e->data->e_msg)->sip_status->st_status, 401);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, b->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-4.6: PASSED\n");

  END();
}


/* ---------------------------------------------------------------------- */

int test_mime_negotiation(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;
  sip_t const *sip;

  /* Make call reject-3 */
  if (print_headings)
    printf("TEST NUA-4.5: check for rejections of invalid requests\n");

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  if (print_headings)
    printf("TEST NUA-4.5.1: invalid Content-Type\n");

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-3"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 SIPTAG_CONTENT_TYPE_STR("application/xyzzy+xml"),
	 SIPTAG_CONTENT_DISPOSITION_STR("session;required"),
	 SIPTAG_PAYLOAD_STR("m=audio 5008 RTP/AVP 8\n"),
	 TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, NULL);

  /*
   A    reject-5.1      B
   |			|
   |-------INVITE------>|
   |<-------415---------|
   |--------ACK-------->|
  */

  /*
   Client transitions in reject-3:
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED
  */

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 415);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(sip->sip_status->st_status, 415);
  TEST_1(sip->sip_accept);
  TEST_S(sip->sip_accept->ac_type, "application/sdp");
  TEST_1(sip->sip_accept_encoding);
  /* No content-encoding is supported */
  TEST_S(sip->sip_accept_encoding->aa_value, "");
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* CALLING */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-4.5.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-4.5.2: invalid Content-Encoding\n");

  /*
   A    reject-5.2      B
   |			|
   |-------INVITE------>|
   |<-------415---------|
   |--------ACK-------->|
  */

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-5"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 SIPTAG_CONTENT_ENCODING_STR("zyxxy"),
	 TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, NULL);

  /*
   Client transitions in reject-3:
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED
  */

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 415);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(sip->sip_status->st_status, 415);
  TEST_1(sip->sip_accept);
  TEST_S(sip->sip_accept->ac_type, "application/sdp");
  TEST_1(sip->sip_accept_encoding);
  /* No content-encoding is supported */
  TEST_S(sip->sip_accept_encoding->aa_value, "");
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-4.5.2: PASSED\n");

  if (print_headings)
    printf("TEST NUA-4.5.3: invalid Accept\n");

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SIPTAG_SUBJECT_STR("reject-3"),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 SIPTAG_ACCEPT_STR("application/xyzzy+xml"),
	 TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, NULL);


  /*
   A    reject-5.3      B
   |			|
   |-------INVITE------>|
   |<-------406---------|
   |--------ACK-------->|
  */

  /*
   Client transitions in reject-3:
   INIT -(C1)-> PROCEEDING -(C6a)-> TERMINATED
  */

  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 406);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(sip->sip_status->st_status, 406);
  TEST_1(sip->sip_accept);
  TEST_S(sip->sip_accept->ac_type, "application/sdp");
  TEST_1(sip->sip_accept_encoding);
  /* No content-encoding is supported */
  TEST_S(sip->sip_accept_encoding->aa_value, "");
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* CALLING */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-4.5.3: PASSED\n");

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-4.5: PASSED\n");

  END();
}

/* ======================================================================== */

/* Cancel cases:


   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |------CANCEL------->|
   |<------200 OK-------|
   |			|
   |<-------487---------|
   |--------ACK-------->|
   |			|
   |			|

   Client transitions:
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED

   Server transitions:
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED

   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |------CANCEL------->|
   |<------200 OK-------|
   |			|
   |<-------487---------|
   |--------ACK-------->|
   |			|
   |			|

   Client transitions:
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(C6b)-> TERMINATED

   Server transitions:
   INIT -(S1)-> RECEIVED -(S2a)-> EARLY -(S6b)-> TERMINATED

*/

int cancel_when_calling(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_calling:
    CANCEL(ep, call, nh, TAG_END());
    return 0;
  case nua_callstate_terminated:
    return 1;
  default:
    return 0;
  }
}


int cancel_when_ringing(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_proceeding:
    CANCEL(ep, call, nh, TAG_END());
    return 0;
  case nua_callstate_terminated:
    return 1;
  default:
    return 0;
  }
}


int alert_call(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_terminated:
    return 1;
  default:
    return 0;
  }
}


int test_call_cancel(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  if (print_headings)
    printf("TEST NUA-5.1: cancel call\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, cancel_when_calling, -1, until_terminated);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state, nua_cancel()
     CALLING -(C6a)-> TERMINATED: nua_r_invite(487), nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_cancel);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 487);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S6a)--> TERMINATED: nua_i_cancel, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_cancel);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-5.1: PASSED\n");

  /* ------------------------------------------------------------------------ */

  if (print_headings)
    printf("TEST NUA-5.2: cancel call when ringing\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 /*SIPTAG_REJECT_CONTACT_STR("*;audio=FALSE"),*/
	 TAG_END());

  run_ab_until(ctx, -1, cancel_when_ringing, -1, alert_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite(180, nua_i_state, nua_cancel()
     PROCEEDING -(C6b)-> TERMINATED: nua_r_invite(487), nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_cancel);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 487);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(180), nua_i_state
   EARLY -(S6b)--> TERMINATED: nua_i_cancel, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_cancel);
  TEST(e->data->e_status, 200);
  /* Check for bug #1326727 */
  TEST_1(e->data->e_msg);
#if 0
  TEST_1(sip_object(e->data->e_msg)->sip_reject_contact);
  TEST_1(sip_object(e->data->e_msg)->sip_reject_contact->cp_params &&
	 sip_object(e->data->e_msg)->sip_reject_contact->cp_params[0]);
  TEST_S(sip_object(e->data->e_msg)->sip_reject_contact->cp_params[0],
	 "audio=FALSE");
#endif
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-5.2: PASSED\n");

  END();
}

/* ======================================================================== */
/* Early BYE

   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |--------BYE-------->|
   |<------200 OK-------|
   |			|
   |<-------487---------|
   |--------ACK-------->|
   |			|
   |			|

   Client transitions:
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(8)-> TERMINATING -> TERMINATED

   Server transitions:
   INIT -(S1)-> RECEIVED -(S2a)-> EARLY -(S8)-> TERMINATED

*/

int bye_when_ringing(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (callstate(tags)) {
  case nua_callstate_proceeding:
    BYE(ep, call, nh, TAG_END());
    return 0;
  case nua_callstate_terminated:
    return 1;
  default:
    return 0;
  }
}

int test_early_bye(struct context *ctx)
{
  BEGIN();
  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  if (print_headings)
    printf("TEST NUA-6.1: BYE call when ringing\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, bye_when_ringing, -1, alert_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite(180, nua_i_state, nua_cancel()
     PROCEEDING -(C6b)-> TERMINATED: nua_r_invite(487), nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next);
  if (e->data->e_event == nua_r_bye) {
    /* We might receive this before or after response to INVITE */
    /* If afterwards, it will come after nua_i_state and we just ignore it */
    TEST_E(e->data->e_event, nua_r_bye); TEST(e->data->e_status, 200);
    TEST_1(e->data->e_msg);
    /* Forking has not been enabled, so this should be actually a CANCEL */
    TEST(sip_object(e->data->e_msg)->sip_cseq->cs_method, sip_method_cancel);
    TEST_1(e = e->next);
  }
  TEST_E(e->data->e_event, nua_r_invite); TEST(e->data->e_status, 487);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(180), nua_i_state
   EARLY -(S6b)--> TERMINATED: nua_i_cancel, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  /* Forking has not been enabled, so this should be actually a CANCEL */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_cancel);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-6.1: PASSED\n");

  END();
}

/* ======================================================================== */
/* Call hold */


/* test_call_hold message sequence looks like this:

 A                    B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<----180 Ringing----|
 |                    |
 |<--------200--------|
 |---------ACK------->|
 :                    :
 |--INVITE(sendonly)->|
 |<---200(recvonly)---|
 |---------ACK------->|
 :                    :
 |<-INVITE(inactive)--|
 |----200(inactive)-->|
 |<--------ACK--------|
 :                    :
 |--INVITE(recvonly)->|
 |<---200(sendonly)---|
 |---------ACK------->|
 :                    :
 |<-INVITE(sendrecv)--|
 |----200(sendrecv)-->|
 |<--------ACK--------|
 :                    :
 |--------INFO------->|
 |<--------200--------|
 :                    :
 |---------BYE------->|
 |<--------200--------|
*/

int test_call_hold(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;

  if (print_headings)
    printf("TEST NUA-7: Test call hold\n");

  a_call->sdp =
    "m=audio 5008 RTP/AVP 0 8\n"
    "m=video 6008 RTP/AVP 30\n";
  b_call->sdp =
    "m=audio 5010 RTP/AVP 8\n"
    "a=rtcp:5011\n"
    "m=video 6010 RTP/AVP 30\n"
    "a=rtcp:6011\n";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));
  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, accept_call);

  /*
    Client transitions:
    INIT -(C1)-> CALLING: nua_invite(), nua_i_state
    CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
    PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  TEST_1(nua_handle_has_active_call(a_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(a_call->nh));

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(b_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(b_call->nh));

  free_events_in_list(ctx, b->events);

  /*
 :                    :
 |--INVITE(sendonly)->|
 |<---200(recvonly)---|
 |---------ACK------->|
 :                    :
  */

  if (print_headings)
    printf("TEST NUA-7.1: put B on hold\n");

  /* Put B on hold */
  INVITE(a, a_call, a_call->nh, SOATAG_HOLD("audio"),
	 SIPTAG_SUBJECT_STR("hold b"),
	 TAG_END());
  run_ab_until(ctx, -1, until_ready, -1, until_ready);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3a+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDONLY);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(a_call->nh));
  TEST_1(nua_handle_has_call_on_hold(a_call->nh));

  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   READY -(S3a)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_RECVONLY);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_RECVONLY);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(b_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(b_call->nh));

  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-7.1: PASSED\n");

  /* ------------------------------------------------------------------------ */
  /*
 :                    :
 |<-INVITE(inactive)--|
 |----200(inactive)-->|
 |<--------ACK--------|
 :                    :
  */

  if (print_headings)
    printf("TEST NUA-7.2: put A on hold\n");

  /* Put A on hold, too. */
  INVITE(b, b_call, b_call->nh, SOATAG_HOLD("audio"),
	 SIPTAG_SUBJECT_STR("hold a"),
	 TAG_END());
  run_ab_until(ctx, -1, until_ready, -1, until_ready);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3a+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_INACTIVE);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(b_call->nh));
  TEST_1(nua_handle_has_call_on_hold(b_call->nh));

  free_events_in_list(ctx, b->events);

  /*
   Server transitions:
   READY -(S3a)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_INACTIVE);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_INACTIVE);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(a_call->nh));
  TEST_1(nua_handle_has_call_on_hold(a_call->nh));

  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-7.2: PASSED\n");

  /* ------------------------------------------------------------------------ */
  /*
 :                    :
 |--INVITE(recvonly)->|
 |<---200(sendonly)---|
 |---------ACK------->|
 :                    :
  */

  if (print_headings)
    printf("TEST NUA-7.3: resume B\n");

  /* Resume B from hold */
  INVITE(a, a_call, a_call->nh, SOATAG_HOLD(NULL),
	 SIPTAG_SUBJECT_STR("resume b"),
	 TAG_END());
  run_ab_until(ctx, -1, until_ready, -1, until_ready);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3a+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_RECVONLY);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  TEST_1(nua_handle_has_active_call(a_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(a_call->nh));

  /*
   Server transitions:
   READY -(S3a)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDONLY);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDONLY);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(b_call->nh));
  TEST_1(nua_handle_has_call_on_hold(b_call->nh));

  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-7.3: PASSED\n");

  /* ------------------------------------------------------------------------ */
  /*
 :                    :
 |<-INVITE(sendrecv)--|
 |----200(sendrecv)-->|
 |<--------ACK--------|
 :                    :
  */

  if (print_headings)
    printf("TEST NUA-7.4: resume A\n");

  /* Resume A on hold, too. */
  INVITE(b, b_call, b_call->nh, SOATAG_HOLD(""),
	 SIPTAG_SUBJECT_STR("TEST NUA-7.4: resume A"),
	 TAG_END());
  run_ab_until(ctx, -1, until_ready, -1, until_ready);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3a+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  TEST_1(nua_handle_has_active_call(a_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(a_call->nh));

  /*
   Server transitions:
   READY -(S3a)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  TEST_1(nua_handle_has_active_call(b_call->nh));
  TEST_1(!nua_handle_has_call_on_hold(b_call->nh));

  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-7.4: PASSED\n");

  /* ---------------------------------------------------------------------- */
  /*
 A                    B
 |--------INFO------->|
 |<--------200--------|
   */
  if (print_headings)
    printf("TEST NUA-7.5: send INFO\n");

  INFO(a, a_call, a_call->nh, TAG_END());
  run_a_until(ctx, -1, save_until_final_response);
  /* XXX - B should get a  nua_i_info event with 405 */

  /* A sent INFO, receives 405 */
  TEST_1(e = a->events->head);  TEST_E(e->data->e_event, nua_r_info);
  TEST(e->data->e_status, 405);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

#if 0				/* XXX */
  /* B received INFO */
  TEST_1(e = b->events->head);  TEST_E(e->data->e_event, nua_i_info);
  TEST(e->data->e_status, 405);
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);
#endif

  /* Add INFO to allowed methods */
  nua_set_hparams(b_call->nh, NUTAG_ALLOW("INFO, PUBLISH"), TAG_END());
  run_b_until(ctx, nua_r_set_params, until_final_response);

  INFO(a, a_call, a_call->nh, TAG_END());
  run_ab_until(ctx, -1, save_until_final_response, -1, save_until_received);

  /* A sent INFO, receives 200 */
  TEST_1(e = a->events->head);  TEST_E(e->data->e_event, nua_r_info);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /* B received INFO */
  TEST_1(e = b->events->head);  TEST_E(e->data->e_event, nua_i_info);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-7.5: PASSED\n");

  /* ------------------------------------------------------------------------ */
  /*
 :                    :
 |<------INVITE-------|
 |--------200-------->|
 |<--------ACK--------|
 :                    :
  */

  if (print_headings)
    printf("TEST NUA-7.6: re-INVITE without auto-ack\n");

  /* Turn off auto-ack */
  nua_set_hparams(b_call->nh, NUTAG_AUTOACK(0), TAG_END());
  run_b_until(ctx, nua_r_set_params, until_final_response);

  INVITE(b, b_call, b_call->nh, SOATAG_HOLD(""),
	 SIPTAG_SUBJECT_STR("TEST NUA-7.6: re-INVITE without auto-ack"),
	 TAG_END());
  run_ab_until(ctx, -1, until_ready, -1, ack_when_completing);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3a)-> COMPLETING: nua_r_invite, nua_i_state
     COMPLETING -(C4)-> READY: nua_ack(), nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completing); /* COMPLETING */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /*
   Server transitions:
   READY -(S3a)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-7.6: PASSED\n");


  /* ---------------------------------------------------------------------- */
  /*
 A                    B
 |---------BYE------->|
 |<--------200--------|
   */

  if (print_headings)
    printf("TEST NUA-7.6: terminate call\n");

  BYE(a, a_call, a_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /*
   Transitions of A:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /* Transitions of B:
     READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-7.6: PASSED\n");

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-7: PASSED\n");


  END();
}


/* ======================================================================== */
/* Session timer, UPDATE */

int test_session_timer(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;
  sip_t const *sip;

  if (print_headings)
    printf("TEST NUA-8.1: Session timers\n");

/* Session timer test:

   A			B
   |-------INVITE------>|
   |<-------422---------|
   |--------ACK-------->|
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |<------200 OK-------|
   |--------ACK-------->|
   |			|
   |<-------BYE---------|
   |-------200 OK-------|
   |			|

*/

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 NUTAG_SESSION_TIMER(15),
	 NUTAG_MIN_SE(5),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, accept_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C6a)-> (TERMINATED/INIT): nua_r_invite
     (INIT) -(C1)-> CALLING: nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 100);
  TEST(sip_object(e->data->e_msg)->sip_status->st_status, 422);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_session_expires);
  TEST_S(sip->sip_session_expires->x_refresher, "uac");
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-8.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-8.2: use UPDATE\n");

  UPDATE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_ready, -1, until_ready);

  /* Events from B (who sent UPDATE) */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_offer_sent(e->data->e_tags));
  if (!e->next)
    run_b_until(ctx, -1, until_ready);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_update);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_session_expires);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /* Events from A (who received UPDATE) */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_update);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_session_expires);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  BYE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /* B transitions:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /* A: READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-8.2: PASSED\n");

  END();
}

/* ======================================================================== */
/* NUA-9 tests: REFER */

/* Referred call:

   A			B
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<----180 Ringing----|
   |			|
   |<------200 OK-------|
   |--------ACK-------->|
   |			|
   |<------REFER--------|
   |-------200 OK------>|			C
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   |			|			|
   |			|			|
   |<-----SUBSCRIBE-----|                       |
   |-------200 OK------>|			|
   |			|			|
   |			|			|
   |-----------------INVITE-------------------->|
   |			|			|
   |<------------------180----------------------|
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   |			|			|
   |<------------------200----------------------|
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   |-------------------ACK--------------------->|
   |			|			|
   |--------BYE-------->|			|
   |<------200 OK-------|			|
   |			X			|
   |			 			|
   |-------------------BYE--------------------->|
   |<------------------200----------------------|
   |						|

*/


int test_refer(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b, *c = &ctx->c;
  struct call *a_call = a->call, *b_call = b->call, *c_call = c->call;
  struct call *a_c2;
  struct event *e;
  sip_t const *sip;
  sip_event_t const *r_event;
  sip_refer_to_t const *refer_to;
  sip_referred_by_t const *referred_by;

  sip_refer_to_t r0[1];
  sip_to_t to[1];

  su_home_t tmphome[SU_HOME_AUTO_SIZE(16384)];

  su_home_auto(tmphome, sizeof(tmphome));

  if (print_headings)
    printf("TEST NUA-9.1.1: REFER: make a call between A and B\n");

  TEST_1(a_c2 = calloc(1, (sizeof *a_c2) + (sizeof *a_c2->events)));
  call_init(a_c2);
  a_c2->events = (void *)(a_c2 + 1);
  eventlist_init(a_c2->events);

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";
  a_c2->sdp   = "m=audio 5012 RTP/AVP 8";
  c_call->sdp = "m=audio 5014 RTP/AVP 0 8";

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, accept_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-9.1.1: PASSED\n");

  /* ---------------------------------------------------------------------- */
  /*
   A                    B
   |<------REFER--------|
   |-------200 OK------>|
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   */

  if (print_headings)
    printf("TEST NUA-9.1.2: refer A to C\n");

  /* XXX: check header parameters! */
  *sip_refer_to_init(r0)->r_url = *c->contact->m_url;
  r0->r_display = "C";

  REFER(b, b_call, b_call->nh, SIPTAG_REFER_TO(r0), TAG_END());
  run_ab_until(ctx, -1, save_until_final_response,
	       -1, save_until_final_response);

  /*
    Events in A:
    nua_i_refer
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_refer);
  TEST(e->data->e_status, 202);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_refer_to);
  TEST_1(refer_to = sip_refer_to_dup(tmphome, sip->sip_refer_to));
  TEST_1(sip->sip_referred_by);
  TEST_1(referred_by = sip_referred_by_dup(tmphome, sip->sip_referred_by));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_notify);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
     Events in B after nua_refer():
     nua_r_refer
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_refer);
  TEST(e->data->e_status, 100);
  TEST(tl_gets(e->data->e_tags,
	       NUTAG_REFER_EVENT_REF(r_event),
	       TAG_END()), 1);
  TEST_1(r_event); TEST_1(r_event->o_id);
  TEST_1(r_event = sip_event_dup(tmphome, r_event));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_refer);
  TEST(e->data->e_status, 202);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST(strtoul(r_event->o_id, NULL, 10), sip->sip_cseq->cs_seq);
  if (!e->next)
    run_b_until(ctx, -1, save_until_received);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_notify);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event);
  TEST_S(sip->sip_event->o_id, r_event->o_id);
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "pending");
  TEST_1(sip->sip_payload && sip->sip_payload->pl_data);
  TEST_S(sip->sip_payload->pl_data, "SIP/2.0 100 Trying\r\n");
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-9.1.2: PASSED\n");

  /* ---------------------------------------------------------------------- */
  /*
   A                    B
   |<-----SUBSCRIBE-----|
   |-------200 OK------>|
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   */

  if (print_headings)
    printf("TEST NUA-9.1.3: extend expiration time for implied subscription\n");

  SUBSCRIBE(b, b_call, b_call->nh,
	    SIPTAG_EVENT(r_event),
	    SIPTAG_EXPIRES_STR("3600"),
	    TAG_END());
  run_ab_until(ctx, -1, save_until_final_response,
	       -1, save_until_final_response);

  /*
    Events in A:
    nua_i_subscribe, nua_r_notify
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_subscribe);
  TEST(e->data->e_status, 202);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_notify);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
     Events in B after nua_subscribe():
     nua_r_subscribe, nua_i_notify
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_subscribe);
  TEST(e->data->e_status, 202);
  if (!e->next)
    run_b_until(ctx, -1, save_until_received);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_notify);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event);
  TEST_S(sip->sip_event->o_id, r_event->o_id);
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "pending");
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-9.1.3: PASSED\n");

  /* ---------------------------------------------------------------------- */
  /*
   A                    B                       C
   |			|			|
   |-----------------INVITE-------------------->|
   |			|			|
  XXX			|			|
   | 			|			|
   |<------------------180----------------------|
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   | 			|			|
  XXX			|			|
   |			|			|
   |<------------------200----------------------|
   |-------NOTIFY------>|			|
   |<------200 OK-------|			|
   |-------------------ACK--------------------->|
   */

  if (print_headings)
    printf("TEST NUA-9.1.3: A invites C\n");

  *sip_to_init(to)->a_url = *refer_to->r_url;
  to->a_display = refer_to->r_display;

  a->call->next = a_c2;

  TEST_1(a_c2->nh = nua_handle(a->nua, a_c2, SIPTAG_TO(to), TAG_END()));

  INVITE(a, a_c2, a_c2->nh, /* NUTAG_URL(refer_to->r_url), */
	 NUTAG_REFER_EVENT(r_event),
	 NUTAG_NOTIFY_REFER(a_call->nh),
	 SOATAG_USER_SDP_STR(a_c2->sdp),
	 SIPTAG_REFERRED_BY(referred_by),
	 TAG_END());

  run_abc_until(ctx,
		-1, until_ready,
		-1, save_until_received,
		-1, accept_call_immediately);
  /* XXX - we should use accept_call instead of accept_call_immediately but
     nua has a problem with automatically generated NOTIFYs:
     3rd NOTIFY is not sent because 2nd is still in progress
  */

  /* Client A transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2a+C4)-> READY: nua_r_invite, nua_i_state
     nua_i_notify

     XXX should be:
     CALLING -(C2+C4)-> PROCEEDING: nua_r_invite, nua_i_state
     optional: nua_i_notify
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
     nua_i_notify
     optional: nua_i_notify
  */
  TEST_1(e = a_c2->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a_c2->events);

  if (a->events->head == NULL)
    run_a_until(ctx, -1, save_until_received);
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_notify);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
     Events in B after nua_refer():
     nua_i_notify
  */
  if (b->events->head == NULL)
    run_b_until(ctx, -1, save_until_received);
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_notify);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "terminated");
  TEST_1(sip->sip_payload && sip->sip_payload->pl_data);
  TEST_S(sip->sip_payload->pl_data, "SIP/2.0 200 OK\r\n");
  TEST_1(sip->sip_event);
  TEST_S(sip->sip_event->o_id, r_event->o_id);
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /*
   C transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = c->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags));
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!e->next);
  free_events_in_list(ctx, c->events);

  if (print_headings)
    printf("TEST NUA-9.1.3: PASSED\n");

  /* ---------------------------------------------------------------------- */
  /*
 A                    B
 |---------BYE------->|
 |<--------200--------|
   */

  if (print_headings)
    printf("TEST NUA-9.1.4: terminate call between A and B\n");

  BYE(a, a_call, a_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /*
   Transitions of A:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /* Transitions of B:
     READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-9.1.4: PASSED\n");

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;


  /* ---------------------------------------------------------------------- */
  /*
   A                                            C
   |-------------------BYE--------------------->|
   |<------------------200----------------------|
   */

  if (print_headings)
    printf("TEST NUA-9.1.5: terminate call between A and C\n");

  BYE(a, a_c2, a_c2->nh, TAG_END());
  run_abc_until(ctx, -1, until_terminated, -1, NULL, -1, until_terminated);

  /*
   Transitions of A:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = a_c2->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a_c2->events);

  /* Transitions of B:
     READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state
  */
  TEST_1(e = c->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, c->events);

  if (print_headings)
    printf("TEST NUA-9.1.5: PASSED\n");

  nua_handle_destroy(a_c2->nh), a_c2->nh = NULL;
  a->call->next = NULL; free(a_c2);

  nua_handle_destroy(c_call->nh), c_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-9: PASSED\n");

  su_home_deinit(tmphome);

  END();
}

/* ======================================================================== */
/* NUA-10 tests: early session, PRACK, UPDATE, precondition */

/*
 X  accept_pracked    ep
 |-------INVITE------>|
 |        (sdp)       |
 |                    |
 |<----100 Trying-----|
 |                    |
 |<-------180---------|
 |       (sdp)        |
 |-------PRACK------->|
 |<-------200---------|
 |                    |
 |<------200 OK-------|
 |--------ACK-------->|
 |                    |
*/
int accept_pracked(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (event) {
  case nua_i_prack:
    if (200 <= status && status < 300) {
      RESPOND(ep, call, nh, SIP_200_OK, TAG_END());
      ep->next_condition = until_ready;
    }
  default:
    break;
  }

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_180_RINGING,
	    TAG_IF(call->sdp, SOATAG_USER_SDP_STR(call->sdp)),
	    TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}


/*
 X  ringing_pracked    ep
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<-------183---------|
 |-------PRACK------->|
 |<-------200---------|
 |                    |
 |<-------180---------|
 |-------PRACK------->|
 |<-------200---------|
 |                    |
 |<------200 OK-------|
 |--------ACK-------->|
 |                    |
*/
int ringing_pracked(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (event) {
  case nua_i_prack:
    if (200 <= status && status < 300) {
      RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
      ep->next_condition = accept_pracked;
    }
  default:
    break;
  }

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_183_SESSION_PROGRESS,
	    TAG_IF(call->sdp, SOATAG_USER_SDP_STR(call->sdp)),
	    TAG_END());
    return 0;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

/*
 X  accept_updated    ep
 |-------INVITE------>|
 |       (sdp)        |
 |<----100 Trying-----|
 |                    |
 |<-------183---------|
 |       (sdp)        |
 |-------PRACK------->|
 |       (sdp)        |
 |<-------200---------|
 |       (sdp)        |
 |                    |
 |-------UPDATE------>|
 |       (sdp)        |
 |<-------200---------|
 |       (sdp)        |
 |                    |
<using  acccept_pracked>
 |                    |
 |<-------180---------|
 |-------PRACK------->|
 |<-------200---------|
 |                    |
 |<------200 OK-------|
 |--------ACK-------->|
 |                    |
*/
int ringing_updated(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (event) {
  case nua_i_update:
    if (200 <= status && status < 300) {
      RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
      ep->next_condition = accept_pracked;
    }
    return 0;
  default:
    break;
  }

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_183_SESSION_PROGRESS,
	    SIPTAG_REQUIRE_STR("100rel"),
	    TAG_IF(call->sdp, SOATAG_USER_SDP_STR(call->sdp)),
	    TAG_END());
    return 0;
  case nua_callstate_early:
    return 0;
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

/*
 X  accept_updated    ep
 |-------INVITE------>|
 |       (sdp)        |
 |<----100 Trying-----|
 |                    |
 |<-------183---------|
 |       (sdp)        |
 |-------PRACK------->|
 |       (sdp)        |
 |<-------200---------|
 |       (sdp)        |
 |                    |
 |-------UPDATE------>|
 |       (sdp)        |
 |<-------200---------|
 |       (sdp)        |
 |                    |
 |                    |
 |<-------180---------|
 |                    |
 |<------200 OK-------|
 |--------ACK-------->|
 |                    |
*/
int accept_updated(CONDITION_PARAMS)
{
  if (!(check_handle(ep, call, nh, SIP_500_INTERNAL_SERVER_ERROR)))
    return 0;

  save_event_in_list(ctx, event, ep, call);

  switch (event) {
  case nua_i_update:
    if (200 <= status && status < 300) {
      RESPOND(ep, call, nh, SIP_180_RINGING, TAG_END());
    }
    return 0;
  default:
    break;
  }

  switch (callstate(tags)) {
  case nua_callstate_received:
    RESPOND(ep, call, nh, SIP_183_SESSION_PROGRESS,
	    SIPTAG_REQUIRE_STR("100rel"),
	    TAG_IF(call->sdp, SOATAG_USER_SDP_STR(call->sdp)),
	    TAG_END());
    return 0;
  case nua_callstate_early:
    if (status == 180)
      RESPOND(ep, call, nh, SIP_200_OK, TAG_END());
    return 0;
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    if (call)
      nua_handle_destroy(call->nh), call->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

int test_100rel(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;


  if (print_headings)
    printf("TEST NUA-10.1: Call with 100rel and 180\n");

/* Test for 100rel:

   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<-------180---------|
   |-------PRACK------->|
   |<-------200---------|
   |			|
   |<------200 OK-------|
   |--------ACK-------->|
   |			|
   |<-------BYE---------|
   |-------200 OK-------|
   |			|

*/

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  nua_set_params(ctx->a.nua,
		 NUTAG_EARLY_MEDIA(1),
		 TAG_END());
  run_a_until(ctx, nua_r_set_params, until_final_response);

  nua_set_params(ctx->b.nua,
		 NUTAG_EARLY_MEDIA(1),
		 TAG_END());
  run_b_until(ctx, nua_r_set_params, until_final_response);

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, accept_pracked);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state, nua_r_prack
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_prack);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));

  /* Responded with 180 Ringing */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_answer_sent(e->data->e_tags));

  /* 180 is PRACKed */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_prack);
  /* Does not have effect on call state */

  /* Respond with 200 OK */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-10.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-10.1.1: terminate call\n");

  BYE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /* B transitions:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /* A: READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-10.1.1: PASSED\n");

  /* -------------------------------------------------------------------- */

  if (print_headings)
    printf("TEST NUA-10.2: Call with 100rel, 183 and 180\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, ringing_pracked);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state, nua_r_prack
     PROCEEDING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state, nua_r_prack
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 183);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_prack);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_prack);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags));

  /* Responded with 183 Session Progress */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(e->data->e_status, 183);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_answer_sent(e->data->e_tags));

  /* 183 is PRACKed */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_prack);
  /* Does not have effect on call state */

  /* Responded with 180 Ringing */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(e->data->e_status, 180);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  /* 180 is PRACKed */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_prack);
  /* Does not have effect on call state */

  /* Respond with 200 OK */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(e->data->e_status, 200);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-10.2: PASSED\n");

  if (print_headings)
    printf("TEST NUA-10.2.1: terminate call\n");

  BYE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /* B transitions:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /* A: READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-10.2.1: PASSED\n");

  /* -------------------------------------------------------------------- */

  if (print_headings)
    printf("TEST NUA-10.3: Call with 100rel and preconditions\n");

/* Test for precondition:

   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<-------183---------|
   |-------PRACK------->|
   |<-------200---------|
   |			|
   |-------UPDATE------>|
   |<-------200---------|
   |			|
   |<-------180---------|
   |-------PRACK------->|
   |<-------200---------|
   |			|
   |<------200 OK-------|
   |--------ACK-------->|
   |			|
   |<-------BYE---------|
   |-------200 OK-------|
   |			|

*/

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  nua_set_params(ctx->a.nua,
		 NUTAG_EARLY_MEDIA(1),
		 SIPTAG_SUPPORTED_STR("100rel, precondition"),
		 TAG_END());
  run_a_until(ctx, nua_r_set_params, until_final_response);

  nua_set_params(ctx->b.nua,
		 NUTAG_EARLY_MEDIA(0),
		 SIPTAG_SUPPORTED_STR("100rel, precondition"),
		 TAG_END());
  run_b_until(ctx, nua_r_set_params, until_final_response);

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 SIPTAG_SUPPORTED_STR("100rel"),
	 SIPTAG_REQUIRE_STR("precondition"),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, ringing_updated);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 183);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_prack);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(!is_answer_recv(e->data->e_tags));
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_update);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_prack);
  TEST(e->data->e_status, 200);
  /* Does not have effect on call state */

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */

  /* Responded with 183 Session Progress */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(e->data->e_status, 183);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_answer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_prack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(is_answer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_update);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(is_answer_sent(e->data->e_tags));

  /* Responded with 180 Ringing */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(e->data->e_status, 180);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  /* 180 PRACKed */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_prack);
  /* Does not have effect on call state */

  /* Responded with 200 OK */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(e->data->e_status, 200);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-10.3: PASSED\n");

  if (print_headings)
    printf("TEST NUA-10.3.1: terminate call\n");

  BYE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /* B transitions:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /* A: READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-10.3.1: PASSED\n");

  if (print_headings)
    printf("TEST NUA-10.4: Call with preconditions and non-100rel 180\n");

/* Test 100rel and preconditions with NUTAG_ONLY183_100REL(1):

   A			B
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<-------183---------|
   |-------PRACK------->|
   |<-------200---------|
   |			|
   |<-------180---------|
   |			|
   |<------200 OK-------|
   |--------ACK-------->|
   |			|
   |<-------BYE---------|
   |-------200 OK-------|
   |			|

*/

  a_call->sdp = "m=audio 5008 RTP/AVP 8";
  b_call->sdp = "m=audio 5010 RTP/AVP 0 8";

  nua_set_params(ctx->a.nua,
		 NUTAG_EARLY_MEDIA(1),
		 SIPTAG_SUPPORTED_STR("100rel, precondition"),
		 TAG_END());
  run_a_until(ctx, nua_r_set_params, until_final_response);

  nua_set_params(ctx->b.nua,
		 NUTAG_EARLY_MEDIA(1),
		 NUTAG_ONLY183_100REL(1),
		 SIPTAG_SUPPORTED_STR("100rel, precondition"),
		 TAG_END());
  run_b_until(ctx, nua_r_set_params, until_final_response);

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  INVITE(a, a_call, a_call->nh,
	 TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	 SOATAG_USER_SDP_STR(a_call->sdp),
	 SIPTAG_SUPPORTED_STR("100rel"),
	 SIPTAG_REQUIRE_STR("precondition"),
	 TAG_END());

  run_ab_until(ctx, -1, until_ready, -1, accept_updated);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 183);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_prack);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!is_offer_sent(e->data->e_tags));

  /* Send UPDATE */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(!is_answer_recv(e->data->e_tags));
  TEST_1(is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_update);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding);
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST_1(!is_offer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 200);

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3b)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_invite);
  TEST(e->data->e_status, 100);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */

  /* Responded with 183 Session Progress */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_answer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_prack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(is_answer_sent(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_update);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(is_offer_recv(e->data->e_tags));
  TEST_1(is_answer_sent(e->data->e_tags));

  /* Responded with 180 Ringing */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  /* Responded with 200 OK */
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(!is_offer_answer_done(e->data->e_tags));

  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(!is_offer_answer_done(e->data->e_tags));
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-10.4: PASSED\n");

  if (print_headings)
    printf("TEST NUA-10.4.1: terminate call\n");

  BYE(b, b_call, b_call->nh, TAG_END());
  run_ab_until(ctx, -1, until_terminated, -1, until_terminated);

  /* B transitions:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b->events);

  /* A: READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_bye);
  TEST(e->data->e_status, 200);
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-10.4.1: PASSED\n");


  END();
}

/* ======================================================================== */
/* Test simple methods: OPTIONS, MESSAGE, PUBLISH */

int test_methods(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;
  sip_t const *sip;

/* Message test

   A			B
   |-------MESSAGE----->|
   |<-------200---------|
   |			|

*/
  if (print_headings)
    printf("TEST NUA-11.1: MESSAGE\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  MESSAGE(a, a_call, a_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	  SIPTAG_SUBJECT_STR("NUA-11.1"),
	  SIPTAG_CONTENT_TYPE_STR("text/plain"),
	  SIPTAG_PAYLOAD_STR("Hello hellO!\n"),
	  TAG_END());

  run_ab_until(ctx, -1, save_until_final_response, -1, save_until_received);

  /* Client events:
     nua_message(), nua_r_message
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_message);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  /*
   Server events:
   nua_i_message
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_message);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_subject && sip->sip_subject->g_string);
  TEST_S(sip->sip_subject->g_string, "NUA-11.1");
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-11.1: PASSED\n");


/* Message test

   A
   |-------MESSAGE--\
   |<---------------/
   |--------200-----\
   |<---------------/
   |

*/
  if (print_headings)
    printf("TEST NUA-11.1b: MESSAGE\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(a->to), TAG_END()));

  MESSAGE(a, a_call, a_call->nh,
	  /* We cannot reach us by using our contact! */
	  NUTAG_URL(!ctx->p && !ctx->proxy_tests ? a->contact->m_url : NULL),
	  SIPTAG_SUBJECT_STR("NUA-11.1b"),
	  SIPTAG_CONTENT_TYPE_STR("text/plain"),
	  SIPTAG_PAYLOAD_STR("Hello hellO!\n"),
	  TAG_END());

  run_a_until(ctx, -1, save_until_final_response);

  /* Events:
     nua_message(), nua_i_message, nua_r_message
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_message);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_subject && sip->sip_subject->g_string);
  TEST_S(sip->sip_subject->g_string, "NUA-11.1b");
  TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_message);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-11.1b: PASSED\n");


/* OPTIONS test

   A			B
   |-------OPTIONS----->|
   |<-------200---------|
   |			|

*/
  if (print_headings)
    printf("TEST NUA-11.2: OPTIONS\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  OPTIONS(a, a_call, a_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	  TAG_END());

  run_ab_until(ctx, -1, save_until_final_response, -1, save_until_received);

  /* Client events:
     nua_options(), nua_r_options
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_options);
  TEST(e->data->e_status, 200);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_allow);
  TEST_1(sip->sip_accept);
  TEST_1(sip->sip_supported);
  /* TEST_1(sip->sip_content_type); */
  /* TEST_1(sip->sip_payload); */
  TEST_1(!e->next);

  /*
   Server events:
   nua_i_options
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_options);
  TEST(e->data->e_status, 200);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-11.2: PASSED\n");

/* PUBLISH test

   A			B
   |-------PUBLISH----->|
   |<-------405---------| (not allowed by default)
   |			|
   |-------PUBLISH----->|
   |<-------500---------| (XXX - not implemented)

*/
  if (print_headings)
    printf("TEST NUA-11.3: PUBLISH\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  PUBLISH(a, a_call, a_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	  SIPTAG_EVENT_STR("presence"),
	  SIPTAG_CONTENT_TYPE_STR("text/urllist"),
	  SIPTAG_PAYLOAD_STR("sip:example.com\n"),
	  TAG_END());

  run_ab_until(ctx, -1, save_until_final_response, -1, NULL);

  /* Client events:
     nua_publish(), nua_r_publish
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_publish);
  TEST(e->data->e_status, 405);
  TEST_1(!e->next);

  /*
   Server events:
   nua_i_publish
  */
  /* TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_publish);
     TEST(e->data->e_status, 405); */
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;

  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  nua_set_params(b->nua, NUTAG_ALLOW("PUBLISH"), TAG_END());

  run_b_until(ctx, nua_r_set_params, until_final_response);

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  PUBLISH(a, a_call, a_call->nh,
	  TAG_IF(!ctx->proxy_tests, NUTAG_URL(b->contact->m_url)),
	  SIPTAG_EVENT_STR("presence"),
	  SIPTAG_CONTENT_TYPE_STR("text/urllist"),
	  SIPTAG_PAYLOAD_STR("sip:example.com\n"),
	  TAG_END());

  run_ab_until(ctx, -1, save_until_final_response, -1, save_until_received);

  /* Client events:
     nua_publish(), nua_r_publish
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_publish);
  TEST(e->data->e_status, 501);	/* Not implemented */
  TEST_1(!e->next);

  /*
   Server events:
   nua_i_publish
  */
  TEST_1(e = b->events->head); TEST_E(e->data->e_event, nua_i_publish);
  TEST(e->data->e_status, 501);
  TEST_1(!e->next);

  free_events_in_list(ctx, a->events);
  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-11.3: PASSED\n");

  END();
}

/* ======================================================================== */
/* Test events methods: SUBSCRIBE/NOTIFY */

#include <sofia-sip/nea.h>

/**Terminate until received notify.
 * Save events (except nua_i_active or terminated).
 */
int save_until_notified(CONDITION_PARAMS)
{
  save_event_in_list(ctx, event, ep, call);
  return event == nua_i_notify;
}

int save_until_notified_and_responded(CONDITION_PARAMS)
{
  save_event_in_list(ctx, event, ep, call);
  if (event == nua_i_notify) ep->flags.b.bit0 = 1;
  if (event == nua_r_subscribe || event == nua_r_unsubscribe) {
    if (status >= 300)
      return 1;
    else if (status >= 200)
      ep->flags.b.bit1 = 1;
  }

  return ep->flags.b.bit0 && ep->flags.b.bit1;
}


int save_until_subscription(CONDITION_PARAMS)
{
  save_event_in_list(ctx, event, ep, call);
  return event == nua_i_subscription;
}


int test_events(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct call *a_call = a->call, *b_call = b->call;
  struct event *e;
  sip_t const *sip;
  tagi_t const *n_tags, *r_tags;
  url_t b_url[1];
  nea_sub_t *sub = NULL;

  char const open[] =
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<presence xmlns='urn:ietf:params:xml:ns:cpim-pidf' \n"
    "   entity='pres:bob@example.org'>\n"
    "  <tuple id='ksac9udshce'>\n"
    "    <status><basic>open</basic></status>\n"
    "    <contact priority='1.0'>sip:bob@example.org</contact>\n"
    "  </tuple>\n"
    "</presence>\n";

  char const closed[] =
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    "<presence xmlns='urn:ietf:params:xml:ns:cpim-pidf' \n"
    "   entity='pres:bob@example.org'>\n"
    "  <tuple id='ksac9udshce'>\n"
    "    <status><basic>closed</basic></status>\n"
    "  </tuple>\n"
    "</presence>\n";


/* SUBSCRIBE test

   A			B
   |------SUBSCRIBE---->|
   |<--------405--------|
   |			|

*/
  if (print_headings)
    printf("TEST NUA-12.1: SUBSCRIBE without notifier\n");

  TEST_1(a_call->nh = nua_handle(a->nua, a_call, SIPTAG_TO(b->to), TAG_END()));

  SUBSCRIBE(a, a_call, a_call->nh, NUTAG_URL(b->contact->m_url),
	    SIPTAG_EVENT_STR("presence"),
	    TAG_END());

  run_ab_until(ctx, -1, save_until_final_response,
	       -1, NULL /* XXX save_until_received */);

  /* Client events:
     nua_subscribe(), nua_r_subscribe
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_r_subscribe);
  TEST(e->data->e_status, 489);
  TEST_1(!e->next);

#if 0				/* XXX */
  /*
   Server events:
   nua_i_subscribe
  */
  TEST_1(e = b->events->head);
  TEST_E(e->data->e_event, nua_i_subscribe);
  TEST(e->data->e_status, 405);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event);
  TEST_S(sip->sip_event->o_type, "presence");
  TEST_1(!e->next);
#endif

  free_events_in_list(ctx, a->events);
  free_events_in_list(ctx, b->events);
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  if (print_headings)
    printf("TEST NUA-12.1: PASSED\n");

  /* ---------------------------------------------------------------------- */

/* SUBSCRIBE test using notifier and establishing subscription

   A			B
   |                    |
   |------SUBSCRIBE---->|
   |<--------202--------|
   |<------NOTIFY-------|
   |-------200 OK------>|
   |                    |
*/

  if (print_headings)
    printf("TEST NUA-12.2: using notifier and establishing subscription\n");

  TEST_1(b_call->nh = nua_handle(b->nua, b_call, TAG_END()));

  *b_url = *b->contact->m_url;

  NOTIFIER(b, b_call, b_call->nh,
	   NUTAG_URL(b_url),
	   SIPTAG_EVENT_STR("presence"),
	   SIPTAG_CONTENT_TYPE_STR("application/pidf+xml"),
	   SIPTAG_PAYLOAD_STR(closed),
	   NEATAG_THROTTLE(1),
	   TAG_END());
  run_b_until(ctx, nua_r_notifier, until_final_response);

  SUBSCRIBE(a, a_call, a_call->nh, NUTAG_URL(b->contact->m_url),
	    SIPTAG_EVENT_STR("presence"),
	    SIPTAG_ACCEPT_STR("application/xpidf, application/pidf+xml"),
	    TAG_END());

  run_ab_until(ctx, -1, save_until_notified_and_responded,
	       -1, NULL /* XXX save_until_received */);

  /* Client events:
     nua_subscribe(), nua_i_notify/nua_r_subscribe
  */
  TEST_1(e = a->events->head);
  if (e->data->e_event == nua_i_notify) {
    TEST_E(e->data->e_event, nua_i_notify);
    TEST_1(sip = sip_object(e->data->e_msg));
    n_tags = e->data->e_tags;
    TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_subscribe);
    r_tags = e->data->e_tags;
    TEST_1(tl_find(r_tags, nutag_substate));
    TEST(tl_find(r_tags, nutag_substate)->t_value, nua_substate_active);
  }
  else {
    TEST_E(e->data->e_event, nua_r_subscribe);
    TEST(e->data->e_status, 202);
    r_tags = e->data->e_tags;
    TEST_1(tl_find(r_tags, nutag_substate));
    TEST(tl_find(r_tags, nutag_substate)->t_value, nua_substate_embryonic);
    TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_notify);
    TEST_1(sip = sip_object(e->data->e_msg));
    n_tags = e->data->e_tags;
  }
  TEST_1(sip->sip_event); TEST_S(sip->sip_event->o_type, "presence");
  TEST_1(sip->sip_content_type);
  TEST_S(sip->sip_content_type->c_type, "application/pidf+xml");
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "active");
  TEST_1(sip->sip_subscription_state->ss_expires);
  TEST_1(tl_find(n_tags, nutag_substate));
  TEST(tl_find(n_tags, nutag_substate)->t_value, nua_substate_active);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-12.2: PASSED\n");

  /* ---------------------------------------------------------------------- */

/* NOTIFY with updated content

   A			B
   |                    |
   |<------NOTIFY-------|
   |-------200 OK------>|
   |                    |
*/
  if (print_headings)
    printf("TEST NUA-12.3: update notifier\n");

  /* Update presence data */

  NOTIFIER(b, b_call, b_call->nh,
	   SIPTAG_EVENT_STR("presence"),
	   SIPTAG_CONTENT_TYPE_STR("application/pidf+xml"),
	   SIPTAG_PAYLOAD_STR(open),
	   TAG_END());

  run_ab_until(ctx, -1, save_until_notified,
	       -1, NULL /* XXX save_until_received */);

  /* subscriber events:
     nua_i_notify
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_notify);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event); TEST_S(sip->sip_event->o_type, "presence");
  TEST_1(sip->sip_content_type);
  TEST_S(sip->sip_content_type->c_type, "application/pidf+xml");
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "active");
  TEST_1(sip->sip_subscription_state->ss_expires);
  n_tags = e->data->e_tags;
  TEST_1(tl_find(n_tags, nutag_substate));
  TEST(tl_find(n_tags, nutag_substate)->t_value,
       nua_substate_active);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-12.3: PASSED\n");

  /* ---------------------------------------------------------------------- */

/* un-SUBSCRIBE

   A			B
   |                    |
   |------SUBSCRIBE---->|
   |<--------202--------|
   |<------NOTIFY-------|
   |-------200 OK------>|
   |                    |
*/
  if (print_headings)
    printf("TEST NUA-12.5: un-SUBSCRIBE\n");

  UNSUBSCRIBE(a, a_call, a_call->nh, TAG_END());

  run_ab_until(ctx, -1, save_until_notified_and_responded,
	       -1, NULL /* XXX save_until_received */);

  /* Client events:
     nua_unsubscribe(), nua_i_notify/nua_r_unsubscribe
  */
  TEST_1(e = a->events->head);
  if (e->data->e_event == nua_i_notify) {
    TEST_E(e->data->e_event, nua_i_notify);
    TEST_1(sip = sip_object(e->data->e_msg));
    n_tags = e->data->e_tags;
    TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_unsubscribe);
    TEST_1(tl_find(e->data->e_tags, nutag_substate));
    TEST(tl_find(e->data->e_tags, nutag_substate)->t_value,
	 nua_substate_terminated);
  }
  else {
    TEST_E(e->data->e_event, nua_r_unsubscribe);
    TEST(e->data->e_status, 202);
    TEST_1(tl_find(e->data->e_tags, nutag_substate));
    TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_notify);
    TEST_1(sip = sip_object(e->data->e_msg));
    n_tags = e->data->e_tags;
  }
  TEST_1(sip->sip_event);
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "terminated");
  TEST_1(!sip->sip_subscription_state->ss_expires);
  TEST_1(tl_find(n_tags, nutag_substate));
  TEST(tl_find(n_tags, nutag_substate)->t_value, nua_substate_terminated);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-12.5: PASSED\n");

  /* ---------------------------------------------------------------------- */
/* 2nd SUBSCRIBE with event id

   A			B
   |                    |
   |------SUBSCRIBE---->|
   |<--------202--------|
   |<------NOTIFY-------|
   |-------200 OK------>|
   |                    |
*/
  /* XXX - we should do this before unsubscribing first one */
  if (print_headings)
    printf("TEST NUA-12.4: establishing 2nd subscription\n");

   NOTIFIER(b, b_call, b_call->nh,
	    SIPTAG_EVENT_STR("presence"),
	    SIPTAG_CONTENT_TYPE_STR("application/xpidf+xml"),
	    SIPTAG_PAYLOAD_STR(open),
	    NEATAG_THROTTLE(1),
	    NUTAG_SUBSTATE(nua_substate_pending),
	    TAG_END());
  run_b_until(ctx, nua_r_notifier, until_final_response);

  NOTIFIER(b, b_call, b_call->nh,
	   SIPTAG_EVENT_STR("presence"),
	   SIPTAG_CONTENT_TYPE_STR("application/xpidf+xml"),
	   SIPTAG_PAYLOAD_STR(closed),
	   NEATAG_THROTTLE(1),
	   NEATAG_FAKE(1),
	   NUTAG_SUBSTATE(nua_substate_pending),
	   TAG_END());
  run_b_until(ctx, nua_r_notifier, until_final_response);

  SUBSCRIBE(a, a_call, a_call->nh, NUTAG_URL(b->contact->m_url),
	    SIPTAG_EVENT_STR("presence;id=1"),
	    SIPTAG_ACCEPT_STR("application/xpidf+xml"),
	    TAG_END());

  run_ab_until(ctx, -1, save_until_notified_and_responded,
	       -1, save_until_subscription);

  /* Client events:
     nua_subscribe(), nua_i_notify/nua_r_subscribe
  */
  TEST_1(e = a->events->head);
  if (e->data->e_event == nua_i_notify) {
    TEST_E(e->data->e_event, nua_i_notify);
    TEST_1(sip = sip_object(e->data->e_msg));
    n_tags = e->data->e_tags;
    TEST_1(e = e->next); TEST_E(e->data->e_event, nua_r_subscribe);
    TEST_1(tl_find(e->data->e_tags, nutag_substate));
    TEST(tl_find(e->data->e_tags, nutag_substate)->t_value,
	 nua_substate_pending);
  }
  else {
    TEST_E(e->data->e_event, nua_r_subscribe);
    TEST(e->data->e_status, 202);
    TEST_1(tl_find(e->data->e_tags, nutag_substate));
    TEST(tl_find(e->data->e_tags, nutag_substate)->t_value,
	 nua_substate_embryonic);
    TEST_1(e = e->next); TEST_E(e->data->e_event, nua_i_notify);
    TEST_1(sip = sip_object(e->data->e_msg));
    n_tags = e->data->e_tags;
  }
  TEST_1(sip->sip_event); TEST_S(sip->sip_event->o_type, "presence");
  TEST_S(sip->sip_event->o_id, "1");
  TEST_1(sip->sip_content_type);
  TEST_S(sip->sip_content_type->c_type, "application/xpidf+xml");
  TEST_1(sip->sip_payload && sip->sip_payload->pl_data);
  /* Check that we really got "fake" content */
  TEST_1(memmem(sip->sip_payload->pl_data, sip->sip_payload->pl_len,
		"<basic>closed</basic>", strlen("<basic>closed</basic>")));
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "pending");
  TEST_1(sip->sip_subscription_state->ss_expires);
  TEST_1(tl_find(n_tags, nutag_substate));
  TEST(tl_find(n_tags, nutag_substate)->t_value,
       nua_substate_pending);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server events:
   nua_i_subscription
  */
  TEST_1(e = b->events->head);
  TEST_E(e->data->e_event, nua_i_subscription);
  TEST(tl_gets(e->data->e_tags, NEATAG_SUB_REF(sub), TAG_END()), 1);
  TEST_1(sub);
  TEST_1(!e->next);

  free_events_in_list(ctx, b->events);

  /* Authorize user A */
  AUTHORIZE(b, b_call, b_call->nh,
	    NUTAG_SUBSTATE(nua_substate_active),
	    NEATAG_SUB(sub),
	    NEATAG_FAKE(0),
	    TAG_END());

  run_ab_until(ctx, -1, save_until_notified,
	       -1, save_until_final_response);

  /* subscriber events:
     nua_i_notify with NUTAG_SUBSTATE(nua_substate_active)
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_notify);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event); TEST_S(sip->sip_event->o_type, "presence");
  TEST_1(sip->sip_content_type);
  TEST_S(sip->sip_content_type->c_type, "application/xpidf+xml");
  TEST_1(sip->sip_payload && sip->sip_payload->pl_data);
  /* Check that we really got real content */
  TEST_1(memmem(sip->sip_payload->pl_data, sip->sip_payload->pl_len,
		"<basic>open</basic>", strlen("<basic>open</basic>")));
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "active");
  TEST_1(sip->sip_subscription_state->ss_expires);
  n_tags = e->data->e_tags;
  TEST_1(tl_find(n_tags, nutag_substate));
  TEST(tl_find(n_tags, nutag_substate)->t_value, nua_substate_active);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  /*
   Server events:
   nua_r_authorize
  */
  TEST_1(e = b->events->head);
  TEST_E(e->data->e_event, nua_r_authorize);
  TEST_1(!e->next);

  free_events_in_list(ctx, b->events);

  if (print_headings)
    printf("TEST NUA-12.4: PASSED\n");

  /* ---------------------------------------------------------------------- */

/* NOTIFY terminating subscription

   A			B
   |                    |
   |<------NOTIFY-------|
   |-------200 OK------>|
   |                    |
*/

  if (print_headings)
    printf("TEST NUA-12.6: terminate notifier\n");

  TERMINATE(b, b_call, b_call->nh, TAG_END());

  run_ab_until(ctx, -1, save_until_notified, -1, until_final_response);

  /* Client events:
     nua_i_notify
  */
  TEST_1(e = a->events->head); TEST_E(e->data->e_event, nua_i_notify);
  TEST_1(sip = sip_object(e->data->e_msg));
  TEST_1(sip->sip_event); TEST_S(sip->sip_event->o_type, "presence");
  TEST_S(sip->sip_event->o_id, "1");
  TEST_1(sip->sip_subscription_state);
  TEST_S(sip->sip_subscription_state->ss_substate, "terminated");
  TEST_1(!sip->sip_subscription_state->ss_expires);
  n_tags = e->data->e_tags;
  TEST_1(tl_find(n_tags, nutag_substate));
  TEST(tl_find(n_tags, nutag_substate)->t_value, nua_substate_terminated);
  TEST_1(!e->next);
  free_events_in_list(ctx, a->events);

  if (print_headings)
    printf("TEST NUA-12.6: PASSED\n");

  /* ---------------------------------------------------------------------- */


  nua_handle_destroy(a_call->nh), a_call->nh = NULL;
  nua_handle_destroy(b_call->nh), b_call->nh = NULL;

  END();			/* test_events */
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
  int retval = 0, quit_on_single_failure = 1;
  int i, o_quiet = 0, o_attach = 0, o_alarm = 1;
  int o_events_a = 0, o_events_b = 0, o_events_c = 0, o_iproxy = 1, o_inat = 1;
  int o_inat_symmetric = 0, o_inat_logging = 0, o_expensive = 0;
  url_t const *o_proxy = NULL;
  int level = 0;

  struct context ctx[1] = {{{ SU_HOME_INIT(ctx) }}};

  if (getenv("EXPENSIVE_CHECKS"))
    o_expensive = 1;

  ctx->threading = 1;

  endpoint_init(ctx, &ctx->a, 'a');
  endpoint_init(ctx, &ctx->b, 'b');
  endpoint_init(ctx, &ctx->c, 'c');

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
      tstflags &= ~tst_verbatim, o_quiet = 1;
    else if (strcmp(argv[i], "-k") == 0)
      quit_on_single_failure = 0;
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
      o_events_a = o_events_b = o_events_c = 1;
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
    if (retval && quit_on_single_failure) { su_deinit(); return retval; } \
  } while(0)

  retval |= test_nua_api_errors(ctx); SINGLE_FAILURE_CHECK();
  retval |= test_tag_filter(); SINGLE_FAILURE_CHECK();
  retval |= test_nua_params(ctx); SINGLE_FAILURE_CHECK();

  retval |= test_nua_init(ctx, o_iproxy, o_proxy, o_inat,
			  TESTNATTAG_SYMMETRIC(o_inat_symmetric),
			  TESTNATTAG_LOGGING(o_inat_logging),
			  TAG_END());

  ctx->expensive = o_expensive;

  if (retval == 0) {
    if (o_events_a)
      ctx->a.printer = print_event;
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
      retval |= test_early_bye(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_call_hold(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_session_timer(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_refer(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_100rel(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_methods(ctx); SINGLE_FAILURE_CHECK();
      retval |= test_events(ctx); SINGLE_FAILURE_CHECK();
    }

    if (ctx->proxy_tests)
      retval |= test_unregister(ctx); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ctx);

  su_home_deinit(ctx->home);

  su_deinit();

  return retval;
}
