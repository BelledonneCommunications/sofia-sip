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
 *
 * @date Created: Wed Aug 17 12:12:12 EEST 2005 ppessi
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#if HAVE_ALARM
#include <unistd.h>
#include <signal.h>
#endif

struct context;
#define NUA_MAGIC_T struct context
#define NUA_HMAGIC_T void

#include "nua.h"
#include "nua_tag.h"
#include "sip_status.h"

#include <sdp.h>
#include <sip_header.h>

#include <su_log.h>
#include <su_tagarg.h>
#include <su_tag_io.h>

extern su_log_t nua_log[];
extern su_log_t su_log_default[];

char const name[] = "test_nua";
int tstflags = 0;
#define TSTFLAGS tstflags

#include <tstdef.h>

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
#define __func__ name
#endif

#define NONE ((void*)-1)

struct endpoint;

typedef
int condition_function(nua_event_t event,
		       int status, char const *phrase,
		       nua_t *nua, struct context *ctx,
		       struct endpoint *ep,
		       nua_handle_t *nh, void *call,
		       sip_t const *sip,
		       tagi_t tags[]);

struct context
{
  su_home_t home[1];
  su_root_t *root;

  int running;

  struct endpoint {
    char name[4];
    struct context *ctx;	/* Backpointer */
    condition_function *next_condition;
    nua_event_t next_event, last_event;
    nua_t *nua;
    sip_contact_t *contact;
    sip_from_t *address;

    condition_function *printer;

    /* Per-call stuff */
    nua_handle_t *nh;
    char const *subject;
    nua_saved_event_t saved_event[1];

    struct {
      struct event *head, **tail;
    } events;
  } a, b;
};

struct event
{
  struct event *next, **prev;
  nua_saved_event_t saved_event[1];
  nua_event_data_t const *data;
};

#define CONDITION_FUNCTION(name)		\
  int name(nua_event_t event,			\
	   int status, char const *phrase,	\
	   nua_t *nua, struct context *ctx,	\
	   struct endpoint *ep,			\
	   nua_handle_t *nh, void *call, \
	   sip_t const *sip,			\
	   tagi_t tags[])

CONDITION_FUNCTION(condition_final_response){ return status >= 200; }
CONDITION_FUNCTION(never){ return 0; }
CONDITION_FUNCTION(save_final_response)
{
  if (status < 200)
    return 0;
  nua_save_event(ep->nua, ep->saved_event);
  return 1;
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


CONDITION_FUNCTION(print_event)
{
  if (event == nua_i_state) {
    fprintf(stderr, "%s.nua(%p): event %s %s\n",
	    ep->name, nh, nua_event_name(event), 
	    nua_callstate_name(callstate(tags)));
  }
  else if ((int)event >= 0) {
    fprintf(stderr, "%s.nua(%p): event %s status %u %s\n",
	    ep->name, nh, nua_event_name(event), status, phrase);
  }
  else if (status > 0) {
    fprintf(stderr, "%s.nua(%p): call %s() with status %u %s\n",
	    ep->name, nh, (char const *)call, status, phrase);
  }
  else {
    tagi_t const *t;
    t = tl_find(tags, siptag_subject_str);
    if (t && t->t_value) {
      char const *subject = (char const *)t->t_value;
      fprintf(stderr, "%s.nua(%p): call %s() \"%s\"\n",
	      ep->name, nh, (char const *)call, subject);
    }
    else
      fprintf(stderr, "%s.nua(%p): call %s()\n",
	      ep->name, nh, (char const *)call);
  }

  if ((tstflags & tst_verbatim) && tags)
    tl_print(stderr, "", tags);

  return 0;
}
	       

void a_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, void *call,
		sip_t const *sip,
		tagi_t tags[])
{
  struct endpoint *ep = &ctx->a;

  if (ep->printer)
    ep->printer(event, status, phrase, nua, ctx, ep, nh, call, sip, tags);

  if ((ep->next_event == -1 || ep->next_event == event) &&
      (ep->next_condition == NULL ||
       ep->next_condition(event, status, phrase,
			  nua, ctx, ep, nh, call, sip, tags)))
    ctx->running = 0;

  ep->last_event = event;
  ctx->b.last_event = -1;
}

void b_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, void *call,
		sip_t const *sip,
		tagi_t tags[])
{
  struct endpoint *ep = &ctx->b;

  if (ep->printer)
    ep->printer(event, status, phrase, nua, ctx, ep, nh, call, sip, tags);

  if ((ep->next_event == -1 || ep->next_event == event) &&
      (ep->next_condition == NULL ||
       ep->next_condition(event, status, phrase,
			  nua, ctx, ep, nh, call, sip, tags)))
    ctx->running = 0;

  ep->last_event = -1;
  ep->last_event = event;
}

void run_until(struct context *ctx,
	       nua_event_t a_event, condition_function *a_condition,
	       nua_event_t b_event, condition_function *b_condition)
{
  ctx->a.next_event = a_event;
  ctx->a.next_condition = a_condition;
  ctx->a.last_event = -1;
  ctx->b.next_event = b_event;
  ctx->b.next_condition = b_condition;
  ctx->b.last_event = -1;

  for (ctx->running = 1; ctx->running;) {
    su_root_step(ctx->root, 1000);
  }
}

int run_a_until(struct context *ctx,
		nua_event_t a_event,
		condition_function *a_condition)
{
  run_until(ctx, a_event, a_condition, -1, never);
  return ctx->a.last_event;
}

int run_b_until(struct context *ctx,
		nua_event_t b_event,
		condition_function *b_condition)
{
  run_until(ctx, -1, never, b_event, b_condition);
  return ctx->b.last_event;
}

/* Invite via endpoint and handle */
int invite(struct endpoint *ep, nua_handle_t *nh,
	   tag_type_t tag, tag_value_t value,
	   ...)
{
  ta_list ta;
  ta_start(ta, tag, value);

  if (ep->printer)
    ep->printer(-1, 0, "", ep->nua, ep->ctx, ep, 
		nh, "nua_invite", NULL, ta_args(ta));

  nua_invite(nh, ta_tags(ta));

  ta_end(ta);
  return 0;
}

/* bye via endpoint and handle */
int bye(struct endpoint *ep, nua_handle_t *nh,
	tag_type_t tag, tag_value_t value,
	...)
{
  ta_list ta;

  ta_start(ta, tag, value);
  if (ep->printer)
    ep->printer(-1, 0, "", ep->nua, ep->ctx, ep, 
		nh, "nua_bye", NULL, ta_args(ta));
  nua_bye(nh, ta_tags(ta));
  ta_end(ta);

  return 0;
}

/* Respond via endpoint and handle */
int respond(struct endpoint *ep, nua_handle_t *nh,
	    int status, char const *phrase,
	    tag_type_t tag, tag_value_t value,
	    ...)
{
  ta_list ta;

  ta_start(ta, tag, value);

  if (ep->printer)
    ep->printer(-1, status, phrase, ep->nua, ep->ctx, ep, 
		nh, "nua_respond", NULL, ta_args(ta));

  nua_respond(nh, status, phrase, ta_tags(ta));
  ta_end(ta);

  return 0;
}



/* Reject all but currently used handle */
int check_handle(struct endpoint *ep, nua_handle_t *nh, 
		 int status, char const *phrase)
{
  if (ep->nh && ep->nh != nh) {
    if (status) {
      respond(ep, nh, status, phrase, TAG_END());
    }
    nua_handle_destroy(nh);
    return 0;
  }
  ep->nh = nh;
  return 1;
}

/* Save nua event in endpoint list */
int save_event_in_list(struct context *ctx,
		       struct endpoint *ep)
{
  struct event *e = su_zalloc(ctx->home, sizeof *e);

  if (!e) { perror("su_zalloc"), abort(); }

  *(e->prev = ep->events.tail) = e;
  ep->events.tail = &e->next;

  if (!nua_save_event(ep->nua, e->saved_event))
    return -1;

  e->data = nua_event_data(e->saved_event);

  return 0;
}

/* Save nua event in endpoint list */
void free_events_in_list(struct context *ctx, struct endpoint *ep)
{
  struct event *e;

  while ((e = ep->events.head)) {
    if ((*e->prev = e->next))
      e->next->prev = e->prev;
    nua_destroy_event(e->saved_event);
    su_free(ctx->home, e);
  }
  ep->events.tail = &ep->events.head;
}

void nolog(void *stream, char const *fmt, va_list ap) {}

int test_api_errors(struct context *ctx)
{
  BEGIN();

  /* Invoke every API function with invalid arguments */

  int level;

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

  END();
}

int test_params(struct context *ctx)
{
  BEGIN();

  char const Alice[] = "Alice <sip:a@wonderland.org>";
  sip_from_t const *from;
  su_home_t tmphome[SU_HOME_AUTO_SIZE(16384)];
  nua_handle_t *nh;

  su_home_auto(tmphome, sizeof(tmphome));

  ctx->root = su_root_create(ctx); TEST_1(ctx->root);

  /* Disable threading by command line switch? */
  su_root_threading(ctx->root, 1);

  ctx->a.nua = nua_create(ctx->root, a_callback, ctx,
			  SIPTAG_FROM_STR("sip:alice@example.com"),
			  NUTAG_URL("sip:*:*;transport=udp"),
			  TAG_END());

  TEST_1(ctx->a.nua);

  from = sip_from_make(tmphome, Alice);

  nh = nua_handle(ctx->a.nua, NULL, TAG_END());

  nua_set_hparams(nh, NUTAG_INVITE_TIMER(90), TAG_END());
  run_a_until(ctx, nua_r_set_params, condition_final_response);

  /* Modify all pointer values */
  nua_set_params(ctx->a.nua,
		 SIPTAG_FROM_STR(Alice),

		 SIPTAG_SUPPORTED_STR("test"),
		 SIPTAG_ALLOW_STR("DWIM, OPTIONS, INFO"),
		 SIPTAG_USER_AGENT_STR("test_nua/1.0"),

		 SIPTAG_ORGANIZATION_STR("Te-Ras y.r."),

		 NUTAG_REGISTRAR("sip:openlaboratory.net"),

		 TAG_END());

  run_a_until(ctx, nua_r_set_params, condition_final_response);

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

		 SIPTAG_SUPPORTED(sip_supported_make(tmphome, "humppaa,kuole")),
		 SIPTAG_ALLOW(sip_allow_make(tmphome, "OPTIONS, INFO")),
		 SIPTAG_USER_AGENT(sip_user_agent_make(tmphome, "test_nua")),

		 SIPTAG_ORGANIZATION(sip_organization_make(tmphome, "Pussy Galore's Flying Circus")),

		 NUTAG_MEDIA_ENABLE(0),
		 NUTAG_REGISTRAR(url_hdup(tmphome, (url_t *)"sip:sip.wonderland.org")),

		 TAG_END());

  run_a_until(ctx, nua_r_set_params, condition_final_response);

  /* Modify something... */
  nua_set_params(ctx->a.nua,
		 NUTAG_RETRY_COUNT(5),
		 TAG_END());
  run_a_until(ctx, nua_r_set_params, condition_final_response);

  {
    sip_from_t const *from = NONE;
    char const *from_str = "NONE";

    int retry_count = -1;
    int max_subscriptions = -1;

    int invite_enable = -1;
    int auto_alert = -1;
    int early_media = -1;
    int auto_answer = -1;
    int auto_ack = -1;
    int invite_timeout = -1;

    int session_timer = -1;
    int min_se = -1;
    int refresher = -1;
    int update_refresh = -1;

    int message_enable = -1;
    int win_messenger_enable = -1;
    int message_auto_respond = -1;

    int callee_caps = -1;
    int media_features = -1;
    int service_route_enable = -1;
    int path_enable = -1;

    sip_allow_t const *allow = NONE;
    char const *allow_str = "NONE";
    sip_supported_t const *supported = NONE;
    char const *supported_str = "NONE";
    sip_user_agent_t const *user_agent = NONE;
    char const *user_agent_str = "NONE";
    sip_organization_t const *organization = NONE;
    char const *organization_str = "NONE";

    url_string_t const *registrar = NONE;

    int n;
    nua_event_data_t const *e;

    nua_get_params(ctx->a.nua, TAG_ANY(), TAG_END());
    run_a_until(ctx, nua_r_get_params, save_final_response);
    TEST_1(e = nua_event_data(ctx->a.saved_event));

    TEST(e->e_event, nua_r_get_params);

    n = tl_gets(e->e_tags,
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
    TEST(n, 29);

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

    TEST_S(sip_header_as_string(tmphome, (void *)allow), "OPTIONS, INFO");
    TEST_S(allow_str, "OPTIONS, INFO");
    TEST_S(sip_header_as_string(tmphome, (void *)supported), "humppaa, kuole");
    TEST_S(supported_str, "humppaa, kuole");
    TEST_S(sip_header_as_string(tmphome, (void *)user_agent), "test_nua");
    TEST_S(user_agent_str, "test_nua");
    TEST_S(sip_header_as_string(tmphome, (void *)organization),
	   "Pussy Galore's Flying Circus");
    TEST_S(organization_str, "Pussy Galore's Flying Circus");

    TEST_S(url_as_string(tmphome, registrar->us_url),
	   "sip:sip.wonderland.org");

    nua_destroy_event(ctx->a.saved_event);
  }

  {
    sip_from_t const *from = NONE;
    char const *from_str = "NONE";

    int retry_count = -1;
    int max_subscriptions = -1;

    int invite_enable = -1;
    int auto_alert = -1;
    int early_media = -1;
    int auto_answer = -1;
    int auto_ack = -1;
    int invite_timeout = -1;

    int session_timer = -1;
    int min_se = -1;
    int refresher = -1;
    int update_refresh = -1;

    int message_enable = -1;
    int win_messenger_enable = -1;
    int message_auto_respond = -1;

    int callee_caps = -1;
    int media_features = -1;
    int service_route_enable = -1;
    int path_enable = -1;

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
    nua_event_data_t const *e;

    nua_get_hparams(nh, TAG_ANY(), TAG_END());
    run_a_until(ctx, nua_r_get_params, save_final_response);

    TEST_1(e = nua_event_data(ctx->a.saved_event));

    TEST(e->e_event, nua_r_get_params);

    n = tl_gets(e->e_tags,
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
    TEST(retry_count, -1);
    TEST(max_subscriptions, -1);

    TEST(invite_enable, -1);
    TEST(auto_alert, -1);
    TEST(early_media, -1);
    TEST(auto_answer, -1);
    TEST(auto_ack, -1);

    TEST(session_timer, -1);
    TEST(min_se, -1);
    TEST(refresher, -1);
    TEST(update_refresh, -1);

    TEST(message_enable, -1);
    TEST(win_messenger_enable, -1);
    TEST(message_auto_respond, -1); /* XXX */

    TEST(callee_caps, -1);
    TEST(media_features, -1);
    TEST(service_route_enable, -1);
    TEST(path_enable, -1);

    TEST(allow, NONE);
    TEST_S(allow_str, "NONE");
    TEST(supported, NONE);
    TEST_S(supported_str, "NONE");
    TEST(user_agent, NONE);
    TEST_S(user_agent_str, "NONE");
    TEST(organization, NONE);
    TEST_S(organization_str, "NONE");

    TEST(registrar->us_url, NONE);

    nua_destroy_event(ctx->a.saved_event);
  }

  nua_handle_destroy(nh);

  nua_shutdown(ctx->a.nua);
  run_a_until(ctx, nua_r_shutdown, condition_final_response);
  nua_destroy(ctx->a.nua), ctx->a.nua = NULL;

  su_root_destroy(ctx->root), ctx->root = NULL;

  su_home_deinit(tmphome);

  END();
}

int test_init(struct context *ctx, char *argv[])
{
  BEGIN();
  nua_event_data_t const *e;
  sip_contact_t const *m = NULL;
  sip_from_t const *a = NULL;

  ctx->root = su_root_create(ctx); TEST_1(ctx->root);

  /* Disable threading by command line switch? */
  su_root_threading(ctx->root, 1);

  ctx->a.nua = nua_create(ctx->root, a_callback, ctx,
			  SIPTAG_FROM_STR("sip:alice@example.com"),
			  NUTAG_URL("sip:*:*"),
			  SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
			  TAG_END());
  TEST_1(ctx->a.nua);

  nua_get_params(ctx->a.nua, TAG_ANY(), TAG_END());
  run_a_until(ctx, nua_r_get_params, save_final_response);
  TEST_1(e = nua_event_data(ctx->a.saved_event));
  TEST(tl_gets(e->e_tags,
	       NTATAG_CONTACT_REF(m),
	       SIPTAG_FROM_REF(a),
	       TAG_END()), 2); TEST_1(m);
  TEST_1(ctx->a.contact = sip_contact_dup(ctx->home, m));
  TEST_1(ctx->a.address = sip_to_dup(ctx->home, a));
  nua_destroy_event(ctx->a.saved_event);

  ctx->b.nua = nua_create(ctx->root, b_callback, ctx,
			  SIPTAG_FROM_STR("sip:bob@example.org"),
			  NUTAG_URL("sip:*:*"),
			  SOATAG_USER_SDP_STR("m=audio 5006 RTP/AVP 8 0"),
			  TAG_END());
  TEST_1(ctx->b.nua);

  nua_get_params(ctx->b.nua, TAG_ANY(), TAG_END());
  run_b_until(ctx, nua_r_get_params, save_final_response);
  TEST_1(e = nua_event_data(ctx->b.saved_event));
  TEST(tl_gets(e->e_tags,
	       NTATAG_CONTACT_REF(m),
	       SIPTAG_FROM_REF(a),
	       TAG_END()), 2); TEST_1(m);
  TEST_1(ctx->b.contact = sip_contact_dup(ctx->home, m));
  TEST_1(ctx->b.address = sip_to_dup(ctx->home, a));
  nua_destroy_event(ctx->b.saved_event);

  END();
}

CONDITION_FUNCTION(save_events)
{
  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);
  return 0;
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
   |-------200 OK-------|
   |			|

   Client transitions:
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(C3+C4)-> READY
   READY -(T1)-> TERMINATED

   Server transitions:
   INIT -(S1)-> RECEIVED -(S2a)-> EARLY -(S3a)-> COMPLETED -(S4)-> READY
   READY -(T2)-> TERMINATING -(T3)-> TERMINATED

   See @page nua_call_model in nua.docs for more information

*/

CONDITION_FUNCTION(receive_basic_call)
{
  int state = nua_callstate_init;

  if (!check_handle(ep, nh, SIP_486_BUSY_HERE))
    return 0;
  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);

  if (event != nua_i_state)
    return 0;

  tl_gets(tags, NUTAG_CALLSTATE_REF(state), TAG_END());

  switch (state) {
  case nua_callstate_init:
    return 0;
  case nua_callstate_calling:
    return 0;
  case nua_callstate_proceeding:
    return 0;
  case nua_callstate_received:
    respond(ep, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    respond(ep, nh, SIP_200_OK,
	    SOATAG_USER_SDP_STR("m=audio 5010 RTP/AVP 8\n"
				"a=rtcp:5011"),
	    TAG_END());
    return 0;
  case nua_callstate_completed:
    return 0;
  case nua_callstate_ready:
    bye(ep, nh, TAG_END());
    return 0;
  case nua_callstate_terminating:
    return 0;
  case nua_callstate_terminated:
    return 1;
  default:
    return 0;
  }
}

int test_basic_call(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a,  *b = &ctx->b;
  struct event *e;

  TEST_1(a->nh = nua_handle(a->nua, 0, SIPTAG_TO(b->address), TAG_END()));

  invite(a, a->nh, NUTAG_URL(b->contact->m_url),
	 SOATAG_USER_SDP_STR("m=audio 5008 RTP/AVP 8"),
	 TAG_END());

  run_until(ctx, -1, save_events, -1, receive_basic_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
     READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state
  */
  TEST_1(e = a->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_bye);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3a)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state

   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = b->events.head); TEST(e->data->e_event, nua_i_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a);
  nua_handle_destroy(a->nh), a->nh = NULL;

  free_events_in_list(ctx, b);
  nua_handle_destroy(b->nh), b->nh = NULL;

  END();
}

/* ======================================================================== */
/* Call rejections */

CONDITION_FUNCTION(until_terminated)
{
  if (!check_handle(ep, nh, 0, 0)) 
    return 0;

  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);

  return event == nua_i_state && callstate(tags) == nua_callstate_terminated;
}

char const *call_subject(sip_t const *sip)
{
  if (sip && sip->sip_subject && sip->sip_subject->g_string)
    return sip->sip_subject->g_string;
  else
    return "unknown";
}

/*
 A      reject-1      B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<--------486--------|
 |---------ACK------->|
*/
CONDITION_FUNCTION(reject_1)
{
  if (!check_handle(ep, nh, SIP_500_INTERNAL_SERVER_ERROR)) 
    return 0;

  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);
  
  switch (callstate(tags)) {
  case nua_callstate_received:
    respond(ep, nh, SIP_486_BUSY_HERE, TAG_END());
    return 0;

  case nua_callstate_terminated:
    nua_handle_destroy(ep->nh), ep->nh = NULL;
    return 0;

  default:
    return 0;
  }
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
CONDITION_FUNCTION(reject_2)
{
  if (!check_handle(ep, nh, SIP_500_INTERNAL_SERVER_ERROR)) 
    return 0;

  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);
  
  switch (callstate(tags)) {
  case nua_callstate_received:
    respond(ep, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    respond(ep, nh, 602, "Rejected 2", TAG_END());
    return 0;
  case nua_callstate_terminated:
    nua_handle_destroy(ep->nh), ep->nh = NULL;
    return 0;
  default:
    return 0;
  }
}


/*
 A      reject-3      B
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
CONDITION_FUNCTION(reject_4);
CONDITION_FUNCTION(reject_3)
{
  if (!check_handle(ep, nh, SIP_500_INTERNAL_SERVER_ERROR)) 
    return 0;

  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);

  switch (callstate(tags)) {
  case nua_callstate_received:
    {
      sip_contact_t m[1];
      *m = *ep->contact;
      m->m_url->url_user = "302";
      respond(ep, nh, SIP_302_MOVED_TEMPORARILY, 
	      SIPTAG_CONTACT(m), TAG_END());
      ep->next_condition = reject_4;
    }
    return 0;
  case nua_callstate_terminated:
    nua_handle_destroy(ep->nh), ep->nh = NULL;
    return 0;
  default:
    return 0;
  }
}

CONDITION_FUNCTION(reject_4)
{
  if (!check_handle(ep, nh, SIP_500_INTERNAL_SERVER_ERROR)) 
    return 0;

  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);
  
  switch (callstate(tags)) {
  case nua_callstate_received:
    respond(ep, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    respond(ep, nh, SIP_604_DOES_NOT_EXIST_ANYWHERE, TAG_END());
    return 0;
  case nua_callstate_terminated:
    nua_handle_destroy(ep->nh), ep->nh = NULL;
    return 0;

  default:
    return 0;
  }
}

int test_call_rejects(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct event *e;

  /*
   A      reject-1      B
   |			|
   |-------INVITE------>|
   |<----100 Trying-----|
   |			|
   |<--------486--------|
   |---------ACK------->|
  */

  TEST_1(a->nh = nua_handle(a->nua, 0, SIPTAG_TO(b->address), TAG_END()));
  invite(a, a->nh, NUTAG_URL(b->contact->m_url),
	 SIPTAG_SUBJECT_STR("reject-1"),
	 SOATAG_USER_SDP_STR("m=audio 5008 RTP/AVP 8"),
	 TAG_END());
  run_until(ctx, -1, until_terminated, -1, reject_1);

  /* 
   Client transitions in reject-1:
   INIT -(C1)-> CALLING -(C6a)-> TERMINATED
  */
  TEST_1(e = ctx->a.events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 486); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions in reject-1:
   INIT -(S1)-> RECEIVED -(S6a)-> TERMINATED
  */
  TEST_1(e = ctx->b.events.head); TEST(e->data->e_event, nua_i_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a);
  nua_handle_destroy(a->nh), a->nh = NULL;
  free_events_in_list(ctx, b);
  nua_handle_destroy(b->nh), b->nh = NULL;

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

  /* Make call reject-2 */
  TEST_1(a->nh = nua_handle(a->nua, 0, SIPTAG_TO(b->address), TAG_END()));
  invite(a, a->nh, NUTAG_URL(b->contact->m_url),
	 SIPTAG_SUBJECT_STR("reject-2"),
	 SOATAG_USER_SDP_STR("m=audio 5008 RTP/AVP 8"),
	 TAG_END());
  run_until(ctx, -1, until_terminated, -1, reject_2);

  /*
   Client transitions in reject-2:
   INIT -(C1)-> CALLING -(C2)-> PROCEEDING -(C6b)-> TERMINATED
  */
  TEST_1(e = a->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 602); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions in reject-2:
   INIT -(S1)-> RECEIVED -(S2)-> EARLY -(S6a)-> TERMINATED
  */    
  TEST_1(e = b->events.head); TEST(e->data->e_event, nua_i_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a);
  nua_handle_destroy(a->nh), a->nh = NULL;
  free_events_in_list(ctx, b);
  nua_handle_destroy(b->nh), b->nh = NULL;

  /* Make call reject-3 */
  TEST_1(a->nh = nua_handle(a->nua, 0, SIPTAG_TO(b->address), TAG_END()));
  invite(a, a->nh, NUTAG_URL(b->contact->m_url),
	 SIPTAG_SUBJECT_STR("reject-3"),
	 SOATAG_USER_SDP_STR("m=audio 5008 RTP/AVP 8"),
	 TAG_END());
  run_until(ctx, -1, until_terminated, -1, reject_3);

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

  TEST_1(e = ctx->a.events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 100); 
  TEST(sip_object(e->data->e_msg)->sip_status->st_status, 302); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 180); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST(e->data->e_status, 604); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED -(S2)-> TERMINATED/INIT
   INIT -(S1)-> RECEIVED -(S2)-> EARLY -(S6a)-> TERMINATED
  */
  TEST_1(e = ctx->b.events.head); TEST(e->data->e_event, nua_i_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);

  free_events_in_list(ctx, a);
  nua_handle_destroy(a->nh), a->nh = NULL;
  free_events_in_list(ctx, b);
  nua_handle_destroy(b->nh), b->nh = NULL;

  END();
}

/* ======================================================================== */
/* Call hold */

/*
 A     accept_call    B
 |                    |
 |-------INVITE------>|
 |<----100 Trying-----|
 |                    |
 |<----180 Ringing----|
 |                    |
 |<--------200--------|
 |---------ACK------->|
*/
CONDITION_FUNCTION(accept_call)
{
  if (!check_handle(ep, nh, SIP_500_INTERNAL_SERVER_ERROR)) 
    return 0;

  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);
  
  switch (callstate(tags)) {
  case nua_callstate_received:
    respond(ep, nh, SIP_180_RINGING, TAG_END());
    return 0;
  case nua_callstate_early:
    respond(ep, nh, SIP_200_OK, 
	    SOATAG_USER_SDP_STR("m=audio 5010 RTP/AVP 8\n"
				"a=rtcp:5011\n"
				"m=video 6010 RTP/AVP 30\n"
				"a=rtcp:6011\n"
				),
	    TAG_END());
    return 0;
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    nua_handle_destroy(ep->nh), ep->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

/*
 A     re-INVITE      B
 |                    |
 |-------INVITE------>|
 |<--------200--------|
 |---------ACK------->|
*/
CONDITION_FUNCTION(until_ready) 
{
  if (!check_handle(ep, nh, SIP_500_INTERNAL_SERVER_ERROR)) 
    return 0;
  if (event != nua_i_active && event != nua_i_terminated)
    save_event_in_list(ctx, ep);

  switch (callstate(tags)) {
  case nua_callstate_ready:
    return 1;
  case nua_callstate_terminated:
    nua_handle_destroy(ep->nh), ep->nh = NULL;
    return 1;
  default:
    return 0;
  }
}

/*
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
 |---------BYE------->|
 |<--------200--------|
*/

int test_call_hold(struct context *ctx)
{
  BEGIN();

  struct endpoint *a = &ctx->a, *b = &ctx->b;
  struct event *e;

  TEST_1(a->nh = nua_handle(a->nua, 0, SIPTAG_TO(b->address), TAG_END()));
  invite(a, a->nh, NUTAG_URL(b->contact->m_url),
	 SOATAG_USER_SDP_STR("m=audio 5008 RTP/AVP 0 8\n"
			     "m=video 6008 RTP/AVP 30\n"),
	 TAG_END());
  run_until(ctx, -1, until_terminated, -1, accept_call);

  /* Client transitions:
     INIT -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C2)-> PROCEEDING: nua_r_invite, nua_i_state
     PROCEEDING -(C3+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_proceeding); /* PROCEEDING */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags));
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, a);

  /*
   Server transitions:
   INIT -(S1)-> RECEIVED: nua_i_invite, nua_i_state
   RECEIVED -(S2a)-> EARLY: nua_respond(), nua_i_state
   EARLY -(S3a)-> COMPLETED: nua_respond(), nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events.head); TEST(e->data->e_event, nua_i_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_received); /* RECEIVED */
  TEST_1(is_offer_recv(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_early); /* EARLY */
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  free_events_in_list(ctx, b);

  /*
 :                    :
 |--INVITE(sendonly)->|
 |<---200(recvonly)---|
 |---------ACK------->|
 :                    :
  */

  /* Put B on hold */
  invite(a, a->nh, SOATAG_HOLD("audio"), 
	 SIPTAG_SUBJECT_STR("hold b"),
	 TAG_END());
  run_until(ctx, -1, until_terminated, -1, until_ready);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3b+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDONLY);
  TEST_1(!e->next);
  free_events_in_list(ctx, a);

  /*
   Server transitions: 
   READY -(S3b)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events.head); /* TEST(e->data->e_event, nua_i_invite);
  XXX - nua_i_invite from re-INVITE missing?
  TEST_1(e = e->next); */ TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_RECVONLY);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_RECVONLY);
  TEST_1(!e->next);

  free_events_in_list(ctx, b);

  /*
 :                    :
 |<-INVITE(inactive)--|
 |----200(inactive)-->|
 |<--------ACK--------|
 :                    :
  */

  /* Put A on hold, too. */
  invite(b, b->nh, SOATAG_HOLD("audio"), 
	 SIPTAG_SUBJECT_STR("hold a"),
	 TAG_END());
  run_until(ctx, -1, until_ready, -1, until_terminated);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3b+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = b->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_INACTIVE);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, b);

  /*
   Server transitions: 
   READY -(S3b)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = a->events.head); /* TEST(e->data->e_event, nua_i_invite);
  XXX - nua_i_invite from re-INVITE missing?
  TEST_1(e = e->next); */ TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_INACTIVE);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_INACTIVE);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  free_events_in_list(ctx, a);

  /* ------------------------------------------------------------------------ */
  /* Resume B from hold */
  invite(a, a->nh, SOATAG_HOLD(NULL), 
	 SIPTAG_SUBJECT_STR("resume b"),
	 TAG_END());
  run_until(ctx, -1, until_terminated, -1, until_ready);

  /*
 :                    :
 |--INVITE(recvonly)->|
 |<---200(sendonly)---|
 |---------ACK------->|
 :                    :
  */

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3b+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = a->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_RECVONLY);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, a);

  /*
   Server transitions: 
   READY -(S3b)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = b->events.head); /* TEST(e->data->e_event, nua_i_invite);
  XXX - nua_i_invite from re-INVITE missing?
  TEST_1(e = e->next); */ TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDONLY);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDONLY);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  free_events_in_list(ctx, b);

  /* ------------------------------------------------------------------------ */
  /*
 :                    :
 |<-INVITE(sendrecv)--|
 |----200(sendrecv)-->|
 |<--------ACK--------|
 :                    :
  */

  /* Resume A on hold, too. */
  invite(b, b->nh, SOATAG_HOLD(""), 
	 SIPTAG_SUBJECT_STR("resume a"),
	 TAG_END());
  run_until(ctx, -1, until_ready, -1, until_terminated);

  /* Client transitions:
     READY -(C1)-> CALLING: nua_invite(), nua_i_state
     CALLING -(C3b+C4)-> READY: nua_r_invite, nua_i_state
  */
  TEST_1(e = b->events.head); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_calling); /* CALLING */
  TEST_1(is_offer_sent(e->data->e_tags)); 
  TEST_1(e = e->next); TEST(e->data->e_event, nua_r_invite);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST_1(is_answer_recv(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);
  free_events_in_list(ctx, b);

  /*
   Server transitions: 
   READY -(S3b)-> COMPLETED: nua_i_invite, <auto-answer>, nua_i_state
   COMPLETED -(S4)-> READY: nua_i_ack, nua_i_state
  */
  TEST_1(e = a->events.head); /* TEST(e->data->e_event, nua_i_invite);
  XXX - nua_i_invite from re-INVITE missing?
  TEST_1(e = e->next); */ TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_completed); /* COMPLETED */
  TEST_1(is_answer_sent(e->data->e_tags)); 
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_ack);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_ready); /* READY */
  TEST(audio_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST(video_activity(e->data->e_tags), SOA_ACTIVE_SENDRECV);
  TEST_1(!e->next);

  free_events_in_list(ctx, a);

  /*
 A                    B
 |---------BYE------->|
 |<--------200--------|
   */
  bye(a, a->nh, TAG_END());
  run_until(ctx, -1, until_terminated, -1, save_events);

  /*
   Transitions of A:
   READY --(T2)--> TERMINATING: nua_bye()
   TERMINATING --(T3)--> TERMINATED: nua_r_bye, nua_i_state
  */
  TEST_1(e = a->events.head); TEST(e->data->e_event, nua_r_bye);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, a);

  /* Transitions of B:
     READY -(T1)-> TERMINATED: nua_i_bye, nua_i_state
  */
  TEST_1(e = b->events.head); TEST(e->data->e_event, nua_i_bye);
  TEST_1(e = e->next); TEST(e->data->e_event, nua_i_state);
  TEST(callstate(e->data->e_tags), nua_callstate_terminated); /* TERMINATED */
  TEST_1(!e->next);
  free_events_in_list(ctx, b);

  nua_handle_destroy(a->nh), a->nh = NULL;
  nua_handle_destroy(b->nh), b->nh = NULL;

  END();
}


int test_deinit(struct context *ctx)
{
  BEGIN();

  nua_handle_destroy(ctx->a.nh), ctx->a.nh = NULL;

  nua_shutdown(ctx->a.nua);
  run_a_until(ctx, nua_r_shutdown, condition_final_response);
  nua_destroy(ctx->a.nua), ctx->a.nua = NULL;

  nua_handle_destroy(ctx->b.nh), ctx->b.nh = NULL;

  nua_shutdown(ctx->b.nua);
  run_b_until(ctx, nua_r_shutdown, condition_final_response);
  nua_destroy(ctx->b.nua), ctx->b.nua = NULL;

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
  int i, o_attach = 0, o_alarm = 1;

  struct context ctx[1] = {{{ SU_HOME_INIT(ctx) }}};

  ctx->a.name[0] = 'a';
  ctx->a.ctx = ctx;
  ctx->a.events.tail = &ctx->a.events.head;
  ctx->b.name[0] = 'b';
  ctx->b.ctx = ctx;
  ctx->b.events.tail = &ctx->b.events.head;

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

      su_log_set_level(nua_log, level);
    }
    else if (strcmp(argv[i], "--attach") == 0) {
      o_attach = 1;
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
      usage();
  }

  if (o_attach) {
    char line[10];
    printf("%s: pid %u\n", name, getpid());
    printf("<Press RETURN to continue>\n");
    fgets(line, sizeof line, stdin);
  }
#if HAVE_ALARM
  else if (o_alarm) {
    alarm(60);
    signal(SIGALRM, sig_alarm);
  }
#endif

  su_init();

  if (!(TSTFLAGS & tst_verbatim)) {
    su_log_soft_set_level(nua_log, 0);
  }

#define SINGLE_FAILURE_CHECK()						\
  do { fflush(stdout);							\
    if (retval && quit_on_single_failure) { su_deinit(); return retval; } \
  } while(0)

  retval |= test_api_errors(ctx); SINGLE_FAILURE_CHECK();
  retval |= test_params(ctx); SINGLE_FAILURE_CHECK();

  retval |= test_init(ctx, argv + i); SINGLE_FAILURE_CHECK();
  if (retval == 0) {
    retval |= test_basic_call(ctx); SINGLE_FAILURE_CHECK();
    retval |= test_call_rejects(ctx); SINGLE_FAILURE_CHECK();
    ctx->b.printer = print_event;
    retval |= test_call_hold(ctx); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ctx); SINGLE_FAILURE_CHECK();

  su_deinit();

  return retval;
}
