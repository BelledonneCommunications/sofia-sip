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
 * $Date: 2005/09/29 18:35:22 $
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
struct call;
#define NUA_HMAGIC_T struct call

#include "nua.h"
#include "nua_tag.h"

#include <sdp.h>
#include <sip_header.h>

#include <su_log.h>

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
		       nua_handle_t *nh, struct call *call,
		       sip_t const *sip,
		       tagi_t tags[]);

struct context
{
  su_home_t home[1];
  su_root_t *root;

  int running;

  nua_t *next_stack, *last_stack;

  struct endpoint {
    condition_function *next_condition;
    nua_event_t next_event, last_event;
    nua_t *nua;
    nua_handle_t *nh;
    nua_saved_event_t saved_event[1];
  } a, b;
};

void a_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, struct call *call,
		sip_t const *sip,
		tagi_t tags[])
{
  fprintf(stderr, "a.nua(%p): event %s status %u %s\n",
	  nh, nua_event_name(event), status, phrase);

  if ((ctx->a.next_event == -1 || ctx->a.next_event == event) &&
      (ctx->a.next_condition == NULL ||
       ctx->a.next_condition(event, status, phrase,
			     nua, ctx, &ctx->a, nh, call, sip, tags)))
    ctx->running = 0;

  ctx->a.last_event = event;
  ctx->b.last_event = -1;
}

void b_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, struct context *ctx,
		nua_handle_t *nh, struct call *call,
		sip_t const *sip,
		tagi_t tags[])
{
  fprintf(stderr, "a.nua(%p): event %s status %u %s\n",
	  nh, nua_event_name(event), status, phrase);

  if ((ctx->b.next_event == -1 || ctx->b.next_event == event) &&
      (ctx->b.next_condition == NULL ||
       ctx->b.next_condition(event, status, phrase,
			     nua, ctx, &ctx->a, nh, call, sip, tags)))
    ctx->running = 0;


  ctx->a.last_event = -1;
  ctx->b.last_event = event;
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
  run_until(ctx, a_event, a_condition, -1, NULL);
  return ctx->a.last_event;
}

int run_b_until(struct context *ctx,
		nua_event_t b_event,
		condition_function *b_condition)
{
  run_until(ctx, -1, NULL, b_event, b_condition);
  return ctx->b.last_event;
}

#define CONDITION_FUNCTION(name)		\
  int name(nua_event_t event,			\
	   int status, char const *phrase,	\
	   nua_t *nua, struct context *ctx,	\
	   struct endpoint *ep,			\
	   nua_handle_t *nh, struct call *call, \
	   sip_t const *sip,			\
	   tagi_t tags[])

CONDITION_FUNCTION(condition_final_response){ return status >= 200; }
CONDITION_FUNCTION(save_final_response)
{
  if (status < 200)
    return 0;
  nua_save_event(ep->nua, ep->saved_event);
  return 1;
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
  TEST_1(!nua_info_event(NULL, NULL, NULL, NULL, NULL,
			 NULL, NULL, NULL, NULL));
  TEST_VOID(nua_destroy_event(NULL));

  {
    nua_saved_event_t event[1];

    memset(event, 0, sizeof event);

    TEST_1(!nua_save_event(NULL, event));
    TEST_1(!nua_info_event(event, NULL, NULL, NULL, NULL,
			   NULL, NULL, NULL, NULL));
    TEST_VOID(nua_destroy_event(event));
  }

  su_log_set_level(nua_log, level);

  END();
}

int test_init(struct context *ctx, char *argv[])
{
  BEGIN();

  ctx->root = su_root_create(ctx); TEST_1(ctx->root);

  /* Disable threading by command line switch? */
  su_root_threading(ctx->root, 0);

  ctx->a.nua = nua_create(ctx->root, a_callback, ctx,
			  NUTAG_URL("sip:*:*"),
			  TAG_END());
  TEST_1(ctx->a.nua);

  ctx->b.nua = nua_create(ctx->root, b_callback, ctx,
			  NUTAG_URL("sip:*:*"),
			  TAG_END());
  TEST_1(ctx->b.nua);

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

  from = sip_from_make(tmphome, Alice);

  nh = nua_handle(ctx->a.nua, NULL, TAG_END());

  nua_set_handle_params(nh, NUTAG_INVITE_TIMER(90), TAG_END());

  /* Modify everything from their default value */
  nua_set_params(ctx->a.nua,
		 SIPTAG_FROM(from),
		 NUTAG_RETRY_COUNT(5),
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

		 SIPTAG_SUPPORTED_STR("humppaa,kuole"),
		 SIPTAG_ALLOW_STR("OPTIONS, INFO"),
		 SIPTAG_USER_AGENT_STR("test_nua"),

		 SIPTAG_ORGANIZATION_STR("Pussy Galore's Flying Circus"),

		 NUTAG_MEDIA_ENABLE(0),
		 NUTAG_REGISTRAR("sip:sip.wonderland.org"),
		
		 TAG_END());

  nua_get_params(ctx->a.nua, TAG_ANY(), TAG_END());

  run_a_until(ctx, nua_r_get_params, save_final_response);

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
    nua_event_t event = nua_i_error;
    tagi_t const *tags = NULL;

    TEST(nua_info_event(ctx->a.saved_event, 
			&event, NULL, NULL, NULL, NULL, NULL, NULL, &tags), 1);
    TEST(event, nua_r_get_params);

    n = tl_gets(tags,
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
  }
  nua_destroy_event(ctx->a.saved_event);

  if (0)
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
    nua_event_t event = nua_i_error;
    tagi_t const *tags = NULL;

    nua_get_handle_params(nh, TAG_ANY(), TAG_END());
    run_a_until(ctx, nua_r_get_params, save_final_response);

    TEST(nua_info_event(ctx->a.saved_event, 
			&event, NULL, NULL, NULL, NULL, NULL, NULL, &tags), 1);
    TEST(event, nua_r_get_params);

    n = tl_gets(tags,
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
    TEST(n, 1);

    TEST(invite_timeout, 90);

    TEST(from, NONE);
    TEST_S(from_str, "NONE");

    TEST(retry_count, -1);
    TEST(max_subscriptions, -1);

    TEST(invite_enable, -1);
    TEST(auto_alert, -1);
    TEST(early_media, -1);
    TEST(auto_answer, -1);
    TEST(auto_ack, -1);
    TEST(invite_timeout, -1);

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
  }

  nua_handle_destroy(nh);

  END();
}

int test_basic_call(struct context *ctx)
{
  BEGIN();
  END();
}



int test_deinit(struct context *ctx)
{
  BEGIN();

  nua_shutdown(ctx->a.nua);
  run_a_until(ctx, nua_r_shutdown, condition_final_response);
  nua_destroy(ctx->a.nua), ctx->a.nua = NULL;

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
  retval |= test_init(ctx, argv + i); SINGLE_FAILURE_CHECK();
  if (retval == 0) {
    retval |= test_params(ctx); SINGLE_FAILURE_CHECK();
    retval |= test_basic_call(ctx); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ctx); SINGLE_FAILURE_CHECK();

  su_deinit();

  return retval;
}
