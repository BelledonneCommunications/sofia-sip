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

typedef 
int condition_function(nua_event_t event,
		       int status, char const *phrase,
		       nua_t *nua, struct context *ctx,
		       nua_handle_t *nh, struct call *call,
		       sip_t const *sip,
		       tagi_t tags[]);

struct context 
{
  su_home_t home[1];
  su_root_t *root;

  int running;

  condition_function *next_condition;
  nua_event_t next_event, last_event;
  nua_t *next_stack, *last_stack;

  struct {
    nua_t *nua;
  } a, b;
};

void callback(nua_event_t event,
	      int status, char const *phrase,
	      nua_t *nua, struct context *ctx,
	      nua_handle_t *nh, struct call *call,
	      sip_t const *sip,
	      tagi_t tags[])
{
  fprintf(stderr, "%c.nua(%p): event %s status %u %s\n", 
	  nua == ctx->a.nua ? 'a' : 'b', call,
	  nua_event_name(event), status, phrase);

  if ((ctx->next_stack == NULL || ctx->next_stack == nua) &&
      (ctx->next_event == -1 || ctx->next_event == event) &&
      (ctx->next_condition == NULL || 
       ctx->next_condition(event, status, phrase, 
			   nua, ctx, nh, call, sip, tags)))
    ctx->running = 0;

  ctx->last_event = event;
  ctx->last_stack = nua;
}

int run_until(struct context *ctx, nua_event_t event, nua_t *nua, 
	      condition_function *condition)
{
  ctx->next_stack = nua;
  ctx->next_event = event;
  ctx->next_condition = condition;

  for (ctx->running = 1; ctx->running;) {
    su_root_step(ctx->root, 1000);
  }

  return ctx->last_event;
}

#define CONDITION_FUNCTION(name) \
  int name(nua_event_t event, \
		       int status, char const *phrase, \
		       nua_t *nua, struct context *ctx,\
		       nua_handle_t *nh, struct call *call,\
		       sip_t const *sip,\
		       tagi_t tags[])

CONDITION_FUNCTION(condition_final_response){ return status >= 200; }

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
  su_root_threading(ctx->root, 1);

  ctx->a.nua = nua_create(ctx->root, callback, ctx, 
			  NUTAG_URL("sip:*:*"),
			  TAG_END());
  TEST_1(ctx->a.nua);

  ctx->b.nua = nua_create(ctx->root, callback, ctx, 
			  NUTAG_URL("sip:*:*"),
			  TAG_END());
  TEST_1(ctx->b.nua);

  END();
}

int test_params(struct context *ctx)
{
  BEGIN();
#if 0
  int n;
  unsigned af;
  char const *address;
  nua_session_t *a = ctx->synch.a, *b = ctx->synch.b;

  n = nua_set_params(a, TAG_END()); TEST(n, 0);
  n = nua_set_params(b, TAG_END()); TEST(n, 0);

  af = -42;
  address = NONE;
  TEST(nua_get_params(a,
		      NUATAG_AF_REF(af),
		      NUATAG_ADDRESS_REF(address),
		      TAG_END()),
       2);
  TEST(af, NUA_AF_ANY);
  TEST(address, 0);

  TEST(nua_set_params(a,
		      NUATAG_AF(NUA_AF_IP4_IP6),
		      TAG_END()),
       1);
  TEST(nua_get_params(a,
		      NUATAG_AF_REF(af),
		      TAG_END()),
       1);
  TEST(af, NUA_AF_IP4_IP6);
#endif
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
  run_until(ctx, nua_r_shutdown, ctx->a.nua, condition_final_response);
  nua_destroy(ctx->a.nua), ctx->a.nua = NULL;

  nua_shutdown(ctx->b.nua);
  run_until(ctx, nua_r_shutdown, ctx->b.nua, condition_final_response);
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
