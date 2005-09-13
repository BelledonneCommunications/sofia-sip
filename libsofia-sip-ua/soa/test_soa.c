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

/**@CFILE test_soa.c
 * @brief High-level tester for Sofia SDP Offer/Answer Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Aug 17 12:12:12 EEST 2005 ppessi
 * $Date: 2005/09/09 10:56:31 $
 */

#include "config.h"

const char test_soa_c_id[] =
"$Id: test_soa.c,v 1.2 2005/09/09 10:56:31 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#if HAVE_ALARM
#include <unistd.h>
#include <signal.h>
#endif

struct context;
#define SOA_MAGIC_T struct context

#include "soa.h"
#include "soa_add.h"

#include <su_log.h>

extern su_log_t soa_log[];

char const name[] = "test_soa";
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

struct context 
{
  su_home_t home[1];
  su_root_t *root;

  struct {
    soa_session_t *a;
    soa_session_t *b;
  } synch, asynch;

  soa_session_t *completed;
};

int test_api_completed(struct context *arg, soa_session_t *session)
{
  return 0;
}

int test_api_errors(struct context *ctx)
{
  BEGIN();

  char const *phrase = NULL;
  char const *null = NULL;

  TEST_1(!soa_create("default", NULL, NULL));
  TEST_1(!soa_clone(NULL, NULL, NULL));
  TEST_VOID(soa_destroy(NULL));

  TEST_1(-1 == soa_set_params(NULL, TAG_END()));
  TEST_1(-1 == soa_get_params(NULL, TAG_END()));

  TEST_1(!soa_get_paramlist(NULL));

  TEST(soa_error_as_sip_response(NULL, &phrase), 500);
  TEST_S(phrase, "Internal Server Error");

  TEST_1(soa_error_as_sip_reason(NULL));

  TEST_1(!soa_media_features(NULL, 0, NULL));

  TEST_1(!soa_sip_required(NULL));
  TEST_1(!soa_sip_support(NULL));

  TEST_1(-1 == soa_remote_sip_features(NULL, &null, &null));

  TEST_1(soa_set_capability_sdp(NULL, NULL, -1) < 0);
  TEST_1(soa_set_remote_sdp(NULL, NULL, -1) < 0);
  TEST_1(soa_set_local_sdp(NULL, NULL, -1) < 0);

  TEST_1(soa_get_capability_sdp(NULL, NULL, NULL) < 0);
  TEST_1(soa_get_local_sdp(NULL, NULL, NULL) < 0);
  TEST_1(soa_get_remote_sdp(NULL, NULL, NULL) < 0);

  TEST_1(-1 == soa_generate_offer(NULL, 0, test_api_completed)); 

  TEST_1(-1 == soa_generate_answer(NULL, test_api_completed)); 

  TEST_1(-1 == soa_process_answer(NULL, test_api_completed)); 

  TEST(soa_activate(NULL, "both"), -1);
  TEST(soa_deactivate(NULL, "both"), -1);
  TEST_VOID(soa_terminate(NULL, "both"));

  TEST_1(!soa_is_complete(NULL));

  TEST_1(!soa_init_offer_answer(NULL));

  TEST_1(SOA_ACTIVE_DISABLED == soa_is_audio_active(NULL));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_video_active(NULL));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_image_active(NULL));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_chat_active(NULL));

  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_audio_active(NULL));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_video_active(NULL));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_image_active(NULL));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_chat_active(NULL));

  END();
}

int test_init(struct context *ctx, char *argv[])
{
  BEGIN();

  int n;

  ctx->root = su_root_create(ctx); TEST_1(ctx->root);

  ctx->asynch.a = soa_create("asynch", ctx->root, ctx); 
  TEST_1(!ctx->asynch.a);

  TEST_1(!soa_find("asynch"));
  TEST_1(soa_find("default"));

  n = soa_add("asynch", &soa_asynch_actions); TEST(n, 0);

  TEST_1(soa_find("asynch"));

  ctx->asynch.a = soa_create("asynch", ctx->root, ctx); 
  TEST_1(ctx->asynch.a);

  ctx->asynch.b = soa_create("asynch", ctx->root, ctx);
  TEST_1(ctx->asynch.b);

  /* Create asynchronous endpoints */

  ctx->synch.a = soa_create("static", ctx->root, ctx); 
  TEST_1(!ctx->synch.a);

  TEST_1(!soa_find("static"));
  TEST_1(soa_find("default"));

  n = soa_add("static", &soa_static_actions); TEST(n, 0);

  TEST_1(soa_find("static"));

  ctx->synch.a = soa_create("static", ctx->root, ctx);
  TEST_1(ctx->synch.a);

  ctx->synch.b = soa_create("static", ctx->root, ctx);
  TEST_1(ctx->synch.b);

  END();
}

int test_params(struct context *ctx)
{
  BEGIN();
  int n;

  n = soa_set_params(ctx->asynch.a, TAG_END()); TEST(n, 0);
  n = soa_set_params(ctx->asynch.b, TAG_END()); TEST(n, 0);

  END();
}

int test_completed(struct context *ctx, soa_session_t *session)
{
  ctx->completed = session;
  su_root_break(ctx->root);
  return 0;
}

int test_static_offer_answer(struct context *ctx)
{
  BEGIN();
  int n;
  
  soa_session_t *a, *b;

  char const *caps = NONE, *offer = NONE, *answer = NONE;
  int capslen = -1, offerlen = -1, answerlen = -1;

  char const a_caps[] = 
    "v=0\r\n"
    "o=left 219498671 2 IN IP4 127.0.0.2\r\n"
    "c=IN IP4 127.0.0.2\r\n"
    "m=audio 5004 RTP/AVP 0 8\r\n";

  char const b_caps[] = 
    "v=0\n"
    "o=right 93298573265 321974 IN IP4 127.0.0.3\n"
    "c=IN IP4 127.0.0.3\n"
    "m=audio 5006 RTP/AVP 96\n"
    "m=rtpmap:96 GSM/8000\n";

  n = soa_set_capability_sdp(ctx->synch.a, "m=audio 5004 RTP/AVP 0 8", -1); 
  TEST(n, 1);

  n = soa_set_capability_sdp(ctx->synch.a, a_caps, strlen(a_caps)); TEST(n, 1);
  n = soa_get_capability_sdp(ctx->synch.a, &caps, &capslen); TEST(n, 1);

  TEST_1(caps != NULL && caps != NONE);
  TEST_1(capslen > 0);

  n = soa_set_capability_sdp(ctx->synch.b, b_caps, strlen(b_caps)); TEST(n, 1);

  TEST_1(a = soa_clone(ctx->synch.a, ctx->root, ctx));
  TEST_1(b = soa_clone(ctx->synch.b, ctx->root, ctx));

  n = soa_get_local_sdp(a, &offer, &offerlen); TEST(n, 0);

  n = soa_generate_offer(a, 1, test_completed); TEST(n, 0);

  n = soa_get_local_sdp(a, &offer, &offerlen); TEST(n, 1);
  TEST_1(offer != NULL && offer != NONE);

  n = soa_set_remote_sdp(b, offer, offerlen); TEST(n, 1);

  n = soa_get_local_sdp(b, &answer, &answerlen); TEST(n, 0);

  n = soa_generate_answer(b, test_completed); TEST(n, 0);

  TEST_1(soa_is_complete(b));
  TEST(soa_activate(b, NULL), 0);

  n = soa_get_local_sdp(b, &answer, &answerlen); TEST(n, 1);
  TEST_1(answer != NULL && answer != NONE);

  n = soa_set_remote_sdp(a, answer, -1); TEST(n, 1);

  n = soa_process_answer(a, test_completed); TEST(n, 0);

  TEST_1(soa_is_complete(a));
  TEST(soa_activate(a, NULL), 0);

  TEST_1(SOA_ACTIVE_SENDRECV == soa_is_audio_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_video_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_image_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_chat_active(a));

  TEST_1(SOA_ACTIVE_SENDRECV == soa_is_remote_audio_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_video_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_image_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_chat_active(a));

  TEST_VOID(soa_terminate(a, NULL));

  TEST_1(SOA_ACTIVE_DISABLED == soa_is_audio_active(a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_audio_active(a));

  TEST_VOID(soa_terminate(b, NULL));
  
  TEST_VOID(soa_destroy(a));
  TEST_VOID(soa_destroy(b));

  END();
}


int test_asynch_offer_answer(struct context *ctx)
{
  BEGIN();
  int n;
  
  char const *caps = NONE, *offer = NONE, *answer = NONE;
  int capslen = -1, offerlen = -1, answerlen = -1;

  char const a[] = 
    "v=0\r\n"
    "o=left 219498671 2 IN IP4 127.0.0.2\r\n"
    "c=IN IP4 127.0.0.2\r\n"
    "m=audio 5004 RTP/AVP 0 8\r\n";

  char const b[] = 
    "v=0\n"
    "o=right 93298573265 321974 IN IP4 127.0.0.3\n"
    "c=IN IP4 127.0.0.3\n"
    "m=audio 5006 RTP/AVP 96\n"
    "m=rtpmap:96 GSM/8000\n";

  n = soa_set_capability_sdp(ctx->asynch.a, "m=audio 5004 RTP/AVP 0 8", -1); 
  TEST(n, 1);

  n = soa_set_capability_sdp(ctx->asynch.a, a, strlen(a)); TEST(n, 1);
  n = soa_get_capability_sdp(ctx->asynch.a, &caps, &capslen); TEST(n, 1);

  TEST_1(caps != NULL && caps != NONE);
  TEST_1(capslen > 0);

  n = soa_set_capability_sdp(ctx->asynch.b, b, strlen(b)); TEST(n, 1);

  n = soa_generate_offer(ctx->asynch.a, 1, test_completed); TEST(n, 1);

  su_root_run(ctx->root); TEST(ctx->completed, ctx->asynch.a); 
  ctx->completed = NULL;

  n = soa_get_local_sdp(ctx->asynch.a, &offer, &offerlen); TEST(n, 1);

  n = soa_set_remote_sdp(ctx->asynch.b, offer, offerlen); TEST(n, 1);

  n = soa_generate_answer(ctx->asynch.b, test_completed); TEST(n, 1);

  su_root_run(ctx->root); TEST(ctx->completed, ctx->asynch.b); 
  ctx->completed = NULL;

  TEST_1(soa_is_complete(ctx->asynch.b));
  TEST(soa_activate(ctx->asynch.b, NULL), 0);

  n = soa_get_local_sdp(ctx->asynch.b, &answer, &answerlen); TEST(n, 1);

  n = soa_set_remote_sdp(ctx->asynch.a, answer, answerlen); TEST(n, 1);

  n = soa_process_answer(ctx->asynch.a, test_completed); TEST(n, 1);

  su_root_run(ctx->root); TEST(ctx->completed, ctx->asynch.a); 
  ctx->completed = NULL;

  TEST_1(soa_is_complete(ctx->asynch.a));
  TEST(soa_activate(ctx->asynch.a, NULL), 0);

  TEST_1(SOA_ACTIVE_SENDRECV == soa_is_audio_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_video_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_image_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_chat_active(ctx->asynch.a));

  TEST_1(SOA_ACTIVE_SENDRECV == soa_is_remote_audio_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_video_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_image_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_chat_active(ctx->asynch.a));

  TEST(soa_deactivate(ctx->asynch.a, NULL), 0);
  TEST(soa_deactivate(ctx->asynch.b, NULL), 0);

  TEST_VOID(soa_terminate(ctx->asynch.a, NULL));

  TEST_1(SOA_ACTIVE_DISABLED == soa_is_audio_active(ctx->asynch.a));
  TEST_1(SOA_ACTIVE_DISABLED == soa_is_remote_audio_active(ctx->asynch.a));

  TEST_VOID(soa_terminate(ctx->asynch.b, NULL));
  
  END();
}

int test_deinit(struct context *ctx)
{
  BEGIN();
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
      
      su_log_set_level(soa_log, level);
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
    su_log_soft_set_level(soa_log, 0);
  }

#define SINGLE_FAILURE_CHECK()						\
  do { fflush(stdout);							\
    if (retval && quit_on_single_failure) { su_deinit(); return retval; } \
  } while(0)

  retval |= test_api_errors(ctx); SINGLE_FAILURE_CHECK();
  retval |= test_init(ctx, argv + i); SINGLE_FAILURE_CHECK();
  if (retval == 0) {
    retval |= test_params(ctx); SINGLE_FAILURE_CHECK();
    retval |= test_static_offer_answer(ctx); SINGLE_FAILURE_CHECK();
    retval |= test_asynch_offer_answer(ctx); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ctx); SINGLE_FAILURE_CHECK();

  su_deinit();

  return retval;
}
