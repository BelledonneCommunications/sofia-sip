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
 * $Date: 2005/08/17 14:51:23 $
 */

#include "config.h"

const char test_soa_c_id[] =
"$Id: test_soa.c,v 1.1 2005/08/17 14:51:23 ppessi Exp $";

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

struct context 
{
  su_home_t home[1];
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
  char const * const *featurelist;

  TEST_1(!soa_create(NULL, "default"));
  TEST_1(!soa_clone(NULL, NULL));
  TEST_VOID(soa_destroy(NULL));

  TEST_1(-1 == soa_set_params(NULL, TAG_END()));
  TEST_1(-1 == soa_get_params(NULL, TAG_END()));

  TEST_1(!soa_get_paramlist(NULL));

  TEST(soa_error_as_sip_response(NULL, &phrase), 500);
  TEST_S(phrase, "Internal Server Error");

  TEST_1(soa_error_as_sip_reason(NULL));

  TEST_1(-1 == soa_parse_sdp(NULL, NULL, 0));

  TEST_VOID(soa_clear_sdp(NULL));

  TEST_1(-1 == soa_print_sdp(NULL, 0, NULL, NULL, NULL));

  TEST_1(!soa_media_features(NULL, 0, NULL));

  TEST_1(!soa_sip_required(NULL));
  TEST_1(!soa_sip_support(NULL));

  TEST_1(-1 == soa_remote_sip_features(NULL, &null, &null));

  TEST_1(-1 == soa_offer(NULL, 0, test_api_completed)); 

  TEST_1(-1 == soa_offer_answer(NULL, 0, test_api_completed)); 

  TEST_1(-1 == soa_answer(NULL, 0, test_api_completed)); 

  TEST_VOID(soa_activate(NULL, "both"));
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


  END();
}

int test_params(struct context *ctx)
{
  BEGIN();
  END();
}

int test_deinit(struct context *ctx)
{
  BEGIN();
  END();
}

void sig_alarm(int s)
{
  fprintf(stderr, "%s: FAIL! test timeout!\n", name);
  exit(1);
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
  int i, o_attach = 0, o_alarm = 1;

  struct context ctx[1] = {{ SU_HOME_INIT(ctx) }};

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
  do { if (retval && quit_on_single_failure) { su_deinit(); return retval; } \
  } while(0)

  retval |= test_api_errors(ctx); SINGLE_FAILURE_CHECK();
  retval |= test_init(ctx, argv + i); fflush(stdout); SINGLE_FAILURE_CHECK();
  if (retval == 0) {
    retval |= test_params(ctx); fflush(stdout); SINGLE_FAILURE_CHECK();
  }
  retval |= test_deinit(ctx); fflush(stdout); 

  su_deinit();

  return retval;
}
