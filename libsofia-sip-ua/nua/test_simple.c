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

/**@CFILE test_nua_simple.c
 * @brief NUA-11: Test MESSAGE and PUBLISH.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti Mela@nokia.com>
 *
 * @date Created: Wed Aug 17 12:12:12 EEST 2005 ppessi
 */

#include "config.h"

#include "test_nua.h"
#include <sofia-sip/su_tag_class.h>

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
#define __func__ "test_simple"
#endif

/* ======================================================================== */
/* Test simple methods: MESSAGE, PUBLISH */

int test_simple(struct context *ctx)
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
    printf("TEST NUA-11.2: MESSAGE to myself\n");

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

