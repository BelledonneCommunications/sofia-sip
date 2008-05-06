/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2007 Nokia Corporation.
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

/**@CFILE suite2_for_nua.c
 *
 * @brief Check-driven tester for Sofia SIP User Agent library
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @copyright (C) 2007 Nokia Corporation.
 */

#include "config.h"

#include "check_sofia.h"
#include "s2tester.h"

#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/soa.h>
#include <sofia-sip/su_tagarg.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static nua_t *nua;

int s2_verbose = 0;

static void s2_ua_setup(void)
{
  s2_setup(NULL);

  if (s2_verbose) {
    s2_setup_logs(7);
    s2_setup_tport(NULL, TPTAG_LOG(1), TAG_END());
  }
  else {
    s2_setup_logs(0);
    s2_setup_tport(NULL, TPTAG_LOG(0), TAG_END());
  }

  assert(s2tester->contact);
  s2_setup_nua(SIPTAG_FROM_STR("Alice <sip:alice@example.org>"),
	       NUTAG_PROXY((url_string_t *)s2tester->contact->m_url),
	       TAG_END());

  nua = s2tester->nua;
}

void s2_ua_teardown(void)
{
  s2_ua_teardown();
}

/* ====================================================================== */

nua_handle_t *rnh;

void s2_register_setup(void)
{
  struct message *m;

  s2_case("0.1", "Registration Setup", "");

  rnh = nua_handle(nua, NULL, TAG_END());

  nua_register(rnh, TAG_END());

  m = s2_wait_for_request(SIP_METHOD_REGISTER);
  fail_if(m == NULL, NULL);

  s2_save_register(m);

  s2_respond_to(m, NULL,
		SIP_200_OK,
		SIPTAG_CONTACT(s2tester->registration->contact),
		TAG_END());
  s2_free_message(m);

  fail_if(s2tester->registration->contact == NULL);
  fail_unless(s2_check_event(nua_r_register, 200));
}

void s2_register_teardown(void)
{
  if (rnh) {
    struct message *m;

    s2_case("0.2", "Registration Teardown", "");

    nua_unregister(rnh, TAG_END());
    
    fail_if((m = s2_wait_for_request(SIP_METHOD_REGISTER)) == NULL);

    s2_save_register(m);

    s2_respond_to(m, NULL,
		  SIP_200_OK,
		  SIPTAG_CONTACT(s2tester->registration->contact),
		  TAG_END());
    fail_unless(s2tester->registration->contact == NULL);

    s2_free_message(m);

    fail_unless(s2_check_event(nua_r_unregister, 200));

    nua_handle_destroy(rnh), rnh = NULL;
  }    
}

START_TEST(basic_register)
{
  nua_handle_t *nh = nua_handle(nua, NULL, TAG_END());
  struct message *m;

  s2_case("1.5", "Failed Register", "REGISTER returned 403 response");

  nua_register(nh, TAG_END());

  fail_unless((m = s2_wait_for_request(SIP_METHOD_REGISTER)) != NULL, NULL);

  s2_respond_to(m, NULL,
		SIP_403_FORBIDDEN,
		TAG_END());
  s2_free_message(m);

  fail_unless(s2_check_event(nua_r_register, 403));

  nua_register(nh, TAG_END());

  fail_unless((m = s2_wait_for_request(SIP_METHOD_REGISTER)) != NULL, NULL);

  s2_respond_to(m, NULL,
	     SIP_403_FORBIDDEN,
	     TAG_END());
  s2_free_message(m);

  fail_unless(s2_check_event(nua_r_register, 403));

} END_TEST

/* ====================================================================== */
/* Call cases */

static soa_session_t *soa = NULL;
static struct dialog *dialog = NULL;

void s2_call_setup(void)
{
  s2_ua_setup();

  soa = soa_create(NULL, s2tester->root, NULL);

  fail_if(!soa);

  soa_set_params(soa,
		 SOATAG_USER_SDP_STR("m=audio 5008 RTP/AVP 8 0\r\n"
				     "m=video 5010 RTP/AVP 34\r\n"),
		 TAG_END());

  dialog = su_home_new(sizeof *dialog); fail_if(!dialog);

  s2_register_setup();
}

void s2_call_teardown(void)
{
  mark_point();

  s2_register_teardown();

  nua_shutdown(nua);
  fail_unless(s2_check_event(nua_r_shutdown, 200));
  
  s2_ua_teardown();
}

void s2_save_sdp(struct message *message)
{
  sip_payload_t *pl;
  char const *body;
  isize_t bodylen;

  fail_if(!message);

  fail_if(!message->sip->sip_content_length);
  fail_if(!message->sip->sip_content_type);
  fail_if(strcmp(message->sip->sip_content_type->c_type,
		  "application/sdp"));

  fail_if(!message->sip->sip_payload);
  pl = message->sip->sip_payload;
  body = pl->pl_data, bodylen = pl->pl_len;

  fail_if(soa_set_remote_sdp(soa, NULL, body, (issize_t)bodylen) != 1);
}

void s2_process_offer(struct message *message)
{
  s2_save_sdp(message);
  fail_if(soa_generate_answer(soa, NULL) < 0);
}

void s2_process_answer(struct message *message)
{
  s2_save_sdp(message);
  fail_if(soa_process_answer(soa, NULL) < 0);
}

void s2_respond_with_sdp(struct message *request,
			 struct dialog *dialog,
			 int status, char const *phrase,
			 tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;

  char const *body;
  isize_t bodylen;

  fail_if(soa_get_local_sdp(soa, NULL, &body, &bodylen) != 1);

  ta_start(ta, tag, value);
  s2_respond_to(request, dialog, status, phrase, 
		SIPTAG_CONTENT_TYPE_STR("application/sdp"),
		SIPTAG_PAYLOAD_STR(body),
		ta_tags(ta));
  ta_end(ta);
}

void s2_request_with_sdp(struct dialog *dialog,
			 sip_method_t method, char const *name,
			 tport_t *tport,
			 tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;

  char const *body;
  isize_t bodylen;

  fail_if(soa_get_local_sdp(soa, NULL, &body, &bodylen) != 1);

  ta_start(ta, tag, value);
  fail_if(
    s2_request_to(dialog, method, name, tport, 
		  SIPTAG_CONTENT_TYPE_STR("application/sdp"),
		  SIPTAG_PAYLOAD_STR(body),
		  ta_tags(ta)));
  ta_end(ta);
}
			 

void
s2_invite_by_nua(nua_handle_t *nh,
		       tag_type_t tag, tag_value_t value, ...)
{
  struct message *invite;

  ta_list ta;

  ta_start(ta, tag, value);
  nua_invite(nh, SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
	     ta_tags(ta));
  ta_end(ta);

  fail_unless(s2_check_callstate(nua_callstate_calling));

  invite = s2_wait_for_request(SIP_METHOD_INVITE);

  s2_process_offer(invite);
  s2_respond_with_sdp(
    invite, dialog, SIP_180_RINGING, 
    SIPTAG_CONTENT_DISPOSITION_STR("session;handling=optional"),
    TAG_END());
    
  fail_unless(s2_check_event(nua_r_invite, 180));
  fail_unless(s2_check_callstate(nua_callstate_proceeding));

  s2_respond_with_sdp(
    invite, dialog, SIP_200_OK,
    SIPTAG_CONTENT_DISPOSITION_STR("session"),
    TAG_END());

  s2_free_message(invite);

  fail_unless(s2_check_event(nua_r_invite, 200));
  fail_unless(s2_check_callstate(nua_callstate_ready));
  fail_unless(s2_check_request(SIP_METHOD_ACK));
}

nua_handle_t *
s2_invite_to_nua(void)
{
  struct event *invite;
  struct message *response;
  nua_handle_t *nh;
  sip_cseq_t cseq[1];

  //s2_setup_logs(7);
  //tport_set_params(s2tester->master, TPTAG_LOG(1), TAG_END());

  soa_generate_offer(soa, 1, NULL);

  s2_request_with_sdp(dialog, SIP_METHOD_INVITE, NULL, TAG_END());

  invite = s2_wait_for_event(nua_i_invite, 100); fail_unless(invite != NULL);
  fail_unless(s2_check_callstate(nua_callstate_received));

  nh = invite->nh;
  fail_if(!nh);

  sip_cseq_init(cseq);
  cseq->cs_method = sip_method_ack;
  cseq->cs_method_name = "ACK";
  cseq->cs_seq = sip_object(invite->data->e_msg)->sip_cseq->cs_seq;

  s2_free_event(invite);

  response = s2_wait_for_response(100, SIP_METHOD_INVITE);
  fail_if(!response);

  nua_respond(nh, SIP_180_RINGING,
	      SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
	      TAG_END());
  fail_unless(s2_check_callstate(nua_callstate_early));

  response = s2_wait_for_response(180, SIP_METHOD_INVITE);
  fail_if(!response);
  s2_update_dialog(dialog, response);
  s2_process_answer(response);
  s2_free_message(response);

  nua_respond(nh, SIP_200_OK, TAG_END());

  fail_unless(s2_check_callstate(nua_callstate_completed));

  response = s2_wait_for_response(200, SIP_METHOD_INVITE);

  fail_if(!response);
  s2_update_dialog(dialog, response);
  s2_free_message(response);

  fail_if(s2_request_to(dialog, SIP_METHOD_ACK, NULL,
			SIPTAG_CSEQ(cseq), TAG_END()));

  fail_unless(s2_check_event(nua_i_ack, 200));
  fail_unless(s2_check_callstate(nua_callstate_ready));

  return nh;
}

void 
s2_bye_by_nua(nua_handle_t *nh,
	      tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  struct message *bye;

  ta_start(ta, tag, value);
  nua_bye(nh, ta_tags(ta));
  ta_end(ta);

  bye = s2_wait_for_request(SIP_METHOD_BYE);
  fail_if(!bye);
  s2_respond_to(bye, dialog, SIP_200_OK, TAG_END());
  s2_free_message(bye);
  fail_unless(s2_check_event(nua_r_bye, 200));
  fail_unless(s2_check_callstate(nua_callstate_terminated));
}

void 
s2_bye_by_nua_challenged(nua_handle_t *nh,
			 tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  struct message *bye;

  s2_flush_events();

  ta_start(ta, tag, value);
  nua_bye(nh, ta_tags(ta));
  ta_end(ta);

  bye = s2_wait_for_request(SIP_METHOD_BYE);
  fail_if(!bye);
  s2_respond_to(bye, dialog, SIP_407_PROXY_AUTH_REQUIRED,
		SIPTAG_PROXY_AUTHENTICATE_STR(
		  "Digest "
		  "realm=\"s2test\", "
		  "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
		  "qop=\"auth\", "
		  "algorithm=\"MD5\""),
		TAG_END());
  s2_free_message(bye);
  fail_unless(s2_check_event(nua_r_bye, 407));

  nua_authenticate(nh, NUTAG_AUTH("Digest:\"s2test\":abc:abc"), TAG_END());
  bye = s2_wait_for_request(SIP_METHOD_BYE);
  fail_if(!bye);
  s2_respond_to(bye, dialog, SIP_200_OK, TAG_END());
  s2_free_message(bye);
  fail_unless(s2_check_event(nua_r_bye, 200));
  fail_unless(s2_check_callstate(nua_callstate_terminated));
  fail_if(s2tester->events);
}


void 
s2_cancel_by_nua(nua_handle_t *nh,
		 struct message *invite,
		 struct dialog *dialog,
		 tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  struct message *cancel;

  ta_start(ta, tag, value);
  nua_cancel(nh, ta_tags(ta));
  ta_end(ta);

  cancel = s2_wait_for_request(SIP_METHOD_CANCEL);
  fail_if(!cancel);
  s2_respond_to(cancel, dialog, SIP_200_OK, TAG_END());
  s2_free_message(cancel);
  fail_unless(s2_check_event(nua_r_cancel, 200));

  s2_respond_to(invite, dialog, SIP_487_REQUEST_CANCELLED, TAG_END());
  fail_unless(s2_check_request(SIP_METHOD_ACK));

  fail_unless(s2_check_event(nua_r_invite, 487));
}

void 
s2_bye_to_nua(nua_handle_t *nh,
	      tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;

  ta_start(ta, tag, value);
  fail_if(s2_request_to(dialog, SIP_METHOD_BYE, NULL, ta_tags(ta)));
  ta_end(ta);

  fail_unless(s2_check_event(nua_i_bye, 200));
  fail_unless(s2_check_callstate(nua_callstate_terminated));
  fail_unless(s2_check_response(200, SIP_METHOD_BYE));
}

/* ====================================================================== */
/* 2 - Call cases */

/* 2.1 - Basic call cases */
 
START_TEST(basic_call_with_bye_by_nua)
{
  nua_handle_t *nh;

  s2_case("2.1.1", "Basic call",
	 "NUA sends INVITE, NUA sends BYE");

  nh = nua_handle(nua, NULL, SIPTAG_TO(s2tester->local), TAG_END());

  s2_invite_by_nua(nh, TAG_END());

  s2_bye_by_nua(nh, TAG_END());

  nua_handle_destroy(nh);
}
END_TEST


START_TEST(basic_call_with_bye_to_nua)
{
  nua_handle_t *nh;

  s2_case("2.1.2", "Basic call",
	 "NUA sends INVITE, NUA receives BYE");

  nh = nua_handle(nua, NULL, SIPTAG_TO(s2tester->local), TAG_END());

  s2_invite_by_nua(nh, TAG_END());

  s2_bye_to_nua(nh, TAG_END());

  nua_handle_destroy(nh);
}
END_TEST


START_TEST(call_to_nua_with_bye_to_nua)
{
  nua_handle_t *nh;

  s2_case("2.1.3", "Incoming call",
	 "NUA receives INVITE and BYE");

  nh = s2_invite_to_nua();

  s2_bye_to_nua(nh, TAG_END());

  nua_handle_destroy(nh);
}
END_TEST


START_TEST(call_to_nua_with_bye_by_nua)
{
  nua_handle_t *nh;

  s2_case("2.1.4", "Incoming call",
	 "NUA receives INVITE and sends BYE");

  nh = s2_invite_to_nua();

  s2_bye_by_nua(nh, TAG_END());

  nua_handle_destroy(nh);
}
END_TEST


START_TEST(call_to_nua_with_bye_by_nua_challenged)
{
  nua_handle_t *nh;

  s2_case("2.1.5", "Incoming call",
	 "NUA receives INVITE and sends BYE, BYE is challenged");

  nh = s2_invite_to_nua();

  s2_bye_by_nua_challenged(nh, TAG_END());

  nua_handle_destroy(nh);
}
END_TEST


/* 2.2 - Call CANCEL cases */

START_TEST(call_with_cancel_by_nua)
{
  nua_handle_t *nh;
  struct message *invite;

  s2_case("2.2.1", "Canceled call",
	 "NUA is callee, NUA sends CANCEL");

  nh = nua_handle(nua, NULL, SIPTAG_TO(s2tester->local), TAG_END());

  nua_invite(nh, SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
	     TAG_END());
  fail_unless(s2_check_callstate(nua_callstate_calling));
  
  invite = s2_wait_for_request(SIP_METHOD_INVITE);
  s2_process_offer(invite);
  s2_respond_with_sdp(
    invite, dialog, SIP_180_RINGING, 
    SIPTAG_CONTENT_DISPOSITION_STR("session;handling=optional"),
    TAG_END());
  fail_unless(s2_check_event(nua_r_invite, 180));
  fail_unless(s2_check_callstate(nua_callstate_proceeding));

  s2_cancel_by_nua(nh, invite, dialog, TAG_END());
  fail_unless(s2_check_callstate(nua_callstate_terminated));

  nua_handle_destroy(nh);
}
END_TEST


/* ====================================================================== */

/* 3.1 - Call error cases */
START_TEST(call_forbidden)
{
  nua_handle_t *nh;
  struct message *invite;

  s2_case("3.1", "Call failure", "Call fails with 403 response");
  nh = nua_handle(nua, NULL, SIPTAG_TO(s2tester->local),
		  TAG_END());

  nua_invite(nh, SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
	     TAG_END());

  fail_unless(s2_check_callstate(nua_callstate_calling));

  invite = s2_wait_for_request(SIP_METHOD_INVITE);
  fail_if(!invite);
  s2_respond_to(invite, NULL, SIP_403_FORBIDDEN, TAG_END());
  s2_free_message(invite);

  fail_unless(s2_check_request(SIP_METHOD_ACK));
  fail_unless(s2_check_event(nua_r_invite, 403));
  fail_unless(s2_check_callstate(nua_callstate_terminated));

  nua_handle_destroy(nh);
}
END_TEST

START_TEST(reinvite_forbidden)
{
  nua_handle_t *nh;
  struct message *invite;

  s2_case("3.1", "Call failure", "Call fails with 403 response");
  nh = nua_handle(nua, NULL, SIPTAG_TO(s2tester->local),
		  TAG_END());

  nua_invite(nh, SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
	     TAG_END());

  fail_unless(s2_check_callstate(nua_callstate_calling));

  invite = s2_wait_for_request(SIP_METHOD_INVITE);
  fail_if(!invite);
  s2_respond_to(invite, NULL, SIP_403_FORBIDDEN, TAG_END());
  s2_free_message(invite);

  fail_unless(s2_check_request(SIP_METHOD_ACK));

  fail_unless(s2_check_event(nua_r_invite, 403));
  fail_unless(s2_check_callstate(nua_callstate_terminated));

  nua_handle_destroy(nh);
}
END_TEST

/* ====================================================================== */

START_TEST(s2_empty)
{
}
END_TEST

Suite *suite2_for_nua(void)
{
  Suite *suite = suite_create("suite2_for_nua");
  TCase *tc;

  tc = tcase_create("REGISTER");
  /* Each testcase is run in different process */
  tcase_add_checked_fixture(tc, s2_ua_setup, s2_ua_teardown);
  {
    tcase_add_test(tc, basic_register);
  }
  tcase_set_timeout(tc, 5);
  suite_add_tcase(suite, tc);

  tc = tcase_create("INVITE");
  tcase_add_checked_fixture(tc, s2_call_setup, s2_call_teardown);
  {
    tcase_add_test(tc, s2_empty);
    tcase_add_test(tc, basic_call_with_bye_by_nua);
    tcase_add_test(tc, basic_call_with_bye_to_nua);
    tcase_add_test(tc, call_to_nua_with_bye_to_nua);
    tcase_add_test(tc, call_to_nua_with_bye_by_nua);
    tcase_add_test(tc, call_to_nua_with_bye_by_nua_challenged);
    tcase_add_test(tc, call_with_cancel_by_nua);
  }
  suite_add_tcase(suite, tc);

  tc = tcase_create("INVITE rejected");
  tcase_add_checked_fixture(tc, s2_call_setup, s2_call_teardown);
  {
    tcase_add_test(tc, call_forbidden);
    tcase_add_test(tc, reinvite_forbidden);
    tcase_set_timeout(tc, 5);
  }
  suite_add_tcase(suite, tc);

  return suite;
}
