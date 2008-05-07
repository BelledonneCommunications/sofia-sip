/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2008 Nokia Corporation.
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

/**@CFILE s2tester.c
 * @brief 2nd test Suite for Sofia SIP User Agent Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Apr 30 12:48:27 EEST 2008 ppessi
 */

#include "config.h"

#undef NDEBUG

#define TP_MAGIC_T struct tp_magic_s

#include <s2tester.h>

#include <sofia-sip/sip_header.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-sip/su_log.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/su_alloc.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

/* -- Types ------------------------------------------------------------- */

struct tp_magic_s
{
  sip_via_t *via;
  sip_contact_t *contact;
};

/* -- Prototypes -------------------------------------------------------- */

static msg_t *s2_msg(int flags);
static int s2_complete_response(msg_t *response, 
				int status, char const *phrase, 
				msg_t *request);
static char *s2_generate_tag(su_home_t *home);

/* -- Globals ----------------------------------------------------------- */

struct tester *s2tester;

char const *_s2case = "0.0";
static unsigned s2_tag_generator = 0;

unsigned default_registration_duration = 3600;


/* -- Delay scenarios --------------------------------------------------- */

static unsigned long time_offset;

extern void (*_su_time)(su_time_t *tv);

static void _su_time_fast_forwarder(su_time_t *tv)
{
  tv->tv_sec += time_offset;
}

void s2_fast_forward(unsigned long seconds)
{
  if (_su_time == NULL)
    _su_time = _su_time_fast_forwarder;

  time_offset += seconds;
}

/* -- NUA events -------------------------------------------------------- */

struct event *s2_remove_event(struct event *e)
{
  if ((*e->prev = e->next))
    e->next->prev = e->prev;

  e->prev = NULL, e->next = NULL;

  return e; 
}

void s2_free_event(struct event *e)
{
  if (e) {
    if (e->prev) {
      if ((*e->prev = e->next))
	e->next->prev = e->prev;
    }
    nua_destroy_event(e->event);
    nua_handle_unref(e->nh);
    free(e);
  }
}

void s2_flush_events(void)
{
  struct tester *t = s2tester;

  while (t->events) {
    s2_free_event(t->events);
  }
}

struct event *s2_next_event(void)
{
  struct tester *t = s2tester;

  for (;;) {
    if (t->events)
      return s2_remove_event(t->events);

    su_root_step(t->root, 100);
  }
} 

struct event *s2_wait_for_event(nua_event_t event, int status)
{
  struct tester *t = s2tester;
  struct event *e;

  for (;;) {
    for (e = t->events; e; e = e->next) {
      if (event != nua_i_none && event != e->data->e_event)
	continue;
      if (status && e->data->e_status != status)
	continue;
      return s2_remove_event(e);
    }

    su_root_step(t->root, 100);
  }
} 

int s2_check_event(nua_event_t event, int status)
{
  struct event *e = s2_wait_for_event(event, status);
  s2_free_event(e);
  return e != NULL;
}

int s2_check_callstate(enum nua_callstate state)
{
  int retval = 0;
  tagi_t const *tagi;
  struct event *e;

  e = s2_wait_for_event(nua_i_state, 0);
  if (e) {
    tagi = tl_find(e->data->e_tags, nutag_callstate);
    if (tagi) {
      retval = (tag_value_t)state == tagi->t_value;
    }
  }
  s2_free_event(e);
  return retval;
}

static void 
s2_nua_callback(nua_event_t event,
		int status, char const *phrase,
		nua_t *nua, nua_magic_t *_t,
		nua_handle_t *nh, nua_hmagic_t *hmagic,
		sip_t const *sip,
		tagi_t tags[])
{
  struct tester *t = s2tester;
  struct event *e, **prev;

  if (event == nua_i_active || event == nua_i_terminated)
    return;
  
  e = calloc(1, sizeof *e);
  nua_save_event(nua, e->event);
  e->nh = nua_handle_ref(nh);
  e->data = nua_event_data(e->event);

  for (prev = &t->events; *prev; prev = &(*prev)->next)
    ;

  *prev = e, e->prev = prev;
}


struct message *
s2_remove_message(struct message *m)
{
  if ((*m->prev = m->next))
    m->next->prev = m->prev;

  m->prev = NULL, m->next = NULL;

  return m; 
}

void
s2_free_message(struct message *m)
{
  if (m) {
    if (m->prev) {
      if ((*m->prev = m->next))
	m->next->prev = m->prev;
    }
    msg_destroy(m->msg);
    tport_unref(m->tport);
    free(m);
  }
}

void s2_flush_messages(void)
{
  struct tester *t = s2tester;

  while (t->received) {
    s2_free_message(t->received);
  }
}

struct message *
s2_next_response(void)
{
  struct tester *t = s2tester;
  struct message *m;

  for (;;) {
    for (m = t->received; m; m = m->next) {
      if (m->sip->sip_status)
	return s2_remove_message(m);
    }
    su_root_step(t->root, 100);
  }
}

struct message *
s2_wait_for_response(int status, sip_method_t method, char const *name)
{
  struct tester *t = s2tester;
  struct message *m;

  for (;;) {
    for (m = t->received; m; m = m->next) {
      if (!m->sip->sip_status)
	continue;

      if (status != 0 && m->sip->sip_status->st_status != status)
	continue;

      if (method == sip_method_unknown && name == NULL)
	break;
      
      if (m->sip->sip_cseq == NULL)
	continue;
      
      if (m->sip->sip_cseq->cs_method != method)
	continue;
      if (name == NULL)
	break;
      if (strcmp(m->sip->sip_cseq->cs_method_name, name) == 0)
	break;
    }

    if (m)
      return s2_remove_message(m);

    su_root_step(t->root, 100);
  }
} 

int
s2_check_response(int status, sip_method_t method, char const *name)
{
  struct message *m = s2_wait_for_response(status, method, name);
  s2_free_message(m);
  return m != NULL;
}


struct message *
s2_next_request(void)
{
  struct message *m;

  for (;;) {
    for (m = s2tester->received; m; m = m->next) {
      if (m->sip->sip_request)
	return s2_remove_message(m);
    }

    su_root_step(s2tester->root, 100);
  }
  
  return NULL;
} 

struct message *
s2_wait_for_request(sip_method_t method, char const *name)
{
  struct message *m;

  for (;;) {
    for (m = s2tester->received; m; m = m->next) {
      if (m->sip->sip_request) {
	if (method == sip_method_unknown && name == NULL)
	  return s2_remove_message(m);

	if (m->sip->sip_request->rq_method == method &&
	    strcmp(m->sip->sip_request->rq_method_name, name) == 0)
	  return s2_remove_message(m);
      }
    }

    su_root_step(s2tester->root, 100);
  }
  
  return NULL;
} 

int
s2_check_request(sip_method_t method, char const *name)
{
  struct message *m = s2_wait_for_request(method, name);
  s2_free_message(m);
  return m != NULL;
}

struct message *
s2_respond_to(struct message *m, struct dialog *d,
	      int status, char const *phrase,
	      tag_type_t tag, tag_value_t value, ...)
{
  struct tester *t = s2tester;
  ta_list ta;
  msg_t *reply;
  sip_t *sip;
  su_home_t *home;
  tp_name_t tpn[1];
  char *rport;

  assert(m); assert(m->msg); assert(m->tport);
  assert(100 <= status && status < 700);

  ta_start(ta, tag, value);

  reply = s2_msg(0); sip = sip_object(reply); home = msg_home(reply);

  assert(reply && home && sip);

  if (sip_add_tl(reply, sip, ta_tags(ta)) < 0) {
    abort();
  }

  s2_complete_response(reply, status, phrase, m->msg);

  if (sip->sip_status && sip->sip_status->st_status > 100 &&
      sip->sip_to && !sip->sip_to->a_tag &&
      sip->sip_cseq && sip->sip_cseq->cs_method != sip_method_cancel) {
    char const *ltag = NULL;

    if (d && d->local)
      ltag = d->local->a_tag;

    if (ltag == NULL)
      ltag = s2_generate_tag(home);

    if (sip_to_tag(msg_home(reply), sip->sip_to, ltag) < 0) {
      assert(!"add To tag");
    }
  }

  if (d && !d->local) {
    d->local = sip_from_dup(d->home, sip->sip_to);
    d->remote = sip_to_dup(d->home, sip->sip_from);
    d->call_id = sip_call_id_dup(d->home, sip->sip_call_id);
    d->rseq = sip->sip_cseq->cs_seq;
    /* d->route = sip_route_dup(d->home, sip->sip_record_route); */
    d->target = sip_contact_dup(d->home, m->sip->sip_contact);
    d->contact = sip_contact_dup(d->home, sip->sip_contact);
  }

  *tpn = *tport_name(m->tport);

  rport = su_sprintf(home, "rport=%u", 
		     ntohs(((su_sockaddr_t *)
			    msg_addrinfo(m->msg)->ai_addr)->su_port));

  if (sip->sip_via->v_rport && t->server_uses_rport) {
    msg_header_add_param(home, sip->sip_via->v_common, rport);
  }    

  tpn->tpn_port = rport + strlen("rport=");

  tport_tsend(m->tport, reply, tpn, TPTAG_MTU(INT_MAX), ta_tags(ta));
  msg_destroy(reply);

  ta_end(ta);

  return m;
}

/** Add headers from the request to the response message. */
static int 
s2_complete_response(msg_t *response, 
		     int status, char const *phrase, 
		     msg_t *request)
{
  su_home_t *home = msg_home(response);
  sip_t *response_sip = sip_object(response);
  sip_t const *request_sip = sip_object(request);

  int incomplete = 0;

  if (!response_sip || !request_sip || !request_sip->sip_request)
    return -1;

  if (!response_sip->sip_status)
    response_sip->sip_status = sip_status_create(home, status, phrase, NULL);
  if (!response_sip->sip_via)
    response_sip->sip_via = sip_via_dup(home, request_sip->sip_via);
  if (!response_sip->sip_from)
    response_sip->sip_from = sip_from_dup(home, request_sip->sip_from);
  if (!response_sip->sip_to)
    response_sip->sip_to = sip_to_dup(home, request_sip->sip_to);
  if (!response_sip->sip_call_id)
    response_sip->sip_call_id = 
      sip_call_id_dup(home, request_sip->sip_call_id);
  if (!response_sip->sip_cseq)
    response_sip->sip_cseq = sip_cseq_dup(home, request_sip->sip_cseq);

  if (!response_sip->sip_record_route && request_sip->sip_record_route)
    sip_add_dup(response, response_sip, (void*)request_sip->sip_record_route);

  incomplete = sip_complete_message(response) < 0;

  msg_serialize(response, (msg_pub_t *)response_sip);

  if (incomplete ||
      !response_sip->sip_status ||
      !response_sip->sip_via ||
      !response_sip->sip_from ||
      !response_sip->sip_to ||
      !response_sip->sip_call_id ||
      !response_sip->sip_cseq ||
      !response_sip->sip_content_length ||
      !response_sip->sip_separator ||
      (request_sip->sip_record_route && !response_sip->sip_record_route))
    return -1;

  return 0;
}

/* Send request (updating dialog). 
 *
 * Return zero upon success, nonzero upon failure.
 */
int 
s2_request_to(struct dialog *d,
	      sip_method_t method, char const *name,
	      tport_t *tport,
	      tag_type_t tag, tag_value_t value, ...)
{
  struct tester *t = s2tester;

  ta_list ta;
  tagi_t const *tags;

  msg_t *msg = s2_msg(0);
  sip_t *sip = sip_object(msg);
  url_string_t *target = NULL;
  sip_cseq_t cseq[1];
  sip_via_t via[1]; char const *v_params[8];
  sip_content_length_t l[1];
  tp_name_t tpn[1];
  tp_magic_t *magic;

  ta_start(ta, tag, value);
  tags = ta_args(ta);

  if (sip_add_tagis(msg, sip, &tags) < 0)
    goto error;

  if (!sip->sip_request) {
    sip_request_t *rq;

    if (d->target)
      target = (url_string_t *)d->target->m_url;
    else if (t->registration->contact)
      target = (url_string_t *)t->registration->contact->m_url;
    else
      target = NULL;

    if (target == NULL)
      goto error;

    rq = sip_request_create(msg_home(msg), method, name, target, NULL);
    sip_header_insert(msg, sip, (sip_header_t *)rq);
  }

  if (!d->local && sip->sip_from)
    d->local = sip_from_dup(d->home, sip->sip_from);
  if (!d->contact && sip->sip_contact) 
    d->contact = sip_contact_dup(d->home, sip->sip_contact);
  if (!d->remote && sip->sip_to)
    d->remote = sip_to_dup(d->home, sip->sip_to);
  if (!d->target && sip->sip_request)
    d->target = sip_contact_create(d->home,
				   (url_string_t *)sip->sip_request->rq_url,
				   NULL);
  if (!d->call_id && sip->sip_call_id)
    d->call_id = sip_call_id_dup(d->home, sip->sip_call_id);
  if (!d->lseq && sip->sip_cseq)
    d->lseq = sip->sip_cseq->cs_seq;
  
  if (!d->local)
    d->local = sip_from_dup(d->home, t->local);
  if (!d->contact)
    d->contact = sip_contact_dup(d->home, t->contact);
  if (!d->remote)
    d->remote = sip_to_dup(d->home, t->registration->aor);
  if (!d->call_id)
    d->call_id = sip_call_id_create(d->home, NULL);
  assert(d->local && d->contact);
  assert(d->remote && d->target);
  assert(d->call_id);

  if (tport == NULL)
    tport = d->tport;

  if (tport == NULL)
    tport = t->registration->tport;

  if (tport == NULL && d->target->m_url->url_type == url_sips)
    tport = t->tls.tport;

  if (tport == NULL)
    tport = t->udp.tport;
  else if (tport == NULL)
    tport = t->tcp.tport;
  else if (tport == NULL)
    tport = t->tls.tport;

  assert(tport);

  *tpn = *tport_name(tport);
  tpn->tpn_host = d->target->m_url->url_host;
  tpn->tpn_port = d->target->m_url->url_port;

  magic = tport_magic(tport);
  assert(magic != NULL);

  sip_cseq_init(cseq);
  cseq->cs_method = method;
  cseq->cs_method_name = name;
  
  if (d->invite && (method == sip_method_ack || method == sip_method_cancel)) {
    cseq->cs_seq = sip_object(d->invite)->sip_cseq->cs_seq;
  }
  else {
    cseq->cs_seq = ++d->lseq;
  }

  if (d->invite && method == sip_method_cancel) {
    *via = *sip_object(d->invite)->sip_via;
  }
  else {
    *via = *magic->via;
    via->v_params = v_params;
    v_params[0] = su_sprintf(msg_home(msg), "branch=z9hG4bK%lx", ++t->tid);
    v_params[1] = NULL;
  }

  sip_content_length_init(l);
  if (sip->sip_payload)
    l->l_length = sip->sip_payload->pl_len;

  sip_add_tl(msg, sip, 
	     TAG_IF(!sip->sip_from, SIPTAG_FROM(d->local)),
	     TAG_IF(!sip->sip_contact, SIPTAG_CONTACT(d->contact)),
	     TAG_IF(!sip->sip_to, SIPTAG_TO(d->remote)),
	     TAG_IF(!sip->sip_call_id, SIPTAG_CALL_ID(d->call_id)),
	     TAG_IF(!sip->sip_cseq, SIPTAG_CSEQ(cseq)),
	     SIPTAG_VIA(via),
	     TAG_IF(!sip->sip_content_length, SIPTAG_CONTENT_LENGTH(l)),
	     TAG_IF(!sip->sip_separator, SIPTAG_SEPARATOR_STR("\r\n")),
	     TAG_END());

  msg_serialize(msg, NULL);

  if (method == sip_method_invite) {
    msg_destroy(d->invite);
    d->invite = msg_ref_create(msg);
  }

  tport = tport_tsend(tport, msg, tpn, ta_tags(ta));
  ta_end(ta);

  if (d->tport != tport) {
    tport_unref(d->tport);
    d->tport = tport_ref(tport);
  }

  return tport ? 0 : -1;
  
 error:
  ta_end(ta);
  return -1;
}

/** Save information from response.
 *
 * Send ACK for error messages to INVITE.
 */
int s2_update_dialog(struct dialog *d, struct message *m)
{
  int status = 0;

  if (m->sip->sip_status)
    status = m->sip->sip_status->st_status;

  if (100 < status && status < 300) {
    d->remote = sip_to_dup(d->home, m->sip->sip_to);
    if (m->sip->sip_contact)
      d->contact = sip_contact_dup(d->home, m->sip->sip_contact);
  }

  if (300 <= status && m->sip->sip_cseq &&
      m->sip->sip_cseq->cs_method == sip_method_invite &&
      d->invite) {
    msg_t *ack = s2_msg(0);
    sip_t *sip = sip_object(ack);
    sip_t *invite = sip_object(d->invite);
    sip_request_t rq[1];
    sip_cseq_t cseq[1];
    tp_name_t tpn[1];

    *rq = *invite->sip_request;
    rq->rq_method = sip_method_ack, rq->rq_method_name = "ACK";
    *cseq = *invite->sip_cseq;
    cseq->cs_method = sip_method_ack, cseq->cs_method_name = "ACK";

    sip_add_tl(ack, sip,
	       SIPTAG_REQUEST(rq),
	       SIPTAG_VIA(invite->sip_via),
	       SIPTAG_FROM(invite->sip_from),
	       SIPTAG_TO(invite->sip_to),
	       SIPTAG_CALL_ID(invite->sip_call_id),
	       SIPTAG_CSEQ(cseq),
	       SIPTAG_CONTENT_LENGTH_STR("0"),
	       SIPTAG_SEPARATOR_STR("\r\n"),
	       TAG_END());

    *tpn = *tport_name(d->tport);
    if (!tport_is_secondary(d->tport) ||
	!tport_is_clear_to_send(d->tport)) {
      tpn->tpn_host = rq->rq_url->url_host;
      tpn->tpn_port = rq->rq_url->url_port;
    }

    msg_serialize(ack, NULL);
    tport_tsend(d->tport, ack, tpn, TAG_END());
  }

  return 0;
}

/* ---------------------------------------------------------------------- */

int
s2_save_register(struct message *rm)
{
  struct tester *t = s2tester;
  sip_contact_t *contact, *m, **m_prev;
  sip_expires_t const *ex;
  sip_date_t const *date;
  sip_time_t now = rm->when.tv_sec, expires;

  msg_header_free_all(t->home, (msg_header_t *)t->registration->aor);
  msg_header_free_all(t->home, (msg_header_t *)t->registration->contact);
  tport_unref(t->registration->tport);

  memset(t->registration, 0, sizeof *t->registration);

  if (rm == NULL)
    return 0;

  assert(rm && rm->sip && rm->sip->sip_request);
  assert(rm->sip->sip_request->rq_method == sip_method_register);

  ex = rm->sip->sip_expires;
  date = rm->sip->sip_date;

  contact = sip_contact_dup(t->home, rm->sip->sip_contact);

  for (m_prev = &contact; *m_prev;) {
    m = *m_prev;

    expires = sip_contact_expires(m, ex, date,
				  default_registration_duration,
				  now);
    if (expires) {
      char *p = su_sprintf(t->home, "expires=%lu", (unsigned long)expires);
      msg_header_add_param(t->home, m->m_common, p);
      m_prev = &m->m_next;
    }
    else {
      *m_prev = m->m_next;
      m->m_next = NULL;
      msg_header_free(t->home, (msg_header_t *)m);
    }
  }

  if (contact == NULL)
    return 0;

  t->registration->aor = sip_to_dup(t->home, rm->sip->sip_to);
  t->registration->contact = contact;
  t->registration->tport = tport_ref(rm->tport);

  return 0;
}

/* ---------------------------------------------------------------------- */

static char *
s2_generate_tag(su_home_t *home)
{
  s2_tag_generator += 1;

  return su_sprintf(home, "tag=N2-%s/%u", _s2case, s2_tag_generator);
}

void s2_case(char const *number,
	     char const *title,
	     char const *desciption)
{
  _s2case = number;
}


/* ---------------------------------------------------------------------- */
/* tport interface */
static void 
s2_stack_recv(struct tester *t,
	      tport_t *tp,
	      msg_t *msg,
	      tp_magic_t *magic,
	      su_time_t now)
{
  struct message *next = calloc(1, sizeof *next), **prev;

  next->msg = msg;
  next->sip = sip_object(msg);
  next->when = now;
  next->tport = tport_ref(tp);

#if 0
  if (next->sip->sip_request)
    printf("nua sent: %s\n", next->sip->sip_request->rq_method_name);
  else
    printf("nua sent: SIP/2.0 %u %s\n",
	   next->sip->sip_status->st_status,
	   next->sip->sip_status->st_phrase);
#endif

  for (prev = &t->received; *prev; prev = &(*prev)->next)
    ;

  next->prev = prev, *prev = next;
}

static void
s2_stack_error(struct tester *t,
	       tport_t *tp,
	       int errcode,
	       char const *remote)
{
  fprintf(stderr, "%s(%p): error %d (%s) from %s\n", 
	  "nua_tester_error",
	  (void *)tp, errcode, su_strerror(errcode), 
	  remote ? remote : "<unknown destination>");
}

static msg_t *
s2_stack_alloc(struct tester *t, int flags,
	       char const data[], usize_t size,
	       tport_t const *tport, 
	       tp_client_t *tpc)
{
  return msg_create(t->mclass, flags | t->flags);
}

static msg_t *
s2_msg(int flags)
{
  struct tester *t = s2tester;
  return msg_create(t->mclass, flags | t->flags);
}

tp_stack_class_t const s2_stack[1] =
  {{
      /* tpac_size */ (sizeof s2_stack),
      /* tpac_recv */  s2_stack_recv,
      /* tpac_error */ s2_stack_error,
      /* tpac_alloc */ s2_stack_alloc,
  }};

struct tester *s2tester = NULL;

/** Basic setup for test cases */
void
s2_setup(char const *hostname)
{
  struct tester *t;

  assert(s2tester == NULL);

  su_init();

  s2tester = t = su_home_new(sizeof *s2tester);

  assert(s2tester != NULL);

  t->root = su_root_create(s2tester);

  assert(t->root != NULL);

  su_root_threading(t->root, 0);	/* disable multithreading */

  t->local = sip_from_format(t->home, "Bob <sip:bob@%s>",
			     hostname ? hostname : "example.net");
  
  if (hostname == NULL)
    hostname = "127.0.0.1";

  t->hostname = hostname;
  t->tid = (unsigned long)time(NULL) * 510633671UL;
}

SOFIAPUBVAR su_log_t nua_log[];
SOFIAPUBVAR su_log_t soa_log[];
SOFIAPUBVAR su_log_t nea_log[];
SOFIAPUBVAR su_log_t nta_log[];
SOFIAPUBVAR su_log_t tport_log[];
SOFIAPUBVAR su_log_t su_log_default[];

void
s2_setup_logs(int level)
{
  assert(s2tester);

  su_log_soft_set_level(nua_log, level);
  su_log_soft_set_level(soa_log, level);
  su_log_soft_set_level(su_log_default, level);
  su_log_soft_set_level(nea_log, level);
  su_log_soft_set_level(nta_log, level);
  su_log_soft_set_level(tport_log, level);
}

static char const * default_protocols[] = { "udp", "tcp", NULL };

void
s2_setup_tport(char const * const *protocols,
	       tag_type_t tag, tag_value_t value, ...)
{
  struct tester *t = s2tester;
  ta_list ta;
  tp_name_t tpn[1];
  int bound;
  tport_t *tp;

  assert(s2tester != NULL);

  ta_start(ta, tag, value);

  if (t->master == NULL) {
    t->master = tport_tcreate(t, s2_stack, t->root, ta_tags(ta));

    if (t->master == NULL) {
      assert(t->master);
    }
    t->mclass = sip_default_mclass();
    t->flags = 0;
  }

  memset(tpn, 0, (sizeof tpn));
  tpn->tpn_proto = "*";
  tpn->tpn_host = t->hostname;
  tpn->tpn_port = "*";

  if (protocols == NULL)
    protocols = default_protocols;
  
  bound = tport_tbind(t->master, tpn, protocols, 
		      TPTAG_SERVER(1),
		      ta_tags(ta));
  assert(bound != -1);

  tp = tport_primaries(t->master);

  if (protocols == default_protocols && t->contact == NULL) {
    *tpn = *tport_name(tp);
    t->contact = sip_contact_format(t->home, "<sip:%s:%s>",
				    tpn->tpn_host,
				    tpn->tpn_port);
  }

  for (;tp; tp = tport_next(tp)) {
    sip_via_t *v;
    sip_contact_t *m;
    tp_magic_t *magic;

    if (tport_magic(tp))
      continue;

    *tpn = *tport_name(tp);

    v = sip_via_format(t->home, "SIP/2.0/%s %s:%s",
		       tpn->tpn_proto,
		       tpn->tpn_host, 
		       tpn->tpn_port);
    assert(v != NULL);
    if (strncasecmp(tpn->tpn_proto, "tls", 3)) {
      m = sip_contact_format(t->home, "<sip:%s:%s;transport=%s>",
			     tpn->tpn_host,
			     tpn->tpn_port,
			     tpn->tpn_proto);
      if (t->udp.contact == NULL && strcasecmp(tpn->tpn_proto, "udp") == 0) {
	t->udp.tport = tport_ref(tp); 
	t->udp.contact = m;
      }
      if (t->tcp.contact == NULL && strcasecmp(tpn->tpn_proto, "tcp") == 0) {
	t->tcp.tport = tport_ref(tp); 
	t->tcp.contact = m;
      }
    }
    else if (strcasecmp(tpn->tpn_proto, "tls")) {
      m = sip_contact_format(t->home, "<sips:%s:%s;transport=%s>",
			     tpn->tpn_host,
			     tpn->tpn_port,
			     tpn->tpn_proto);
    }
    else {
      m = sip_contact_format(t->home, "<sips:%s:%s>",
			     tpn->tpn_host,
			     tpn->tpn_port);
      if (t->tls.contact == NULL) {
	t->tls.tport = tport_ref(tp); 
	t->tls.contact = m;
      }
    }
    assert(m != NULL);

    magic = su_zalloc(t->home, (sizeof *magic));
    magic->via = v, magic->contact = m;

    if (t->contact == NULL)
      t->contact = m;

    tport_set_magic(tp, magic);
  }
}

void
s2_setup_nua(tag_type_t tag, tag_value_t value, ...)
{
  struct tester *t = s2tester;
  ta_list ta;

  assert(s2tester);
  assert(t->nua == NULL);

  ta_start(ta, tag, value);

  t->nua = nua_create(t->root,
		      s2_nua_callback,
		      t,
		      ta_tags(ta));

  ta_end(ta);
}

void
s2_teardown(void)
{
  su_deinit();
}
