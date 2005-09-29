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

/**@NUA
 * 
 * @cfile nua_cli.c  Test application for Sofia-SIP User Agent Library 
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Feb 14 18:37:04 EET 2001 ppessi
 * $Date: 2005/09/28 20:05:24 $
 */

#include "config.h"

const char _nua_cli_c_id[] =
"$Id: nua_cli.c,v 1.5 2005/09/28 20:05:24 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

typedef struct cli_s cli_t;
typedef struct cli_oper_s cli_oper_t;

#define SU_ROOT_MAGIC_T cli_t
#define NUA_MAGIC_T     cli_t
#define NUA_IMAGIC_T    cli_oper_t
#define NUA_HMAGIC_T    cli_oper_t

#include <sip.h>
#include <sip_header.h>
#include <sip_status.h>

#include "nua.h"
#include "nua_tag.h"
#include <su_tag_io.h>
#include <su_tagarg.h>
#include <sl_utils.h>

#include <soa.h>

#include <su_debug.h>

#ifdef WIN32
#include <conio.h>
#endif

#if HAVE_FUNC
#define enter (void)SU_DEBUG_9(("%s: entering\n", __func__))
#elif HAVE_FUNCTION
#define enter (void)SU_DEBUG_9(("%s: entering\n", __FUNCTION__))
#else
#define enter (void)0
#endif

struct cli_oper_s {
  cli_oper_t   *op_next;
  cli_t        *op_cli;		/**< Backpointer */

  /**< Remote end identity
   *
   * Contents of To: when initiating, From: when receiving.
   */
  char const   *op_ident;	

  /** NUA handle */ 
  nua_handle_t *op_handle;

  /** How this handle was used initially */
  sip_method_t  op_method;	/* REGISTER, INVITE, MESSAGE, or SUBSCRIBE */
  char const   *op_method_name;

  /** Call state. 
   *
   * - opc_sent when initial INVITE has been sent
   * - opc_recv when initial INVITE has been received
   * - opc_complate when 200 Ok has been sent/received
   * - opc_active when media is used
   * - opc_sent when re-INVITE has been sent
   * - opc_recv when re-INVITE has been received
   */
  enum { 
    opc_none, 
    opc_sent = 1, 
    opc_recv = 2, 
    opc_complete = 3, 
    opc_active = 4,
    opc_sent2 = 5,
    opc_recv2 = 6
  } op_callstate;

  unsigned      op_authstate : 1; /**< Does this handle need authentication  */
  unsigned      op_persistent : 1; /**< Is this handle persistent? */
  unsigned      op_referred : 1;
  unsigned :0;
};

#ifdef WIN32
typedef su_timer_t *cli_input_t;
static int handle_input(cli_t *cli, su_timer_t *t, void *arg);
#else
static int handle_input(cli_t *cli, su_wait_t *w, void *p);
typedef su_wait_t   cli_input_t;
#endif

struct cli_s {
  su_home_t     cli_home[1];	/**< Our memory home */
  char const   *cli_name;	/**< Our name */
  su_root_t    *cli_root;        /**< Pointer to application root */

  cli_input_t   cli_input;	/**< Input structure */
  unsigned      cli_init : 1;	/**< True if input is initialized */

  unsigned      cli_prompt : 1;	/**< True if showing prompt */
  unsigned      cli_debug : 1;	/**< True if debugging is on */
  
  char const   *cli_contact;	/**< Argument contact */

  char const   *cli_media;	/**< Media address */
  nua_t        *cli_nua;        /**< Pointer to NUA object */

  soa_session_t *cli_soa;	/**< SOA object */

  char const   *cli_address;	/**< Our SIP address */

  cli_oper_t   *cli_operations;	/**< Remote destinations */
};


int cli_init(cli_t *cli, char *av[]);
void cli_deinit(cli_t *cli);
void cli_callback(nua_event_t event,
		  int status, char const *phrase,
		  nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[]);
void cli_i_error(nua_t *nua, cli_t *cli, nua_handle_t *nh, cli_oper_t *op,
		 int status, char const *phrase,
		 tagi_t tags[]);
void cli_i_media_error(nua_t *nua, cli_t *cli, nua_handle_t *nh, cli_oper_t *op,
		       int status, char const *phrase,
		       tagi_t tags[]);

void cli_shutdown(cli_t *cli);
void cli_r_shutdown(int status, char const *phrase, 
		    nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[]);

void cli_param(cli_t *cli, char *param, char *rest);
void cli_r_get_params(int status, char const *phrase,
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[]);

void cli_list(cli_t *cli);

void cli_register(cli_t *cli, char *registrar);
void cli_r_register(int status, char const *phrase,
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[]);

void cli_unregister(cli_t *cli, char *registrar);
void cli_r_unregister(int status, char const *phrase,
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[]);

void cli_publish(cli_t *cli, char *note);
void cli_unpublish(cli_t *cli);
void cli_r_publish(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);

void cli_invite(cli_t *cli, char *destination);
void cli_r_invite(int status, char const *phrase,
		  nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[]);
void cli_i_fork(int status, char const *phrase,
		nua_t *nua, cli_t *cli,
		nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		tagi_t tags[]);

void cli_i_invite(nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[]);

void cli_answer(cli_t *cli, int status, char const *phrase);

void cli_i_active(nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[]);
void cli_i_terminated(int status, char const *phrase, 
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[]);

void cli_i_prack(nua_t *nua, cli_t *cli,
		 nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		 tagi_t tags[]);

void cli_bye(cli_t *cli);
void cli_r_bye(int status, char const *phrase, 
	       nua_t *nua, cli_t *cli,
	       nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
	       tagi_t tags[]);
void cli_i_bye(nua_t *nua, cli_t *cli,
		 nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		 tagi_t tags[]);
void cli_i_cancel(nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[]);

void cli_message(cli_t *cli, char *destination);
void cli_r_message(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);
void cli_i_message(nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);

void cli_info(cli_t *cli, char *destination);
void cli_r_info(int status, char const *phrase,
		nua_t *nua, cli_t *cli,
		nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		tagi_t tags[]);
void cli_i_info(nua_t *nua, cli_t *cli,
		nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		tagi_t tags[]);

void cli_refer(cli_t *cli, char *destination);
void cli_r_refer(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);
void cli_i_refer(nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);

void cli_subscribe(cli_t *cli, char *destination);
void cli_r_subscribe(int status, char const *phrase,
		     nua_t *nua, cli_t *cli,
		     nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		     tagi_t tags[]);
void cli_unsubscribe(cli_t *cli, char *destination);
void cli_r_unsubscribe(int status, char const *phrase,
		       nua_t *nua, cli_t *cli,
		       nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		       tagi_t tags[]);

void cli_r_notify(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);
void cli_i_notify(nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[]);

void cli_options(cli_t *cli, char *destination);
void cli_r_options(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[]);

void cli_cancel(cli_t *cli);
void cli_zap(cli_t *cli, char *d);

void cli_media_event(cli_t *cli, char *rest);
void cli_r_media_event(int status, char const *phrase,
		       nua_t *nua, cli_t *cli,
		       nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		       tagi_t tags[]);

void cli_prompt(cli_t *cli);
void cli_prompt2(cli_t *cli, char const *p2);
void cli_print_payload(cli_t *cli, sip_payload_t const *pl);

/** Print usage message */
void usage(char const *a0)
{
  fprintf(stderr, "usage: %s url\n", a0);
  exit(1);
}

int main(int ac, char *av[])
{
  cli_t cli[1] = {{{{sizeof(cli)}}}};
  
  su_init();

  su_home_init(cli->cli_home);

  if ((cli->cli_root = su_root_create(cli))) {
    if (cli_init(cli, av) != -1) {

      if ((cli->cli_nua = 
	   nua_create(cli->cli_root, 
		      cli_callback, cli,
		      NUTAG_URL(cli->cli_contact),
		      NUTAG_MEDIA_ADDRESS(cli->cli_media),
		      NUTAG_SOA_NAME("default"),
		      /* Used in OPTIONS */
		      SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 8 0"),
		      TAG_NULL()))) {
	int min_se = 0;
	int s_e = 0;

	if (getenv("MIN_SE")) min_se = atoi(getenv("MIN_SE"));
	if (getenv("SESSION_EXPIRES")) s_e = atoi(getenv("SESSION_EXPIRES"));

	nua_set_params(cli->cli_nua,
		       NUTAG_PROXY(getenv("sip_proxy")),
		       NUTAG_REGISTRAR(getenv("SIPHOME")),
		       NUTAG_ENABLEMESSAGE(1),
		       NUTAG_ENABLEINVITE(1),
		       NUTAG_AUTOALERT(1),
		       NUTAG_SESSION_TIMER(s_e),
		       NUTAG_MIN_SE(min_se),
		       SIPTAG_FROM_STR(getenv("SIPADDRESS")),
#if HAVE_SOFIA_MSS
		       NUTAG_MEDIA_PATH(getenv("MSS_PATH")),
#endif
		       NUTAG_CERTIFICATE_DIR(getenv("SIPCERTDIR")),
		       TAG_NULL());
	nua_get_params(cli->cli_nua, TAG_ANY(), TAG_NULL());
	su_root_run(cli->cli_root);
	nua_destroy(cli->cli_nua);
      }
      cli_deinit(cli);
    }
    su_root_destroy(cli->cli_root), cli->cli_root = NULL;
  }

  su_home_deinit(cli->cli_home);

  su_deinit();

  return 0;
}


void cli_callback(nua_event_t event,
		  int status, char const *phrase,
		  nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[])
{
  assert(cli);

  switch (event) {
  case nua_r_shutdown:    
    cli_r_shutdown(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_r_get_params:    
    cli_r_get_params(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_r_register:
    cli_r_register(status, phrase, nua, cli, nh, op, sip, tags);
    return;
    
  case nua_r_unregister:
    cli_r_unregister(status, phrase, nua, cli, nh, op, sip, tags);
    return;
    
  case nua_r_options:
    cli_r_options(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_r_invite:
    cli_r_invite(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_i_fork:
    cli_i_fork(status, phrase, nua, cli, nh, op, sip, tags);
    return;
    
  case nua_i_invite:
    cli_i_invite(nua, cli, nh, op, sip, tags);
    return;

  case nua_i_prack:
    cli_i_prack(nua, cli, nh, op, sip, tags);
    return;

  case nua_i_active:
    cli_i_active(nua, cli, nh, op, sip, tags);
    return;
    
  case nua_i_terminated:
    cli_i_terminated(status, phrase, nua, cli, nh, op, sip, tags);
    return;
    
  case nua_r_bye:
    cli_r_bye(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_i_bye:
    cli_i_bye(nua, cli, nh, op, sip, tags);
    return;

  case nua_r_message:
    cli_r_message(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_i_message:
    cli_i_message(nua, cli, nh, op, sip, tags);
    return;

  case nua_r_info:
    cli_r_info(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_i_info:
    cli_i_info(nua, cli, nh, op, sip, tags);
    return;

  case nua_r_refer:
    cli_r_refer(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_i_refer:
    cli_i_refer(nua, cli, nh, op, sip, tags);
    return;
     
  case nua_r_subscribe:
    cli_r_subscribe(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_r_unsubscribe:
    cli_r_unsubscribe(status, phrase, nua, cli, nh, op, sip, tags);
    return;

  case nua_r_publish:
    cli_r_publish(status, phrase, nua, cli, nh, op, sip, tags);
    return;
    
  case nua_r_notify:
    cli_r_notify(status, phrase, nua, cli, nh, op, sip, tags);
    return;
     
  case nua_i_notify:
    cli_i_notify(nua, cli, nh, op, sip, tags);
    return;

  case nua_i_cancel:
    cli_i_cancel(nua, cli, nh, op, sip, tags);
    return;

  default:
    break;
  }

  if (status > 100)
    printf("%s: unknown event %d: %03d %s\n", 
	   cli->cli_name, event, status, phrase);
  else
    printf("%s: unknown event %d\n", cli->cli_name, event);

  tl_print(stdout, "", tags);
  cli_prompt(cli);
}

/* ====================================================================== */
static inline
void oper_assign(cli_oper_t *op, sip_method_t method, char const *name);

void cli_oper_destroy(cli_t *cli, cli_oper_t *op);

cli_oper_t *cli_oper_create(cli_t *cli, 
			    sip_method_t method,
			    char const *name,
			    char *address,
			    tag_type_t tag, tag_value_t value, ...)
{
  cli_oper_t *op, *old;

  ta_list ta;
   
  enter;

  for (old = cli->cli_operations; old; old = old->op_next)
    if (!old->op_persistent)
      break;

  if (address) {
    int have_url = 1;
    sip_to_t *to;

    to = sip_to_make(cli->cli_home, address);

    if (to == NULL) {
      printf("%s: %s: invalid address: %s\n", cli->cli_name, name, address);
      return NULL;
    }

    /* Try to make sense out of the URL */
    if (url_sanitize(to->a_url) < 0) {
      printf("%s: %s: invalid address\n", cli->cli_name, name);
      return NULL;
    }

    if (!(op = su_zalloc(cli->cli_home, sizeof(*op)))) {
      printf("%s: %s: cannot create handle\n", cli->cli_name, name);
      return NULL;
    }

    op->op_cli = cli;
    op->op_next = cli->cli_operations;
    cli->cli_operations = op;      

    if (method == sip_method_register)
      have_url = 0;
    
    ta_start(ta, tag, value); 
     
    op->op_handle = nua_handle(cli->cli_nua, op, 
			       TAG_IF(have_url, NUTAG_URL(to->a_url)), 
			       SIPTAG_TO(to),
			       ta_tags(ta));

    ta_end(ta);  
     
    op->op_ident = sip_header_as_string(cli->cli_home, (sip_header_t *)to);

    oper_assign(op, method, name);
    
    if (!op->op_persistent) {
      cli_oper_t *old_next;
      for (; old; old = old_next) {      /* Clean old handles */
	old_next = old->op_next;
	if (!old->op_persistent && !old->op_callstate)
	  cli_oper_destroy(cli, old);
      }
    }
    
    su_free(cli->cli_home, to);
  }
  else if (method || name) 
    oper_assign(op = old, method, name);
  else
    return old;

  if (!op) {
    if (address)
      printf("%s: %s: invalid destination\n", cli->cli_name, name);
    else
      printf("%s: %s: no destination\n", cli->cli_name, name);
    return NULL;
  }

  return op;
}

cli_oper_t *cli_oper_create2(cli_t *cli, 
			     sip_method_t method,
			     char const *name,
			     nua_handle_t *nh,
			     sip_from_t const *from)
{
  cli_oper_t *op;

  enter;

  if ((op = su_zalloc(cli->cli_home, sizeof(*op)))) {
    op->op_cli = cli;
    op->op_next = cli->cli_operations;
    cli->cli_operations = op;      

    oper_assign(op, method, name);
    nua_handle_bind(op->op_handle = nh, op);
    op->op_ident = sip_header_as_string(cli->cli_home, (sip_header_t*)from);
  }
  else {
    printf("%s: cannot create operation object for %s\n", 
	   cli->cli_name, name);
  }

  return op;
}

/** Delete operation and attached handles and identities */
void cli_oper_destroy(cli_t *cli, cli_oper_t *op)
{
  cli_oper_t **prev;

  if (!op)
    return;

  /* Remove from queue */
  for (prev = &cli->cli_operations; 
       *prev && *prev != op; 
       prev = &(*prev)->op_next)
    ;
  if (*prev)
    *prev = op->op_next, op->op_next = NULL;

  if (op->op_handle)
    nua_handle_destroy(op->op_handle), op->op_handle = NULL;

  su_free(cli->cli_home, op);
}

/* ====================================================================== */
void oper_assign(cli_oper_t *op, sip_method_t method, char const *name)
{
  if (!op)
    return;

  op->op_method = method, op->op_method_name = name;

  op->op_persistent = 
    method == sip_method_subscribe ||
    method == sip_method_register ||
    method == sip_method_publish;
}

/** Find call operation */
cli_oper_t *oper_find_call(cli_t *cli)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_callstate)
      break;

  return op;
}

/** Find call operation */
cli_oper_t *oper_find_call_in_progress(cli_t *cli)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_callstate & opc_sent) /* opc_sent bit is on? */
      break;

  return op;
}

cli_oper_t *oper_find_call_embryonic(cli_t *cli)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_callstate == 0 && op->op_method == sip_method_invite)
      break;

  return op;
}
  
/** Find unanswered call */
cli_oper_t *oper_find_unanswered(cli_t *cli)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_callstate == opc_recv)
      break;

  return op;
}

/** Find unauthenticated operation */
cli_oper_t *oper_find_unauth(cli_t *cli)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_authstate)
      break;

  return op;
}

/** Find operation by method */
cli_oper_t *oper_find_by_method(cli_t *cli, sip_method_t method)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_method == method && op->op_persistent)
      break;

  return op;
}

/** Find register operation */
cli_oper_t *oper_find_register(cli_t *cli)
{
  cli_oper_t *op;

  for (op = cli->cli_operations; op; op = op->op_next)
    if (op->op_method == sip_method_register && op->op_persistent)
      break;

  return op;
}

/** Set operation to be authenticated */
void oper_set_auth(cli_t *cli, cli_oper_t *op, sip_t const *sip, tagi_t *tags)
{
  sip_www_authenticate_t const *wa = sip->sip_www_authenticate;
  sip_proxy_authenticate_t const *pa = sip->sip_proxy_authenticate;

  enter;

  tl_gets(tags, 
	  SIPTAG_WWW_AUTHENTICATE_REF(wa),
	  SIPTAG_PROXY_AUTHENTICATE_REF(pa),
	  TAG_NULL());

  printf("%s: %s was unauthorized\n", cli->cli_name, op->op_method_name);
  if (wa) sl_header_print(stdout, "Server auth: %s\n", (sip_header_t *)wa);
  if (pa) sl_header_print(stdout, "Proxy auth: %s\n", (sip_header_t *)pa);
  
  op->op_authstate = 1;
  printf("%s: authenticate %s operation by command\n"
	 "%s> k scheme:\"realm\":user:pass\n",
	 cli->cli_name, op->op_method_name, cli->cli_name);
}

/** Authenticate operation. */
void cli_auth(cli_t *cli, char *data)
{
  cli_oper_t *op;

  if (!data || !(strchr(data, ':'))) {
    printf("%s: usage: k Basic:\"realm\":user:password\n", cli->cli_name);
  }
  else if ((op = oper_find_unauth(cli))) {
    nua_authenticate(op->op_handle, NUTAG_AUTH(data), TAG_END());
    op->op_authstate = 0;
    return;
  }
  else
    printf("%s: No operation to authenticate\n", cli->cli_name);

  cli_prompt(cli);
}


void cli_i_error(nua_t *nua, cli_t *cli, nua_handle_t *nh, cli_oper_t *op, 
		 int status, char const *phrase,
		 tagi_t tags[])
{
  printf("%s: error %03d %s\n", cli->cli_name, status, phrase);
}

void cli_i_media_error(nua_t *nua, cli_t *cli, nua_handle_t *nh, cli_oper_t *op,
		       int status, char const *phrase,
		       tagi_t tags[])
{
  printf("%s: media error %03d %s\n", cli->cli_name, status, phrase);
}



void cli_param(cli_t *cli, char *param, char *s)
{
  tag_type_t tag = NULL, *list;
  tag_value_t value = 0;
  char *ns = NULL, *sep;
  su_home_t home[1] = { SU_HOME_INIT(home) };
  int scanned;

  enter;

  if ((sep = strstr(param, "::"))) {
    ns = param, *sep = '\0', param = sep + 2;
  } else if ((sep = strstr(param, "."))) {
    ns = param, *sep = '\0', param = sep + 1;
  } else if ((sep = strstr(param, ":"))) {
    ns = param, *sep = '\0', param = sep + 1;
  }

  if (!ns || strcmp(ns, "nua") == 0)
      for (list = nua_tag_list; (tag = *list); list++) {
	if (strcmp(tag->tt_name, param) == 0) {
	  ns = "found";
	  break;
	}
      }
  if (!ns || strcmp(ns, "nta") == 0) 
      for (list = nta_tag_list; (tag = *list); list++) {
	if (strcmp(tag->tt_name, param) == 0) {
	  ns = "found";
	  break;
	}
      }
  if (!ns || strcmp(ns, "sip") == 0) 
      for (list = sip_tag_list; (tag = *list); list++) {
	if (strcmp(tag->tt_name, param) == 0) {
	  ns = "found";
	  break;
	}
      }


  if (!tag) {
    printf("%s: unknown parameter %s::%s\n", cli->cli_name, 
	   ns ? ns : "", param);
    cli_prompt(cli);
    return;
  }

  scanned = t_scan(tag, home, s, &value);
  if (scanned <= 0) {
    printf("%s: invalid value for %s::%s\n", cli->cli_name, 
	   ns ? ns : "", param);
    cli_prompt(cli);
    return;
  }

  nua_set_params(cli->cli_nua, tag, value, TAG_NULL());
  nua_get_params(cli->cli_nua, tag, (tag_value_t)0, TAG_NULL());

  su_home_deinit(home);
}

void cli_r_get_params(int status, char const *phrase, 
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[])
{
  sip_from_t const *from = NULL;

  printf("%s: nua_r_getparams: %03d %s\n", cli->cli_name, status, phrase);
  tl_print(stdout, "", tags);

  tl_gets(tags, SIPTAG_FROM_REF(from), TAG_END());

  if (from) {
    char const *new_address = 
      sip_header_as_string(cli->cli_home, (sip_header_t *)from);
    if (new_address) {
      su_free(cli->cli_home, (char *)cli->cli_address);
      cli->cli_address = new_address;
    }      
  }

  cli_prompt(cli);
}

/** List active calls */
void cli_list(cli_t *cli)
{
  cli_oper_t *op;

  printf("%s: listing active handles\n", cli->cli_name);
  for (op = cli->cli_operations; op; op = op->op_next) {
    if (op->op_ident) {
      printf("\t%s to %s\n", 
	     sip_method_name(op->op_method, op->op_method_name), 
	     op->op_ident);
    }
  }

  cli_prompt(cli);
}

void cli_invite(cli_t *cli, char *destination)
{
  cli_oper_t *op;

  op = cli_oper_create(cli, SIP_METHOD_INVITE, destination, TAG_END());

  if (op) {
    nua_invite(op->op_handle,
#if 0
	       SIPTAG_SUBJECT_STR("Call!"),
	       SIPTAG_CALL_INFO_STR("<http://127.1/my_face.jpg>"
				    ";purpose=icon"),
	       NUTAG_MEDIA_ENABLE(0),
#endif
	       TAG_END());

    op->op_callstate |= opc_sent;
    printf("%s: INVITE to %s\n", cli->cli_name, op->op_ident);
  }
  else
    cli_prompt(cli);
}

void cli_r_invite(int status, char const *phrase, 
		    nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[])
{
  printf("%s: INVITE: %03d %s\n", cli->cli_name, status, phrase);

  if (status >= 300) {
    op->op_callstate &= ~opc_sent;
    if (status == 401 || status == 407)
      oper_set_auth(cli, op, sip, tags);
    cli_prompt(cli);
  }
}

void cli_i_fork(int status, char const *phrase,
		nua_t *nua, cli_t *cli,
		nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		tagi_t tags[])
{
  nua_handle_t *nh2 = NULL;

  printf("%s: call fork: %03d %s\n", cli->cli_name, status, phrase);

  /* We just release forked calls. */
  tl_gets(tags, NUTAG_HANDLE_REF(nh2), TAG_END());
  assert(nh2);

  nua_bye(nh2, TAG_END());
  nua_handle_destroy(nh2);
  
  cli_prompt(cli);
}

void cli_i_invite(nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[])
{
  /* Incoming call */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_subject_t const *subject;

  assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  subject = sip->sip_subject;

  assert(from && to);

  if (op) {
    op->op_callstate |= opc_recv;
  }
  else if ((op = cli_oper_create2(cli, SIP_METHOD_INVITE, nh, from))) {
    op->op_callstate = opc_recv;
  }
  else {
    nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    nua_handle_destroy(nh);
  }

  if (op) {
    if (op->op_callstate == opc_recv) {
      printf("%s: incoming call\n\tFrom: %s\n", cli->cli_name, op->op_ident);
      printf("\tTo: %s%s<" URL_PRINT_FORMAT ">\n",
	     to->a_display ? to->a_display : "", 
	     to->a_display ? " " : "",
	     URL_PRINT_ARGS(to->a_url));
      if (subject)
	printf("\tSubject: %s\n", subject->g_value);
      printf("Please Answer(a), decline(d) or Decline(D) the call\n");
    }
    else {
      printf("%s: re-INVITE from: %s\n", cli->cli_name, op->op_ident);
    }
  }

  cli_prompt(cli);
}

/** Answer a call. */
void cli_answer(cli_t *cli, int status, char const *phrase)
{
  cli_oper_t *op;

  if ((op = oper_find_unanswered(cli))) {
    if (status >= 200 && status < 300)
      op->op_callstate |= opc_sent;
    else
      op->op_callstate = opc_none;
    nua_respond(op->op_handle, status, phrase, TAG_END());
  }
  else
    printf("%s: no call to answer\n", cli->cli_name);

  cli_prompt(cli);
}

/** query text-string for call mode */
char const *cli_active(int mode)
{
  switch (mode) {
  case nua_active_inactive: return "inactive";
  case nua_active_sendonly: return "sendonly";
  case nua_active_recvonly: return "recvonly";
  case nua_active_sendrecv: return "sendrecv";
  default:                  return "none";
  }
}


void cli_i_prack(nua_t *nua, cli_t *cli,
		 nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		 tagi_t tags[])
{
  /* Incoming PRACK */
  sip_rack_t const *rack;

  assert(sip);

  rack = sip->sip_rack;

  printf("%s: received PRACK %u\n", cli->cli_name, rack ? rack->ra_response : 0);

  if (op == NULL)
    nua_handle_destroy(nh);
}


void cli_i_active(nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[])
{
  int audio = nua_active_inactive, video = nua_active_inactive, chat = nua_active_inactive;
  
  assert(op);

  tl_gets(tags, 
	  NUTAG_ACTIVE_AUDIO_REF(audio), 
	  NUTAG_ACTIVE_VIDEO_REF(video), 
	  NUTAG_ACTIVE_CHAT_REF(chat), 
	  TAG_END());

  op->op_callstate = opc_active;
  printf("%s: call to %s is active:\n\taudio %s, video %s, chat %s\n", 
	 cli->cli_name, op->op_ident, 
	 cli_active(audio), cli_active(video), cli_active(chat));
  cli_prompt(cli);
}

void cli_i_terminated(int status, char const *phrase, 
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[])
{
  if (op) {
    printf("%s: call to %s terminated\n", cli->cli_name, op->op_ident);
    if (status)
      printf("%s: %u %s\n", cli->cli_name, status, phrase);
    else
      printf("%s: %s\n", cli->cli_name, phrase);
    op->op_callstate = 0;
    cli_oper_destroy(cli, op);
  }

  cli_prompt(cli);
}

void cli_bye(cli_t *cli)
{
  cli_oper_t *op = oper_find_call(cli);

  if (op) {
    printf("%s: BYE to %s\n", cli->cli_name, op->op_ident);
    nua_bye(op->op_handle, TAG_END());
    op->op_callstate = 0;
  }
  else {
    printf("%s: no call to bye\n", cli->cli_name);
    cli_prompt(cli);
  }
}

void cli_r_bye(int status, char const *phrase, 
	       nua_t *nua, cli_t *cli,
	       nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
	       tagi_t tags[])
{
  assert(op); assert(op->op_handle == nh);

  printf("%s: BYE: %03d %s\n", cli->cli_name, status, phrase);
  if (status < 200)
    return;
}

void cli_i_bye(nua_t *nua, cli_t *cli,
		 nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		 tagi_t tags[])
{
  assert(op); assert(op->op_handle == nh);

  printf("%s: BYE received\n", cli->cli_name);
}

void cli_cancel(cli_t *cli)
{
  cli_oper_t *op = oper_find_call_in_progress(cli);

  if (op) {
    printf("%s: CANCEL %s to %s\n", 
	   cli->cli_name, op->op_method_name, op->op_ident);
    nua_cancel(op->op_handle, TAG_END());
  }
  else if ((op = oper_find_call_embryonic(cli))) {
    printf("%s: reject REFER to %s\n", 
	   cli->cli_name, op->op_ident);
    nua_cancel(op->op_handle, TAG_END());
  }
  else {
    printf("%s: no call to CANCEL\n", cli->cli_name);
  }
}

void cli_i_cancel(nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[])
{
  assert(op); assert(op->op_handle == nh);

  printf("%s: CANCEL received\n", cli->cli_name);
}

void cli_zap(cli_t *cli, char *which)
{
  cli_oper_t *op;

  op = cli_oper_create(cli, sip_method_unknown, NULL, NULL, TAG_END());

  if (op) {
    printf("%s: zap %s to %s\n", cli->cli_name, 
	   op->op_method_name, op->op_ident);
    cli_oper_destroy(cli, op);
  }
  cli_prompt(cli);
}

void cli_options(cli_t *cli, char *destination)
{
  cli_oper_t *op = cli_oper_create(cli, SIP_METHOD_OPTIONS, destination,
				   TAG_END());

  if (op) {
    printf("%s: OPTIONS to %s\n", cli->cli_name, op->op_ident);
    nua_options(op->op_handle, TAG_END());
  }
  else
    cli_prompt(cli);
}

void cli_r_options(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  printf("%s: OPTIONS %d %s\n", cli->cli_name, status, phrase);

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);

  cli_prompt(cli);
}

void cli_message(cli_t *cli, char *destination)
{
  cli_oper_t *op = cli_oper_create(cli, SIP_METHOD_MESSAGE, destination, 
				   TAG_END());

  if (op) {
    char msg[160];
    printf("%s: sending message to %s\n", cli->cli_name, op->op_ident);

    cli_prompt2(cli, "Enter message");
    fgets(msg, sizeof(msg), stdin);
  
    nua_message(op->op_handle,
		SIPTAG_CONTENT_TYPE_STR("text/plain"),
		SIPTAG_PAYLOAD_STR(msg),
		TAG_END());
  }
  else
    cli_prompt(cli);
}

void cli_r_message(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  printf("%s: MESSAGE: %d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);

  cli_prompt(cli);
}

void cli_i_message(nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  /* Incoming message */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_subject_t const *subject;

  assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  subject = sip->sip_subject;

  assert(from && to);

  printf("%s: new message \n", cli->cli_name);
  printf("\tFrom: %s%s" URL_PRINT_FORMAT "\n", 
	 from->a_display ? from->a_display : "", from->a_display ? " " : "",
	 URL_PRINT_ARGS(from->a_url));
  if (subject) 
    printf("\tSubject: %s\n", subject->g_value);
  cli_print_payload(cli, sip->sip_payload);

  if (op == NULL)
    op = cli_oper_create2(cli, SIP_METHOD_MESSAGE, nh, from);
  if (op == NULL)
    nua_handle_destroy(nh);

  cli_prompt(cli);
}

void cli_info(cli_t *cli, char *destination)
{
  cli_oper_t *op = oper_find_call(cli);
   
  if (op) {
    char msg[160];
    printf("%s: sending INFO to %s\n", cli->cli_name, op->op_ident);

    cli_prompt2(cli, "Enter INFO message");
    fgets(msg, sizeof(msg), stdin);
  
    nua_info(op->op_handle,
	     SIPTAG_CONTENT_TYPE_STR("text/plain"),
	     SIPTAG_PAYLOAD_STR(msg),
	     TAG_END());
  }
  else {
    printf("INFO can be send only within an existing call\n");
    cli_prompt(cli);
  }
}

void cli_r_info(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  printf("%s: INFO: %d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);

  cli_prompt(cli);
}

void cli_i_info(nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  /* Incoming info */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_subject_t const *subject;

  assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  subject = sip->sip_subject;

  assert(from && to);

  printf("%s: new info \n", cli->cli_name);
  printf("\tFrom: %s%s" URL_PRINT_FORMAT "\n", 
	 from->a_display ? from->a_display : "", from->a_display ? " " : "",
	 URL_PRINT_ARGS(from->a_url));
  cli_print_payload(cli, sip->sip_payload);

  if (op == NULL)
    op = cli_oper_create2(cli, SIP_METHOD_INFO, nh, from);
  if (op == NULL)
    nua_handle_destroy(nh);

  cli_prompt(cli);
}

/*=======================================*/
/*REFER */
void cli_refer(cli_t *cli, char *destination)
{
   /* Send a refer */
   cli_oper_t *op = oper_find_call(cli);
   
   if (op == NULL) 
     op = cli_oper_create(cli, SIP_METHOD_REFER, destination, TAG_END());

   if (op) {
      char msg[160];
      printf("%s: Refer to %s\n", cli->cli_name, op->op_ident);

      cli_prompt2(cli, "Enter refer_to address:");
      fgets(msg, sizeof(msg), stdin);
      
      nua_refer(op->op_handle,
		SIPTAG_REFER_TO_STR(msg),
		TAG_END());
   }
   else
     cli_prompt(cli);
}
/*---------------------------------------*/
void cli_r_refer(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  /* Respond to refer */
  printf("%s: refer: %d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);

  cli_prompt(cli);
}

/*---------------------------------------*/
void cli_i_refer(nua_t *nua, cli_t *cli,
		 nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		 tagi_t tags[])
{
  /* Incoming refer */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_refer_to_t const *refer_to;
  cli_oper_t *op2;
  char *refer_to_str;

  assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  refer_to = sip->sip_refer_to;

  assert(from && to);

  printf("%s: refer to " URL_PRINT_FORMAT " from %s%s" URL_PRINT_FORMAT "\n", 
	 cli->cli_name,
	 URL_PRINT_ARGS(from->a_url),
	 from->a_display ? from->a_display : "", from->a_display ? " " : "",
	 URL_PRINT_ARGS(from->a_url));
   
  printf("Please follow(i) or reject(c) the refer\n");
   
   if(refer_to->r_url->url_type == url_sip) {
      refer_to_str = sip_header_as_string(cli->cli_home, (sip_header_t*)refer_to);
      op2 = cli_oper_create(cli, SIP_METHOD_INVITE, refer_to_str,
			    NUTAG_NOTIFY_REFER(nh), TAG_END());
      su_free(cli->cli_home, refer_to_str);
   }
   else {
     printf("\nPlease Refer to URI: "URL_PRINT_FORMAT"\n", URL_PRINT_ARGS(refer_to->r_url));
   }

   cli_prompt(cli);
}

/*---------------------------------------*/
void cli_follow_refer(cli_t *cli)
{

}
/*---------------------------------------*/
void cli_hold(cli_t *cli, char *destination, int hold)
{
   /* Put a media stream on hold */
   cli_oper_t *op = oper_find_call(cli);

   if (op) {
      printf("%s: Sending re-INVITE with %s to %s\n", 
	     cli->cli_name, hold ? "hold" : "unhold", op->op_ident);

      nua_invite(op->op_handle, NUTAG_HOLD(hold), TAG_END());
      
      op->op_callstate = opc_sent2;
   }
   else {
     printf("%s: no call to put on hold\n", cli->cli_name);
     cli_prompt(cli);
   }
}

/*---------------------------------------*/
void cli_subscribe(cli_t *cli, char *destination)
{
  cli_oper_t *op;
  char const *event = "presence";
  char const *supported = NULL;

  if (strncasecmp(destination, "list ", 5) == 0) {
    destination += 5;
    while (*destination == ' ')
      destination++;
    supported = "eventlist";
  }

  op = cli_oper_create(cli, SIP_METHOD_SUBSCRIBE, destination, TAG_END());

  if (op) {
    printf("%s: SUBSCRIBE %s to %s\n", cli->cli_name, event, op->op_ident);
    nua_subscribe(op->op_handle, 
		  SIPTAG_EXPIRES_STR("3600"),
		  SIPTAG_ACCEPT_STR("application/cpim-pidf+xml;q=0.5, "
				    "application/pidf-partial+xml"),
		  TAG_IF(supported, 
			 SIPTAG_ACCEPT_STR("multipart/related, "
					   "application/rlmi+xml")),
		  SIPTAG_SUPPORTED_STR(supported),
		  SIPTAG_EVENT_STR(event),
		  TAG_END());
  }
  else
    cli_prompt(cli);
}

void cli_watch(cli_t *cli, char *event)
{
  cli_oper_t *op;
  char *destination;

  destination = strchr(event, ' ');
  while (destination && *destination == ' ')
    *destination++ = '\0';

  op = cli_oper_create(cli, SIP_METHOD_SUBSCRIBE, destination, TAG_END());

  if (op) {
    printf("%s: SUBSCRIBE %s to %s\n", cli->cli_name, event, op->op_ident);
    nua_subscribe(op->op_handle, 
		  SIPTAG_EVENT_STR(event),
		  TAG_END());
  }
  else
    cli_prompt(cli);
}

void cli_r_subscribe(int status, char const *phrase,
		     nua_t *nua, cli_t *cli,
		     nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		     tagi_t tags[])
{
  printf("%s: SUBSCRIBE: %03d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;
  if (status >= 300)
    op->op_persistent = 0;
  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);

  cli_prompt(cli);
}
/*---------------------------------------*/
void cli_notify(cli_t *cli, char *destination)
{
  cli_oper_t *op = oper_find_call_embryonic(cli);

  if (op) {
    printf("%s: not follow refer, NOTIFY(503)\n", cli->cli_name);

    nua_cancel(op->op_handle, TAG_END());
    cli_oper_destroy(cli, op);
  }
  else {
    printf("%s: no REFER to NOTIFY\n", cli->cli_name);
  }
}
/*---------------------------------------*/
void cli_i_notify(nua_t *nua, cli_t *cli,
		  nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		  tagi_t tags[])
{
  sip_from_t const *from = sip->sip_from;
  sip_event_t const *event = sip->sip_event;
  sip_content_type_t const *content_type = sip->sip_content_type;
  sip_payload_t const *payload = sip->sip_payload;

  assert(sip);

  if (op)
    printf("%s: NOTIFY from %s\n", cli->cli_name, op->op_ident);
  else
    printf("%s: rogue NOTIFY from " URL_PRINT_FORMAT "\n", 
	   cli->cli_name, URL_PRINT_ARGS(from->a_url));    
  if (event)
    printf("\tEvent: %s\n", event->o_type);
  if (content_type)
    printf("\tContent type: %s\n", content_type->c_type);
  fputs("\n", stdout);
  cli_print_payload(cli, payload);

  cli_prompt(cli);
}
/*---------------------------------------*/
void cli_r_notify(int status, char const *phrase,
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  /* Respond to notify */
  printf("%s: notify: %d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);

  cli_prompt(cli);
}
/*---------------------------------------*/

void cli_unsubscribe(cli_t *cli, char *destination)
{
  cli_oper_t *op = oper_find_by_method(cli, sip_method_subscribe);

  if (op) {
    printf("%s: un-SUBSCRIBE to %s\n", cli->cli_name, op->op_ident);
    nua_unsubscribe(op->op_handle, TAG_END());
  }
  else
    printf("%s: no subscriptions\n", cli->cli_name);

  cli_prompt(cli);
}

void cli_r_unsubscribe(int status, char const *phrase,
		       nua_t *nua, cli_t *cli,
		       nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		       tagi_t tags[])
{
  printf("%s: un-SUBSCRIBE: %03d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  cli_oper_destroy(cli, op);
}

void cli_register(cli_t *cli, char *registrar)
{
  char *address;
  cli_oper_t *op;

  if (!registrar && (op = oper_find_by_method(cli, sip_method_register))) {
    printf("%s: REGISTER %s\n", cli->cli_name, op->op_ident);
    nua_register(op->op_handle, TAG_NULL());
    return;
  }

  address = su_strdup(cli->cli_home, cli->cli_address);

  if ((op = cli_oper_create(cli, SIP_METHOD_REGISTER, address, TAG_END()))) {
    printf("%s: REGISTER %s\n", cli->cli_name, op->op_ident);
    nua_register(op->op_handle, 
		 TAG_IF(registrar, NUTAG_REGISTRAR(registrar)), 
		 TAG_NULL());
  }
  else 
    cli_prompt(cli);

  su_free(cli->cli_home, address);
}

void cli_r_register(int status, char const *phrase, 
		    nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[])
{
  sip_contact_t *m = sip ? sip->sip_contact : NULL;

  printf("%s: REGISTER: %03d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);
  else if (status >= 300)
    cli_oper_destroy(cli, op);
  else if (status == 200)
    for (m = sip ? sip->sip_contact : NULL; m; m = m->m_next)
      sl_header_print(stdout, "\tContact: %s\n", (sip_header_t *)m);

  cli_prompt(cli);
}

void cli_unregister(cli_t *cli, char *registrar)
{
  cli_oper_t *op;

  if (!registrar && (op = oper_find_by_method(cli, sip_method_register))) {
    printf("%s: un-REGISTER %s\n", cli->cli_name, op->op_ident);
    nua_unregister(op->op_handle, TAG_NULL());
    return;
  }
  else {
    char *address = su_strdup(cli->cli_home, cli->cli_address);
    op = cli_oper_create(cli, SIP_METHOD_REGISTER, address, TAG_END());
    su_free(cli->cli_home, address);

    if (op) {
      printf("%s: un-REGISTER %s%s%s\n", cli->cli_name, 
	     op->op_ident, 
	     registrar ? " at " : "", 
	     registrar ? registrar : "");
      nua_unregister(op->op_handle,
		     TAG_IF(registrar, NUTAG_REGISTRAR(registrar)),
		     SIPTAG_CONTACT_STR("*"),
		     SIPTAG_EXPIRES_STR("0"),
		     TAG_NULL());
      return;
    }
  }

  cli_prompt(cli);
}


void cli_r_unregister(int status, char const *phrase, 
		      nua_t *nua, cli_t *cli,
		      nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		      tagi_t tags[])
{
  sip_contact_t *m;

  printf("%s: un-REGISTER: %03d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 200)
    for (m = sip ? sip->sip_contact : NULL; m; m = m->m_next)
      sl_header_print(stdout, "\tContact: %s\n", (sip_header_t *)m);

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);
  else
    cli_oper_destroy(cli, op);

  cli_prompt(cli);
}


void cli_publish(cli_t *cli, char *note)
{
  cli_oper_t *op;
  sip_payload_t *pl = NULL;
  char *address;
  char *xmlnote = NULL;
  int open;

  open = note == NULL || note[0] != '-';

  if (note && strcmp(note, "-") != 0)
    xmlnote = su_sprintf(cli->cli_home, "<note>%s</note>\n", 
			 open ? note : note + 1);

  pl = sip_payload_format
    (cli->cli_home, 
     "<?xml version='1.0' encoding='UTF-8'?>\n"
     "<presence xmlns='urn:ietf:params:xml:ns:cpim-pidf'\n"
     "          entity='%s'>\n"
     "  <tuple id='%s'>\n"
     "    <status><basic>%s</basic></status>\n"
     "%s"
     "  </tuple>\n"
     "</presence>\n",
     cli->cli_address, cli->cli_name, 
     open ? "open" : "closed", 
     xmlnote ? xmlnote : "");

  if ((op = oper_find_by_method(cli, sip_method_publish))) {
    printf("%s: %s %s\n", cli->cli_name, op->op_method_name, op->op_ident);
    nua_publish(op->op_handle, 
		SIPTAG_PAYLOAD(pl),
		TAG_IF(pl, SIPTAG_CONTENT_TYPE_STR("application/cpim-pidf+xml")),
		TAG_NULL());

    su_free(cli->cli_home, pl);
    return;
  }

  address = su_strdup(cli->cli_home, cli->cli_address);

  if ((op = cli_oper_create(cli, SIP_METHOD_PUBLISH, address, 
			    SIPTAG_EVENT_STR("presence"),
			    TAG_END()))) {
    printf("%s: %s %s\n", cli->cli_name, op->op_method_name, op->op_ident);
    nua_publish(op->op_handle, 
		SIPTAG_CONTENT_TYPE_STR("application/cpim-pidf+xml"),
		SIPTAG_PAYLOAD(pl),
		TAG_END());
  }
  else 
    cli_prompt(cli);

  su_free(cli->cli_home, pl);
  su_free(cli->cli_home, address);
}

void cli_unpublish(cli_t *cli)
{
  cli_oper_t *op;
  char *address;

  if ((op = oper_find_by_method(cli, sip_method_publish))) {
    printf("%s: %s %s\n", cli->cli_name, op->op_method_name, op->op_ident);
    nua_publish(op->op_handle, 
		SIPTAG_EXPIRES_STR("0"),
		TAG_NULL());
    return;
  }

  address = su_strdup(cli->cli_home, cli->cli_address);

  if ((op = cli_oper_create(cli, SIP_METHOD_PUBLISH, address, 
			    SIPTAG_EVENT_STR("presence"),
			    TAG_END()))) {
    printf("%s: un-%s %s\n", cli->cli_name, op->op_method_name, op->op_ident);
    nua_publish(op->op_handle, 
		SIPTAG_EXPIRES_STR("0"),
		TAG_END());
  }
  else 
    cli_prompt(cli);

  su_free(cli->cli_home, address);
}

void cli_r_publish(int status, char const *phrase, 
		   nua_t *nua, cli_t *cli,
		   nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		   tagi_t tags[])
{
  printf("%s: PUBLISH: %03d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;

  if (status == 401 || status == 407)
    oper_set_auth(cli, op, sip, tags);
  else if (status >= 300)
    cli_oper_destroy(cli, op);
  else if (!sip->sip_expires || sip->sip_expires->ex_delta == 0)
    cli_oper_destroy(cli, op);

  cli_prompt(cli);
}

/* ====================================================================== */
void cli_shutdown(cli_t *cli)
{
  enter;

  printf("%s: quitting (this can take some time)\n", cli->cli_name);

  nua_shutdown(cli->cli_nua);

  cli_deinit(cli);		/* Unregister stdin */
}

void cli_r_shutdown(int status, char const *phrase, 
		    nua_t *nua, cli_t *cli,
		    nua_handle_t *nh, cli_oper_t *op, sip_t const *sip,
		    tagi_t tags[])
{
  printf("%s: nua_shutdown: %03d %s\n", cli->cli_name, status, phrase);

  if (status < 200)
    return;
  
  su_root_break(cli->cli_root);
}

void cli_help(cli_t *cli)
{
  printf("Synopsis:\n"
	 "\tl (list)\n"
	 "\tr (register) [home]\n"
	 "\tu (unregister)\n"
	 "\tk (auth) method:\"realm\":user:password\n"
	 "\tp (publish) [-] \n"
	 "\tup (unpublish)\n"
	 "\ti (invite) url\n"
	 "\thold (hold) url\n"	 
	 "\tc (cancel)\n"
	 "\tb (bye)\n"
	 "\tm (message) [url]\n"
	 "\tref (refer) [url]\n"	 
	 "\to (options) [url]\n"
	 "\ts (subscribe) [url]\n"
	 "\tU (unsubscribe)\n"
	 "\tz (zap)\n"
	 "\tinfo\n"
	 "\te|q|x (exit)\n"
	 "\th|? (help)\n");
}

/** Add command line (standard input) to be waited. */
int cli_init(cli_t *cli, char *av[])
{
  cli->cli_name = "UA";
  if (av[1] && strncmp(av[1], "--media=", 8) == 0)
    cli->cli_media = av++[1] + 8;
  cli->cli_contact = av[1];

  /* Disable threading by command line switch? */
  su_root_threading(cli->cli_root, 0);

#ifndef WIN32
  su_wait_create(&cli->cli_input, 0, SU_WAIT_IN); 
  if (su_root_register(cli->cli_root, 
		       &cli->cli_input, 
		       handle_input, 
		       NULL, 
		       0) == SOCKET_ERROR) {
    su_perror("su_root_register");
    return -1;
  }
#else
  cli->cli_input = su_timer_create(su_root_task(cli->cli_root), 500L);
  if (!cli->cli_input)
    return -1;
  su_timer_set(cli->cli_input, handle_input, NULL);
#endif

  cli->cli_init = 1;

  return 0;
}

/** Unregister standard input. */
void cli_deinit(cli_t *cli)
{
  if (cli->cli_init) {
    cli->cli_init = 0;
#ifndef WIN32
    if (su_root_unregister(cli->cli_root, 
			   &cli->cli_input, 
			   handle_input, 
			   NULL) == SOCKET_ERROR) {
      su_perror("su_root_unregister");
    }

    su_wait_destroy(&cli->cli_input);

#else
    su_timer_destroy(cli->cli_input);
    cli->cli_input = NULL;
#endif
  }
}

#ifdef WIN32
static
int handle_input(cli_t *cli, su_timer_t *t, void *arg)
{
  if( _kbhit() ) {
    int ch = _getch();
    char rest[200];

    switch (ch) {

    case 'a': case 'A': cli_answer(cli, SIP_200_OK); break;

    case 'b': case 'B': cli_bye(cli); break;

    case 'c': case 'C': cli_cancel(cli); break;
       
    case 'd': cli_answer(cli, SIP_480_TEMPORARILY_UNAVAILABLE); break;
    case 'D': cli_answer(cli, SIP_603_DECLINE); break;

    case 'i': case 'I':
      printf("To: ");
      gets(rest);
      cli_invite(cli, rest[0] ? rest : NULL);
      break;

    case 'o': case 'O':
      printf("To: ");
      gets(rest);
      cli_options(cli, rest[0] ? rest : NULL);
      break;

    case 'r': case 'R':
      printf("registrar: ");
      gets(rest);
      cli_register(cli, rest[0] ? rest : NULL);
      break;

    case 's': case 'S':
      printf("To: ");
      gets(rest);
      cli_subscribe(cli, rest[0] ? rest : NULL);
      break;

    case 'u': 
      cli_unregister(cli, NULL);
      break;

    case 'U':
      cli_unsubscribe(cli, NULL);
      break;

    case 'z': case 'Z': cli_zap(cli, NULL); break;

    case 'x': case 'X':
    case 'q': case 'Q':
    case 'e': case 'E':
      cli_shutdown(cli);
      break;

    case '?': 
    case 'h': case 'H':
      cli_help(cli);
      cli_prompt(cli);
      break;

    default:
      cli_prompt(cli);
      break;
    }
  } 

  su_timer_set(t, handle_input, NULL);

  return 0; 
}
#else
static
int handle_input(cli_t *cli, su_wait_t *w, void *p)
{
  int n;
  char buf[1024];
  char *command, *rest;

  n = read(0, command = buf, sizeof(buf) - 1);

  if (n < 0) {
    perror("input: read");
    return 0;
  }

#define is_ws(c) ((c) != '\0' && strchr(" \t\r\n", (c)) != NULL)

  /* Skip whitespace at the end of line */
  while (n > 0 && is_ws(command[n - 1]))
    n--;
  command[n] = 0;
  /* Skip whitespace at the beginning of line */
  while (is_ws(*command))
    command++;

  /* Search first whitespace character */
  for (rest = command; *rest && !is_ws(*rest); rest++)
    ;
  /* Search non-whitespace and zero the whitespace */
  while (rest < command + n && is_ws(*rest))
    *rest++ = 0;
  if (rest >= command + n || !*rest)
    rest = NULL;

#define MATCH(c) (strcmp(command, c) == 0)
#define match(c) (strcasecmp(command, c) == 0)

  cli->cli_prompt = 0;

  if (n == 0) {
  }
  else if (match("a") || match("answer")) {
    cli_answer(cli, SIP_200_OK);
    return 0;
  }
  else if (match("b") || match("bye")) {
    cli_bye(cli);
    return 0;
  }
  else if (match("c") || match("cancel")) {
    cli_cancel(cli);
    return 0;
  }
  else if (MATCH("d")) {
    cli_answer(cli, SIP_480_TEMPORARILY_UNAVAILABLE);
    return 0;
  }
  else if (MATCH("D")) {
    cli_answer(cli, SIP_603_DECLINE); 
    return 0;
  }
  else if (match("f") || match("follow")) {
    cli_follow_refer(cli); //do we need to do something for this???
  }
  else if (match("h") || match("help")) {
    cli_help(cli);
  }
  else if (match("i") || match("invite")) {
    cli_invite(cli, rest);
    return 0;
  }
  else if (match("info")) {
    cli_info(cli, rest);
    return 0;
  }
  else if (match("hold")) {
    cli_hold(cli, rest, 1);
    return 0;
  }   
  else if (match("unhold")) {
    cli_hold(cli, rest, 0);
    return 0;
  }   
  else if (match("k") || match("key")) {
    cli_auth(cli, rest);
    return 0;
  }
  else if (match("l") || match("list")) {
    cli_list(cli);
    return 0;
  }
  else if (match("m") || match("message")) {
    cli_message(cli, rest);
    return 0;
  }
  else if (match("s") || match("subscribe")) {
    cli_subscribe(cli, rest);
    return 0;
  }
  else if (match("w") || match("watch")) {
    cli_watch(cli, rest);
    return 0;
  }
  else if (match("o") || match("options")) {
    cli_options(cli, rest);
    return 0;
  }
  else if (match("p") || match("publish")) {
    cli_publish(cli, rest);
    return 0;
  }
  else if (match("up") || match("unpublish")) {
    cli_unpublish(cli);
    return 0;
  }
  else if (match("r") || match("register")) {
    cli_register(cli, rest);
    return 0;
  }
  else if (MATCH("u") || match("unregister")) {
    cli_unregister(cli, rest);
    return 0;
  }
  else if (match("ref") || match("refer")) {
    cli_refer(cli, rest);
    return 0;
  }
  else if (MATCH("U") || match("us") || match("unsubscribe")) {
    cli_unsubscribe(cli, rest);
    return 0;
  }
  else if (match("z") || match("zap")) {
    cli_zap(cli, rest);
    return 0;
  }
  else if (match("q") || match("x") || match("exit")) {
    cli_shutdown(cli);
    return 0;
  } 
  else if (command[strcspn(command, " \t\n\r=")] == '=') {
    /* Test assignment: foo=bar  */
    if ((rest = strchr(command, '='))) {
      cli->cli_prompt = 0;
      *rest++ = '\0';
      cli_param(cli, command, rest);
    }
  } 
  else if (match("?") || match("h") || match("help")) {
    cli_help(cli);
  }
  else {
    printf("Unknown command. Type \"help\" for help\n");
  }

  cli_prompt(cli);

  return 0; /* @ */
}
#endif

void cli_prompt(cli_t *cli)
{
  if (cli->cli_prompt)
    return;
  cli->cli_prompt = 1;
#ifdef WIN32
  printf("\n%s> ", cli->cli_name); fflush(stdout);
#else
  printf("%s> ", cli->cli_name); fflush(stdout);
#endif
}

void cli_prompt2(cli_t *cli, char const *p2)
{
#ifdef WIN32
  printf("\n%s> ", p2); fflush(stdout);
#else
  printf("%s> ", p2); fflush(stdout);
#endif
}

void cli_print_payload(cli_t *cli, sip_payload_t const *pl)
{
  fputs("\n", stdout); 
  if (pl) {
    fwrite(pl->pl_data, pl->pl_len, 1, stdout);
    if (pl->pl_len < 1 || 
	(pl->pl_data[pl->pl_len - 1] != '\n' ||
	 pl->pl_data[pl->pl_len - 1] != '\r'))
      fputs("\n\n", stdout);
    else
      fputs("\n", stdout);
  }
}
