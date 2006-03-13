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

/**@file nth_server.c
 * @brief HTTP server.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Sat Oct 19 01:37:36 2002 ppessi
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include <sofia-sip/string0.h>

#if !defined(EALREADY) && defined(_WIN32)
#define EALREADY WSAEALREADY
#endif

typedef struct server_s server_t;

/** @internal SU timer argument pointer type */
#define SU_TIMER_ARG_T server_t

#include <sofia-sip/http_header.h>
#include <sofia-sip/http_status.h>
#include <sofia-sip/http_tag.h>

#include "sofia-sip/nth.h"

#include <sofia-sip/msg_date.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-sip/su_tagarg.h>

/* We are customer of tport_t */
#define TP_STACK_T   server_t
#define TP_MAGIC_T   void
                                     
#ifndef TPORT_H                 
#include <sofia-sip/tport.h>
#endif
#include <sofia-sip/htable.h>

enum { SERVER_TICK = 1000 };

#define SERVER_VERSION "nth/" NTH_VERSION

HTABLE_DECLARE(hc_htable, hct, nth_client_t);

struct server_s 
{
  su_home_t          srv_home[1];
  su_root_t         *srv_root;

  su_timer_t        *srv_timer;
  unsigned           srv_now;

  msg_mclass_t const*srv_mclass;
  int                srv_mflags;	/**< Message flags */

  tport_t           *srv_tports;
  unsigned           srv_queuesize;	/**< Maximum number of queued responses */

  size_t             srv_max_bodylen;	/**< Maximum accepted length */

  unsigned           srv_persistent:1;	/**< Allow persistent connections */

  /** Sites */
  nth_site_t        *srv_sites;

  /* Statistics */
  struct {
    uint32_t           st_requests;     /**< Received requests */
    uint32_t           st_responses;    /**< Sent responses */
    uint32_t           st_bad;		/**< Bad requests */
  }                  srv_stats[1];

  http_server_t     *srv_server;      /**< Server header */
};

struct nth_site_s 
{
  nth_site_t          *site_next;
  nth_site_t         **site_prev;
  nth_site_t          *site_kids;

  server_t            *site_server;

  url_t               *site_url;
  char const          *site_path;
  size_t               site_path_len;

  nth_request_f       *site_callback;
  nth_site_magic_t    *site_magic;

  unsigned             site_strict : 1;
};

struct nth_request_s
{
  server_t              *req_server;

  http_method_t        	req_method;
  char const           *req_method_name;
  url_t const          *req_url;         /**< RequestURI  */
  char const           *req_version;
  
  tport_t              *req_tport;
  msg_t		       *req_request;
  msg_t                *req_response;

  unsigned short      	req_status;
  unsigned              req_close : 1; /**< Client asked for close */
  unsigned              req_in_callback : 1;
  unsigned              req_destroyed : 1;
};

/* ====================================================================== */
/* Debug log settings */

#define SU_LOG   nth_server_log

#ifdef SU_DEBUG_H
#error <su_debug.h> included directly.
#endif
#include <sofia-sip/su_debug.h>

/**@var NTH_DEBUG
 *
 * Environment variable determining the debug log level for @b nth
 * module.
 *
 * The NTH_DEBUG environment variable is used to determine the debug
 * logging level for @b nth module. The default level is 1.
 * 
 * @sa <su_debug.h>, nth_server_log, SOFIA_DEBUG
 */
extern char const NTH_DEBUG[];

#ifndef SU_DEBUG
#define SU_DEBUG 1
#endif

/**Debug log for @b nth module. 
 * 
 * The nth_server_log is the log object used by @b nth module. The level of
 * #nth_server_log is set using #NTH_DEBUG environment variable.
 */
su_log_t nth_server_log[] = { SU_LOG_INIT("nth", "NTH_DEBUG", SU_DEBUG) };

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
static char const __func__[] = "nth";
#endif

/* ====================================================================== */
/** Server side
 */
static server_t *server_create(url_t const *url,
			       tag_type_t tag, tag_value_t value, ...);
void server_destroy(server_t *srv);
static inline int server_timer_init(server_t *srv);
static void server_timer(su_root_magic_t *rm, su_timer_t *timer, server_t *srv);
static inline uint32_t server_now(server_t const *srv);
static void server_request(server_t *srv, tport_t *tport, msg_t *msg,
				    void *arg, su_time_t now);
static nth_site_t **site_get_host(nth_site_t **, char const *host, char const *port);
static nth_site_t **site_get_directory(nth_site_t **list, char const *path,
				       char const **res);
static void server_tport_error(server_t *srv, tport_t *tport,
			       int errcode, char const *remote);
static msg_t *server_msg_create(server_t *srv, int flags, 
				char const data[], unsigned dlen,
				tport_t const *tp, tp_client_t *tpc);

static void server_reply(server_t *srv, tport_t *tport, 
			 msg_t *request, msg_t *response,
			 int status, char const *phrase);

static
void nth_site_request(server_t *srv,
		      nth_site_t *site,
		      tport_t *tport,
		      msg_t *request,
		      http_t *http,
		      char const *path,
		      msg_t *response);

/* ----------------------------------------------------------------------
 * 5) Site functions
 */

/** Create a http site object. 
 *
 * The function nth_site_create() allocates and initializes a web site
 * object. A web site object can be either a primary http server, a virtual
 * http server or a site within a server 
 */
nth_site_t *nth_site_create(nth_site_t *parent,  
			    nth_request_f *callback,
			    nth_site_magic_t *magic,
			    url_string_t const *address,
			    tag_type_t tag, tag_value_t value,
			    ...)
{
  nth_site_t *site = NULL, **prev;
  url_t *url;
  server_t *srv;
  ta_list ta;
  su_home_t temphome[1] = { SU_HOME_INIT(temphome) };
  char const *path = NULL;
  size_t len = 0;

  url = url_hdup(temphome, address->us_url);

  if (!url || !callback)
    return NULL;

  if (url->url_host && url->url_path) {
    SU_DEBUG_3(("nth_site_create(): virtual host and path simultanously\n"));
    su_home_deinit(temphome);
    errno = EINVAL;
    return NULL;
  }

  if (!parent && url->url_path) {
    SU_DEBUG_3(("nth_site_create(): no virtual host\n"));
    su_home_deinit(temphome);
    errno = EINVAL;
    return NULL;
  }

  ta_start(ta, tag, value);

  if (parent) {
    srv = parent->site_server; assert(srv);
    if (url->url_host)
      prev = site_get_host(&srv->srv_sites, url->url_host, url->url_port);
    else {
      len = strlen(url->url_path);
      if (len > 1 && url->url_path[len - 1] == '/')
	((char *)url->url_path)[len - 1] = '\0';
      prev = site_get_directory(&parent, url->url_path, &path);
    }
  }
  else {
    srv = server_create(url, ta_tags(ta));
    prev = &srv->srv_sites;
  }

  if (url->url_path) {
    assert(path);

    len = strlen(path);
    if (len == 0) {
      SU_DEBUG_3(("nth_site_create(): directory \"%s\" already exists\n", 
		  url->url_path));
      su_home_deinit(temphome);
      ta_end(ta);
      errno = EALREADY;
      return NULL;
    }
  }

  if (srv && (site = su_zalloc(srv->srv_home, sizeof *site))) {
    if (*prev) {
      /* The existing node should will be kid */
      site->site_next = (*prev)->site_next;
      site->site_next->site_prev = &site->site_next;
      site->site_kids = *prev;
      (*prev)->site_prev = NULL;
      (*prev)->site_next = NULL;
    }
    *prev = site, site->site_prev = prev;
    site->site_server = srv;
    site->site_url = url_hdup(srv->srv_home, url);
    if (path) {
      site->site_path = site->site_url->url_path + (path - url->url_path);
      site->site_path_len = len;
    } else {
      site->site_path = "";
      site->site_path_len = 0;
    }
    site->site_callback = callback;
    site->site_magic = magic;
    nth_site_set_params(site, ta_tags(ta));
  }

  su_home_deinit(temphome);
  ta_end(ta);

  return site;
}

void nth_site_destroy(nth_site_t *site)
{
  if (site == NULL) {
  }
  else if (site->site_server->srv_sites == site) {
    server_destroy(site->site_server);
  }
}

nth_site_magic_t *nth_site_magic(nth_site_t const *site)
{
  return site ? site->site_magic : NULL;
}

void nth_site_bind(nth_site_t *site, 
		   nth_request_f *callback, 
		   nth_site_magic_t *magic)
{
  if (site) {
    site->site_callback = callback;
    site->site_magic = magic;
  }

}

char const *nth_site_server_version(void)
{
  return "nth/" NTH_VERSION;
}

int nth_site_set_params(nth_site_t *site,
			tag_type_t tag, tag_value_t value, ...)
{
  int n;
  ta_list ta;

  server_t *server;
  int master;
  msg_mclass_t const *mclass;
  int mflags;

  if (site == NULL)
    return (errno = EINVAL), -1;

  server = site->site_server;
  master = site == server->srv_sites;

  mclass = server->srv_mclass;
  mflags = server->srv_mflags;

  ta_start(ta, tag, value);

  n = tl_gets(ta_args(ta),
	      TAG_IF(master, NTHTAG_MCLASS_REF(mclass)),
	      TAG_IF(master, NTHTAG_MFLAGS_REF(mflags)),
	      TAG_END());
  
  if (n > 0) {
    if (mclass)
      server->srv_mclass = mclass;
    else
      server->srv_mclass = http_default_mclass();
    server->srv_mflags = mflags;
  }

  ta_end(ta);

  return n;
}

int nth_site_get_params(nth_site_t const *site,
			tag_type_t tag, tag_value_t value, ...)
{
  int n;
  ta_list ta;
  server_t *server;
  int master;
  msg_mclass_t const *mclass;

  if (site == NULL)
    return (errno = EINVAL), -1;

  server = site->site_server;
  master = site == server->srv_sites;

  if (master && server->srv_mclass != http_default_mclass())
    mclass = server->srv_mclass;
  else
    mclass = NULL;

  ta_start(ta, tag, value);

  n = tl_tgets(ta_args(ta),
	       TAG_IF(master, NTHTAG_MCLASS(mclass)),
	       TAG_IF(master, NTHTAG_MFLAGS(server->srv_mflags)),
	       TAG_END());
  
  ta_end(ta);

  return n;
}

int nth_site_get_stats(nth_site_t const *site, 
		       tag_type_t tag, tag_value_t value, ...)
{
  int n;
  ta_list ta;

  if (site == NULL)
    return (errno = EINVAL), -1;

  ta_start(ta, tag, value);

  n = tl_tgets(ta_args(ta),
	       TAG_END());
  
  ta_end(ta);

  return n;
}

static
nth_site_t **site_get_host(nth_site_t **list, char const *host, char const *port)
{
  nth_site_t *site;

  assert(host);

  for (; (site = *list); list = &site->site_next) {
    if (strcasecmp(host, site->site_url->url_host) == 0 &&
	str0cmp(port, site->site_url->url_port) == 0) {
      break;
    }
  }

  return list;
}

static
nth_site_t **site_get_directory(nth_site_t **list, char const *path, char const **res)
{
  nth_site_t *site, **prev;

  assert(path);

  if (path[0] == '/')
    while (path[1] == '/')
      path++;

  if (path[0] && (path[0] != '/' || path[1]))
    for (prev = &(*list)->site_kids; (site = *prev); prev = &site->site_next) {
      size_t len = site->site_path_len;
      if (strncmp(path, site->site_path, len) == 0) {
	return site_get_directory(prev, path + len, res);
      }
    }

  if (res)
    *res = path;

  return list;
}


/* ----------------------------------------------------------------------
 * Server functions
 */

static char const * const http_tports[] =
  {
    "tcp", "tls", NULL
  };

static tp_stack_class_t nth_server_class[1] =
  {{
    sizeof(nth_server_class),
    server_request,
    server_tport_error,
    server_msg_create
  }};

server_t *server_create(url_t const *url,
			tag_type_t tag, tag_value_t value, ...)
{
  server_t *srv;
  msg_mclass_t *mclass = NULL;
  tp_name_t tpn[1] = {{ NULL }};
  su_root_t *root = NULL;
  http_server_t const *server = NULL;
  int persistent = 0;
  char const *server_str = SERVER_VERSION;
  ta_list ta;

  ta_start(ta, tag, value);
  tl_gets(ta_args(ta), 
	  NTHTAG_ROOT_REF(root),
	  NTHTAG_MCLASS_REF(mclass),
	  TPTAG_REUSE_REF(persistent),
	  HTTPTAG_SERVER_REF(server),
	  HTTPTAG_SERVER_STR_REF(server_str),
	  TAG_END());

  if (!root || !url || 
      (url->url_type != url_http && url->url_type != url_https)
      || !(srv = su_home_new(sizeof(*srv)))) {
    ta_end(ta);
    return NULL;
  }

  tpn->tpn_proto = url_tport_default(url->url_type);
  tpn->tpn_canon = url->url_host;
  tpn->tpn_host =  url->url_host;
  tpn->tpn_port = url_port(url);

  srv->srv_tports = tport_tcreate(srv, nth_server_class, root, 
				  TPTAG_IDLE(600000),
				  TPTAG_TIMEOUT(300000),
				  ta_tags(ta));

  srv->srv_persistent = persistent;
  srv->srv_max_bodylen = 1 << 30; /* 1 GB */

  if (tport_tbind(srv->srv_tports, tpn, http_tports,
		  TAG_END()) >= 0) {
    srv->srv_root = root;
    srv->srv_mclass = mclass ? mclass : http_default_mclass();
    srv->srv_mflags = MSG_DO_CANONIC;

    if (server)
      srv->srv_server = http_server_dup(srv->srv_home, server);
    else
      srv->srv_server = http_server_make(srv->srv_home, server_str);

    tport_get_params(srv->srv_tports,
		     TPTAG_QUEUESIZE_REF(srv->srv_queuesize),
		     TAG_END());
  }
  else {
    SU_DEBUG_1(("nth_server_create: cannot bind transports " 
		URL_FORMAT_STRING "\n",
		URL_PRINT_ARGS(url))); 
    server_destroy(srv), srv = NULL;
  }

  ta_end(ta);

  return srv;
}

void server_destroy(server_t *srv)
{
  tport_destroy(srv->srv_tports);
  su_timer_destroy(srv->srv_timer);
  su_home_unref(srv->srv_home);
}

/** Initialize server timer. */
static inline
int server_timer_init(server_t *srv)
{
  srv->srv_timer = su_timer_create(su_root_task(srv->srv_root), SERVER_TICK);
  return su_timer_set(srv->srv_timer, server_timer, srv);
}

/**
 * Server timer routine.
 */
static
void server_timer(su_root_magic_t *rm, su_timer_t *timer, server_t *srv)
{
  uint32_t now;

  su_timer_set(timer, server_timer, srv);

  now = su_time_ms(su_now()); now += now == 0; srv->srv_now = now;

  /* Xyzzy */

  srv->srv_now = 0;
}

/** Get current timestamp in milliseconds */
static inline
uint32_t server_now(server_t const *srv)
{
  if (srv->srv_now)
    return srv->srv_now;
  else
    return su_time_ms(su_now());
}


/** Process incoming request message */
static
void server_request(server_t *srv,
		    tport_t *tport,
		    msg_t *request,
		    void *arg,
		    su_time_t now)
{
  nth_site_t *site = NULL;
  msg_t *response;
  http_t *http = http_object(request);
  http_host_t *h;
  char const *host, *port, *path;

  /* Disable streaming */
  if (msg_is_streaming(request)) {
    msg_set_streaming(request, 0);
    return;
  }

  /* Create a response message */
  response = server_msg_create(srv, 0, NULL, 0, NULL, NULL);
  tport_tqueue(tport, response, TAG_END());

  if (http && http->http_flags & MSG_FLG_TIMEOUT) {
    server_reply(srv, tport, request, response, 400, "Request timeout");
    return;
  } else if (http && http->http_flags & MSG_FLG_TOOLARGE) {
    server_reply(srv, tport, request, response, HTTP_413_ENTITY_TOO_LARGE);
    return;
  } else if (!http || !http->http_request || 
	     (http->http_flags & MSG_FLG_ERROR)) {
    server_reply(srv, tport, request, response, HTTP_400_BAD_REQUEST);
    return;
  }

  if (http->http_request->rq_version != http_version_1_0 &&
      http->http_request->rq_version != http_version_1_1) {
    server_reply(srv, tport, request, response, HTTP_505_HTTP_VERSION);
    return;
  }

  h = http->http_host;

  if (h) {
    host = h->h_host, port = h->h_port;
  }
  else if (http->http_request->rq_url->url_host) {
    host = http->http_request->rq_url->url_host;
    port = http->http_request->rq_url->url_port;
  }
  else
    host = NULL, port = NULL;

  path = http->http_request->rq_url->url_path;

  if (host)
    site = *site_get_host(&srv->srv_sites, host, port);

  if (site == NULL && !srv->srv_sites->site_strict)
    site = srv->srv_sites;

  if (path == NULL)
    path = "";

  if (site)
    nth_site_request(srv, site, tport, request, http, path, response);
  else
    /* Answer with 404 */
    server_reply(srv, tport, request, response, HTTP_404_NOT_FOUND);
}

static void server_tport_error(server_t *srv,
				   tport_t *tport,
				   int errcode,
				   char const *remote)
{
  su_log("\nth: tport: %s%s%s\n",
	 remote ? remote : "", remote ? ": " : "",
	 su_strerror(errcode));
}

/** Respond without creating a request structure */
static void server_reply(server_t *srv, tport_t *tport, 
			 msg_t *request, msg_t *response,
			 int status, char const *phrase)
{
  http_t *http;
  http_payload_t *pl;
  int close;
  http_status_t st[1];
  char const *req_version = NULL;

  if (status < 200 || status >= 600)
    status = 500, phrase = http_500_internal_server;

  http = http_object(request);
  
  if (http && http->http_request)
    req_version = http->http_request->rq_version;

  close = status >= 200 && 
    (!srv->srv_persistent
     || status == 400
     || (http && http->http_request && 
	 http->http_request->rq_version != http_version_1_1)
     || (http && http->http_connection && 
	 msg_params_find(http->http_connection->k_items, "close")));

  msg_destroy(request);

  http = http_object(response);

  pl = http_payload_format(msg_home(response), 
			   "<html>\n"
			   "<head><title>%u %s</title></head>\n"
			   "<body><h2>%u %s</h2></body>\n"
			   "</html>\n", status, phrase, status, phrase);

  msg_header_insert(response, (msg_pub_t *)http, (msg_header_t *)pl);

  if (req_version != http_version_0_9) {
    http_status_init(st);
    st->st_version = http_version_1_1;
    st->st_status = status;
    st->st_phrase = phrase;
    
    http_add_tl(response, http,
		HTTPTAG_STATUS(st),
		HTTPTAG_SERVER(srv->srv_server),
		HTTPTAG_CONTENT_TYPE_STR("text/html"),
		HTTPTAG_SEPARATOR_STR("\r\n"),
		TAG_IF(close, HTTPTAG_CONNECTION_STR("close")),
		TAG_END());

    msg_serialize(response, (msg_pub_t *)http);
  } else {
    /* Just send the response */
    *msg_chain_head(response) = (msg_header_t *)pl;
    close = 1;
  }

  if (tport_tqsend(tport, response, NULL, 
		   TPTAG_CLOSE_AFTER(close), 
		   TAG_END()) == -1) {
    SU_DEBUG_3(("server_reply(): cannot queue response\n"));
    tport_shutdown(tport, 2);
  }

  msg_destroy(response);
}

/** Create a new message for transport */
static
msg_t *server_msg_create(server_t *srv, int flags, 
			 char const data[], unsigned dlen,
			 tport_t const *tp, tp_client_t *tpc)
{
  msg_t *msg = msg_create(srv->srv_mclass, srv->srv_mflags | flags);

  return msg;
}

/* ----------------------------------------------------------------------
 * 6) Server transactions 
 */

static
void nth_site_request(server_t *srv,
		      nth_site_t *site,
		      tport_t *tport,
		      msg_t *request,
		      http_t *http,
		      char const *path,
		      msg_t *response)
{
  nth_request_t *req = su_zalloc(srv->srv_home, sizeof *req);
  int status;

  if (req == NULL) {
    server_reply(srv, tport, request, response, HTTP_500_INTERNAL_SERVER);
    return;
  }
  
  req->req_server = srv;
  req->req_method = http->http_request->rq_method;
  req->req_method_name = http->http_request->rq_method_name;
  req->req_url = http->http_request->rq_url;
  req->req_version = http->http_request->rq_version;

  req->req_tport = tport_incref(tport);
  req->req_request = request;
  req->req_response = response;

  req->req_status = 100;
  req->req_close = 
    !srv->srv_persistent
    || http->http_request->rq_version != http_version_1_1
    || (http->http_connection && 
	msg_params_find(http->http_connection->k_items, "close"));

  req->req_in_callback = 1;
  status = site->site_callback(site->site_magic, site, req, http, path);
  req->req_in_callback = 0;

  if (status != 0 && (status < 100 || status >= 600))
    status = 500;

  if (status != 0 && req->req_status < 200) {
    nth_request_treply(req, status, NULL, TAG_END());
  }

  if (req->req_status < 100) {
    /* Stall transport - do not read more requests */
    if (tport_queuelen(tport) * 2 >= srv->srv_queuesize)
      tport_stall(tport);
  }

  if (status >= 200 || req->req_destroyed)
    nth_request_destroy(req);
}

void nth_request_destroy(nth_request_t *req)
{
  if (req == NULL)
    return;

  if (req->req_status < 200)
    nth_request_treply(req, HTTP_500_INTERNAL_SERVER, TAG_END());

  req->req_destroyed = 1;

  if (req->req_in_callback) 
    return;

  tport_decref(&req->req_tport);
  msg_destroy(req->req_request), req->req_request = NULL;
  msg_destroy(req->req_response), req->req_response = NULL;
  su_free(req->req_server->srv_home, req);
}

int nth_request_status(nth_request_t const *req)
{
  return req ? req->req_status : 400;
}

http_method_t nth_request_method(nth_request_t const *req)
{
  return req ? req->req_method : http_method_invalid;
}

msg_t *nth_request_message(nth_request_t *req)
{
  msg_t *retval = NULL;

  if (req)
    retval = msg_ref_create(req->req_request);

  return retval;
}

int nth_request_treply(nth_request_t *req, 
		       int status, char const *phrase, 
		       tag_type_t tag, tag_value_t value, ...)
{
  msg_t *response, *next = NULL;
  http_t *http;
  int retval = -1;
  int req_close, close;
  ta_list ta;
  
  if (req == NULL || status < 100 || status >= 600) {
    return -1;
  }

  response = req->req_response;
  http = http_object(response);

  ta_start(ta, tag, value);

  http_add_tl(response, http,
	      HTTPTAG_SERVER(req->req_server->srv_server),
	      ta_tags(ta));

  if (http->http_payload && !http->http_content_length) {
    http_content_length_t *l;
    http_payload_t *pl;
    unsigned len = 0;
    
    for (pl = http->http_payload; pl; pl = pl->pl_next)
      len += pl->pl_len;

    l = http_content_length_create(msg_home(response), len);

    msg_header_insert(response, (msg_pub_t *)http, (msg_header_t *)l);
  }

  if (req->req_method == http_method_head && http->http_payload) {
    http_payload_t *pl;
    
    for (pl = http->http_payload; pl; pl = pl->pl_next)
      msg_header_remove(response, (msg_pub_t *)http, (msg_header_t *)pl);
  }

  http_complete_response(response, status, phrase, 
			 http_object(req->req_request));

  if (!http->http_date) {
    http_date_t date[1];
    http_date_init(date)->d_time = msg_now();
    msg_header_add_dup(response, (msg_pub_t *)http, (msg_header_t*)date);
  }

  if (status < 200) {
    close = 0;
    next = server_msg_create(req->req_server, 0, NULL, 0, NULL, NULL);
  }
  else {
    req_close = req->req_close;

    close = (http->http_connection && 
	     msg_params_find(http->http_connection->k_items, "close"));
    
    if (req_close && !close && status >= 200) {
      close = 1;
      http_add_tl(response, http, HTTPTAG_CONNECTION_STR("close"), TAG_END());
    }
  }

  msg_serialize(response, (msg_pub_t *)http);

  retval = tport_tqsend(req->req_tport, response, next, 
			TAG_IF(close, TPTAG_CLOSE_AFTER(1)),
			ta_tags(ta));

  ta_end(ta);
  
  if (retval == 0)
    req->req_status = status;

  return retval;
}
