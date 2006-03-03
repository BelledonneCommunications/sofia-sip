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

#ifndef SOFIA_RESOLV_SRES_H
/** Defined when <sofia-resolv/sres.h> has been included. */
#define SOFIA_RESOLV_SRES_H
/**
 * @file sofia-resolv/sres.h Sofia DNS Resolver.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>,
 * @author Teemu Jalava <Teemu.Jalava@nokia.com>,
 * @author Mikko Haataja <ext-Mikko.A.Haataja@nokia.com>.
 *
 * @par Include Context
 * @code
 * #include <stdint.h>
 * #include <netinet/in.h>
 * #include <sofia-resolv/sres.h>
 * @endcode
 *
 */

#ifdef __cplusplus
extern "C" { }
#endif

enum {
  /** Resolver timer interval in milliseconds. */
  SRES_RETRANSMIT_INTERVAL = 500,
#define SRES_RETRANSMIT_INTERVAL  (SRES_RETRANSMIT_INTERVAL)

  /** Initial retry interval in seconds. */
  SRES_RETRY_INTERVAL = 1,
#define SRES_RETRY_INTERVAL  (SRES_RETRY_INTERVAL)

  /** Maximum number of retries sent. */
  SRES_MAX_RETRY_COUNT = 6,
#define SRES_MAX_RETRY_COUNT (SRES_MAX_RETRY_COUNT)

  /** Maximum number of search domains. */
  SRES_MAX_SEARCH = 6,
#define SRES_MAX_SEARCH (SRES_MAX_SEARCH)

  /** Maximum number of nameservers. */
  SRES_MAX_NAMESERVERS = 6,
#define SRES_MAX_NAMESERVERS (SRES_MAX_NAMESERVERS)

  /** Maximum length of domain name. */
  SRES_MAXDNAME = 1025,
#define SRES_MAXDNAME (SRES_MAXDNAME)

  /** Maximum length of sortlist */
  SRES_MAX_SORTLIST = 10
#define SRES_MAX_SORTLIST (SRES_MAX_SORTLIST)
};

#ifndef SRES_RECORD_T
#define SRES_RECORD_T
typedef union sres_record sres_record_t;
#endif

#ifndef SRES_CACHE_T
#define SRES_CACHE_T
typedef struct sres_cache_s sres_cache_t;
#endif

typedef struct sres_resolver_s sres_resolver_t;

#ifndef SRES_ASYNC_T 
#define SRES_ASYNC_T struct sres_async_s
#endif
typedef SRES_ASYNC_T sres_async_t;

#ifndef SRES_CONTEXT_T 
#define SRES_CONTEXT_T struct sres_context_s
#endif
typedef SRES_CONTEXT_T sres_context_t;

typedef struct sres_query_s         sres_query_t;

/** Prototype for update function.
 *
 * This kind of function is called when the nameserver configuration has
 * been updated. The called function should register the @a new_sockets with
 * resolver: it is up to thread to invoke sres_resolver_receive() whenever
 * it receives data from one of the new sockets. The @a old_sockets are
 * provided for reference.
 */
typedef int sres_update_f(sres_async_t *async,
			  int new_socket,
			  int old_socket);

/** Prototype for callback function.
 *
 * This kind of function is called when a query is completed. The called
 * function is responsible for freeing the list of answers and it must
 * (eventually) call sres_free_answers().
 */
typedef void sres_answer_f(sres_context_t *context, 
			   sres_query_t *query,
			   sres_record_t **answers);

/** Create an resolver object. */
sres_resolver_t *sres_resolver_new(char const *resolv_conf_path,
				   sres_cache_t *cache);

sres_resolver_t *sres_resolver_ref(sres_resolver_t *res);

void sres_resolver_unref(sres_resolver_t *res);

/** Set userdata pointer. */
void *sres_resolver_set_userdata(sres_resolver_t *res, void *userdata);

/** Get userdata pointer. */
void *sres_resolver_get_userdata(sres_resolver_t const *res);

/** Set asynchronous operation data. */
sres_async_t *sres_resolver_set_async(sres_resolver_t *res, 
				      sres_update_f *update,
				      sres_async_t *async,
				      int update_all);

/** Get async operation data. */
sres_async_t *sres_resolver_get_async(sres_resolver_t const *res,
				      sres_update_f *update);

/** Resolver timer function. */
void sres_resolver_timer(sres_resolver_t *res);

/** Receive DNS response from socket. */
int sres_resolver_receive(sres_resolver_t *res, int socket);

/** Receive error message from socket. */
int sres_resolver_error(sres_resolver_t *res, int socket);

/** Make a DNS query. */
sres_query_t *sres_query_make(sres_resolver_t *res,
			      sres_answer_f *callback,
			      sres_context_t *context,
			      uint16_t type,
			      char const *domain);

/** Make a reverse DNS query. */
sres_query_t *sres_query_make_sockaddr(sres_resolver_t *res,
				       sres_answer_f *callback,
				       sres_context_t *context,
				       uint16_t type,
				       struct sockaddr const *addr);

/** Rebind a DNS query. */
void sres_query_bind(sres_query_t *q,
                     sres_answer_f *callback,
                     sres_context_t *context);

/** Get a list of matching records from cache. */
sres_record_t **sres_cached_answers(sres_resolver_t *res,
				    uint16_t type,
				    char const *domain);

sres_record_t **sres_cached_answers_sockaddr(sres_resolver_t *res,
                                             uint16_t type,
					     struct sockaddr const *addr);

/** Sort the list of records */
int sres_sort_answers(sres_resolver_t *res, sres_record_t **answers);

/** Filter and sort the list of records */
int sres_filter_answers(sres_resolver_t *res, 
			sres_record_t **answers, 
			uint16_t type);

/** Free the list records. */
void sres_free_answers(sres_resolver_t *res, sres_record_t **answers);

/** Free and zero one record. */
void sres_free_answer(sres_resolver_t *res, sres_record_t *answer);

#ifdef __cplusplus
}
#endif

#endif /* SOFIA_RESOLV_SRES_H */
