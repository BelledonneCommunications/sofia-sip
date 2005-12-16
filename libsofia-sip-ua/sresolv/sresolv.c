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

/**@CFILE sresolv.c
 * @brief Sofia Asynchronous DNS Resolver implementation.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Teemu Jalava <Teemu.Jalava@nokia.com>
 * @author Mikko Haataja <ext-Mikko.A.Haataja@nokia.com>
 *
 * @todo The resolver should allow handling arbitrary records.
 */

#include "config.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <time.h>
#include <limits.h>

#include <assert.h>

#if 0 && !HAVE_SOFIA_SU
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <su_alloc.h>
#include <su_strlst.h>

#include <su.h>

#if HAVE_SU_WAIT_H

#define SU_TIMER_ARG_T  struct sres_sofia_s
#define SU_WAKEUP_ARG_T struct sres_sofia_s

#include <su_wait.h>

#include <su_types.h>
#include <su_time.h>

#define SU_LOG sresolv_log

#include <su_debug.h>

/**@var SRESOLV_DEBUG
 *
 * Environment variable determining the debug log level for @b sresolv
 * module.
 *
 * The SRESOLV_DEBUG environment variable is used to determine the debug
 * logging level for @b sresolv module. The default level is 3.
 * 
 * @sa <su_debug.h>, sresolv_log, SOFIA_DEBUG
 */
extern char const SRESOLV_DEBUG[];

/**Debug log for @b sresolv module. 
 * 
 * The sresolv_log is the log object used by @b sresolv module. The level of
 * #sresolv_log is set using #SRESOLV_DEBUG environment variable.
 */
su_log_t sresolv_log[] = { SU_LOG_INIT("sresolv", "SRESOLV_DEBUG", 3) };

#else

#define su_close(s) close(s)
#define su_strerror(s) strerror(s)
#define su_errno() errno
#define su_seterrno(x) (errno = (x))

#define SU_DEBUG_0(x) printf x
#define SU_DEBUG_1(x) printf x
#define SU_DEBUG_3(x) printf x
#define SU_DEBUG_5(x) printf x
#define SU_DEBUG_7(x) printf x
#define SU_DEBUG_9(x) printf x

#endif

#define sres_resolver_create public_sres_resolver_create

#include "sresolv.h"

#undef sres_resolver_create

#include "htable.h"

/** Cache cleanup interval in seconds. */
#define SRES_CACHE_TIMER_INTERVAL (30)

/** Sofia timer interval in milliseconds. */
#define SRES_RETRANSMIT_INTERVAL  (500)

/** Maximum number of retries sent. */
#define SRES_MAX_RETRY_COUNT (6)

/** Maximum number of search domains. */
#define SRES_MAX_SEARCH (6)

/** Maximum length of domain name. */
#define SRES_MAXDNAME (1025)

/** Internal errors */
enum {
  SRES_EDNS0_ERR = 255		/**< Server did not support EDNS. */
};

typedef struct sres_rr_hash_entry_s sres_rr_hash_entry_t;
typedef struct sres_message_s       sres_message_t;

#define SRES_HENTRY_HASH(e) ((e)->rr_hash_key)

HTABLE_DECLARE(sres_htable, ht, sres_rr_hash_entry_t);
HTABLE_DECLARE(sres_qtable, qt, sres_query_t);

typedef struct sres_server_s {    
  char const             *dns_name;     /**< Server name */
  struct sockaddr_storage dns_addr[1];  /**< Server node address */
  ssize_t                 dns_addrlen;  /**< Size of addres */
  unsigned                dns_edns;	/**< Server supports edns */

  /** ICMP error received, zero when successful. */
  time_t                  dns_icmp_error; 
} sres_server_t;


struct sres_resolver_s {
  su_home_t           res_home[1];
  unsigned            res_refcount;
  void               *res_userdata;

  int               (*res_lock)(void *mutex);
  int               (*res_unlock)(void *mutex);
  void               *res_mutex;

  time_t              res_now;
  uint16_t            res_id;
  sres_qtable_t       res_queries[1];   /**< Table of active queries */
  time_t              res_cache_cleaned;
  sres_htable_t       res_cache[1];
  char const         *res_config;    /**< Configuration file name */
  uint16_t            res_port;	     /**< Server port to use */
  short               res_n_servers; /**< Number of servers */
  short               res_i_server;  /**< Current server to try 
					(when doing round-robin) */
  sres_server_t      *res_servers;
  char const         *res_search[1 + SRES_MAX_SEARCH];
};


struct sres_rr_hash_entry_s {
  unsigned int   rr_hash_key;
  time_t         rr_received;
  sres_record_t *rr;
};


struct sres_query_s {
  hash_value_t    q_hash;
  sres_resolver_t*q_res;
  sres_answer_f  *q_callback;
  sres_context_t *q_context;
  char           *q_name;
  time_t          q_timestamp;
  int             q_socket;
  uint16_t        q_type;
  uint16_t        q_class;
  uint16_t        q_id;			/**< If nonzero, not answered */
  uint16_t        q_retry_count;
  short           q_i_server;
  uint8_t         q_edns;
  uint8_t         q_n_subs;
  sres_query_t   *q_subqueries[1 + SRES_MAX_SEARCH];
  sres_record_t **q_subanswers[1 + SRES_MAX_SEARCH];
};


struct sres_message_s {
  uint16_t m_offset;
  uint16_t m_size;
  char const *m_error;
  union {
    struct {
      /* Header defined in RFC 1035 section 4.1.1 (page 26) */
      uint16_t mh_id;		/* Query ID */
      uint16_t mh_flags;	/* Flags */
      uint16_t mh_qdcount;	/* Question record count */
      uint16_t mh_ancount;	/* Answer record count */
      uint16_t mh_nscount;	/* Authority records count */
      uint16_t mh_arcount;	/* Additional records count */
    } mp_header;
    uint8_t mp_data[1500 - 40];	/**< IPv6 datagram */
  } m_packet;
#define m_id      m_packet.mp_header.mh_id
#define m_flags   m_packet.mp_header.mh_flags
#define m_qdcount m_packet.mp_header.mh_qdcount
#define m_ancount m_packet.mp_header.mh_ancount
#define m_nscount m_packet.mp_header.mh_nscount
#define m_arcount m_packet.mp_header.mh_arcount 
#define m_data    m_packet.mp_data
};

#define sr_refcount sr_record->r_refcount
#define sr_name     sr_record->r_name
#define sr_status   sr_record->r_status
#define sr_size     sr_record->r_size
#define sr_type     sr_record->r_type
#define sr_class    sr_record->r_class
#define sr_ttl      sr_record->r_ttl
#define sr_rdlen    sr_record->r_rdlen
#define sr_rdata    sr_generic->g_data

enum {
  SRES_HDR_QR = (1 << 15),
  SRES_HDR_QUERY = (0 << 11),
  SRES_HDR_IQUERY = (1 << 11),
  SRES_HDR_STATUS = (2 << 11),
  SRES_HDR_OPCODE = (15 << 11),	/* mask */
  SRES_HDR_AA = (1 << 10),
  SRES_HDR_TC = (1 << 9),
  SRES_HDR_RD = (1 << 8),
  SRES_HDR_RA = (1 << 7),
  SRES_HDR_RCODE = (15 << 0)	/* mask of return code */
};

HTABLE_PROTOS(sres_htable, ht, sres_rr_hash_entry_t);
HTABLE_PROTOS(sres_qtable, qt, sres_query_t);

/** Get address from sockaddr storage. */
#if SU_HAVE_IN6
#define SS_ADDR(ss) \
  ((ss)->ss_family == AF_INET ? \
   (void *)&((struct sockaddr_in *)ss)->sin_addr : \
  ((ss)->ss_family == AF_INET6 ? \
   (void *)&((struct sockaddr_in6 *)ss)->sin6_addr : \
   (void *)&((struct sockaddr *)ss)->sa_data))
#else
#define SS_ADDR(ss) \
  ((ss)->ss_family == AF_INET ? \
   (void *)&((struct sockaddr_in *)ss)->sin_addr : \
   (void *)&((struct sockaddr *)ss)->sa_data)
#endif

/** Generate new 16-bit identifier for DNS query. */
uint16_t
sres_new_id(sres_resolver_t *res)
{
  return res->res_id ? res->res_id++ : (res->res_id += 2);
}

/** Return true if we have a search list or a local domain name. */
static int 
sres_has_search_domain(sres_resolver_t *res) 
{
  return res->res_search[0] || res->res_search[1];
}

static sres_query_t * sres_query_alloc(sres_resolver_t *res,
				       sres_answer_f *callback,
				       sres_context_t *context,
				       int socket,
				       uint16_t type,
				       char const * domain);

static void sres_free_query(sres_resolver_t *res, sres_query_t *q);

static void sres_store(sres_resolver_t *res, sres_record_t *rr);

static unsigned int sres_hash_key(const char *string);

static int 
sres_record_compare(sres_record_t const *a, sres_record_t const *b);

static 
int sres_sockaddr2string(char name[], size_t namelen, struct sockaddr const *);

static 
int sres_parse_resolv_conf(sres_resolver_t *, const char *filename);

static
int sres_send_dns_query(sres_resolver_t *res, sres_query_t *q);

static 
void sres_answer_subquery(sres_context_t *context, 
			  sres_query_t *query,
			  sres_record_t **answers);

static
void sres_query_report_error(sres_resolver_t *res, sres_query_t *q,
			     sres_record_t **answers);

void
sres_resend_dns_query(sres_resolver_t *res, sres_query_t *q, int timeout);

static 
sres_server_t *
sres_server_by_sockaddr(sres_resolver_t const *res, 
			void const *from, int fromlen);

static
int sres_resolver_report_error(sres_resolver_t *res, 
			       int socket,
			       int errcode,
			       struct sockaddr_storage *remote,
			       socklen_t remotelen, 
			       char const *info);

static inline void _sres_free_answer(sres_resolver_t *, sres_record_t *);
static inline void _sres_free_answers(sres_resolver_t *, sres_record_t **);

static
void sres_log_response(sres_resolver_t const *res, 
		       sres_message_t const *m,
		       struct sockaddr_storage const *from,
		       sres_query_t const *query,
		       sres_record_t * const *reply);

static int sres_decode_msg(sres_resolver_t *res, 
			   sres_message_t *m,
			   sres_query_t **,
			   sres_record_t ***aanswers);

static char const *sres_toplevel(char buf[SRES_MAXDNAME], char const *domain);

static sres_record_t *sres_create_record(sres_resolver_t *, sres_message_t *m);

static void sres_init_rr_soa(sres_resolver_t *res, sres_soa_record_t *rr,
			     sres_message_t *m);
static void sres_init_rr_a(sres_resolver_t *res, sres_a_record_t *rr,
			   sres_message_t *m);

#if SU_HAVE_IN6
static void sres_init_rr_a6(sres_resolver_t *res, sres_a6_record_t *rr,
			    sres_message_t *m);
static void sres_init_rr_aaaa(sres_resolver_t *res, sres_aaaa_record_t *rr,
			      sres_message_t *m);
#endif
static void sres_init_rr_cname(sres_resolver_t *res, sres_cname_record_t *rr,
			       sres_message_t *m);
static void sres_init_rr_ptr(sres_resolver_t *res, sres_ptr_record_t *rr,
			     sres_message_t *m);
static void sres_init_rr_srv(sres_resolver_t *res, sres_srv_record_t *rr,
			     sres_message_t *m);
static void sres_init_rr_naptr(sres_resolver_t *res, sres_naptr_record_t *rr,
			       sres_message_t *m);

static sres_record_t *sres_create_error_rr(sres_resolver_t *res,
                                           sres_query_t const *q,
                                           uint16_t errcode);

static int sres_get_domain(sres_resolver_t *res, char **buf, 
                           sres_message_t *m);

static int sres_get_string(sres_resolver_t *res, char **buf, 
                           sres_message_t *m);

static void m_put_uint16(sres_message_t *m, uint16_t h);
static void m_put_uint32(sres_message_t *m, uint32_t w);

static uint16_t m_put_domain(sres_message_t *m, 
                             char const *domain, 
                             uint16_t top, 
                             char const *topdomain);

static uint32_t m_get_uint32(sres_message_t *m);
static uint16_t m_get_uint16(sres_message_t *m);
static uint8_t m_get_uint8(sres_message_t *m);
static int m_get_string(char *d, int n, sres_message_t *m);
static int m_get_domain(char *d, int n, sres_message_t *m, int indirected);

/**Create a resolver.
 *
 * The function sres_resolver_new() is used to allocate and initialize a new
 * sres resolver object. The resolver object contains the parsed resolv.conf
 * file, cached answers from DNS, and a list of active queries. The default
 * resolv.conf file can be overriden by giving the name of the configuration
 * file as @a conf_file_path.
 *
 * @param conf_file_path name of the resolv.conf configuration file 
 *
 * @return The function sres_resolver_new() returns a pointer to a newly
 * created sres resolver object, or NULL upon an error.
 * 
 */
sres_resolver_t *
sres_resolver_new(char const *conf_file_path)
{
  sres_resolver_t *res;

  res = su_home_clone(NULL, sizeof(*res));

  if (res == NULL)
    return NULL;

  while (res->res_id == 0) {
#if HAVE_SU_WAIT_H
    su_ntp_t ntp;
    ntp = su_ntp_now();
    res->res_id = su_ntp_lo(ntp) + su_ntp_hi(ntp) + su_random();
#else
    res->res_id = time(NULL);
#endif
  }

  res->res_port = 53;		/* Domain */

  if (sres_htable_resize(res->res_home, res->res_cache, 0) < 0) {
    perror("sres: res_htable_resize");
  } 
  else if (sres_qtable_resize(res->res_home, res->res_queries, 0) < 0) {
    perror("sres: res_qtable_resize");
  } 
  else if (sres_parse_resolv_conf(res, conf_file_path)) {
    res->res_refcount = 1;
    return res;
  }

  sres_resolver_unref(res);
  return NULL;
}

/** Add a lock to resolver object. 
 *
 * The function sres_resolver_add_mutex() is used to pass a mutex along with
 * the functions used obtaining and releasing the mutex to the resolver. The
 * mutex is needed when resolver is used in multithreaded environment. The
 * @a lock function is used to obtain the lock. The @a unlock function is
 * used to release the lock. Both are called with @a mutex as their only
 * argument. Both @a lock() and @a unlock() should return 0 when successful,
 * -1 upon an error.
 *
 * @note
 * Please note that the resolver gives away its mutex lock while it
 * calls the query-specific callback functions.
 *
 * @param res pointer to resolver object
 * @param mutex pointer to a mutex object (may be NULL)
 * @param lock function used to obtain a lock on @a mutex
 * @param unlock function used to release a lock on @a mutex
 * 
 * @retval 0 when successful
 * @retval -1 upon an error
 * 
 * @ERRORS
 * @ERROR EINVAL Invalid arguments passed.
 */
int sres_resolver_add_mutex(sres_resolver_t *res,
			    void *mutex,
			    int (*lock)(void *mutex),
			    int (*unlock)(void *mutex))
{
  if (res && lock && unlock) {
    res->res_mutex = mutex;
    res->res_lock = lock;
    res->res_unlock = unlock;
    return 0;
  }
  else {
    errno = EINVAL;
    return -1;
  }
}

/** Obtain lock */
#define LOCK(res) \
  ((res ? 1 : (errno = EINVAL, 0)) && \
   ((res)->res_lock ? (res)->res_lock((res)->res_mutex) : 0) == 0)

#define UNLOCK(res) \
  (((res)->res_unlock ? (res)->res_unlock((res)->res_mutex) : 0) == 0)

/** Create a new reference to resolver. */
sres_resolver_t *
sres_resolver_ref(sres_resolver_t *res)
{
  if (LOCK(res)) {
    if (res->res_refcount != UINT_MAX)
      res->res_refcount++;
    UNLOCK(res);
    return res;
  }

  return NULL;
}
		     
/** Decrease the reference count on a resolver object. 
 *
 */
void
sres_resolver_unref(sres_resolver_t *res)
{
  if (LOCK(res)) {
    sres_resolver_t res0[1];

    if (res->res_refcount > 0)
      res->res_refcount--;
    if (res->res_refcount == 0) {
      *res0 = *res;
      su_home_zap(res->res_home);
      res = res0;
    }
    UNLOCK(res);
  }
}

void *
sres_resolver_set_userdata(sres_resolver_t *res, void *userdata)
{
  if (LOCK(res)) {
    void *old;
    old = res->res_userdata;
    res->res_userdata = userdata;
    UNLOCK(res);
    return old;
  }
  return NULL;
}

void *
sres_resolver_get_userdata(sres_resolver_t const *res)
{
  return res ? res->res_userdata : NULL;
}

/** Make a DNS query.
 *
 * The function sres_query_make() sends a query with specified @a type and
 * @a domain. The sres resolver takes care of retransmitting the query, and
 * generating an error record with nonzero status if no response is
 * received.
 */
sres_query_t *
sres_query_make(sres_resolver_t *res,
		sres_answer_f *callback,
		sres_context_t *context,
		int socket,
		uint16_t type,
		char const *domain)
{
  sres_query_t *query = NULL;
  size_t dlen;
  int enough_dots;

  SU_DEBUG_9(("sres_query_make() called\n"));

  if (domain == NULL) {
    su_seterrno(EINVAL);
    return NULL;
  }

  dlen = strlen(domain);
  if (dlen > SRES_MAXDNAME ||
      (dlen == SRES_MAXDNAME && domain[dlen - 1] != '.')) {
    su_seterrno(ENAMETOOLONG);
    return NULL;
  }

  enough_dots = strchr(domain, '.') != NULL;

  if (!LOCK(res)) {
    su_seterrno(EINVAL);
    return NULL;
  }

  time(&res->res_now);

  query = sres_query_alloc(res, callback, context, socket, type, domain);

  if (query) {
    /* Create sub-query for each search domain */
    if (sres_has_search_domain(res) && !enough_dots) {
      sres_query_t *sub;
      int i, subs, len;
      char search[SRES_MAXDNAME + 1];

      memcpy(search, domain, dlen);
      search[dlen++] = '.';
      search[dlen] = '\0';

      for (i = 0, subs = 0; i <= SRES_MAX_SEARCH; i++) {
	if (res->res_search[i]) {
	  len = strlen(res->res_search[i]);
	  
	  if (dlen + len + 1 > SRES_MAXDNAME)
	    continue;

	  memcpy(search + dlen, res->res_search[i], len);
	  search[dlen + len] = '.';
	  search[dlen + len + 1] = '\0';
	  sub = sres_query_alloc(res, sres_answer_subquery, 
				 (sres_context_t *)query, 
				 socket, 
				 type, search);

	  if (sres_send_dns_query(res, sub) == 0) {
	    query->q_subqueries[i] = sub;
	  } else {
	    sres_free_query(res, sub), sub = NULL;
	  }
	  subs += sub != NULL;
	}
      }
      
      query->q_n_subs = subs;
    }

    if (sres_send_dns_query(res, query) != 0) {
      if (!query->q_n_subs)
	sres_free_query(res, query), query = NULL;
      else
	query->q_id = 0;
    }
  }

  UNLOCK(res);

  return query;
}

/** Make a reverse DNS query.
 *
 * The function sres_query_sockaddr() sends a query with specified @a type
 * and domain name formed from the socket address @a addr. The sres resolver
 * takes care of retransmitting the query, and generating an error record
 * with nonzero status if no response is received.
 *
 */
sres_query_t *
sres_query_make_sockaddr(sres_resolver_t *res,
			 sres_answer_f *callback,
			 sres_context_t *context,
			 int socket,
			 uint16_t type,
			 struct sockaddr const *addr)
{
  sres_query_t *query;
  char name[80]; 

  if (!sres_sockaddr2string(name, sizeof(name), addr))
    return NULL;

  query = sres_query_make(res, callback, context, socket, type, name);

  return query;
}

void sres_query_bind(sres_query_t *q,
                     sres_answer_f *callback,
                     sres_context_t *context)
{
  q->q_callback = callback;
  q->q_context = context;
}

/**Get a list of matching (type/domain) records from cache.
 *
 * 
 *
 * @retval 
 * pointer to an array of pointers to cached records, or
 * NULL if no entry was found.
 */
sres_record_t **
sres_cached_answers(sres_resolver_t *res,
		    uint16_t type,
		    char const *domain)
{
  sres_record_t **result = NULL, *rr = NULL;
  sres_rr_hash_entry_t **rr_iter, **rr_iter2;
  int result_size, rr_count = 0;
  unsigned hash;
  char rooted_domain[SRES_MAXDNAME];

  domain = sres_toplevel(rooted_domain, domain);

  if (!domain)
    return NULL;

  SU_DEBUG_9(("%s(res, %02d, \"%s\") called\n", "sres_cached_answers",
	      type, domain));

  if (!LOCK(res))
    return NULL;

  time(&res->res_now);

  /* Find the domain records from the hash table */

  /* First pass: just count the number of rr:s for array allocation */
  hash = sres_hash_key(domain);
  rr_iter2 = sres_htable_hash(res->res_cache, hash);

  for (rr_iter = rr_iter2; 
       rr_iter && *rr_iter; 
       rr_iter = sres_htable_next(res->res_cache, rr_iter)) {
    rr = (*rr_iter)->rr;

    if (rr != NULL &&
	res->res_now - (*rr_iter)->rr_received <= rr->sr_ttl &&
        (type == sres_qtype_any || rr->sr_type == type) &&
        rr->sr_name != NULL &&
        strcasecmp(rr->sr_name, domain) == 0) 
      rr_count++;
  }

  result_size = (sizeof *result) * (rr_count + 1);
  result = rr_count ? su_zalloc(res->res_home, result_size) : NULL;
  
  if (result == NULL) {
    UNLOCK(res);
    if (rr_count == 0)
      errno = ENOENT;
    return NULL;
  }

  /* Second pass: add the rr pointers to the allocated array */

  for (rr_iter = rr_iter2, rr_count = 0; 
       rr_iter && *rr_iter; 
       rr_iter = sres_htable_next(res->res_cache, rr_iter)) {
    rr = (*rr_iter)->rr;

    if (rr != NULL &&
	res->res_now - (*rr_iter)->rr_received <= rr->sr_ttl &&
        (type == sres_qtype_any || rr->sr_type == type) &&
        rr->sr_name != NULL &&
        strcasecmp(rr->sr_name, domain) == 0) {
      SU_DEBUG_9(("rr found in cache: %s %02d\n", 
		  rr->sr_name, rr->sr_type));

      result[rr_count++] = rr;
      rr->sr_refcount++;
    }
  }

  result[rr_count] = NULL;

  SU_DEBUG_9(("sres_cached_answers(res, %02d, %s) returned\n", type, domain));

  UNLOCK(res);

  return result;
}

/**Get a list of matching (type/domain) records from cache.
 *
 * 
 *
 * @retval 
 * pointer to an array of pointers to cached records, or
 * NULL if no entry was found.
 */
sres_record_t **
sres_cached_answers_sockaddr(sres_resolver_t *res,
			     uint16_t type,
			     struct sockaddr const *addr)
{
  sres_record_t **result;
  char name[80];

  if (!sres_sockaddr2string(name, sizeof name, addr))
    return NULL;

  result = sres_cached_answers(res, type, name);

  return result;
}

/** Sort answers. */
void
sres_sort_answers(sres_resolver_t *res, sres_record_t **answers)
{
  int i, j;

  if (answers == NULL || answers[0] == NULL || answers[1] == NULL)
    return;

  /* Simple insertion sorting */
  for (i = 1; answers[i]; i++) {
    for (j = 0; j < i; j++) {
      if (sres_record_compare(answers[i], answers[j]) < 0)
	break;
    }
    if (j < i) {
      sres_record_t *r = answers[i];
      for (; j < i; i--) {
	answers[i] = answers[i - 1];
      }
      answers[j] = r;
    }
  }
}

/** Sort and filter query results */
int
sres_filter_answers(sres_resolver_t *sres, sres_record_t **answers, uint16_t type)
{		    
  int i, n;

  for (n = 0, i = 0; answers && answers[i]; i++) { 
    if (answers[i]->sr_record->r_status ||
	answers[i]->sr_record->r_class != sres_class_in ||
	(type != 0 && answers[i]->sr_record->r_type != type)) {
      sres_free_answer(sres, answers[i]);
      continue;
    }
    answers[n++] = answers[i];
  }
  answers[n] = NULL;

  sres_sort_answers(sres, answers);

  return n;
}


/** Free and zero one record. */
void sres_free_answer(sres_resolver_t *res, sres_record_t *answer)
{
  if (LOCK(res)) {
    _sres_free_answer(res, answer);
    UNLOCK(res);
  }
}

void 
sres_free_answers(sres_resolver_t *res,
		  sres_record_t **answers)
{
  if (LOCK(res)) {
    _sres_free_answers(res, answers);
    UNLOCK(res);
  }
}

/* Private functions */

static inline
void _sres_free_answer(sres_resolver_t *res, sres_record_t *answer)
{
  if (answer) {
    if (answer->sr_refcount <= 1)
      su_free(res->res_home, answer);
    else 
      answer->sr_refcount--;
  }
}

static inline
void 
_sres_free_answers(sres_resolver_t *res,
		   sres_record_t **answers)
{
  if (answers != NULL) {
    int i;
    for (i = 0; answers[i] != NULL; i++) {
      if (answers[i]->sr_refcount <= 1)
	su_free(res->res_home, answers[i]);
      else 
	answers[i]->sr_refcount--;
      answers[i] = NULL;
    }
    su_free(res->res_home, answers);
  }
}



/*
 * 3571 is a prime => 
 * we hash successive id values to different parts of hash tables
 */
#define Q_PRIME 3571
#define SRES_QUERY_HASH(q) ((q)->q_hash)

HTABLE_BODIES(sres_qtable, qt, sres_query_t, SRES_QUERY_HASH);

/** Allocate a query structure */
static
sres_query_t *
sres_query_alloc(sres_resolver_t *res,
		 sres_answer_f *callback,
		 sres_context_t *context,
		 int socket,
		 uint16_t type,
		 char const *domain)
{
  sres_query_t *query;
  size_t dlen = strlen(domain);

  if (sres_qtable_is_full(res->res_queries))
    if (sres_qtable_resize(res->res_home, res->res_queries, 0) < 0)
      return NULL;

  query = su_alloc(res->res_home, sizeof(*query) + dlen + 1);

  if (query) {
    memset(query, 0, sizeof *query);
    query->q_res = res;
    query->q_callback = callback;
    query->q_context = context;
    query->q_socket = socket;
    query->q_type = type;
    query->q_class = sres_class_in;
    query->q_timestamp = res->res_now;
    query->q_i_server = res->res_i_server;
    query->q_name = strcpy((char *)(query + 1), domain);

    query->q_id = sres_new_id(res); assert(query->q_id);
    query->q_hash = query->q_id * Q_PRIME;
    sres_qtable_append(res->res_queries, query);
  }

  return query;
}

static inline
void 
sres_remove_query(sres_resolver_t *res, sres_query_t *q, int all)
{
  int i;

  if (q->q_hash) {
    sres_qtable_remove(res->res_queries, q), q->q_hash = 0;

    if (all)
      for (i = 0; i <= SRES_MAX_SEARCH; i++) {
	if (q->q_subqueries[i] && q->q_subqueries[i]->q_hash) {
	  sres_qtable_remove(res->res_queries, q->q_subqueries[i]);
	  q->q_subqueries[i]->q_hash = 0;
	}
      }
  }
}

/** Remove a query from hash table and free it. */
static
void sres_free_query(sres_resolver_t *res, sres_query_t *q)
{
  int i;

  if (q == NULL)
    return;

  if (q->q_hash)
    sres_qtable_remove(res->res_queries, q), q->q_hash = 0;

  for (i = 0; i <= SRES_MAX_SEARCH; i++) {
    sres_query_t *sq;

    sq = q->q_subqueries[i];
    q->q_subqueries[i] = NULL;
    if (sq)
      sres_free_query(res, sq);
    if (q->q_subanswers[i])
      _sres_free_answers(res, q->q_subanswers[i]);
    q->q_subanswers[i] = NULL;
  }
 
  su_free(res->res_home, q);
}

/** Compare two records. */
int 
sres_record_compare(sres_record_t const *aa, sres_record_t const *bb)
{
  int D;
  sres_common_t const *a = aa->sr_record, *b = bb->sr_record;

  D = a->r_status - b->r_status; if (D) return D;
  D = a->r_class - b->r_class; if (D) return D;
  D = a->r_type - b->r_type; if (D) return D;

  if (a->r_status)
    return 0;
  
  switch (a->r_type) {
  case sres_type_soa: 
    {
      sres_soa_record_t const *A = aa->sr_soa, *B = bb->sr_soa;
      D = A->soa_serial - B->soa_serial; if (D) return D;
      D = strcasecmp(A->soa_mname, B->soa_mname); if (D) return D;
      D = strcasecmp(A->soa_rname, B->soa_rname); if (D) return D;
      D = A->soa_refresh - B->soa_refresh; if (D) return D;
      D = A->soa_retry - B->soa_retry; if (D) return D;
      D = A->soa_expire - B->soa_expire; if (D) return D;
      D = A->soa_minimum - B->soa_minimum; if (D) return D;
      return 0;
    }
  case sres_type_a:
    {
      sres_a_record_t const *A = aa->sr_a, *B = bb->sr_a;
      return memcmp(&A->a_addr, &B->a_addr, sizeof A->a_addr);
    }
#if SU_HAVE_IN6
  case sres_type_a6:
    {
      sres_a6_record_t const *A = aa->sr_a6, *B = bb->sr_a6;
      D = A->a6_prelen - B->a6_prelen; if (D) return D;
      D = strcasecmp(A->a6_prename, B->a6_prename); if (D) return D;
      return memcmp(&A->a6_suffix, &B->a6_suffix, sizeof A->a6_suffix);
    }
  case sres_type_aaaa:
    {
      sres_aaaa_record_t const *A = aa->sr_aaaa, *B = bb->sr_aaaa;
      return memcmp(&A->aaaa_addr, &B->aaaa_addr, sizeof A->aaaa_addr);      
    }
#endif
  case sres_type_cname:
    {
      sres_cname_record_t const *A = aa->sr_cname, *B = bb->sr_cname;
      return strcmp(A->cn_cname, B->cn_cname);
    }
  case sres_type_ptr:
    {
      sres_ptr_record_t const *A = aa->sr_ptr, *B = bb->sr_ptr;
      return strcmp(A->ptr_domain, B->ptr_domain);
    }
  case sres_type_srv:
    {
      sres_srv_record_t const *A = aa->sr_srv, *B = bb->sr_srv;
      D = A->srv_priority - B->srv_priority; if (D) return D;
      /* Record with larger weight first */
      D = B->srv_weight - A->srv_weight; if (D) return D;
      D = strcmp(A->srv_target, B->srv_target); if (D) return D;
      return A->srv_port - B->srv_port;
    }
  case sres_type_naptr:
    {
      sres_naptr_record_t const *A = aa->sr_naptr, *B = bb->sr_naptr;
      D = A->na_order - B->na_order; if (D) return D;
      D = A->na_prefer - B->na_prefer; if (D) return D;
      D = strcmp(A->na_flags, B->na_flags); if (D) return D;
      D = strcmp(A->na_services, B->na_services); if (D) return D;
      D = strcmp(A->na_regexp, B->na_regexp); if (D) return D;
      return strcmp(A->na_replace, B->na_replace); 
    }
  default:
    return 0;
  }
}


static 
int
sres_sockaddr2string(char name[],
		     size_t namelen,
		     struct sockaddr const *addr)
{
  name[0] = '\0';

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in const *sin = (struct sockaddr_in *)addr;
    uint8_t const *in_addr = (uint8_t*)&sin->sin_addr;
    return snprintf(name, namelen, "%u.%u.%u.%u.in-addr.arpa.",
		    in_addr[3], in_addr[2], in_addr[1], in_addr[0]);
  }
#if HAVE_SIN6
  else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 const *sin6 = (struct sockaddr_in6 *)addr;
    int addrsize = sizeof(sin6->sin6_addr.s6_addr);
    int required = addrsize * 4 + strlen("ip6.int.");
    int i;

    if (namelen <= required)
      return required;

    for (i = 0; i < addrsize; i++) {
      uint8_t byte = sin6->sin6_addr.s6_addr[addrsize - i - 1];
      uint8_t hex;

      hex = byte & 0xf;
      name[4 * i] = hex > 9 ? hex + 'a' - 10 : hex + '0';
      name[4 * i + 1] = '.';
      hex = (byte >> 4) & 0xf;
      name[4 * i + 2] = hex > 9 ? hex + 'a' - 10 : hex + '0';
      name[4 * i + 3] = '.';
    }
    
    strcpy(name + 4 * i, "ip6.int");

    return required;
  }
#endif
  else {
    errno = EPROTONOSUPPORT;
    SU_DEBUG_3(("%s: %s\n", "sres_sockaddr2string", 
                su_strerror(EPROTONOSUPPORT)));
    return 0;
  }
}

/** Parse /etc/resolv.conf file.
 *
 * @retval 0 when successful 
 * @retval -1 upon an error
 *
 * @todo The resolv.conf directives @b sortlist and options 
 *       are currently ignored.
 */
static 
int
sres_parse_resolv_conf(sres_resolver_t *res, const char *filename)
{
  char buf[PATH_MAX];
  FILE *f;
  int line;
  su_home_t *home = res->res_home;
  su_strlst_t *dns_list;
  sres_server_t *dns;
  int num_servers, i, search = 0;
  char const *localdomain = getenv("LOCALDOMAIN");

  res->res_search[0] = localdomain;

  dns_list = su_strlst_create(home);

  if (filename)
    res->res_config = su_strdup(res->res_home, filename);
  else
    res->res_config = filename = "/etc/resolv.conf";

  f = fopen(filename, "r");

  if (f != NULL) {  
    for (line = 1; fgets(buf, sizeof(buf), f); line++) {
      int n;
      char *value, *b;

      /* Skip whitespace at the beginning ...*/
      b = buf + strspn(buf, " \t");

      /* ... and at the end of line */
      for (n = strlen(b); n > 0 && strchr(" \t\r\n", b[n - 1]); n--)
	;

      if (n == 0 || b[0] == '#') 	/* Empty line or comment */
	continue;

      b[n] = '\0';

      n = strcspn(b, " \t");
      value = b + n; value += strspn(value, " \t");

#define MATCH(token) (n == strlen(token) && strncasecmp(token, b, n) == 0)
      if (MATCH("nameserver")) {
	su_strlst_dup_append(dns_list, value);
      }
      else if (MATCH("domain")) {
	if (localdomain)
	  continue;
	memset(res->res_search, 0, sizeof res->res_search);
	res->res_search[0] = su_strdup(home, value);
      }
      else if (MATCH("search")) {
	if (localdomain)
	  continue;
	memset(res->res_search, 0, sizeof res->res_search);
	while (value[0] && search < SRES_MAX_SEARCH) {
	  n = strcspn(value, " \t\r\n");
	  res->res_search[search++ + 1] = su_strndup(home, value, n);
	  value += n + strspn(value + n, " \t\r\n");
	}
      }
      else if (MATCH("port")) {
	unsigned long port = strtoul(value, NULL, 10);
	res->res_port = port;
      }
    }

    fclose(f);
  }
  
  num_servers = su_strlst_len(dns_list);

  if (num_servers == 0) {
    su_strlst_dup_append(dns_list, "127.0.0.1");
    num_servers++;
  }

  res->res_n_servers = num_servers;
  dns = su_zalloc(res->res_home, num_servers * sizeof(*res->res_servers));
  res->res_servers = dns;

  if (!dns)
    return -1;

  for (i = 0; i < num_servers; i++) {
    const char* server = su_strlst_item(dns_list, i);
    struct sockaddr *sa = (struct sockaddr *)dns->dns_addr;
    int err;

#if HAVE_SIN6
    if (strchr(server, ':')) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
      err = inet_pton(sa->sa_family = AF_INET6, server, &sin6->sin6_addr);
      sin6->sin6_port = htons(res->res_port);
      dns->dns_addrlen = sizeof *sin6;
    } 
    else 
#endif
      {
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      err = inet_pton(sa->sa_family = AF_INET, server, &sin->sin_addr);
      sin->sin_port = htons(res->res_port);
      dns->dns_addrlen = sizeof *sin;
    }

    if (err <= 0) {
      res->res_n_servers--;
      SU_DEBUG_3(("sres: nameserver %s: invalid address\n", server));
      continue;
    }

    dns->dns_name = su_strdup(res->res_home, server);
    dns->dns_edns = 1;
    dns++;
  }

  su_strlst_destroy(dns_list);

  return res->res_n_servers;
}

/** Send a query packet */
static 
int 
sres_send_dns_query(sres_resolver_t *res, 
		    sres_query_t *q)
{                        
  sres_message_t m[1];
  int i, i0, N = res->res_n_servers;
  int transient, error;
  unsigned size, no_edns_size, edns_size;
  uint16_t id = q->q_id;
  uint16_t type = q->q_type;
  char const *domain = q->q_name;
  sres_server_t *dns;

  SU_DEBUG_9(("sres_send_dns_query(%p, %p) called\n", res, q));

  if (domain == NULL)
    return -1;

  memset(m, 0, offsetof(sres_message_t, m_data[sizeof m->m_packet.mp_header]));

  /* Create a DNS message */
  m->m_size = sizeof(m->m_data);
  m->m_offset = size = sizeof(m->m_packet.mp_header);
  
  m->m_id = id;
  m->m_flags = htons(SRES_HDR_QUERY | SRES_HDR_RD);
  
  /* Query record */
  m->m_qdcount = htons(1);
  m_put_domain(m, domain, 0, NULL);
  m_put_uint16(m, type);
  m_put_uint16(m, sres_class_in);
  
  no_edns_size = m->m_offset;

  /* EDNS0 record (optional) */
  m_put_domain(m, ".", 0, NULL);
  m_put_uint16(m, sres_type_opt);
  m_put_uint16(m, sizeof(m->m_packet)); /* Class: our UDP payload size */
  m_put_uint32(m, 0);		/* TTL: extended RCODE & flags */
  m_put_uint16(m, 0);
  
  edns_size = m->m_offset;

  if (m->m_error) {
    SU_DEBUG_3(("sres_query_create(): encoding: %s\n", m->m_error));
    su_seterrno(EIO);
    return -1;
  }

  i = i0 = q->q_i_server; assert(i0 < N);
  transient = 0;

  for (;;) {
    dns = res->res_servers + i;
    /* If server supports EDNS, include EDNS0 record */
    q->q_edns = dns->dns_edns != 0;
    /* 0 (no EDNS) or 1 (EDNS supported) additional data records */
    m->m_arcount = htons(q->q_edns); 
    /* Size with or without EDNS record */
    size = q->q_edns ? edns_size : no_edns_size; 

    /* Send the DNS message to the UDP socket */
    if (sendto(q->q_socket, m->m_data, size, 0,
	       (struct sockaddr *)dns->dns_addr, dns->dns_addrlen) == size)
      break;

    error = su_errno();
    /* EINVAL is returned if destination address is bad */
    if (transient++ < 3 && error != EINVAL)
      continue;
    transient = 0;

    dns->dns_icmp_error = res->res_now;	/* Mark as a bad destination */

    /* Retry using another server */
    for (i = (i + 1) % N; res->res_servers[i].dns_icmp_error; i = (i + 1) % N) {
      if (i == i0) {
	/* All servers have reported errors */
	SU_DEBUG_5(("sres_query_create(): sendto: %s\n", su_strerror(error)));
	su_seterrno(error);
	return -1;
      }
    }

  }

  q->q_i_server = i;

  SU_DEBUG_5(("sres_send_dns_query(%p, %p) id=%u %u? %s (to [%s]:%u)\n", 
	      res, q, id, type, domain, dns->dns_name, res->res_port));

  return 0;
}

/**
 * Callback function for subqueries
 */
static
void sres_answer_subquery(sres_context_t *context, 
			  sres_query_t *query,
			  sres_record_t **answers)
{
  sres_resolver_t *res;
  sres_query_t *top = (sres_query_t *)context;
  int i;
  assert(top); assert(top->q_n_subs > 0); assert(query);

  res = query->q_res;

  LOCK(query->q_res);

  for (i = 0; i <= SRES_MAX_SEARCH; i++) {
    if (top->q_subqueries[i] == query)
      break;
  }
  assert(i <= SRES_MAX_SEARCH);
  if (i > SRES_MAX_SEARCH || top->q_n_subs == 0) {
    _sres_free_answers(res, answers);
    UNLOCK(res);
    return;
  }

  if (answers) {
    int j, k;
    for (j = 0, k = 0; answers[j]; j++) {
      if (answers[j]->sr_status)
	_sres_free_answer(query->q_res, answers[j]);
      else
	answers[k++] = answers[j];
    }
    answers[k] = NULL;
    if (!answers[0])
      _sres_free_answers(query->q_res, answers), answers = NULL;
  }

  top->q_subqueries[i] = NULL;
  top->q_subanswers[i] = answers;

  if (--top->q_n_subs == 0 && top->q_id == 0) {
    sres_query_report_error(top->q_res, top, NULL);
  };

  UNLOCK(res);
}

/** Report sres error */
static void
sres_query_report_error(sres_resolver_t *res, sres_query_t *q,
			sres_record_t **answers)
{
  int i;

  if (q->q_callback) {
    for (i = 0; i <= SRES_MAX_SEARCH; i++) {
      if (q->q_subqueries[i])	/* a pending query... */
	return;

      if (q->q_subanswers[i]) {
	answers = q->q_subanswers[i];
	q->q_subanswers[i] = NULL;
	break;
      }
    }


    SU_DEBUG_5(("sres(%p): reporting errors for %u %s\n",
		res, q->q_type, q->q_name));
 
    sres_remove_query(res, q, 1);
    UNLOCK(res);
    (q->q_callback)(q->q_context, q, answers);
    LOCK(res);
  }

  sres_free_query(res, q);
}

/** Resolver timer function.
 *
 * The function sresolver_timer() should be called in regular intervals. We
 * recommend calling it in 500 ms intervals.
 *
 */
void sres_resolver_timer(sres_resolver_t *res, int socket)
{
  int i;
  sres_query_t *q;
  time_t now, retry_time;

  if (res == NULL)
    return;

  if (!LOCK(res))
    return;

  now = time(&res->res_now);

  if (res->res_queries->qt_used) {
    /** Every time it is called it goes through all query structures, and
     * retransmits all the query messages, which have not been answered yet.
     */
    for (i = 0; i < res->res_queries->qt_size; i++) {
      q = res->res_queries->qt_table[i];
      
      if (!q || q->q_socket != socket)
	continue;
      
      /* Exponential backoff */
      retry_time = q->q_timestamp + (1 << q->q_retry_count);
      
      if (now < retry_time)
	continue;
      
      sres_resend_dns_query(res, q, 1);

      if (q != res->res_queries->qt_table[i])
	i--;
    }
  }

  /** Every 30 seconds it goes through the cache and removes outdated entries. */
  if (res->res_now > res->res_cache_cleaned + SRES_CACHE_TIMER_INTERVAL) {
    /* Clean cache from old entries */
    res->res_cache_cleaned = res->res_now;

    for (i = 0; i < res->res_cache->ht_size; i++) {
      sres_rr_hash_entry_t *e;
      
      while ((e = res->res_cache->ht_table[i]) != NULL) {
	if (res->res_now - e->rr_received <= e->rr->sr_ttl)
	  break;
	
	sres_htable_remove(res->res_cache, e);
      
	_sres_free_answer(res, e->rr);
      }
    }
  }

  UNLOCK(res);
}

/** Resend DNS query, report error cannot resend any more. */
void
sres_resend_dns_query(sres_resolver_t *res, sres_query_t *q, int timeout)
{
  int i, N;

  SU_DEBUG_9(("sres_resend_dns_query(%p, %p, %u) called\n",
	      res, q, timeout));
  
  N = res->res_n_servers;

  if (q->q_retry_count < SRES_MAX_RETRY_COUNT) {
    for (i = (q->q_i_server + 1) % N; i != q->q_i_server; i = (i + 1) % N) {
      sres_server_t *dns = res->res_servers + i;
      if (dns->dns_icmp_error == 0)
	break;
    }

    if (i == q->q_i_server && timeout) 
      /* All servers are unreachable... so, retry next one */
      i = (i + 1) % N;

    if (i != q->q_i_server || timeout) {
      res->res_i_server = q->q_i_server = i;
      
      sres_send_dns_query(res, q);

      if (timeout)
	q->q_retry_count++;
      
      return;
    }
  }

  /* report timeout/network error */
  q->q_id = 0;
    
  if (q->q_n_subs)
    return;			/* let subqueries also timeout */
  
  sres_query_report_error(res, q, NULL);
}

/** Make a domain name a top level domain name.
 *
 * The function sres_toplevel() returns a copies string @a domain and 
 * terminates it with a dot if it is not already terminated. 
 */
static
char const *
sres_toplevel(char buf[SRES_MAXDNAME], char const *domain)
{
  size_t len;
  int already;

  if (!domain)
    return NULL;

  len = strlen(domain);

  if (len >= SRES_MAXDNAME)
    return NULL;

  already = len > 0 && domain[len - 1] == '.';

  if (already)
    return domain;

  if (len + 1 >= SRES_MAXDNAME)
    return NULL;

  strcpy(buf, domain);
  buf[len] = '.'; buf[len + 1] = '\0';

  return buf;
}

/** Get a server by socket address */
static
sres_server_t *
sres_server_by_sockaddr(sres_resolver_t const *res, 
			void const *from, int fromlen)
{
  int i;

  for (i = 0; i < res->res_n_servers; i++) {
    sres_server_t *dns = &res->res_servers[i];
    if (dns->dns_addrlen == fromlen && 
	memcmp(dns->dns_addr, from, fromlen) == 0)
      return dns;
  }
  
  return NULL;
}

static
void
sres_canonize_sockaddr(struct sockaddr_storage *from, socklen_t *fromlen)
{
#if HAVE_SIN6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)from;

  size_t sin6_addrsize =
    offsetof(struct sockaddr_in6, sin6_addr) +
    (sizeof sin6->sin6_addr);

  if (from->ss_family == AF_INET6) {
    struct in6_addr const *ip6 = &sin6->sin6_addr;
  
    if (IN6_IS_ADDR_V4MAPPED(ip6) || IN6_IS_ADDR_V4COMPAT(ip6)) {
      /* Convert to a IPv4 address */
      struct sockaddr_in *sin = (struct sockaddr_in *)from;
      memcpy(&sin->sin_addr, ip6->s6_addr + 12, sizeof sin->sin_addr);
      sin->sin_family = AF_INET;
      *fromlen = sizeof (*sin);
#if SA_LEN
      sin->sin_len = sizeof (*sin);
#endif
    }
    else if (sin6_addrsize < *fromlen) {
      /* Zero extra sin6 members like sin6_flowinfo or sin6_scope_id */
      memset((char *)from + sin6_addrsize, 0, *fromlen - sin6_addrsize);
    }
  }
#endif

  if (from->ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)from;
    memset(sin->sin_zero, 0, sizeof (sin->sin_zero));
  }
}


#if HAVE_IP_RECVERR || HAVE_IPV6_RECVERR
#include <linux/types.h>
#include <linux/errqueue.h>
#include <sys/uio.h>
#endif

/** Create connected sockets for resolver. */
int sres_resolver_sockets(sres_resolver_t const *res,
			  int *sockets, int n)
{
  int s = -1, i = 0, family = 0, retval;
  int one = 1, zero = 0;
  int error = su_errno();
  char const *what = "socket";
  struct sockaddr_storage name;
  socklen_t namelen;
  unsigned short port;

  if (res == NULL)
    return (errno = EINVAL), -1;

  if (!sockets || n == 0)
    return 1 + res->res_n_servers;

  retval = 1 + res->res_n_servers;

#if HAVE_SIN6
  s = socket(family = AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  namelen = sizeof(struct sockaddr_in6);
#endif
  if (s == -1) {
    s = socket(family = AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    namelen = sizeof(struct sockaddr_in);
  }
  if (s == -1)
    return -1;
  sockets[i++] = s;

  memset(&name, 0, namelen);
#if HAVE_SA_LEN
  name.ss_len = namelen;
#endif
  name.ss_family = family;

#if HAVE_IP_RECVERR
  if (setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0)
    SU_DEBUG_3(("sres: IP_RECVERR: %s\n", su_strerror(su_errno())));
#endif
#if HAVE_IPV6_RECVERR
  if (family == AF_INET6 && 
      setsockopt(s, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one)) < 0)
    SU_DEBUG_3(("sres: IPV6_RECVERR: %s\n", su_strerror(su_errno())));
#endif

  /*
   * First socket is not connected:
   * bind it to a port and obtain the port number
   * so that the connected sockets will have same source port.
   */
  if (bind(s, (struct sockaddr *)&name, namelen) < 0) {
    what = "bind"; retval = -1; 
  }
  else if (n == 1)
    ;
  else if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one))
	   < 0) {
    what = "SO_REUSEADDR"; retval = -1; 
  }
  else if (getsockname(s, (struct sockaddr *)&name, &namelen) < 0) {
    what = "getsockname"; retval = -1;
  }
  else for (i = 1; i < retval && i < n;) {
    sres_server_t *dns = res->res_servers + i - 1;

    family = dns->dns_addr->ss_family;

    s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
      retval = -1;
      break;
    }

    sockets[i++] = s;

#if HAVE_IP_RECVERR
    if (setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0)
      SU_DEBUG_3(("sres: IP_RECVERR: %s\n", su_strerror(su_errno())));
#endif
#if HAVE_IPV6_RECVERR
    if (family == AF_INET6 && 
	setsockopt(s, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one)) < 0)
      SU_DEBUG_3(("sres: IPV6_RECVERR: %s\n", su_strerror(su_errno())));
#endif

#if HAVE_SIN6
    if (family == AF_INET6)
      namelen = sizeof(struct sockaddr_in6);
    else
      namelen = sizeof(struct sockaddr_in);
    port = ((struct sockaddr_in *)&name)->sin_port;
    memset(&name, 0, namelen);
#if HAVE_SA_LEN
    name.ss_len = namelen;
#endif
    name.ss_family = family;
    ((struct sockaddr_in *)&name)->sin_port = port;
#endif

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, 
		   (void *)&one, sizeof(one)) < 0) {
      SU_DEBUG_3(("%s: %s: %s\n", "sres_resolver_sockets", "SO_REUSEADDR",
		  strerror(errno)));
    }
    else if (bind(s, (struct sockaddr *)&name, namelen) < 0) {
      SU_DEBUG_3(("%s: %s: %s\n", "sres_resolver_sockets", "bind2",
		  strerror(errno)));
    }
    else if (connect(s, (struct sockaddr *)dns->dns_addr, dns->dns_addrlen)
	     < 0) {
      SU_DEBUG_3(("%s: connect: %s\n", "sres_resolver_sockets",
		  strerror(errno)));
    }
  }

  if (retval > 1) {
    setsockopt(sockets[0], SOL_SOCKET, SO_REUSEADDR, 
	       (void *)&zero, sizeof(zero));
  }
  else if (retval < 0) {
    error = su_errno();
    SU_DEBUG_3(("%s: %s: %s\n", "sres_resolver_sockets", what, 
		strerror(error)));
    while (i >= 0)
      su_close(sockets[i--]);
  }
  
  su_seterrno(error);

  return retval;
}

/** Receive error message from socket. */
#if HAVE_IP_RECVERR || HAVE_IPV6_RECVERR
int sres_resolver_error(sres_resolver_t *res, int socket)
{
  int errcode = 0;
  struct cmsghdr *c;
  struct sock_extended_err *ee;
  struct sockaddr_storage *from;
  char control[512];
  char errmsg[64 + 768];
  struct iovec iov[1];
  struct msghdr msg[1] = {{ 0 }};
  struct sockaddr_storage name[1] = {{ 0 }};
  int n;
  char info[128] = "";

  SU_DEBUG_9(("%s(%p, %u) called\n", "sres_resolver_error", res, socket));

  msg->msg_name = name, msg->msg_namelen = sizeof(name);
  msg->msg_iov = iov, msg->msg_iovlen = 1;
  iov->iov_base = errmsg, iov->iov_len = sizeof(errmsg);
  msg->msg_control = control, msg->msg_controllen = sizeof(control);

  n = recvmsg(socket, msg, MSG_ERRQUEUE);

  if (n < 0) {
    SU_DEBUG_1(("%s: recvmsg: %s\n", __func__, su_strerror(su_errno())));
    return n;
  }

  if ((msg->msg_flags & MSG_ERRQUEUE) != MSG_ERRQUEUE) {
    SU_DEBUG_1(("%s: recvmsg: no errqueue\n", __func__));
    su_seterrno(EIO);
    return -1;
  }

  if (msg->msg_flags & MSG_CTRUNC) {
    SU_DEBUG_1(("%s: extended error was truncated\n", __func__));
    su_seterrno(EIO);
    return -1;
  }

  if (msg->msg_flags & MSG_TRUNC) {
    /* ICMP message may contain original message... */
    SU_DEBUG_5(("%s: icmp(6) message was truncated (at %d)\n", __func__, n));
  }

  /* Go through the ancillary data */
  for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
    if (0
#if HAVE_IP_RECVERR
	|| (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR)
#endif
#if HAVE_IPV6_RECVERR
	|| (c->cmsg_level == SOL_IPV6 && c->cmsg_type == IPV6_RECVERR)
#endif
	) {
      char const *origin;

      ee = (struct sock_extended_err *)CMSG_DATA(c);
      from = (void *)SO_EE_OFFENDER(ee);
      info[0] = '\0';

      switch (ee->ee_origin) {
      case SO_EE_ORIGIN_LOCAL:
	strcpy(info, origin = "local");
	break;
      case SO_EE_ORIGIN_ICMP:
	snprintf(info, sizeof(info), "%s type=%u code=%u", 
		 origin = "icmp", ee->ee_type, ee->ee_code);
	break;
      case SO_EE_ORIGIN_ICMP6:
	snprintf(info, sizeof(info), "%s type=%u code=%u", 
		 origin = "icmp6", ee->ee_type, ee->ee_code);
	break;
      case SO_EE_ORIGIN_NONE:
	strcpy(info, origin = "none");
	break;
      default:
	strcpy(info, origin = "unknown");
	break;
      }

      if (ee->ee_info)
	snprintf(info + strlen(info), sizeof(info) - strlen(info), 
		 " info=%08x", ee->ee_info);
      errcode = ee->ee_errno;

      if (from->ss_family != AF_UNSPEC) {
	socklen_t fromlen = ((char *)c + c->cmsg_len) - (char *)from;

	sres_canonize_sockaddr(from, &fromlen);

	snprintf(info + strlen(info), sizeof(info) - strlen(info), 
		 " reported by ");
	inet_ntop(from->ss_family, SS_ADDR(from), 
		  info + strlen(info), sizeof(info) - strlen(info));
      }

      if (msg->msg_namelen <= 0)
	break;

      {
	int error;
	socklen_t errorlen = sizeof error;
	/* Get error, if any */
	getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)&error, &errorlen);
      }
      
      if (sres_resolver_report_error(res, socket, errcode, 
				     msg->msg_name, msg->msg_namelen,
				     info))
	return errcode;
      break;
    }
  }

  if (errcode)
    sres_resolver_report_error(res, socket, errcode, NULL, 0, info);

  return errcode;
}

#else
int sres_resolver_error(sres_resolver_t *res, int socket)
{
  int errcode = 0;
  int errorlen = sizeof(errcode);
  struct sockaddr_storage remote[1] = {{ 0 }};
  socklen_t remotelen = sizeof remote;

  SU_DEBUG_9(("%s(%p, %u) called\n", "sres_resolver_error", res, socket));

  getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)&errcode, &errorlen);

  if (getpeername(socket, (struct sockaddr *)remote, &remotelen) == 0) {
    return sres_resolver_report_error(res, socket, errcode, 
				      remote, remotelen, "");
  }
  else
    return sres_resolver_report_error(res, socket, errcode, 
				      NULL, 0, "");
}
#endif


/** Report error */
static
int 
sres_resolver_report_error(sres_resolver_t *res,
			   int socket,
			   int errcode,
			   struct sockaddr_storage *remote,
			   socklen_t remotelen, 
			   char const *info)
{
  char buf[80];

  buf[0] = '\0';

  if (remote) {
    sres_canonize_sockaddr(remote, &remotelen);

    if (remote->ss_family == AF_INET) {
      struct sockaddr_in const *sin = (struct sockaddr_in *)remote;
      uint8_t const *in_addr = (uint8_t*)&sin->sin_addr;
      inet_ntop(AF_INET, in_addr, buf, sizeof(buf));
    } 
#if HAVE_SIN6
    else if (remote->ss_family == AF_INET6) {
      struct sockaddr_in6 const *sin6 = (struct sockaddr_in6 *)remote;
      uint8_t const *in_addr = (uint8_t*)&sin6->sin6_addr;
      inet_ntop(AF_INET6, in_addr, buf, sizeof(buf));
    }
#endif
  }

  SU_DEBUG_5(("sres: network error %u (%s)%s%s%s%s\n", 
	      errcode, su_strerror(errcode),
	      buf[0] ? " from " : "", buf, 
	      info ? " by " : "",
	      info ? info : ""));

  if (res->res_queries->qt_used) {
    /* Report error to queries */
    sres_server_t *dns;
    sres_query_t *q;
    int i;
    
    dns = sres_server_by_sockaddr(res, remote, remotelen);

    if (dns && LOCK(res)) {
      time(&res->res_now);
      dns->dns_icmp_error = res->res_now;

      for (i = 0; i < res->res_queries->qt_size; i++) {
	q = res->res_queries->qt_table[i];
      
	if (!q || 
	    q->q_socket != socket ||
	    dns != res->res_servers + q->q_i_server)
	  continue;
	/* Resend query/report error to application */
	sres_resend_dns_query(res, q, 1);

	if (q != res->res_queries->qt_table[i])
	  i--;
      }
      UNLOCK(res);
    }
  }
  
  return 1;
}


/** Receive a response packet from socket. */
int 
sres_resolver_receive(sres_resolver_t *res, int socket)
{
  int num_bytes, error;
  sres_message_t m[1];
  struct sockaddr_storage from[1];
  socklen_t fromlen = (sizeof from);

  sres_query_t *query = NULL;
  sres_record_t **reply;
  sres_server_t *dns;

  SU_DEBUG_9(("%s(%p, %u) called\n", "sres_resolver_receive", res, socket));

  assert(res);

  if (res == NULL)
    return 0;

  memset(m, 0, offsetof(sres_message_t, m_data)); 
  
  num_bytes = recvfrom(socket, m->m_data, sizeof (m->m_data), 0,
		       (struct sockaddr *)from, &fromlen);

  if (num_bytes <= 0) {
    SU_DEBUG_5(("%s: %s\n", "sres_receive_packet", su_strerror(su_errno())));
    return 0;
  }

  sres_canonize_sockaddr(from, &fromlen);
  dns = sres_server_by_sockaddr(res, from, fromlen);
  if (!dns)
    return 0;

  m->m_size = num_bytes;

  if (!LOCK(res))
    return -1;

  time(&res->res_now);

  /* Decode the received message and get the matching query object */
  error = sres_decode_msg(res, m, &query, &reply);

  sres_log_response(res, m, from, query, reply);

  if (query == NULL)
    ;
  else if (error == SRES_EDNS0_ERR) {
    dns->dns_edns = 0;
    assert(query->q_id);
    sres_remove_query(res, query, 0);
    query->q_id = sres_new_id(res);
    query->q_hash = query->q_id * Q_PRIME;
    sres_qtable_append(res->res_queries, query);
    sres_send_dns_query(res, query);
    query->q_retry_count++;
  } 
  else if (!error && reply) {
    /* Remove the query from the pending list and notify the listener */
    sres_remove_query(res, query, 1);
    UNLOCK(res);
    if (query->q_callback != NULL)
      (query->q_callback)(query->q_context, query, reply); 
    LOCK(res);
    sres_free_query(res, query);
  }
  else {
    sres_query_report_error(res, query, reply);
  }

  UNLOCK(res);

  return 1;
}

static
void sres_log_response(sres_resolver_t const *res, 
		       sres_message_t const *m,
		       struct sockaddr_storage const *from,
		       sres_query_t const *query,
		       sres_record_t * const *reply)
{
  if (SU_LOG->log_level >= 5) {
#ifndef ADDRSIZE
#define ADDRSIZE 48
#endif
    char host[ADDRSIZE];

    if (from->ss_family == AF_INET) {
      struct sockaddr_in const *sin = (void *)from;
      inet_ntop(AF_INET, &sin->sin_addr, host, sizeof host);
    } 
#if HAVE_SIN6
    else if (from->ss_family == AF_INET6) {
      struct sockaddr_in6 const *sin6 = (void *)from;
      inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof host);
    }
#endif
    else
      strcpy(host, "*");

    SU_DEBUG_5(("sres_resolver_receive(%p, %p) id=%u (from [%s]:%u)\n", 
		res, query, m->m_id, 
		host, ntohs(((struct sockaddr_in *)from)->sin_port)));
  }
}

/** Decode DNS message.
 *
 */
static
int
sres_decode_msg(sres_resolver_t *res, 
		sres_message_t *m,
		sres_query_t **qq,
		sres_record_t ***aanswers)
{
  sres_record_t *rr = NULL, **answers = NULL, *error = NULL;
  sres_query_t *query = NULL, **hq;
  hash_value_t hash;
  int i, err;

  assert(res && m && aanswers);

  *qq = NULL;
  *aanswers = answers;

  m->m_offset = sizeof(m->m_packet.mp_header);

  if (m->m_size < m->m_offset) {
    SU_DEBUG_5(("sres_decode_msg: truncated message\n"));
    return -1;
  }

  m->m_flags   = ntohs(m->m_flags);
  m->m_qdcount = ntohs(m->m_qdcount);
  m->m_ancount = ntohs(m->m_ancount); 
  m->m_nscount = ntohs(m->m_nscount); 
  m->m_arcount = ntohs(m->m_arcount); 

  hash = Q_PRIME * m->m_id;

  /* Search for query with this ID */
  for (hq = sres_qtable_hash(res->res_queries, hash);
       *hq;
       hq = sres_qtable_next(res->res_queries, hq))
    if (hash == (*hq)->q_hash)
      break;

  *qq = query = *hq;

  if (!query) {
    SU_DEBUG_5(("sres_decode_msg: %u has no matching query\n", m->m_id));
    return -1;
  }

  assert(query && m->m_id == query->q_id);

  if ((m->m_flags & 15) == SRES_FORMAT_ERR && query->q_edns)
    return SRES_EDNS0_ERR;

  /* Scan question section */
  for (i = 0; i < m->m_qdcount; i++) {
    char name[1024];
    uint16_t qtype, qclass;
    m_get_domain(name, sizeof(name), m, 0); /* Query domain */
    qtype = m_get_uint16(m);  /* Query type */
    qclass = m_get_uint16(m); /* Query class */
  }

  if (m->m_error) {
    SU_DEBUG_5(("sres_decode_msg: %s\n", m->m_error));
    return -1;
  }

  err = m->m_flags & SRES_HDR_RCODE;

  if (m->m_ancount) {
    *aanswers = answers = su_zalloc(res->res_home, 
				    (m->m_ancount + 1) * sizeof answers[0]);
    assert(answers);
  } 
#if 1
  else if (err == 0 || err == SRES_NAME_ERR || err == SRES_UNIMPL_ERR) {
    if (err == 0) 
      err = SRES_RECORD_ERR;
    *aanswers = answers = su_zalloc(res->res_home, 2 * sizeof answers[0]);
    if (answers) {
      error = sres_create_error_rr(res, query, err);
      if (error) {
	sres_store(res, error);
	*answers++ = error;
	error->sr_refcount++;
      }
    }
  }
#endif
  else {
    *aanswers = answers = NULL;
  }

  /* Scan resource records */
  /* XXX - this should be atomic  */ 
  for (i = 0; i < m->m_ancount + m->m_nscount + m->m_arcount; i++) {
    rr = sres_create_record(res, m);
 
    if (!rr) {
      SU_DEBUG_5(("sres_create_record: %s\n", m->m_error));
      return -1;
    }

    if (error && rr->sr_type == sres_type_soa) {
      sres_soa_record_t *soa = (sres_soa_record_t *)rr;
      if (error->sr_ttl > soa->soa_minimum && soa->soa_minimum > 10)
	  error->sr_ttl = soa->soa_minimum;
    }
	
    sres_store(res, rr);

    if (i < m->m_ancount) {
      *answers++ = rr;
      rr->sr_refcount++;
    } 
  }

  return err;
}  

static
sres_record_t *
sres_alloc_record(sres_resolver_t *res, uint16_t qtype, uint16_t rdlen)
{
  int size;
  sres_record_t *sr;

  switch (qtype) {
  case sres_type_soa:     size = sizeof(sres_soa_record_t); break;
  case sres_type_a:       size = sizeof(sres_a_record_t); break;
#if SU_HAVE_IN6
  case sres_type_a6:      size = sizeof(sres_a6_record_t); break;
  case sres_type_aaaa:    size = sizeof(sres_aaaa_record_t); break;
#endif
  case sres_type_cname:   size = sizeof(sres_cname_record_t); break;
  case sres_type_ptr:     size = sizeof(sres_ptr_record_t); break;
  case sres_type_srv:     size = sizeof(sres_srv_record_t); break;
  case sres_type_naptr:   size = sizeof(sres_naptr_record_t); break;
  default:                size = sizeof(sres_common_t) + rdlen; break;
  }

  sr = su_zalloc(res->res_home, size);

  if (sr) 
    sr->sr_size = size;
    
  return sr;
}

static
sres_record_t *
sres_create_record(sres_resolver_t *res, sres_message_t *m)
{
  sres_record_t *rr = NULL;

  uint16_t qtype, qclass, rdlen, size_old;
  uint32_t ttl;
  char name[1024];
  int name_length;

  name_length = m_get_domain(name, sizeof(name), m, 0);	/* Name */
  qtype = m_get_uint16(m);  /* Type */
  qclass = m_get_uint16(m); /* Class */
  ttl = m_get_uint32(m);    /* TTL */
  rdlen = m_get_uint16(m);   /* rdlength */

  SU_DEBUG_9(("rr: %s %d %d %d %d\n", name, qtype, qclass, ttl, rdlen));

  if (m->m_error)
    return NULL;

  /* temporarily adjust m_size to check if the current rr is truncated */
  size_old = m->m_size; 
  m->m_size = m->m_offset + rdlen;

  rr = sres_alloc_record(res, qtype, rdlen);
  if (rr) switch(qtype) {
  case sres_type_soa:
    sres_init_rr_soa(res, rr->sr_soa, m);
    break;
  case sres_type_a:
    sres_init_rr_a(res, rr->sr_a, m);
    break;
#if SU_HAVE_IN6
  case sres_type_a6:
    sres_init_rr_a6(res, rr->sr_a6, m);
    break;
  case sres_type_aaaa:
    sres_init_rr_aaaa(res, rr->sr_aaaa, m);
    break;
#endif
  case sres_type_cname:
    sres_init_rr_cname(res, rr->sr_cname, m);
    break;
  case sres_type_ptr:
    sres_init_rr_ptr(res, rr->sr_ptr, m);
    break;
  case sres_type_srv:
    sres_init_rr_srv(res, rr->sr_srv, m);
    break;
  case sres_type_naptr:
    sres_init_rr_naptr(res, rr->sr_naptr, m);
    break;
  default: /* copy the raw rdata to rr->r_data */
    if (m->m_offset + rdlen > m->m_size) {
      m->m_error = "truncated message";
    } else {
      memcpy(rr->sr_rdata, m->m_data + m->m_offset, rdlen);
      m->m_offset += rdlen;
    }
  }
  else 
    m->m_error = "memory exhausted";
  
  if (m->m_error) {
    SU_DEBUG_5(("sres_create_rr: %s\n", m->m_error));
    su_free(res->res_home, rr);
    return NULL;
  }

  m->m_size = size_old;

  /* Fill in the common fields */
  if (rr != NULL) {
    rr->sr_name = su_strdup(res->res_home, name);
    rr->sr_type = qtype;
    rr->sr_class = qclass;
    rr->sr_ttl = ttl;
    rr->sr_rdlen = rdlen;
  }

  return rr;
}

static void
sres_init_rr_soa(sres_resolver_t *res, 
		 sres_soa_record_t *rr,
		 sres_message_t *m)
{
  assert(rr->soa_record->r_size == sizeof(sres_soa_record_t));

  sres_get_domain(res, &rr->soa_mname, m);
  sres_get_domain(res, &rr->soa_rname, m);
  rr->soa_serial = m_get_uint32(m);
  rr->soa_refresh = m_get_uint32(m);
  rr->soa_retry = m_get_uint32(m);
  rr->soa_expire = m_get_uint32(m);
  rr->soa_minimum = m_get_uint32(m);
}

static void
sres_init_rr_a(sres_resolver_t *res, 
	       sres_a_record_t *rr,
	       sres_message_t *m)
{
  assert(rr->a_record->r_size == sizeof(sres_a_record_t));

  rr->a_addr.s_addr = htonl(m_get_uint32(m));
}

#if SU_HAVE_IN6
static void
sres_init_rr_a6(sres_resolver_t *res,
		sres_a6_record_t *rr,
		sres_message_t *m)
{
  int suffix_length, i;

  assert(rr->a6_record->r_size == sizeof(sres_a6_record_t));

  rr->a6_prelen = m_get_uint8(m);

  suffix_length = (128 - rr->a6_prelen) / 8;
      
  if ((128 - rr->a6_prelen) % 8 != 0)
    suffix_length++;

  for (i = 16 - suffix_length; i < 16; i++) {
    if (i >= 0) {
      rr->a6_suffix.s6_addr[i] = m_get_uint8(m);
    }
  }

  if (suffix_length < 16)
    sres_get_domain(res, &rr->a6_prename, m);
}

static void
sres_init_rr_aaaa(sres_resolver_t *res,
		  sres_aaaa_record_t *rr,
		  sres_message_t *m)
{
  assert(rr->aaaa_record->r_size == sizeof(sres_aaaa_record_t));

  if (m->m_offset + sizeof(rr->aaaa_addr.s6_addr) > m->m_size) {
    m->m_error = "truncated message";
    return;
  }

  memcpy(rr->aaaa_addr.s6_addr, 
	 m->m_data + m->m_offset, 
	 sizeof(rr->aaaa_addr.s6_addr));

  m->m_offset += sizeof(rr->aaaa_addr.s6_addr);
}
#endif /* SU_HAVE_IN6 */

static void
sres_init_rr_cname(sres_resolver_t *res,
		   sres_cname_record_t *rr,
		   sres_message_t *m)
{
  assert(rr->cname_record->r_size == sizeof(sres_cname_record_t));

  sres_get_domain(res, &rr->cn_cname, m);
}

static void
sres_init_rr_ptr(sres_resolver_t *res,
		 sres_ptr_record_t *rr,
		 sres_message_t *m)
{
  assert(rr->ptr_record->r_size == sizeof(sres_ptr_record_t));

  sres_get_domain(res, &rr->ptr_domain, m);
}

static void
sres_init_rr_srv(sres_resolver_t *res,
		 sres_srv_record_t *rr,
		 sres_message_t *m)
{
  assert(rr->srv_record->r_size == sizeof(sres_srv_record_t));

  rr->srv_priority = m_get_uint16(m);
  rr->srv_weight = m_get_uint16(m);
  rr->srv_port = m_get_uint16(m);

  sres_get_domain(res, &rr->srv_target, m);
}

static void
sres_init_rr_naptr(sres_resolver_t *res,
		   sres_naptr_record_t *rr,
		   sres_message_t *m)
{
  assert(rr->na_record->r_size == sizeof(sres_naptr_record_t));

  rr->na_order = m_get_uint16(m);
  rr->na_prefer = m_get_uint16(m);

  sres_get_string(res, &rr->na_flags, m);
  sres_get_string(res, &rr->na_services, m);
  sres_get_string(res, &rr->na_regexp, m);
  sres_get_domain(res, &rr->na_replace, m);
}

static
sres_record_t *
sres_create_error_rr(sres_resolver_t *res,
		     sres_query_t const *q,
		     uint16_t errcode)
{
  sres_record_t *sr;
  char buf[SRES_MAXDNAME];

  sr = sres_alloc_record(res, q->q_type, 0);
  
  if (sr) {
    sr->sr_status = errcode;
    sr->sr_name = su_strdup(res->res_home, sres_toplevel(buf, q->q_name));
    sr->sr_type = q->q_type;
    sr->sr_class = q->q_class;
    sr->sr_ttl = 10 * 60;
    /* sr->sr_ttl = 30; */
  }

  return sr;
}

static
int
sres_get_domain(sres_resolver_t *res,
		char **buf,
		sres_message_t *m)
{
  char name[1024];
  int length = 0;

  assert(buf);

  if (buf) {
    length = m_get_domain(name, sizeof(name), m, 0);
    *buf = su_zalloc(res->res_home, length + 1);

    assert(*buf);
    if (*buf) {
      memcpy(*buf, name, length);
      *(*buf + length) = 0;
    }
  }

  return length;
}

static
int 
sres_get_string(sres_resolver_t *res,
		char **buf,
		sres_message_t *m)
{
  char name[1024];
  int length = 0;

  assert(buf);

  if (buf) {
    length = m_get_string(name, sizeof(name), m);
    *buf = su_zalloc(res->res_home, length + 1);

    assert(*buf);
    if (*buf) {
      memcpy(*buf, name, length);
      *(*buf + length) = 0;
    }
  }

  return length;
}

/* Cache-related functions */

HTABLE_BODIES(sres_htable, ht, sres_rr_hash_entry_t, SRES_HENTRY_HASH);

static
void 
sres_store(sres_resolver_t *res, sres_record_t *rr)
{
  sres_rr_hash_entry_t **rr_iter, *rr_hash_entry;
  unsigned hash;

  if (rr == NULL)
    return;

  if (sres_htable_is_full(res->res_cache))
    sres_htable_resize(res->res_home, res->res_cache, 0);

  hash = sres_hash_key(rr->sr_name);

  for (rr_iter = sres_htable_hash(res->res_cache, hash);
       (rr_hash_entry = *rr_iter); 
       rr_iter = sres_htable_next(res->res_cache, rr_iter)) {
    sres_record_t *or = rr_hash_entry->rr;

    if (or == NULL)
      continue;
    if (rr_hash_entry->rr_hash_key != hash)
      continue;
    if (or->sr_type != rr->sr_type)
      continue;
    if (!!or->sr_name != !!rr->sr_name)
      continue;
    if (or->sr_name != rr->sr_name && 
	strcasecmp(or->sr_name, rr->sr_name) != 0)
      continue;
    if (rr->sr_type != sres_type_soa /* There can be only one */
	&& sres_record_compare(or, rr))
      continue;
    
    /* There was an old entry in the cache.. Zap it, replace this with it */
    rr_hash_entry->rr_received = res->res_now;
    rr_hash_entry->rr = rr;
    rr->sr_refcount++;
    
    _sres_free_answer(res, or);
    return;
  }

  rr_hash_entry = su_zalloc(res->res_home, sizeof(*rr_hash_entry));
  if (rr_hash_entry) {
    rr_hash_entry->rr_hash_key = hash;
    rr_hash_entry->rr_received = res->res_now;
    rr_hash_entry->rr = rr;
    rr->sr_refcount++;

    res->res_cache->ht_used++;
  }
  
  *rr_iter = rr_hash_entry;
}

/** Calculate a hash key for a string */
static
unsigned
sres_hash_key(const char *string)
{
  unsigned int result = 0;
  
  while (string && *string)
    result = result * 797 + (unsigned char) * (string++);

  if (result == 0)
    result--;

  return result;
}

/* Message processing primitives */

static
void
m_put_uint16(sres_message_t *m, 
	     uint16_t h)
{
  uint8_t *p;

  if (m->m_error)
    return;

  p = m->m_data + m->m_offset;
  m->m_offset += sizeof h;

  if (m->m_offset > m->m_size) {
    m->m_error = "message size overflow";
    return;
  }

  p[0] = h >> 8; p[1] = h;
}

static
void 
m_put_uint32(sres_message_t *m, 
	     uint32_t w)
{
  uint8_t *p;

  if (m->m_error)
    return;

  p = m->m_data + m->m_offset;
  m->m_offset += sizeof w;

  if (m->m_offset > m->m_size) {
    m->m_error = "message size overflow";
    return;
  }

  p[0] = w >> 24; p[1] = w >> 16; p[2] = w >> 8; p[3] = w;
}

/*
 * Put domain into query
 */
static
uint16_t
m_put_domain(sres_message_t *m,
	     char const *domain, 
	     uint16_t top,
	     char const *topdomain)
{
  char const *label;
  uint16_t llen;

  if (m->m_error)
    return top;

  /* Copy domain into query label at a time */
  for (label = domain; label && label[0]; label += llen) {
    if (label[0] == '.' && label[1] != '\0') {
      m->m_error = "empty label";
      return 0;
    }

    llen = strcspn(label, ".");

    if (llen >= 64) {
      m->m_error = "too long label";
      return 0;
    }
    if (m->m_offset + llen + 1 > m->m_size) {
      m->m_error = "message size overflow";
      return 0;
    }

    m->m_data[m->m_offset++] = llen;
    memcpy(m->m_data + m->m_offset, label, llen);
    m->m_offset += llen;

    if (label[llen] == '\0')
      break;
    if (llen == 0)
      return top;
    if (label[llen + 1])
      llen++;
  }

  if (top) {
    m_put_uint16(m, 0xc000 | top);
    return top;
  }
  else if (topdomain) {
    uint16_t retval = m->m_offset;
    m_put_domain(m, topdomain, 0, NULL);
    return retval;
  }
  else if (m->m_offset < m->m_size)
    m->m_data[m->m_offset++] = '\0';
  else
    m->m_error = "message size overflow";

  return 0;
}

static
uint32_t
m_get_uint32(sres_message_t *m)
{
  uint8_t const *p = m->m_data + m->m_offset;

  if (m->m_error)
    return 0;

  m->m_offset += 4;

  if (m->m_offset > m->m_size) {
    m->m_error = "truncated message";
    return 0;
  }

  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static
uint16_t 
m_get_uint16(sres_message_t *m)
{
  uint8_t const *p = m->m_data + m->m_offset;

  if (m->m_error)
    return 0;

  m->m_offset += 2;

  if (m->m_offset > m->m_size) {
    m->m_error = "truncated message";
    return 0;
  }

  return (p[0] << 8) | p[1];
}

static
uint8_t 
m_get_uint8(sres_message_t *m)
{
  uint8_t const *p = m->m_data + m->m_offset;

  if (m->m_error)
    return 0;

  m->m_offset += 1;

  if (m->m_offset > m->m_size) {
    m->m_error = "truncated message";
    return 0;
  }

  return p[0];
}

/**
 * Get a string.
 */
static
int 
m_get_string(char *d, 
	     int n,
	     sres_message_t *m)
{
  uint8_t size;
  uint8_t *p = m->m_data;

  if (m->m_error)
    return 0;

  size = p[m->m_offset++];
  
  if (size + m->m_offset >= m->m_size) {
    m->m_error = "truncated message";
    return size;
  }

  m->m_offset += size;

  if (n == 0 || d == NULL)
    return size;

  memcpy(d, p + m->m_offset - size, size < n ? size : n);

  if (size < n)
    d[size] = '\0';		/* NUL terminate */

  return size;
}

/**
 * Uncompress a domain.
 */
static
int 
m_get_domain(char *d, 
	     int n,
	     sres_message_t *m,
	     int indirected)
{
  uint8_t cnt;
  int i = 0;
  uint8_t *p = m->m_data;
  uint16_t offset = m->m_offset;
  uint16_t new_offset;

  if (m->m_error)
    return 0;

  if (d == NULL) 
    n = 0;

  while ((cnt = p[offset++])) {
    if (cnt >= 0xc0) {
      if (offset >= m->m_size) {
        m->m_error = "truncated message";
        return 0;
      }

      new_offset = ((cnt & 0x3F) << 8) + p[offset++];

      if (!indirected)
        m->m_offset = offset;

      if (new_offset <= 0 || new_offset >= m->m_size) {
        m->m_error = "invalid domain compression";
        return 0;
      }

      offset = new_offset;
      indirected = 1;
    } 
    
    else {
      if (offset + cnt >= m->m_size) {
        m->m_error = "truncated message";
        return 0;
      }
      if (i + cnt + 1 < n) {
        memcpy(d + i, p + offset, cnt);
        d[i + cnt] = '.';
      }

      i += cnt + 1;
      offset += cnt;
    }  
  }

  if (i == 0) { 
    if (i < n) 
      d[i] = '.'; i++; 
  }

  if (i < n)
    d[i] = '\0';

  if (!indirected)
    m->m_offset = offset;

  return i;
}

/* ====================================================================== */
/* Glue functions for Sofia root (reactor) */
#if HAVE_SU_WAIT_H

#define TAG_NAMESPACE "sres"

#include <su_tag_class.h>
#include <su_tagarg.h>

tag_typedef_t srestag_resolv_conf = STRTAG_TYPEDEF(resolv_conf);
tag_typedef_t srestag_resolv_conf_ref = REFTAG_TYPEDEF(srestag_resolv_conf);

typedef struct sres_sofia_s {
  sres_resolver_t *srs_resolver;
  su_root_t  	  *srs_root;
  su_timer_t 	  *srs_timer;
  su_wait_t  	   srs_wait[1];
  int              srs_index;
  int        	   srs_socket;
} sres_sofia_t;

static void sres_sofia_timer(su_root_magic_t *magic, 
			     su_timer_t *t,
			     sres_sofia_t *arg);

static int sres_sofia_poll(su_root_magic_t *, su_wait_t *, sres_sofia_t *);

/**Create a resolver.
 *
 * The function sres_resolver_create() is used to allocate and initialize
 * the resolver object using the Sofia asynchronous reactor #su_root_t.
 */
sres_resolver_t *
sres_resolver_create(su_root_t *root, 
		     char const *conf_file_path,
		     tag_type_t tag, tag_value_t value, ...)
{
  sres_resolver_t *res;
  sres_sofia_t *srs;
  ta_list ta;

  if (root == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ta_start(ta, tag, value);
  tl_gets(ta_args(ta),
	  SRESTAG_RESOLV_CONF_REF(conf_file_path),
	  TAG_END());
  ta_end(ta);

  res = sres_resolver_new(conf_file_path);
  srs = res ? su_zalloc(res->res_home, sizeof *srs) : NULL;

  if (res && srs) {
    su_wait_t *wait = srs->srs_wait;
    int idx;

    sres_resolver_set_userdata(res, srs);

    srs->srs_resolver = res;
    srs->srs_index = -1, srs->srs_socket = -1;
    srs->srs_root = root;
    srs->srs_timer = su_timer_create(su_root_task(root), 
				     SRES_RETRANSMIT_INTERVAL);
    if (su_timer_run(srs->srs_timer, sres_sofia_timer, srs) < 0) {
      SU_DEBUG_3(("sres: cannot create timer\n"));
      sres_resolver_destroy(res);
      return NULL;
    }

    if (sres_resolver_sockets(res, &srs->srs_socket, 1) == -1) {
      SU_DEBUG_3(("sres: socket: %s", su_strerror(su_errno())));
    }
    else if (su_wait_create(wait, srs->srs_socket, SU_WAIT_IN | SU_WAIT_ERR) 
	     == -1) {
      SU_DEBUG_3(("sres: su_wait_create: %s\n", su_strerror(su_errno())));
    } 
    else if ((idx = su_root_register(srs->srs_root, srs->srs_wait, 
				     sres_sofia_poll, srs, 
				     0)) == -1) {
      SU_DEBUG_3(("sres: su_root_register: %s\n", su_strerror(su_errno())));
    }
    else {
      srs->srs_index = idx;
      return res;		/* success */
    }
    
    su_wait_destroy(wait);
    sres_resolver_destroy(res);

    return NULL;
  }

  return res;
}

/** Destroy a resolver object. */
void 
sres_resolver_destroy(sres_resolver_t *res)
{
  sres_sofia_t *srs = sres_resolver_get_userdata(res);
  
  if (srs) {
    assert(srs->srs_resolver->res_refcount == 1);

    if (srs->srs_index != -1)
      su_root_deregister(srs->srs_root, srs->srs_index);

    if (srs->srs_socket != -1)
      su_close(srs->srs_socket), srs->srs_socket = -1;

    su_timer_destroy(srs->srs_timer), srs->srs_timer = NULL;

    sres_resolver_unref(srs->srs_resolver); 
  }
}

int sres_resolver_root_socket(sres_resolver_t *res)
{
  sres_sofia_t *srs = sres_resolver_get_userdata(res);

  if (srs) 
    return srs->srs_socket;

  errno = EINVAL;
  return -1;
}


/** Sofia timer wrapper. */
static 
void 
sres_sofia_timer(su_root_magic_t *magic, su_timer_t *t, sres_sofia_t *srs)
{
  sres_resolver_timer(srs->srs_resolver, srs->srs_socket);
}

/** Sofia poll/select wrapper */
static 
int 
sres_sofia_poll(su_root_magic_t *magic, 
		su_wait_t *w, 
		sres_sofia_t *srs)
{
  int retval = 0;
  int events = su_wait_events(w, srs->srs_socket);

  if (events & SU_WAIT_ERR)
    retval = sres_resolver_error(srs->srs_resolver, srs->srs_socket);
  else if (events & SU_WAIT_IN)
    retval = sres_resolver_receive(srs->srs_resolver, srs->srs_socket);

  return retval;
}

sres_query_t *
sres_query(sres_resolver_t *res,
	   sres_answer_f *callback,
	   sres_context_t *context,
	   uint16_t type,
	   char const *domain)
{
  sres_sofia_t *srs = sres_resolver_get_userdata(res);
  
  if (srs) {
    return sres_query_make(res, callback, context, 
			   srs->srs_socket,
			   type, domain);
  }
     
  errno = EINVAL;
  return NULL;
}

/** Make a reverse DNS query.
 *
 * The function sres_query_sockaddr() sends a query with specified @a type
 * and domain name formed from the socket address @a addr. The sres resolver
 * takes care of retransmitting the query, and generating an error record
 * with nonzero status if no response is received.
 *
 */
sres_query_t *
sres_query_sockaddr(sres_resolver_t *res,
		    sres_answer_f *callback,
		    sres_context_t *context,
		    uint16_t type,
		    struct sockaddr const *addr)
{
  sres_sofia_t *srs = sres_resolver_get_userdata(res);
  
  if (srs) {
    return sres_query_make_sockaddr(res, callback, context, 
				    srs->srs_socket,
				    type, addr);
  }

  errno = EINVAL;
  return NULL;
}

#endif /* Glue functions for Sofia root (reactor) */
