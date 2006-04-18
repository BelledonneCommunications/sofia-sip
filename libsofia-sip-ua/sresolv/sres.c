/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2006 Nokia Corporation.
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

/**@CFILE sres.c
 * @brief Sofia DNS Resolver implementation.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Teemu Jalava <Teemu.Jalava@nokia.com>
 * @author Mikko Haataja
 *
 * @todo The resolver should allow handling arbitrary records, too.
 */

#include "config.h"

#if HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#else
#if defined(_WIN32)
typedef _int8 int8_t;
typedef unsigned _int8 uint8_t;
typedef unsigned _int16 uint16_t;
typedef unsigned _int32 uint32_t;
#endif
#endif

#if HAVE_NETINET_IN_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_WINSOCK2_H
#include <winsock2.h>
#include <ws2tcpip.h>
#if HAVE_SIN6
#include <tpipv6.h>
#else
struct sockaddr_storage {
    short ss_family;
    char ss_pad[126];
};
#endif
#else
#define closesocket(s) close(s)
#endif

#include <time.h>

#include "sofia-resolv/sres.h"
#include "sofia-resolv/sres_cache.h"
#include "sofia-resolv/sres_record.h"
#include "sofia-resolv/sres_async.h"

#include <sofia-sip/su_alloc.h>
#include <sofia-sip/su_strlst.h>
#include <sofia-sip/su_errno.h>

#include "sofia-sip/htable.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <limits.h>

#include <assert.h>

#if defined(va_copy)
#elif defined(__va_copy)
#define va_copy(dst, src) __va_copy((dst), (src))
#else
#define va_copy(dst, src) (memcpy(&(dst), &(src), sizeof (va_list)))
#endif

void sres_cache_clean(sres_cache_t *cache, time_t now);

typedef struct sres_message    sres_message_t;
typedef struct sres_config     sres_config_t;
typedef struct sres_server     sres_server_t;
typedef struct sres_nameserver sres_nameserver_t;

/** EDNS0 support */
enum edns { 
  edns_not_tried = -1,
  edns_not_supported = 0,
  edns0_supported = 1
};

struct sres_server {
  int                     dns_socket;

  char                    dns_name[48];     /**< Server name */
  struct sockaddr_storage dns_addr[1];  /**< Server node address */
  ssize_t                 dns_addrlen;  /**< Size of address */

  enum edns               dns_edns;	/**< Server supports edns. */

  /** ICMP/temporary error received, zero when successful. */
  time_t                  dns_icmp;
  /** Persisten error, zero when successful. */
  time_t                  dns_error;
};

HTABLE_DECLARE(sres_qtable, qt, sres_query_t);

struct sres_resolver_s {
  su_home_t           res_home[1];

  void               *res_userdata;
  sres_cache_t       *res_cache;

  time_t              res_now;
  sres_qtable_t       res_queries[1];   /**< Table of active queries */

  char const         *res_cnffile;      /**< Configuration file name */
  char const        **res_options;      /**< Option strings */

  sres_config_t      *res_config;
  time_t              res_checked;

  unsigned long       res_updated;
  sres_update_f      *res_updcb;
  sres_async_t       *res_async;
  short               res_update_all;

  uint16_t            res_id;
  short               res_i_server;  /**< Current server to try 
					(when doing round-robin) */
  short               res_n_servers; /**< Number of servers */
  sres_server_t     **res_servers;
};


struct sres_config {
  su_home_t c_home[1];

  time_t c_update;
  time_t c_modified;
  char const *c_filename;

  /** domain and search */
  char const *c_search[1 + SRES_MAX_SEARCH + 1];

  /** nameserver */
  struct sres_nameserver {
    struct sockaddr_storage ns_addr[1];
    ssize_t ns_addrlen;
  } *c_nameservers[SRES_MAX_NAMESERVERS + 1];

  /** sortlist */
  struct sres_sortlist {
    struct sockaddr_storage addr[1];
    ssize_t addrlen;
    char const *name;
  } *c_sortlist[SRES_MAX_SORTLIST + 1];

  uint16_t    c_port;	     /**< Server port to use */

  /** options */
  struct sres_options {
    uint16_t timeout;
    uint16_t attempts;
    uint16_t ndots;
    unsigned debug:1;
    unsigned rotate:1;
    unsigned check_names:1;
    unsigned inet6:1;
    unsigned ip6int:1;
    unsigned ip6bytestring:1;
  } c_opt;
};

struct sres_query_s {
  hash_value_t    q_hash;
  sres_resolver_t*q_res;
  sres_answer_f  *q_callback;
  sres_context_t *q_context;
  char           *q_name;
  time_t          q_timestamp;
  uint16_t        q_type;
  uint16_t        q_class;
  uint16_t        q_id;			/**< If nonzero, not answered */
  uint16_t        q_retry_count;
  uint8_t         q_n_servers;
  uint8_t         q_i_server;
  int8_t          q_edns;
  uint8_t         q_n_subs;
  sres_query_t   *q_subqueries[1 + SRES_MAX_SEARCH];
  sres_record_t **q_subanswers[1 + SRES_MAX_SEARCH];
};


struct sres_message {
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

HTABLE_PROTOS(sres_qtable, qt, sres_query_t);

#define CHOME(cache) ((su_home_t *)(cache))

/** Get address from sockaddr storage. */
#if HAVE_SIN6
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

static sres_server_t **sres_servers_new(sres_resolver_t *res,
				       sres_config_t const *c);

/** Generate new 16-bit identifier for DNS query. */
static uint16_t
sres_new_id(sres_resolver_t *res)
{
  return res->res_id ? res->res_id++ : (res->res_id = 2, 1);
}

/** Return true if we have a search list or a local domain name. */
static int 
sres_has_search_domain(sres_resolver_t *res) 
{
  return res->res_config->c_search[0] != NULL;
}

static void sres_resolver_destructor(void *);

sres_resolver_t *
sres_resolver_new_with_cache_va(char const *conf_file_path,
				sres_cache_t *cache,
				char const *options, 
				va_list va);
static
sres_resolver_t *
sres_resolver_new_internal(char const *conf_file_path,
			   sres_cache_t *cache,
			   char const **options);

static void sres_servers_unref(sres_resolver_t *res,
			       sres_server_t **servers);

static int sres_servers_count(sres_server_t * const *servers);

static int sres_server_socket(sres_resolver_t *res, sres_server_t *dns);

static sres_query_t * sres_query_alloc(sres_resolver_t *res,
				       sres_answer_f *callback,
				       sres_context_t *context,
				       uint16_t type,
				       char const * domain);

static void sres_free_query(sres_resolver_t *res, sres_query_t *q);

static 
int sres_sockaddr2string(sres_resolver_t *, 
			 char name[], size_t namelen, 
			 struct sockaddr const *);

static 
sres_config_t *sres_parse_resolv_conf(sres_resolver_t *res);

static
sres_server_t *sres_next_server(sres_resolver_t *res, 
				int *in_out_i,
				int timeout);

static
int sres_send_dns_query(sres_resolver_t *res, sres_query_t *q);

static 
void sres_answer_subquery(sres_context_t *context, 
			  sres_query_t *query,
			  sres_record_t **answers);

static
void sres_query_report_error(sres_query_t *q,
			     sres_record_t **answers);

static void
sres_resend_dns_query(sres_resolver_t *res, sres_query_t *q, int timeout);

static 
sres_server_t *sres_server_by_socket(sres_resolver_t const *ts, int socket);

static
int sres_resolver_report_error(sres_resolver_t *res, 
			       int socket,
			       int errcode,
			       struct sockaddr_storage *remote,
			       socklen_t remotelen, 
			       char const *info);

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

static char const *sres_toplevel(char buf[], size_t bsize, char const *domain);

static sres_record_t *sres_create_record(sres_resolver_t *, sres_message_t *m);

static void sres_init_rr_soa(sres_resolver_t *res, sres_soa_record_t *rr,
			     sres_message_t *m);
static void sres_init_rr_a(sres_resolver_t *res, sres_a_record_t *rr,
			   sres_message_t *m);
static void sres_init_rr_a6(sres_resolver_t *res, sres_a6_record_t *rr,
			    sres_message_t *m);
static void sres_init_rr_aaaa(sres_resolver_t *res, sres_aaaa_record_t *rr,
			      sres_message_t *m);
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

/* ---------------------------------------------------------------------- */

#define SU_LOG sresolv_log

#include <sofia-sip/su_debug.h>

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

/** Internal errors */
enum {
  SRES_EDNS0_ERR = 255		/**< Server did not support EDNS. */
};

/* ---------------------------------------------------------------------- */

/**Create a resolver.
 *
 * Allocate and initialize a new sres resolver object. The resolver object
 * contains the parsed resolv.conf file, a cache object containing past
 * answers from DNS, and a list of active queries. The default resolv.conf
 * file can be overriden by giving the name of the configuration file as @a
 * conf_file_path.
 *
 * @param conf_file_path name of the resolv.conf configuration file 
 *
 * @return A pointer to a newly created sres resolver object, or NULL upon
 * an error.
 */
sres_resolver_t *
sres_resolver_new(char const *conf_file_path)
{
  return sres_resolver_new_internal(conf_file_path, NULL, NULL);
}

/** Copy a resolver.
 *
 * Make a copy of resolver with old
 */
sres_resolver_t *sres_resolver_copy(sres_resolver_t *res)
{
  char const *cnffile;
  sres_cache_t *cache;
  char const **options;

  if (!res)
    return NULL;

  cnffile = res->res_cnffile;
  cache = res->res_cache;
  options = res->res_options;

  return sres_resolver_new_internal(cnffile, cache, options);
}

/**Create a resolver.
 *
 * Allocate and initialize a new sres resolver object. The resolver object
 * contains the parsed resolv.conf file, a cache object containing past
 * answers from DNS, and a list of active queries. The default resolv.conf
 * file can be overriden by giving the name of the configuration file as @a
 * conf_file_path.
 *
 * It is also possible to override the values in the resolv.conf and
 * RES_OPTIONS by giving the directives in the NULL-terminated list.
 *
 * @param conf_file_path name of the resolv.conf configuration file 
 * @param cache          optional pointer to a resolver cache
 * @param options, ...   list of resolv.conf directives (overriding conf_file)
 *
 * @par Environment Variables
 * - LOCALDOMAIN overrides @c domain or @c search directives
 * - RES_OPTIONS overrides values of @a options in resolv.conf
 * - SRES_OPTIONS overrides values of @a options in resolv.conf, RES_OPTIONS,
 *   and @a options, ... list given as argument for this function
 *
 * @return A pointer to a newly created sres resolver object, or NULL upon
 * an error.
 */
sres_resolver_t *
sres_resolver_new_with_cache(char const *conf_file_path,
			     sres_cache_t *cache,
			     char const *option, ...)
{
  sres_resolver_t *retval;
  va_list va;
  va_start(va, option);
  retval = sres_resolver_new_with_cache_va(conf_file_path, cache, option, va);
  va_end(va);
  return retval;
}

/**Create a resolver.
 *
 * Allocate and initialize a new sres resolver object. 
 *
 * This is a stdarg version of sres_resolver_new_with_cache().
 */
sres_resolver_t *
sres_resolver_new_with_cache_va(char const *conf_file_path,
				sres_cache_t *cache,
				char const *option,
				va_list va)
{
  va_list va0;
  size_t i;
  char const *o, *oarray[16], **olist = oarray;
  sres_resolver_t *res;

  va_copy(va0, va);
  
  for (i = 0, o = option; o; o = va_arg(va0, char const *)) {
    if (i < 16)
      olist[i] = o;
    i++;
  }

  if (i >= 16) {
    olist = malloc((i + 1) * sizeof *olist);
    if (!olist)
      return NULL;
    for (i = 0, o = option; o; o = va_arg(va, char const *)) {
      olist[i++] = o;
      i++;
    }
  }
  olist[i] = NULL;
  res = sres_resolver_new_internal(conf_file_path, cache, olist);
  if (olist != oarray)
    free(olist);

  return res;
}

sres_resolver_t *
sres_resolver_new_internal(char const *conf_file_path,
			   sres_cache_t *cache,
			   char const **options)
{
  sres_resolver_t *res;
  size_t i, n, len;
  char **array, *o, *end;
 
  for (n = 0, len = 0; options && options[n]; n++)
    len += strlen(options[n]) + 1;

  res = su_home_new(sizeof(*res) + (n + 1) * (sizeof *options) + len);

  if (res == NULL)
    return NULL;

  array = (void *)(res + 1);
  o = (void *)(array + n + 1);
  end = o + len;

  for (i = 0; options && options[i]; i++)
    o = memccpy(array[i] = o, options[i], '\0', len - (end - o));
  assert(o == end);

  su_home_desctructor(res->res_home, sres_resolver_destructor);

  while (res->res_id == 0) {
#if HAVE_DEV_URANDOM
    int fd;
    if ((fd = open("/dev/urandom", O_RDONLY, 0)) != -1) {
      read(fd, &res->res_id, (sizeof res->res_id));
      close(fd);
    }
    else
#endif
    res->res_id = time(NULL);
  }

  time(&res->res_now);

  if (cache)
    res->res_cache = sres_cache_ref(cache);
  else
    res->res_cache = sres_cache_new(0);

  if (conf_file_path)
    res->res_cnffile = su_strdup(res->res_home, conf_file_path);
  else
    res->res_cnffile = conf_file_path = "/etc/resolv.conf";

  if (!res->res_cache || !res->res_cnffile) {
    perror("sres: malloc");
  }
  else if (sres_qtable_resize(res->res_home, res->res_queries, 0) < 0) {
    perror("sres: res_qtable_resize");
  }
  else if (sres_resolver_update(res, 1) < 0) {
    perror("sres: res_qtable_resize");
  }
  else {
    return res;
  }

  sres_resolver_unref(res);

  return NULL;
}

/** Create a new reference to resolver. */
sres_resolver_t *
sres_resolver_ref(sres_resolver_t *res)
{
  return su_home_ref(res->res_home);
}
		     
/** Decrease the reference count on a resolver object.  */
void
sres_resolver_unref(sres_resolver_t *res)
{
  su_home_unref(res->res_home);
}

/** Set userdata pointer.
 *
 * @return New userdata pointer.
 * 
 * @ERRORS
 * @ERROR EFAULT @a res points outside the address space
 */
void *
sres_resolver_set_userdata(sres_resolver_t *res, 
			   void *userdata)
{
  void *old;

  if (!res)
    return su_seterrno(EFAULT), (void *)NULL;

  old = res->res_userdata, res->res_userdata = userdata;

  return old;
}

/**Get userdata pointer.
 *
 * @return Userdata pointer.
 * 
 * @ERRORS
 * @ERROR EFAULT @a res points outside the address space
 */
void *
sres_resolver_get_userdata(sres_resolver_t const *res)
{
  if (res == NULL)
    return su_seterrno(EFAULT), (void *)NULL;
  else
    return res->res_userdata;
}

/** Set async object.
 *
 * @return Set async object.
 * 
 * @ERRORS
 * @ERROR EFAULT @a res points outside the address space
 * @ERROR EALREADY different async callback already set
 */
sres_async_t *
sres_resolver_set_async(sres_resolver_t *res,
			sres_update_f *callback,
			sres_async_t *async, 
			int update_all)
{
  if (!res)
    return su_seterrno(EFAULT), (void *)NULL;

  if (res->res_updcb && res->res_updcb != callback)
    return su_seterrno(EALREADY), (void *)NULL;
    
  res->res_async = async;
  res->res_updcb = callback;
  res->res_update_all = callback && update_all != 0;

  return async;
}

sres_async_t *
sres_resolver_get_async(sres_resolver_t const *res,
			sres_update_f *callback)
{
  if (res == NULL || res->res_updcb != callback)
    return su_seterrno(EFAULT), (void *)NULL;
  else
    return res->res_async;
}

/** Make a DNS query.
 *
 * Sends a DNS query with specified @a type and @a domain to the DNS server. 
 * The sres resolver takes care of retransmitting the query if
 * sres_resolver_timer() is called in regular intervals. It generates an
 * error record with nonzero status if no response is received.
 *
 * @sa sres_blocking_query(), sres_query_make()
 */
sres_query_t *
sres_query(sres_resolver_t *res,
	   sres_answer_f *callback,
	   sres_context_t *context,
	   uint16_t type,
	   char const *domain)
{
  sres_query_t *query = NULL;
  size_t dlen;
  int enough_dots;

  SU_DEBUG_9(("sres_query() called\n"));

  if (res == NULL || domain == NULL)
    return su_seterrno(EFAULT), (void *)NULL;

  dlen = strlen(domain);
  if (dlen > SRES_MAXDNAME ||
      (dlen == SRES_MAXDNAME && domain[dlen - 1] != '.')) {
    su_seterrno(ENAMETOOLONG);
    return NULL;
  }

  enough_dots = strchr(domain, '.') != NULL;

  sres_resolver_update(res, 0);

  query = sres_query_alloc(res, callback, context, type, domain);

  if (query) {
    /* Create sub-query for each search domain */
    if (sres_has_search_domain(res) && !enough_dots) {
      sres_query_t *sub;
      int i, subs, len;
      char const **domains = res->res_config->c_search;
      char search[SRES_MAXDNAME + 1];

      memcpy(search, domain, dlen);
      search[dlen++] = '.';
      search[dlen] = '\0';

      for (i = 0, subs = 0; i <= SRES_MAX_SEARCH; i++) {
	if (domains[i]) {
	  len = strlen(domains[i]);
	  
	  if (dlen + len + 1 > SRES_MAXDNAME)
	    continue;

	  memcpy(search + dlen, domains[i], len);
	  search[dlen + len] = '.';
	  search[dlen + len + 1] = '\0';
	  sub = sres_query_alloc(res, sres_answer_subquery, (void *)query,
				 type, search);

	  if (sres_send_dns_query(res, sub) == 0) {
	    query->q_subqueries[i] = sub;
	  }
	  else {
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

  return query;
}

/** Make a reverse DNS query.
 *
 * Send a query to DNS server with specified @a type and domain name formed
 * from the socket address @a addr. The sres resolver takes care of
 * retransmitting the query if sres_resolver_timer() is called in regular
 * intervals. It generates an error record with nonzero status if no
 * response is received.
 */
sres_query_t *
sres_query_sockaddr(sres_resolver_t *res,
		    sres_answer_f *callback,
		    sres_context_t *context,
		    uint16_t type,
		    struct sockaddr const *addr)
{
  char name[80]; 

  if (!res || !addr)
    return su_seterrno(EFAULT), (void *)NULL;

  if (!sres_sockaddr2string(res, name, sizeof(name), addr))
    return NULL;

  return sres_query(res, callback, context, type, name);
}


/** Make a DNS query.
 *
 * Sends a DNS query with specified @a type and @a domain to the DNS server. 
 * The sres resolver takes care of retransmitting the query if
 * sres_resolver_timer() is called in regular intervals. It generates an
 * error record with nonzero status if no response is received.
 *
 * This function just makes sure that we have the @a socket is valid,
 * otherwise it behaves exactly like sres_query().
 */
sres_query_t *
sres_query_make(sres_resolver_t *res,
		sres_answer_f *callback,
		sres_context_t *context,
		int socket,
		uint16_t type,
		char const *domain)
{
  if (socket == -1)
    return errno = EINVAL, NULL;

  return sres_query(res, callback, context, type, domain);
}

/** Make a reverse DNS query.
 *
 * Send a query to DNS server with specified @a type and domain name formed
 * from the socket address @a addr. The sres resolver takes care of
 * retransmitting the query if sres_resolver_timer() is called in regular
 * intervals. It generates an error record with nonzero status if no
 * response is received.
 *
 * This function just makes sure that we have the @a socket is valid,
 * otherwise it behaves exactly like sres_query_sockaddr().
 */
sres_query_t *
sres_query_make_sockaddr(sres_resolver_t *res,
			 sres_answer_f *callback,
			 sres_context_t *context,
			 int socket,
			 uint16_t type,
			 struct sockaddr const *addr)
{
  char name[80]; 

  if (!res || !addr)
    return su_seterrno(EFAULT), (void *)NULL;

  if (socket == -1)
    return errno = EINVAL, NULL;

  if (!sres_sockaddr2string(res, name, sizeof(name), addr))
    return NULL;

  return sres_query_make(res, callback, context, socket, type, name);
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
 * @return
 * pointer to an array of pointers to cached records, or
 * NULL if no entry was found.
 *
 * @ERRORS
 * @ERROR ENAMETOOLONG @a domain is longer than SRES_MAXDNAME
 * @ERROR ENOENT no cached records were found
 * @ERROR EFAULT @a res or @a domain point outside the address space
 * @ERROR ENOMEM memory exhausted
 */
sres_record_t **
sres_cached_answers(sres_resolver_t *res,
		    uint16_t type,
		    char const *domain)
{
  sres_record_t **result;
  char rooted_domain[SRES_MAXDNAME];

  if (!res)
    return su_seterrno(EFAULT), (void *)NULL;

  domain = sres_toplevel(rooted_domain, sizeof rooted_domain, domain);

  if (!domain)
    return NULL;
  
  if (!sres_cache_get(res->res_cache, type, domain, &result))
    su_seterrno(ENOENT), (void *)NULL;

  return result;
}

/**Get a list of matching (type/domain) records from cache.
 *
 * 
 *
 * @retval 
 * pointer to an array of pointers to cached records, or
 * NULL if no entry was found.
 *
 * @ERRORS
 * @ERROR EAFNOSUPPORT address family specified in @a addr is not supported
 * @ERROR ENOENT no cached records were found
 * @ERROR EFAULT @a res or @a addr point outside the address space
 * @ERROR ENOMEM memory exhausted
 */
sres_record_t **
sres_cached_answers_sockaddr(sres_resolver_t *res,
			     uint16_t type,
			     struct sockaddr const *addr)
{
  sres_record_t **result;
  char name[80];

  if (!res || !addr)
    return su_seterrno(EFAULT), (void *)NULL;

  if (!sres_sockaddr2string(res, name, sizeof name, addr))
    return NULL;

  if (!sres_cache_get(res->res_cache, type, name, &result))
    su_seterrno(ENOENT), (void *)NULL;

  return result;
}

/** Sort answers. */
int
sres_sort_answers(sres_resolver_t *res, sres_record_t **answers)
{
  int i, j;

  if (res == NULL || answers == NULL)
    return su_seterrno(EFAULT);

  if (answers[0] == NULL || answers[1] == NULL)
    return 0;

  /* Simple insertion sorting */
  /*
   * We do not use qsort because we want later extend this to sort 
   * local A records first etc.
   */
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

  return 0;
}

/** Sort and filter query results */
int
sres_filter_answers(sres_resolver_t *res, 
		    sres_record_t **answers, 
		    uint16_t type)
{		    
  int i, n;

  for (n = 0, i = 0; answers && answers[i]; i++) {
    if (answers[i]->sr_record->r_status ||
	answers[i]->sr_record->r_class != sres_class_in ||
	(type != 0 && answers[i]->sr_record->r_type != type)) {
      sres_free_answer(res, answers[i]);
      continue;
    }
    answers[n++] = answers[i];
  }
  answers[n] = NULL;

  sres_sort_answers(res, answers);

  return n;
}


/** Free and zero one record. */
void sres_free_answer(sres_resolver_t *res, sres_record_t *answer)
{
  if (res && answer)
    sres_cache_free_one(res->res_cache, answer);
}

void 
sres_free_answers(sres_resolver_t *res,
		  sres_record_t **answers)
{
  if (res && answers)
    sres_cache_free_answers(res->res_cache, answers);
}

/* ---------------------------------------------------------------------- */
/* Private functions */

static 
void 
sres_resolver_destructor(void *arg)
{
  sres_resolver_t *res = arg;

  assert(res);
  sres_cache_unref(res->res_cache); 
  res->res_cache = NULL;

  sres_servers_unref(res, res->res_servers);

  if (res->res_updcb)
    res->res_updcb(res->res_async, -1, -1);
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
    query->q_type = type;
    query->q_class = sres_class_in;
    query->q_timestamp = res->res_now;
    query->q_name = strcpy((char *)(query + 1), domain);

    query->q_id = sres_new_id(res); assert(query->q_id);
    query->q_i_server = res->res_i_server;
    query->q_n_servers = res->res_n_servers;
    query->q_hash = query->q_id * Q_PRIME /* + query->q_i_server */;
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
      sres_cache_free_answers(res->res_cache, q->q_subanswers[i]);
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
  case sres_type_a6:
    {
      sres_a6_record_t const *A = aa->sr_a6, *B = bb->sr_a6;
      D = A->a6_prelen - B->a6_prelen; if (D) return D;
      D = !A->a6_prename - !B->a6_prename; 
      if (D == 0 && A->a6_prename && B->a6_prename)
	D = strcasecmp(A->a6_prename, B->a6_prename); if (D) return D;
      return memcmp(&A->a6_suffix, &B->a6_suffix, sizeof A->a6_suffix);
    }
  case sres_type_aaaa:
    {
      sres_aaaa_record_t const *A = aa->sr_aaaa, *B = bb->sr_aaaa;
      return memcmp(&A->aaaa_addr, &B->aaaa_addr, sizeof A->aaaa_addr);      
    }
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
sres_sockaddr2string(sres_resolver_t *res,
		     char name[],
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
    char *postfix;
    int required;
    int i;

    if (res->res_config->c_opt.ip6int)
      postfix = "ip6.int.";
    else
      postfix = "ip6.arpa.";

    required = addrsize * 4 + strlen(postfix);

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
    
    strcpy(name + 4 * i, postfix);

    return required;
  }
#endif
  else {
    su_seterrno(EAFNOSUPPORT);
    SU_DEBUG_3(("%s: %s\n", "sres_sockaddr2string", 
                su_strerror(EAFNOSUPPORT)));
    return 0;
  }
}

/** Make a domain name a top level domain name.
 *
 * The function sres_toplevel() returns a copies string @a domain and 
 * terminates it with a dot if it is not already terminated. 
 */
static
char const *
sres_toplevel(char buf[], size_t blen, char const *domain)
{
  size_t len;
  int already;

  if (!domain)
    return su_seterrno(EFAULT), (void *)NULL;

  len = strlen(domain);

  if (len >= blen)
    return su_seterrno(ENAMETOOLONG), (void *)NULL;

  already = len > 0 && domain[len - 1] == '.';

  if (already)
    return domain;

  if (len + 1 >= blen)
    return su_seterrno(ENAMETOOLONG), (void *)NULL;

  strcpy(buf, domain);
  buf[len] = '.'; buf[len + 1] = '\0';

  return buf;
}

/* ---------------------------------------------------------------------- */

static int sres_parse_config(sres_config_t *, FILE *);
static int sres_parse_options(sres_config_t *c, char const *value);
static int sres_parse_nameserver(sres_config_t *c, char const *server);
static time_t sres_config_timestamp(sres_config_t const *c);

/** Update configuration
 *
 */
int sres_resolver_update(sres_resolver_t *res, int always)
{
  sres_config_t *previous, *c = NULL;
  sres_server_t **servers, **old_servers;

  previous = res->res_config;

  time(&res->res_now);

  if (!always && previous && 
      (res->res_now < previous->c_update ||
       sres_config_timestamp(previous) == previous->c_modified)) {
    return 0;
  }

  c = sres_parse_resolv_conf(res);
  if (!c)
    return -1;

  servers = sres_servers_new(res, c);
  if (!servers) {
    su_home_unref(c->c_home);
    return -1;
  }

  old_servers = res->res_servers;

  res->res_config = c;
  res->res_i_server = 0;
  res->res_n_servers = sres_servers_count(servers);
  res->res_servers = servers;

  c->c_update = res->res_now + 5; /* Do not try to read for 5 sec?  */
  
  sres_servers_unref(res, old_servers);
  su_home_unref(previous->c_home);

  return 0;
}

/** Parse /etc/resolv.conf file.
 *
 * @retval #sres_config_t structure when successful 
 * @retval NULL upon an error
 *
 * @todo The resolv.conf directives @b sortlist and options 
 *       are currently ignored.
 */
static 
sres_config_t *sres_parse_resolv_conf(sres_resolver_t *res)
{
  sres_config_t *c = su_home_clone(res->res_home, (sizeof *c));

  if (c) {
    FILE *f;

    f = fopen(c->c_filename = res->res_cnffile, "r");

    if (sres_parse_config(c, f) < 0)
      su_home_unref((void *)c), c = NULL;

    if (f)
      fclose(f);
  }

  return c;
}

static
int sres_parse_config(sres_config_t *c, FILE *f)
{
  su_home_t *home = c->c_home;
  int line;
  char const *localdomain;
  char *search = NULL, *domain = NULL;
  char buf[1025];
  int i;

  localdomain = getenv("LOCALDOMAIN");

  /* Default values */
  c->c_opt.ndots = 1;
  c->c_opt.check_names = 1;
  c->c_opt.timeout = SRES_RETRY_INTERVAL;
  c->c_opt.attempts = SRES_MAX_RETRY_COUNT;
  c->c_port = 53;

  if (f != NULL) {  
    for (line = 1; fgets(buf, sizeof(buf), f); line++) {
      int len;
      char *value, *b;

      /* Skip whitespace at the beginning ...*/
      b = buf + strspn(buf, " \t");

      /* ... and at the end of line */
      for (len = strlen(b); len > 0 && strchr(" \t\r\n", b[len - 1]); len--)
	;

      if (len == 0 || b[0] == '#') 	/* Empty line or comment */
	continue;

      b[len] = '\0';

      len = strcspn(b, " \t");
      value = b + len; value += strspn(value, " \t");

#define MATCH(token) (len == strlen(token) && strncasecmp(token, b, len) == 0)

      if (MATCH("nameserver")) {
	if (sres_parse_nameserver(c, value) < 0)
	  return -1;
      }
      else if (MATCH("domain")) {
	if (localdomain)
	  continue;
	if (search)
	  su_free(home, search), search = NULL;
	if (domain)
	  su_free(home, domain), domain = NULL;
	domain = su_strdup(home, value);
	if (!domain)
	  return -1;
      }
      else if (MATCH("search")) {
	if (localdomain)
	  continue;
	if (search) su_free(home, search), search = NULL;
	if (domain) su_free(home, domain), domain = NULL;
	search = su_strdup(home, value);
	if (!search)
	  return -1;
      }
      else if (MATCH("port")) {
	unsigned long port = strtoul(value, NULL, 10);
	if (port < 65536)
	  c->c_port = port;
      }
      else if (MATCH("options")) {
	sres_parse_options(c, value);
      }
    }
  }

  if (f) {
    struct stat st;
    if (stat(c->c_filename, &st) == 0)
      c->c_modified = st.st_mtime;
  }

  if (localdomain)
    c->c_search[0] = localdomain;
  else if (domain)
    c->c_search[0] = domain;
  else if (search) {
    for (i = 0; search[0] && i < SRES_MAX_SEARCH; i++) {
      c->c_search[i] = search;
      search += strcspn(search, " \t");
      if (*search) {
	*search++ = '\0';
	search += strspn(search, " \t");
      }
    }
  }

  sres_parse_options(c, getenv("RES_OPTIONS"));
    
  if (c->c_nameservers[0] == NULL)
    sres_parse_nameserver(c, "127.0.0.1");

  for (i = 0; c->c_nameservers[i] && i < SRES_MAX_NAMESERVERS; i++) {
    struct sockaddr_in *sin = (void *)c->c_nameservers[i]->ns_addr;
    sin->sin_port = htons(c->c_port);
  }

  return i;
}

static int 
sres_parse_options(sres_config_t *c, char const *options)
{
  char *value = su_strdup(c->c_home, options), *value0 = value;

  if (!value)
    return -1;

  while (value[0]) {
    int len;
    unsigned long n = 0;
    char const *b;

    b = value; 
    value += strcspn(value, " \t");
    if (*value)
      *value++ = '\0', value += strspn(value, " \t");
    len = strcspn(b, ":");

    if (b[len]) {
      len++;
      n = strtoul(b + len, NULL, 10);
      if (n > 65536) {
	SU_DEBUG_3(("sres: %s: invalid %s\n", c->c_filename, b));
	continue;
      }
    }
    
    if (MATCH("no-debug")) c->c_opt.debug = 0;
    else if (MATCH("debug")) c->c_opt.debug = 1;
    else if (MATCH("ndots:")) c->c_opt.ndots = n;
    else if (MATCH("timeout:")) c->c_opt.timeout = n;
    else if (MATCH("attempts:")) c->c_opt.attempts = n;
    else if (MATCH("no-rotate")) c->c_opt.rotate = 0;
    else if (MATCH("rotate")) c->c_opt.rotate = 1;
    else if (MATCH("no-check-names")) c->c_opt.check_names = 0;
    else if (MATCH("check-names")) c->c_opt.check_names = 1;
    else if (MATCH("no-inet6")) c->c_opt.inet6 = 0;
    else if (MATCH("inet6")) c->c_opt.inet6 = 1;
    else if (MATCH("no-ip6-dotint")) c->c_opt.ip6int = 0;
    else if (MATCH("ip6-dotint")) c->c_opt.ip6int = 1;
    else if (MATCH("no-ip6-bytestring")) c->c_opt.ip6bytestring = 0;
    else if (MATCH("ip6-bytestring")) c->c_opt.ip6bytestring = 1;
    else {
      SU_DEBUG_3(("sres: %s: unknown option %s\n", c->c_filename, b));
    }
  }

  su_free(c->c_home, value0);

  return 0;
}

static
int sres_parse_nameserver(sres_config_t *c, char const *server)
{
  sres_nameserver_t *ns;
  struct sockaddr *sa;
  int err, i;

  for (i = 0; i < SRES_MAX_NAMESERVERS; i++)
    if (c->c_nameservers[i] == NULL)
      break;

  if (i >= SRES_MAX_NAMESERVERS)
    return 0 /* Silently discard extra nameservers */;

  ns = su_zalloc(c->c_home, (sizeof *ns) + strlen(server) + 1);
  if (!ns)
    return -1;

  sa = (void *)ns->ns_addr;

#if HAVE_SIN6
  if (strchr(server, ':')) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
    memset(sa, 0, ns->ns_addrlen = sizeof *sin6);
    err = inet_pton(sa->sa_family = AF_INET6, server, &sin6->sin6_addr);
  } 
  else 
#endif
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      memset(sa, 0, ns->ns_addrlen = sizeof *sin);
      err = inet_pton(sa->sa_family = AF_INET, server, &sin->sin_addr);
    }

  if (err <= 0) {
    SU_DEBUG_3(("sres: nameserver %s: invalid address\n", server));
    su_free(c->c_home, ns);
    return 0;
  }

#if HAVE_SA_LEN
  sa->sa_len = ns->ns_addrlen;
#endif

  c->c_nameservers[i] = ns;

  return 1;
}

/** Get current timestamp of resolv.conf file */
static
time_t sres_config_timestamp(sres_config_t const *c)
{
  struct stat st;

  if (stat(c->c_filename, &st) == 0)
    return st.st_mtime;

  /** If the resolv.conf file does not exists, return old timestamp */
  return c->c_modified;		
}


/* ---------------------------------------------------------------------- */

/** Allocate new servers structure */
static
sres_server_t **sres_servers_new(sres_resolver_t *res,
				 sres_config_t const *c)
{
  sres_server_t **servers, *dns;
  sres_nameserver_t *ns;
  int N, i;
  size_t size;

  for (N = 0; c->c_nameservers[N] && N < SRES_MAX_NAMESERVERS; N++)
    ;

  size = (N + 1) * (sizeof *servers) + N * (sizeof **servers);

  servers = su_zalloc(res->res_home, size); if (!servers) return servers;
  dns = (void *)(servers + N + 1);
  for (i = 0; i < N; i++) {
    dns->dns_socket = -1;
    ns = c->c_nameservers[i];
    memcpy(dns->dns_addr, ns->ns_addr, dns->dns_addrlen = ns->ns_addrlen);
    inet_ntop(dns->dns_addr->ss_family, SS_ADDR(dns->dns_addr), 
	      dns->dns_name, sizeof dns->dns_name);
    dns->dns_edns = edns_not_tried;
    servers[i] = dns++;
  }

  return servers;
}

static
void sres_servers_unref(sres_resolver_t *res,
			sres_server_t **servers)
{
  int i;

  if (res == NULL || servers == NULL)
    return;

  for (i = 0; i < SRES_MAX_NAMESERVERS; i++) {
    if (!servers[i])
      break;

    if (servers[i]->dns_socket != -1) {
      if (res->res_updcb)
	res->res_updcb(res->res_async, -1, servers[i]->dns_socket);
      closesocket(servers[i]->dns_socket);
    }
  }

  su_free(res->res_home, servers);
}

static
int sres_servers_count(sres_server_t *const *servers)
{
  int i;

  if (!servers)
    return 0;

  for (i = 0; i < SRES_MAX_NAMESERVERS; i++) {
    if (!servers[i])
      break;
  }  

  return i;
}

static
int sres_server_socket(sres_resolver_t *res, sres_server_t *dns)
{
  int family = dns->dns_addr->ss_family;
  int s;

  if (dns->dns_socket != -1)
    return dns->dns_socket;

  s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (s == -1) {
    SU_DEBUG_1(("%s: %s: %s\n", "sres_server_socket", "socket",
		su_strerror(su_errno())));
    return s;
  }

#if HAVE_IP_RECVERR
  if (family == AF_INET || family == AF_INET6) {
    int const one = 1;
    if (setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0) {
      if (family == AF_INET)
	SU_DEBUG_3(("setsockopt(IPVRECVERR): %s\n", su_strerror(su_errno())));
    }
  }
#endif
#if HAVE_IPV6_RECVERR
  if (family == AF_INET6) {
    int const one = 1;
    if (setsockopt(s, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one)) < 0)
      SU_DEBUG_3(("setsockopt(IPV6_RECVERR): %s\n", su_strerror(su_errno())));
  }
#endif

  if (connect(s, (void *)dns->dns_addr, dns->dns_addrlen) < 0) {
    char ipaddr[64];

    if (family == AF_INET) {
      void *addr = &((struct sockaddr_in *)dns->dns_addr)->sin_addr;
      inet_ntop(family, addr, ipaddr, sizeof ipaddr);
    }
#if HAVE_SIN6
    else if (family == AF_INET6) {
      void *addr = &((struct sockaddr_in6 *)dns->dns_addr)->sin6_addr;
      inet_ntop(family, addr, ipaddr, sizeof ipaddr);
    }
#endif
    else
      snprintf(ipaddr, sizeof ipaddr, "<af=%u>", family);

    SU_DEBUG_1(("%s: %s: %s: %s:%u\n", "sres_server_socket", "connect",
		su_strerror(su_errno()),
		ipaddr, ntohs(((struct sockaddr_in *)dns->dns_addr)->sin_port)));
    closesocket(s);
    return -1;
  }
  
  if (res->res_updcb) {
    if (res->res_updcb(res->res_async, s, -1) < 0) {
      SU_DEBUG_1(("%s: %s: %s\n", "sres_server_socket", "update callback",
		  su_strerror(su_errno())));
      closesocket(s);
      return -1;
    }
  }

  dns->dns_socket = s;
  
  return s;
}

/* ---------------------------------------------------------------------- */

/** Send a query packet */
static 
int 
sres_send_dns_query(sres_resolver_t *res, 
		    sres_query_t *q)
{                        
  sres_message_t m[1];
  int i, i0, N = res->res_n_servers;
  int s, transient, error = 0;
  unsigned size, no_edns_size, edns_size;
  uint16_t id = q->q_id;
  uint16_t type = q->q_type;
  char const *domain = q->q_name;
  time_t now = res->res_now;
  sres_server_t **servers = res->res_servers, *dns;

  if (now == 0) time(&now);

  SU_DEBUG_9(("sres_send_dns_query(%p, %p) called\n", res, q));

  if (domain == NULL)
    return -1;
  if (servers == NULL)
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
    SU_DEBUG_3(("%s(): encoding: %s\n", "sres_send_dns_query", m->m_error));
    su_seterrno(EIO);
    return -1;
  }

  transient = 0;
  i = i0 = q->q_i_server; assert(i0 < N);

  for (dns = servers[i]; dns; dns = sres_next_server(res, &i, 0)) {
    /* If server supports EDNS, include EDNS0 record */
    q->q_edns = dns->dns_edns;
    /* 0 (no EDNS) or 1 (EDNS supported) additional data records */
    m->m_arcount = htons(q->q_edns != 0); 
    /* Size with or without EDNS record */
    size = q->q_edns ? edns_size : no_edns_size; 

    s = sres_server_socket(res, dns);

    /* Send the DNS message via the UDP socket */
    if (s != -1 && send(s, m->m_data, size, 0) == size)
      break;

    error = su_errno();
    dns->dns_icmp = now;
    /* EINVAL is returned if destination address is bad */
    if (transient++ < 3 && error != EINVAL && s != -1)
      continue;
    transient = 0;

    dns->dns_error = now;	/* Mark as a bad destination */
  }

  if (!dns) {
    /* All servers have reported errors */
    SU_DEBUG_5(("%s(): sendto: %s\n", "sres_send_dns_query",
		su_strerror(error)));
    return su_seterrno(error);
  }

  q->q_i_server = i;

  SU_DEBUG_5(("%s(%p, %p) id=%u %u? %s (to [%s]:%u)\n", 
	      "sres_send_dns_query",
	      res, q, id, type, domain, 
	      dns->dns_name, 
	      htons(((struct sockaddr_in *)dns->dns_addr)->sin_port)));

  return 0;
}


/** Select next server */
static
sres_server_t *sres_next_server(sres_resolver_t *res, 
				int *in_out_i,
				int timeout)
{
  int i, j, N;
  sres_server_t **servers;

  assert(res && in_out_i);

  N = res->res_n_servers;
  servers = res->res_servers;
  i = *in_out_i;

  assert(res->res_servers && res->res_servers[i]);
  
  /* Retry using another server? */
  for (j = (i + 1) % N; (j != i); j = (j + 1) % N) {
    if (servers[j]->dns_icmp == 0) {
      return *in_out_i = j, servers[j];
    }
  }

  for (j = (i + 1) % N; (j != i); j = (j + 1) % N) {
    if (servers[j]->dns_error == 0) {
      return *in_out_i = j, servers[j];
    }
  }

  if (timeout)
    return servers[i];
  
  return NULL;
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

  for (i = 0; i <= SRES_MAX_SEARCH; i++) {
    if (top->q_subqueries[i] == query)
      break;
  }
  assert(i <= SRES_MAX_SEARCH);
  if (i > SRES_MAX_SEARCH || top->q_n_subs == 0) {
    sres_free_answers(res, answers);
    return;
  }

  if (answers) {
    int j, k;
    for (j = 0, k = 0; answers[j]; j++) {
      if (answers[j]->sr_status)
	sres_free_answer(query->q_res, answers[j]);
      else
	answers[k++] = answers[j];
    }
    answers[k] = NULL;
    if (!answers[0])
      sres_free_answers(query->q_res, answers), answers = NULL;
  }

  top->q_subqueries[i] = NULL;
  top->q_subanswers[i] = answers;

  if (--top->q_n_subs == 0 && top->q_id == 0) {
    sres_query_report_error(top, NULL);
  };
}

/** Report sres error */
static void
sres_query_report_error(sres_query_t *q,
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

    SU_DEBUG_5(("sres(q=%p): reporting errors for %u %s\n",
		q, q->q_type, q->q_name));
 
    sres_remove_query(q->q_res, q, 1);
    (q->q_callback)(q->q_context, q, answers);
  }

  sres_free_query(q->q_res, q);
}

/** Resolver timer function.
 *
 * The function sresolver_timer() should be called in regular intervals. We
 * recommend calling it in 500 ms intervals.
 *
 * @param dummy argument for compatibility 
 */
void sres_resolver_timer(sres_resolver_t *res, int dummy)
{
  int i;
  sres_query_t *q;
  time_t now, retry_time;

  if (res == NULL)
    return;

  now = time(&res->res_now);

  SU_DEBUG_9(("sres_resolver_timer() called at %lu\n", (long) now));

  if (res->res_queries->qt_used) {
    /** Every time it is called it goes through all query structures, and
     * retransmits all the query messages, which have not been answered yet.
     */
    for (i = 0; i < res->res_queries->qt_size; i++) {
      q = res->res_queries->qt_table[i];
      
      if (!q)
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

  sres_cache_clean(res->res_cache, res->res_now);
}

/** Resend DNS query, report error if cannot resend any more. */
static void
sres_resend_dns_query(sres_resolver_t *res, sres_query_t *q, int timeout)
{
  int i, N;
  sres_server_t *dns;

  SU_DEBUG_9(("sres_resend_dns_query(%p, %p, %u) called\n",
	      res, q, timeout));
  
  N = res->res_n_servers;

  if (N && q->q_retry_count < SRES_MAX_RETRY_COUNT) {
    i = q->q_i_server;
    dns = sres_next_server(res, &i, timeout);

    if (dns) {
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
  
  sres_query_report_error(q, NULL);
}


/** Get a server by socket */
static 
sres_server_t *
sres_server_by_socket(sres_resolver_t const *res, int socket)
{
  int i;

  if (socket == -1)
    return NULL;

  for (i = 0; i < res->res_n_servers; i++) {
    if (socket == res->res_servers[i]->dns_socket)
      return res->res_servers[i];
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

static
int sres_no_update(sres_async_t *async, int new_socket, int old_socket)
{
  return 0;
}

/** Create connected sockets for resolver.
 *
 * @related sres_resolver_t
 */
int sres_resolver_sockets(sres_resolver_t *res,
			  int *return_sockets, 
			  int n)
{
  int s = -1, i, retval;

  if (!sres_resolver_set_async(res, sres_no_update,
			       (sres_async_t *)-1, 1))
    return -1;

  retval = res->res_n_servers; assert(retval <= SRES_MAX_NAMESERVERS);

  if (!return_sockets || n == 0)
    return retval;

  for (i = 0; i < retval && i < n;) {
    sres_server_t *dns = res->res_servers[i];

    s = sres_server_socket(res, dns);
    return_sockets[i++] = s;
  }

  return retval;
}

#if 0
/** Get a server by socket address */
static
sres_server_t *
sres_server_by_sockaddr(sres_resolver_t const *res, 
			void const *from, int fromlen)
{
  int i;

  for (i = 0; i < res->res_n_servers; i++) {
    sres_server_t *dns = res->res_servers[i];
    if (dns->dns_addrlen == fromlen && 
	memcmp(dns->dns_addr, from, fromlen) == 0)
      return dns;
  }
  
  return NULL;
}
#endif

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
    return su_seterrno(EIO);
  }

  if (msg->msg_flags & MSG_CTRUNC) {
    SU_DEBUG_1(("%s: extended error was truncated\n", __func__));
    return su_seterrno(EIO);
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

  return sres_resolver_report_error(res, socket, errcode, NULL, 0, "");
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

    dns = sres_server_by_socket(res, socket);

    if (dns) {
      time(&res->res_now);
      dns->dns_icmp = res->res_now;

      for (i = 0; i < res->res_queries->qt_size; i++) {
	q = res->res_queries->qt_table[i];
      
	if (!q || dns != res->res_servers[q->q_i_server])
	  continue;

	/* Resend query/report error to application */
	sres_resend_dns_query(res, q, 1);

	if (q != res->res_queries->qt_table[i])
	  i--;
      }
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

  sres_query_t *query = NULL;
  sres_record_t **reply;
  sres_server_t *dns;

  struct sockaddr_storage from[1];
  socklen_t fromlen = sizeof from;

  SU_DEBUG_9(("%s(%p, %u) called\n", "sres_resolver_receive", res, socket));

  memset(m, 0, offsetof(sres_message_t, m_data)); 
  
  num_bytes = recvfrom(socket, m->m_data, sizeof (m->m_data), 0,
		       (void *)from, &fromlen);

  if (num_bytes <= 0) {
    SU_DEBUG_5(("%s: %s\n", "sres_receive_packet", su_strerror(su_errno())));
    return 0;
  }

  dns = sres_server_by_socket(res, socket);
  if (!dns)
    return 0;

  m->m_size = num_bytes;

  /* Decode the received message and get the matching query object */
  error = sres_decode_msg(res, m, &query, &reply);

  sres_log_response(res, m, from, query, reply);

  if (query == NULL)
    ;
  else if (error == SRES_EDNS0_ERR) {
    dns->dns_edns = edns_not_supported;
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
    if (query->q_callback != NULL)
      (query->q_callback)(query->q_context, query, reply); 
    sres_free_query(res, query);
  }
  else {
    sres_query_report_error(query, reply);
  }

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
    char host[ADDRSIZE] = "*";

    if (from == NULL)
      ;
    else if (from->ss_family == AF_INET) {
      struct sockaddr_in const *sin = (void *)from;
      inet_ntop(AF_INET, &sin->sin_addr, host, sizeof host);
    } 
#if HAVE_SIN6
    else if (from->ss_family == AF_INET6) {
      struct sockaddr_in6 const *sin6 = (void *)from;
      inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof host);
    }
#endif

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
		sres_record_t ***return_answers)
{
  sres_record_t *rr = NULL, **answers = NULL, *error = NULL;
  sres_query_t *query = NULL, **hq;
  su_home_t *chome = CHOME(res->res_cache);
  hash_value_t hash;
  int i, err;
  unsigned total, errorcount = 0;

  assert(res && m && return_answers);

  time(&res->res_now);

  *qq = NULL;
  *return_answers = NULL;

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

  if (m->m_ancount == 0 && err == 0)
    err = SRES_RECORD_ERR;

  if (err == SRES_RECORD_ERR || 
      err == SRES_NAME_ERR || 
      err == SRES_UNIMPL_ERR)
    errorcount = 1;

  total = errorcount + m->m_ancount + m->m_nscount + m->m_arcount;

  answers = su_zalloc(chome, (total + 1) * sizeof answers[0]);
  if (!answers)
    return -1;

  /* Scan resource records */
  for (i = 0; i < total; i++) {
    if (i < errorcount)
      rr = error = sres_create_error_rr(res, query, err);
    else
      rr = sres_create_record(res, m);
 
    if (!rr) {
      SU_DEBUG_5(("sres_create_record: %s\n", m->m_error));
      break;
    }

    if (error && rr->sr_type == sres_type_soa) {
      sres_soa_record_t *soa = (sres_soa_record_t *)rr;
      if (error->sr_ttl > soa->soa_minimum && soa->soa_minimum > 10)
	  error->sr_ttl = soa->soa_minimum;
    }

    answers[i] = rr;
  }

  if (i < total) {
    for (i = 0; i < total; i++)
      su_free(chome, answers[i]);
    su_free(chome, answers);
    return -1;
  }

  for (i = 0; i < total; i++) {
    rr = answers[i];

    if (i < m->m_ancount + errorcount)
      rr->sr_refcount++;
    else
      answers[i] = NULL;

    sres_cache_store(res->res_cache, rr, res->res_now);
  }

  *return_answers = answers;

  return err;
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

  SU_DEBUG_9(("rr: %.*s %d %d %d %d\n", name_length, name, 
	      qtype, qclass, ttl, rdlen));

  if (m->m_error)
    return NULL;

  /* temporarily adjust m_size to check if the current rr is truncated */
  size_old = m->m_size; 
  m->m_size = m->m_offset + rdlen;

  rr = sres_cache_alloc_record(res->res_cache, name, name_length, qtype, rdlen);
  if (rr) switch(qtype) {
  case sres_type_soa:
    sres_init_rr_soa(res, rr->sr_soa, m);
    break;
  case sres_type_a:
    sres_init_rr_a(res, rr->sr_a, m);
    break;
  case sres_type_a6:
    sres_init_rr_a6(res, rr->sr_a6, m);
    break;
  case sres_type_aaaa:
    sres_init_rr_aaaa(res, rr->sr_aaaa, m);
    break;
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
      rr->a6_suffix.u6_addr[i] = m_get_uint8(m);
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

  if (m->m_offset + sizeof(rr->aaaa_addr) > m->m_size) {
    m->m_error = "truncated message";
    return;
  }

  memcpy(&rr->aaaa_addr, m->m_data + m->m_offset, sizeof(rr->aaaa_addr));

  m->m_offset += sizeof(rr->aaaa_addr);
}

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
  char const *name;

  name = sres_toplevel(buf, sizeof buf, q->q_name);
  if (!name)
    return NULL;

  sr = sres_cache_alloc_record(res->res_cache, name, strlen(name), q->q_type, 0);
  
  if (sr) {
    sr->sr_status = errcode;
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
