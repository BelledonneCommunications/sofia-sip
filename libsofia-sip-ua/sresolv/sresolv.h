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

#ifndef SRESOLV_H /** Defined when <sresolv.h> has been included. */
#define SRESOLV_H
/**
 * @file sresolv.h Sofia Asynchronous DNS Resolver.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>,
 * @author Teemu Jalava <Teemu.Jalava@nokia.com>,
 * @author Mikko Haataja <ext-Mikko.A.Haataja@nokia.com>.
 *
 */

#include <su.h>

typedef union  sres_record          sres_record_t;
typedef struct sres_common          sres_common_t;
typedef struct sres_generic         sres_generic_t;
typedef struct sres_soa_record      sres_soa_record_t;
typedef struct sres_a_record        sres_a_record_t;
typedef struct sres_a6_record       sres_a6_record_t;
typedef struct sres_aaaa_record     sres_aaaa_record_t;
typedef struct sres_cname_record    sres_cname_record_t;
typedef struct sres_ptr_record      sres_ptr_record_t;
typedef struct sres_srv_record      sres_srv_record_t;
typedef struct sres_naptr_record    sres_naptr_record_t;   

typedef struct sres_query_s         sres_query_t;
typedef struct sres_resolver_s      sres_resolver_t;

#ifndef SRES_CONTEXT_T 
#define SRES_CONTEXT_T struct sres_context_s
#endif
typedef SRES_CONTEXT_T sres_context_t;

/** Prototype for callback function.
 *
 * This kind of function is called when a query is completed. The called
 * function is responsible for freeing the list of answers and it must
 * (eventually) call sres_free_answers().
 */
typedef void sres_answer_f(sres_context_t *context, 
			   sres_query_t *query,
			   sres_record_t **answers);

/** Common part of DNS record */
struct sres_common
{
  int               r_refcount;	/**< Number of references to this record */
  char             *r_name;	/**< Domain name */
  uint16_t          r_status;	/**< Status of query (nonzero upon an error) */
  uint16_t          r_size;	/**< Size of this record */
  uint16_t          r_type;	/**< Record type (A, CNAME, A6, etc) */
  uint16_t          r_class;	/**< Record class (IN) */
  uint32_t          r_ttl;	/**< Time-to-live */
  uint16_t          r_rdlen;	/**< Length of record data */
  uint16_t          r_pad;	/**< Padding */
};

/** Possible values for r_status (RCODE) */
enum {
  SRES_OK = 0,			/**< No error condition. */
  SRES_FORMAT_ERR = 1,		/**< Server could not interpret query. */
  SRES_SERVER_ERR = 2,		/**< Server error. */
  SRES_NAME_ERR = 3,		/**< No domain name. */
  SRES_UNIMPL_ERR = 4,		/**< Not implemented. */
  SRES_AUTH_ERR = 5,		/**< Refused */
  /* */
  SRES_TIMEOUT_ERR = 16,	/**< Timeout occurred */
  SRES_RECORD_ERR = 17	        /**< Name has no given record type */
};

/** Start-of-authority record (RFC 1035). */
struct sres_soa_record
{
  sres_common_t     soa_record[1];
  char             *soa_mname;
  char             *soa_rname;
  uint32_t          soa_serial;
  uint32_t          soa_refresh;
  uint32_t          soa_retry;
  uint32_t          soa_expire;
  uint32_t          soa_minimum;
};

/** Generic record. */
struct sres_generic
{
  sres_common_t     g_record[1];
  uint8_t           g_data[128];
};


/** Address record (RFC 1035). */
struct sres_a_record
{
  sres_common_t     a_record[1];
  struct in_addr    a_addr;
};

#if SU_HAVE_IN6
/** Address record for IPv6 (RFC 2874, deprecated). */
struct sres_a6_record
{
  sres_common_t     a6_record[1];
  uint8_t           a6_prelen;
  uint8_t           a6_pad[3];
  struct in6_addr   a6_suffix;
  char             *a6_prename;
};

/** Address record for IPv6 (RFC 1886). */
struct sres_aaaa_record
{
  sres_common_t     aaaa_record[1];
  struct in6_addr   aaaa_addr;
};
#endif /* if SU_HAVE_IN6 */

/** Canonic name record (RFC 1035). */
struct sres_cname_record
{
  sres_common_t     cname_record[1];
  char             *cn_cname;
};

/** Pointer record (RFC 1035). */
struct sres_ptr_record
{
  sres_common_t     ptr_record[1];
  char             *ptr_domain;
};

/** Service location record (RFC 2782). */
struct sres_srv_record
{
  sres_common_t     srv_record[1];
  uint16_t          srv_priority;
  uint16_t          srv_weight;
  uint16_t          srv_port;
  uint16_t          srv_pad;
  char             *srv_target;
};

/** Naming authority pointer record (RFC2915). */
struct sres_naptr_record
{
  sres_common_t     na_record[1];
  uint16_t          na_order;
  uint16_t          na_prefer;
  char             *na_flags;
  char             *na_services;
  char             *na_regexp;
  char             *na_replace;
};

/** Union of different records */
union sres_record
{
  sres_common_t       sr_record[1];
  sres_generic_t      sr_generic[1];
  sres_soa_record_t   sr_soa[1];    
  sres_a_record_t     sr_a[1];    
  sres_cname_record_t sr_cname[1];   
  sres_ptr_record_t   sr_ptr[1];
#if SU_HAVE_IN6
  sres_a6_record_t    sr_a6[1];   
  sres_aaaa_record_t  sr_aaaa[1]; 
#endif
  sres_srv_record_t   sr_srv[1]; 
  sres_naptr_record_t sr_naptr[1];   
};

/** Record classes */
enum {
  sres_class_in = 1,
  sres_class_any = 255
};

enum {
  sres_type_a = 1,		/**< IPv4 address. */
  sres_type_ns = 2,		/**< Authoritative server. */
  sres_type_mf = 4,		/**< Mail forwarder. */
  sres_type_cname = 5,		/**< Canonical name. */
  sres_type_soa = 6,		/**< Start of authority zone. */
  sres_type_mb = 7,		/**< Mailbox domain name. */
  sres_type_mg = 8,		/**< Mail group member. */
  sres_type_mr = 9,		/**< Mail rename name. */
  sres_type_null = 10,		/**< Null resource record. */
  sres_type_wks = 11,		/**< Well known service. */
  sres_type_ptr = 12,		/**< Domain name pointer. */
  sres_type_hinfo = 13,		/**< Host information. */
  sres_type_minfo = 14,		/**< Mailbox information. */
  sres_type_mx = 15,		/**< Mail routing information. */
  sres_type_txt = 16,		/**< Text strings. */
  sres_type_rp = 17,		/**< Responsible person. */
  sres_type_afsdb = 18,		/**< AFS cell database. */
  sres_type_x25 = 19,		/**< X_25 calling address. */
  sres_type_isdn = 20,		/**< ISDN calling address. */
  sres_type_rt = 21,		/**< Router. */
  sres_type_nsap = 22,		/**< NSAP address. */
  sres_type_nsap_ptr = 23,	/**< Reverse NSAP lookup. */
  sres_type_sig = 24,		/**< Security signature. */
  sres_type_key = 25,		/**< Security key. */
  sres_type_px = 26,		/**< X.400 mail mapping. */
  sres_type_gpos = 27,		/**< ICBM record. */
  sres_type_aaaa = 28,		/**< IPv6 Address. */
  sres_type_loc = 29,		/**< Location Information. */
  sres_type_nxt = 30,		/**< Next domain. */
  sres_type_eid = 31,		/**< Endpoint identifier. */
  sres_type_nimloc = 32,	/**< Nimrod Locator. */
  sres_type_srv = 33,		/**< Server Selection. */
  sres_type_atma = 34,		/**< ATM Address */
  sres_type_naptr = 35,		/**< Naming Authority PoinTeR (RFC 2915) */
  sres_type_kx = 36,		/**< Key Exchange */
  sres_type_cert = 37,		/**< Certification record */
  sres_type_a6 = 38,		/**< IPv6 address (deprecates AAAA) */
  sres_type_dname = 39,		/**< Non-terminal DNAME (for IPv6) */
  sres_type_sink = 40,		/**< Kitchen sink (experimental) */
  sres_type_opt = 41,		/**< EDNS 0 option (RFC 2671) */

  sres_qtype_tsig = 250,	/**< Transaction signature. */
  sres_qtype_ixfr = 251,	/**< Incremental zone transfer. */
  sres_qtype_axfr = 252,	/**< Transfer zone of authority. */
  sres_qtype_mailb = 253,	/**< Transfer mailbox records. */
  sres_qtype_maila = 254,	/**< Transfer mail agent records. */
  sres_qtype_any = 255		/**< Wildcard match. */
};

/** Create an resolver object. */
sres_resolver_t *sres_resolver_new(char const *resolv_conf_path);

sres_resolver_t *sres_resolver_ref(sres_resolver_t *res);
void sres_resolver_unref(sres_resolver_t *res);

/** Add a mutex to resolver object. */
int sres_resolver_add_mutex(sres_resolver_t *res,
			    void *mutex,
			    int (*lock)(void *mutex),
			    int (*unlock)(void *mutex));

/** Set userdata pointer. */
void *sres_resolver_set_userdata(sres_resolver_t *res, void *userdata);

/** Get userdata pointer. */
void *sres_resolver_get_userdata(sres_resolver_t const *res);

/** Create sockets for resolver. */
int sres_resolver_sockets(sres_resolver_t const *res,
			  int *sockets, int n);

/** Resolver timer function. */
void sres_resolver_timer(sres_resolver_t *, int socket);

/** Receive DNS response from socket. */
int sres_resolver_receive(sres_resolver_t *res, int socket);

/** Receive error message from socket. */
int sres_resolver_error(sres_resolver_t *res, int socket);

/** Make a DNS query. */
sres_query_t *sres_query_make(sres_resolver_t *res,
			      sres_answer_f *callback,
			      sres_context_t *context,
			      int socket,
			      uint16_t type,
			      char const *domain);

/** Make a reverse DNS query. */
sres_query_t *sres_query_make_sockaddr(sres_resolver_t *res,
				       sres_answer_f *callback,
				       sres_context_t *context,
				       int socket,
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

/** Sort and filter the list of records */
int sres_filter_answers(sres_resolver_t *sres, sres_record_t **answers, 
			uint16_t type);

/** Free the list records. */
void sres_free_answers(sres_resolver_t *res, sres_record_t **answers);

/** Free and zero one record. */
void sres_free_answer(sres_resolver_t *res, sres_record_t *answer);

#if HAVE_SU_WAIT_H
/* Sofia-specific reactor interface for asynchronous operation */
#include <su_wait.h>
#include <su_tag.h>

extern tag_typedef_t srestag_resolv_conf;
#define SRESTAG_RESOLV_CONF(x) srestag_resolv_conf, tag_str_v((x))
extern tag_typedef_t srestag_resolv_conf_ref;
#define SRESTAG_RESOLV_CONF_REF(x) srestag_resolv_conf_ref, tag_str_vr(&(x))

/* Easy API for Sofia */

/** Create a resolver object using @a root reactor. */
sres_resolver_t *sres_resolver_create(su_root_t *root, 
				      char const *resolv_conf,
				      tag_type_t, tag_value_t, ...);
/** Destroy a resolver object. */
int sres_resolver_destroy(sres_resolver_t *res);

/* Return socket used by root */
int sres_resolver_root_socket(sres_resolver_t *res);

/** Make a DNS query. */
sres_query_t *sres_query(sres_resolver_t *res,
                         sres_answer_f *callback,
                         sres_context_t *context,
                         uint16_t type,
                         char const *domain);

/** Make a DNS query. */
sres_query_t *sres_query_sockaddr(sres_resolver_t *res,
                                  sres_answer_f *callback,
                                  sres_context_t *context,
                                  uint16_t type,
				  struct sockaddr const *addr);

#endif

#endif /* SRESOLV_H */
