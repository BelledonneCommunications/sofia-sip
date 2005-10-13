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

/**@CFILE tport.c Transport interface implementation.
 *
 * See tport.docs for more detailed description of tport interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Ismo Puustinen <Ismo.H.Puustinen@nokia.com>
 * @author Tat Chan <Tat.Chan@nokia.com>
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 *
 * @date Created: Thu Jul 20 12:54:32 2000 ppessi
 */

#include "config.h"

#include <string0.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <su.h>

#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif

#define SU_LOG   tport_log

#include <su_debug.h>
#include <su_alloc.h>
#include <su_tagarg.h>

#include <su_localinfo.h>

#ifndef NONE
#define NONE ((void *)-1)
#endif

typedef struct tport_master tport_master_t;
typedef struct tport_nat_s tport_nat_t;

#define SU_WAKEUP_ARG_T struct tport_s
#define SU_TIMER_ARG_T struct tport_master
#define SU_ROOT_MAGIC_T struct tport_threadpool
#define SU_MSG_ARG_T union tport_su_msg_arg

#include <su_wait.h>

#include <msg.h>
#include <msg_addr.h>

#if HAVE_IP_RECVERR || HAVE_IPV6_RECVERR
#include <linux/types.h>
#include <linux/errqueue.h>
#include <sys/uio.h>
#endif

#if HAVE_SCTP && HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#endif

#if HAVE_TLS
#include "tport_tls.h"
#else
typedef struct _tls_t tls_t;	/* dummy */
#endif

#if HAVE_SIGCOMP
#include <sigcomp.h>
#endif

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP (132)
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL (0)
#endif

#if HAVE_SOFIA_STUN
#include "stun.h"
#endif

#if HAVE_UPNP
#include "upnp_wrapper.h"
#endif

#include "tport.h"
#include "su_uniqueid.h"
#include <rbtree.h>

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
char const __func__[] = "tport";
#endif

typedef struct tport_pending_s tport_pending_t;
typedef struct tport_threadpool tport_threadpool_t;
typedef struct tport_sigcomp_handler tport_sigcomp_handler_t;
typedef struct tport_sigcomp tport_sigcomp_t;
typedef struct tport_primary tport_primary_t;

struct sigcomp_state_handler;
struct sigcomp_algorithm;
struct sigcomp_udvm;
struct sigcomp_magic;

#if HAVE_SIGCOMP

/** Per-socket SigComp data */
struct tport_sigcomp {
  struct sigcomp_udvm          *sc_udvm;
  struct sigcomp_compartment   *sc_cc;
  struct sigcomp_compressor    *sc_compressor;
  struct sigcomp_buffer        *sc_output;
  unsigned                      sc_compressed; 

  struct sigcomp_buffer        *sc_input;
  unsigned                      sc_copied;
  
  enum {
    format_is_unknown,
    format_is_sigcomp,
    format_is_noncomp
  } sc_infmt, sc_outfmt;
};

#endif

/** Transport parameters */
typedef struct {
  unsigned tpp_mtu;		/**< Maximum packet size */
  unsigned tpp_idle;		/**< Allowed connection idle time. */
  unsigned tpp_timeout;		/**< Allowed idle time for message. */
  unsigned tpp_sigcomp_lifetime;  /**< SigComp compartment lifetime  */
  unsigned tpp_thrpsize;	/**< Size of thread pool */

  unsigned tpp_thrprqsize;	/**< Length of per-thread recv queue */
  unsigned tpp_qsize;		/**< Size of queue */

  unsigned tpp_drop;		/**< Packet drop probablity */

  unsigned tpp_conn_orient:1;   /**< Connection-orienteded */
  unsigned tpp_sdwn_error:1;	/**< If true, shutdown is error. */
  unsigned :0;

} tport_params_t;


/** Transport object.
 *
 * A transport object can be used in three roles, to represent transport
 * list (aka master transport), to represent available transports (aka
 * primary transport) and to represent actual transport connections (aka
 * secondary transport).
 */
struct tport_s {
  su_home_t           tp_home[1];       /**< Memory home */

  int                 tp_refs;		/**< Number of references to tport */

  tport_t *tp_left, *tp_right, *tp_dad; /**< Links in tport tree */

  tport_master_t     *tp_master;        /**< Master transport */
  tport_primary_t    *tp_pri;           /**< Primary transport */

  tport_params_t     *tp_params;        /**< Transport parameters */

  tp_magic_t         *tp_magic; 	/**< Context provided by consumer */

  unsigned            tp_black:1;       /**< Used by red-black-tree */

  unsigned            tp_conn_orient:1;	/**< Is connection-oriented */
  unsigned            tp_connected : 1;	/**< Has real connection */
  unsigned            tp_reusable:1;    /**< Can this connection be reused */
  unsigned            tp_closed : 1;    /**< This transport is closed */
  unsigned            tp_recv_close:1;  /**< Remote end has sent FIN */
  /** We will send FIN (1) or have sent FIN (2) */
  unsigned            tp_send_close:2; 

  unsigned:0;

  msg_t const        *tp_rlogged;       /**< Last logged when receiving */
  msg_t const        *tp_slogged;       /**< Last logged when sending */

  unsigned            tp_time;	        /**< When this transport was last used */

  tp_name_t           tp_name[1];	/**< Transport name.
					 * 
					 * This is either our name (if primary)
					 * or peer name (if secondary).
					 */

#define tp_protoname tp_name->tpn_proto
#define tp_canon     tp_name->tpn_canon
#define tp_host      tp_name->tpn_host
#define tp_port      tp_name->tpn_port
#define tp_ident     tp_name->tpn_ident

  su_socket_t  	      tp_socket;	/**< Socket of this tport*/
  int                 tp_index;		/**< Root registration index */
  int                 tp_events;        /**< Subscribed events */
  int                 tp_addrlen;       /**< Size fo tp_addr */
  su_sockaddr_t       tp_addr[1];	/**< Peer address */

#if HAVE_TLS
  tls_t              *tp_tls;
  char               *tp_tls_buffer;    /**< 2k Buffer  */
#endif

#if HAVE_SIGCOMP
  tport_sigcomp_t     tp_sigcomp[1];
#endif  

#if HAVE_SOFIA_STUN
  stun_socket_t      *tp_stun_socket;
#endif

  /* ==== Receive queue ================================================== */

  msg_t   	     *tp_msg;		/**< Message being received */

  /* ==== Pending messages =============================================== */

  tport_pending_t    *tp_pending;       /**< Pending requests */
  tport_pending_t    *tp_released;      /**< Released pends */
  unsigned            tp_plen;          /**< Size of tp_pending */
  unsigned            tp_pused;         /**< Used pends */
  unsigned            tp_reported;      /**< Report counter */

  /* ==== Send queue ===================================================== */

  msg_t             **tp_queue;		/**< Messages being sent */
  unsigned short      tp_qhead;		/**< Head of queue */

  msg_iovec_t        *tp_unsent;	/**< Pointer to first unsent iovec */
  unsigned            tp_unsentlen;	/**< Number of unsent iovecs */

  msg_iovec_t        *tp_iov;		/**< Iovecs allocated for sending */
  unsigned            tp_iovlen;	/**< Number of allocated iovecs */

  /* ==== Statistics  ===================================================== */
  
  struct {
    uint64_t sent_bytes, sent_on_line, recv_bytes, recv_on_line;
    uint64_t sent_msgs, recv_msgs;
  } tp_stats;
};

/** Primary structure */
struct tport_primary {
  tport_t             pri_primary[1];   /**< Transport part */
#if DOX
  su_home_t           pri_home[1];
  tport_t           **pri_stail;	/**< End of secondary list */
#else
#define pri_home      pri_primary->tp_home
#define pri_master    pri_primary->tp_master
#define pri_protoname pri_primary->tp_name->tpn_proto
#endif

  char                pri_ident[16];
  tport_primary_t    *pri_next;	        /**< Next primary tport */

  tport_t            *pri_secondary;	/**< Secondary tports */

  tport_threadpool_t *pri_threadpool;   /**< Worker threads */
  unsigned            pri_thrpsize;
  unsigned            pri_family : 8;   /**< Network family (INET/INET6) */
  unsigned            pri_socktype : 8; /**< Socket type  */
  unsigned            pri_protocol : 8;	/**< IP protocol number  */

  unsigned            pri_natted:1;	/**< Using natted address  */

  unsigned:0;

  tport_params_t      pri_params[1];      /**< Transport parameters */

};

/** Master structure */
struct tport_master {
  tport_t             mr_master[1];
#if DOX
  su_home_t           mr_home[1];
#else
#define mr_home mr_master->tp_home
#endif

  tp_stack_t  	     *mr_stack;        /**< Transport consumer */
  tp_stack_class_t 
               const *mr_tpac;		/**< Methods provided by stack */
  int                 mr_log;	/**< Log message contents? */
#define mr_msg_flags  mr_log	/**< Flags used by msg_t creation */
  su_root_t    	     *mr_root;		/**< SU root pointer */

  /**< Timer reclaiming unused connections and compartment */
  su_timer_t         *mr_timer;		
  /** File to dump received and sent data */
  FILE               *mr_dump_file;	

  tport_primary_t    *mr_primaries;     /**< List of primary contacts */

  tport_params_t      mr_params[1];
  
  unsigned            mr_boundserver:1; /**< Server has been bound */
  unsigned            mr_bindv6only:1; /**< We can bind separately to IPv6/4 */
  unsigned :0;

#if HAVE_SIGCOMP
  struct sigcomp_compartment   *mr_compartment;
#endif

  /* Delivery context */
  struct tport_delivery {
    tport_t              *d_tport;
    msg_t                *d_msg;
    tp_name_t             d_from[1];
    struct sigcomp_udvm **d_udvm;
  } mr_delivery[1];

  struct tport_nat_s {
    int initialized;
    int bound;
    int stun_enabled;
    char *external_ip_address;
#if HAVE_UPNP || HAVE_SOFIA_STUN
    int try_stun;
#endif
#if HAVE_UPNP
#endif
#if HAVE_SOFIA_STUN
    char *stun_server;
    stun_socket_t *stun_socket;
    stun_engine_t *stun;
#endif
  }                   mr_nat[1];
};

#define STACK_RECV(tp, msg, now)		       \
  (tp)->tp_master->mr_tpac->tpac_recv((tp)->tp_master->mr_stack, (tp), \
				      (msg), (tp)->tp_magic, (now))

#define STACK_ERROR(tp, errcode, dstname) \
  (tp)->tp_master->mr_tpac->tpac_error((tp)->tp_master->mr_stack, (tp), \
				       (errcode), (dstname))

#define STACK_SIGCOMP_ACCEPT(tp, msg)				  \
  (tp)->tp_master->mr_tpac->					  \
  tpac_sigcomp_accept((tp)->tp_master->mr_stack, (tp), (msg))

#define TP_STACK   tp_master->mr_stack

#define TP_SCTP_MSG_MAX (32768)

/* These should not overlap with existing AI flags. */
#define TP_AI_COMPRESSED 0x0010
/* Halfclose (shutdown(c, 1)) connection after sending message */
#define TP_AI_SHUTDOWN   0x0020
/* Close connection (shutdown(c, 2)) after sending message */
#define TP_AI_CLOSE      0x0020

/* Address was inaddr_any */
#define TP_AI_ANY        0x0040

typedef long unsigned LU; 	/* for printf() and friends */

char const tport_sigcomp_name[] = "sigcomp";

#if HAVE_SIGCOMP
static inline
int msg_is_compressed(msg_t *msg)
{
  return msg && 
    (msg_addrinfo(msg)->ai_flags & TP_AI_COMPRESSED) == TP_AI_COMPRESSED;
}

static inline
void msg_mark_as_compressed(msg_t *msg)
{
  if (msg)
    msg_addrinfo(msg)->ai_flags |= TP_AI_COMPRESSED;
}

static struct sigcomp_udvm *tport_init_udvm(tport_t *self);
static int tport_recv_sigcomp_r(tport_t *, msg_t **, struct sigcomp_udvm *);
static struct sigcomp_compartment *tport_primary_compartment(tport_master_t *);
static inline void tport_try_accept_sigcomp(tport_t *self, msg_t *msg);

static
char const *tport_canonize_comp(char const *comp)
{
  if (comp && strcasecmp(comp, tport_sigcomp_name) == 0)
    return tport_sigcomp_name;
  return NULL;
}

/** Check if transport can receive compressed messages */
int tport_can_recv_sigcomp(tport_t const *self)
{
  return self && self->tp_sigcomp->sc_infmt != format_is_noncomp;
}

/** Check if transport can send compressed messages */
int tport_can_send_sigcomp(tport_t const *self)
{
  return self && self->tp_sigcomp->sc_outfmt != format_is_noncomp;
}

/** Check if transport supports sigcomp */
int tport_has_compression(tport_t const *self, char const *comp)
{
  return
    self && comp && 
    self->tp_name->tpn_comp == tport_canonize_comp(comp);
}

/** Set/reset compression */
int tport_set_compression(tport_t *self, char const *comp)
{
  if (self == NULL)
    ;
  else if (comp == NULL) {
    if (self->tp_sigcomp->sc_outfmt != format_is_sigcomp) {
      self->tp_name->tpn_comp = NULL;
      return 0;
    }
  }
  else {
    comp = tport_canonize_comp(comp);

    if (comp && self->tp_sigcomp->sc_outfmt != format_is_noncomp) {
      self->tp_name->tpn_comp = comp;
      return 0;
    }
  }
  
  return -1;
}
#else

#define tport_try_accept_sigcomp(self, msg) ((void)0)
#define tport_canonize_comp(comp) ((void *)0)

int tport_can_recv_sigcomp(tport_t const *self)
{
  return 0;
}

int tport_can_send_sigcomp(tport_t const *self)
{
  return 0;
}

int tport_has_compression(tport_t const *self, char const *comp)
{
  return 0;
}

int tport_set_compression(tport_t *self, char const *comp)
{
  return (self == NULL || comp) ? -1 : 0;
}
#endif

/* Define macros for rbtree implementation */
#define TP_LEFT(tp) ((tp)->tp_left)
#define TP_RIGHT(tp) ((tp)->tp_right)
#define TP_PARENT(tp) ((tp)->tp_dad)
#define TP_SET_RED(tp) ((tp)->tp_black = 0)
#define TP_SET_BLACK(tp) ((tp)->tp_black = 1)
#define TP_IS_RED(tp) ((tp) && (tp)->tp_black == 0)
#define TP_IS_BLACK(tp) (!(tp) || (tp)->tp_black == 1)
#define TP_COPY_COLOR(dst, src) ((dst)->tp_black = (src)->tp_black)
#define TP_INSERT(tp) ((void)0)
#define TP_REMOVE(tp) ((tp)->tp_left = (tp)->tp_right = (tp)->tp_dad = NULL)

static inline int tp_cmp(tport_t const *a, tport_t const *b)
{
  if (a == b)
    return 0;
  
  if (a->tp_addrlen != b->tp_addrlen)
    return a->tp_addrlen - b->tp_addrlen;

  return memcmp(a->tp_addr, b->tp_addr, sizeof(a->tp_addr));
}

static inline int tprb_is_inserted(tport_t const *a)
{
  return a->tp_dad != 0 || a->tp_left != 0 || a->tp_right != 0;
}

RBTREE_PROTOS(static inline, tprb, tport_t);

RBTREE_BODIES(static inline, tprb, tport_t, 
	      TP_LEFT, TP_RIGHT, TP_PARENT,
	      TP_IS_RED, TP_SET_RED, TP_IS_BLACK, TP_SET_BLACK, TP_COPY_COLOR,
	      tp_cmp, TP_INSERT, TP_REMOVE);

enum {
  /** Default per-thread read queue length */
  THRP_PENDING = 8
};

struct tport_pending_s {
  //  tport_pending_t       *p_left, *p_right, *p_parent;
  void               *p_client;
  tport_pending_error_f *p_callback;
  msg_t              *p_msg;
  int                 p_reported;
};

/** Return true if transport is master. */
inline int tport_is_master(tport_t const *self)
{
  return 
    self && 
    self->tp_master->mr_master == self;
}

/** Return true if transport is primary. */
inline int tport_is_primary(tport_t const *self)
{
  return 
    self && 
    self->tp_pri->pri_primary == self;
}

/** Return true if transport is secondary. */
inline int tport_is_secondary(tport_t const *self)
{
  return 
    self && 
    self->tp_master->mr_master != self && 
    self->tp_pri->pri_primary != self;
}

/** Test if transport has been registered */
static inline int tport_is_registered(tport_t const *self)
{
  return self->tp_index != 0;
}

/** Test if transport is stream. */
inline int tport_is_stream(tport_t const *self)
{
  return self->tp_pri->pri_socktype == SOCK_STREAM;
}
 
/** Test if transport is dgram. */
static inline int tport_is_dgram(tport_t const *self)
{
  return self->tp_pri->pri_socktype == SOCK_DGRAM;
}
 
/** Test if transport is udp. */
inline int tport_is_udp(tport_t const *self)
{
  return self->tp_pri->pri_protocol == IPPROTO_UDP;
}
 
/** Test if transport is tcp. */
inline int tport_is_tcp(tport_t const *self)
{
  return self->tp_pri->pri_protocol == IPPROTO_TCP;
}
 
/** Test if transport is needs connect() before sending. */
static inline int tport_is_connection_oriented(tport_t const *self)
{
  return self->tp_conn_orient;
}

/** Test if transport has actual connection. */
static inline int tport_is_connected(tport_t const *self)
{
  return self->tp_connected;
}

/** Return 1 if transport is reliable, 0 otherwise.
 *
 * (Note that this is part of external API).
 */
inline int tport_is_reliable(tport_t const *self)
{
  return self != NULL && 
    (self->tp_pri->pri_socktype == SOCK_STREAM || 
     self->tp_pri->pri_socktype == SOCK_SEQPACKET);
}


/** Return true if transport supports IPv4 */
inline int tport_has_ip4(tport_t const *self)
{
  return self && 
    (self->tp_pri->pri_family == 0 || 
     self->tp_pri->pri_family == AF_INET 
     /* || self->tp_pri->pri_family2 == AF_INET */);
}

/** Return true if transport supports IPv6 */
inline int tport_has_ip6(tport_t const *self)
{
  return self && 
    (self->tp_pri->pri_family == 0 || self->tp_pri->pri_family == AF_INET6);
}

/** Return true if transport supports TLS. */
inline int tport_has_tls(tport_t const *self)
{
#if HAVE_TLS
  return self && self->tp_tls != NULL;
#else
  return 0;
#endif  
}

/** Test if transport has been closed */
static inline int tport_is_closed(tport_t const *self)
{
  return self->tp_closed;
}

/** Test if transport has been shut down */
static inline int tport_is_shutdown(tport_t const *self)
{
  return self->tp_closed || self->tp_send_close || self->tp_recv_close;
}


/** Test if transport is bound */
static inline int tport_is_bound(tport_t const *self)
{
  return self->tp_protoname != NULL;
}

/** MTU for transport  */
static inline unsigned tport_mtu(tport_t const *self)
{
  return self->tp_params->tpp_mtu;
}

static inline
int tport_has_sigcomp(tport_t const *self)
{
  return self->tp_name->tpn_comp != NULL;
}

static
int tport_events(tport_t const *self)
{
  int events = self->tp_events;

#if HAVE_TLS
  if (self->tp_tls) {
    events = tls_events(self->tp_tls, events);

    SU_DEBUG_7(("tport_events(%p): logical events%s%s%s%s real%s%s%s%s\n",
		self, (self->tp_events & SU_WAIT_IN) ? " IN" : "",
		(self->tp_events & SU_WAIT_OUT) ? " OUT" : "",
		(self->tp_events & SU_WAIT_HUP) ? " HUP" : "",
		(self->tp_events & SU_WAIT_ERR) ? " ERR" : "",
		(events & SU_WAIT_IN) ? " IN" : "",
		(events & SU_WAIT_OUT) ? " OUT" : "",
		(events & SU_WAIT_HUP) ? " HUP" : "",
		(events & SU_WAIT_ERR) ? " ERR" : ""));
  }
  else
#endif
    SU_DEBUG_7(("tport_events(%p): events%s%s%s%s\n", self,
		(events & SU_WAIT_IN) ? " IN" : "",
		(events & SU_WAIT_OUT) ? " OUT" : "",
		(events & SU_WAIT_HUP) ? " HUP" : "",
		(events & SU_WAIT_ERR) ? " ERR" : ""));
		
  return
    su_root_eventmask(self->tp_master->mr_root, 
		      self->tp_index, 
		      self->tp_socket, 
		      events);
}

/* NAT things */

static
struct tport_nat_s *
tport_nat_initialize_nat_traversal(tport_master_t *mr, 
				   tp_name_t const *tpn,
				   char const * const **return_transports);

static
char *tport_nat_get_external_ip_address(struct tport_nat_s *nat);


#if HAVE_SOFIA_STUN
static
int tport_nat_stun_bind(struct tport_nat_s *nat,
			su_sockaddr_t su[1],
			socklen_t *sulen,
			su_socket_t s);
#endif

static
int tport_nat_traverse_nat(tport_master_t *, 
			   su_sockaddr_t su[1],
			   su_addrinfo_t const *ai,
			   su_socket_t s);

static
int tport_nat_set_canon(tport_t *self, struct tport_nat_s *nat);

static
int tport_nat_finish(tport_primary_t *self);

#define PASSIVE PASSIVE
#define ACTIVE  ACTIVE
enum socket_open { PASSIVE = 0, ACTIVE = 1 };

static 
tport_t *tport_connect(tport_primary_t *pri, su_addrinfo_t *ai, 
		       tp_name_t const *tpn);

static int tport_get_local_addrinfo(tport_master_t *mr, 
				    su_localinfo_t *li,
				    char const *port,
				    su_addrinfo_t const *hints,
				    su_addrinfo_t **return_ai);

static void tport_freeaddrinfo(tport_master_t *mr, su_addrinfo_t *ai);

#if HAVE_TLS
static tls_t *tport_init_tls(tagi_t *tags);
#endif

static int
  tport_bind_client(tport_master_t *self, tp_name_t const *tpn, 
		    char const * const transports[], tagi_t *tags),
  tport_bind_server(tport_master_t *, tp_name_t const *tpn, 
		    char const * const transports[], tagi_t *tags),

  tport_init_compression(tport_primary_t *self, char const *compression, 
			 tagi_t *tl),

  tport_setname(tport_t *, char const *, su_sockaddr_t const *, char const *),
  tport_recv(su_root_magic_t *m, su_wait_t *w, tport_t *self),
  tport_accept(su_root_magic_t *m, su_wait_t *w, tport_t *self),
  tport_resolve(tport_t *self, msg_t *msg, tp_name_t const *tpn),
  tport_send_msg(tport_t *, msg_t *, tp_name_t const *tpn,
		 struct sigcomp_compartment *cc),
  tport_vsend(tport_t *self, msg_t *msg, tp_name_t const *tpn,
	      msg_iovec_t iov[], int iovused,
	      struct sigcomp_compartment *cc),
  tport_vsend_iovec(tport_t const *, msg_t *, msg_iovec_t iov[], int iovused),
  tport_send_error(tport_t *, msg_t *, tp_name_t const *, char const *comp),
  tport_queue(tport_t *self, msg_t *msg),
  tport_queue_rest(tport_t *self, msg_t *msg, msg_iovec_t iov[], int iovused),
  tport_pending_error(tport_t *self, su_sockaddr_t const *dst, int error),
  tport_pending_errmsg(tport_t *self, msg_t *msg, int error),
  tport_launch_threadpool(tport_primary_t *pri),
  tport_kill_threadpool(tport_primary_t *pri),
  tport_thread_send(tport_t *, struct sigcomp_compartment *, 
		    msg_t *, unsigned mtu);

tport_t *tport_by_addrinfo(tport_primary_t const *pri,
			   su_addrinfo_t const *ai,
			   tp_name_t const *tpn);

void tport_peer_address(tport_t *self, msg_t *msg);
static unsigned long tport_now(void);
static void tport_tick(su_root_magic_t *, su_timer_t *, tport_master_t *mr);

#if HAVE_TLS
static int
  tport_tls_event(tport_t *self, int events),
  tport_tls_writevec(tport_t *self, msg_iovec_t iov[], int iovlen);
#endif

#if HAVE_SIGCOMP
static int 
tport_sigcomp_vsend(tport_t const *self, 
		    msg_t *msg, msg_iovec_t iov[], int iovused,
		    struct sigcomp_compartment *cc, tport_sigcomp_t *sc);
#endif 

static void
  tport_error_event(tport_t *self, int events),
  tport_send_event(tport_t *self, int events), 
  tport_hup_event(tport_t *self, int events),
  tport_recv_event(tport_t *self, int events);

static void tport_parse(tport_t *self, int complete, su_time_t now);
static void tport_deliver(tport_t *, msg_t *msg, msg_t *next,
			  struct sigcomp_udvm **udvm, su_time_t now);

static tport_primary_t *tport_alloc_primary(tport_master_t *tpm);
static tport_primary_t *tport_listen(tport_master_t *mr, 
				     su_addrinfo_t const *ai, 
				     char const *canon, char const *protoname,
				     int port,
				     tagi_t *tags);

static void tport_zap_primary(tport_primary_t *);

static tport_t *tport_alloc_secondary(tport_primary_t *pri);
static void tport_zap_secondary(tport_t *);

static void tport_close(tport_t *self);

static void tport_open_log(tport_master_t *mr, tagi_t *tags);
static void tport_dump_iovec(tport_t const *self, msg_t *msg, int n,
			     su_iovec_t const iov[], int iovused,
			     char const *what, char const *how);
static void tport_log_msg(tport_t *tp, msg_t *msg, char const *what, 
			  char const *via, char const *indent, su_time_t now);
static void tport_stamp(tport_t const *tp, msg_t *msg, char stamp[128], 
			char const *what, int n, char const *via,
			su_time_t now);

static char *localipname(int pf, char *buf, int bufsiz);
static void tport_error_report(tport_t *self, int errcode, 
			       su_sockaddr_t const *dst);
static int getprotohints(su_addrinfo_t *hints,
			 char const *proto, int flags);

static void tport_send_queue(tport_t *self);


/* Stack class used when transports are being destroyed */
static
void tport_destroy_recv(tp_stack_t *stack, tport_t *tp, 
			msg_t *msg, tp_magic_t *magic, 
			su_time_t received)
{
  msg_destroy(msg);
}

static
void tport_destroy_error(tp_stack_t *stack, tport_t *tp, 
			 int errcode, char const *remote)
{
}

static
msg_t *tport_destroy_alloc(tp_stack_t *stack, int flags, 
			   char const data[], unsigned len,
			   tport_t const *tp,
			   tp_client_t *tpc)
{
  return NULL;
}

/**@var TPORT_LOG
 *
 * Environment variable determining if parsed message contents are logged.
 *
 * If the TPORT_LOG environment variable is set, the tport module logs the
 * contents of parsed messages. This eases debugging the signaling greatly.
 * 
 * @sa TPORT_DUMP, TPORT_DEBUG, tport_log
 */
extern char const TPORT_LOG[];	/* dummy declaration for Doxygen */

/**@var TPORT_DUMP
 *
 * Environment variable for transport data dump.
 *
 * The received and sent data is dumped to the file specified by TPORT_DUMP
 * environment variable. This can be used to save message traces and help
 * hairy debugging tasks.
 * 
 * @sa TPORT_LOG, TPORT_DEBUG, tport_log
 */
extern char const TPORT_DUMP[];	/* dummy declaration for Doxygen */

/**@var TPORT_DEBUG
 *
 * Environment variable determining the debug log level for @b tport module.
 *
 * The TPORT_DEBUG environment variable is used to determine the debug logging
 * level for @b tport module. The default level is 3.
 * 
 * @sa <su_debug.h>, tport_log, SOFIA_DEBUG
 */
extern char const TPORT_DEBUG[]; /* dummy declaration for Doxygen */

/**Debug log for @b tport module. 
 * 
 * The tport_log is the log object used by @b tport module. The level of
 * #tport_log is set using #TPORT_DEBUG environment variable.
 */
su_log_t tport_log[] = { 
  SU_LOG_INIT("tport", "TPORT_DEBUG", SU_DEBUG)
};

/** Name for "any" transport. @internal */
static char const tpn_any[] = "*";

/** Create the master transport. @deprecated Use tport_tcreate(). */
tport_t *tport_create(tp_stack_t *stack,
		      tp_stack_class_t const *tpac,
		      su_root_t *root)
{
  return tport_tcreate(stack, tpac, root, TAG_END());
}

/** Create the master transport. */
tport_t *tport_tcreate(tp_stack_t *stack,
		       tp_stack_class_t const *tpac,
		       su_root_t *root, 
		       tag_type_t tag, tag_value_t value, ...)
{
  tport_master_t *mr;
  tp_name_t *tpn;
  tport_params_t *tpp;
  unsigned tick;
  ta_list ta;

  if (!stack || !tpac || !root) {
    su_seterrno(EINVAL);
    return NULL;
  }

  mr = su_home_clone(NULL, sizeof *mr);
  if (!mr)
    return NULL;

  SU_DEBUG_7(("%s(): %p\n", __func__, mr));

  mr->mr_stack = stack;
  mr->mr_tpac = tpac;
  mr->mr_root = root;

  mr->mr_master->tp_master = mr;
  mr->mr_master->tp_params = tpp = mr->mr_params;

  mr->mr_master->tp_reusable = 1;
  tpp->tpp_mtu = UINT_MAX;
  tpp->tpp_thrprqsize = THRP_PENDING;
  tpp->tpp_qsize = TPORT_QUEUESIZE;
  tpp->tpp_sdwn_error = 1;
  tpp->tpp_idle = UINT_MAX;
  tpp->tpp_timeout = UINT_MAX;
  tpp->tpp_sigcomp_lifetime = UINT_MAX;

  tpn = mr->mr_master->tp_name;
  tpn->tpn_proto = "*";
  tpn->tpn_host = "*";
  tpn->tpn_canon = "*";
  tpn->tpn_port = "*";

  ta_start(ta, tag, value);

  tport_set_params(mr->mr_master, ta_tags(ta));
  tport_open_log(mr, ta_args(ta));

  tick = 5000; /* For testing, usually 30000 is enough */  
  if (tpp->tpp_idle < 4 * tick)
    tick = tpp->tpp_idle / 4;
  if (tpp->tpp_timeout < 4 * tick)
    tick = tpp->tpp_timeout / 4;
  if (tick < 200)
    tick = 200;

  mr->mr_timer = su_timer_create(su_root_task(root), tick);
  su_timer_set(mr->mr_timer, tport_tick, mr);

  ta_end(ta);

  return mr->mr_master;
}

/** Destroy the master transport. */
void tport_destroy(tport_t *self)
{
  tport_master_t *mr;

  static tp_stack_class_t tport_destroy_tpac[1] = 
    {{
	sizeof tport_destroy_tpac,
	/* tpac_recv */ tport_destroy_recv,
	/* tpac_error */ tport_destroy_error,
	/* tpac_alloc */ tport_destroy_alloc,
	/* tpac_comp_accept */ NULL
      }};

  SU_DEBUG_7(("%s(%p)\n", __func__, self));

  if (self == NULL)
    return;
  
  assert(tport_is_master(self));
  if (!tport_is_master(self))
    return;

  mr = (tport_master_t *)self;
  mr->mr_tpac = tport_destroy_tpac;

  while (mr->mr_primaries)
    tport_zap_primary(mr->mr_primaries);

#if HAVE_SIGCOMP
  if (mr->mr_compartment)
    sigcomp_compartment_unref(mr->mr_compartment), mr->mr_compartment = NULL;
#endif

  if (mr->mr_dump_file)
    fclose(mr->mr_dump_file), mr->mr_dump_file = NULL;

  if (mr->mr_timer)
    su_timer_destroy(mr->mr_timer), mr->mr_timer = NULL;

  su_home_zap(mr->mr_home);
}

/** Allocate a primary transport */
static 
tport_primary_t *tport_alloc_primary(tport_master_t *mr)
{
  tport_primary_t *pri, **next;

  for (next = &mr->mr_primaries; *next; next = &(*next)->pri_next)
    ;

  if ((pri = su_home_clone(mr->mr_home, sizeof (*pri)))) {
    tport_t *tp = pri->pri_primary;
    tp->tp_master = mr;
    tp->tp_pri = pri;
    tp->tp_socket = SOCKET_ERROR;

    tp->tp_magic = mr->mr_master->tp_magic;

    tp->tp_params = pri->pri_params;
    memcpy(tp->tp_params, mr->mr_params, sizeof (*tp->tp_params));
    tp->tp_reusable = mr->mr_master->tp_reusable;

    SU_DEBUG_5(("%s(%p): new primary tport %p\n", __func__, mr, pri));
  }

  *next = pri;

  return pri;
}

/**Create a primary transport object with socket.
 *
 * Creates a primary transport object with a server socket, and then
 * registers the socket with suitable events to the root.
 *
 * @param dad   parent (master or primary) transport object
 * @param ai    pointer to addrinfo structure
 * @param canon canonical name of node
 * @param protoname name of the protocol
 */
static
tport_primary_t *tport_listen(tport_master_t *mr, su_addrinfo_t const *ai, 
			      char const *canon, char const *protoname,
			      int port,
			      tagi_t *tags)
{
  tport_primary_t *pri = NULL;

  su_socket_t s = SOCKET_ERROR;
  int index = 0, events = 0, nat_bound = 0;
  su_wakeup_f wakeup = NULL;
  su_wait_t wait[1] = { SU_WAIT_INIT };

  su_sockaddr_t su[1];
  socklen_t sulen = ai->ai_addrlen;

  int err;
  int errlevel = 3;
  char buf[TPORT_HOSTPORTSIZE];

  /* Log an error, return error */
#define TPORT_LISTEN_ERROR(errno, what)  \
  ((void)(err = errno, s != SOCKET_ERROR ? su_close(s) : 0,	     \
	    (SU_LOG_LEVEL >= errlevel ?				     \
	     su_llog(tport_log, errlevel,			     \
		     "%s(%p): %s(pf=%d %s/%s): %s\n",		     \
		     __func__, mr, #what, ai->ai_family,	     \
		     protoname,					     \
		     tport_hostport(buf, sizeof(buf), su, 2),	     \
		     su_strerror(err)) : (void)0),		     \
	    tport_zap_primary(pri),		                     \
	    su_seterrno(err)),					     \
     (void *)NULL)

  if (sulen > sizeof(su))
    return NULL;
  memcpy(su, ai->ai_addr, sulen);

  if (port > 0)
    su->su_port = htons(port);

  /* Create a primary transport object for another transport. */
  pri = tport_alloc_primary(mr);
  if (pri == NULL)
    return TPORT_LISTEN_ERROR(errno, tport_alloc_primary);
  pri->pri_family = ai->ai_family;
  pri->pri_socktype = ai->ai_socktype;
  pri->pri_protocol = ai->ai_protocol;

  if (tport_set_params(pri->pri_primary, TAG_NEXT(tags)) < 0)
    return TPORT_LISTEN_ERROR(su_errno(), tport_set_params);    

  if (ai->ai_protocol == IPPROTO_SCTP) {
    if (pri->pri_params->tpp_mtu > TP_SCTP_MSG_MAX)
      pri->pri_params->tpp_mtu = TP_SCTP_MSG_MAX;
  }

  s = su_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

  if (s == SOCKET_ERROR) {
    if (ai->ai_family == AF_INET6 && su_errno() == EAFNOSUPPORT)
      errlevel = 7;
    return TPORT_LISTEN_ERROR(su_errno(), socket);
  }

  /* Passive open, do bind() (and listen() if connection-oriented). */

#ifdef __linux__
  /* Linux does not allow reusing TCP port while this one is open,
     so we can safely call su_setreuseaddr() before bind(). */
  if (ai->ai_socktype == SOCK_STREAM || ai->ai_socktype == SOCK_SEQPACKET)
    su_setreuseaddr(s, 1);
#endif

  nat_bound = tport_nat_traverse_nat(mr, su, ai, s);

  if (!nat_bound /* || !mr->mr_nat->stun_enabled */) {
    /* STUN has a problem or is not enabled */
    if (bind(s, &su->su_sa, sulen) == SOCKET_ERROR) {
      if (su_errno() == EADDRINUSE) errlevel = 7;
      return TPORT_LISTEN_ERROR(su_errno(), bind);
    }

    if (getsockname(s, &su->su_sa, &sulen) == SOCKET_ERROR)
      return TPORT_LISTEN_ERROR(su_errno(), getsockname);

#if __linux__
    if (ai->ai_family == AF_INET6) {
      if (SU_SOCKADDR_INADDR_ANY(su))
	/* pri->pri_family2 = AF_INET */ ;
      else if (IN6_IS_ADDR_V4MAPPED(&su->su_sin6.sin6_addr) ||
	       IN6_IS_ADDR_V4COMPAT(&su->su_sin6.sin6_addr))
	pri->pri_family = AF_INET;
    }
#endif
  }
    
  if (ai->ai_socktype == SOCK_STREAM || 
      ai->ai_socktype == SOCK_SEQPACKET) {
    /* Connection-oriented protocols listen and accept connections */
    wakeup = tport_accept;	/* accepting function will be registered */
    events = SU_WAIT_ACCEPT;

    /* XXX - we should take this from the current tags */
    if (listen(s, mr->mr_params->tpp_qsize) == SOCKET_ERROR)
      return TPORT_LISTEN_ERROR(su_errno(), listen);
#ifndef __linux__
    /* Allow reusing TCP sockets
     *
     * On Solaris & BSD, call setreuseaddr() after bind in order to avoid
     * binding to a port owned by an existing server.
     */
    su_setreuseaddr(s, 1);
#endif
  } else {
    /* Connectionless protocols sendto() and recvfrom() messages */
    wakeup = tport_recv;	/* receiving function will be registered */
    events = SU_WAIT_IN;

    if (ai->ai_protocol == IPPROTO_UDP) {
      unsigned rmem = 0, wmem = 0;

#if HAVE_IP_RECVERR
      if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
	int const one = 1;
	if (setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0) {
	  if (ai->ai_family == AF_INET)
	    return TPORT_LISTEN_ERROR(su_errno(), IP_RECVERR);
	}
	events |= SU_WAIT_ERR;
      }
#endif
#if HAVE_IPV6_RECVERR
      if (ai->ai_family == AF_INET6) {
	int const one = 1;
	if (setsockopt(s, SOL_IPV6, IPV6_RECVERR, &one, sizeof(one)) < 0)
	  return TPORT_LISTEN_ERROR(su_errno(), IPV6_RECVERR);
	events |= SU_WAIT_ERR;
      }
#endif

      tl_gets(tags, 
	      TPTAG_UDP_RMEM_REF(rmem),
	      TPTAG_UDP_WMEM_REF(wmem),
	      TAG_END());

      if (rmem != 0 && 
	  setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rmem, sizeof rmem) < 0) {
	SU_DEBUG_3(("setsockopt(SO_RCVBUF): %s\n", 
		    su_strerror(su_errno())));
      }

      if (wmem != 0 && 
	  setsockopt(s, SOL_SOCKET, SO_SNDBUF, &wmem, sizeof wmem) < 0) {
	SU_DEBUG_3(("setsockopt(SO_SNDBUF): %s\n", 
		    su_strerror(su_errno())));
      }
    }
  }

  if (su_wait_create(wait, s, events) == -1)
    return TPORT_LISTEN_ERROR(su_errno(), su_wait_create);

  /* Register receiving or accepting function with events specified above */
  index = su_root_register(mr->mr_root, wait, wakeup, pri->pri_primary, 0);
   if (index == -1)
     return TPORT_LISTEN_ERROR(su_errno(), su_root_register);
  if (tport_setname(pri->pri_primary, protoname, su, canon) == -1) 
    return TPORT_LISTEN_ERROR(su_errno(), tport_setname);

  pri->pri_primary->tp_socket   = s;
  pri->pri_primary->tp_index    = index;
  pri->pri_primary->tp_events   = events;
  pri->pri_primary->tp_connected = 0;
  pri->pri_primary->tp_conn_orient = ai->ai_socktype != SOCK_DGRAM;
  pri->pri_primary->tp_addr[0] = su[0];
  pri->pri_primary->tp_addrlen = sulen;
  
  if (nat_bound) {
    /* XXX - should set also the IP address in tp_addr? */
    pri->pri_natted = 1;
    tport_nat_set_canon(pri->pri_primary, mr->mr_nat);
  }

  SU_DEBUG_5(("%s(%p): %s " TPN_FORMAT "\n", 
	      __func__, pri, "listening at",
	      TPN_ARGS(pri->pri_primary->tp_name)));

  return pri;
}

/** Destroy a primary transport and its secondary transports. @internal */
static 
void tport_zap_primary(tport_primary_t *pri)
{
  tport_primary_t **prip;

  if (pri == NULL)
    return;

  assert(tport_is_primary(pri->pri_primary));

  if (pri->pri_threadpool) {
    tport_kill_threadpool(pri);
    SU_DEBUG_3(("%s(%p): zapped threadpool\n", __func__, pri));
  }

  while (pri->pri_secondary)
    tport_zap_secondary(pri->pri_secondary);

  tport_nat_finish(pri);

  /* We have just a single-linked list for primary transports */
  for (prip = &pri->pri_master->mr_primaries;
       *prip != pri;
       prip = &(*prip)->pri_next)
    assert(*prip);

  *prip = pri->pri_next;

  tport_zap_secondary(pri->pri_primary);
}


/**Allocate a secondary transport. @internal
 *
 * The function tport_alloc_secondary() creates a secondary transport
 * object. The new transport initally shares parameters structure with the
 * original transport.
 *
 * @param dad primary transport
 *
 * @return
 * The function tport_alloc_seconary() returns a pointer to the newly
 * created transport, or NULL upon an error.
 */
static
tport_t *tport_alloc_secondary(tport_primary_t *pri)
{
  tport_master_t *mr = pri->pri_master;
  tport_t *self;

  self = su_home_clone(mr->mr_home, sizeof *self);

  if (self) {
    SU_DEBUG_7(("%s(%p): new secondary tport %p\n", __func__, pri, self));

    self->tp_refs = -1;			/* Freshly allocated  */
    self->tp_master = mr;
    self->tp_pri = pri;
    self->tp_params = pri->pri_params;
    self->tp_reusable = pri->pri_primary->tp_reusable;

    self->tp_magic = pri->pri_primary->tp_magic;
  }

  return self;
}

/** Create a connected transport object with socket.
 *
 * The function tport_connect() creates a secondary transport with a
 * connected socket. It registers the socket with suitable events to the
 * root.
 *
 * @param pri   primary transport object
 * @param ai    pointer to addrinfo structure
 * @param canon canonical name of node
 * @param protoname name od the protocol
 */
static
tport_t *tport_connect(tport_primary_t *pri, 
		       su_addrinfo_t *ai,
		       tp_name_t const *tpn)
{
  tport_master_t *mr = pri->pri_master;
  tport_t *self = NULL;

  su_socket_t s = SOCKET_ERROR;
  int index = 0, err;
  su_wait_t wait[1] = { SU_WAIT_INIT };

  int errlevel = 3;
  char buf[TPORT_HOSTPORTSIZE];

  if (ai == NULL || ai->ai_addrlen > sizeof (self->tp_addr))
    return NULL;
  
  /* Log an error, return error */
#define TPORT_CONNECT_ERROR(errno, what)  \
  return							     \
    ((void)(err = errno, s != SOCKET_ERROR ? su_close(s) : 0,	     \
	    su_wait_destroy(wait),				     \
	    (SU_LOG_LEVEL >= errlevel ?				     \
	     su_llog(tport_log, errlevel,			     \
		     "%s(%p): %s(pf=%d %s/%s): %s\n",		     \
		     __func__, pri, #what, ai->ai_family,	     \
		     tpn->tpn_proto,				     \
		       tport_hostport(buf, sizeof(buf),		     \
				      (void *)ai->ai_addr, 2),	     \
		     su_strerror(err)) : (void)0),		     \
	    tport_zap_secondary(self),				     \
	    su_seterrno(err)),					     \
     (void *)NULL)

  if ((self = tport_alloc_secondary(pri)) == NULL)
    TPORT_CONNECT_ERROR(errno, tport_alloc_secondary);

  s = su_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

  if (s == SOCKET_ERROR) {
    if (ai->ai_family == AF_INET6 && su_errno() == EAFNOSUPPORT)
      errlevel = 7;
    TPORT_CONNECT_ERROR(su_errno(), socket);
  }

  if (pri->pri_primary->tp_socket != SOCKET_ERROR) {
    su_sockaddr_t susa;
    socklen_t susalen = sizeof(susa);
    int pri_s = pri->pri_primary->tp_socket;

    if (getsockname(pri_s, &susa.su_sa, &susalen) < 0) {
      SU_DEBUG_3(("tport_connect: getsockname(): %s\n", 
		  su_strerror(su_errno())));
    }
    else {
      susa.su_port = 0;
      if (bind(s, &susa.su_sa, susalen) < 0) {
	SU_DEBUG_3(("tport_connect: bind(local-ip): %s\n", 
		    su_strerror(su_errno())));
      }
    }
  }

  if (/* !do_tls && */ su_setblocking(s, 0) < 0) /* asynchronous connect() */
    TPORT_CONNECT_ERROR(su_errno(), su_setblocking);

  if (ai->ai_socktype == SOCK_STREAM) {
    int one = 1;
    if (setsockopt(s, SOL_TCP, TCP_NODELAY, &one, sizeof one) == -1)
      TPORT_CONNECT_ERROR(su_errno(), setsockopt(TCP_NODELAY));
  }

  if (connect(s, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
    err = su_errno();
    if (err != EINPROGRESS && err != EAGAIN)
      TPORT_CONNECT_ERROR(err, connect);
  }

  if (su_wait_create(wait, s, SU_WAIT_IN | SU_WAIT_HUP) == -1)
    TPORT_CONNECT_ERROR(su_errno(), su_wait_create);

  /* Register receiving function with events specified above */
  if ((index = su_root_register(mr->mr_root, wait, tport_recv, self, 0)) == -1)
    TPORT_CONNECT_ERROR(su_errno(), su_root_register);

  /* */
  if (tport_setname(self, tpn->tpn_proto, 
		    (void *)ai->ai_addr, tpn->tpn_canon) == -1) 
    TPORT_CONNECT_ERROR(su_errno(), tport_setname);

  self->tp_socket   = s;
  self->tp_index    = index;
  self->tp_events   = SU_WAIT_IN | SU_WAIT_HUP;
  self->tp_connected = ai->ai_socktype != SOCK_DGRAM;
  self->tp_conn_orient = 1;

#if HAVE_SIGCOMP
  if (tpn->tpn_comp == pri->pri_primary->tp_name->tpn_comp)
    self->tp_name->tpn_comp = pri->pri_primary->tp_name->tpn_comp;
  if (!pri->pri_primary->tp_name->tpn_comp)
    self->tp_sigcomp->sc_infmt = format_is_noncomp;
#endif

#if HAVE_TLS
  if (pri->pri_primary->tp_tls) {
    self->tp_tls = tls_init_client(pri->pri_primary->tp_tls, s);
    if (!self->tp_tls)
      TPORT_CONNECT_ERROR(errno, tls_init_client);
  }
#endif

  memcpy(self->tp_addr, ai->ai_addr, self->tp_addrlen = ai->ai_addrlen);
  
  SU_DEBUG_5(("%s(%p): %s " TPN_FORMAT "\n", 
	      __func__, self, "connecting to",
	      TPN_ARGS(self->tp_name)));

  tprb_append(&pri->pri_secondary, self);

  return self;
}

/** Destroy a secondary transport. @internal */
static 
void tport_zap_secondary(tport_t *self)
{
  tport_master_t *mr;

  if (self == NULL)
    return;

  /* Remove from rbtree */
  tprb_remove(&self->tp_pri->pri_secondary, self);

  if (self->tp_msg) {
    msg_destroy(self->tp_msg), self->tp_msg = NULL;
    SU_DEBUG_3(("%s(%p): zapped partially received message\n", 
		__func__, self));
  }

  if (self->tp_queue && self->tp_queue[self->tp_qhead]) {
    size_t n = 0, i, N = self->tp_params->tpp_qsize;
    for (i = self->tp_qhead; self->tp_queue[i]; i = (i + 1) % N) {
      msg_destroy(self->tp_queue[i]), self->tp_queue[i] = NULL;
      n++;
    }
    SU_DEBUG_3(("%s(%p): zapped %lu queued messages\n", 
		__func__, self, (LU)n));
  }

  if (self->tp_pused) {
    SU_DEBUG_3(("%s(%p): zapped with pending requests\n", __func__, self));
  }

  mr = self->tp_master;

  if (self->tp_index)
    su_root_deregister(mr->mr_root, self->tp_index);
  self->tp_index = 0;
  if (self->tp_socket != -1)
    su_close(self->tp_socket);
  self->tp_socket = -1;

#if HAVE_TLS
  if (self->tp_tls)
    tls_free(self->tp_tls);
#endif

#if HAVE_SIGCOMP
  if (self->tp_sigcomp) {
    tport_sigcomp_t *sc = self->tp_sigcomp;

    if (sc->sc_udvm)
      sigcomp_udvm_free(sc->sc_udvm), sc->sc_udvm = NULL;
    if (sc->sc_compressor)
      sigcomp_compressor_free(sc->sc_compressor), sc->sc_compressor = NULL;
  }
#endif

  su_home_zap(self->tp_home);
}

/** Create a new transport reference. */
tport_t *tport_incref(tport_t *tp)
{
  if (tp) {
    if (tp->tp_refs >= 0)
      tp->tp_refs++;
    else if (tp->tp_refs == -1)
      tp->tp_refs = 1;
  }
  return tp;
}

/** Destroy a transport reference. */
void tport_decref(tport_t **ttp)
{
  assert(ttp);

  if (*ttp) {
    if ((*ttp)->tp_refs > 0)
      if (--(*ttp)->tp_refs == 0 && (*ttp)->tp_params->tpp_idle == 0)
	if (!tport_is_closed(*ttp))
	  tport_close(*ttp);
    *ttp = NULL;
  }
}

/** Get transport parameters.
 *
 * @param self          pointer to a transport object
 * @param tag,value,... list of tags
 */
int tport_get_params(tport_t const *self,
		     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int n;
  tport_params_t const *tpp;

  if (self == NULL)
    return (errno = EINVAL), -1;

  tpp = self->tp_params;
  ta_start(ta, tag, value);

  n = tl_tgets(ta_args(ta),
	       TPTAG_MTU(tpp->tpp_mtu),
	       TPTAG_REUSE(self->tp_reusable),
	       TPTAG_CONNECT(tpp->tpp_conn_orient),
	       TPTAG_QUEUESIZE(tpp->tpp_qsize),
	       TPTAG_IDLE(tpp->tpp_idle),
	       TPTAG_TIMEOUT(tpp->tpp_timeout),
	       TPTAG_SDWN_ERROR(tpp->tpp_sdwn_error),
	       TPTAG_DEBUG_DROP(tpp->tpp_drop),
	       TPTAG_THRPSIZE(tpp->tpp_thrpsize),
	       TPTAG_THRPRQSIZE(tpp->tpp_thrprqsize),
	       TAG_END());

  ta_end(ta);

  return n;
}

/** Set transport parameters.
 *
 * @param self          pointer to a transport object
 * @param tag,value,... list of tags
 */
int tport_set_params(tport_t *self,
		     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int n;
  tport_params_t tpp[1], *tpp0;

  int connect, sdwn_error, reusable;

  struct sigcomp_compartment *cc = NONE;

  if (self == NULL)
    return (errno = EINVAL), -1;

  memcpy(tpp, tpp0 = self->tp_params, sizeof *tpp);

  connect = tpp->tpp_conn_orient;
  sdwn_error = tpp->tpp_sdwn_error;
  reusable = self->tp_reusable;

  ta_start(ta, tag, value);

  n = tl_gets(ta_args(ta),
	      TPTAG_MTU_REF(tpp->tpp_mtu),
	      TAG_IF(!self->tp_queue, TPTAG_QUEUESIZE_REF(tpp->tpp_qsize)),
	      TPTAG_IDLE_REF(tpp->tpp_idle),
	      TPTAG_TIMEOUT_REF(tpp->tpp_timeout),
	      TPTAG_DEBUG_DROP_REF(tpp->tpp_drop),
	      TPTAG_THRPSIZE_REF(tpp->tpp_thrpsize),
	      TPTAG_THRPRQSIZE_REF(tpp->tpp_thrprqsize),
	      TPTAG_SIGCOMP_LIFETIME_REF(tpp->tpp_sigcomp_lifetime),
	      TPTAG_CONNECT_REF(connect),
	      TPTAG_SDWN_ERROR_REF(sdwn_error),
	      TPTAG_REUSE_REF(reusable),
	      TPTAG_COMPARTMENT_REF(cc),
	      TAG_END());

  ta_end(ta);

  if (n == 0)
    return 0;

  if (tpp->tpp_idle > 0 && tpp->tpp_idle < 2000)
    tpp->tpp_idle = 2000;
  if (tpp->tpp_timeout < 1000)
    tpp->tpp_timeout = 1000;
  if (tpp->tpp_drop > 1000)
    tpp->tpp_drop = 1000;
  if (tpp->tpp_thrprqsize > 0)
    tpp->tpp_thrprqsize = tpp0->tpp_thrprqsize;
  if (tpp->tpp_sigcomp_lifetime != 0 && tpp->tpp_sigcomp_lifetime < 30)
    tpp->tpp_sigcomp_lifetime = 30;
  if (tpp->tpp_qsize >= 1000)
    tpp->tpp_qsize = 1000;

  tpp->tpp_sdwn_error = sdwn_error;

  self->tp_reusable = reusable;

  /* Currently only primary UDP transport can *not* be connection oriented */ 
  tpp->tpp_conn_orient = connect 
    || !tport_is_primary(self) || !tport_is_dgram(self);

  if (tport_is_secondary(self) && 
      self->tp_params == self->tp_pri->pri_primary->tp_params) {
    tpp0 = su_zalloc(self->tp_home, sizeof *tpp0); if (!tpp0) return -1;
  }

#if HAVE_SIGCOMP
  if (cc != NONE && self == self->tp_master->mr_master) {
    if (self->tp_master->mr_compartment)
      sigcomp_compartment_unref(self->tp_master->mr_compartment);
    self->tp_master->mr_compartment = sigcomp_compartment_ref(cc);
  }
#endif

  memcpy(tpp0, tpp, sizeof *tpp);

  return n;
}

/** Bind transport objects. 
 *
 * @deprecated 
 * Use tport_tbind().
 */
int tport_bind(tport_t *self,
	       tp_name_t const *tpn,
	       char const * const transports[],
	       int flags)
{
  return tport_tbind(self, tpn, transports, TAG_END());
}

/** Bind transport objects.
 *
 * @param self        pointer to a transport object
 * @param tpn         desired transport address
 * @param transports  list of protocol names supported by stack
 * @param tag,value,... tagged argument list
 */
int tport_tbind(tport_t *self,
		tp_name_t const *tpn,
		char const * const transports[],
		tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int server = 1, retval;
  tp_name_t mytpn[1];
  tport_master_t *mr;

  if (self == NULL || tport_is_secondary(self) ||
      tpn == NULL || transports == NULL) {
    su_seterrno(EINVAL);
    return -1;
  }

  *mytpn = *tpn;

  if (mytpn->tpn_ident == NULL)
    mytpn->tpn_ident = self->tp_ident;

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta),
	  TPTAG_SERVER_REF(server),
	  TPTAG_IDENT_REF(mytpn->tpn_ident),
	  TAG_END());

  mr = self->tp_master; assert(mr);

  if (server)
    retval = tport_bind_server(mr, mytpn, transports, ta_args(ta));
  else
    retval = tport_bind_client(mr, mytpn, transports, ta_args(ta));


  ta_end(ta);

  return retval;
}

/** Bind primary transport objects used by a client-only application.
 * @internal
 */
int tport_bind_client(tport_master_t *mr,
                      tp_name_t const *tpn,
                      char const * const transports[],
		      tagi_t *tags)
{
  int i;
  tport_primary_t *pri = NULL, **tbf;
  tport_t *tp;

  SU_DEBUG_5(("%s(%p) to " TPN_FORMAT "\n", __func__, mr, TPN_ARGS(tpn)));

  for (tbf = &mr->mr_primaries; *tbf; tbf = &(*tbf)->pri_next)
    ;

  for (i = 0; transports[i]; i++) {
    su_addrinfo_t hints[1];
    char const *proto = transports[i];
    
    if (strcmp(proto, tpn->tpn_proto) != 0 && 
        strcmp(tpn->tpn_proto, tpn_any) != 0)
      continue;

    /* Resolve protocol, skip unknown transport protocols */
    if (getprotohints(hints, proto, AI_PASSIVE) < 0)
      continue;

    if (!(pri = tport_alloc_primary(mr)))
      break;

    tp = pri->pri_primary;
    
#if HAVE_TLS
    if (strcasecmp(proto, "tls") == 0) {
      tp->tp_tls = tport_init_tls(tags);
      if (tp->tp_tls == NULL)
	break;
    }
#endif

    pri->pri_family   = hints->ai_family;
    pri->pri_socktype = hints->ai_socktype;
    pri->pri_protocol = hints->ai_protocol;

    tp->tp_name->tpn_proto = proto;
    tp->tp_name->tpn_host = "*";
    tp->tp_name->tpn_port = "*";
    tp->tp_name->tpn_canon = "*";
    tp->tp_name->tpn_ident = su_strdup(tp->tp_home, tpn->tpn_ident);

    tport_init_compression(pri, tpn->tpn_comp, tags);
  }

  if (!pri)
    tport_zap_primary(*tbf);

  return pri ? 0 : -1;
}

/** Bind primary transport objects used by a server application. */
int tport_bind_server(tport_master_t *mr,
                      tp_name_t const *tpn,
                      char const * const transports[],
		      tagi_t *tags)
{
  char hostname[256];
  char const *proto, *canon, *host, *port;
  char port0[16];
  int ephemeral_port;
  int i, error = 0, not_supported, family = 0;
  tport_primary_t *pri = NULL, **tbf;
  su_localinfo_t *li = NULL;
  unsigned p;

  struct tport_nat_s *nat;

#if SU_HAVE_IN6
  if (!mr->mr_boundserver) {
    /* Check if we can bind to IPv6 separately */
    su_sockaddr_t su[1], su4[1];
    socklen_t sulen, su4len;
    int s6, s4;

    s4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    s6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    memset(su, 0, sizeof *su);
    su->su_len = sulen = (sizeof su->su_sin6);
    su->su_family = AF_INET6;

    memset(su4, 0, sizeof *su4);
    su4->su_len = su4len = (sizeof su->su_sin);
    su4->su_family = AF_INET;

    if (bind(s6, &su->su_sa, sulen) < 0)
      ;
    else if (getsockname(s6, &su->su_sa, &sulen) < 0)
      ;
    else if ((su4->su_port = su->su_port) != 0 && 
	     bind(s4, &su4->su_sa, su4len) == 0)
      mr->mr_bindv6only = 1;

    close(s6), close(s4);

    mr->mr_boundserver = 1;
  }
#endif

  for (tbf = &mr->mr_primaries; *tbf; tbf = &(*tbf)->pri_next)
    ;

  SU_DEBUG_5(("%s(%p) to " TPN_FORMAT "\n", __func__, mr, TPN_ARGS(tpn)));

  nat = tport_nat_initialize_nat_traversal(mr, tpn, &transports);
  if (!nat) 
    SU_DEBUG_1(("%s: %s\n", __func__, strerror(errno)));

  if (tpn->tpn_host == NULL || strcmp(tpn->tpn_host, tpn_any) == 0) {
    /* Use a local IP address */
    host = NULL;
  }
  else if (tpn->tpn_host && tpn->tpn_host[0] == '[') {
    /* Remove [] around IPv6 addresses. */
    host = strcpy(hostname, tpn->tpn_host + 1);
    hostname[strlen(hostname) - 1] = '\0';
  }
  else
    host = tpn->tpn_host; 

  if (tpn->tpn_port != NULL && strlen(tpn->tpn_port) > 0 &&
      strcmp(tpn->tpn_port, tpn_any) != 0)
    port = tpn->tpn_port, ephemeral_port = 0;
  else 
    port = "", ephemeral_port = -1;			/* XXX */

  if (host && (strcmp(host, "0.0.0.0") == 0 || strcmp(host, "0") == 0))
    host = NULL, family = AF_INET;
  else if (host && strcmp(host, "::") == 0)
    host = NULL, family = AF_INET6;

  if (tpn->tpn_canon && strcmp(tpn->tpn_canon, tpn_any) &&
      (host || tpn->tpn_canon != tpn->tpn_host))
    canon = tpn->tpn_canon;
  else {
    /* NULL if UPnP not present */
    canon = tport_nat_get_external_ip_address(nat);
  }

  if (host == NULL) {
    su_localinfo_t hints[1] = {{ 0 }};
    
    hints->li_flags = 0;
    hints->li_family = family;
    hints->li_scope = LI_SCOPE_GLOBAL | LI_SCOPE_SITE | LI_SCOPE_HOST;

    error = su_getlocalinfo(hints, &li);
    if (error) {
      SU_DEBUG_3(("%s(%p): su_getlocalinfo() for %s address: %s\n", 
		  __func__, mr, 
		  family == AF_INET6 ? "ip6" 
		  : family == AF_INET ? "ip4" : "ip",
		  su_gli_strerror(error)));
      su_seterrno(ENOENT);
      return -1;
    }
  }

  /* 
   * Loop until we can bind all the transports requested by the protocol to
   * the same port. 
   */
  do {
    not_supported = 1;		/* Make sure we don't loop for ever */
    pri = NULL;
    
    for (i = 0; transports[i]; i++) {
      su_addrinfo_t *ai, *res, hints[1];

      proto = transports[i];
      error = EPROTONOSUPPORT;

      if (strcasecmp(proto, tpn->tpn_proto) != 0 && 
          strcmp(tpn->tpn_proto, tpn_any) != 0)
        continue;

      /* Resolve protocol, skip unknown transport protocols. */
      if (getprotohints(hints, proto, AI_PASSIVE) < 0)
        continue;

      hints->ai_family = family;

      if (host == NULL)
	hints->ai_flags |= AI_NUMERICHOST;

      pri = NULL;

      if (host)
	error = su_getaddrinfo(host, port, hints, &res);
      else
	error = tport_get_local_addrinfo(mr, li, port, hints, &res);

      if (error || !res) {
	if (error == EAI_SOCKTYPE)
	  SU_DEBUG_7(("%s(%p): su_getaddrinfo(%s, %s) for %s: %s\n", 
		      __func__, mr, host ? host : "\"\"", port, proto,
		      su_gai_strerror(error)));
	else
	  SU_DEBUG_3(("%s(%p): su_getaddrinfo(%s, %s) for %s: %s\n", 
		      __func__, mr, host ? host : "\"\"", port, proto,
		      su_gai_strerror(error)));
	error = ENOENT;
        continue;
      }

      p = ntohs(((su_sockaddr_t *)res->ai_addr)->su_port);

      for (ai = res; ai; ai = ai->ai_next) {
        /* Skip non-internet (AF_LOCAL) addresses */
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
          continue;

        SU_DEBUG_9(("%s(%p): calling tport_socket\n", __func__, mr));

	ai->ai_socktype = hints->ai_socktype;
	ai->ai_protocol = hints->ai_protocol;

        pri = tport_listen(mr, ai, canon, proto, p, tags);

        if (pri) {
	  pri->pri_primary->tp_ident = su_strdup(pri->pri_home, tpn->tpn_ident);
	  tport_init_compression(pri, tpn->tpn_comp, tags);

#if HAVE_TLS
	  if (strcasecmp(tpn->tpn_proto, "tls") == 0) {
	    pri->pri_primary->tp_tls = tport_init_tls(tags);
	    if (!pri->pri_primary->tp_tls)
	      goto error;
	  }
#endif
	  not_supported = 0;
          if (ephemeral_port)
            port = strcpy(port0, pri->pri_primary->tp_port);
          if (ephemeral_port == -1) {
            ephemeral_port = ntohs(pri->pri_primary->tp_addr->su_port);
	    assert(ephemeral_port != 0);
	    if (p == 0)
	      p = ephemeral_port;
	  }
        }
	else {
	  error = su_errno();
	  if (error == EADDRINUSE)
	    not_supported = 0;
	}
      }

      if (host)
	su_freeaddrinfo(res);
      else
	tport_freeaddrinfo(mr, res);

      if (!pri) {
        while (*tbf)
	  tport_zap_primary(*tbf);

        if (ephemeral_port != 0 && ephemeral_port != -1) {
          if (++p >= 65536) p = 1024;
          if (p == ephemeral_port)
            ephemeral_port = 0;
          SU_DEBUG_3(("%s(%p): cannot bind all transports to port %s, "
		      "trying %u\n", 
		      __func__, mr, port, p));
          snprintf(port0, sizeof(port0), "%u", p);
          port = port0;
        }
        break;
      }
    }
  }
  while (!pri && ephemeral_port && !not_supported);

  if (li)
    su_freelocalinfo(li);

  if (not_supported)
    error = EPROTONOSUPPORT;

  if (!pri) {
    su_seterrno(error);
    return -1;
  }

  for (pri = *tbf; pri; pri = pri->pri_next) {
    tport_launch_threadpool(pri);
  }

  return 0;

 error:
  if (li)
    su_freelocalinfo(li);
  return -1;
}


/** Convert localinfo into addrinfo */
static
int
tport_get_local_addrinfo(tport_master_t *mr, 
			 su_localinfo_t *li,
			 char const *port,
			 su_addrinfo_t const *hints,
			 su_addrinfo_t **return_ai)
{
  su_addrinfo_t *ai, **prev;
  su_sockaddr_t *su;
  unsigned long lport = 0;
  char *rest;

  if (port) {
    lport = strtoul(port, &rest, 10);
    if (lport >= 65536) {
      su_seterrno(EINVAL);
      return EAI_NONAME;
    }
  }

  prev = return_ai;

  for (; li; li = li->li_next) {
    if (hints->ai_family && hints->ai_family != li->li_family)
      continue;

    ai = calloc(1, sizeof *ai + li->li_addrlen);
    if (ai == NULL) {
      tport_freeaddrinfo(mr, *return_ai);
      return EAI_MEMORY;
    }
    
    *prev = ai, prev = &ai->ai_next;

    ai->ai_flags = AI_PASSIVE | TP_AI_ANY;
    ai->ai_family = li->li_family;
    ai->ai_socktype = hints->ai_socktype;
    ai->ai_protocol = hints->ai_protocol;
    ai->ai_addr = memcpy(ai + 1, li->li_addr, ai->ai_addrlen = li->li_addrlen);
    su = (void *)ai->ai_addr;
    su->su_port = htons(lport);
  }

  return 0;
}

static
void tport_freeaddrinfo(tport_master_t *mr, 
			su_addrinfo_t *ai)
{
  su_addrinfo_t *ai_next;

  while (ai) {
    ai_next = ai->ai_next;
    free(ai);
    ai = ai_next;
  }
}


#if HAVE_TLS
tls_t *
tport_init_tls(tagi_t *tags)
{
  char *homedir = getenv("HOME");
  char *tbf = NULL;
  char const *path = NULL;
  tls_t *tls = NULL;
  su_home_t *home = su_home_clone(NULL, sizeof *home);
  unsigned version = 1;

  if (getenv("TPORT_SSL"))
    version = 0;

  tl_gets(tags,
	  TPTAG_CERTIFICATE_REF(path),
	  TPTAG_TLS_VERSION_REF(version),
	  TAG_END());

  if (!homedir)
    homedir = "";
	   
  if (!path)
    path = tbf = su_sprintf(home, "%s/.sip/auth", homedir);
  
  if (path) {
    tls_issues_t ti = {0};
    ti.verify_depth = 2;
    ti.configured = path != tbf;
    ti.randFile = su_sprintf(home, "%s/%s", path, "tls_seed.dat");
    ti.key = su_sprintf(home, "%s/%s", path, "agent.pem");
    ti.cert = ti.key;
    ti.CAfile = su_sprintf(home, "%s/%s", path, "cafile.pem");
    ti.version = version;

    SU_DEBUG_9(("%s(%p): tls key = %s\n", __func__, home, ti.key));

    if (ti.key && ti.CAfile && ti.randFile) {
      tls = tls_init_master(&ti);
      if (tls == NULL)
	SU_DEBUG_3(("tls_init_master: %s\n", strerror(errno)));
    }
  }

  su_home_zap(home); 

  return tls;
}
#endif

static 
int tport_init_compression(tport_primary_t *pri, 
			   char const *compression, 
			   tagi_t *tl)
{
#if HAVE_SIGCOMP
  tport_master_t *mr = pri->pri_master;

  if (compression == NULL || 
      strcasecmp(compression, "sigcomp"))
    return 0;

  if (pri->pri_protocol != IPPROTO_TCP &&
      pri->pri_protocol != IPPROTO_UDP) {
    SU_DEBUG_3(("tport: no sigcomp for %s\n", pri->pri_primary->tp_protoname));
    return 0;
  }

  if (mr->mr_compartment) {
    pri->pri_primary->tp_name->tpn_comp = tport_sigcomp_name;
  }
#endif

  return 0;
}

/** Close a transport. 
 * 
 * The function tport_close() closes a socket associated with a transport
 * object.
 */
void tport_close(tport_t *self)
{
  int i;

  SU_DEBUG_5(("%s(%p): " TPN_FORMAT "\n", __func__, self,
	      TPN_ARGS(self->tp_name)));

  self->tp_closed = 1;
  self->tp_send_close = 1;
  self->tp_recv_close = 1;

#if HAVE_TLS
  if (self->tp_tls != NULL) {
    /* if (tport_is_primary(self)) */
      tls_free(self->tp_tls);
      /* XXX - PPe: does the tls_shutdown zap everything but socket? */
    self->tp_tls = NULL;
    su_free(self->tp_home, self->tp_tls_buffer);
  }
  else 
#endif
  if (self->tp_socket != -1)
    shutdown(self->tp_socket, 2);

  if (self->tp_index)
    su_root_deregister(self->tp_master->mr_root, self->tp_index);
  self->tp_index = 0;
  if (self->tp_socket != -1)
    su_close(self->tp_socket);
  self->tp_socket = -1;

  if (self->tp_params->tpp_sdwn_error && self->tp_pused)
    tport_error_report(self, -1, NULL);

#if HAVE_SIGCOMP
  if (self->tp_sigcomp->sc_cc) {
    sigcomp_compartment_unref(self->tp_sigcomp->sc_cc);
    self->tp_sigcomp->sc_cc = NULL;
  }  
#endif

  /* Zap the queued messages */
  if (self->tp_queue) {
    int N = self->tp_params->tpp_qsize;
    for (i = 0; i < N; i++) {
      if (self->tp_queue[i])
	msg_ref_destroy(self->tp_queue[i]), self->tp_queue[i] = NULL;
    }
  }

  self->tp_index = 0;
  self->tp_events = 0;
}

/** Shutdown a transport.
 *
 * The tport_shutdown() shuts down a full-duplex transport connection
 * partially or completely. If @a how is 0, the further incoming data is
 * shut down. If @a how is 1, further outgoing data is shut down. If @a how
 * is 2, both incoming and outgoing traffic is shut down.
 *
 */
int tport_shutdown(tport_t *self, int how)
{
  if (self == NULL || tport_is_primary(self))
    return -1;

  SU_DEBUG_7(("%s(%p, %d)\n", __func__, self, how));

  if (!tport_is_tcp(self) ||
      how < 0 || 
      (how == 0 && self->tp_send_close) ||
      (how == 1 && self->tp_recv_close) || 
      how >= 2) {
    tport_close(self);
    return 1;
  }

#if HAVE_TLS
  if (self->tp_tls != NULL) {
    /* XXX - send alert */
    return 0;
  }
#endif

  shutdown(self->tp_socket, how);

  if (how == 0) {
    self->tp_recv_close = 1;
    self->tp_events &= ~SU_WAIT_IN;
    if (self->tp_params->tpp_sdwn_error && self->tp_pused)
      tport_error_report(self, -1, NULL);
  }
  else if (how == 1) {
    self->tp_send_close = 2;
    self->tp_events &= ~SU_WAIT_OUT;

    if (self->tp_queue && self->tp_queue[self->tp_qhead]) {
      int i, N = self->tp_params->tpp_qsize;
      for (i = 0; i < N; i++) {
	if (self->tp_queue[i]) {
	  tport_pending_errmsg(self, self->tp_queue[i], EPIPE);
	  msg_ref_destroy(self->tp_queue[i]), self->tp_queue[i] = NULL;
	}
      }
    }
  }

  tport_events(self);

  return 0;
}

static inline
unsigned long tport_now(void)
{
  return su_now().tv_sec;
}

/** Transport timer function. */
static
void tport_tick(su_root_magic_t *magic, su_timer_t *t, tport_master_t *mr)
{
  tport_primary_t *dad;
  tport_t *tp, *tp_next;
  su_time_t now = su_now();
  int ts = su_time_ms(now);

  /* Go through all primary transports */
  for (dad = mr->mr_primaries; dad; dad = dad->pri_next) {
    if (dad->pri_protocol == IPPROTO_SCTP) {
      /* Go through all SCTP connections */

      tp = dad->pri_secondary;

      for (tp = tprb_first(tp); tp; tp = tp_next) {
	tp_next = tprb_succ(tp);
	if (tp->tp_queue && tp->tp_queue[tp->tp_qhead]) {
	  SU_DEBUG_9(("tport_tick(%p) - trying to send to %s/%s:%s\n", 
		      tp, tp->tp_protoname, tp->tp_host, tp->tp_port));
	  tport_send_queue(tp);
	}
      }      
    }

    /* Go through all secondary transports with incomplete messages */
    for (tp = tprb_first(dad->pri_secondary); tp; tp = tp_next) {
      msg_t *msg = tp->tp_msg;
      int closed;

      if (msg &&
	  tp->tp_params->tpp_timeout != UINT_MAX && 
	  tp->tp_params->tpp_timeout < ts - (int)tp->tp_time &&
	  !msg_is_streaming(msg)) {
	SU_DEBUG_5(("tport_tick(%p): incomplete message idle for %d ms\n",
		    tp, ts - (int)tp->tp_time));
	msg_set_streaming(msg, 0);
	msg_set_flags(msg, MSG_FLG_ERROR | MSG_FLG_TRUNC | MSG_FLG_TIMEOUT);
	tport_deliver(tp, msg, NULL, NULL, now);
	tp->tp_msg = NULL;
      }

      tp_next = tprb_succ(tp);

      if (tp->tp_refs)
	continue;

      closed = tport_is_closed(tp);

      if (!closed &&
	  !(tp->tp_params->tpp_idle > 0 
	    && tp->tp_params->tpp_idle < ts - (int)tp->tp_time)) {
	continue;
      }

      if (closed) {
	SU_DEBUG_5(("tport_tick(%p): closed, zapping\n", tp));
      } else {
	SU_DEBUG_5(("tport_tick(%p): unused for %d ms, closing and zapping\n",
		    tp, ts - (int)tp->tp_time));
	if (!tport_is_closed(tp))
	  tport_close(tp);
      }

      tport_zap_secondary(tp);
    }
  }

  su_timer_set(t, tport_tick, mr);
}

/** Flush idle connections. */
int tport_flush(tport_t *tp)
{
  tport_t *tp_next;

  if (tp == NULL)
    return -1;

  /* Go through all secondary transports, zap idle ones */
  for (tp = tprb_first(tp->tp_pri->pri_secondary); tp; tp = tp_next) {
    tp_next = tprb_succ(tp);

    if (tp->tp_refs != 0)
      continue;

    SU_DEBUG_1(("tport_flush(%p): %szapping\n",
		tp, tport_is_closed(tp) ? "" : "closing and "));
    if (!tport_is_closed(tp))
      tport_close(tp);
    tport_zap_secondary(tp);
  }

  return 0;
}

/**Convert sockaddr_t to a transport name.
 *
 * @retval 0 when successful
 * @retval -1 upon an error
 */
int tport_convert_addr(su_home_t *home,
		       tp_name_t *tpn,
		       char const *protoname,
		       char const *canon,
		       su_sockaddr_t const *su)
{
  tp_name_t name[1] = {{ NULL }};
  char const *host;
  char buf[TPORT_HOSTPORTSIZE];
  char port[8];
  int canonlen = canon ? strlen(canon) : 0;

  if (!SU_SOCKADDR_INADDR_ANY(su))
    host = tport_hostport(buf, sizeof(buf), su, 0);
  else if (canonlen && su->su_family == AF_INET && 
	   strspn(canon, "0123456789.") == canonlen)
    host = canon;
  else if (canonlen && su->su_family == AF_INET6 && 
	   strspn(canon, "0123456789abcdefABCDEF:.") == canonlen)
    host = canon;
  else
    host = localipname(su->su_family, buf, sizeof(buf));

  if (host == NULL)
    return -1;

  snprintf(port, sizeof(port), "%u", ntohs(su->su_port));
  
  name->tpn_proto = protoname;
  name->tpn_host = host;
  name->tpn_canon = canon ? canon : host;
  name->tpn_port = port;

  return tport_name_dup(home, tpn, name);
}

/** Set transport object name. @internal
 */
static
int tport_setname(tport_t *self,
		  char const *protoname,
		  su_sockaddr_t const *su,
		  char const *canon)
{
  if (tport_convert_addr(self->tp_home, self->tp_name, 
			 protoname, canon, su) < 0)
    return -1;

  if (tport_is_secondary(self))
    self->tp_ident = self->tp_pri->pri_primary->tp_ident;

  return 0;
}

/**Resolve protocol name.
 *
 * Convert a protocol name to IP protocol number and socket type used by
 * su_getaddrinfo().
 *
 * @param hints hints with the protocol number and socktype [OUT]
 * @param proto protocol name [IN]
 * @param flags hint flags      
 */
static
int getprotohints(su_addrinfo_t *hints, 
		  char const *proto,
		  int flags)
{
  memset(hints, 0, sizeof *hints);

  hints->ai_flags = flags;

#if HAVE_TLS
  if (strcasecmp(proto, "tls") == 0)
    proto = "tcp";
#endif

#if HAVE_SCTP  
  if (strcasecmp(proto, "sctp") == 0) {
    hints->ai_protocol = IPPROTO_SCTP;
    hints->ai_socktype = SOCK_STREAM;
    return 0;
  }
#endif

  if (strcasecmp(proto, "udp") == 0) {
    hints->ai_protocol = IPPROTO_UDP;
    hints->ai_socktype = SOCK_DGRAM;
    return 0;
  }
  
  if (strcasecmp(proto, "tcp") == 0) {
    hints->ai_protocol = IPPROTO_TCP;
    hints->ai_socktype = SOCK_STREAM;
    return 0;
  }

  return -1;
}

/** Get local IP.
 *
 * Get primary local IP address in URI format (IPv6 address will be
 * []-quoted).
 */
static
char *localipname(int pf, char *buf, int bufsiz)
{
  su_localinfo_t *li = NULL, hints[1] = {{ LI_NUMERIC | LI_CANONNAME }};
  int n, error;

  hints->li_family = pf;

  if (pf == AF_INET6) {
    /* Link-local addresses are not usable on IPv6 */
    hints->li_scope = LI_SCOPE_GLOBAL | LI_SCOPE_SITE /* | LI_SCOPE_HOST */;
  }

  if ((error = su_getlocalinfo(hints, &li))) {
    if (error == ELI_NOADDRESS && pf == AF_INET6) {
      hints->li_family = AF_INET;
      error = su_getlocalinfo(hints, &li);
      if (error == ELI_NOADDRESS) {
	hints->li_family = AF_INET6; hints->li_scope |= LI_SCOPE_HOST;
	error = su_getlocalinfo(hints, &li);
      }
      if (error == ELI_NOADDRESS) {
	hints->li_family = AF_INET;
	error = su_getlocalinfo(hints, &li);
      }
    }
    if (error) {
      SU_DEBUG_1(("tport: su_getlocalinfo: %s\n", su_gli_strerror(error)));
      return NULL;
    }
  }

  assert(li); assert(li->li_canonname);

  n = strlen(li->li_canonname);

  if (li->li_family == AF_INET) {
    if (n >= bufsiz)
      return NULL;
    
    memcpy(buf, li->li_canonname, n + 1);
  }
  else {
    if (n + 2 >= bufsiz)
      return NULL;

    memcpy(buf + 1, li->li_canonname, n);
    buf[0] = '['; buf[++n] = ']'; buf[++n] = '\0';
  }
      
  su_freelocalinfo(li);
  
  return buf;
}

/** Process errors from transport. */
static void tport_error_report(tport_t *self, int errcode, 
			       su_sockaddr_t const *addr)
{
  char const *errmsg;

  if (errcode == 0)
    return;
  else if (errcode > 0)
    errmsg = su_strerror(errcode);
  else
    errcode = 0, errmsg = "stream closed";

  if (addr && addr->su_family == AF_UNSPEC)
    addr = NULL;

  /* Mark this connection as unusable */
  if (errcode > 0 && tport_is_connected(self))
    self->tp_send_close = 2, self->tp_recv_close = 1;

  if (addr == NULL && tport_is_connection_oriented(self))
    addr = self->tp_addr;

  /* Report error */
  if (addr && tport_pending_error(self, addr, errcode))
    ;
  else if (self->tp_master->mr_tpac->tpac_error) {
    char *dstname = NULL;
    char hp[TPORT_HOSTPORTSIZE];

    if (addr)
      dstname = tport_hostport(hp, sizeof hp, addr, 1);

    STACK_ERROR(self, errcode, dstname);
  }
  else {
    if (tport_is_primary(self))
      SU_DEBUG_3(("%s(%p): %s (with %s)\n", __func__, self, 
		  errmsg, self->tp_protoname));
    else
      SU_DEBUG_3(("%s(%p): %s (with %s/%s:%s)\n", __func__, self, 
		  errmsg, self->tp_protoname, self->tp_host, self->tp_port));
  }

  /* Close connection */
  if (!self->tp_closed && errcode > 0 && tport_is_connected(self))
    tport_close(self);
}

/** Accept a new connection.
 * 
 * The function tport_accept() accepts a new connection and creates a
 * secondary transport object for the new socket.
 */
static 
int tport_accept(su_root_magic_t *m, su_wait_t *w, tport_t *_pri)
{
  tport_primary_t *pri = _pri->tp_pri;
  tport_t *self;
  su_sockaddr_t su[1]; 
  socklen_t sulen = sizeof(su);
  su_socket_t s = SOCKET_ERROR, l = pri->pri_primary->tp_socket;
  int events = su_wait_events(w, l);
  int one = 1;

  assert(pri == _pri->tp_pri);

  if (events & SU_WAIT_ERR)
    tport_error_event(pri->pri_primary, events);

  if (!(events & SU_WAIT_ACCEPT))
    return 0;

  s = accept(l, &su->su_sa, &sulen);

  if (s < 0) {
    tport_error_report(pri->pri_primary, su_errno(), NULL);
    return 0;
  }

  setsockopt(s, SOL_TCP, TCP_NODELAY, &one, sizeof one);

  SU_CANONIZE_SOCKADDR(su);

  /* Alloc a new transport object, then register socket events with it */ 
  self = tport_alloc_secondary(pri);

  if (self) {
    int i;
    su_wakeup_f wakeup = tport_recv;
    int events = SU_WAIT_IN|SU_WAIT_ERR|SU_WAIT_HUP;
    su_wait_t wait[1] = { SU_WAIT_INIT };
    
    self->tp_socket = s;

    if (pri->pri_socktype == SOCK_STREAM)
      su_setblocking(s, 0);

#if HAVE_TLS
    if (pri->pri_primary->tp_tls)
      self->tp_tls = tls_init_slave(pri->pri_primary->tp_tls, s);
#endif

    if (
#if HAVE_TLS
	!pri->pri_primary->tp_tls == !self->tp_tls &&
#endif
	/* Create wait object with appropriate events. */
	su_wait_create(wait, s, events) != -1 
	/* Register socket to root */
	&&
	(i = su_root_register(self->tp_master->mr_root, wait, wakeup, self, 0)) != -1) {

      self->tp_index     = i;
      self->tp_connected = 1;
      self->tp_events   = events;
      self->tp_addr[0]  = su[0];
      self->tp_addrlen  = sulen;

#if HAVE_TLS
      if (self->tp_tls && events != tls_events(self->tp_tls, events))
	tport_events(self);
#endif

      if (tport_setname(self, pri->pri_protoname, su, NULL) != -1) {
#if HAVE_SIGCOMP
	if (!pri->pri_primary->tp_name->tpn_comp)
	  self->tp_sigcomp->sc_infmt = format_is_noncomp;
#endif
	SU_DEBUG_5(("%s(%p): new connection from " TPN_FORMAT "\n", 
		    __func__,  self, TPN_ARGS(self->tp_name)));

	tprb_append(&pri->pri_secondary, self);

	/* Return succesfully */
	return 0;
      }
    }
    else
      su_wait_destroy(wait);

    /* Failure: shutdown socket,  */
    tport_close(self);
    tport_zap_secondary(self);
  }
  else {
    su_close(s);
  }

  /* XXX - report error ? */

  return 0;
}

/** Allocate a new message object */
msg_t *tport_msg_alloc(tport_t const *self, unsigned size)
{
  if (self) {
    tport_master_t *mr = self->tp_master;
    msg_t *msg = mr->mr_tpac->tpac_alloc(mr->mr_stack, mr->mr_msg_flags,
				  NULL, size, self, NULL);
    if (msg) {
      msg_addrinfo(msg)->ai_family =   self->tp_pri->pri_family;
      msg_addrinfo(msg)->ai_protocol = self->tp_pri->pri_protocol;
      msg_addrinfo(msg)->ai_socktype = self->tp_pri->pri_socktype;
    }

    return msg;
  }
  else {
    return NULL;
  }
}

/** Process events for connected socket
 */
static int tport_recv(su_root_magic_t *magic, su_wait_t *w, tport_t *self)
{
  int events = su_wait_events(w, self->tp_socket);
#if HAVE_TLS
  int old_mask = 0, new_mask;
  
  if (self->tp_tls)
    old_mask = tls_events(self->tp_tls, self->tp_events);
#endif

  SU_DEBUG_7(("tport_recv(%p): events%s%s%s%s\n", self,
	      events & SU_WAIT_IN ? " IN" : "",
	      events & SU_WAIT_HUP ? " HUP" : "",
	      events & SU_WAIT_OUT ? " OUT" : "",
	      events & SU_WAIT_ERR ? " ERR" : ""));

#if HAVE_POLL
  assert(w->fd == self->tp_socket);
#endif

  if (events & SU_WAIT_ERR)
    tport_error_event(self, events);

#if HAVE_TLS
  if (self->tp_tls)
    events = tport_tls_event(self, events);
#endif

  if ((events & SU_WAIT_OUT) && !self->tp_closed)
    tport_send_event(self, events);

  if ((events & SU_WAIT_IN) && !self->tp_closed)
    tport_recv_event(self, events);
  
  if ((events & SU_WAIT_HUP) && !self->tp_closed)
    tport_hup_event(self, events);

#if HAVE_TLS
  if (self->tp_tls && !self->tp_closed) {
    new_mask = tls_events(self->tp_tls, self->tp_events);

    if (old_mask ^ new_mask)
      tport_events(self);
  }
#endif

  return 0;
}

#if HAVE_TLS
/** Handle TLS events */
int tport_tls_event(tport_t *self, int events)
{
  int ret, fake_events = 0;
  
  if ((self->tp_events & SU_WAIT_IN) && !self->tp_closed) {
    ret = tls_want_read(self->tp_tls, events);
    if (ret > 0)
      fake_events |= SU_WAIT_IN;
    else if (ret < 0)
      tport_error_report(self, errno, NULL);
  }
  
  if ((self->tp_events & SU_WAIT_OUT) && !self->tp_closed) {
    ret = tls_want_write(self->tp_tls, events);
    if (ret > 0)
      fake_events |= SU_WAIT_OUT;
    else if (ret < 0)
      tport_error_report(self, errno, NULL);
  }
  
  events &= ~(SU_WAIT_IN | SU_WAIT_OUT);
  events |= fake_events;

  return events;
}
#endif

/** Stop reading from socket until tport_continue() is called. */
int tport_stall(tport_t *self)
{
  if (self == NULL)
    return -1;

  self->tp_events &= ~SU_WAIT_IN;

  return tport_events(self);
}

/** Continue reading from socket. */
int tport_continue(tport_t *self)
{
  if (self == NULL || self->tp_recv_close)
    return -1;

  self->tp_events |= SU_WAIT_IN;

  return tport_events(self);
}

/** Process "hangup" event.
 *
 */
static void tport_hup_event(tport_t *self, int events)
{
  SU_DEBUG_7(("%s(%p)\n", __func__, self));

  if (self->tp_msg) {
    su_time_t now = su_now();
    msg_recv_commit(self->tp_msg, 0, 1);
    tport_parse(self, 1, now);
  }

  /* End of stream */
  tport_shutdown(self, 0);
}

static int tport_recv_data(tport_t *self);

/** Process "ready to receive" event.
 *
 */
static void tport_recv_event(tport_t *self, int event)
{
  su_time_t now;
  int again;

  SU_DEBUG_7(("%s(%p)\n", __func__, self));

  do {
    now = su_now(); 

    /* Receive data from socket */
    if ((again = tport_recv_data(self)) < 0) {
      int error = su_errno();

      if (error != EAGAIN) {
	tport_error_report(self, error, NULL);
	/* Failure: shutdown socket */
	if (tport_is_connected(self))
	  tport_close(self);
	return;
      } else {
	SU_DEBUG_3(("%s: recvfrom(): %s (%d)\n", __func__, 
		    su_strerror(EAGAIN), EAGAIN));
      }
    }

    self->tp_time = su_time_ms(now);

    if (again >= 0)
      tport_parse(self, !again, now);
  } 
  while (again > 1);

  if (again == 0 && !tport_is_dgram(self)) {
    /* End of stream */
    if (!self->tp_closed) {
      /* Don't shutdown completely if there are queued messages */
      tport_shutdown(self, self->tp_queue && self->tp_queue[self->tp_qhead] ? 0 : 2);
    }
  }
}

/* 
 * Parse the data and feed complete messages to the stack 
 */
static void tport_parse(tport_t *self, int complete, su_time_t now)
{
  msg_t *msg, *next = NULL;
  int n, streaming, stall = 0;

  for (msg = self->tp_msg; msg; msg = next) {
    n = msg_extract(msg);	/* Parse message */

    streaming = 0;

    if (n == 0) {
      if (complete)
	msg_mark_as_complete(msg, MSG_FLG_ERROR), n = -1;
      else if (!(streaming = msg_is_streaming(msg))) {
	tport_try_accept_sigcomp(self, msg);
	break;
      }
    } 

    if (msg_get_flags(msg, MSG_FLG_TOOLARGE))
      SU_DEBUG_3(("%s(%p): too large message from " TPN_FORMAT "\n",
		  __func__, self, TPN_ARGS(self->tp_name)));

    /* Do not try to read anymore from this connection? */
    if (tport_is_stream(self) && 
	msg_get_flags(msg, MSG_FLG_TOOLARGE | MSG_FLG_ERROR))
      self->tp_recv_close = stall = 1;
    
    if (n == -1)
      next = NULL;
    else if (streaming)
      msg_ref_create(msg);	/* Keep a reference */
    else if (tport_is_stream(self))
      next = msg_next(msg);
    else
      next = NULL;

#if HAVE_SIGCOMP
    tport_deliver(self, msg, next, &self->tp_sigcomp->sc_udvm, now);
#else
    tport_deliver(self, msg, next, NULL, now);
#endif

    if (streaming && next == NULL)
      break;
  }

  if (stall)
    tport_stall(self);

  if (self->tp_rlogged != msg)
    self->tp_rlogged = NULL;
  
  self->tp_msg = msg;
}

/** Deliver message to the protocol stack */
static 
void tport_deliver(tport_t *self, msg_t *msg, msg_t *next, 
		   struct sigcomp_udvm **pointer_to_udvm,
		   su_time_t now)
{
  tport_t *ref;
  int error;
  struct tport_delivery *d;

  assert(msg);

  d = self->tp_master->mr_delivery;

  d->d_tport = self;
  d->d_msg = msg;
  d->d_udvm = pointer_to_udvm;
  *d->d_from = *self->tp_name;

  if (tport_is_primary(self)) {
    char ipaddr[SU_ADDRSIZE + 2];
    su_sockaddr_t *su = msg_addr(msg);

    if (su->su_family == AF_INET6) {
      ipaddr[0] = '[';
      inet_ntop(su->su_family, SU_ADDR(su), ipaddr + 1, sizeof(ipaddr) - 1);
      strcat(ipaddr, "]");
    }
    else {
      inet_ntop(su->su_family, SU_ADDR(su), ipaddr, sizeof(ipaddr));
    }

    d->d_from->tpn_canon = ipaddr;
    d->d_from->tpn_host = ipaddr;    
  }

#if HAVE_SIGCOMP
  if (!pointer_to_udvm && !*pointer_to_udvm)
#endif
    d->d_from->tpn_comp = NULL;

  error = msg_has_error(msg);

  if (error && !*msg_chain_head(msg)) {
    /* This is badly damaged packet */
  }
  else if (self->tp_master->mr_log && msg != self->tp_rlogged) {
    char const *via = "recv";
    tport_log_msg(self, msg, via, "from", "   ", now);
    self->tp_rlogged = msg;
  }

  SU_DEBUG_7(("%s(%p): %smsg %p (%u bytes)"
	      " to stack from " TPN_FORMAT " next=%p\n", 
	      __func__, self, error ? "bad " : "", msg, msg_size(msg),
	      TPN_ARGS(d->d_from), next));

  ref = tport_incref(self);
  /* Pass message to the protocol stack */
  STACK_RECV(self, msg, now);

#if HAVE_SIGCOMP
  if (d->d_udvm && *d->d_udvm)
    sigcomp_udvm_accept(*d->d_udvm, NULL);
#endif

  tport_decref(&ref);

  d->d_msg = NULL;
}

/** Return source transport object for delivered message */
tport_t *tport_delivered_by(tport_t const *tp, msg_t const *msg)
{
  if (tp && msg && msg == tp->tp_master->mr_delivery->d_msg)
    return tp->tp_master->mr_delivery->d_tport;
  else
    return NULL;
}


/** Return source transport name for delivered message */
int tport_delivered_from(tport_t *tp, msg_t const *msg, tp_name_t name[1])
{
  if (name == NULL)
    return -1;
  
  if (tp == NULL || msg == NULL || msg != tp->tp_master->mr_delivery->d_msg) {
    memset(name, 0, sizeof *name);
    return -1;
  }
  else {
    *name = *tp->tp_master->mr_delivery->d_from;
    return 0;
  }
}

/** Return UDVM used to decompress the message. */
int
tport_delivered_using_udvm(tport_t *tp, msg_t const *msg,
			   struct sigcomp_udvm **return_pointer_to_udvm,
			   int remove)
{
  if (tp == NULL || msg == NULL || msg != tp->tp_master->mr_delivery->d_msg)
    return -1;

  if (return_pointer_to_udvm) {
    if (tp->tp_master->mr_delivery->d_udvm) {
      *return_pointer_to_udvm = *tp->tp_master->mr_delivery->d_udvm;
      if (remove)
	tp->tp_master->mr_delivery->d_udvm = NULL;
    }
    else {
      *return_pointer_to_udvm = NULL;
    }
  }

  return 0;
}

static int tport_recv_stream(tport_t *self);
static int tport_recv_dgram(tport_t *self);
static int tport_recv_dgram_r(tport_t const *self, msg_t **mmsg, int N);

#if HAVE_TLS
static int tport_recv_tls(tport_t *self);
#endif
#if HAVE_SIGCOMP
static int tport_recv_sigcomp(tport_t *self);
#endif
static int tport_recv_sctp(tport_t *self);

/** Receive data available on the socket.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive
 * @retval 2  incomplete recv, recv again
 */
static 
int tport_recv_data(tport_t *self)
{
#if HAVE_TLS
  if (self->tp_tls)
    return tport_recv_tls(self);
#endif

  /* Simulate packet loss */
  if (self->tp_pri->pri_protocol == IPPROTO_UDP &&
      self->tp_params->tpp_drop && 
      su_randint(0, 1000) < self->tp_params->tpp_drop) {
    char sample[1];
    recv(self->tp_socket, &sample, 1, 0);
    SU_DEBUG_3(("tport(%p): simulated packet loss!\n", self));
    return 0;
  }

#if HAVE_SIGCOMP
  if (tport_can_recv_sigcomp(self))
    return tport_recv_sigcomp(self);
#endif
#if 0
  if (self->tp_pri->pri_socktype == 0)
    return tport_recv_file(self);
#endif
  if (self->tp_pri->pri_protocol == IPPROTO_SCTP)
    return tport_recv_sctp(self);
  if (self->tp_pri->pri_socktype == SOCK_STREAM)
    return tport_recv_stream(self);
  if (self->tp_pri->pri_socktype == SOCK_DGRAM)
    return tport_recv_dgram(self);
  
  SU_DEBUG_1(("%s(%p): receive semantics not implemented\n", __func__, self));

  su_seterrno(EINVAL);		/* Internal error */
  return -1;
}

/** Allocate message for N bytes,
 *  return message buffer as a iovec */
static int tport_recv_iovec(tport_t const *self, 
			    msg_t **mmsg,
			    msg_iovec_t iovec[msg_n_fragments], int N, 
			    int exact)
{
  msg_t *msg = *mmsg;
  int veclen, fresh;

  if (N == 0)
    return 0;

  fresh = !msg;

  /*
   * Allocate a new message if needed 
   */
  if (!msg) {
    if (!(*mmsg = msg = tport_msg_alloc(self, N))) {
      SU_DEBUG_7(("%s(%p): cannot allocate msg for %u bytes "
		  "from (%s/%s:%s)\n", 
		  __func__, self, N, 
		  self->tp_protoname, self->tp_host, self->tp_port));
      return -1;
    }
  }

  /*
   * Get enough buffer space for the incoming data
   */
  veclen = msg_recv_iovec(msg, iovec, msg_n_fragments, N, exact);
  if (veclen < 0) {
    if (fresh && errno == ENOBUFS && msg_get_flags(msg, MSG_FLG_TOOLARGE))
      veclen = msg_recv_iovec(msg, iovec, msg_n_fragments, 4096, 1);
  }
  if (veclen < 0) {
    int err = errno;
    SU_DEBUG_7(("%s(%p): cannot get msg %p buffer for %u bytes "
		"from (%s/%s:%s): %s\n", 
		__func__, self, msg, N, 
		self->tp_protoname, self->tp_host, self->tp_port,
		su_strerror(err)));
    su_seterrno(err);
    return veclen;
  }

  assert(veclen <= msg_n_fragments);

  SU_DEBUG_7(("%s(%p) msg %p from (%s/%s:%s) has %u bytes, veclen = %d\n",
              __func__, self, 
	      msg, self->tp_protoname, self->tp_host, self->tp_port, 
	      N, veclen));
  for (N = 0; veclen > 1 && N < veclen; N++) {
    SU_DEBUG_7(("\tiovec[%u] = %lu bytes\n", N, (LU)iovec[N].mv_len));
  }

  return veclen;
}

static int tport_recv_error_report(tport_t *self)
{
  if (su_errno() == EAGAIN)
    return 1;

  /* Report error */
  tport_error_report(self, su_errno(), NULL);

  return -1;
}

/** Receive datagram.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 */
static 
int tport_recv_dgram(tport_t *self)
{
  int N = su_getmsgsize(self->tp_socket);

  if (N == 0) {
#if defined(__arm__) && defined(__GNUC__)
    /* XXX: recv() with zero len blocks infinitely on some arm-linux targets */
    tport_error_event(self, 0);
#else
    SU_DEBUG_1(("tport_recv_dgram(%p): empty msg\n", self));
    /* recv(self->tp_socket, (void *)iovec, sizeof(iovec), 0); */
#endif
    return 0;
  }
  if (N == -1) {
    int err = su_errno();
    SU_DEBUG_1(("%s: su_getmsgsize(): %s (%d)\n", __func__, 
		su_strerror(err), err));
    return -1;
  }

  return tport_recv_dgram_r(self, &self->tp_msg, N);
}

/** Receive datagram.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 */
static 
int tport_recv_dgram_r(tport_t const *self, msg_t **mmsg, int N)
{
  msg_t *msg;
  int n, veclen;
  su_sockaddr_t *from;
  socklen_t *fromlen;
  msg_iovec_t iovec[msg_n_fragments] = {{ 0 }};

  assert(*mmsg == NULL);

  veclen = tport_recv_iovec(self, mmsg, iovec, N, 1);
  if (veclen < 0)
    return -1;

  msg = *mmsg;

  n = su_vrecv(self->tp_socket, iovec, veclen, 0, 
	       from = msg_addr(msg), fromlen = msg_addrlen(msg));
  if (n == SOCKET_ERROR) {
    int error = su_errno();
    msg_destroy(msg); *mmsg = NULL;
    su_seterrno(error);
    return -1;
  }

  SU_CANONIZE_SOCKADDR(from);
  assert(n <= N);		/* FIONREAD tells the size of all messages.. */

  if (self->tp_master->mr_dump_file && !self->tp_pri->pri_threadpool)
    tport_dump_iovec(self, msg, n, iovec, veclen, "recv", "from");

  msg_recv_commit(msg, n, 1);  /* Mark buffer as used */

  return 0;
}

/** Receive from stream.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive
 * @retval 2  incomplete recv, recv again
 * 
 */
static int tport_recv_stream(tport_t *self)
{
  msg_t *msg;
  int n, N, veclen, err;
  msg_iovec_t iovec[msg_n_fragments] = {{ 0 }};

  N = su_getmsgsize(self->tp_socket);
  if (N == 0) {
    if (self->tp_msg)
      msg_recv_commit(self->tp_msg, 0, 1);
    return 0;    /* End of stream */
  }
  if (N == -1) {
    err = su_errno();
    SU_DEBUG_1(("%s(%p): su_getmsgsize(): %s (%d)\n", __func__, self,
		su_strerror(err), err));
    return -1;
  }

  veclen = tport_recv_iovec(self, &self->tp_msg, iovec, N, 0);
  if (veclen < 0)
    return -1;

  msg = self->tp_msg;

  /* Message address */
  *msg_addr(msg) = *self->tp_addr;
  *msg_addrlen(msg) = self->tp_addrlen;

  n = su_vrecv(self->tp_socket, iovec, veclen, 0, NULL, NULL);
  if (n == SOCKET_ERROR)
    return tport_recv_error_report(self);

  assert(n <= N);

  /* Write the received data to the message dump file */
  if (self->tp_master->mr_dump_file)
    tport_dump_iovec(self, msg, n, iovec, veclen, "recv", "from");

  /* Mark buffer as used */
  msg_recv_commit(msg, n, 0);

  return 1;
}

#if HAVE_SIGCOMP

/** Receive data using SigComp. */
static int tport_recv_sigcomp(tport_t *self)
{
  struct sigcomp_udvm *udvm;
  int retval, stream;

  SU_DEBUG_7(("%s(%p)\n", __func__, self));

  stream = tport_is_stream(self);

  /* Peek for first byte in message/stream, 
     determine if this is a compressed stream or not */
  if (!stream || self->tp_sigcomp->sc_infmt == format_is_unknown) {
    unsigned char sample;
    int n;

    n = recv(self->tp_socket, &sample, 1, MSG_PEEK);
    if (n < 0)
      return n;
    if (n == 0) {
      recv(self->tp_socket, &sample, 1, 0);
      return 0;			/* E-o-S from first message */
    }

    if ((sample & 0xf8) != 0xf8) {
      /* Not SigComp, receive as usual */
      if (self->tp_pri->pri_socktype == SOCK_DGRAM)
	return tport_recv_dgram(self);

      if (tport_is_primary(self)) {
	SU_DEBUG_1(("%s(%p): receive semantics not implemented\n", 
		    __func__, self));
	su_seterrno(EINVAL);		/* Internal error */
	return -1;
      }

      /* Do not try to receive with sigcomp from this socket */
      if (stream)
	self->tp_sigcomp->sc_infmt = format_is_noncomp;

      return tport_recv_data(self);
    }
    else {
      /* SigComp, receive using UDVM */ 
      if (stream)
	self->tp_sigcomp->sc_infmt = format_is_sigcomp;      

      self->tp_sigcomp->sc_udvm = tport_init_udvm(self);

      if (!self->tp_sigcomp->sc_udvm) {
	int save = errno;
	recv(self->tp_socket, &sample, 1, 0); /* remove msg from socket */
	errno = save;
	return -1;
      }
    }
  }

  udvm = self->tp_sigcomp->sc_udvm; assert(udvm);

  retval = tport_recv_sigcomp_r(self, &self->tp_msg, udvm);

  if (retval < 0)
    sigcomp_udvm_reject(udvm);

  return retval;
}

/** Receive data available on the socket.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive
 * @retval 2  incomplete recv, recv again
 */
static int tport_recv_sigcomp_r(tport_t *self, 
				msg_t **mmsg,
				struct sigcomp_udvm *udvm)
{
  msg_t *msg;
  unsigned n, N, m, i, eos, complete;
  int veclen;
  msg_iovec_t iovec[msg_n_fragments] = {{ 0 }};
  su_sockaddr_t su[1];
  socklen_t su_size = sizeof(su);
  struct sigcomp_buffer *input, *output;
  void *data;
  unsigned dlen;

  SU_DEBUG_7(("%s(%p)\n", __func__, self));

  assert(udvm);

  if (sigcomp_udvm_has_input(udvm)) {
    input = sigcomp_udvm_input_buffer(udvm, n = N = 0); assert(input);
  } else {
    N = su_getmsgsize(self->tp_socket);
    if (N == (unsigned)-1) 
      return -1;

    if (N == 0) {
      assert(self->tp_pri->pri_socktype != SOCK_DGRAM);
      if (self->tp_pri->pri_socktype == SOCK_DGRAM) {
	recv(self->tp_socket, (void *)su, 1, 0);
	return 1;
      }
    }

    input = sigcomp_udvm_input_buffer(udvm, N); assert(input);
    if (input == NULL)
      return (errno = EIO), -1;

    data = input->b_data + input->b_avail;
    dlen = input->b_size - input->b_avail;
    
    if (tport_is_stream(self)) {
      n = recv(self->tp_socket, data, dlen, 0);
    } 
    else if (dlen >= N) {
      n = recvfrom(self->tp_socket, data, dlen, 0, &su->su_sa, &su_size);
      SU_CANONIZE_SOCKADDR(su);
    } 
    else {
      recvfrom(self->tp_socket, data, dlen, 0, &su->su_sa, &su_size);
      SU_CANONIZE_SOCKADDR(su);
      su_seterrno(EMSGSIZE);		/* Protocol error */
      return -1;
    }
  
    if (n == (unsigned)-1) {
      char const *pn = self->tp_protoname;
      int err = su_errno();
    
      if (err == EAGAIN) {
	SU_DEBUG_7(("%s(%p): recv from %s: EAGAIN\n", __func__, self, pn));
	return 1;
      }
    
      SU_DEBUG_1(("%s(%p): recv from %s: %s (%d)\n", __func__, self, pn,
		  su_strerror(err), err));
      return -1;
    }
  
    /* XXX - in case of stream, use message buffers for output? */
    
    input->b_avail += n;
    input->b_complete = (n == 0) || !tport_is_stream(self);
  }

  for (complete = eos = 0; !complete;) {
    output = sigcomp_udvm_output_buffer(udvm, 16384);
    
    if (sigcomp_udvm_decompress(udvm, output, input) < 0) {
      int error = sigcomp_udvm_errno(udvm);
      
      SU_DEBUG_3(("%s: UDVM error %d: %s\n", __func__,
		  error, sigcomp_udvm_strerror(udvm)));
      
      su_seterrno(EREMOTEIO);

      return -1;
    }

    data = output->b_data + output->b_used;
    dlen = output->b_avail - output->b_used;
    complete = output->b_complete;
    eos = complete && input->b_complete;

    veclen = tport_recv_iovec(self, mmsg, iovec, dlen, eos);
    
    if (dlen ? veclen <= 0 : veclen < 0) {
      return -1;
    }

    for (i = 0, n = 0; i < veclen; i++) {
      m = iovec[i].mv_len; assert(dlen >= n + m);
      memcpy(iovec[i].mv_base, data + n, m);
      n += m;
    }
    assert(dlen == n);

    msg = *mmsg;
    
    if (msg) {
      /* Message address */
      if (self->tp_pri->pri_socktype == SOCK_STREAM) {
	*msg_addr(msg) = *self->tp_addr;
	*msg_addrlen(msg) = self->tp_addrlen;
      } else {
	*msg_addr(msg) = *su;
	*msg_addrlen(msg) = su_size;
      }
      
      SU_DEBUG_5(("%s(%p): sigcomp recv = %u => %u %s\n", __func__, self, 
		  N, dlen, eos ? " (complete)" : ""));

      msg_mark_as_compressed(msg);
      
      /* Write the received data to the message dump file */
      if (self->tp_master->mr_dump_file && !self->tp_pri->pri_threadpool)
	tport_dump_iovec(self, msg, n, iovec, veclen, "recv", "from");
      
      msg_recv_commit(msg, dlen, eos);    /* Mark buffer as used */
    }
    else {
      SU_DEBUG_5(("%s(%p): sigcomp recv = %u => %u %s\n", __func__, self, 
		  N, dlen, eos ? " (complete)" : ""));
      if (complete || !tport_is_stream(self)) {
	sigcomp_udvm_reject(udvm); /* Reject empty message */
      }
    }

    if (self->tp_pri->pri_socktype == SOCK_STREAM) {
      if (eos)
	return 0;
    
      if (output->b_complete)
	return n < N || sigcomp_udvm_has_pending_data(udvm) ? 2 : 1;

      if (!sigcomp_udvm_has_input(udvm))
	return 1;
    }
  }

  return eos ? 0 : 2;
}

/** Initialize UDVM */
static 
struct sigcomp_udvm *tport_init_udvm(tport_t *self)
{
  struct sigcomp_compartment *cc;
  struct sigcomp_udvm *udvm;

  if (self->tp_sigcomp->sc_udvm)
    return self->tp_sigcomp->sc_udvm;

  cc = tport_primary_compartment(self->tp_master);

  if (!cc)
    return NULL;

  if (self->tp_pri->pri_socktype == SOCK_STREAM)
    udvm = sigcomp_udvm_create_for_stream(cc);
  else
    udvm = sigcomp_udvm_create_for_compartment(cc);

  return udvm;
}


/** Get primary compartment */
static 
struct sigcomp_compartment *
tport_primary_compartment(tport_master_t *mr)
{
  return mr->mr_compartment;
}

/** Assign a SigComp compartment (to a possibly connected tport). */
int tport_sigcomp_assign(tport_t *self, struct sigcomp_compartment *cc)
{
  if (tport_is_connection_oriented(self) && 
      tport_is_secondary(self) &&
      self->tp_socket != SOCKET_ERROR) {

    if (self->tp_sigcomp->sc_cc) {
      if (cc == self->tp_sigcomp->sc_cc)
	return 0;

      /* Remove old assignment */
      sigcomp_compartment_unref(self->tp_sigcomp->sc_cc);
    }
    
    self->tp_sigcomp->sc_cc = sigcomp_compartment_ref(cc);

    return 0;
  }

  return su_seterrno(EINVAL);
}

/** Test if tport has a SigComp compartment is assigned to it. */
int tport_has_sigcomp_assigned(tport_t const *self)
{
  return self && self->tp_sigcomp->sc_udvm != NULL;
}

static inline
void tport_try_accept_sigcomp(tport_t *self, msg_t *msg)
{
  struct sigcomp_udvm *udvm;

  udvm = self->tp_sigcomp->sc_udvm;
  if (udvm && sigcomp_udvm_is_complete(udvm)) {
    if (self->tp_master->mr_tpac->tpac_sigcomp_accept && 
	self->tp_sigcomp->sc_cc == NULL) {
      tport_t *ref;
      struct tport_delivery *d;

      d = self->tp_master->mr_delivery;

      d->d_tport = self; 
      d->d_msg = msg;
      d->d_udvm = &self->tp_sigcomp->sc_udvm;
      *d->d_from = *self->tp_name;

      ref = tport_incref(self);
      STACK_SIGCOMP_ACCEPT(self, msg);
      /* Reject by default */
      if (self->tp_sigcomp->sc_udvm)
	sigcomp_udvm_accept(self->tp_sigcomp->sc_udvm, NULL);
      tport_decref(&ref);

      d->d_msg = NULL;
    }
    else {
      if (tport_log->log_level >= 5) {
	char const *name; 
	int namelen;
      
	name = sigcomp_compartment_name(self->tp_sigcomp->sc_cc, &namelen);
	SU_DEBUG_5(("tport(%p): msg %p SigComp implicit accept '%.*s'\n", 
		    self, msg, namelen, name));
      }
      sigcomp_udvm_accept(udvm, self->tp_sigcomp->sc_cc);
    }
  }
}


/** Accept a SigComp message */
int 
tport_sigcomp_accept(tport_t *self, 
		     struct sigcomp_compartment *cc, 
		     msg_t *msg)
{
  struct sigcomp_udvm *udvm;

  if (self == NULL || msg != self->tp_master->mr_delivery->d_msg)
    return su_seterrno(EINVAL);

  if (!self->tp_master->mr_delivery->d_udvm || cc == NONE)
    return 0;

  udvm = *self->tp_master->mr_delivery->d_udvm;

  if (udvm) {
    if (tport_log->log_level >= 5) {
      char const *name; 
      int namelen;
   
      if (cc) {
	name = sigcomp_compartment_name(cc, &namelen);
	SU_DEBUG_5(("tport(%p): msg %p SigComp accept '%.*s'\n", 
		    self, msg, namelen, name));
      }
      else {
	SU_DEBUG_5(("tport(%p): msg %p SigComp reject\n", self, msg));
      }
    }
    sigcomp_udvm_accept(udvm, cc);
  }

  self->tp_master->mr_delivery->d_udvm = NULL;

  return 0;
}


#else

int tport_sigcomp_assign(tport_t *self, struct sigcomp_compartment *cc)
{
  return 0;
}

/** Test if tport has a SigComp compartment is assigned to it. */
int tport_has_sigcomp_assigned(tport_t const *self)
{
  return 0;
}

int 
tport_sigcomp_accept(tport_t *self, 
		     struct sigcomp_compartment *cc, 
		     msg_t *msg)
{
  return 0;
}

#endif

#if HAVE_TLS
/** Receive data from TLS.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive
 * @retval 2  incomplete recv, recv again
 * 
 */
static 
int tport_recv_tls(tport_t *self)
{
  msg_t *msg;
  int n, N, veclen, i, m;
  msg_iovec_t iovec[msg_n_fragments] = {{ 0 }};
  char *tls_buf;

  N = tls_read(self->tp_tls);

  SU_DEBUG_7(("%s(%p): tls_read() returned %d\n", __func__, self, N));

  if (N == 0) /* End-of-stream */
    return 0;
  else if (N == -1) {
    if (errno == EAGAIN) {
      tport_events(self);
      return 1;
    }
    return -1;
  }

  veclen = tport_recv_iovec(self, &self->tp_msg, iovec, N, 0);
  if (veclen < 0)
    return -1;

  msg = self->tp_msg;

  tls_buf = tls_read_buffer(self->tp_tls, N);

  /* Message address */
  *msg_addr(msg) = *self->tp_addr;
  *msg_addrlen(msg) = self->tp_addrlen;

  for (i = 0, n = 0; i < veclen; i++) {
    m = iovec[i].mv_len; assert(N >= n + m);
    memcpy(iovec[i].mv_base, tls_buf + n, m);
    n += m;
  }
    
  assert(N == n);

  /* Write the received data to the message dump file */
  if (self->tp_master->mr_dump_file)
    tport_dump_iovec(self, msg, n, iovec, veclen, "recv", "from");

  /* Mark buffer as used */
  msg_recv_commit(msg, N, 0);

  return tls_pending(self->tp_tls) ? 2 : 1;
}
#endif

/** Receive data available on the socket.
 *
 * @retval -1 error
 * @retval 0  end-of-stream  
 * @retval 1  normal receive
 * @retval 2  incomplete recv, recv again
 */
static 
int tport_recv_sctp(tport_t *self)
{
  msg_t *msg;
  int N, veclen, exact = 0, eos;
  msg_iovec_t iovec[2] = {{ 0 }};

  char sctp_buf[TP_SCTP_MSG_MAX];

  iovec[0].mv_base = sctp_buf;
  iovec[0].mv_len = sizeof(sctp_buf);

  N = su_vrecv(self->tp_socket, iovec, 1, 0, NULL, NULL);
  if (N == SOCKET_ERROR)
    return tport_recv_error_report(self);

  veclen = tport_recv_iovec(self, &self->tp_msg, iovec, N, exact = 1);
  if (veclen < 0)
    return -1;

  assert(veclen == 1); assert(iovec[0].mv_len == N);
  msg = self->tp_msg;

  /* Message address */
  *msg_addr(msg) = *self->tp_addr;
  *msg_addrlen(msg) = su_sockaddr_size(self->tp_addr);

  memcpy(iovec[0].mv_base, sctp_buf, iovec[0].mv_len);

  if (self->tp_master->mr_dump_file)
    tport_dump_iovec(self, msg, N, iovec, veclen, "recv", "from");

  msg_recv_commit(msg, N, eos = 1);  /* Mark buffer as used */

  return 2;
}

/** Send a message. 
 *
 * @deprecated 
 * Use tport_tsend().
 */
int tport_send(tport_t *self, msg_t *msg, tp_name_t const *tpn)
{
  return tport_tsend(self, msg, tpn, TAG_END()) ? 0 : -1;
}

/** Send a message. 
 *
 * The function tport_tsend() sends a message using the transport @a self.
 *
 * @TAGS
 * TPTAG_MTU(), TPTAG_REUSE(), TPTAG_CLOSE_AFTER(), TPTAG_SDWN_AFTER(), 
 */
tport_t *tport_tsend(tport_t *self, 
		     msg_t *msg, 
		     tp_name_t const *_tpn, 
		     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta; 
  tagi_t const *t;
  int reuse, sdwn_after, close_after, resolved = 0;
  unsigned mtu;
  su_addrinfo_t *ai;
  tport_primary_t *primary;
  tp_name_t tpn[1];
  struct sigcomp_compartment *cc;

  assert(self);

  if (!self || !msg || !_tpn) {
    msg_set_errno(msg, EINVAL);
    return NULL;
  }

  *tpn = *_tpn;

  SU_DEBUG_7(("tport_tsend(%p) tpn = " TPN_FORMAT "\n", self, TPN_ARGS(tpn)));

  if (tport_is_master(self)) {
    primary = (tport_primary_t *)tport_primary_by_name(self, tpn);
    if (!primary) {
      msg_set_errno(msg, EPROTONOSUPPORT);
      return NULL;
    }
  }
  else {
    primary = self->tp_pri;
  }

  ta_start(ta, tag, value);

  reuse = primary->pri_primary->tp_reusable && self->tp_reusable;
  sdwn_after = 0;
  close_after = 0;
  mtu = 0;
  cc = NULL;

  /* tl_gets() is a bit too slow here... */
  for (t = ta_args(ta); t; t = tl_next(t)) {
    tag_type_t tt = t->t_tag; 
    
    if (tptag_reuse == tt)
      reuse = t->t_value != 0;
    else if (tptag_mtu == tt)
      mtu = t->t_value;
    else if (tptag_sdwn_after == tt)
      sdwn_after = t->t_value != 0;
    else if (tptag_close_after == tt)
      close_after = t->t_value != 0;
    else if (tptag_compartment == tt)
      cc = (struct sigcomp_compartment *)t->t_value;
  }    

  ai = msg_addrinfo(msg);

  ai->ai_flags = 0;

  tpn->tpn_comp = tport_canonize_comp(tpn->tpn_comp);
  if (tpn->tpn_comp) {
    ai->ai_flags |= TP_AI_COMPRESSED;
    SU_DEBUG_9(("%s: compressed msg(%p) with %s\n", 
		__func__, msg, tpn->tpn_comp));
  } 

  if (!tpn->tpn_comp || cc == NONE)
    cc = NULL;

  if (sdwn_after)
    ai->ai_flags |= TP_AI_SHUTDOWN;
  if (close_after)
    ai->ai_flags |= TP_AI_CLOSE;

  if (reuse) {
    if (tport_is_secondary(self) && 
	tport_is_registered(self) && 
	self->tp_reusable &&
	!self->tp_closed &&
	!self->tp_send_close) {
      self = self;
    }
    /*
     * Try to find an already open connection to the destination, 
     * or get a primary protocol 
     */
    else {
      /* If primary, resolve the destination address, store it in the msg */
      if (tport_resolve(primary->pri_primary, msg, tpn) < 0) {
	return NULL;
      }
      resolved = 1;

      self = tport_by_addrinfo(primary, msg_addrinfo(msg), tpn);

      if (!self)
	self = primary->pri_primary;
    }
  }
  else {
    self = primary->pri_primary;    /* Use a primary protocol */
  }

  if (tport_is_primary(self)) {
    /* If primary, resolve the destination address, store it in the msg */
    if (!resolved && tport_resolve(self, msg, tpn) < 0) {
      return NULL;
    }

    if (tport_is_connection_oriented(self) || 
	(!tport_is_registered(self) && !self->tp_pri->pri_threadpool)) {
#if 0 && HAVE_UPNP /* We do not want to use UPnP with secondary transports! */
      if (upnp_register_upnp_client(1) != 0) { 
	upnp_check_for_nat();
      }
#endif

      tpn->tpn_proto = self->tp_protoname;

#if HAVE_SIGCOMP
      if (!cc)
	tpn->tpn_comp = NULL;
#endif

      /* Create a secondary transport which is connected to the destination */
      self = tport_connect(primary, msg_addrinfo(msg), tpn);

#if 0 && HAVE_UPNP /* We do not want to use UPnP with secondary transports! */
      upnp_deregister_upnp_client(0, 0);
#endif

      if (!self) {
	msg_set_errno(msg, su_errno());
        SU_DEBUG_9(("tport_socket failed in tsend\n"));
	return NULL;
      }

#if HAVE_SIGCOMP
      if (cc)
	tport_sigcomp_assign(self, cc);
#endif
    }
  }
#if HAVE_SIGCOMP
  else if (tport_is_secondary(self)) {
    if (self->tp_name->tpn_comp) {
      if (cc)
	tport_sigcomp_assign(self, cc);
      else if (self->tp_sigcomp->sc_cc)
	cc = self->tp_sigcomp->sc_cc;
      else
	/* Use default compartment */
	cc = self->tp_master->mr_compartment;
    }
    else 
      cc = NULL;
  }
#endif

  if (cc == NULL)
    tpn->tpn_comp = NULL;

  if (tport_is_secondary(self)) {
    /* Set the peer address to msg */
    tport_peer_address(self, msg);
    if (sdwn_after || close_after)
      self->tp_reusable = 0;
  }

  /* If there is threadpool, pass the message to it */
  if (self->tp_pri->pri_threadpool && 
      tport_thread_send(self, cc, msg, mtu) == 0) {
    SU_DEBUG_9(("tport_thread_send()\n"));
    return self;
  }

  /* Prepare message for sending - i.e., encode it */
  if (msg_prepare(msg) < 0) {
    msg_set_errno(msg, errno);
    return NULL;
  }

  if (msg_size(msg) > (mtu ? mtu : tport_mtu(self))) {
    msg_set_errno(msg, EMSGSIZE);
    return NULL;
  }

  /*
   * If there is already an queued message, 
   * put this message straight in the queue
   */
  if (self->tp_queue && self->tp_queue[self->tp_qhead]) {
    if (tport_queue(self, msg) < 0) {
      SU_DEBUG_9(("tport_queue failed in tsend\n"));
      return NULL;
    }
  }

  else if (tport_send_msg(self, msg, tpn, cc) < 0) {
    SU_DEBUG_9(("tport_send_msg failed in tsend\n"));
    return NULL;
  }

  return self;
}


/** Send a message.
 *
 * 
 */
static
int tport_send_msg(tport_t *self, msg_t *msg, 
		   tp_name_t const *tpn, 
		   struct sigcomp_compartment *cc)
{
  msg_iovec_t *iov, auto_iov[40];
  int iovlen, iovused, n, i, total, sdwn_after, close_after;
  su_time_t now;
  su_addrinfo_t *ai;

  assert(self->tp_queue == NULL || 
	 self->tp_queue[self->tp_qhead] == NULL ||
	 self->tp_queue[self->tp_qhead] == msg);

  if (self->tp_iov)
    /* Use the heap-allocated I/O vector */
    iov = self->tp_iov, iovlen = self->tp_iovlen;
  else
    /* Use the stack I/O vector */
    iov = auto_iov, iovlen = sizeof(auto_iov)/sizeof(auto_iov[0]);

  /* Get a iovec for message contents */
  for (;;) {
    iovused = msg_iovec(msg, iov, iovlen);
    if (iovused <= iovlen) 
      break;

    iov = su_realloc(self->tp_home, self->tp_iov, sizeof(*iov) * iovused);

    if (iov == NULL) {
      msg_set_errno(msg, errno);
      return -1;
    }
    
    self->tp_iov = iov, self->tp_iovlen = iovlen = iovused;
  }

  assert(iovused > 0);

  self->tp_time = su_time_ms(now = su_now());

  n = tport_vsend(self, msg, tpn, iov, iovused, cc);
  SU_DEBUG_9(("tport_vsend returned %d\n", n));

  if (n < 0)
    return n;

  self->tp_unsent = NULL, self->tp_unsentlen = 0;
  
  if (n > 0 && self->tp_master->mr_log && self->tp_slogged != msg) {
    tport_log_msg(self, msg, "send", "to", "   ", now);
    self->tp_slogged = msg;
  }

  for (i = 0, total = 0; i < iovused; i++) {
    if (total + iov[i].mv_len > n) {
      if (tport_is_connection_oriented(self)) {
	iov[i].mv_len -= n - total;
	iov[i].mv_base = (char *)iov[i].mv_base + (n - total);
	if (tport_queue_rest(self, msg, &iov[i], iovused - i) >= 0)
	  return n;
      }
      else {
	char const *comp = tpn->tpn_comp;

	SU_DEBUG_1(("tport(%p): send truncated for %s/%s:%s%s%s\n", 
		    self, tpn->tpn_proto, tpn->tpn_host, tpn->tpn_port,
		    comp ? ";comp=" : "", comp ? comp : ""));

	errno = EIO;
      }

      return -1;
    }
    total += iov[i].mv_len;
  }

  /* We have sent a complete message */

  self->tp_slogged = NULL;

  ai = msg_addrinfo(msg); assert(ai);
  close_after = (ai->ai_flags & TP_AI_CLOSE) == TP_AI_CLOSE;
  sdwn_after = (ai->ai_flags & TP_AI_SHUTDOWN) == TP_AI_SHUTDOWN ||
    self->tp_send_close;

  if (close_after || sdwn_after)
    tport_shutdown(self, close_after ? 2 : 1);

  return n;
}

static 
int tport_vsend(tport_t *self, 
		msg_t *msg, 
		tp_name_t const *tpn,
		msg_iovec_t iov[], 
		int iovused,
		struct sigcomp_compartment *cc)
{  
  int n, m;
  char const *comp = "";
  char const *via = "send";

  for (n = 0, m = 0; n < iovused; n++)
    m += iov[n].mv_len;

  if (0)
    ;
#if HAVE_TLS
  else if (self->tp_tls) {
    n = tport_tls_writevec(self, iov, iovused);
    SU_DEBUG_9(("tport_tls_writevec returned %d\n", n));
  }
#endif
#if HAVE_SIGCOMP
  else if ((cc || self->tp_sigcomp->sc_cc) && 
	   (msg_addrinfo(msg)->ai_flags & TP_AI_COMPRESSED)) {
    via = "send", comp = ";comp=sigcomp";
    if (cc == NULL)
      cc = self->tp_sigcomp->sc_cc;
    if (tport_is_tcp(self))
      self->tp_sigcomp->sc_outfmt = format_is_sigcomp;
    n = tport_sigcomp_vsend(self, msg, iov, iovused, cc, self->tp_sigcomp);
  } 
#endif
  else {
#if HAVE_SIGCOMP
    if (tport_is_tcp(self))
      self->tp_sigcomp->sc_outfmt = format_is_noncomp;
#endif
    n = tport_vsend_iovec(self, msg, iov, iovused);
  }

  if (tpn == NULL)
    tpn = self->tp_name;

  if (n == -1) 
    return tport_send_error(self, msg, tpn, comp);

  self->tp_stats.sent_bytes += n;

  SU_DEBUG_7(("tport_vsend(%p): %d bytes of %u to %s/%s:%s%s\n", 
	      self, n, m, tpn->tpn_proto, tpn->tpn_host, tpn->tpn_port, comp));

  if (n > 0 && self->tp_master->mr_dump_file)
    tport_dump_iovec(self, msg, n, iov, iovused, via, "to");
    
  return n;
}

/** Send using su_vsend(). Map IPv4 addresses as IPv6 addresses, if needed. */
static
int tport_vsend_iovec(tport_t const *self, msg_t *msg, 
		      msg_iovec_t iov[], 
		      int iovused)
{
  su_sockaddr_t *su;
  int sulen;

  if (tport_is_connection_oriented(self)) {
#if __sun__			/* XXX - there must be better way... */
    if (iovused > 16)
      iovused = 16;
#endif
    return su_vsend(self->tp_socket, iov, iovused, MSG_NOSIGNAL, NULL, 0);
  }

  su = msg_addr(msg);
  sulen = *msg_addrlen(msg);

#if SU_HAVE_IN6 && defined(IN6_INADDR_TO_V4MAPPED)
  if (su->su_family == AF_INET && self->tp_pri->pri_family == AF_INET6) {
    su_sockaddr_t su0[1];

    memset(su0, 0, sizeof su0);

    su0->su_family = self->tp_pri->pri_family;
    su0->su_port = su->su_port;

    IN6_INADDR_TO_V4MAPPED(&su->su_sin.sin_addr, &su0->su_sin6.sin6_addr);

    su = su0, sulen = sizeof(su0->su_sin6);
  }
#endif

  su_soerror(self->tp_socket); /* XXX - we *still* have a race condition */

  return su_vsend(self->tp_socket, iov, iovused, MSG_NOSIGNAL, su, sulen);
}


static
int tport_send_error(tport_t *self, msg_t *msg, 
		     tp_name_t const *tpn, char const *comp)
{
  int error = su_errno();

  if (error == EPIPE) {
    /*Xyzzy*/
  }

  if (error == EAGAIN) {
    SU_DEBUG_5(("tport_vsend(%p): %s with (s=%d %s/%s:%s%s)\n", 
		self, "EAGAIN", self->tp_socket, 
		tpn->tpn_proto, tpn->tpn_host, tpn->tpn_port, comp));
    return 0;
  }

  msg_set_errno(msg, error);

  if (self->tp_pri->pri_family == AF_INET) {
    SU_DEBUG_3(("tport_vsend(%p): %s with (s=%d %s/%s:%s%s)\n", 
		self, su_strerror(error), self->tp_socket, 
		tpn->tpn_proto, tpn->tpn_host, tpn->tpn_port, comp));
  }
  else if (self->tp_pri->pri_family == AF_INET6) {
    su_sockaddr_t const *su = msg_addr(msg);
    SU_DEBUG_3(("tport_vsend(%p): %s with "
		"(s=%d, IP6=%s/%s:%s%s (scope=%i) addrlen=%d)\n", 
		self, su_strerror(error), self->tp_socket, 
		tpn->tpn_proto, tpn->tpn_host, tpn->tpn_port, comp,
		su->su_scope_id, *msg_addrlen(msg)));
  }
  else {
    su_sockaddr_t const *su = msg_addr(msg);
    SU_DEBUG_3(("\ttport_vsend(%p): %s with "
		"(s=%d, AF=%u addrlen=%d)%s\n", 
		self, su_strerror(error), 
		self->tp_socket, su->su_family, *msg_addrlen(msg), comp));
  }

#if 0
  int i;
  for (i = 0; i < iovused; i++)
    SU_DEBUG_7(("\t\tiov[%d] = { %d bytes @ %p }\n", 
		i, iov[i].siv_len, iov[i].siv_base));
#endif

  if (tport_is_connection_oriented(self)) {
    tport_error_report(self, error, NULL);
    if (tport_is_connected(self))
      tport_close(self);
  }

  return -1;
}

#if HAVE_SIGCOMP
static
int tport_sigcomp_vsend(tport_t const *self,
			msg_t *msg, 
			msg_iovec_t iov[], 
			int iovused,
			struct sigcomp_compartment *cc,
			tport_sigcomp_t *sc)
{
  struct sigcomp_compressor *c = sc->sc_compressor;
  struct sigcomp_buffer *input = sc->sc_input;
  struct sigcomp_buffer *output = sc->sc_output;
  msg_iovec_t ciov[1];

  int i, n, m, k, stream = tport_is_stream(self);
  char const *ccname;
  int ccnamelen;

  assert(cc);
  
  if (c == NULL) {
    assert(input == NULL);
    if (self->tp_pri->pri_socktype == SOCK_STREAM)
      c = sigcomp_compressor_create_for_stream(cc);
    else
      c = sigcomp_compressor_create(cc);
    sc->sc_compressor = c;
  } 

  ccname = sigcomp_compartment_name(cc, &ccnamelen);

  if (sc->sc_compressed != 0) {
    input = NONE;
  }
  else if (input == NULL) {
    int input_size = -1;

    if (tport_is_udp(self)) {
      input_size = 0;

      for (i = 0; i < iovused; i++)
	input_size += iov[i].siv_len;
    }

    sc->sc_input = input = sigcomp_compressor_input_buffer(c, input_size);

    assert(input->b_avail == 0 && input->b_used == 0);
  } 
  else if (!input->b_complete) {
    int input_size = 0;

    for (i = 0; i < iovused; i++)
      input_size += iov[i].siv_len;

    if (input_size > input->b_size - input->b_avail)
      sigcomp_buffer_align_available(input, 0);
  }

  if (output == NULL)
    sc->sc_output = output = sigcomp_compressor_output_buffer(c, NULL);
    
  if (!c || !input || !output) {
    SU_DEBUG_3(("%s(%p): %s (%u)%s%s%s\n", 
		__func__, self, strerror(errno), errno,
		c ? "" : " (comp)",
		input ? "" : " (input)",
		output ? "" : " (output)"));
    sigcomp_compressor_free(c);
    sc->sc_compressor = NULL; 
    sc->sc_output = NULL; sc->sc_input = NULL;
    sc->sc_compressed = 0; sc->sc_copied = 0;
    return -1;
  }

  if (sc->sc_compressed == 0) {
    k = sc->sc_copied;

    if (!input->b_complete) {
      int m = sc->sc_copied;

      for (i = 0, n = 0; i < iovused; i++) {
	char *b = iov[i].siv_base;
	int l = iov[i].siv_len;

	if (m >= l) {
	  m -= l;
	  continue;
	}

	b += m; l -= m;

	if (input->b_size == input->b_avail)
	  break;

	if (l > input->b_size - input->b_avail)
	  l = input->b_size - input->b_avail;

	memcpy(input->b_data + input->b_avail, b, l);
	input->b_avail += l; n += l; sc->sc_copied += l;

	if (l != iov[i].siv_len)
	  break;
      }
      input->b_complete = i == iovused;
      assert(stream || input->b_complete); (void)stream;
    }
    
    m = output->b_avail - output->b_used;

    n = sigcomp_compressor_compress(c, output, input);
    
    if (n < 0) {
      SU_DEBUG_3(("%s(%p): %s (%u)\n", __func__, self,
		  sigcomp_compressor_strerror(c), 
		  sigcomp_compressor_errno(c)));
      sigcomp_compressor_free(c);
      sc->sc_compressor = NULL; 
      sc->sc_output = NULL; sc->sc_input = NULL;
      sc->sc_compressed = 0;
      return -1;
    }

    assert(input->b_complete || sc->sc_copied - k > 0);

    SU_DEBUG_5(("%s: input %u (%u new) compressed %u to %u with '%.*s'\n", 
		__func__, sc->sc_copied, k, n, 
		(output->b_avail - output->b_used) - m, 
		ccnamelen, ccname));

    sc->sc_compressed = n;

    assert(stream || output->b_complete);
  } 
  else {
    assert(tport_is_connection_oriented(self));
    n = sc->sc_compressed;
  }

  assert(input && cc && c && output);

  ciov->siv_base = output->b_data + output->b_used;
  ciov->siv_len = output->b_avail - output->b_used;

  m = tport_vsend_iovec(self, msg, ciov, 1);
  
  if (m == -1) {
    int error = su_errno();

    if (error != EAGAIN) {
      sigcomp_compressor_free(c);
      sc->sc_compressor = NULL;
      sc->sc_output = NULL; sc->sc_input = NULL;
      sc->sc_compressed = 0; sc->sc_copied = 0;
      su_seterrno(error);
    }

    return -1;
  }
  
  output->b_used += m;
  
  if (output->b_used < output->b_avail)
    return 0;

  if (output->b_complete) {
    sigcomp_compressor_accept(c, cc), sc->sc_output = output = NULL;
  }

  if (input != NONE && input->b_avail == input->b_used && input->b_complete)
    sigcomp_buffer_reset(input, -1), sc->sc_input = input = NULL;

  if (!input && !output) {
    sigcomp_compressor_free(c);
    sc->sc_compressor = NULL;
  }

  assert(sc->sc_compressed >= n); assert(sc->sc_copied >= n); 

  sc->sc_compressed -= n;
  sc->sc_copied -= n;

  return n;
}
#endif

#if HAVE_TLS
static
int tport_tls_writevec(tport_t *self,
                       msg_iovec_t iov[],
                       int iovlen)
{
  enum { TLSBUFSIZE = 2048 };
  int i, j, n, m, size = 0;
  int oldmask, newmask;

  oldmask = tls_events(self->tp_tls, self->tp_events);

#if 0
  if (!self->tp_tls_buffer)
    self->tp_tls_buffer = su_alloc(self->tp_home, TLSBUFSIZE);
#endif

  for (i = 0; i < iovlen; i = j) {
#if 0
    n = tls_write(self->tp_tls, 
		  iov[i].siv_base,
		  m = iov[i].siv_len);
    j = i + 1;
#else
    char *buf = self->tp_tls_buffer;
    unsigned tlsbufsize = TLSBUFSIZE;

    if (i + 1 == iovlen)
      buf = NULL;		/* Don't bother copying single chunk */

    if (buf && 
	(char *)iov[i].siv_base - buf < TLSBUFSIZE &&
	(char *)iov[i].siv_base - buf >= 0) {
      tlsbufsize = buf + TLSBUFSIZE - (char *)iov[i].siv_base;
      assert(tlsbufsize <= TLSBUFSIZE);
    }

    for (j = i, m = 0; buf && j < iovlen; j++) {
      if (m + iov[j].siv_len > tlsbufsize)
	break;
      if (buf + m != iov[j].siv_base)
	memcpy(buf + m, iov[j].siv_base, iov[j].siv_len);
      m += iov[j].siv_len; iov[j].siv_len = 0;
    }

    if (j == i)
      buf = iov[i].siv_base, m = iov[i].siv_len, j++;
    else
      iov[j].siv_base = buf, iov[j].siv_len = m;

    n = tls_write(self->tp_tls, buf, m);
#endif

    SU_DEBUG_9(("tport_tls_writevec: vec %p %p %lu (%d)\n",  
		self->tp_tls, iov[i].siv_base, (LU)iov[i].siv_len, n));

    if (n < 0) {
      if (su_errno() == EAGAIN)
	break;
      SU_DEBUG_3(("tls_write: %s\n", strerror(errno)));
      return -1;
    }

    size += n;

    /* Return if the write buffer is full for now */
    if (n != m)
      break;
  }

  newmask = tls_events(self->tp_tls, self->tp_events);

  if (oldmask != newmask)
    tport_events(self);

  return size;
}
#endif

static
int tport_queue_rest(tport_t *self, 
		     msg_t *msg, 
		     msg_iovec_t iov[], 
		     int iovused)
{
  int iovlen = self->tp_iovlen;

  assert(tport_is_connection_oriented(self));
  assert(self->tp_queue == NULL || 
	 self->tp_queue[self->tp_qhead] == NULL || 
	 self->tp_queue[self->tp_qhead] == msg);

  if (tport_queue(self, msg) < 0)
    return -1;

  assert(self->tp_queue[self->tp_qhead] == msg);

  if (self->tp_iov == NULL) {
    if (iovlen < 40) iovlen = 40;
    if (iovlen < iovused) iovlen = iovused;
    self->tp_iov = su_alloc(self->tp_home, iovlen * sizeof(iov[0]));
    self->tp_iovlen = iovlen;

    if (!self->tp_iov) {
      msg_set_errno(msg, errno);
      return -1;
    }

    memcpy(self->tp_iov, iov, iovused * sizeof(iov[0]));

    iov = self->tp_iov;
  }

  self->tp_unsent = iov;
  self->tp_unsentlen = iovused;

  /* the POLLOUT event is far too unreliable with SCTP */
  if (self->tp_pri->pri_protocol == IPPROTO_SCTP)
    return 0;

  /* Ask for a send event */
  self->tp_events |= SU_WAIT_OUT;
  tport_events(self);

  return 0;
}

/** Queue a message to transport. 
 *
 * The tport_tqueue() function queues a message in the send queue. It is
 * used by an (server) application that is required to send (response)
 * messages in certain order. For example, a HTTP server or proxy may
 * receive multiple requests from a single TCP connection. The server is
 * required to answer to the requests in same order as they are received. 
 * The responses are, however, sometimes generated asynchronously, that is,
 * a response to a later request may be ready earlier. For that purpose, the
 * HTTP protocol stack queues an empty response message immediately upon
 * receiving a request. Other messages cannot be sent before the queued one.
 *
 * The function tport_tqsend() is used to send the completed response message. 
 *
 * @param self pointer to transport object
 * @param msg  message to be inserted into queue
 * @param tag,value,... tagged argument list
 *
 * @TAGS
 * @par Currently none.
 *
 * @retval 0 when successful
 * @retval -1 upon an error

 * @ERRORS
 * @ERROR EINVAL  Invalid argument(s).
 * @ERROR ENOMEM  Memory was exhausted.
 * @ERROR ENOBUFS The transport object queue was full.
 *
 * @deprecated Alternative interface will be provided in near future.
 *
 * @sa tport_tqsend()
 */
int tport_tqueue(tport_t *self, msg_t *msg, 
		 tag_type_t tag, tag_value_t value, ...)
{
  msg_unprepare(msg);

  return tport_queue(self, msg);
}

/** Return number of queued messages. */
int tport_queuelen(tport_t const *self)
{
  int retval = 0;

  if (self && self->tp_queue) {
    unsigned short i;
    unsigned short N = self->tp_params->tpp_qsize;

    for (i = self->tp_qhead; self->tp_queue[i]; i = (i + 1) % N)
      retval++;
  }

  return retval;
}

static
int tport_queue(tport_t *self, msg_t *msg)
{
  unsigned short qhead = self->tp_qhead;
  unsigned short N = self->tp_params->tpp_qsize;

  SU_DEBUG_7(("tport_queue(%p): queueing %p for %s/%s:%s\n", 
	      self, msg, self->tp_protoname, self->tp_host, self->tp_port));

  if (self->tp_queue == NULL) {
    assert(N > 0);
    assert(qhead == 0);
    self->tp_queue = su_zalloc(self->tp_home, N * sizeof(msg));
    if (!self->tp_queue) {
      msg_set_errno(msg, errno);
      return -1;
    }
  }

  if (self->tp_queue[qhead] == msg)
    return 0;

  while (self->tp_queue[qhead]) {
    qhead = (qhead + 1) % N;
    if (qhead == self->tp_qhead) {
      msg_set_errno(msg, ENOBUFS);
      return -1;
    }
  }

  self->tp_queue[qhead] = msg_ref_create(msg);

  return 0;
}

/** Send a queued message (and queue another, if required).
 * 
 * The function tport_tqsend() sends a message to the transport. 
 *
 * @deprecated Alternative interface will be provided in near future.
 */
int tport_tqsend(tport_t *self, msg_t *msg, msg_t *next,
		 tag_type_t tag, tag_value_t value, ...)
{
  unsigned short qhead = self->tp_qhead;
  ta_list ta;
  int reuse, sdwn_after, close_after;
  unsigned short N;
  su_addrinfo_t *ai;

  if (self == NULL)
    return -1;

  N = self->tp_params->tpp_qsize;
  reuse = self->tp_reusable;
  sdwn_after = 0;
  close_after = 0;

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta),
	  TPTAG_REUSE_REF(reuse),
	  TPTAG_SDWN_AFTER_REF(sdwn_after),
	  TPTAG_CLOSE_AFTER_REF(close_after),
	  TAG_END());

  ta_end(ta);

  /* If "next", make sure we can queue it */
  if (next && self->tp_queue[qhead == 0 ? N - 1 : qhead - 1]) {
    msg_set_errno(next, ENOBUFS);
    return -1;
  }

  /* Prepare message for sending - i.e., encode it */
  if (msg_prepare(msg) < 0) {
    msg_set_errno(msg, errno);
    return -1;
  }

  tport_peer_address(self, msg);  /* Set addrinfo */
  if (next == NULL) {
    ai = msg_addrinfo(msg);

    if (sdwn_after)
      ai->ai_flags |= TP_AI_SHUTDOWN;
    if (close_after)
      ai->ai_flags |= TP_AI_CLOSE;

    if (self->tp_queue[qhead] == msg)
      tport_send_queue(self);
    return 0;
  }

  ai = msg_addrinfo(next);

  if (sdwn_after)
    ai->ai_flags |= TP_AI_SHUTDOWN;
  if (close_after)
    ai->ai_flags |= TP_AI_CLOSE;

  if (self->tp_queue[qhead] == msg) {
    /* XXX - what about errors? */
    tport_send_msg(self, msg, self->tp_name, NULL);
    if (!self->tp_unsent) {
      msg_destroy(self->tp_queue[qhead]);
      if ((self->tp_queue[qhead] = msg_ref_create(next)))
	msg_unprepare(next);
      return 0; 
    }
  }

  while (self->tp_queue[qhead] && self->tp_queue[qhead] != msg) {
    qhead = (qhead + 1) % N;
    if (qhead == self->tp_qhead)
      break;
  }

  if (self->tp_queue[qhead] != msg) {
    msg_set_errno(next, EINVAL);
    return -1;
  }

  msg = msg_ref_create(next);

  do {
    qhead = (qhead + 1) % N;
    next = self->tp_queue[qhead]; self->tp_queue[qhead] = msg; msg = next;
    /* Above we made sure that there is an empty slot */
    assert(!next || qhead != self->tp_qhead); 
  } while (next);

  return 0;
}

/** Send event.
 *
 * Process SU_WAIT_OUT event.
 */ 
static
void tport_send_event(tport_t *self, int events)
{
  assert(tport_is_connection_oriented(self));

  SU_DEBUG_7(("tport_send_event(%p) - ready to send to (%s/%s:%s)\n", 
	      self, self->tp_protoname, self->tp_host, self->tp_port));
  tport_send_queue(self);
}

/** Send queued messages */
static
void tport_send_queue(tport_t *self)
{
  int n, i, total;
  msg_t *msg;
  msg_iovec_t *iov;
  int iovused;
  unsigned short qhead = self->tp_qhead, N = self->tp_params->tpp_qsize;
  su_time_t now;

  //assert(self->tp_iov && self->tp_iovlen > 0);
  assert(self->tp_queue && self->tp_queue[qhead]);
  //assert(self->tp_unsent && self->tp_unsentlen > 0);

  self->tp_time = su_time_ms(now = su_now());

  msg = self->tp_queue[qhead];

  iov = self->tp_unsent, self->tp_unsent = NULL;
  iovused = self->tp_unsentlen, self->tp_unsentlen = 0;

  if (iov && iovused) {
    n = tport_vsend(self, msg, self->tp_name, iov, iovused, NULL);

    if (n < 0)				/* XXX */
      return;

    if (n > 0 && self->tp_master->mr_log && self->tp_slogged != msg) {
      tport_log_msg(self, msg, "send", "to", "   ", now);
      self->tp_slogged = msg;
    }
    
    for (i = 0, total = 0; i < iovused; i++) {
      if (total + iov[i].mv_len > n) {
	iov[i].mv_len -= n - total;
	iov[i].mv_base = (char *)iov[i].mv_base + (n - total);

	self->tp_unsent = iov + i;
	self->tp_unsentlen = iovused - i;

	return;
      }
      total += iov[i].mv_len;
    }
    assert(total == n);

    self->tp_queue[qhead] = NULL;
    msg_destroy(msg);
    self->tp_slogged = NULL;

    qhead = (qhead + 1) % N;
  }

  while (msg_is_prepared(msg = self->tp_queue[self->tp_qhead = qhead])) {
    /* XXX - what about errors? */
    tport_send_msg(self, msg, self->tp_name, NULL); 
    if (self->tp_unsent) 
      return;

    msg = self->tp_queue[qhead]; /* tport_send_msg() may flush queue! */
    self->tp_queue[qhead] = NULL;
    msg_destroy(msg);
    qhead = (qhead + 1) % N;
  }

  /* No more send event(s)? */
  self->tp_events &= ~SU_WAIT_OUT;
  tport_events(self);
}

static int msg_select_addrinfo(msg_t *msg, su_addrinfo_t *res);

static int
tport_resolve(tport_t *self, msg_t *msg, tp_name_t const *tpn)
{
  int error;
  char ipaddr[TPORT_HOSTPORTSIZE];
  su_addrinfo_t *res, hints[1] = {{ 0 }};
  char const *host;
  su_sockaddr_t *su;

  hints->ai_socktype = self->tp_pri->pri_socktype;
  hints->ai_protocol = self->tp_pri->pri_protocol;

  if (tpn->tpn_host[0] == '[') {
    /* Remove [] around IPv6 address */
    char *end;
    hints->ai_flags |= AI_NUMERICHOST;
    host = strncpy(ipaddr, tpn->tpn_host +  1, sizeof(ipaddr) - 1);
    ipaddr[sizeof(ipaddr) - 1] = '\0';

    if ((end = strchr(host, ']'))) {
      *end = 0;
    }
    else {
      SU_DEBUG_3(("tport_resolve: bad IPv6 address\n"));
      msg_set_errno(msg, EINVAL);
      return -1;
    }
  }
  else 
    host = tpn->tpn_host;

  if ((error = su_getaddrinfo(host, tpn->tpn_port, hints, &res))) {
    SU_DEBUG_3(("tport_resolve: getaddrinfo(\"%s\":%s): %s\n",
		tpn->tpn_host, tpn->tpn_port,
		su_gai_strerror(error)));
    msg_set_errno(msg, ENXIO);
    return -1;
  }

  error = msg_select_addrinfo(msg, res);

  su = (su_sockaddr_t *) msg_addrinfo(msg)->ai_addr;

  SU_DEBUG_9(("tport_resolve addrinfo = %s%s%s:%d\n", 
	      su->su_family == AF_INET6 ? "[" : "",
              inet_ntop(su->su_family, SU_ADDR(su), ipaddr, sizeof(ipaddr)),
	      su->su_family == AF_INET6 ? "]" : "",
              htons(su->su_port)));

  su_freeaddrinfo(res);

  return error;
}

static int
msg_select_addrinfo(msg_t *msg, su_addrinfo_t *res)
{
  su_addrinfo_t *ai, *mai = msg_addrinfo(msg);
  su_sockaddr_t *su = msg_addr(msg);
  socklen_t *sulen = msg_addrlen(msg);

  for (ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
      continue;
    if (ai->ai_addrlen > sizeof(su_sockaddr_t))
      continue;
    mai->ai_family = ai->ai_family;
    mai->ai_socktype = ai->ai_socktype;
    mai->ai_protocol = ai->ai_protocol;
    if (ai->ai_addrlen < sizeof(su_sockaddr_t))
      memset(su, 0, sizeof(su_sockaddr_t));
    memcpy(su, ai->ai_addr, ai->ai_addrlen);
    if (su_sockaddr_size(su))
      *sulen = su_sockaddr_size(su);
    else
      *sulen = ai->ai_addrlen;
    return 0;
  }

  msg_set_errno(msg, EAFNOSUPPORT);
   
  return -1;
}

/** Copy peer address to msg */
void
tport_peer_address(tport_t *self, msg_t *msg)
{
  su_addrinfo_t *ai = msg_addrinfo(msg);
  socklen_t addrlen = su_sockaddr_size(self->tp_addr);

  ai->ai_family   = self->tp_pri->pri_family;
  ai->ai_socktype = self->tp_pri->pri_socktype;
  ai->ai_protocol = self->tp_pri->pri_protocol;

  memcpy(ai->ai_addr, self->tp_addr, ai->ai_addrlen = addrlen);
}

static int tport_udp_error(tport_t const *self, 
			   su_sockaddr_t name[1]);

/** Process error event. */
static void
tport_error_event(tport_t *self, int events)
{
  int errcode;
  su_sockaddr_t name[1] = {{ 0 }};

  name->su_family = AF_UNSPEC; /* 0 */

  if (tport_is_udp(self)) {
    errcode = tport_udp_error(self, name);
  } else {
    /* Process error event for basic transport. */
    errcode = su_soerror(self->tp_socket);
  }

  if (!errcode)    /* Xyzzy */
    return;

  if (errcode == EPIPE && (events & SU_WAIT_IN) && !self->tp_closed)
    tport_recv_event(self, events);
  
  tport_error_report(self, errcode, name);
}


#if !HAVE_IP_RECVERR && !HAVE_IPV6_RECVERR

/** Process UDP error event. */
static int
tport_udp_error(tport_t const *self, su_sockaddr_t name[1])
{
  if (tport_is_connection_oriented(self))
    name[0] = self->tp_addr[0];
  return su_soerror(self->tp_socket);
}

#else

/** Process UDP error event. */
static int
tport_udp_error(tport_t const *self, su_sockaddr_t name[1])
{
  struct cmsghdr *c;
  struct sock_extended_err *ee;
  su_sockaddr_t *from;
  char control[512];
  char errmsg[64 + 768];
  struct iovec iov[1];
  struct msghdr msg[1] = {{ 0 }};
  int n;

  msg->msg_name = name, msg->msg_namelen = sizeof(*name);
  msg->msg_iov = iov, msg->msg_iovlen = 1;
  iov->iov_base = errmsg, iov->iov_len = sizeof(errmsg);
  msg->msg_control = control, msg->msg_controllen = sizeof(control);

  n = recvmsg(self->tp_socket, msg, MSG_ERRQUEUE);

  if (n < 0) {
    if (su_errno() != EAGAIN)
      SU_DEBUG_1(("%s: recvmsg: %s\n", __func__, su_strerror(su_errno())));
    return 0;
  }

  if ((msg->msg_flags & MSG_ERRQUEUE) != MSG_ERRQUEUE) {
    SU_DEBUG_1(("%s: recvmsg: no errqueue\n", __func__));
    return 0;
  }

  if (msg->msg_flags & MSG_CTRUNC) {
    SU_DEBUG_1(("%s: extended error was truncated\n", __func__));
    return 0;
  }

  if (msg->msg_flags & MSG_TRUNC) {
    /* ICMP message may contain original message... */
    SU_DEBUG_3(("%s: icmp(6) message was truncated (at %d)\n", __func__, n));
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
      char info[128];
      char const *origin;

      ee = (struct sock_extended_err *)CMSG_DATA(c);
      from = (su_sockaddr_t *)SO_EE_OFFENDER(ee);
      info[0] = '\0';

      switch (ee->ee_origin) {
      case SO_EE_ORIGIN_LOCAL:
	origin = "local";
	break;
      case SO_EE_ORIGIN_ICMP:
	origin = "icmp";
	snprintf(info, sizeof(info), " type=%u code=%u", 
		 ee->ee_type, ee->ee_code);
	break;
      case SO_EE_ORIGIN_ICMP6:
	origin = "icmp6";
	snprintf(info, sizeof(info), " type=%u code=%u", 
		ee->ee_type, ee->ee_code);
	break;
      case SO_EE_ORIGIN_NONE:
	origin = "none";
	break;
      default:
	origin = "unknown";
	break;
      }

      if (ee->ee_info)
	snprintf(info + strlen(info), sizeof(info) - strlen(info), 
		 " info=%08x", ee->ee_info);

      SU_DEBUG_3(("%s: %s (%d) [%s%s]\n",
		  __func__, su_strerror(ee->ee_errno), ee->ee_errno, 
		  origin, info));
      if (from->su_family != AF_UNSPEC)
	SU_DEBUG_3(("\treported by [%s]:%u\n",
		    inet_ntop(from->su_family, SU_ADDR(from), 
			      info, sizeof(info)),
		    ntohs(from->su_port)));

      if (msg->msg_namelen == 0)
	name->su_family = AF_UNSPEC;

      SU_CANONIZE_SOCKADDR(name);

      return ee->ee_errno;
    }
  }

  return 0;
}
#endif

/** Initialize logging. */
static void
tport_open_log(tport_master_t *mr, tagi_t *tags)
{
  char const *log;
  
  mr->mr_log = 
    getenv("MSG_STREAM_LOG") != NULL ||
    getenv("TPORT_LOG") != NULL 
    ? MSG_DO_EXTRACT_COPY : 0;
    
  if ((log = getenv("TPORT_DUMP")) || (log = getenv("MSG_DUMP"))) {
    time_t now;

    if (strcmp(log, "-")) 
      mr->mr_dump_file = fopen(log, "ab"); /* XXX */
    else
      mr->mr_dump_file = stdout;

    if (mr->mr_dump_file) {
      time(&now);
      fprintf(mr->mr_dump_file, "dump started at %s\n\n", ctime(&now));
    }
  }
}

/** Create log stamp */
void tport_stamp(tport_t const *self, msg_t *msg, 
		 char stamp[128], char const *what, 
		 int n, char const *via,
		 su_time_t now)
{
  char label[24] = "";
  char *comp = "";
  char name[SU_ADDRSIZE];
  su_sockaddr_t const *su = msg_addr(msg);
  unsigned short second, minute, hour;

  second = (unsigned short)(now.tv_sec % 60);
  minute = (unsigned short)((now.tv_sec / 60) % 60);
  hour = (unsigned short)((now.tv_sec / 3600) % 24);

#if SU_HAVE_IN6
  if (su->su_family == AF_INET6) {
    if (su->su_sin6.sin6_flowinfo)
      snprintf(label, sizeof(label), "/%u", ntohl(su->su_sin6.sin6_flowinfo));
  }
#endif

  if (tport_has_sigcomp(self) &&
      msg_addrinfo(msg)->ai_flags & TP_AI_COMPRESSED)
    comp = ";comp=sigcomp";

  inet_ntop(su->su_family, SU_ADDR(su), name, sizeof(name));

  snprintf(stamp, 128,
	   "%s %d bytes %s %s/[%s]:%u%s%s at %02u:%02u:%02u.%06lu:\n",
	   what, n, via, self->tp_name->tpn_proto,
	   name, ntohs(su->su_port), label[0] ? label : "", comp,
	   hour, minute, second, now.tv_usec);

}

/** Dump the data from the iovec */
static 
void tport_dump_iovec(tport_t const *self, msg_t *msg, 
		      int n, su_iovec_t const iov[], int iovused,
		      char const *what, char const *how)
{
  tport_master_t *mr = self->tp_master;
  char stamp[128];
  int i;

  if (!mr->mr_dump_file)
    return;

  tport_stamp(self, msg, stamp, what, n, how, su_now());
  fputs(stamp, mr->mr_dump_file);

  for (i = 0; i < iovused && n > 0; i++) {
    int len = iov[i].mv_len;
    if (len > n)
      len = n;
    fwrite(iov[i].mv_base, len, 1, mr->mr_dump_file);
    n -= len;
  }

  fputs("\v\n", mr->mr_dump_file);
  fflush(mr->mr_dump_file);
}

/** Log the message. */
void tport_log_msg(tport_t *self, msg_t *msg, 
		   char const *what, char const *via,
		   char const *first, su_time_t now)
{
  char stamp[128];
  msg_iovec_t iov[80];
  int i, n, iovlen = msg_iovec(msg, iov, 80);
  int skip_lf = 0, linelen = 0;
  char const *prefix = first;

  if (iovlen < 0) return;

  for (i = n = 0; i < iovlen && i < 80; i++)
    n += iov[i].mv_len;

  tport_stamp(self, msg, stamp, what, n, via, now);
  su_log(stamp);

  for (i = 0; i < iovlen && i < 80; i++) {
    char *s = iov[i].mv_base, *end = s + iov[i].mv_len;
    int n;

    if (skip_lf && s < end && s[0] == '\n') { s++; skip_lf = 0; }

    while (s < end) {
      if (s[0] == '\0') {
	int j, len = s - (char *)iov[i].mv_base;
	for (j = 0; j < i; j++)
	  len += iov[j].mv_len;
	su_log("\n%s*** message truncated at %d\n", prefix, len);
	return;
      }

      n = strncspn(s, end - s, "\r\n");
      if (prefix) {
	su_log("%s", prefix); linelen = n;
      } else {
	linelen += n;
      }
      su_log("%.*s", n, s);
      if (s + n < end) {
	su_log("\n");
	prefix = first;
      }
      else {
	prefix = "";
      }
      s += n;
      /* Skip a eol */
      if (s < end) {
	if (s + 1 < end && s[0] == '\r' && s[1] == '\n')
	  s += 2;
	else if (s[0] == '\r')
	  s++, (skip_lf = s + 1 == end);
	else if (s[0] == '\n')
	  s++;
      }
    }
  }

  if (linelen) su_log("\n");

  if (i == 80) {
    int j, len = 0;
    for (j = 0; j < i; j++)
      len += iov[j].mv_len;
    su_log("\n%s*** message truncated at %d\n", prefix, len);
    return;
  }
}

/** Mark message as waiting for a response.
 *
 * @return Positive integer, or -1 upon an error.
 */
int tport_pend(tport_t *self, 
	       msg_t *msg, 
	       tport_pending_error_f *callback, 
	       tp_client_t *client)
{
  tport_pending_t *pending;

  if (self == NULL || msg == NULL || callback == NULL || client == NULL)
    return -1;

  SU_DEBUG_7(("tport_pend(%p): pending %p for %s/%s:%s (already %u)\n", 
	      self, msg, 
	      self->tp_protoname, self->tp_host, self->tp_port,
	      self->tp_pused));

  if (self->tp_released == NULL) {
    unsigned i, len = 8;
    if (self->tp_plen)
      len = 2 * self->tp_plen;
    pending = su_realloc(self->tp_home, 
			 self->tp_pending, len * sizeof(*pending));
    if (!pending) {
      msg_set_errno(msg, errno);
      return -1;
    }

    memset(pending + self->tp_plen, 0, (len - self->tp_plen) * sizeof(*pending));

    for (i = self->tp_plen; i + 1 < len; i++)
      pending[i].p_client = pending + i + 1;
      
    self->tp_released = pending + self->tp_plen;
    self->tp_pending = pending;
    self->tp_plen = len;
  }

  pending = self->tp_released;
  self->tp_released = pending->p_client;

  pending->p_callback = callback;
  pending->p_client = client;
  pending->p_msg = msg;
  pending->p_reported = self->tp_reported;

  self->tp_pused++;

  return (pending - self->tp_pending) + 1;
}

/** Mark message as no more pending */
int tport_release(tport_t *self, 
		  int pendd,
		  msg_t *msg, 
		  msg_t *reply, 
		  tp_client_t *client, 
		  int still_pending)
{
  tport_pending_t *pending;

  if (self == NULL || msg == NULL || pendd <= 0 || pendd > self->tp_plen)
    return su_seterrno(EINVAL), -1;

  pending = self->tp_pending + (pendd - 1);

  if (pending->p_client != client || 
      pending->p_msg != msg) {
    SU_DEBUG_1(("tport_release(%p): %u %p by %p not pending\n", self, 
		pendd, msg, client));
    return su_seterrno(EINVAL), -1;
  }

  SU_DEBUG_7(("tport_release(%p): %p by %p with %p%s\n", 
	      self, msg, client, reply,
	      still_pending ? " (preliminary)" : ""));

  /* sigcomp can here associate request (msg) with response (reply) */

  if (still_pending)
    return 0;
	    
  /* Just to make sure nobody uses stale data */
  memset(pending, 0, sizeof(*pending));
  pending->p_client = self->tp_released;
  self->tp_released = pending;
  self->tp_pused--;
  return 0;
}

/** Report error to pending messages with destination */
int
tport_pending_error(tport_t *self, su_sockaddr_t const *dst, int error)
{
  unsigned i, reported, callbacks;
  tport_pending_t *pending;
  msg_t *msg;

  assert(self); assert(dst);

  callbacks = 0;
  reported = ++self->tp_reported;

  if (self->tp_pused == 0)
    return 0;

  for (i = 0; i < self->tp_plen; i++) {
    pending = self->tp_pending + i;

    if (!pending->p_callback || !pending->p_msg)
      continue;

    if (pending->p_reported == reported)
      continue;

    msg = pending->p_msg;
    
    if (su_cmp_sockaddr(dst, msg_addr(msg)) != 0)
      continue;

    pending->p_reported = reported;

    msg_set_errno(msg, error);

    pending->p_callback(self->TP_STACK, pending->p_client, self, msg, error);

    callbacks++;
  }

  return callbacks;
}


/** Report error via pending message */
int
tport_pending_errmsg(tport_t *self, msg_t *msg, int error)
{
  unsigned i, reported, callbacks;
  tport_pending_t *pending;

  assert(self); assert(msg);

  callbacks = 0;
  reported = ++self->tp_reported;

  msg_set_errno(msg, error);

  if (self->tp_pused == 0)
    return 0;

  for (i = 0; i < self->tp_plen; i++) {
    pending = self->tp_pending + i;

    if (!pending->p_client || 
	pending->p_msg != msg ||
	pending->p_reported == reported)
      continue;
    
    pending->p_reported = reported;

    pending->p_callback(self->TP_STACK, pending->p_client, self, msg, error);

    callbacks++;
  }

  return callbacks;
}


/** Set transport magic. */
void tport_set_magic(tport_t *self, tp_magic_t *magic)
{
  self->tp_magic = magic;
}

/** Get transport magic. */
tp_magic_t *tport_magic(tport_t const *self)
{
  return self ? self->tp_magic : NULL;
}

/** Get primary transport (or self, if primary) */
tport_t *tport_parent(tport_t const *self)
{
  return self ? self->tp_pri->pri_primary : NULL;
}

/** Get list of primary transports */
tport_t *tport_primaries(tport_t const *self)
{
  if (self)
    return self->tp_master->mr_primaries->pri_primary;
  else
    return NULL;
}

/** Get next transport */
tport_t *tport_next(tport_t const *self)
{
  if (self == NULL)
    return NULL;
  else if (tport_is_master(self))
    return ((tport_master_t *)self)->mr_primaries->pri_primary;
  else if (tport_is_primary(self))
    return ((tport_primary_t *)self)->pri_next->pri_primary;
  else
    return tprb_succ(self);
}

/** Get secondary transports. */
tport_t *tport_secondary(tport_t const *self)
{
  if (tport_is_primary(self))
    return self->tp_pri->pri_secondary;
  else
    return NULL;
}

#if 0
void tport_hints(tport_t const *self, su_addrinfo_t *hints)
{
  hints->ai_protocol = self->tp_pri->pri_protocol;
  hints->ai_socktype = self->tp_pri->pri_socktype;
}
#endif

/** Get transport name. */
tp_name_t const *tport_name(tport_t const *self)
{
  return self->tp_name;
}

/** Get transport identifier. */ 
char const *tport_ident(tport_t const *self)
{
  return self ? self->tp_ident : NULL;
}

/** Get transport by protocol name. */
tport_t *tport_by_protocol(tport_t const *self, char const *proto) 
{
  if (proto && strcmp(proto, tpn_any) != 0) {
    for (; self; self = tport_next(self))
      if (strcasecmp(proto, self->tp_protoname) == 0)
	break;
  }

  return (tport_t *)self;
}

/** Get transport by protocol name. */
tport_t *tport_primary_by_name(tport_t const *tp, tp_name_t const *tpn)
{
  char const *ident = tpn->tpn_ident;
  char const *proto = tpn->tpn_proto;
  char const *comp = tpn->tpn_comp;
  int family = 0;

  tport_primary_t const *self, *nocomp = NULL;

  self = tp ? tp->tp_master->mr_primaries : NULL;

  if (ident && strcmp(ident, tpn_any) == 0)
    ident = NULL;

  if (tpn->tpn_host == NULL)
    family = 0;
  else if (strchr(tpn->tpn_host, ':'))
    family = AF_INET6;
  else if (strcmp(tpn->tpn_host, tpn_any))
    family = AF_INET;

  if (proto && strcmp(proto, tpn_any) == 0)
    proto = NULL;

  if (!ident && !proto && !family && !comp)
    return (tport_t *)self;		/* Anything goes */

  if (comp && strcasecmp(comp, tport_sigcomp_name) == 0)
    comp = tport_sigcomp_name;

  for (; self; self = self->pri_next) {
    tp = self->pri_primary;

    if (ident && strcmp(ident, tp->tp_ident))
      continue;
    if (family) {
      if (family == AF_INET && !tport_has_ip4(tp))
	continue;
      if (family == AF_INET6 && !tport_has_ip6(tp))
	continue;
    }
    if (proto && strcasecmp(proto, tp->tp_protoname))
      continue;
    
    if (comp && comp != tp->tp_name->tpn_comp) {
      if (tp->tp_name->tpn_comp == NULL && nocomp == NULL)
	nocomp = self;
      continue;
    }

    break;
  }

  if (self)
    return (tport_t *)self;
  else
    return (tport_t *)nocomp;
}

/** Get transport by name. */
tport_t *tport_by_name(tport_t const *self, tp_name_t const *tpn)
{
  tport_t const *sub, *next;
  char const *canon, *host, *port, *comp;

  assert(self); assert(tpn);

  assert(tpn->tpn_proto); assert(tpn->tpn_host); assert(tpn->tpn_port);
  assert(tpn->tpn_canon);

  if (!tport_is_primary(self))
    self = tport_primary_by_name(self, tpn);

  host = strcmp(tpn->tpn_host, tpn_any) ? tpn->tpn_host : NULL;
  port = strcmp(tpn->tpn_port, tpn_any) ? tpn->tpn_port : NULL;
  canon = tpn->tpn_canon;
  comp = tport_canonize_comp(tpn->tpn_comp);

  if (self && host && port) {
    int resolved = 0, sulen, cmp;
    su_sockaddr_t su[1];

    sub = self->tp_pri->pri_secondary;

    memset(su, 0, sizeof su);

#if SU_HAVE_IN6
    if (strchr(host, ':')) {
      char *end, ipaddr[TPORT_HOSTPORTSIZE];
      
      if (host[0] == '[') {
	/* Remove [] around IPv6 address */
	host = strncpy(ipaddr, host +  1, sizeof(ipaddr) - 1);
	ipaddr[sizeof(ipaddr) - 1] = '\0';

	if ((end = strchr(host, ']')))
	  *end = 0;
      }

      su->su_len = sulen = sizeof (struct sockaddr_in6);
      su->su_family = AF_INET6;
    }
    else
#endif
    {
      su->su_len = sulen = sizeof (struct sockaddr_in);
      su->su_family = AF_INET;
    }

    su->su_port = htons(strtoul(port, NULL, 10));
    
    if (inet_pton(su->su_family, host, SU_ADDR(su)) > 0) {
      resolved = 1;
      next = NULL;

      /* Depth-first search */
      while (sub) {
	cmp = sub->tp_addrlen - sulen; 
	if (cmp == 0)
	  cmp = memcmp(sub->tp_addr, su, sulen);

	if (cmp == 0) {
	  if (sub->tp_left) {
	    next = sub;
	    sub = sub->tp_left;
	    continue;
	  }
	  break;
	}
	else if (next) {
	  sub = next;
	  break;
	}
	else if (cmp > 0) {
	  sub = sub->tp_left;
	  continue;
	}
	else /* if (cmp < 0) */ {
	  sub = sub->tp_right;
	  continue;
	}
      }
    }
    else {
      SU_DEBUG_7(("tport(%p): EXPENSIVE unresolved " TPN_FORMAT "\n",
		  self, TPN_ARGS(tpn)));

      sub = tprb_first(sub);
    }

    for (; sub; sub = tprb_succ(sub)) {
      if (!sub->tp_reusable)
	continue;
      if (!tport_is_registered(sub))
	continue;
      if (tport_is_shutdown(sub))
	continue;

      if (comp != sub->tp_name->tpn_comp)
	continue;

      if (resolved) {
	if (sub->tp_addrlen != sulen ||
	    memcmp(sub->tp_addr, su, sulen)) {
	  SU_DEBUG_7(("tport(%p): not found by name " TPN_FORMAT "\n",
		      self, TPN_ARGS(tpn)));
	  break;
	}
	SU_DEBUG_7(("tport(%p): found %p by name " TPN_FORMAT "\n",
		    self, sub, TPN_ARGS(tpn)));
      }
      else if ((strcasecmp(canon, sub->tp_canon) &&
		strcasecmp(host, sub->tp_host)) ||
	       strcmp(port, sub->tp_port))
	continue;

      return (tport_t *)sub;
    }
  }

  return (tport_t *)self;
}

/** Get transport from primary by addrinfo. */
tport_t *tport_by_addrinfo(tport_primary_t const *pri, 
			   su_addrinfo_t const *ai,
			   tp_name_t const *tpn)
{
  tport_t const *sub, *maybe;
  struct sockaddr const *sa;
  int salen, cmp;
  char const *comp;

  assert(pri); assert(ai);

  sa = ai->ai_addr, salen = ai->ai_addrlen;

  sub = pri->pri_secondary, maybe = NULL;

  comp = tport_canonize_comp(tpn->tpn_comp);

  /* Depth-first search */
  while (sub) {
    cmp = sub->tp_addrlen - salen; 
    if (cmp == 0)
      cmp = memcmp(sub->tp_addr, sa, salen);

    if (cmp == 0) {
      if (sub->tp_left) {
	maybe = sub;
	sub = sub->tp_left;
	continue;
      }
      break;
    }
    else if (maybe) {
      sub = maybe;
      break;
    }
    else if (cmp > 0) {
      sub = sub->tp_left;
      continue;
    }
    else /* if (cmp < 0) */ {
      sub = sub->tp_right;
      continue;
    }
  }

  maybe = NULL;

  for (; sub; sub = tprb_succ(sub)) {
    if (!sub->tp_reusable)
      continue;
    if (!tport_is_registered(sub))
      continue;
    if (tport_is_shutdown(sub))
      continue;

    if (comp != sub->tp_name->tpn_comp)
      continue;
    
    if (sub->tp_addrlen != salen || memcmp(sub->tp_addr, sa, salen)) {
      sub = NULL;
      break;
    }

    break;
  }

  if (sub == NULL)
    sub = maybe;

  if (sub)
    SU_DEBUG_7(("%s(%p): found %p by name " TPN_FORMAT "\n",
		__func__, pri, sub, TPN_ARGS(tpn)));
  else
    SU_DEBUG_7(("%s(%p): not found by name " TPN_FORMAT "\n",
		__func__, pri, TPN_ARGS(tpn)));

  return (tport_t *)sub;
}


/** Get transport name from URL. */
int tport_name_by_url(su_home_t *home, 
		      tp_name_t *tpn,
		      url_string_t const *us)
{
  int n;
  url_t url[1];
  char *b;

  n = url_xtra(us->us_url);
  b = su_alloc(home, n);

  if (b == NULL || url_dup(b, n, url, us->us_url) < 0) {
    su_free(home, b);
    return -1;
  }

  tpn->tpn_proto = url_tport_default(url->url_type);
  tpn->tpn_canon = url->url_host;
  tpn->tpn_host = url->url_host;
  tpn->tpn_port = url_port(url);

  if (tpn->tpn_host == NULL || tpn->tpn_host[0] == '\0' ||
      tpn->tpn_port == NULL || tpn->tpn_port[0] == '\0') {
    su_free(home, b);
    return -1;
  }

  if (url->url_params) {
    for (b = (char *)url->url_params; b[0]; b += n) {
      n = strcspn(b, ";");

      if (n > 10 && strncasecmp(b, "transport=", 10) == 0)
	tpn->tpn_proto = b + 10;
      else if (n > 6 && strncasecmp(b, "maddr=", 6) == 0)
	tpn->tpn_host = b + 6;

      if (b[n])
	b[n++] = '\0';
    }
  }

  return 0;
}

/** Check if transport named is already resolved */
int tport_name_is_resolved(tp_name_t const *tpn)
{
  int n;

  if (!tpn->tpn_host)
    return 0;
  
  if (tpn->tpn_host[0] == '[')
    return 1;

  n = strspn(tpn->tpn_host, ".0123456789");

  if (tpn->tpn_host[n] == '\0')
    return 1;

  if (strchr(tpn->tpn_host, ':')) {
    n = strspn(tpn->tpn_host, ":0123456789abcdefABCDEF");

    if (tpn->tpn_host[n] == '\0')
      return 1;
  }

  return 0;
}

/** Duplicate name.
 *
 * The tport_name_dup() function copies strings belonging to the transport
 * name. It returns the copied strings via the @a dst transport name
 * structure. The memory block required for copies is allocated from the
 * memory @a home. Please note that only one memory block is allocated, so
 * the memory can be reclainmed only by deinitializing the memory home
 * itself.
 *
 * @retval 0 when successful
 * @retval -1 upon an error
 */
int tport_name_dup(su_home_t *home, 
		   tp_name_t *dst,
		   tp_name_t const *src)
{
  int n_proto, n_host, n_port, n_canon, n_comp = 0;
  char *s;

  if (strcmp(src->tpn_proto, tpn_any)) 
    n_proto = strlen(src->tpn_proto) + 1;
  else
    n_proto = 0;

  n_host = strlen(src->tpn_host) + 1;

  n_port = strlen(src->tpn_port) + 1;

  if (src->tpn_comp != NULL)
    n_comp = strlen(src->tpn_comp) + 1;

  if (src->tpn_canon != src->tpn_host &&
      strcmp(src->tpn_canon, src->tpn_host))
    n_canon = strlen(src->tpn_canon) + 1;
  else
    n_canon = 0;

  s = su_alloc(home, n_proto + n_canon + n_host + n_port + n_comp);
  
  if (n_proto)
    dst->tpn_proto = memcpy(s, src->tpn_proto, n_proto), s += n_proto;
  else
    dst->tpn_proto = tpn_any;

  dst->tpn_host = memcpy(s, src->tpn_host, n_host), s += n_host;
  dst->tpn_port = memcpy(s, src->tpn_port, n_port), s += n_port;

  if (n_canon)
    dst->tpn_canon = memcpy(s, src->tpn_canon, n_canon), s += n_canon;
  else
    dst->tpn_canon = dst->tpn_host;

  if (n_comp)
    dst->tpn_comp = memcpy(s, src->tpn_comp, n_comp), s += n_comp;
  else
    dst->tpn_comp = NULL;
  
  return 0;
}

/** Convert a sockaddr structure into printable form. */
char *tport_hostport(char buf[], int bufsize, 
		     su_sockaddr_t const *su,
		     int with_port_and_brackets)
{
  char *b = buf;
  int n;

  if (with_port_and_brackets > 1 || su->su_family == AF_INET6) {
    *b++ = '['; bufsize--; 
  }
  if (inet_ntop(su->su_family, SU_ADDR(su), b, bufsize) == NULL)
    return NULL;
  n = strlen(b); bufsize -= n; b += n;
  if (bufsize < 2)
    return NULL;
  if (with_port_and_brackets > 1 || su->su_family == AF_INET6) {
    *b++ = ']'; bufsize--; 
  }
  if (with_port_and_brackets) {
    unsigned short port = ntohs(su->su_port);
    if (port != 0) {
      n = snprintf(b, bufsize, ":%u", port);
      if (n <= 0)
        return NULL;
      b += n; 
      if (bufsize > n)
        bufsize -= n;
      else
        bufsize = 0;
    }
  }

  if (bufsize)
    *b++ = 0;

  return buf;
}

/* ==== Thread pools =================================================== */

struct tport_threadpool
{
  /* Shared */
  su_clone_r thrp_clone;
  tport_primary_t *thrp_tport;

  int        thrp_killing; /* Threadpool is being killed */

  /* Private variables */
  su_root_t    *thrp_root;
  int           thrp_reg;
  struct sigcomp_compartment *thrp_compartment;
  su_msg_r   thrp_rmsg;

  /* Slave thread counters */
  int        thrp_r_sent;
  int        thrp_s_recv;

  unsigned   thrp_rcvd_msgs;
  unsigned   thrp_rcvd_bytes;

  /* Master thread counters */
  int        thrp_s_sent;
  int        thrp_r_recv;

  int        thrp_yield;
};

typedef struct 
{
  tport_threadpool_t *tpd_thrp;
  int  tpd_errorcode;
  msg_t *tpd_msg;
  su_time_t tpd_when;
  unsigned tpd_mtu;
#if HAVE_SIGCOMP
  struct sigcomp_compartment *tpd_cc;
#endif
  struct sigcomp_udvm *tpd_udvm;
  socklen_t tpd_namelen;
  su_sockaddr_t tpd_name[1];
} thrp_udp_deliver_t;

union tport_su_msg_arg
{
  tport_threadpool_t   *thrp;
  thrp_udp_deliver_t thrp_udp_deliver[1];
};

static int thrp_udp_init(su_root_t *, tport_threadpool_t *);
static void thrp_udp_deinit(su_root_t *, tport_threadpool_t *);
static int thrp_udp_event(tport_threadpool_t *thrp, 
			    su_wait_t *w, 
			    tport_t *_tp);
static int thrp_udp_recv_deliver(tport_threadpool_t *thrp, 
				 tport_t const *tp, 
				 thrp_udp_deliver_t *tpd,
				 int events);
static int thrp_udp_recv(tport_threadpool_t *thrp, thrp_udp_deliver_t *tpd);
#if HAVE_SIGCOMP
static int thrp_udvm_decompress(tport_threadpool_t *thrp, 
				thrp_udp_deliver_t *tpd);
#endif
static void thrp_udp_deliver(tport_threadpool_t *thrp,
			     su_msg_r msg,
			     union tport_su_msg_arg *arg);
static void thrp_udp_deliver_report(tport_threadpool_t *thrp,
				    su_msg_r m,
				    union tport_su_msg_arg *arg);
static void thrp_udp_send(tport_threadpool_t *thrp,
			  su_msg_r msg,
			  union tport_su_msg_arg *arg);
static void thrp_udp_send_report(tport_threadpool_t *thrp,
				 su_msg_r msg,
				 union tport_su_msg_arg *arg);

/** Launch threads in the tport pool. */
static 
int tport_launch_threadpool(tport_primary_t *pri)
{
  tport_t *tp = pri->pri_primary;
  tport_threadpool_t *thrp = pri->pri_threadpool;
  int i, N = tp->tp_params->tpp_thrpsize;

  if (N == 0 || thrp != NULL || pri->pri_socktype != SOCK_DGRAM)
    return 0;
  
  thrp = su_zalloc(tp->tp_home, (sizeof *thrp) * N);
  if (!thrp)
    return -1;

  su_setblocking(tp->tp_socket, 0);

  pri->pri_threadpool = thrp;
  pri->pri_thrpsize = N;

  for (i = 0; i < N; i++) {
#if HAVE_SIGCOMP
    if (tport_has_sigcomp(tp))
      thrp[i].thrp_compartment = tport_primary_compartment(tp->tp_master);
#endif
    thrp[i].thrp_tport = pri;
    if (su_clone_start(pri->pri_master->mr_root, 
		       thrp[i].thrp_clone,
		       thrp + i,
		       thrp_udp_init,
		       thrp_udp_deinit) < 0)
      goto error;
  }

  if (tp->tp_index) {
    su_root_deregister(tp->tp_master->mr_root, tp->tp_index);
    tp->tp_index = -1;
  }
  
  return 0;

 error:
  assert(!"tport_launch_threadpool");
  return -1;
}

/** Kill threads in the tport pool.
 *
 * @note Executed by stack thread only.
 */
static 
int tport_kill_threadpool(tport_primary_t *pri)
{
  tport_threadpool_t *thrp = pri->pri_threadpool;
  int i, N = pri->pri_thrpsize;

  if (!thrp)
    return 0;

  /* Prevent application from using these. */
  for (i = 0; i < N; i++)
    thrp[i].thrp_killing = 1;

  /* Stop every task in the threadpool. */
  for (i = 0; i < N; i++) 
    su_clone_wait(pri->pri_master->mr_root, thrp[i].thrp_clone);

  su_free(pri->pri_home, thrp), pri->pri_threadpool = NULL;
  
  return 0;
}

static int thrp_udp_init(su_root_t *root, tport_threadpool_t *thrp)
{
  tport_t *tp = thrp->thrp_tport->pri_primary;
  su_wait_t wait[1];

  assert(tp);

  thrp->thrp_root = root;

  if (su_wait_create(wait, tp->tp_socket, SU_WAIT_IN | SU_WAIT_ERR) < 0)
    return -1;

  thrp->thrp_reg = su_root_register(root, wait, thrp_udp_event, tp, 0);

  if (thrp->thrp_reg  == -1)
    return -1;

  return 0;
}

static void thrp_udp_deinit(su_root_t *root, tport_threadpool_t *thrp)
{
  if (thrp->thrp_reg)
    su_root_deregister(root, thrp->thrp_reg), thrp->thrp_reg = 0;
  su_msg_destroy(thrp->thrp_rmsg);
}

static inline void
thrp_yield(tport_threadpool_t *thrp)
{
  su_root_eventmask(thrp->thrp_root, thrp->thrp_reg, 
		    thrp->thrp_tport->pri_primary->tp_socket, 0);
  thrp->thrp_yield = 1;
}

static inline void
thrp_gain(tport_threadpool_t *thrp)
{
  su_root_eventmask(thrp->thrp_root, thrp->thrp_reg, 
		    thrp->thrp_tport->pri_primary->tp_socket, 
		    SU_WAIT_IN | SU_WAIT_ERR);
  thrp->thrp_yield = 0;
}

static int thrp_udp_event(tport_threadpool_t *thrp, 
			  su_wait_t *w, 
			  tport_t *tp)
{
#if HAVE_POLL
  assert(w->fd == tp->tp_socket);
#endif

  for (;;) {
    thrp_udp_deliver_t *tpd;
    int events;

    if (!*thrp->thrp_rmsg) {
      if (su_msg_create(thrp->thrp_rmsg,
			su_root_parent(thrp->thrp_root),
			su_root_task(thrp->thrp_root),
			thrp_udp_deliver,
			sizeof (*tpd)) == -1) {
	SU_DEBUG_1(("thrp_udp_event(%p): su_msg_create(): %s\n", thrp, 
		    strerror(errno)));
	return 0;
      }
    }

    tpd = su_msg_data(thrp->thrp_rmsg)->thrp_udp_deliver; assert(tpd);
    tpd->tpd_thrp = thrp;

    events = su_wait_events(w, tp->tp_socket);
    if (!events)
      return 0;

    thrp_udp_recv_deliver(thrp, tp, tpd, events);

    if (*thrp->thrp_rmsg) {
      SU_DEBUG_7(("thrp_udp_event(%p): no msg sent\n", thrp));
      tpd = su_msg_data(thrp->thrp_rmsg)->thrp_udp_deliver;
      memset(tpd, 0, sizeof *tpd);
      return 0;
    } 

    if (thrp->thrp_yield || (thrp->thrp_s_sent - thrp->thrp_s_recv) > 0)
      return 0;

    su_wait(w, 1, 0);
  }
}

static int thrp_udp_recv_deliver(tport_threadpool_t *thrp, 
				 tport_t const *tp, 
				 thrp_udp_deliver_t *tpd,
				 int events)
{
  unsigned qlen = thrp->thrp_r_sent - thrp->thrp_r_recv;

  SU_DEBUG_7(("thrp_udp_event(%p): events%s%s%s%s for %p\n", thrp,
	      events & SU_WAIT_IN ? " IN" : "",
	      events & SU_WAIT_HUP ? " HUP" : "",
	      events & SU_WAIT_OUT ? " OUT" : "",
	      events & SU_WAIT_ERR ? " ERR" : "",
	      tpd));

  if (events & SU_WAIT_ERR) {
    tpd->tpd_errorcode = tport_udp_error(tp, tpd->tpd_name);
    if (tpd->tpd_errorcode) {
      if (thrp->thrp_yield)
	su_msg_report(thrp->thrp_rmsg, thrp_udp_deliver_report);
      tpd->tpd_when = su_now();
      su_msg_send(thrp->thrp_rmsg);
      thrp->thrp_r_sent++;
      return 0;
    }
  }

  if (events & SU_WAIT_IN) {
    if (thrp_udp_recv(thrp, tpd) < 0) {
      tpd->tpd_errorcode = su_errno();
      assert(tpd->tpd_errorcode);
      if (tpd->tpd_errorcode == EAGAIN)
	return 0;
    } else if (tpd->tpd_msg) {
      int n = msg_extract(tpd->tpd_msg); (void)n;
      
      thrp->thrp_rcvd_msgs++;
      thrp->thrp_rcvd_bytes += msg_size(tpd->tpd_msg);
    }

#if HAVE_SIGCOMP
    if (tpd->tpd_udvm && !tpd->tpd_msg)
      sigcomp_udvm_free(tpd->tpd_udvm), tpd->tpd_udvm = NULL;
#endif

    assert(!tpd->tpd_msg || !tpd->tpd_errorcode);

    if (tpd->tpd_msg || tpd->tpd_errorcode) {
      if (qlen >= tp->tp_params->tpp_thrprqsize) {
	SU_DEBUG_7(("tport recv queue %i: %u\n", 
		    (int)(thrp - tp->tp_pri->pri_threadpool), qlen));
	thrp_yield(thrp);
      }

      if (qlen >= tp->tp_params->tpp_thrprqsize / 2)
	su_msg_report(thrp->thrp_rmsg, thrp_udp_deliver_report);
      tpd->tpd_when = su_now();
      su_msg_send(thrp->thrp_rmsg);
      thrp->thrp_r_sent++;
      return 0;
    }
  }

  return 0;
}

#include <pthread.h>

/** Mutex for reading from socket */
static pthread_mutex_t mutex[1] = { PTHREAD_MUTEX_INITIALIZER };

/** Receive a UDP packet by threadpool. */
static
int thrp_udp_recv(tport_threadpool_t *thrp, thrp_udp_deliver_t *tpd)
{
  tport_t const *tp = thrp->thrp_tport->pri_primary;
  unsigned char sample;
  int N;

  pthread_mutex_lock(mutex);

  /* Simulate packet loss */
  if (tp->tp_params->tpp_drop && 
      su_randint(0, 1000) < tp->tp_params->tpp_drop) {
    recv(tp->tp_socket, &sample, 1, 0);
    SU_DEBUG_3(("tport(%p): simulated packet loss!\n", tp));
    return 0;
  }

  /* Peek for first byte in message
     determine if this is compressed or not */
  N = recv(tp->tp_socket, &sample, 1, MSG_PEEK);

  if (N < 0) {
    if (su_errno() == EAGAIN)
      N = 0;
  } else if (N == 0) {
    SU_DEBUG_1(("thrp_udp_recv(%p): zero len packet\n", thrp));
    recv(tp->tp_socket, &sample, 1, 0);
  }
  else if ((N = su_getmsgsize(tp->tp_socket)) < 0)
    ;
  else if ((sample & 0xf8) != 0xf8) {
    /* Not SigComp, receive as usual */
    N = tport_recv_dgram_r(tp, &tpd->tpd_msg, N);
  } 
#if HAVE_SIGCOMP
  else if (thrp->thrp_compartment) {
    struct sigcomp_buffer *input;
    void *data;
    int dlen;

    tpd->tpd_udvm = sigcomp_udvm_create_for_compartment(thrp->thrp_compartment);
    input = sigcomp_udvm_input_buffer(tpd->tpd_udvm, N); assert(input);

    data = input->b_data + input->b_avail;
    dlen = input->b_size - input->b_avail;

    if (dlen < N)
      dlen = 0;

    tpd->tpd_namelen = sizeof(tpd->tpd_name);
    
    dlen = recvfrom(tp->tp_socket, data, dlen, 0, 
		    &tpd->tpd_name->su_sa, &tpd->tpd_namelen);

    SU_CANONIZE_SOCKADDR(tpd->tpd_name);
      
    if (dlen < N) {
      su_seterrno(EMSGSIZE);		/* Protocol error */
      N = -1;
    } else if (dlen == -1) 
      N = -1;
    else {
      input->b_avail += dlen; 
      input->b_complete = 1;

      pthread_mutex_unlock(mutex);

      N = thrp_udvm_decompress(thrp, tpd);

      if (N == -1)
	/* Do not report decompression errors as ICMP errors */
	memset(tpd->tpd_name, 0, tpd->tpd_namelen);

      return N;
    }
  }
#endif
  else {
    recv(tp->tp_socket, &sample, 1, 0);
    /* XXX - send NACK */
    su_seterrno(EBADMSG);
    N = -1;
  }

  pthread_mutex_unlock(mutex);

  return N;
}

#if HAVE_SIGCOMP
static
int thrp_udvm_decompress(tport_threadpool_t *thrp, thrp_udp_deliver_t *tpd)
{
  struct sigcomp_udvm *udvm = tpd->tpd_udvm;
  struct sigcomp_buffer *output;
  msg_iovec_t iovec[msg_n_fragments] = {{ 0 }};
  su_addrinfo_t *ai;
  tport_t *tp = thrp->thrp_tport->pri_primary;
  unsigned n, m, i, eos, dlen;
  void *data;
  int veclen;

  output = sigcomp_udvm_output_buffer(udvm, -1);
  
  if (sigcomp_udvm_decompress(udvm, output, NULL) < 0) {
    int error = sigcomp_udvm_errno(udvm);
    SU_DEBUG_3(("%s: UDVM error %d: %s\n", __func__,
		error, sigcomp_udvm_strerror(udvm)));
    su_seterrno(EREMOTEIO);
    return -1;
  } 

  data = output->b_data + output->b_used;
  dlen = output->b_avail - output->b_used;
  /* XXX - if a message is larger than default output size... */
  eos = output->b_complete; assert(output->b_complete);
    
  veclen = tport_recv_iovec(tp, &tpd->tpd_msg, iovec, dlen, eos);
    
  if (veclen <= 0) {
    n = -1;
  } else {
    for (i = 0, n = 0; i < veclen; i++) {
      m = iovec[i].mv_len; assert(dlen >= n + m);
      memcpy(iovec[i].mv_base, data + n, m);
      n += m;
    }
    assert(dlen == n);

    msg_recv_commit(tpd->tpd_msg, dlen, eos);    /* Mark buffer as used */
    
    /* Message address */
    ai = msg_addrinfo(tpd->tpd_msg);
    ai->ai_flags |= TP_AI_COMPRESSED;
    ai->ai_family = tpd->tpd_name->su_sa.sa_family;
    ai->ai_socktype = SOCK_DGRAM;
    ai->ai_protocol = IPPROTO_UDP;
    memcpy(ai->ai_addr, tpd->tpd_name, ai->ai_addrlen = tpd->tpd_namelen);

    SU_DEBUG_9(("%s(%p): sigcomp msg sz = %d\n", __func__, tp, n));
  }

  return n;
}
#endif

/** Deliver message from threadpool to the stack
 *
 * @note Executed by stack thread only.
 */
static 
void thrp_udp_deliver(su_root_magic_t *magic,
		      su_msg_r m,
		      union tport_su_msg_arg *arg)
{
  thrp_udp_deliver_t *tpd = arg->thrp_udp_deliver;
  tport_threadpool_t *thrp = tpd->tpd_thrp;
  tport_t *tp = thrp->thrp_tport->pri_primary;
  su_time_t now = su_now();

  assert(magic != thrp);

  thrp->thrp_r_recv++;

  if (thrp->thrp_killing) {
#if HAVE_SIGCOMP
    sigcomp_udvm_free(tpd->tpd_udvm), tpd->tpd_udvm = NULL;
#endif
    msg_destroy(tpd->tpd_msg);
    return;
  }

  SU_DEBUG_7(("thrp_udp_deliver(%p): got %p delay %f\n", 
	      thrp, tpd, 1000 * su_time_diff(now, tpd->tpd_when)));

  if (tpd->tpd_errorcode)
    tport_error_report(tp, tpd->tpd_errorcode, tpd->tpd_name);
  else if (tpd->tpd_msg) {
    tport_deliver(tp, tpd->tpd_msg, NULL, &tpd->tpd_udvm, tpd->tpd_when);
    tp->tp_rlogged = NULL;
  }

#if HAVE_SIGCOMP 
  if (tpd->tpd_udvm) {
    sigcomp_udvm_free(tpd->tpd_udvm), tpd->tpd_udvm = NULL;
  }
#endif
}

static 
void thrp_udp_deliver_report(tport_threadpool_t *thrp,
			     su_msg_r m,
			     union tport_su_msg_arg *arg)
{
  if (thrp->thrp_yield) {
    int qlen = thrp->thrp_r_sent - thrp->thrp_r_recv;
    int qsize = thrp->thrp_tport->pri_params->tpp_thrprqsize;
    if (qlen == 0 || qlen < qsize / 2)
      thrp_gain(thrp);
  }
}

/** Send a message to network using threadpool.
 *
 * @note Executed by stack thread only.
 */
static
int tport_thread_send(tport_t *tp,
		      struct sigcomp_compartment *cc,
		      msg_t *msg,
		      unsigned mtu)
{
  tport_threadpool_t *thrp = tp->tp_pri->pri_threadpool;
  thrp_udp_deliver_t *tpd;
  int i, N = tp->tp_pri->pri_thrpsize;
  su_msg_r m;
  unsigned totalqlen = 0;
  unsigned qlen;

  if (thrp->thrp_killing)
    return (su_seterrno(ECHILD)), -1;

  qlen = totalqlen = thrp->thrp_s_sent - thrp->thrp_s_recv;

  /* Select thread with shortest queue */ 
  for (i = 1; i < N; i++) {
    tport_threadpool_t *other = tp->tp_pri->pri_threadpool + i;
    unsigned len = other->thrp_s_sent - other->thrp_s_recv;

    if (len < qlen || 
	(len == qlen && (other->thrp_s_sent - thrp->thrp_s_sent) < 0))
      thrp = other, qlen = len;

    totalqlen += len;
  }

  if (totalqlen >= N * tp->tp_params->tpp_qsize)
    SU_DEBUG_3(("tport send queue: %u (shortest %u)\n", totalqlen, qlen));

  if (su_msg_create(m,
		    su_clone_task(thrp->thrp_clone),
		    su_root_task(tp->tp_master->mr_root),
		    thrp_udp_send,
		    sizeof (*tpd)) != su_success) {
    SU_DEBUG_1(("thrp_udp_event(%p): su_msg_create(): %s\n", thrp, 
		strerror(errno)));
    return -1;
  }

  tpd = su_msg_data(m)->thrp_udp_deliver;
  tpd->tpd_thrp = thrp;
  tpd->tpd_when = su_now();
  tpd->tpd_mtu = mtu;
  tpd->tpd_msg = msg_ref_create(msg);

#if HAVE_SIGCOMP
  tpd->tpd_cc = cc;
#endif

  su_msg_report(m, thrp_udp_send_report);

  if (su_msg_send(m) == su_success) {
    thrp->thrp_s_sent++;
    return 0;
  }

  msg_ref_destroy(msg);
  return -1;
}

/** thrp_udp_send() is run by threadpool to send the message. */
static 
void thrp_udp_send(tport_threadpool_t *thrp,
		   su_msg_r m,
		   union tport_su_msg_arg *arg)
{
  thrp_udp_deliver_t *tpd = arg->thrp_udp_deliver;
  tport_t *tp = thrp->thrp_tport->pri_primary;
  msg_t *msg = tpd->tpd_msg;
  msg_iovec_t *iov, auto_iov[40], *iov0 = NULL;
  int iovlen, iovused, n;

  assert(thrp == tpd->tpd_thrp);

  thrp->thrp_s_recv++;

  { 
    double delay = 1000 * su_time_diff(su_now(), tpd->tpd_when);
    if (delay > 100)
      SU_DEBUG_3(("thrp_udp_deliver(%p): got %p delay %f\n", thrp, tpd, delay));
    else
      SU_DEBUG_7(("thrp_udp_deliver(%p): got %p delay %f\n", thrp, tpd, delay));
  }

  if (!msg) {
    tpd->tpd_errorcode = EINVAL;
    return;
  }

  /* Prepare message for sending - i.e., encode it */
  if (msg_prepare(msg) < 0) {
    tpd->tpd_errorcode = errno;
    return;
  }

  if (tpd->tpd_mtu != 0 && msg_size(msg) > tpd->tpd_mtu) {
    tpd->tpd_errorcode = EMSGSIZE;
    return;
  }

  /* Use initially the I/O vector from stack */
  iov = auto_iov, iovlen = sizeof(auto_iov)/sizeof(auto_iov[0]);

  /* Get a iovec for message contents */
  for (;;) {
    iovused = msg_iovec(msg, iov, iovlen);
    if (iovused <= iovlen) 
      break;

    iov = iov0 = realloc(iov0, sizeof(*iov) * iovused);
    iovlen = iovused;

    if (iov0 == NULL) {
      tpd->tpd_errorcode = errno;
      return;
    }
  }

  assert(iovused > 0);

  tpd->tpd_when = su_now();

  if (0)
    ;
#if HAVE_SIGCOMP
  else if (tpd->tpd_cc) {
    tport_sigcomp_t sc[1] = {{ NULL }};

    n = tport_sigcomp_vsend(tp, msg, iov, iovused, tpd->tpd_cc, sc);
  } 
#endif
  else 
    n = tport_vsend_iovec(tp, msg, iov, iovused);

  if (n == -1)
    tpd->tpd_errorcode = su_errno();

  if (iov0)
    free(iov0);
}

static 
void thrp_udp_send_report(su_root_magic_t *magic,
			  su_msg_r msg,
			  union tport_su_msg_arg *arg)
{
  thrp_udp_deliver_t *tpd = arg->thrp_udp_deliver;
  tport_threadpool_t *thrp = tpd->tpd_thrp;
  tport_t *tp = thrp->thrp_tport->pri_primary;

  assert(magic != thrp);

  SU_DEBUG_7(("thrp_udp_send_report(%p): got %p delay %f\n", 
	      thrp, tpd, 1000 * su_time_diff(su_now(), tpd->tpd_when)));

  if (tp->tp_master->mr_log)
    tport_log_msg(tp, tpd->tpd_msg, "sent", "to", "   ", tpd->tpd_when);

  if (tpd->tpd_errorcode)
    tport_error_report(tp, tpd->tpd_errorcode, msg_addr(tpd->tpd_msg));

  msg_ref_destroy(tpd->tpd_msg);
}

static
struct tport_nat_s *
tport_nat_initialize_nat_traversal(tport_master_t *mr, 
				   tp_name_t const *tpn,
				   char const * const ** return_transports)
{
  struct tport_nat_s *nat = mr->mr_nat;
  char const *stun_server;

  if (nat->initialized)
    return nat;

  stun_server = getenv("STUN_SERVER");
  
#if HAVE_SOFIA_STUN
  nat->stun = NULL;
  nat->external_ip_address = NULL;
  nat->stun_socket = NULL;

  /* We support only UDP in case STUN_SERVER env variable is defined */
  if (stun_server && 
      (strcmp(tpn->tpn_proto, "*") == 0 || 
       strcasecmp(tpn->tpn_proto, "udp") == 0)) {
    static char const * const stun_transports[] = { "udp", NULL };
    int i;

    SU_DEBUG_5(("Using STUN_SERVER=%s\n", stun_server));

    for (i = 0; stun_transports[i]; i++) {
      if (strcasecmp(stun_transports[i], "udp") == 0) {
        SU_DEBUG_5(("%s(%p) starting STUN engine\n", __func__, mr));
        nat->stun = stun_engine_create(stun_server, 1);

        if (!nat->stun) 
	  return NULL;

	nat->try_stun = 1;
	*return_transports = stun_transports;
        break;
      }
    }
  }
#endif

#if HAVE_UPNP
  /* Register upnp control point and collect descriptions from NATs */
  /* parameter is time in seconds to wait for devices */
  /* return value of 0 unsuccessful; -1 already mapped */
  if (upnp_register_upnp_client(1) != 0) {
    /* see if nat is enabled and if it is, find out the external ip address */
    upnp_check_for_nat();

    SU_DEBUG_5(("Using UPnP IGD for NAT/FW traversal.\n"));

    if (igd_list_s) {
      if (upnp_has_nat_enabled(igd_list_s)) {
	if (upnp_has_external_ip(igd_list_s)) {
	  nat->external_ip_address = upnp_get_external_ip(igd_list_s);
	  SU_DEBUG_5(("UPnP-IGD: queried external IP %s.\n", nat->external_ip_address));
	}
      }
    }
  }
#endif

  nat->initialized = 1;

  return nat;
}

char *tport_nat_get_external_ip_address(struct tport_nat_s *nat)
{
  return nat->external_ip_address;
}


#if HAVE_SOFIA_STUN
/**
 * Binds to socket and tries to create port bindings
 * using STUN.
 *
 * @return non-zero on success
 */
int tport_nat_stun_bind(struct tport_nat_s *nat,
			su_sockaddr_t su[1],
			socklen_t *sulen,
			su_socket_t s)
{
  int nat_bound = 0, lifetime = 0, bind_res = 0;
  nat->stun_socket = stun_socket_create(nat->stun, s);
  bind_res = stun_bind(nat->stun_socket, &su->su_sa, sulen, &lifetime);
  if (bind_res >= 0) {
    SU_DEBUG_9(("%s: stun_bind() ok\n", __func__));
    nat->stun_enabled = 1;
    nat_bound = 1;
  }
  else {
    /* TP_SOCKET_ERROR(errno, stun_bind); */
    SU_DEBUG_3(("%s: STUN bind failed.\n", __func__));
  }
  return nat_bound;
}
#endif /* HAVE_SOFIA_STUN */

/**
 * Creates a binding for address 'su' using various
 * NAT/FW traversal mechanisms.
 *
 * @return Some NAT/FW mechanisms will also bind to the given local
 *         address. In this cases, the return value will be
 *         non-zero.
 */
int tport_nat_traverse_nat(tport_master_t *self,
			   su_sockaddr_t su[1],
			   su_addrinfo_t const *ai,
			   su_socket_t s)
{
  int nat_bound = 0;

#if HAVE_SOFIA_STUN
  socklen_t sulen = ai->ai_addrlen;
  struct tport_nat_s *nat = self->mr_nat;
#endif

#if HAVE_SOFIA_STUN && HAVE_UPNP
  /* If both STUN and UPnP are enabled, we need to choose
     which of them we wish to use under which circumstances */

  /* Algorithm:
   * 1. Check if there are any UPnP-enabled IGDs
   * 2. If there are, see whether they are connected directly to the Internet
   * 3. If they are and a port can be opened, do not use STUN
   * 4. Otherwise use STUN
   *
   * The problem is the case where even the address space on the WAN side of
   * the NAT is part of a private address range, but still includes the 
   * recipient. In this case UPnP could be used but is not.
   *
   * The solution would be to check whether the recipient is on the same
   * address space. The check would need to see if the recipient IP
   * address is also private and on the same range.
   */

  SU_DEBUG_5(("%s: Both UPnP and STUN selected in compilation.\n", __func__));
   
  /* Check if UPnP is available */

  if (igd_list_s 
      && upnp_has_nat_enabled(igd_list_s) /* 1 if enabled, 0 otherwise */
      && upnp_has_external_ip(igd_list_s)
      && su->su_port != 0      /* is there a port to open? */
      /* if external address is not private  */
      && (!upnp_is_private_address(upnp_get_external_ip(igd_list_s)) 
	  /* or if the STUN server was not specified */
	  || !nat->try_stun)
      && upnp_open_port(igd_list_s, ntohs(su->su_port), ntohs(su->su_port), 
			ai->ai_protocol, self, ai->ai_family)) {
    SU_DEBUG_9(("%s: upnp_open_port ok\n", __func__));

    nat->try_stun = 0;
  }

  /* if it isn't, it's time to try STUN */

  if (nat->try_stun) {

    if (nat->stun && ai->ai_protocol == IPPROTO_UDP) {
      nat_bound = tport_nat_stun_bind(nat, su, &sulen, s);
    }

    if (nat->stun == NULL || !nat_bound) { /* UPnP fallback, cascading NAT */
      if (igd_list_s) {
        if (upnp_has_nat_enabled(igd_list_s)) { /* 1 if enabled, 0 otherwise */
          if (upnp_has_external_ip(igd_list_s)) {
            if (ntohs(su->su_port)) {
              if (upnp_open_port(igd_list_s, 
				 ntohs(su->su_port), 
				 ntohs(su->su_port), 
				 ai->ai_protocol, self, ai->ai_family)) {
                SU_DEBUG_9(("%s: upnp_open_port ok\n", __func__));
              }
            }
          }
        }
      }
    }
  }
#elif HAVE_UPNP

  SU_DEBUG_5(("%s: Only UPnP selected in compilation.\n", __func__));

  /* There needs to be some sort of mechanism of choosing the right IGD: now we
     just use the first one in the IGD linked list (usually the only one) */
    
  /* If the linked list does exist, ie. we are behind a firewall: */
  if (igd_list_s) {
    if (upnp_has_nat_enabled(igd_list_s)) { /* 1 if enabled, 0 otherwise */
      if (upnp_has_external_ip(igd_list_s)) {
      /* is there a port to open? */
        if (ntohs(su->su_port)) {
          if (!upnp_open_port(igd_list_s, ntohs(su->su_port), ntohs(su->su_port), ai->ai_protocol, self, ai->ai_family)) {
            SU_DEBUG_3(("%s: upnp_open_port failed\n", __func__));
          }
          else {
            SU_DEBUG_9(("%s: upnp_open_port ok\n", __func__));
          }
        }
      }
    }
  }
#elif HAVE_SOFIA_STUN
    
  SU_DEBUG_5(("%s: Only STUN selected in compilation.\n", __func__));

  if (nat->stun && ai->ai_protocol == IPPROTO_UDP) {
    nat_bound = tport_nat_stun_bind(nat, su, &sulen, s);
  }
#endif

  return nat_bound;
}

static
int tport_nat_set_canon(tport_t *self, struct tport_nat_s *nat)
{
#if HAVE_SOFIA_STUN || HAVE_UPNP
  tp_name_t *tpn = self->tp_name;
#endif

#if HAVE_SOFIA_STUN && HAVE_UPNP
  if (nat->stun_enabled) {
    self->tp_stun_socket = nat->stun_socket;
    if (nat->stun_socket && strcmp(tpn->tpn_canon, tpn->tpn_host)) {
      tpn->tpn_canon = tpn->tpn_host;
    }
  } 
  else {
    if (strcmp(tpn->tpn_canon, tpn->tpn_host))
      tpn->tpn_canon = tpn->tpn_host;
  }
#elif HAVE_SOFIA_STUN

  self->tp_stun_socket = nat->stun_socket;
  if (nat->stun_socket && strcmp(tpn->tpn_canon, tpn->tpn_host))
    tpn->tpn_canon = tpn->tpn_host;
#elif HAVE_UPNP
  if (strcasecmp(tpn->tpn_canon, tpn->tpn_host))
    tpn->tpn_canon = tpn->tpn_host;
#endif

  return 1;
}

int tport_nat_finish(tport_primary_t *pri)
{
#if HAVE_UPNP
  /* close all ports which were registered by self */
  upnp_close_all_ports(pri->pri_primary);
#endif
  return 1;
}
