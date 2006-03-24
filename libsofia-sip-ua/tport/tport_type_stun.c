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

/**@CFILE tport_connect.c Transport using HTTP CONNECT.
 *
 * See tport.docs for more detailed description of tport interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti.Mela@nokia.com>
 *
 * @date Created: Fri Mar 24 08:45:49 EET 2006 ppessi
 */

#include "config.h"

#define STUN_MAGIC_T            struct tport_master
#define STUN_DISCOVERY_MAGIC_T  struct tport_primary

#include "tport_internal.h"

#if HAVE_UPNP
#include "upnp_wrapper.h"
#endif

#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

/* ---------------------------------------------------------------------- */
/* STUN */

#if HAVE_SOFIA_STUN

static
struct tport_nat_s *
tport_nat_initialize_nat_traversal(tport_master_t *mr, 
				   tp_name_t const *tpn,
				   char const * const **return_transports,
				   tagi_t const *tags);

static
char *tport_nat_get_external_ip_address(struct tport_nat_s *nat);


static
int tport_nat_stun_bind(tport_primary_t *pub,
			struct tport_nat_s *nat,
			su_sockaddr_t su[1],
			socklen_t *sulen,
			su_socket_t s);
static
void tport_stun_bind_done(tport_primary_t *pri,
			  stun_handle_t *sh,
			  stun_discovery_t *sd);


static
int tport_nat_traverse_nat(tport_master_t *, 
			   tport_primary_t *pub,
			   su_sockaddr_t su[1],
			   su_addrinfo_t const *ai,
			   su_socket_t s);

static
int tport_nat_set_canon(tport_t *self, struct tport_nat_s *nat);

static
int tport_nat_finish(tport_primary_t *self);

static int tport_udp_init_stun(tport_primary_t *,
			       tp_name_t const tpn[1], 
			       su_addrinfo_t *, 
			       tagi_t const *,
			       char const **return_culprit);

typedef struct
{
  tport_primary_t stuntp_primary[1];
  int stun_try;
  char *stun_server;
  stun_handle_t *stun_handle;
  su_socket_t stun_socket;
  su_sockaddr_t stun_sockaddr;
} tport_stun_t;

tport_vtable_t const tport_stun_vtable =
{
  "UDP", tport_type_stun,
  sizeof (tport_stun_t),
  tport_stun_init_primary,
  tport_init_compression,
  tport_stun_deinit_primary,
  NULL,
  NULL,
  sizeof (tport_t),
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  tport_recv_dgram,
  tport_send_dgram,
};

static int tport_udp_init_stun(tport_primary_t *pri,
			       tp_name_t const tpn[1], 
			       su_addrinfo_t *ai, 
			       tagi_t const *tpn,
			       char const **return_culprit)
{
  struct tport_nat_s *nat;

  nat = tport_nat_initialize_nat_traversal(mr, tpn, &transports, tags);
  if (!nat) 
    SU_DEBUG_1(("%s: %s\n", __func__, strerror(errno)));

  if (nat && tpn->tpn_canon) {
    /* NULL if UPnP not present */
    tpn->tpn_canon = tport_nat_get_external_ip_address(nat);
  }

  if (tport_udp_init_primary(pri, tpn, ai, tpn, return_culprit) < 0)
    return -1;

  if ((ai->ai_protocol == IPPROTO_UDP) &&
      (tport_is_public(pri->pri_primary) == tport_type_stun)) {
    /* Launch NAT resolving */
    nat_bound = tport_nat_traverse_nat(mr, pri, su, ai, s);
  }
    
  if (nat_bound) {
    /* XXX - should set also the IP address in tp_addr? */
    pri->pri_natted = 1;
    tport_nat_set_canon(pri->pri_primary, mr->mr_nat);
  }

  if (nat_bound) {
    /* XXX - should set also the IP address in tp_addr? */
    pri->pri_natted = 1;
    tport_nat_set_canon(pri->pri_primary, mr->mr_nat);
  }

  return 0;
}

static void tport_udp_deinit_stun(tport_primary_t *pri)
{
  tport_nat_finish(pri);	/* XXX */
}

#endif

/** Initialize STUN keepalives.
 *
 *@retval 0
 */
int tport_keepalive(tport_t *tp, tp_name_t *tpn)
{
#if HAVE_SOFIA_STUN && 0
  int err;
  tport_master_t *mr = tp->tp_master;
  stun_handle_t *sh = mr->mr_nat->stun;
  su_sockaddr_t sa[1] = {{ 0 }};

  if (tp->tp_has_keepalive == 1 || sh == NULL)
    return 0;

  inet_pton(AF_INET, tpn->tpn_host, (void *) &sa->su_sin.sin_addr.s_addr);
  sa->su_port = htons(atoi(tpn->tpn_port));
  sa->su_family = AF_INET;

  /*XXX -- remove me after it's working */
  memcpy(sa, tp->tp_addr, sizeof(*sa));

  err = stun_keepalive(sh, sa,
		       STUNTAG_SOCKET(tp->tp_socket),
		       STUNTAG_TIMEOUT(10000),
		       TAG_NULL());
  
  if (err < 0)
    return -1;

  tp->tp_has_keepalive = 1;
#endif
  return 0;
}

#if HAVE_SOFIA_STUN
void tport_stun_cb(tport_master_t *mr,
		   stun_handle_t *sh,
		   stun_request_t *req,
		   stun_discovery_t *sd,
		   stun_action_t action,
		   stun_state_t event)
{
  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  switch (action) {
  case stun_action_tls_query:
    break;

  default:
    break;
  }

  return;
}


/**Callback for STUN bind
*/
void tport_stun_bind_cb(tport_primary_t *pri,
			stun_handle_t *sh,
			stun_request_t *req,
			stun_discovery_t *sd,
			stun_action_t action,
			stun_state_t event)
{
  tport_master_t *mr;
  SU_DEBUG_3(("%s: %s\n", __func__, stun_str_state(event)));

  mr = pri->pri_master;

  if (event == stun_bind_done)
    tport_stun_bind_done(pri, sh, sd);

  return;
}
#endif

static
void tport_stun_bind_done(tport_primary_t *pri,
			  stun_handle_t *sh,
			  stun_discovery_t *sd)
{
  tport_t *tp = pri->pri_primary;
  su_sockaddr_t *sa = NULL;
  char ipaddr[SU_ADDRSIZE + 2] = { 0 };
  su_socket_t s;

  s = stun_discovery_get_socket(sd);
  sa = stun_discovery_get_address(sd);

  SU_DEBUG_0(("%s: local address NATed as %s:%u\n", __func__,
	      inet_ntop(sa->su_family,
			SU_ADDR(sa),
			ipaddr, sizeof(ipaddr)),
	      (unsigned) ntohs(sa->su_port)));

  SU_DEBUG_9(("%s: stun_bind() ok\n", __func__));
  

  /* Send message to calling application indicating there's a new
     public address available */
  STACK_ADDRESS(tp);

  return;
}

static
struct tport_nat_s *
tport_nat_initialize_nat_traversal(tport_master_t *mr, 
				   tp_name_t const *tpn,
				   char const * const ** return_transports,
				   tagi_t const *tags)
{
  struct tport_nat_s *nat = mr->mr_nat; /* */

  if (nat->initialized)
    return nat;

#if HAVE_SOFIA_STUN
  if (stun_is_requested(TAG_NEXT(tags))) {
    static char const * const stun_transports[] = { "udp", NULL };
    int i;

    nat->stun = NULL;
    nat->external_ip_address = NULL;
    /* nat->stun_socket = NULL; */

    nat->tport = mr;

    for (i = 0; stun_transports[i]; i++) {
      if ((strcmp(tpn->tpn_proto, "*") == 0 || 
	   strcasecmp(tpn->tpn_proto, stun_transports[i]) == 0)) {
        SU_DEBUG_5(("%s(%p) initializing STUN handle\n", __func__, mr));

        nat->stun = stun_handle_create(mr,
				       mr->mr_root,
				       tport_stun_cb,
				       TAG_NEXT(tags));

        if (!nat->stun) 
	  return NULL;

	if (stun_request_shared_secret(nat->stun) < 0) {
	  SU_DEBUG_3(("%s: %s failed\n", __func__,
		      "stun_request_shared_secret()"));
	}

	nat->try_stun = 1;
	/* We support only UDP if STUN is used */
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
int tport_nat_stun_bind(tport_primary_t *pub,
			struct tport_nat_s *nat,
			su_sockaddr_t su[1],
			socklen_t *sulen,
			su_socket_t s)
{
  stun_handle_t *sh = nat->stun;
  int nat_bound = 0, reg_socket;

  /* nat->stun_socket = stun_socket_create(nat->stun, s); */

  nat->stun_socket = s;
  
  /* Do not register socket to stun's event loop */
  reg_socket = 0;

  nat_bound = stun_bind(sh, tport_stun_bind_cb, pub,
			STUNTAG_SOCKET(s),
			STUNTAG_REGISTER_SOCKET(reg_socket),
			TAG_NULL());

  if (nat_bound < 0) {
    SU_DEBUG_9(("%s: %s  failed.\n", __func__, "stun_bind()"));
    return nat_bound;
  }

  nat->stun_enabled = 1;
  nat_bound = 1;

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
			   tport_primary_t *pub,
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
      nat_bound = tport_nat_stun_bind(pub, nat, su, &sulen, s);
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
    nat_bound = tport_nat_stun_bind(pub, nat, su, &sulen, s);
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

