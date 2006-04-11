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

/**@CFILE nua_register.c
 * @brief REGISTER and registrations
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 11:48:49 EET 2006 ppessi
 */

#include "config.h"

#include <sofia-sip/string0.h>
#include <sofia-sip/su_strlst.h>
#include <sofia-sip/sha1.h>
#include <sofia-sip/su_uniqueid.h>
#include <sofia-sip/token64.h>
#include <sofia-sip/su_tagarg.h>

#include <sofia-sip/bnf.h>

#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_status.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s
#define NTA_UPDATE_MAGIC_T   struct nua_s

#include "nua_stack.h"
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport_tag.h>

#if HAVE_SIGCOMP
#include <sigcomp.h>
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <assert.h>

#if !defined(random) && defined(_WIN32)
#define random rand
#endif

/* ====================================================================== */
/* Outbound connection */

typedef struct outbound_connect outbound_connect;
typedef struct outbound_owner_vtable outbound_owner_vtable;

int outbound_connect_init(outbound_connect *ru,
			  outbound_owner_vtable const *owner_methods,
			  su_root_t *root,
			  nta_agent_t *agent,
			  char const *options);

int outbound_connect_set_options(outbound_connect *oc, char const *options);

int outbound_connect_set_features(outbound_connect *ru, char *features);

int outbound_connect_check_for_nat(struct outbound_connect *ru,
				 nta_outgoing_t *orq,
				 sip_t const *sip);

int outbound_connect_contacts_from_via(outbound_connect *ru,
				     sip_via_t const *via,
				     sip_via_t const *pair);

int outbound_connect_set_contact(struct outbound_connect *ru,
			       sip_contact_t *m);

int outbound_connects_from_via(struct outbound_connect **list,
			     nua_owner_t *owner,
			     sip_via_t const *via,
			     int public);

int outbound_connect_set_contact_by_aor(struct outbound_connect *ru,
				      url_t const *aor,
				      outbound_connect const *defaults);

outbound_connect *outbound_connect_by_aor(outbound_connect const *usages,
				      url_t const *aor,
				      int only_default);

void outbound_connect_start_keepalive(struct outbound_connect *ru,
				    unsigned interval,
				    nta_outgoing_t *register_trans);

void outbound_connect_stop_keepalive(struct outbound_connect *ru);

int outbound_connect_check_accept(sip_accept_t const *accept);

int outbound_connect_process_options(struct outbound_connect *usages,
				     nta_incoming_t *irq,
				     sip_t const *sip);

sip_contact_t const *outbound_connect_contact(outbound_connect const *ru);

char const * const outbound_connect_content_type;
nua_usage_class const *nua_outbound_connect;

struct outbound_owner_vtable
{
  int oo_size;
  int (*oo_status)(nua_owner_t *, outbound_connect *ru,
		   int status, char const *phrase,
		   tag_type_t tag, tag_value_t value, ...);
  int (*oo_probe_error)(nua_owner_t *, outbound_connect *ru,
			int status, char const *phrase,
			tag_type_t tag, tag_value_t value, ...);
  int (*oo_keepalive_error)(nua_owner_t *, outbound_connect *ru,
			    int status, char const *phrase,
			    tag_type_t tag, tag_value_t value, ...);
};

struct outbound_connect {
  struct outbound_connect *oc_next, **oc_prev; /* Doubly linked list */
  outbound_owner_vtable
  const *oc_oo;			/**< Callbacks */
  nua_owner_t *oc_owner;	/**< Backpointer */
  su_root_t *oc_root;		/**< Root for timers and stuff */
  nta_agent_t *oc_nta;		/**< SIP transactions */

  char oc_cookie[32];		/**< Our magic cookie */

  int32_t oc_reg_id;		/**< Flow-id */

  struct outbound_prefs {
    unsigned gruuize:1;		/**< Establish a GRUU */
    unsigned outbound:1;	/**< Try to use outbound */
    unsigned natify:1;		/**< Try to detect NAT */
    unsigned validate:1;	/**< Validate registration with OPTIONS */
    /* How to detect NAT binding or connect to outbound: */
    unsigned use_connect:1;	/**< Use HTTP connect */
    unsigned use_rport:1;	/**< Use received/rport */
    unsigned use_socks:1;	/**< Detect and use SOCKS V5 */
    unsigned use_upnp:1;	/**< Detect and use UPnP */
    unsigned use_stun:1;	/**< Detect and try to use STUN */
    unsigned :0;
  } oc_prefs;

  struct outbound_info {
    /* 0 do not support, 1 - perhaps supports, 2 supports, 4 requires */
    unsigned gruu:2, outbound:2, pref:2;
  } oc_info;

  unsigned oc_default:1, oc_secure:1, oc_public:1;
  unsigned oc_by_application:1;
  unsigned oc_add_contact:1;

  /* The registration state machine. */
  /** Initial REGISTER containing oc_rcontact has been sent */
  unsigned oc_registering:1;
  /** 2XX response to REGISTER containg oc_rcontact has been received */
  unsigned oc_registered:1;
  /**The registration has been validated:
   * We have successfully sent OPTIONS to ourselves.
   */
  unsigned oc_validated:1;
  /** The registration has been validated once.
   *   We have successfully sent OPTIONS to ourselves, so do not give
   *   up if OPTIONS probe fails.
   */
  unsigned oc_once_validated:1;

  unsigned :0;

  tport_t *oc_tport;		/**< Transport used when registered */
  char const *oc_features;	/**< Feature parameters for rcontact */
  sip_via_t *oc_via;		/**< Our Via (or Via pair) */
  sip_contact_t *oc_rcontact;	/**< Our contact */
  sip_contact_t *oc_dcontact;	/**< Contact for dialogs */
  sip_contact_t *oc_previous;	/**< Stale contact */
  sip_contact_t *oc_gruu;	/**< Contact added to requests */
  sip_route_t *oc_route;	/**< Outgoing Service-Route */
  sip_path_t *oc_path;		/**< Incoming Path */
  sip_contact_t *oc_obp;	/**< Contacts from outbound proxy */

  char *oc_nat_detected;	/**< Our public address */
  char *oc_nat_port;		/**< Our public port number */

  void *oc_stun;		/**< Stun context */
  void *oc_upnp;		/**< UPnP context  */

  char *oc_sipstun;		/**< Stun server usable for keep-alives */
  unsigned oc_keepalive;	/**< Interval. */
  su_timer_t *oc_kalt;		/**< Keep-alive timer */
  msg_t *oc_kalmsg;		/**< Keep-alive OPTIONS message */
  nta_outgoing_t *oc_kalo;	/**< Keep-alive OPTIONS transaction */

#if HAVE_SIGCOMP
  struct sigcomp_compartment *oc_compartment;
#endif
};

/* ======================================================================== */
/* REGISTER */

static void restart_register(nua_handle_t *nh, tagi_t *tags);
static void refresh_register(nua_handle_t *, nua_dialog_usage_t *, sip_time_t);

static int process_response_to_register(nua_handle_t *nh,
					nta_outgoing_t *orq,
					sip_t const *sip);

static void unregister_expires_contacts(msg_t *msg, sip_t *sip);

static char *nua_stack_register_features(nua_handle_t *nh);

static int nua_stack_register_status(nua_handle_t *, outbound_connect *oc,
				     int status, char const *phrase,
				     tag_type_t tag, tag_value_t value, ...);

static int nua_stack_register_failed(nua_handle_t *, outbound_connect *oc,
				     int status, char const *phrase,
				     tag_type_t tag, tag_value_t value, ...);

outbound_owner_vtable nua_stack_register_callbacks = {
    sizeof nua_stack_register_callbacks,
    nua_stack_register_status,
    nua_stack_register_failed,
    nua_stack_register_failed,
  };

/**@fn void nua_register(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);
 * 
 * Send SIP REGISTER request to the registrar. 
 *
 * Request status will be delivered to the application using #nua_r_register
 * event. When successful the registration will be updated periodically.
 *
 * The handle used for registration cannot be used for any other purposes.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     NUTAG_REGISTRAR(), NUTAG_KEEPALIVE(), NUTAG_KEEPALIVE_STREAM(),
 *     NUTAG_OUTBOUND()
 *
 * @par Events:
 *     #nua_r_register, #nua_i_outbound
 *
 * @par NAT, Firewall and Outbound Support
 *
 * If the application did not include the Contact header in the tags,
 * nua_register() will generate one and start a protocol engine for outbound
 * connections used for NAT and firewall traversal and connectivity checks.
 * 
 * First, nua_register() will first probe for NATs in between UA and
 * registrar. It will send a REGISTER request as usual. Upon receiving the
 * response check for the presence of "received" and "rport" parameters in
 * the Via header returned by registrar. The presence of NAT is determined
 * from the "received" parameter in a Via header. When a REGISTER request
 * was sent, the stack inserted the source IP address in the Via header: if
 * that is different from the source IP address seen by the registrar, the
 * registrar inserts the source IP address it sees into the "received"
 * parameter.
 *
 * Please note that an ALG (application-level gateway) modifying the Via
 * headers in outbound requests and again in incoming responses will make
 * the above-described NAT check to fail.
 *
 * The response to the initial REGISTER should also include feature tags
 * indicating whether registrar supports various SIP extensions: @e
 * outbound, @e pref, @e path, @e gruu. If the @e outbound extension is
 * supported, and it is not explicitly disabled by application, the
 * nua_register() will use it. Basically, @e outbound means that instead of
 * registering its contact URI with a particular address-of-record URI, the
 * user-agent registers a transport-level connection. Such a connection is
 * identified on the Contact header field with a @ref NUTAG_INSTANCE()
 * "unique string" identifying the user-agent instance and a numeric index
 * identifying the transport-level connection.
 *
 * If @e outbound is not supported, nua_register() has to generate a URI
 * that can be used to reach it from outside. It will check for public
 * transport addresses detected by underlying stack with, e.g., STUN, UPnP
 * or SOCKS. If there are public addresses, nua_register() will use them. If
 * there is no public address, it will try to generate a Contact URI from
 * the "received" and "rport" parameters found in the Via header of the
 * response message.
 *
 * @par GRUU and Service-Route
 *
 * After a successful response to the REGISTER request has been received,
 * nua_register() will update the information about the registration based
 * on it. If there is a "gruu" parameter included in the response,
 * nua_register() will save it and use the gruu URI in the Contact header
 * fields of dialog-establishing messages, such as INVITE or SUBSCRIBE. 
 * Also, if the registrar has included a Service-Route header in the
 * response, and the service route feature has not been disabled using
 * NUTAG_SERVICE_ROUTE_ENABLE(), the route URIs from the Service-Route
 * header will be used for initial non-REGISTER requests.
 *
 * The #nua_r_register message will include the contact header and route
 * used in with the registration.
 *
 * @par Registration Keep-Alive
 *
 * After the registration has successfully completed the nua_register() will
 * validate the registration and initiate the keepalive mechanism, too. The
 * user-agent validates the registration by sending a OPTIONS requests to
 * itself. If there is an error, nua_register() will indicate that to the
 * application using nua_i_outbound event, and start unregistration
 * procedure (unless that has been explicitly disabled).
 *
 * The keepalive mechanism depends on the network features detected earlier. 
 * If @a outbound extension is used, the STUN keepalives will be used. 
 * Otherwise, NUA stack will repeatedly send OPTIONS requests to itself. In
 * order to save bandwidth, it will include Max-Forwards: 0 in the
 * keep-alive requests, however. The keepalive interval is determined by two
 * parameters: NUTAG_KEEPALIVE() and NUTAG_KEEPALIVE_STREAM(). If the
 * interval is 0, no keepalive messages is sent. The value of
 * NUTAG_KEEPALIVE_STREAM(), if specified, is used to indicate the desired
 * transport-layer keepalive interval for stream-based transports like TLS
 * and TCP.
 */

/** @var nua_event_e::nua_r_register
 *
 * Answer to outgoing REGISTER.
 *
 * The REGISTER may be sent explicitly by nua_register() or implicitly by
 * NUA state machines. The @a status may be 100 even if the real response
 * status returned is different if the REGISTER request has been restarted.
 *
 * @param nh     operation handle associated with the call
 * @param hmagic operation magic associated with the call
 * @param status registration status
 * @param sip    response to REGISTER request or NULL upon an error
 *               (error code and message are in status an phrase parameters)
 * @param tags   empty
 */

/** @var nua_event_e::nua_i_outbound
 *
 * Answer to outgoing REGISTER.
 *
 * The REGISTER may be sent explicitly by nua_register() or
 * implicitly by NUA state machine.
 *
 * @param nh     operation handle associated with the call
 * @param hmagic operation magic associated with the call
 * @param sip    response to REGISTER request or NULL upon an error
 *               (error code and message are in status an phrase parameters)
 * @param tags   empty
 */

/**@fn void nua_unregister(nua_handle_t *nh, tag_type_t tag, tag_value_t value, ...);
 * Unregister. 
 *
 * Send a REGISTER request with expiration time 0. This removes the 
 * registration from the registrar. If the handle was earlier used 
 * with nua_register() the periodic updates will be terminated. 
 *
 * If a SIPTAG_CONTACT_STR() with argument "*" is used, all the
 * registrations will be removed from the registrar otherwise only the
 * contact address belonging to the NUA stack is removed.
 *
 * @param nh              Pointer to operation handle
 * @param tag, value, ... List of tagged parameters
 *
 * @return
 *     nothing
 *
 * @par Related tags:
 *     NUTAG_REGISTRAR() \n
 *     Tags in <sip_tag.h> except SIPTAG_EXPIRES() or SIPTAG_EXPIRES_STR()
 *
 * @par Events:
 *     #nua_r_unregister
 */

/** @var nua_event_e::nua_r_unregister
 *
 * Answer to outgoing un-REGISTER.
 *
 * @param nh     operation handle associated with the call
 * @param hmagic operation magic associated with the call
 * @param sip    response to REGISTER request or NULL upon an error
 *               (error code and message are in status and phrase parameters)
 * @param tags   empty
 */


int
nua_stack_register(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		   tagi_t const *tags)
{
  nua_dialog_usage_t *du;
  struct outbound_connect *oc = NULL;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg = NULL;
  sip_t *sip;
  int terminating = e != nua_r_register;

  if (nh->nh_special && nh->nh_special != nua_r_register)
    return UA_EVENT2(e, 500, "Invalid handle for REGISTER");
  if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  nua_stack_init_handle(nua, nh, nh_has_register, "", TAG_NEXT(tags));
  nh->nh_special = nua_r_register;

  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_outbound_connect, NULL);
  if (!du)
    return UA_EVENT1(e, NUA_500_ERROR);
  oc = nua_dialog_usage_private(du); assert(oc);

  outbound_connect_init(oc, &nua_stack_register_callbacks,
			nh->nh_nua->nua_root, nh->nh_nua->nua_nta,
			NH_PGET(nh, outbound));

  outbound_connect_set_features(oc, nua_stack_register_features(nh));

  outbound_connect_stop_keepalive(oc);

  if (du->du_msg)
    cr->cr_msg = msg_ref_create(du->du_msg);

  msg = nua_creq_msg(nua, nh, cr, cr->cr_msg != NULL,
		     SIP_METHOD_REGISTER,
		     TAG_IF(!terminating, NUTAG_USE_DIALOG(1)),
		     TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    du->du_terminating = terminating;

    if (du->du_msg)
      msg_destroy(du->du_msg);
    du->du_msg = msg_ref_create(cr->cr_msg);

    if (sip->sip_contact)
      outbound_connect_set_contact(oc, sip->sip_contact);

    if (!oc->oc_rcontact) {
      outbound_connect_set_contact_by_aor(oc, sip->sip_to->a_url,
					  nh->nh_nua->nua_registrations);
      /* Try first time without contact if we are not natifying */
      oc->oc_add_contact = !oc->oc_prefs.natify;
    }

    if (terminating)
      /* Add Expires: 0 and remove expire parameter from contacts */
      unregister_expires_contacts(msg, sip);

    cr->cr_orq =
      nta_outgoing_mcreate(nua->nua_nta,
			   process_response_to_register, nh, NULL,
			   msg,
			   TAG_IF(oc->oc_add_contact,
				  SIPTAG_CONTACT(oc->oc_rcontact)),
			   TAG_IF(oc->oc_add_contact,
				  SIPTAG_CONTACT(oc->oc_previous)),
			   SIPTAG_END(),
			   TAG_IF(terminating, NTATAG_SIGCOMP_CLOSE(1)),
			   TAG_IF(!terminating, NTATAG_COMP("sigcomp")),
			   TAG_NEXT(tags));

    if (cr->cr_orq)
      oc->oc_registering = 1;
  }

  if (!cr->cr_orq) {
    msg_destroy(msg);
    msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  cr->cr_usage = du;

  return cr->cr_event = e;
}

static void
restart_register(nua_handle_t *nh, tagi_t *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;
  nua_dialog_usage_t *du = cr->cr_usage;
  struct outbound_connect *oc = nua_dialog_usage_private(du);
  int unregistering = du && du->du_terminating;
  sip_contact_t *contact = NULL, *previous = NULL;

  cr->cr_restart = NULL;

  if (!cr->cr_msg)
    return;

  msg = nua_creq_msg(nh->nh_nua, nh, cr, 1,
		     SIP_METHOD_UNKNOWN,
		     TAG_NEXT(tags));

  if (!msg)
    return;			/* Uh-oh */

  if (unregistering)
    unregister_expires_contacts(msg, sip_object(msg));

  if (oc) {
    if (oc->oc_add_contact) {
      contact = oc->oc_rcontact;
      if (oc->oc_previous && oc->oc_previous->m_expires)
	previous = oc->oc_previous;
    }
  }

  cr->cr_orq = nta_outgoing_mcreate(nh->nh_nua->nua_nta,
				    process_response_to_register, nh, NULL,
				    msg,
				    SIPTAG_CONTACT(contact),
				    SIPTAG_CONTACT(previous),
				    SIPTAG_END(), TAG_NEXT(tags));

  if (cr->cr_orq) {
    oc->oc_registering = 1;
  }
  else
    msg_destroy(msg);
}

static
int process_response_to_register(nua_handle_t *nh,
				 nta_outgoing_t *orq,
				 sip_t const *sip)
{
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  struct outbound_connect *oc = nua_dialog_usage_private(du);
  int status;
  char const *phrase;
  sip_t *req = sip_object(cr->cr_msg);

  assert(sip);
  assert(du && du->du_class == nua_outbound_connect);
  status = sip->sip_status->st_status;
  phrase = sip->sip_status->st_phrase;

  if (status < 200 || !du)
    return nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

  if (oc->oc_prefs.natify && status >= 200) {
    int reregister;

    reregister = outbound_connect_check_for_nat(oc, orq, sip);

    if (reregister < 0)
      SET_STATUS2(500, nua_500_error);
    else if (reregister > 0) {
      msg_t *msg = msg_ref_create(cr->cr_msg);
      if (nua_creq_check_restart(nh, cr, orq, sip, restart_register)) {
	msg_destroy(msg);
	return 0;
      }

      assert(cr->cr_msg == NULL);
      cr->cr_msg = msg;

      if (reregister > 1) {
	/* We can try to reregister immediately */
	nua_creq_restart_with(nh, cr, orq, 100, "Updated Contact",
			      restart_register,
			      TAG_END());
      }
      else {
	nua_creq_save_restart(nh, cr, orq, 100, "Updated Contact",
			      restart_register);
      }

      return 0;
    }
  }

  if (status >= 300) {
    if (nua_creq_check_restart(nh, cr, orq, sip, restart_register))
      return 0;
    du->du_ready = 0;
  }
  else if (status < 300) {
    du->du_ready = 1;

    if (!du->du_terminating && sip->sip_contact)
      oc->oc_registered = oc->oc_registering;
    else
      oc->oc_registered = 0;

    if (oc->oc_registered) {
      sip_time_t now = sip_now(), delta, mindelta;
      sip_contact_t const *m, *m0;

      /** Search for lowest delta of SIP contacts in sip->sip_contact */
      mindelta = SIP_TIME_MAX;

      for (m = sip->sip_contact; m; m = m->m_next) {
	if (m->m_url->url_type != url_sip)
	  continue;
	for (m0 = req->sip_contact; m0; m0 = m0->m_next)
	  if (url_cmp(m->m_url, m0->m_url) == 0) {
	    delta = sip_contact_expires(m, sip->sip_expires, sip->sip_date,
					3600, /* XXX */
					now);
	    if (delta > 0 && delta < mindelta)
	      mindelta = delta;
	    break;
	  }
      }

      if (mindelta == SIP_TIME_MAX)
	mindelta = 3600;

      nua_dialog_usage_set_refresh(du, mindelta);
      du->du_pending = refresh_register;
    }

    if (!du->du_terminating) {
#if HAVE_SIGCOMP
      struct sigcomp_compartment *cc;
      cc = nta_outgoing_compartment(orq);
      sigcomp_compartment_unref(oc->oc_compartment);
      oc->oc_compartment = cc;
#endif
    }
  }

  /*  RFC 3608 Section 6.1 Procedures at the UA

   The UA performs a registration as usual.  The REGISTER response may
   contain a Service-Route header field.  If so, the UA MAY store the
   value of the Service-Route header field in an association with the
   address-of-record for which the REGISTER transaction had registered a
   contact.  If the UA supports multiple addresses-of-record, it may be
   able to store multiple service routes, one per address-of-record.  If
   the UA refreshes the registration, the stored value of the Service-
   Route is updated according to the Service-Route header field of the
   latest 200 class response.  If there is no Service-Route header field
   in the response, the UA clears any service route for that address-
   of-record previously stored by the UA.  If the re-registration
   request is refused or if an existing registration expires and the UA
   chooses not to re-register, the UA SHOULD discard any stored service
   route for that address-of-record.

  */
  if (!du->du_terminating && status < 300) {
    su_free(nh->nh_home, oc->oc_route);
    oc->oc_route = sip_route_dup(nh->nh_home, sip->sip_service_route);
  }
  else {
    su_free(nh->nh_home, oc->oc_route);
    oc->oc_route = NULL;
  }

  /* RFC 3327 */
  /* We are mainly interested in the last part of the Path header */
  if (!du->du_terminating && status < 300) {
    sip_path_t *path = sip->sip_path;

    while (path && path->r_next)
      path = path->r_next;

    if (!oc->oc_path || !path ||
	url_cmp_all(oc->oc_path->r_url, path->r_url)) {
      su_free(nh->nh_home, oc->oc_path);
      oc->oc_path = sip_path_dup(nh->nh_home, path);
    }
  }

  if (!du->du_terminating && status < 300) {
    if (!oc->oc_prev) {
      /* Add to the list of registrations */
      if ((oc->oc_next = nh->nh_nua->nua_registrations))
	oc->oc_next->oc_prev = &oc->oc_next;
      oc->oc_prev = &nh->nh_nua->nua_registrations;
      nh->nh_nua->nua_registrations = oc;
    }
  }

  if (!du->du_terminating && status < 300 && oc->oc_nat_detected)
    outbound_connect_start_keepalive(oc, 15, orq);
  else
    outbound_connect_stop_keepalive(oc);

  return nua_stack_process_response(nh, cr, orq, sip, TAG_END());
}

void
refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
  outbound_connect *oc = nua_dialog_usage_private(du);
  nua_event_t e;
  msg_t *msg;
  sip_t *sip;

  if (cr->cr_msg) {
    /* Delay of 5 .. 15 seconds */
    nua_dialog_usage_set_refresh(du, 5 + (unsigned)random() % 11U);
    du->du_pending = refresh_register;
    return;
  }

  if (now > 0)
    e = nua_r_register;
  else
    e = nua_r_destroy, du->du_terminating = 1;

  outbound_connect_stop_keepalive(oc);

  cr->cr_msg = msg_ref_create(du->du_msg);
  msg = nua_creq_msg(nua, nh, cr, 1,
		     SIP_METHOD_REGISTER,
		     NUTAG_USE_DIALOG(1),
		     TAG_END());
  sip = sip_object(msg);

  if (sip) {
    int unregistering = now == 0;
    sip_contact_t *contact = NULL, *previous = NULL;

    if (unregistering)
      unregister_expires_contacts(msg, sip);

    if (oc) {
      if (oc->oc_add_contact) {
	contact = oc->oc_rcontact;
	if (oc->oc_previous && oc->oc_previous->m_expires)
	  previous = oc->oc_previous;
      }
    }

    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_register, nh, NULL,
				      msg,
				      SIPTAG_CONTACT(contact),
				      SIPTAG_CONTACT(previous),
				      SIPTAG_END(), TAG_NEXT(NULL));
  }

  if (!cr->cr_orq) {
    if (du->du_terminating)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    msg_destroy(msg);
    msg_destroy(cr->cr_msg);
    UA_EVENT2(e, NUA_500_ERROR, TAG_END());
    return;
  }

  cr->cr_usage = du;
  cr->cr_event = e;
}

/* ---------------------------------------------------------------------- */
/* Register usage interface */

static void nua_stack_tport_update(nua_t *nua, nta_agent_t *nta);

int
nua_stack_init_transport(nua_t *nua, tagi_t const *tags)
{
  url_string_t const *contact1 = NULL, *contact2 = NULL;
  char const *name1 = "sip", *name2 = "sip";
  char const *certificate_dir = NULL;

  tl_gets(tags,
	  NUTAG_URL_REF(contact1),
	  NUTAG_SIPS_URL_REF(contact2),
	  NUTAG_CERTIFICATE_DIR_REF(certificate_dir),
	  TAG_END());

  if (contact1 &&
      (url_is_string(contact1) 
       ? strncasecmp(contact1->us_str, "sips:", 5) == 0
       : contact1->us_url->url_type == url_sips))
    name1 = "sips";

  if (contact2 && 
      (url_is_string(contact2) 
       ? strncasecmp(contact2->us_str, "sips:", 5) == 0
       : contact2->us_url->url_type == url_sips))
    name2 = "sips";

  if (!contact1 && !contact2) {
    if (nta_agent_add_tport(nua->nua_nta, NULL,
			    TPTAG_IDENT("sip"),
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0 &&
	nta_agent_add_tport(nua->nua_nta, URL_STRING_MAKE("*"),
			    TPTAG_IDENT("sip"),
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0)
      return -1;

    if (nta_agent_add_tport(nua->nua_nta, URL_STRING_MAKE("*"),
			    TPTAG_IDENT("stun"),
			    TPTAG_PUBLIC(tport_type_stun), /* use stun */
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0)
      return -1;
  }
  else if ((!contact1 ||
	    nta_agent_add_tport(nua->nua_nta, contact1,
				TPTAG_IDENT(name1),
				TPTAG_CERTIFICATE(certificate_dir),
				TAG_NEXT(nua->nua_args)) < 0) &&
	   (!contact2 ||
	    nta_agent_add_tport(nua->nua_nta, contact2,
				TPTAG_IDENT(name2),
				TPTAG_CERTIFICATE(certificate_dir),
				TAG_NEXT(nua->nua_args)) < 0)) {
    return -1;
  }

  if (nua_stack_init_registrations(nua) < 0)
    return -1;

  return 0;
}

int
nua_stack_init_registrations(nua_t *nua)
{
  /* Create initial identities: peer-to-peer, public, sips */
  sip_via_t const *v;
  nua_handle_t *dnh = nua->nua_dhandle;

  v = nta_agent_public_via(nua->nua_nta);
  if (v) {
    outbound_connects_from_via(&nua->nua_registrations, dnh, v, 1);
  }

  v = nta_agent_via(nua->nua_nta);
  if (v) {
    outbound_connects_from_via(&nua->nua_registrations, dnh, v, 0);
  }
  else {
    sip_via_t v[2];

    sip_via_init(v)->v_next = v + 1;
    v[0].v_protocol = sip_transport_udp;
    v[0].v_host = "addr.is.invalid.";
    sip_via_init(v + 1);
    v[1].v_protocol = sip_transport_tcp;
    v[1].v_host = "addr.is.invalid.";

    outbound_connects_from_via(&nua->nua_registrations, dnh, v, 0);
  }

  nta_agent_bind_tport_update(nua->nua_nta, nua,
			      nua_stack_tport_update);

  return 0;
}

static
void nua_stack_tport_update(nua_t *nua, nta_agent_t *nta)
{
  outbound_connect *default_oc;
  outbound_connect const *defaults = nua->nua_registrations;
  sip_via_t *via = nta_agent_via(nta);
  
  default_oc = outbound_connect_by_aor(defaults, NULL, 1);

  if (default_oc) {
    assert(default_oc->oc_via);

    outbound_connect_contacts_from_via(default_oc,
				     via,
				     via->v_next);

    /* refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now); */
  }

  return;
}


sip_contact_t const *nua_contact_by_aor(nua_t *nua,
					url_t const *aor,
					int only_default)
{
  outbound_connect *oc = nua->nua_registrations;

  oc = outbound_connect_by_aor(oc, aor, only_default);

  return outbound_connect_contact(oc);
}

/** @internal Return a string descibing our features. */
static
char *nua_stack_register_features(nua_handle_t *nh)
{
  char *retval;
  su_strlst_t *l = su_strlst_create(NULL);
  su_home_t *home = su_strlst_home(l);

  if (!l)
    return NULL;

  if (NH_PGET(nh, instance))
    su_slprintf(l, ";+sip.instance=\"<%s>\"", NH_PGET(nh, instance));

  if (NH_PGET(nh, callee_caps)) {
    sip_allow_t const *allow = NH_PGET(nh, allow);

    if (allow) {
      su_strlst_append(l, ";methods=\"");
      if (allow->k_items) {
	int i;
	for (i = 0; allow->k_items[i]; i++) {
	  su_strlst_append(l, allow->k_items[i]);
	  if (allow->k_items[i + 1])
	    su_strlst_append(l, ",");
	}
      }
      su_strlst_append(l, "\"");
    }

    if (nh->nh_soa) {
      char **media = soa_media_features(nh->nh_soa, 0, home);

      while (*media) {
	su_strlst_append(l, ";");
	su_strlst_append(l, *media++);
      }
    }
  }

  retval = su_strlst_join(l, nh->nh_home, "");

  su_strlst_destroy(l);

  return retval;
}

/**@internal
 * Fix contacts for un-REGISTER.
 *
 * Remove (possible non-zero) "expires" parameters from contacts and extra
 * contacts, add Expire: 0.
 */
static
void unregister_expires_contacts(msg_t *msg, sip_t *sip)
{
  sip_contact_t *m;
  int unregister_all;

  /* Remove payload */
  while (sip->sip_payload)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_payload);
  while (sip->sip_content_type)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_content_type);

  for (m = sip->sip_contact; m; m = m->m_next) {
    if (m->m_url->url_type == url_any)
      break;
    msg_header_remove_param(m->m_common, "expires");
#if 0
    msg_header_add_param(msg_home(msg), m->m_common, "expires=0");
#endif
  }

  unregister_all = m && (m != sip->sip_contact || m->m_next);

  sip_add_tl(msg, sip,
	     /* Remove existing contacts */
	     TAG_IF(unregister_all, SIPTAG_CONTACT(NONE)),
	     /* Add '*' contact: 0 */
	     TAG_IF(unregister_all, SIPTAG_CONTACT_STR("*")),
	     SIPTAG_EXPIRES_STR("0"),
	     TAG_END());
}


/** @internal Callback from outbound_connect */
static int nua_stack_register_status(nua_handle_t *nh, outbound_connect *oc,
				     int status, char const *phrase,
				     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;

  ta_start(ta, tag, value);

  nua_stack_event(nh->nh_nua, nh, NULL,
		  nua_i_outbound, status, phrase,
		  ta_tags(ta));

  ta_end(ta);

  return 0;
}

/** @internal Callback from outbound_connect */
static int nua_stack_register_failed(nua_handle_t *nh, outbound_connect *oc,
				     int status, char const *phrase,
				     tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  ta_start(ta, tag, value);

  nua_stack_event(nh->nh_nua, nh, NULL,
		  nua_i_outbound, status, phrase,
		  ta_tags(ta));

  ta_end(ta);

  return 0;
}

/* ====================================================================== */
/* Register-usage side */

static
int outbound_connect_nat_detect(outbound_connect *oc, sip_t const *);

/* ---------------------------------------------------------------------- */

/** @internal Check if there is a NAT between us and registrar */
int outbound_connect_check_for_nat(struct outbound_connect *oc,
				   nta_outgoing_t *orq,
				   sip_t const *sip)
{
  int binding_changed;
  sip_contact_t *m = oc->oc_rcontact;

#if 0
  if (host_is_domain(v->v_host)) {
    /*
     * If we use domain name in Via, we assume that application
     * knows something we don't.
     * Just use ordinary contact unless domain name ends with ".invalid"
     */
    char const *invalid = strcasestr(v->v_host, ".invalid");

    if (invalid)
      invalid += (sizeof ".invalid") - 1;
    if (invalid && invalid[0] == '.') /* ... or .invalid. */
      invalid++;

    if (!invalid || invalid[0] != '\0') {
      if (!oc->oc_rcontact)
	...
      if (!oc->oc_rcontact)
	return -1;
      return 0;
    }
  }
#endif

  binding_changed = outbound_connect_nat_detect(oc, sip);

  /* Contact was set by application, do not change it */
  if (oc->oc_by_application)
    return 0;

  if (!oc->oc_nat_detected) {
    if (oc->oc_add_contact)
      return 0;
    oc->oc_add_contact = 1;
    return 2;
  }

  /* We have detected NAT. Now, what to do?
   * 1) do nothing - register as usual and let proxy take care of it?
   * 2) try to detect our public nat binding and use it
   * 2A) use public vias from nta generated by STUN or UPnP
   * 2B) use SIP Via header
   */

  /* Do we have to ask for reregistration */
  if (!m || binding_changed > 1) {
    if (oc->oc_stun) {
      /* Use STUN? */
      return 1;
    }
    else if (oc->oc_upnp) {
      /* Use UPnP */
      return 1;
    }
    else {
      if (outbound_connect_contacts_from_via(oc, sip->sip_via, NULL) < 0)
	return -1;
      oc->oc_add_contact = 1;
    }

    return 2;
  }

  return 0;
}

/**@internal
 *
 * Detect NAT.
 *
 * Based on "received" and possible "rport" parameters in the top-most Via,
 * check and update our NAT status.
 *
 * @retval 2 change in public NAT binding detected
 * @retval 1 NAT binding detected
 * @retval 0 no NAT binding detected
 * @retval -1 an error occurred
 */
static
int outbound_connect_nat_detect(outbound_connect *oc,
				sip_t const *response)
{
  sip_via_t const *v = response->sip_via;
  int one = 1;
  char const *received, *rport;
  char *nat_detected, *nat_port;
  char *new_detected, *new_port;
  su_home_t *home;

  if (!oc || !v)
    return -1;

  received = v->v_received;
  if (!received)
    return 0;

  rport = sip_via_port(v, &one); assert(rport);

  nat_detected = oc->oc_nat_detected;
  nat_port = oc->oc_nat_port;

  if (nat_detected && strcasecmp(received, nat_detected) == 0 &&
      nat_port && strcasecmp(rport, nat_port) == 0)
    return 1;

  if (!nat_detected) {
    SU_DEBUG_1(("outbound_connect: detected NAT: %s != %s\n",
		v->v_host, received));
    if (oc->oc_oo && oc->oc_oo->oo_status)
      oc->oc_oo->oo_status(oc->oc_owner, oc, 101, "NAT detected", TAG_END());
  }
  else {
    SU_DEBUG_1(("outbound_connect: NAT binding changed: "
		"[%s]:%s != [%s]:%s\n",
		nat_detected, nat_port, received, rport));
    if (oc->oc_oo && oc->oc_oo->oo_status)
      oc->oc_oo->oo_status(oc->oc_owner, oc, 102, "NAT binding changed", TAG_END());
  }

  /* Save our nat binding */

  home = (su_home_t *)oc->oc_owner;

  new_detected = su_strdup(home, received);
  new_port = su_strdup(home, rport);

  if (!new_detected || !new_port) {
    su_free(home, new_detected);
    su_free(home, new_port);
    return -1;
  }

  oc->oc_nat_detected = new_detected;
  oc->oc_nat_port = new_port;

  su_free(home, nat_detected);
  su_free(home, nat_port);

  return 2;
}

/* ---------------------------------------------------------------------- */

static int create_keepalive_message(struct outbound_connect *oc,
				    sip_t const *register_request);

static int keepalive_options(outbound_connect *oc);
static int keepalive_options_with_registration_probe(outbound_connect *oc);

static int response_to_keepalive_options(nua_owner_t *oc_casted_as_owner,
					 nta_outgoing_t *orq,
					 sip_t const *sip);

static void keepalive_timer(su_root_magic_t *root_magic,
			    su_timer_t *t,
			    su_timer_arg_t *oc_as_timer_arg);

void outbound_connect_start_keepalive(struct outbound_connect *oc,
				    unsigned interval,
				    nta_outgoing_t *register_transaction)
{
  if (oc->oc_kalt)
    su_timer_destroy(oc->oc_kalt), oc->oc_kalt = NULL;

  if (interval)
    oc->oc_kalt = su_timer_create(su_root_task(oc->oc_root),
				  /* 1000 * */ 100 * interval);

  oc->oc_keepalive = interval;

  if (!oc->oc_validated && oc->oc_sipstun && 0) {
    /* XXX */
  }
  else {
    if (register_transaction) {
      msg_t *msg = nta_outgoing_getrequest(register_transaction);
      sip_t const *register_request = sip_object(msg);
      create_keepalive_message(oc, register_request);
      msg_destroy(msg);
    }

    keepalive_options(oc);
  }
}

void outbound_connect_stop_keepalive(struct outbound_connect *oc)
{
  oc->oc_keepalive = 0;

  if (oc->oc_kalt)
    su_timer_destroy(oc->oc_kalt), oc->oc_kalt = NULL;

  if (oc->oc_kalo)
    nta_outgoing_destroy(oc->oc_kalo), oc->oc_kalo = NULL;
}

/** @internal Create a message template for keepalive. */
static int create_keepalive_message(struct outbound_connect *oc,
				    sip_t const *regsip)
{
  msg_t *msg = nta_msg_create(oc->oc_nta, MSG_FLG_COMPACT), *previous;
  sip_t *osip = sip_object(msg);

  assert(regsip); assert(regsip->sip_request);

  if (
      sip_add_tl(msg, osip,
		 /* Duplicate essential headers from REGISTER request:
		    From/To, Route */
		 SIPTAG_TO(regsip->sip_to),
		 SIPTAG_FROM(regsip->sip_from),
		 /* XXX - we should only use loose routing here */
		 /* XXX - if we used strict routing,
		    the route header/request_uri must be restored
		 */
		 SIPTAG_ROUTE(regsip->sip_route),
		 /* Add Max-Forwards 0 */
		 SIPTAG_MAX_FORWARDS_STR("0"),
		 SIPTAG_SUBJECT_STR("KEEPALIVE"),
		 SIPTAG_CALL_ID_STR(oc->oc_cookie),
		 TAG_END()) < 0 ||
      /* Create request-line, Call-ID, CSeq */
      nta_msg_request_complete(msg,
			       nta_default_leg(oc->oc_nta),
			       SIP_METHOD_OPTIONS,
			       (void *)regsip->sip_request->rq_url) < 0 ||
      msg_serialize(msg, (void *)osip) < 0 ||
      msg_prepare(msg) < 0)
    return msg_destroy(msg), -1;

  previous = oc->oc_kalmsg;
  oc->oc_kalmsg = msg;
  msg_destroy(previous);

  return 0;
}

static int keepalive_options(outbound_connect *oc)
{
  msg_t *req;

  if (oc->oc_kalo)
    return 0;

  if (oc->oc_registered && !oc->oc_validated)
    return keepalive_options_with_registration_probe(oc);

  req = msg_copy(oc->oc_kalmsg);
  if (!req)
    return -1;

  if (nta_msg_request_complete(req, nta_default_leg(oc->oc_nta),
			       SIP_METHOD_UNKNOWN, NULL) < 0)
    return msg_destroy(req), -1;

  oc->oc_kalo = nta_outgoing_mcreate(oc->oc_nta,
				     response_to_keepalive_options,
				     (nua_owner_t *)oc,
				     NULL,
				     req,
				     TAG_END());

  if (!oc->oc_kalo)
    return msg_destroy(req), -1;

  return 0;
}

static int response_to_keepalive_options(nua_owner_t *oc_casted_as_owner,
					 nta_outgoing_t *orq,
					 sip_t const *sip)
{
  outbound_connect *oc = (outbound_connect *)oc_casted_as_owner;
  int status = 408;
  int binding_check;

  if (sip && sip->sip_status)
    status = sip->sip_status->st_status;

  if (status == 100) {
    /* This probably means that we are in trouble. whattodo, whattodo */
  }

  if (status < 200)
    return 0;

  if (orq == oc->oc_kalo)
    oc->oc_kalo = NULL;
  nta_outgoing_destroy(orq);

  if (status == 408) {
    SU_DEBUG_1(("outbound_connect(%p): keepalive timeout\n", oc));
    /* XXX - do something about it! */
    return 0;
  }

  binding_check = outbound_connect_nat_detect(oc, sip);

  if (binding_check > 1) {
    /* Bindings have changed */
    /* XXX - do something about it! */
    if (outbound_connect_contacts_from_via(oc, sip->sip_via, NULL) == 0) {
      /* re-REGISTER */
      nua_dialog_usage_refresh(oc->oc_owner, nua_dialog_usage_public(oc), 1);
      return 0;
    }
  }

  if (binding_check <= 1 && status < 300 && oc->oc_registered) {
    if (!oc->oc_validated)
      SU_DEBUG_1(("outbound_connect(%p): validated contact "
		  URL_PRINT_FORMAT "\n",
		  oc, URL_PRINT_ARGS(oc->oc_rcontact->m_url)));
    oc->oc_validated = oc->oc_once_validated = 1;
  }

  su_timer_set(oc->oc_kalt, keepalive_timer, oc);

  return 0;
}

static void keepalive_timer(su_root_magic_t *root_magic,
			    su_timer_t *t,
			    su_timer_arg_t *oc_casted_as_timer_arg)
{
  outbound_connect *oc = (outbound_connect *)oc_casted_as_timer_arg;

  (void)root_magic;

  if (keepalive_options(oc) < 0)
    su_timer_set(t, keepalive_timer, oc_casted_as_timer_arg);	/* XXX */
}


/** @internal Send a keepalive OPTIONS that probes the registration */
static int keepalive_options_with_registration_probe(outbound_connect *oc)
{
  msg_t *req;
  sip_t *sip;
  void *request_uri;

  if (oc->oc_kalo)
    return 0;

  req = msg_copy(oc->oc_kalmsg);
  if (!req)
    return -1;

  sip = sip_object(req);
  request_uri = sip->sip_to->a_url;

  if (nta_msg_request_complete(req, nta_default_leg(oc->oc_nta),
			       SIP_METHOD_OPTIONS, request_uri) < 0)
    return msg_destroy(req), -1;

  if (oc->oc_features) {
    sip_accept_contact_t *ac;
    ac = sip_accept_contact_format(msg_home(req), "*;%s", oc->oc_features);
    msg_header_insert(req, NULL, (void *)ac);
  }

  oc->oc_kalo = nta_outgoing_mcreate
    (oc->oc_nta,
     response_to_keepalive_options,
     (nua_owner_t *)oc,
     NULL,
     req,
     /* See RFC 3841 */
     SIPTAG_ACCEPT_STR(outbound_connect_content_type),
     SIPTAG_PROXY_REQUIRE_STR("pref"),
     SIPTAG_REQUEST_DISPOSITION_STR("proxy"),
     SIPTAG_SUBJECT_STR("REGISTRATION PROBE"),
     SIPTAG_MAX_FORWARDS(NONE),	/* Remove 0 used in ordinary keepalives */
     TAG_END());

  if (!oc->oc_kalo)
    return msg_destroy(req), -1;

  return 0;
}

/** @internal Check if incoming OPTIONS is a registration probe */
int outbound_connect_check_accept(sip_accept_t const *accept)
{
  return
    accept &&
    accept->ac_type &&
    strcasecmp(accept->ac_type, outbound_connect_content_type) == 0;
}

/** @internal Process incoming keepalive/validate OPTIONS */
int outbound_connect_process_options(struct outbound_connect *usages,
				   nta_incoming_t *irq,
				   sip_t const *sip)
{
  sip_call_id_t *i = sip->sip_call_id;
  struct outbound_connect *oc;

  assert(i);

  for (oc = usages; oc; oc = oc->oc_next) {
    if (strcmp(i->i_id, oc->oc_cookie) == 0)
      break;
  }

  if (!oc)
    return 481;			/* Call/Transaction does not exist */

  nta_incoming_treply(irq, SIP_200_OK,
		      SIPTAG_CONTENT_TYPE_STR(outbound_connect_content_type),
		      SIPTAG_PAYLOAD_STR(oc->oc_cookie),
		      TAG_END());

  return 501;
}

/* ---------------------------------------------------------------------- */

/**@internal
 * Create contacts for register usage.
 *
 * Each registration has two contacts: one suitable for registrations and
 * another that can be used in dialogs.
 */
int outbound_connect_contacts_from_via(outbound_connect *oc,
				     sip_via_t const *via,
				     sip_via_t const *pair)
{
  su_home_t *home = (su_home_t *)oc->oc_owner;
  char *uri;
  sip_contact_t *rcontact, *dcontact;
  sip_contact_t *previous_rcontact, *previous_dcontact;
  char const *transport;
  sip_via_t *v, v0[1], *previous_via;
  int contact_uri_changed;
  
  if (!via)
    return -1;

  if (pair)
    /* Don't use protocol if we have both udp and tcp */
    transport = NULL;
  else
    transport = via->v_protocol;

  v = v0; *v0 = *via; v0->v_next = (sip_via_t *)pair;

  uri = sip_contact_string_from_via(NULL, via, NULL, transport);

  dcontact = sip_contact_make(home, uri);
  if (oc->oc_features && oc->oc_reg_id && oc->oc_prefs.outbound)
    rcontact = sip_contact_format(home, "%s%s;reg-id=%u", 
				  uri, oc->oc_features, oc->oc_reg_id);
  else if (oc->oc_features) 
    rcontact = sip_contact_format(home, "%s%s", uri, oc->oc_features);
  else
    rcontact = dcontact;
  v = sip_via_dup(home, v);

  free(uri);

  if (!rcontact || !dcontact || !v) {
    msg_header_free(home, (void *)dcontact);
    if (rcontact != dcontact)
      msg_header_free(home, (void *)rcontact);
    msg_header_free(home, (void *)v);
    return -1;
  }

  contact_uri_changed = !oc->oc_rcontact ||
    url_cmp_all(oc->oc_rcontact->m_url, rcontact->m_url);

  if (contact_uri_changed) {
    previous_rcontact = oc->oc_previous;
    previous_dcontact = oc->oc_dcontact;
    previous_via = oc->oc_via;

    oc->oc_previous = oc->oc_rcontact;
    if (oc->oc_previous)
      msg_header_replace_param(home, (void*)oc->oc_previous, "expires=0");
  }
  else {
    previous_rcontact = oc->oc_rcontact;
    previous_dcontact = oc->oc_dcontact;
    previous_via = oc->oc_via;
  }

  oc->oc_rcontact = rcontact;
  oc->oc_dcontact = dcontact;
  oc->oc_via = v;

  if (contact_uri_changed) {
    oc->oc_registering = 0;
    oc->oc_registered = 0;
    oc->oc_validated = 0;
  }

  msg_header_free(home, (void *)previous_rcontact);
  if (previous_dcontact != oc->oc_previous &&
      previous_dcontact != previous_rcontact)
    msg_header_free(home, (void *)previous_dcontact);
  msg_header_free(home, (void *)previous_via);

  return 0;
}

/** @internal Set contact by application */
int outbound_connect_set_contact(struct outbound_connect *oc,
			       sip_contact_t *m)
{
  su_home_t *home = (su_home_t *)oc->oc_owner;
  sip_contact_t *m1, *m2, *m3;
  int contact_uri_changed;

  m = sip_contact_dup(home, m);
  if (!m)
    return -1;

  oc->oc_by_application = 1;

  m1 = oc->oc_rcontact;
  m2 = oc->oc_dcontact;
  m3 = oc->oc_previous;

  contact_uri_changed = !m1 || url_cmp_all(m1->m_url, m->m_url);

  oc->oc_rcontact = m, oc->oc_dcontact = m, oc->oc_previous = NULL;

  if (contact_uri_changed) {
    oc->oc_registering = 0;
    oc->oc_registered = 0;
    oc->oc_validated = 0;
  }

  msg_header_free(home, (void *)m1);
  if (m2 != m1 && m2 != m3)
    msg_header_free(home, (void *)m2);
  msg_header_free(home, (void *)m3);

  return 0;
}

/** @internal Set contact to by using aor */
int outbound_connect_set_contact_by_aor(struct outbound_connect *oc,
				      url_t const *aor,
				      outbound_connect const *defaults)
{
  outbound_connect *default_ru;

  default_ru = outbound_connect_by_aor(defaults, aor, 1);

  if (default_ru) {
    assert(default_ru->oc_via);

    outbound_connect_contacts_from_via(oc,
				     default_ru->oc_via,
				     default_ru->oc_via->v_next);

  }

  return 0;
}

int outbound_connects_from_via(struct outbound_connect **list,
			     nua_owner_t *owner,
			     sip_via_t const *via,
			     int public)
{
  su_home_t *ohome = (su_home_t *)owner;
  sip_via_t *v, *pair, *vias, **vv, **prev;
  nua_registration_t *oc = NULL, **next;
  su_home_t autohome[SU_HOME_AUTO_SIZE(1024)];

  vias = sip_via_copy(su_home_auto(autohome, sizeof autohome), via);

  for (; *list; list = &(*list)->oc_next)
    ;

  next = list;

  for (vv = &vias; (v = *vv);) {
    char const *protocol;
    *vv = v->v_next, v->v_next = NULL, pair = NULL;

    if (v->v_protocol == sip_transport_tcp)
      protocol = sip_transport_udp;
    else if (v->v_protocol == sip_transport_udp)
      protocol = sip_transport_tcp;
    else
      protocol = NULL;

    if (protocol) {
      /* Try to pair vias if we have both udp and tcp */
      for (prev = vv; *prev; prev = &(*prev)->v_next) {
	if (strcasecmp(protocol, (*prev)->v_protocol))
	  continue;
	if (strcasecmp(v->v_host, (*prev)->v_host))
	  continue;
	if (str0cmp(v->v_port, (*prev)->v_port))
	  continue;
	break;
      }

      if (*prev) {
	pair = *prev; *prev = pair->v_next; pair->v_next = NULL;
      }
    }

    oc = su_zalloc(ohome, sizeof *oc);
    if (!oc)
      break;

    oc->oc_owner = owner;
    oc->oc_default = 1, oc->oc_public = public;

    if (outbound_connect_contacts_from_via(oc, v, pair) < 0) {
      su_free(ohome, oc);
      break;
    }

    oc->oc_secure = oc->oc_rcontact->m_url->url_type == url_sips;

    oc->oc_next = *next, oc->oc_prev = next; *next = oc, next = &oc->oc_next;
  }

  su_home_deinit(autohome);

  return 0;
}

outbound_connect *outbound_connect_by_aor(outbound_connect const *usages,
				      url_t const *aor,
				      int only_default)
{
  int secure = aor && aor->url_type == url_sips;
  outbound_connect const *oc, *public = NULL;

  for (oc = usages; oc; oc = oc->oc_next) {
    if (only_default && !oc->oc_default)
      continue;

    if (!oc->oc_via)
      continue;

    if (public == NULL && oc->oc_public)
      public = oc;

    if (secure) {
      if (oc->oc_secure)
	return (outbound_connect *)oc;
    }
    else {
      if (!oc->oc_secure)
	return (outbound_connect *)oc;
    }
  }

  return (outbound_connect *)public;
}

sip_contact_t const *outbound_connect_contact(outbound_connect const *oc)
{
  if (oc == NULL)
    return NULL;
  if (oc->oc_gruu)
    return oc->oc_gruu;
  else
    return oc->oc_dcontact;
}

/* ---------------------------------------------------------------------- */

static char const *nua_outbound_connect_name(nua_dialog_usage_t const *du);

static int nua_outbound_connect_add(nua_handle_t *nh,
				  nua_dialog_state_t *ds,
				  nua_dialog_usage_t *du);
static void nua_outbound_connect_remove(nua_handle_t *nh,
				      nua_dialog_state_t *ds,
				      nua_dialog_usage_t *du);
static void nua_outbound_peer_info(nua_dialog_usage_t *du,
				   nua_dialog_state_t const *ds,
				   sip_t const *sip);
static int feature_level(sip_t const *sip, char const *tag, int level);

/* ---------------------------------------------------------------------- */

nua_usage_class const _nua_outbound_connect[1] = {
  {
    sizeof (struct outbound_connect),
    (sizeof _nua_outbound_connect),
    nua_outbound_connect_add,
    nua_outbound_connect_remove,
    nua_outbound_connect_name,
    nua_outbound_peer_info,
  }};

nua_usage_class const *nua_outbound_connect = _nua_outbound_connect;

char const * const outbound_connect_content_type =
  "application/vnd.nokia-register-usage";

/* ---------------------------------------------------------------------- */

static
char const *nua_outbound_connect_name(nua_dialog_usage_t const *du)
{
  return "register";
}

static
int nua_outbound_connect_add(nua_handle_t *nh,
			   nua_dialog_state_t *ds,
			   nua_dialog_usage_t *du)
{
  struct outbound_connect *oc = nua_dialog_usage_private(du);

  oc->oc_owner = nh;

  if (ds->ds_has_register)
    return -1;			/* There can be only one usage */
  ds->ds_has_register = 1;
  oc->oc_reg_id = 1;

  return 0;
}

static
void nua_outbound_connect_remove(nua_handle_t *nh,
			       nua_dialog_state_t *ds,
			       nua_dialog_usage_t *du)
{
  struct outbound_connect *oc = nua_dialog_usage_private(du);

  if (oc->oc_prev) {  /* Remove from list of registrations */
    *oc->oc_prev = oc->oc_next;
    oc->oc_next->oc_prev = oc->oc_prev;
    oc->oc_prev = NULL;
  }

#if HAVE_SIGCOMP
  if (oc->oc_compartment)
    sigcomp_compartment_unref(oc->oc_compartment);
  oc->oc_compartment = NULL;
#endif

  /* XXX - free headers, too */

  if (oc->oc_kalt)
    su_timer_destroy(oc->oc_kalt), oc->oc_kalt = NULL;

  if (oc->oc_kalo)
    nta_outgoing_destroy(oc->oc_kalo), oc->oc_kalo = NULL;

  if (oc->oc_kalmsg)
    msg_destroy(oc->oc_kalmsg), oc->oc_kalmsg = NULL;

  ds->ds_has_register = 0;	/* There can be only one */
}

/** @internal Store information about registrar. */
static void nua_outbound_peer_info(nua_dialog_usage_t *du,
				   nua_dialog_state_t const *ds,
				   sip_t const *sip)
{
  struct outbound_connect *oc = nua_dialog_usage_private(du);

  if (sip == NULL) {
    oc->oc_info.outbound = 1;
    oc->oc_info.gruu = 1;
    oc->oc_info.pref = 1;
    return;
  }

  oc->oc_info.outbound = feature_level(sip, "outbound", oc->oc_info.outbound);
  oc->oc_info.gruu = feature_level(sip, "gruu", oc->oc_info.gruu);
  oc->oc_info.pref = feature_level(sip, "pref", oc->oc_info.pref);

}

static int feature_level(sip_t const *sip, char const *tag, int level)
{
  if (sip_has_feature(sip->sip_require, tag))
    return 3;
  else if (sip_has_feature(sip->sip_supported, tag))
    return 2;
  else if (sip_has_feature(sip->sip_unsupported, tag))
    return 0;
  else
    return level;
}

int outbound_connect_init(outbound_connect *oc,
			  outbound_owner_vtable const *owner_methods,
			  su_root_t *root,
			  nta_agent_t *agent,
			  char const *options)
{
  oc->oc_oo = owner_methods;
  oc->oc_root = root;
  oc->oc_nta = agent;

  return outbound_connect_set_options(oc, options);
}


int outbound_connect_set_options(outbound_connect *oc, char const *options)
{
  struct outbound_prefs prefs[1] = {{ 0 }};
  char *s;

  prefs->gruuize = 1;
  prefs->outbound = 1;
  prefs->natify = 1;
  prefs->validate = 1;

#define MATCH(v) (len == sizeof(#v) - 1 && strncasecmp(#v, s, len) == 0)

  for (s = (char *)options; s && s[0]; ) {
    int len = span_token(s);
    int value = 1;

    if (len > 3 && strncasecmp(s, "no-", 3) == 0)
      value = 0, s += 3, len -= 3;
    else if (len > 3 && strncasecmp(s, "no_", 3) == 0)
      value = 0, s += 3, len -= 3;

    if (len == 0)
      break;
    else if (MATCH(gruuize)) prefs->gruuize = value;
    else if (MATCH(outbound)) prefs->outbound = value;
    else if (MATCH(natify)) prefs->natify = value;
    else if (MATCH(validate)) prefs->validate = value;
    else if (MATCH(use-connect) || MATCH(use_connect)) prefs->use_connect = value;
    else if (MATCH(use-rport) || MATCH(use_rport)) prefs->use_rport = value;
    else if (MATCH(use-socks) || MATCH(use_socks)) prefs->use_socks = value;
    else if (MATCH(use-upnp) || MATCH(use_upnp)) prefs->use_upnp = value;
    else if (MATCH(use-stun) || MATCH(use_stun)) prefs->use_stun = value;
    else 
      SU_DEBUG_1(("outbound_connect: unknown option \"%.*s\"\n", len, s));

    s += len;
    len = strspn(s, " \t\n\r,;");
    if (len == 0)
      break;
    s += len;
  }

  if (s && s[0]) {
    SU_DEBUG_1(("outbound_connect: invalid options \"%s\"\n", options));
    return -1;
  }

  if (prefs->natify && 
      !(prefs->outbound ||
	prefs->use_connect || 
	prefs->use_rport || 
	prefs->use_socks || 
	prefs->use_upnp || 
	prefs->use_stun)) {
    SU_DEBUG_1(("outbound_connect: no nat traversal method given\n"));
  }
       

  oc->oc_prefs = *prefs;

  return 0;
}

int outbound_connect_set_features(outbound_connect *oc, char *features)
{
  su_home_t *home = (su_home_t *)oc->oc_owner;
  char *old = (char *)oc->oc_features;

  oc->oc_features = features;

  if (!oc->oc_cookie[0]) {
    SHA1Context sha1[1];
    uint8_t digest[SHA1HashSize];
    su_guid_t guid[1];

    SHA1Reset(sha1);
    su_guid_generate(guid);
    SHA1Input(sha1, (void *)features, strlen(features));
    SHA1Input(sha1, (void *)guid, sizeof guid);
    SHA1Result(sha1, digest);
    token64_e(oc->oc_cookie, sizeof oc->oc_cookie, digest, sizeof digest);
  }

  su_free(home, old);

  return 0;
}

