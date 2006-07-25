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
#include <sofia-sip/su_uniqueid.h>
#include <sofia-sip/su_tagarg.h>

#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_status.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s
#define NTA_UPDATE_MAGIC_T   struct nua_s

#include "nua_stack.h"

#include <sofia-sip/hostdomain.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/tport_tag.h>

#define OUTBOUND_OWNER_T struct nua_handle_s

#include "outbound.h"

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

/* ======================================================================== */
/* Registrations and contacts */

int nua_registration_from_via(nua_registration_t **list,
			      su_home_t *home,
			      sip_via_t const *via,
			      int public);

int nua_registration_add(nua_registration_t **list, nua_registration_t *nr);

void nua_registration_remove(nua_registration_t *nr);

int nua_registration_set_aor(su_home_t *, nua_registration_t *nr,
			     sip_from_t const *aor);

int nua_registration_set_contact(su_home_t *,
				 nua_registration_t *nr,
				 sip_contact_t const *m,
				 int terminating);

void nua_registration_set_ready(nua_registration_t *nr, int ready);

/* ====================================================================== */
/* REGISTER usage */

static char const *nua_register_usage_name(nua_dialog_usage_t const *du);

static int nua_register_usage_add(nua_handle_t *nh,
				  nua_dialog_state_t *ds,
				  nua_dialog_usage_t *du);
static void nua_register_usage_remove(nua_handle_t *nh,
				      nua_dialog_state_t *ds,
				      nua_dialog_usage_t *du);
static void nua_register_usage_peer_info(nua_dialog_usage_t *du,
					 nua_dialog_state_t const *ds,
					 sip_t const *sip);

/** REGISTER usage, aka nua_registration_t */
struct register_usage {
  nua_registration_t *nr_next, **nr_prev, **nr_list; /* Doubly linked list and its head */
  sip_from_t *nr_aor;		/**< AoR for this registration, NULL if none */
  sip_contact_t *nr_contact;	/**< Our Contact */

  /** Status of registration */
  unsigned nr_ready:1;
  /** Kind of registration.
   *
   * If nr_default is true, this is not a real registration but placeholder
   * for Contact header derived from a transport address.
   *
   * If nr_secure is true, this registration supports SIPS/TLS.
   *
   * If nr_public is true, transport should have public address.
   */
  unsigned nr_default:1, nr_secure:1, nr_public:1;

  /** Stack-generated contact */
  unsigned nr_by_stack:1, :0;

  sip_route_t *nr_route;	/**< Outgoing Service-Route */
  sip_path_t *nr_path;		/**< Incoming Path */

  tport_t *nr_tport;		/**< Transport to be used when registered */
  nua_dialog_state_t *nr_dialogs; /**< List of our dialogs */

#if HAVE_SIGCOMP
  struct sigcomp_compartment *nr_compartment;
#endif

  outbound_t *nr_ob;	/**< Outbound connection */
};

nua_usage_class const nua_register_usage[1] = {
  {
    sizeof (struct register_usage),
    (sizeof nua_register_usage),
    nua_register_usage_add,
    nua_register_usage_remove,
    nua_register_usage_name,
    nua_register_usage_peer_info,
  }};

static char const *nua_register_usage_name(nua_dialog_usage_t const *du)
{
  return "register";
}

static int nua_register_usage_add(nua_handle_t *nh,
				  nua_dialog_state_t *ds,
				  nua_dialog_usage_t *du)
{
  nua_registration_t *nr = nua_dialog_usage_private(du);

  if (ds->ds_has_register)
    return -1;			/* There can be only one usage */

  ds->ds_has_register = 1;

  nr->nr_public = 1;		/* */

  return 0;
}


static void nua_register_usage_remove(nua_handle_t *nh,
				      nua_dialog_state_t *ds,
				      nua_dialog_usage_t *du)
{
  nua_registration_t *nr = nua_dialog_usage_private(du);

  if (nr->nr_list)
    nua_registration_remove(nr);	/* Remove from list of registrations */

  if (nr->nr_ob)
    outbound_unref(nr->nr_ob);

#if HAVE_SIGCOMP
  if (nr->nr_compartment)
    sigcomp_compartment_unref(nr->nr_compartment);
  nr->nr_compartment = NULL;
#endif

  ds->ds_has_register = 0;	/* There can be only one */
}


/** @internal Store information about registrar. */
static void nua_register_usage_peer_info(nua_dialog_usage_t *du,
					 nua_dialog_state_t const *ds,
					 sip_t const *sip)
{
  nua_registration_t *nr = nua_dialog_usage_private(du);
  if (nr->nr_ob)
    outbound_peer_info(nr->nr_ob, sip);
}

/* ======================================================================== */
/* REGISTER */

static void restart_register(nua_handle_t *nh, tagi_t *tags);
static void refresh_register(nua_handle_t *, nua_dialog_usage_t *, sip_time_t);

static int process_response_to_register(nua_handle_t *nh,
					nta_outgoing_t *orq,
					sip_t const *sip);

static void unregister_expires_contacts(msg_t *msg, sip_t *sip);

/* Interface towards outbound_t */
static int nua_stack_outbound_features(nua_handle_t *nh, outbound_t *ob);

static int nua_stack_outbound_refresh(nua_handle_t *,
				      outbound_t *ob);

static int nua_stack_outbound_status(nua_handle_t *,
				     outbound_t *ob,
				     int status, char const *phrase,
				     tag_type_t tag, tag_value_t value, ...);

static int nua_stack_outbound_failed(nua_handle_t *,
				     outbound_t *ob,
				     int status, char const *phrase,
				     tag_type_t tag, tag_value_t value, ...);

static int nua_stack_outbound_credentials(nua_handle_t *, auth_client_t **auc);

outbound_owner_vtable nua_stack_outbound_callbacks = {
    sizeof nua_stack_outbound_callbacks,
    nua_stack_outbound_refresh,
    nua_stack_outbound_status,
    nua_stack_outbound_failed,
    nua_stack_outbound_failed,
    nua_stack_outbound_credentials
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
 *     NUTAG_REGISTRAR(), NUTAG_INSTANCE(), NUTAG_OUTBOUND(),
 *     NUTAG_KEEPALIVE(), NUTAG_KEEPALIVE_STREAM(),
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
 * First, nua_register() will probe for NATs in between UA and registrar. It
 * will send a REGISTER request as usual. Upon receiving the response it
 * checks for the presence of valid "received" and "rport" parameters in the
 * Via header returned by registrar. The presence of NAT is determined from
 * the "received" parameter in a Via header. When a REGISTER request was
 * sent, the stack inserted the source IP address in the Via header: if that
 * is different from the source IP address seen by the registrar, the
 * registrar inserts the source IP address it sees into the "received"
 * parameter.
 *
 * Please note that an ALG (application-level gateway) modifying the Via
 * headers in outbound requests and again in incoming responses will make
 * the above-described NAT check to fail.
 *
 * The response to the initial REGISTER should also include feature tags
 * indicating whether registrar supports various SIP extensions: @e
 * outbound, @e pref, @e path, @e gruu.
 *
 * Basically, @e outbound means that instead of registering its contact URI
 * with a particular address-of-record URI, the user-agent registers a
 * transport-level connection. Such a connection is identified on the
 * Contact header field with an instance identifier, application-provided
 * @ref NUTAG_INSTANCE() "unique string" identifying the user-agent instance
 * and a stack-generated numeric index identifying the transport-level
 * connection.
 *
 * If the @e outbound extension is supported, NUTAG_OUTBOUND() contains
 * option string "outbound" and the application has provided an instance
 * identifer to the stack with NUTAG_INSTANCE(), the nua_register() will try
 * to use outbound.
 *
 * If @e outbound is not supported, nua_register() has to generate a URI
 * that can be used to reach it from outside. It will check for public
 * transport addresses detected by underlying stack with, e.g., STUN, UPnP
 * or SOCKS. If there are public addresses, nua_register() will use them. If
 * there is no public address, it will try to generate a Contact URI from
 * the "received" and "rport" parameters found in the Via header of the
 * response message.
 *
 * @todo Actually generate public addresses.
 *
 * You can disable this kind of NAT traversal by setting "no-natify" into
 * NUTAG_OUTBOUND() options string.
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
 * You can disable validation by inserting "no-validate" into
 * NUTAG_OUTBOUND() string.
 *
 * The keepalive mechanism depends on the network features detected earlier. 
 * If @a outbound extension is used, the STUN keepalives will be used. 
 * Otherwise, NUA stack will repeatedly send OPTIONS requests to itself. In
 * order to save bandwidth, it will include Max-Forwards: 0 in the
 * keep-alive requests, however. The keepalive interval is determined by
 * NUTAG_KEEPALIVE() parameter. If the interval is 0, no keepalive messages
 * is sent.
 *
 * You can disable keepalive OPTIONS by inserting "no-options-keepalive"
 * into NUTAG_OUTBOUND() string. Currently there are no other keepalive
 * mechanisms available.
 *
 * The value of NUTAG_KEEPALIVE_STREAM(), if specified, is used to indicate
 * the desired transport-layer keepalive interval for stream-based
 * transports like TLS and TCP.
 *
 * @sa NUTAG_OUTBOUND() and tags.
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
  nua_registration_t *nr = NULL;
  outbound_t *ob = NULL;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg = NULL;
  sip_t *sip;
  int terminating = e != nua_r_register;

  if (nh->nh_special && nh->nh_special != nua_r_register)
    return UA_EVENT2(e, 900, "Invalid handle for REGISTER");
  if (cr->cr_orq)
    return UA_EVENT2(e, 900, "Request already in progress");

  nua_stack_init_handle(nua, nh, nh_has_register, "", TAG_NEXT(tags));
  nh->nh_special = nua_r_register;

  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_register_usage, NULL);
  if (!du)
    return UA_EVENT1(e, NUA_INTERNAL_ERROR);
  nr = nua_dialog_usage_private(du); assert(nr);
  nua_registration_add(&nh->nh_nua->nua_registrations, nr);
  if (!terminating && du->du_terminating)
    return UA_EVENT2(e, 900, "Unregister in progress");

  if (cr->cr_msg)
    msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
  /* Use original message as template when unregistering */
  if (terminating)		
    cr->cr_msg = msg_ref_create(du->du_msg);

  msg = nua_creq_msg(nua, nh, cr, cr->cr_msg != NULL,
		     SIP_METHOD_REGISTER,
		     TAG_IF(!terminating, NUTAG_USE_DIALOG(1)),
		     TAG_NEXT(tags));
  sip = sip_object(msg);
  if (!msg || !sip)
    goto error;

  if (!nr->nr_aor) {
    if (nua_registration_set_aor(nh->nh_home, nr, sip->sip_to) < 0)
      goto error;
  }

  du->du_terminating = terminating;

  if (du->du_msg == NULL)
    du->du_msg = msg_ref_create(cr->cr_msg); /* Save original message */

  if (terminating)
    /* Add Expires: 0 and remove the expire parameters from contacts */
    unregister_expires_contacts(msg, sip);

  if (nua_registration_set_contact(nh->nh_home, nr, sip->sip_contact, terminating) < 0)
    goto error;
  
  ob = nr->nr_ob;
  
  if (!ob && (NH_PGET(nh, outbound) || NH_PGET(nh, instance))) {
    nr->nr_ob = ob = outbound_new(nh, &nua_stack_outbound_callbacks,
				  nh->nh_nua->nua_root,
				  nh->nh_nua->nua_nta,
				  NH_PGET(nh, instance));
    if (!ob)
      goto error;
  }

  if (ob) {
    outbound_set_options(ob,
			 NH_PGET(nh, outbound),
			 NH_PGET(nh, keepalive),
			 NH_PISSET(nh, keepalive_stream)
			 ? NH_PGET(nh, keepalive_stream)
			 : NH_PGET(nh, keepalive));
    nua_stack_outbound_features(nh, ob);
    outbound_stop_keepalive(ob);

    if (outbound_set_contact(ob, sip->sip_contact, nr->nr_contact, terminating) < 0)
      goto error;
  }

  /* This calls nta_outgoing_mcreate() but adds a few tags */
  cr->cr_orq =
    outbound_register_request(ob, terminating,
			      nr->nr_by_stack ? nr->nr_contact : NULL,
			      nua->nua_nta,
			      process_response_to_register, nh, NULL,
			      msg,
			      SIPTAG_END(), 
			      TAG_IF(terminating, NTATAG_SIGCOMP_CLOSE(1)),
			      TAG_IF(!terminating, NTATAG_COMP("sigcomp")),
			      TAG_NEXT(tags));

  if (!cr->cr_orq)
    goto error;

  cr->cr_usage = du;
  return cr->cr_event = e;

 error:
  msg_destroy(msg);
  msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
  nua_dialog_usage_remove(nh, nh->nh_ds, du);    
  return UA_EVENT1(e, NUA_INTERNAL_ERROR);
}

static void
restart_register(nua_handle_t *nh, tagi_t *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;
  nua_dialog_usage_t *du = cr->cr_usage;
  nua_registration_t *nr = nua_dialog_usage_private(du);
  int terminating = du && du->du_terminating;

  cr->cr_restart = NULL;

  if (!cr->cr_msg)
    return;

  msg = nua_creq_msg(nh->nh_nua, nh, cr, 1,
		     SIP_METHOD_UNKNOWN,
		     TAG_NEXT(tags));

  if (!msg)
    return;			/* XXX - Uh-oh */

  if (terminating)
    unregister_expires_contacts(msg, sip_object(msg));

  /* This calls nta_outgoing_mcreate() but adds a few tags */
  cr->cr_orq =
    outbound_register_request(nr->nr_ob, terminating,
			      nr->nr_by_stack ? nr->nr_contact : NULL,
			      nh->nh_nua->nua_nta,
			      process_response_to_register, nh, NULL,
			      msg,
			      SIPTAG_END(), 
			      TAG_IF(terminating, NTATAG_SIGCOMP_CLOSE(1)),
			      TAG_IF(!terminating, NTATAG_COMP("sigcomp")),
			      TAG_NEXT(tags));

  if (!cr->cr_orq)
    msg_destroy(msg);
}

void
refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
  nua_registration_t *nr = nua_dialog_usage_private(du);
  nua_event_t e;
  msg_t *msg;
  sip_t *sip;
  int terminating;

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

  terminating = du->du_terminating;

  outbound_stop_keepalive(nr->nr_ob);

  cr->cr_msg = msg_copy(du->du_msg);
  msg = nua_creq_msg(nua, nh, cr, 1,
		     SIP_METHOD_REGISTER,
		     NUTAG_USE_DIALOG(1),
		     TAG_END());
  sip = sip_object(msg);
  if (!msg || !sip)
    goto error;

  if (terminating)
    unregister_expires_contacts(msg, sip);

  cr->cr_orq =
    outbound_register_request(nr->nr_ob, terminating,
			      nr->nr_by_stack ? nr->nr_contact : NULL,
			      nh->nh_nua->nua_nta,
			      process_response_to_register, nh, NULL,
			      msg,
			      SIPTAG_END(), 
			      TAG_IF(terminating, NTATAG_SIGCOMP_CLOSE(1)),
			      TAG_IF(!terminating, NTATAG_COMP("sigcomp")),
			      TAG_END());
  if (!cr->cr_orq)
    goto error;

  cr->cr_usage = du;
  cr->cr_event = e;
  return;

 error:
  if (terminating)
    nua_dialog_usage_remove(nh, nh->nh_ds, du);
  msg_destroy(msg);
  msg_destroy(cr->cr_msg);
  UA_EVENT2(e, NUA_INTERNAL_ERROR, TAG_END());
  return;
}


static
int process_response_to_register(nua_handle_t *nh,
				 nta_outgoing_t *orq,
				 sip_t const *sip)
{
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  nua_registration_t *nr = nua_dialog_usage_private(du);
  int status, ready, reregister, terminating;
  char const *phrase;
  msg_t *_reqmsg = nta_outgoing_getrequest(orq);
  sip_t *req = sip_object(_reqmsg); msg_destroy(_reqmsg);

  assert(sip);
  assert(du && du->du_class == nua_register_usage);
  status = sip->sip_status->st_status;
  phrase = sip->sip_status->st_phrase;

  if (status < 200 || !du)
    return nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  terminating = du->du_terminating;
  if (!terminating)
    nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

  reregister = outbound_register_response(nr->nr_ob, terminating, req, sip);
  if (reregister < 0)
    SET_STATUS1(NUA_INTERNAL_ERROR);
  else if (reregister >= ob_reregister) {
    /* Save msg otherwise nua_creq_check_restart() will zap it */
    msg_t *msg = msg_ref_create(cr->cr_msg);

    if (nua_creq_check_restart(nh, cr, orq, sip, restart_register)) {
      msg_destroy(msg);
      return 0;
    }

    assert(cr->cr_msg == NULL);
    cr->cr_msg = msg;

    if (reregister >= ob_reregister_now) {
      /* We can try to reregister immediately */
      nua_creq_restart_with(nh, cr, orq, 100, "Updated Contact",
			    restart_register,
			    TAG_END());
    }
    else {
      /* Outbound will invoke refresh_register() later */
      nua_creq_save_restart(nh, cr, orq, 100, "Updated Contact",
			    restart_register);
    }
    return 0;
  }

  if (status >= 300)
    if (nua_creq_check_restart(nh, cr, orq, sip, restart_register))
      return 0;

  ready = !terminating && status < 300;
  du->du_ready = ready;

  if (status < 300) {
    sip_time_t mindelta = 0;

    if (!du->du_terminating) {
      sip_time_t now = sip_now(), delta, reqdelta;
      sip_contact_t const *m, *sent;

      /** Search for lowest delta of SIP contacts we tried to register */
      mindelta = SIP_TIME_MAX;

      reqdelta = req->sip_expires ? req->sip_expires->ex_delta : 0;

      for (m = sip->sip_contact; m; m = m->m_next) {
        if (m->m_url->url_type != url_sip && 
            m->m_url->url_type != url_sips)
          continue;
        for (sent = req->sip_contact; sent; sent = sent->m_next)
          if (url_cmp(m->m_url, sent->m_url) == 0) {
            sip_time_t mdelta = reqdelta;

            if (sent->m_expires)
              mdelta = strtoul(sent->m_expires, NULL, 10);
            if (mdelta == 0)
              mdelta = 3600;

            delta = sip_contact_expires(m, sip->sip_expires, sip->sip_date,
       				 mdelta, now);
            if (delta > 0 && delta < mindelta)
              mindelta = delta;
            if (url_cmp_all(m->m_url, sent->m_url) == 0)
              break;
          }
      }

      if (mindelta == SIP_TIME_MAX)
        mindelta = 3600;
    }

    nua_dialog_usage_set_refresh(du, mindelta);
    if (mindelta)
      du->du_pending = refresh_register;
  }

#if HAVE_SIGCOMP
  if (ready) {
    struct sigcomp_compartment *cc;
    cc = nta_outgoing_compartment(orq);
    sigcomp_compartment_unref(nr->nr_compartment);
    nr->nr_compartment = cc;
  }
#endif

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
  if (ready) {
    su_free(nh->nh_home, nr->nr_route);
    nr->nr_route = sip_route_dup(nh->nh_home, sip->sip_service_route);
  }
  else {
    su_free(nh->nh_home, nr->nr_route);
    nr->nr_route = NULL;
  }

  if (ready) {
    /* RFC 3327 */
    /* Store last URI in Path header */
    sip_path_t *path = sip->sip_path;

    while (path && path->r_next)
      path = path->r_next;

    if (!nr->nr_path || !path ||
        url_cmp_all(nr->nr_path->r_url, path->r_url)) {
      su_free(nh->nh_home, nr->nr_path);
      nr->nr_path = sip_path_dup(nh->nh_home, path);
    }
  }

  if (ready)
    if (sip->sip_to->a_url->url_type == url_sips)
      nr->nr_secure = 1;

  if (nr->nr_ob) {
    if (ready) {
      outbound_gruuize(nr->nr_ob, sip);
      outbound_start_keepalive(nr->nr_ob, orq);
    }
    else
      outbound_stop_keepalive(nr->nr_ob);
  }

  nua_registration_set_ready(nr, ready);

  return nua_stack_process_response(nh, cr, orq, sip, TAG_END());
}

/* ---------------------------------------------------------------------- */
/* nua_registration_t interface */

#if HAVE_SOFIA_STUN
#include <sofia-sip/stun.h>
#endif

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

  if (!contact1 && contact2)
    contact1 = contact2, contact2 = NULL;

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

  if (!contact1 /* && !contact2 */) {
    if (nta_agent_add_tport(nua->nua_nta, NULL,
			    TPTAG_IDENT("sip"),
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0 &&
        nta_agent_add_tport(nua->nua_nta, URL_STRING_MAKE("sip:*:*"),
			    TPTAG_IDENT("sip"),
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0)
      return -1;
#if HAVE_SOFIA_STUN
    if (stun_is_requested(TAG_NEXT(nua->nua_args)) &&
	nta_agent_add_tport(nua->nua_nta, URL_STRING_MAKE("sip:0.0.0.0:*"),
			    TPTAG_IDENT("stun"),
			    TPTAG_PUBLIC(tport_type_stun), /* use stun */
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0) {
      SU_DEBUG_0(("nua: error initializing STUN transport\n"));
    }
#endif
  }
  else {
    if (nta_agent_add_tport(nua->nua_nta, contact1,
			    TPTAG_IDENT(name1),
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0)
      return -1;

    if (contact2 &&
	nta_agent_add_tport(nua->nua_nta, contact2,
			    TPTAG_IDENT(name2),
			    TPTAG_CERTIFICATE(certificate_dir),
			    TAG_NEXT(nua->nua_args)) < 0) 
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
  nua_registration_t **list = &nua->nua_registrations;
  su_home_t *home = nua->nua_dhandle->nh_home;
  sip_via_t const *v;

  v = nta_agent_public_via(nua->nua_nta);
  if (v) {
    nua_registration_from_via(list, home, v, 1);
  }

  v = nta_agent_via(nua->nua_nta);
  if (v) {
    nua_registration_from_via(list, home, v, 0);
  }
  else {
    sip_via_t v[2];

    sip_via_init(v)->v_next = v + 1;
    v[0].v_protocol = sip_transport_udp;
    v[0].v_host = "addr.is.invalid.";
    sip_via_init(v + 1);
    v[1].v_protocol = sip_transport_tcp;
    v[1].v_host = "addr.is.invalid.";

    nua_registration_from_via(list, home, v, 0);
  }

  nta_agent_bind_tport_update(nua->nua_nta, nua, nua_stack_tport_update);

  return 0;
}

int nua_registration_from_via(nua_registration_t **list,
			      su_home_t *home,
			      sip_via_t const *via,
			      int public)
{
  sip_via_t *v, *pair, /* v2[2], */ *vias, **vv, **prev;
  nua_registration_t *nr = NULL, **next;
  su_home_t autohome[SU_HOME_AUTO_SIZE(1024)];
  int nr_items = 0;

  vias = sip_via_copy(su_home_auto(autohome, sizeof autohome), via);

  for (; *list; list = &(*list)->nr_next)
    ++nr_items;

  next = list;

  for (vv = &vias; (v = *vv);) {
    char const *protocol;
    sip_contact_t *contact;

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

    /* if more than one candidate, ignore local entries */
    if (v && (*vv || nr_items > 0) && 
	host_is_local(v->v_host)) {
      SU_DEBUG_9(("nua_register: ignoring contact candidate %s:%s.\n", 
		  v->v_host, v->v_port ? v->v_port : ""));
      continue;
    }
     
    nr = su_zalloc(home, sizeof *nr);
    if (!nr)
      break;

    /* v2[0] = *v; */

    if (pair)
      /* Don't use protocol if we have both udp and tcp */
      protocol = NULL /*, v2[0].v_next = &v2[1], v2[1] = *pair */;
    else
      protocol = via->v_protocol /*, v2[0].v_next = NULL */;

    contact = sip_contact_create_from_via_with_transport(home, v, NULL, protocol);
    /* v = sip_via_dup(home, v2); */

    if (!contact) {
      su_free(home, nr);
      break;
    }

    nr->nr_ready = 1, nr->nr_default = 1, nr->nr_public = public;
    nr->nr_secure = contact->m_url->url_type == url_sips;
    nr->nr_contact = contact;
    /* nr->nr_via = v; */

    SU_DEBUG_9(("nua_register: Adding contact URL '%s' to list.\n", contact->m_url->url_host));

    ++nr_items;
    nr->nr_next = *next, nr->nr_prev = next; *next = nr, next = &nr->nr_next;
    nr->nr_list = list;
  }

  su_home_deinit(autohome);

  return 0;
}

static
void nua_stack_tport_update(nua_t *nua, nta_agent_t *nta)
{
#if 0
  nua_registration_t *default_oc;
  nua_registration_t const *defaults = nua->nua_registrations;
  sip_via_t *via = nta_agent_via(nta);

  default_oc = outbound_by_aor(defaults, NULL, 1);

  if (default_oc) {
    assert(default_oc->nr_via);

    outbound_contacts_from_via(default_oc,
				       via,
				       via->v_next);

    /* refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now); */
  }
#endif
  return;
}

nua_registration_t *nua_registration_by_aor(nua_registration_t const *list,
					    sip_from_t const *aor,
					    url_t const *remote_uri,
					    int only_default)
{
  sip_from_t *alt_aor = NULL, _alt_aor[1];
  int sips_aor = aor && aor->a_url->url_type == url_sips;
  int sips_uri = remote_uri && remote_uri->url_type == url_sips;

  nua_registration_t const *nr, *public = NULL, *any = NULL;
  nua_registration_t const *namewise = NULL, *sipswise = NULL;

  if (only_default || aor == NULL) {
    /* Ignore AoR, select only by remote_uri */
    for (nr = list; nr; nr = nr->nr_next) {
      if (!nr->nr_ready)
	continue;
      if (only_default && !nr->nr_default)
	continue;
      if (sips_uri ? nr->nr_secure : !nr->nr_secure) 
	return (nua_registration_t *)nr;
      if (!public && nr->nr_public)
	public = nr;
      if (!any)
	any = nr;
    }
    if (public)
      return (nua_registration_t *)public;
    if (any)
      return (nua_registration_t *)any;
    return NULL;
  }

  if (!sips_aor && aor)
    alt_aor = memcpy(_alt_aor, aor, sizeof _alt_aor);

  for (nr = list; nr; nr = nr->nr_next) {
    if (!nr->nr_ready)
      continue;
    if (nr->nr_aor) {
      if (aor && url_cmp(nr->nr_aor->a_url, aor->a_url) == 0)
	return (nua_registration_t *)nr;
      if (!namewise && alt_aor && url_cmp(nr->nr_aor->a_url, aor->a_url) == 0)
	namewise = nr;
    }
    if (!sipswise && (sips_aor || sips_uri) ? nr->nr_secure : !nr->nr_secure) 
      sipswise = nr;
    if (!public && nr->nr_public)
      public = nr;
    if (!any)
      any = nr;
  }

  if (namewise)
    return (nua_registration_t *)namewise;
  if (sipswise)
    return (nua_registration_t *)sipswise;

  /* XXX - 
     should we do some policing whether sips_aor or sips_uri can be used
     with sip contact?
  */
  if (public)
    return (nua_registration_t *)public;
  if (any)
    return (nua_registration_t *)any;

  return NULL;
}


nua_registration_t *
nua_registration_for_msg(nua_registration_t const *list, sip_t const *sip)
{
  sip_from_t const *aor;
  url_t *uri;

  if (sip == NULL)
    return NULL;

  if (sip->sip_request) {
    aor = sip->sip_from;
    uri = sip->sip_request->rq_url;
  }
  else {
    /* This is much hairier! */
    aor = sip->sip_to;
    if (sip->sip_record_route)
      uri = sip->sip_record_route->r_url;
    else if (sip->sip_contact)
      uri = sip->sip_contact->m_url;
    else
      uri = sip->sip_from->a_url;
    assert(uri != ((sip_contact_t *)NULL)->m_url);
  }

  return nua_registration_by_aor(list, aor, uri, 0);
}

/** Return Contact usable in dialogs */
sip_contact_t const *nua_registration_contact(nua_registration_t const *nr)
{
  if (nr->nr_by_stack && nr->nr_ob) {
    sip_contact_t const *m = outbound_dialog_contact(nr->nr_ob);
    if (m)
      return m;
  }

  return nr->nr_contact;
}

/** Return initial route. */
sip_route_t const *nua_registration_route(nua_registration_t const *nr)
{
  return nr ? nr->nr_route : NULL;
}

sip_contact_t const *nua_stack_get_contact(nua_registration_t const *nr)
{
  nr = nua_registration_by_aor(nr, NULL, NULL, 1);
  return nr ? nr->nr_contact : NULL;
}

/** Add a Contact (and Route) header to request (or response) */
int nua_registration_add_contact(nua_handle_t *nh,
				 msg_t *msg,
				 sip_t *sip,
				 int add_contact,
				 int add_service_route)
{
  nua_registration_t *nr = NULL;

  if (!add_contact && !add_service_route)
    return 0;

  if (nh == NULL || msg == NULL)
    return -1;

  if (sip == NULL)
    sip = sip_object(msg);

  if (nr == NULL)
    nr = nua_registration_for_msg(nh->nh_nua->nua_registrations, sip);

  if (nr == NULL)
    return -1;

  if (add_contact) {
    sip_contact_t const *m = nua_registration_contact(nr);
    if (!m || msg_header_add_dup(msg, (msg_pub_t *)sip, (void const *)m) < 0)
      return -1;
  }

  if (add_service_route && !sip->sip_status) {
    sip_route_t const *sr = nua_registration_route(nr);
    if (msg_header_add_dup(msg, (msg_pub_t *)sip, (void const *)sr) < 0)
      return -1;
  }

  return 0;
}



/** Add a registration to list of contacts */
int nua_registration_add(nua_registration_t **list,
			 nua_registration_t *nr)
{
  assert(list && nr);

  if (nr->nr_list == NULL) {
    nua_registration_t *next = *list;
    if (next)
      next->nr_prev = &nr->nr_next;
    nr->nr_next = next, nr->nr_prev = list, nr->nr_list = list;
    *list = nr;
  }

  return 0;
}

/** Remove from list of registrations */
void nua_registration_remove(nua_registration_t *nr)
{
  if ((*nr->nr_prev = nr->nr_next))
    nr->nr_next->nr_prev = nr->nr_prev;
  nr->nr_next = NULL, nr->nr_prev = NULL, nr->nr_list = NULL;
}

/** Set address-of-record. */
int nua_registration_set_aor(su_home_t *home,
			     nua_registration_t *nr,
			     sip_from_t const *aor)
{
  sip_from_t *new_aor, *old_aor;

  if (!home || !nr || !aor)
    return -1;

  new_aor = sip_from_dup(home, aor);
  if (!new_aor)
    return -1;

  old_aor = nr->nr_aor;
  nr->nr_aor = new_aor;
  msg_header_free(home, (void *)old_aor);

  return 0;
}

/** Set contact. */
int nua_registration_set_contact(su_home_t *home,
				 nua_registration_t *nr,
				 sip_contact_t const *application_contact,
				 int terminating)
{
  sip_contact_t *m = NULL, *previous;
  url_t *uri;

  if (!home || !nr)
    return -1;

  uri = nr->nr_aor ? nr->nr_aor->a_url : NULL;
    
  previous = nr->nr_contact;

  if (application_contact) {
    m = sip_contact_dup(home, application_contact);
  }
  else if (terminating && nr->nr_contact) {
    return 0;
  }
  else {
    nua_registration_t *nr0;
    
    nr0 = nua_registration_by_aor(*nr->nr_list, NULL, uri, 1);

    if (nr0)
      m = sip_contact_dup(home, nr0->nr_contact);
  }

  if (!m)
    return -1;

  nr->nr_contact = m;
  nr->nr_by_stack = !application_contact;

  msg_header_free(home, (void *)previous);

  return 0;
}

/** Mark registration as ready */
void nua_registration_set_ready(nua_registration_t *nr, int ready)
{
  nr->nr_ready = ready;
}

/** @internal Hook for processing incoming request by registration.
 *
 * This is used for keepalive/validate OPTIONS.
 */
int nua_registration_process_request(nua_registration_t *list,
				     nta_incoming_t *irq,
				     sip_t const *sip)
{
  sip_call_id_t *i;
  nua_registration_t *nr;

  if (!outbound_targeted_request(sip))
    return 0;

  /* Process by outbound... */
  i = sip->sip_call_id;

  for (nr = list; nr; nr = nr->nr_next) {
    outbound_t *ob = nr->nr_ob;
    if (ob)
      if (outbound_process_request(ob, irq, sip))
	return 501;		/* Just in case  */
  }

  return 481;			/* Call/Transaction does not exist */
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

  if (msg == NULL || sip == NULL)
    return;

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


/** Outbound requests us to refres registration */
static int nua_stack_outbound_refresh(nua_handle_t *nh,
				      outbound_t *ob)
{
  nua_dialog_usage_t *du = nua_dialog_usage_get(nh->nh_ds, nua_register_usage, NULL);
  if (du)
    nua_dialog_usage_refresh(nh, du, 1);
  return 0;
}


/** @internal Callback from outbound_t */
static int nua_stack_outbound_status(nua_handle_t *nh, outbound_t *ob,
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

/** @internal Callback from outbound_t */
static int nua_stack_outbound_failed(nua_handle_t *nh, outbound_t *ob,
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

/** @internal Callback for obtaining credentials for keepalive */
static int nua_stack_outbound_credentials(nua_handle_t *nh, 
					  auth_client_t **auc)
{
  return auc_copy_credentials(auc, nh->nh_auth);
}

/** @internal Return a string describing our features. */
static char *nua_handle_features(nua_handle_t *nh)
{
  char *retval = NULL;
  su_strlst_t *l = su_strlst_create(NULL);
  su_home_t *home = su_strlst_home(l);

  if (!l)
    return NULL;

  if (NH_PGET(nh, callee_caps)) {
    sip_allow_t const *allow = NH_PGET(nh, allow);

    if (allow) {
      /* Skip ";" if this is first one */
      su_strlst_append(l, ";methods=\"" + (su_strlst_len(l) == 0));
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
        if (su_strlst_len(l))
          su_strlst_append(l, ";");
        su_strlst_append(l, *media++);
      }
    }
  }

  if (su_strlst_len(l))
    retval = su_strlst_join(l, nh->nh_home, "");

  su_strlst_destroy(l);

  return retval;
}

static int nua_stack_outbound_features(nua_handle_t *nh, outbound_t *ob)
{
  char *features;
  int retval;

  if (!nh)
    return -1;
  if (!ob)
    return 0;

  features = nua_handle_features(nh);
  retval = outbound_set_features(ob, features);
  su_free(nh->nh_home, features);

  return retval;
}
