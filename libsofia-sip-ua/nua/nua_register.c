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
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s

#include "nua_stack.h"
#include <sofia-sip/nta_tport.h>

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
/* Register usage */

typedef struct register_usage {
  struct register_usage *ru_next, **ru_prev; /* Doubly linked list */
  unsigned ru_default:1, ru_secure:1, ru_public:1;

  unsigned ru_by_application:1, ru_add_contact:1;
  unsigned :0;

  nua_handle_t *ru_owner;	/**< Backpointer */
  su_root_t *ru_root;		/**< Root for timers and stuff */
  nta_agent_t *ru_nta;		/**< SIP transactions */

#if HAVE_SIGCOMP
  struct sigcomp_compartment *ru_compartment;
#endif
  tport_t *ru_tport;		/**< Transport used when registered */
  char const *ru_features;	/**< Feature parameters for rcontact */
  sip_via_t *ru_via;		/**< Our Via (or Via pair) */
  sip_contact_t *ru_rcontact;	/**< Our contact */
  sip_contact_t *ru_dcontact;	/**< Contact for dialogs */
  sip_contact_t *ru_previous;	/**< Stale contact */
  sip_contact_t *ru_gruu;	/**< Contact added to requests */
  sip_route_t *ru_route;	/**< Outgoing Service-Route */
  sip_path_t *ru_path;		/**< Incoming Path */
  sip_contact_t *ru_obp;	/**< Contacts from outbound proxy */

  char *ru_nat_detected;	/**< Our public address */

  void *ru_stun;		/**< Stun context */
  void *ru_upnp;		/**< UPnP context  */

  char *ru_sipstun;		/**< Stun server usable for keep-alives */
  unsigned ru_keepalive;	/**< Interval. */
  su_timer_t *ru_kalt;		/**< Keep-alive timer */
  msg_t *ru_kalmsg;		/**< Keep-alive OPTIONS message */
  nta_outgoing_t *ru_kalo;	/**< Keep-alive OPTIONS transaction */
} register_usage;

static char const *nua_register_usage_name(nua_dialog_usage_t const *du);

static int nua_register_usage_add(nua_handle_t *nh,
				  nua_dialog_state_t *ds,
				  nua_dialog_usage_t *du);
static void nua_register_usage_remove(nua_handle_t *nh,
				      nua_dialog_state_t *ds,
				      nua_dialog_usage_t *du);

int register_usage_check_for_nat(struct register_usage *ru,
				 nta_outgoing_t *orq,
				 sip_t const *sip);

static
int register_usage_init(register_usage *ru,
			su_root_t *root,
			nta_agent_t *agent);

static
int register_usage_set_features(register_usage *ru, char *features);

static
int register_usage_contacts_from_via(register_usage *ru,
				     sip_via_t const *via,
				     sip_via_t const *pair);

static
int register_usage_set_contact(struct register_usage *ru,
			       sip_contact_t *m);

static
int register_usage_set_contact_by_aor(struct register_usage *ru,
				      url_t const *aor,
				      register_usage const *defaults);

static
register_usage *register_usage_by_aor(register_usage const *usages,
				      url_t const *aor,
				      int only_default);

static void register_usage_start_keepalive(struct register_usage *ru,
					   unsigned interval,
					   nta_outgoing_t *register_trans);
static void register_usage_stop_keepalive(struct register_usage *ru);

static nua_usage_class const nua_register_usage[1] = {
  {
    sizeof (struct register_usage), (sizeof nua_register_usage),
    nua_register_usage_add,
    nua_register_usage_remove,
    nua_register_usage_name,
  }};

static
char const *nua_register_usage_name(nua_dialog_usage_t const *du)
{
  return "register";
}

static
int nua_register_usage_add(nua_handle_t *nh,
			   nua_dialog_state_t *ds,
			   nua_dialog_usage_t *du)
{
  struct register_usage *ru = nua_dialog_usage_private(du);

  ru->ru_owner = nh;

  if (ds->ds_has_register)
    return -1;			/* There can be only one usage */
  ds->ds_has_register = 1;

  return 0;
}

static
void nua_register_usage_remove(nua_handle_t *nh,
			       nua_dialog_state_t *ds,
			       nua_dialog_usage_t *du)
{
  struct register_usage *ru = nua_dialog_usage_private(du);

  if (ru->ru_prev) {  /* Remove from list of registrations */
    *ru->ru_prev = ru->ru_next;
    ru->ru_next->ru_prev = ru->ru_prev;
    ru->ru_prev = NULL;
  }

#if HAVE_SIGCOMP
  if (ru->ru_compartment)
    sigcomp_compartment_unref(ru->ru_compartment);
  ru->ru_compartment = NULL;
#endif

  if (ru->ru_kalt)
    su_timer_destroy(ru->ru_kalt), ru->ru_kalt = NULL;

  if (ru->ru_kalo)
    nta_outgoing_destroy(ru->ru_kalo), ru->ru_kalo = NULL;

  if (ru->ru_kalmsg)
    msg_destroy(ru->ru_kalmsg), ru->ru_kalmsg = NULL;

  ds->ds_has_register = 0;	/* There can be only one */
}

static
int register_usage_init(register_usage *ru,
			su_root_t *root,
			nta_agent_t *agent)
{
  ru->ru_root = root;
  ru->ru_nta = agent;
  return 0;
}

static
int register_usage_set_features(register_usage *ru, char *features)
{
  su_home_t *home = (su_home_t *)ru->ru_owner;
  char *old = (char *)ru->ru_features;

  ru->ru_features = features;
  
  su_free(home, old);

  return 0;
}

/* ======================================================================== */
/* REGISTER */

static void
  refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t),
  restart_register(nua_handle_t *nh, tagi_t *tags);

static int process_response_to_register(nua_handle_t *nh,
					nta_outgoing_t *orq,
					sip_t const *sip);

static void unregister_expires_contacts(msg_t *msg, sip_t *sip);

static char *nua_stack_register_features(nua_handle_t *nh);

int
nua_stack_register(nua_t *nua, nua_handle_t *nh, nua_event_t e,
		   tagi_t const *tags)
{
  nua_dialog_usage_t *du;
  struct register_usage *ru = NULL;
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
  
  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_register_usage, NULL);
  if (!du)
    return UA_EVENT1(e, NUA_500_ERROR);
  ru = nua_dialog_usage_private(du); assert(ru);

  register_usage_init(ru, nh->nh_nua->nua_root, nh->nh_nua->nua_nta);
  register_usage_set_features(ru, nua_stack_register_features(nh));

  if (du->du_msg)
    cr->cr_msg = msg_ref_create(du->du_msg);

  msg = nua_creq_msg(nua, nh, cr, cr->cr_msg != NULL,
		     SIP_METHOD_REGISTER,
		     TAG_IF(!terminating, NUTAG_USE_DIALOG(1)),
		     TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    du->du_terminating = terminating;

    if (sip->sip_contact)
      register_usage_set_contact(ru, sip->sip_contact);

    if (!ru->ru_rcontact) {
      register_usage_set_contact_by_aor(ru, sip->sip_to->a_url,
					nh->nh_nua->nua_registrations);
      /* Try first time without contact if we are not natifying */
      ru->ru_add_contact = !NH_PGET(nh, natify);
    }

    if (terminating)
      /* Add Expires: 0 and remove expire parameter from contacts */
      unregister_expires_contacts(msg, sip);

    cr->cr_orq =
      nta_outgoing_mcreate(nua->nua_nta,
			   process_response_to_register, nh, NULL,
			   msg,
			   TAG_IF(ru->ru_add_contact,
				  SIPTAG_CONTACT(ru->ru_rcontact)),
			   TAG_IF(ru->ru_add_contact,
				  SIPTAG_CONTACT(ru->ru_previous)),
			   SIPTAG_END(),
			   TAG_IF(terminating, NTATAG_SIGCOMP_CLOSE(1)),
			   TAG_IF(!terminating, NTATAG_COMP("sigcomp")),
			   TAG_NEXT(tags));
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
  int unregistering = cr->cr_usage && cr->cr_usage->du_terminating;
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

  if (cr->cr_usage) {
    struct register_usage *ru = nua_dialog_usage_private(cr->cr_usage);
    if (ru->ru_add_contact) {
      contact = ru->ru_rcontact;
      if (ru->ru_previous && ru->ru_previous->m_expires)
	previous = ru->ru_previous;
    }
  }

  cr->cr_orq = nta_outgoing_mcreate(nh->nh_nua->nua_nta,
				    process_response_to_register, nh, NULL,
				    msg,
				    SIPTAG_CONTACT(contact),
				    SIPTAG_CONTACT(previous),
				    SIPTAG_END(), TAG_NEXT(tags));

  if (!cr->cr_orq)
    msg_destroy(msg);
}

static
int process_response_to_register(nua_handle_t *nh,
				 nta_outgoing_t *orq,
				 sip_t const *sip)
{
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  struct register_usage *ru = nua_dialog_usage_private(du);
  int status;
  char const *phrase;
  sip_t *req = sip_object(cr->cr_msg);

  assert(sip);
  assert(du && du->du_class == nua_register_usage);
  status = sip->sip_status->st_status;
  phrase = sip->sip_status->st_phrase;

  if (status < 200 || !du)
    return nua_stack_process_response(nh, cr, orq, sip, TAG_END());

  nua_dialog_store_peer_info(nh, nh->nh_ds, sip);

  if (NH_PGET(nh, natify)) {
    int reregister;

    reregister = register_usage_check_for_nat(ru, orq, sip);

    if (reregister < 0)
      SET_STATUS2(500, nua_500_error);
    else if (reregister > 0) {
      if (nua_creq_check_restart(nh, cr, orq, sip, restart_register))
	return 0;
      
      if (reregister > 1) {
	/* We ca try to reregister immediately */
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

    if (!du->du_terminating && req && req->sip_contact && sip->sip_contact) {
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
      sigcomp_compartment_unref(ru->ru_compartment);
      ru->ru_compartment = cc;
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
    su_free(nh->nh_home, ru->ru_route);
    ru->ru_route = sip_route_dup(nh->nh_home, sip->sip_service_route);
  }
  else {
    su_free(nh->nh_home, ru->ru_route);
    ru->ru_route = NULL;
  }

  /* RFC 3327 */
  /* We are mainly interested in the last part of the Path header */
  if (!du->du_terminating && status < 300) {
    sip_path_t *path = sip->sip_path;

    while (path->r_next)
      path = path->r_next;

    if (!ru->ru_path || !path ||
	url_cmp_all(ru->ru_path->r_url, path->r_url)) {
      su_free(nh->nh_home, ru->ru_path);
      ru->ru_path = sip_path_dup(nh->nh_home, path);
    }
  }


  if (!du->du_terminating && status < 300) {
    if (!ru->ru_prev) {
      /* Add to the list of registrations */
      if ((ru->ru_next = nh->nh_nua->nua_registrations))
	ru->ru_next->ru_prev = &ru->ru_next;
      ru->ru_prev = &nh->nh_nua->nua_registrations;
      nh->nh_nua->nua_registrations = ru;
    }
  }

  if (!du->du_terminating && status < 300 && ru->ru_nat_detected)
    register_usage_start_keepalive(ru, 15, orq);
  else
    register_usage_stop_keepalive(ru);

  return nua_stack_process_response(nh, cr, orq, sip, TAG_END());
}

void
refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  nua_t *nua = nh->nh_nua;
  nua_client_request_t *cr = nh->nh_cr;
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

  cr->cr_msg = msg_ref_create(du->du_msg);
  msg = nua_creq_msg(nua, nh, cr, 1,
		     SIP_METHOD_REGISTER,
		     NUTAG_USE_DIALOG(1),
		     TAG_END());
  sip = sip_object(msg);

  if (sip) {
    int unregistering = now == 0;

    if (unregistering)
      unregister_expires_contacts(msg, sip);

    cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				      process_response_to_register, nh, NULL,
				      msg,
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

/** Check if there is a NAT between us and registrar */
int register_usage_check_for_nat(struct register_usage *ru,
				 nta_outgoing_t *orq,
				 sip_t const *sip)
{
  su_home_t *home = (su_home_t *)ru->ru_owner;
  sip_via_t *v = sip->sip_via;
  int one = 1;
  int use_rport = v->v_rport && !v->v_maddr;
  char const *received = v->v_received;
  char const *rport = sip_via_port(v, &one);
  sip_contact_t *m = ru->ru_rcontact;
  int binding_changed;

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
      if (!ru->ru_rcontact)
	...
      if (!ru->ru_rcontact)
	return -1;
      return 0;
    }
  }
#endif
  
  if (received)
    register_usage_nat_detect(ru, received);

  /* Contact was set by application, do not change it */
  if (ru->ru_by_application)
    return 0;

  if (!ru->ru_nat_detected) {
    if (ru->ru_add_contact)
      return 0;
    ru->ru_add_contact = 1;
    return 2;
  }

  /* We have detected NAT. Now, what to do?
   * 1) do nothing - register as usual and let proxy take care of it?
   * 2) try to detect our public nat binding and use it
   * 2A) use public vias from nta generated by STUN or UPnP
   * 2B) use SIP Via header
   */

  /* If our Contact and Via do not agree, we have to ask for reregistration */
  if (!m ||
      /* NAT binding changed?! */
      (received && str0casecmp(received, m->m_url->url_host)) ||
      (received && use_rport && str0cmp(rport, url_port(m->m_url)))) {
    if (ru->ru_stun) {
      /* Use STUN? */
      return 1;
    }
    else if (ru->ru_upnp) {
      /* Use UPnP */
      return 1;
    }
    else {
      if (register_usage_contacts_from_via(ru, sip->sip_via, NULL) < 0)
	return -1;
      ru->ru_add_contact = 1;
    }

    return 1;
  }

  register_usage_start_keepalive(ru, 15, orq);

  return 0;
}

static
int register_usage_nat_detect(register_usage *ru, 
			      char const *received,
			      char const *rport)
{
  if (received) {
    if (str0casecmp(received, ru->ru_nat_detected)) {
      char *nat_detected = ru->ru_nat_detected;

      if (!nat_detected)
	SU_DEBUG_1(("register_usage: detected NAT: %s != %s\n",
		    v->v_host, received));
      else
	SU_DEBUG_1(("register_usage: NAT binding changed: %s != %s\n",
		    nat_detected, received));

      ru->ru_nat_detected = su_strdup(home, received);
      if (ru->ru_nat_detected)
	su_free(home, nat_detected);
      else
	ru->ru_nat_detected = nat_detected;
    }

    return 1;
  }
  return 0;
}

/* ---------------------------------------------------------------------- */

static int create_keepalive_message(struct register_usage *ru,
				    sip_t const *register_request);

static int keepalive_options(register_usage *ru);

static int response_to_keepalive_options(nua_owner_t *ru_casted_as_owner,
					 nta_outgoing_t *orq,
					 sip_t const *sip);

static void keepalive_timer(su_root_magic_t *root_magic,
			    su_timer_t *t,
			    su_timer_arg_t *ru_as_timer_arg);

static 
void register_usage_start_keepalive(struct register_usage *ru, 
				    unsigned interval,
				    nta_outgoing_t *register_transaction)
{
  if (ru->ru_kalt)
    su_timer_destroy(ru->ru_kalt), ru->ru_kalt = NULL;

  if (interval)
    ru->ru_kalt = su_timer_create(su_root_task(ru->ru_root), 
				  /* 1000 * */ interval);

  if (!interval)
    ;
  else if (ru->ru_sipstun && 0) {
    /* XXX */
  }
  else {
    if (register_transaction) {
      msg_t *msg = nta_outgoing_getrequest(register_transaction);
      sip_t const *register_request = sip_object(msg);
      create_keepalive_message(ru, register_request);
      msg_destroy(msg);
    }

    keepalive_options(ru);
  }

  ru->ru_keepalive = interval;
}

static 
void register_usage_stop_keepalive(struct register_usage *ru)
{
  (void)ru;
}

static int create_keepalive_message(struct register_usage *ru,
				    sip_t const *regsip)
{
  msg_t *msg = nta_msg_create(ru->ru_nta, MSG_FLG_COMPACT), *previous;
  sip_t *osip = sip_object(msg);

  assert(regsip); assert(regsip->sip_request);

  if (/* Duplicate essential headers: From/To, route */
      sip_add_tl(msg, osip,
		 SIPTAG_TO(regsip->sip_to),
		 SIPTAG_FROM(regsip->sip_from),
		 SIPTAG_ROUTE(regsip->sip_route),
		 SIPTAG_MAX_FORWARDS_STR("0"),
		 TAG_END()) < 0 ||
      /* Create request-line, Call-ID, CSeq */
      nta_msg_request_complete(msg,
			       nta_default_leg(ru->ru_nta),
			       SIP_METHOD_OPTIONS, 
			       (void *)regsip->sip_request->rq_url) < 0 ||
      msg_serialize(msg, (void *)osip) < 0 ||
      msg_prepare(msg) < 0)
    return msg_destroy(msg), -1;

  previous = ru->ru_kalmsg;
  ru->ru_kalmsg = msg;
  msg_destroy(previous);

  return 0;
}

static int keepalive_options(register_usage *ru)
{
  msg_t *req;

  if (ru->ru_kalo)
    return 0;

  req = msg_copy(ru->ru_kalmsg);
  if (!req)
    return -1;

  if (nta_msg_request_complete(req, nta_default_leg(ru->ru_nta), 
			       SIP_METHOD_UNKNOWN, NULL) < 0)
    return msg_destroy(req), -1;

  ru->ru_kalo = nta_outgoing_mcreate(ru->ru_nta, 
				     response_to_keepalive_options, 
				     (nua_owner_t *)ru,
				     NULL,
				     req,
				     TAG_END());

  if (!ru->ru_kalo)
    return msg_destroy(req), -1;
  
  return 0;
}

static int response_to_keepalive_options(nua_owner_t *ru_casted_as_owner,
					nta_outgoing_t *orq,
					sip_t const *sip)
{
  register_usage *ru = (register_usage *)ru_casted_as_owner;

  su_timer_set(ru->ru_kalt, keepalive_timer, ru);

  return 0;
}

static void keepalive_timer(su_root_magic_t *root_magic,
			    su_timer_t *t,
			    su_timer_arg_t *ru_casted_as_timer_arg)
{
  register_usage *ru = (register_usage *)ru_casted_as_timer_arg;

  (void)root_magic;
  
  if (keepalive_options(ru) < 0)
    su_timer_set(t, keepalive_timer, ru_casted_as_timer_arg);	/* XXX */
}

/* ---------------------------------------------------------------------- */

/** Create contacts for register usage.
 *
 * Each registration has two contacts: one suitable for registrations and
 * another that can be used in dialogs.
 */
static
int register_usage_contacts_from_via(register_usage *ru,
				     sip_via_t const *via,
				     sip_via_t const *pair)
{
  su_home_t *home = (su_home_t *)ru->ru_owner;
  char *uri;
  sip_contact_t *rcontact, *dcontact;
  sip_contact_t *previous_rcontact, *previous_dcontact;
  char const *transport;
  sip_via_t *v, v0[1], *previous_via;

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
  if (ru->ru_features)
    rcontact = sip_contact_format(home, "%s%s", uri, ru->ru_features);
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

  previous_rcontact = ru->ru_previous;
  previous_dcontact = ru->ru_dcontact;
  previous_via = ru->ru_via;

  ru->ru_previous = ru->ru_rcontact;
  ru->ru_rcontact = rcontact;
  ru->ru_dcontact = dcontact;
  ru->ru_via = v;

  if (ru->ru_previous)
    msg_header_replace_param(home, (void*)ru->ru_previous, "expires=0");

  msg_header_free(home, (void *)previous_rcontact);
  if (previous_dcontact != ru->ru_previous)
    msg_header_free(home, (void *)previous_dcontact);
  msg_header_free(home, (void *)previous_via);

  return 0;
}

/** Set contact by application */
static
int register_usage_set_contact(struct register_usage *ru,
			       sip_contact_t *m)
{
  su_home_t *home = (su_home_t *)ru->ru_owner;
  sip_contact_t *m1, *m2, *m3;

  m = sip_contact_dup(home, m);
  if (!m)
    return -1;

  ru->ru_by_application = 1;

  m1 = ru->ru_rcontact;
  m2 = ru->ru_dcontact;
  m3 = ru->ru_previous;

  ru->ru_rcontact = m, ru->ru_dcontact = m, ru->ru_previous = NULL;

  msg_header_free(home, (void *)m1);
  if (m1 != m2)
    msg_header_free(home, (void *)m2);
  msg_header_free(home, (void *)m3);

  return 0;
}

/** Set contact to by using aor */
static
int register_usage_set_contact_by_aor(struct register_usage *ru,
				      url_t const *aor,
				      register_usage const *defaults)
{
  register_usage *default_ru;

  default_ru = register_usage_by_aor(defaults, aor, 1);

  if (default_ru) {
    assert(default_ru->ru_via);

    register_usage_contacts_from_via(ru,
				     default_ru->ru_via, 
				     default_ru->ru_via->v_next);

  }

  return 0;
}


int register_usages_from_via(struct register_usage **list,
			     nua_owner_t *owner,
			     sip_via_t const *via,
			     int public)
{
  su_home_t *ohome = (su_home_t *)owner;
  sip_via_t *v, *pair, *vias, **vv, **prev;
  nua_registration_t *ru = NULL, **next;
  su_home_t autohome[SU_HOME_AUTO_SIZE(1024)];
  
  vias = sip_via_copy(su_home_auto(autohome, sizeof autohome), via);

  for (; *list; list = &(*list)->ru_next)
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

    ru = su_zalloc(ohome, sizeof *ru);
    if (!ru)
      break;

    ru->ru_owner = owner;
    ru->ru_default = 1, ru->ru_public = public;

    if (register_usage_contacts_from_via(ru, v, pair) < 0) {
      su_free(ohome, ru);
      break;
    }

    ru->ru_secure = ru->ru_rcontact->m_url->url_type == url_sips;

    ru->ru_next = *next, ru->ru_prev = next; *next = ru, next = &ru->ru_next;
  }

  su_home_deinit(autohome);

  return 0;
}

static
register_usage *register_usage_by_aor(register_usage const *usages,
				      url_t const *aor,
				      int only_default)
{
  int secure = aor && aor->url_type == url_sips;
  register_usage const *ru, *public = NULL;

  for (ru = usages; ru; ru = ru->ru_next) {
    if (only_default && !ru->ru_default)
      continue;

    if (!ru->ru_via)
      continue;

    if (public == NULL && ru->ru_public)
      public = ru;

    if (secure) {
      if (ru->ru_secure)
	return (register_usage *)ru;
    }
    else {
      if (!ru->ru_secure)
	return (register_usage *)ru;
    }
  }

  return (register_usage *)public;
}

sip_contact_t const *register_usage_contact(register_usage const *ru)
{
  if (ru == NULL)
    return NULL;
  if (ru->ru_gruu)
    return ru->ru_gruu;
  else
    return ru->ru_dcontact;
}

/* ---------------------------------------------------------------------- */
/* Interface towards rest of nua stack */

int
nua_stack_registrations_init(nua_t *nua)
{
  /* Create initial identities: peer-to-peer, public, sips */
  sip_via_t const *v;
  nua_handle_t *dnh = nua->nua_dhandle;

  v = nta_agent_public_via(nua->nua_nta);
  if (v) {
    register_usages_from_via(&nua->nua_registrations, dnh, v, 1);
  }

  v = nta_agent_via(nua->nua_nta);
  if (v) {
    register_usages_from_via(&nua->nua_registrations, dnh, v, 0);
  }
  else {
    sip_via_t v[2];

    sip_via_init(v)->v_next = v + 1;
    v[0].v_protocol = sip_transport_udp;
    v[0].v_host = "addr.is.invalid.";
    sip_via_init(v + 1);
    v[1].v_protocol = sip_transport_tcp;
    v[1].v_host = "addr.is.invalid.";

    register_usages_from_via(&nua->nua_registrations, dnh, v, 0);
  }

  return 0;
}

sip_contact_t const *nua_contact_by_aor(nua_t *nua,
					url_t const *aor,
					int only_default)
{
  register_usage *ru = nua->nua_registrations;

  ru = register_usage_by_aor(ru, aor, only_default);

  return register_usage_contact(ru);
}

/** Return a string descibing our features. */
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

/** Remove (possible non-zero) "expires" parameters from contacts and extra
 *  contacts, add Expire: 0.
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
