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

struct register_usage {
  struct register_usage *ru_next, **ru_prev; /* Doubly linked list */
  unsigned ru_default:1, ru_secure:1, ru_public:1;

  unsigned ru_by_application:1, ru_add_contact:1;
  unsigned ru_keepalive:1;
  unsigned :0;
#if HAVE_SIGCOMP
  struct sigcomp_compartment *ru_compartment;
#endif
  tport_t *ru_tport;		/**< Transport used when registered */
  sip_via_t *ru_via;		/**< Our Via (or Via pair) */
  sip_contact_t *ru_contact;	/**< Our contact */
  sip_contact_t *ru_previous;	/**< Stale contact */
  sip_contact_t *ru_gruu;	/**< Contact added to requests */
  sip_route_t *ru_route;	/**< Service-Route */
  char *ru_nat_detected;	/**< Our public address */
};

static char const *nua_register_usage_name(nua_dialog_usage_t const *du);

static int nua_register_usage_add(nua_handle_t *nh,
				  nua_dialog_state_t *ds,
				  nua_dialog_usage_t *du);
static void nua_register_usage_remove(nua_handle_t *nh,
				      nua_dialog_state_t *ds,
				      nua_dialog_usage_t *du);

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
  if (ds->ds_has_register)
    return -1;			/* There can be only one */
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

  ds->ds_has_register = 0;	/* There can be only one */
}

/* ======================================================================== */
/* REGISTER */

static void
  refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t),
  restart_register(nua_handle_t *nh, tagi_t *tags);

static int process_response_to_register(nua_handle_t *nh,
					nta_outgoing_t *orq,
					sip_t const *sip);

static int register_add_contact(nua_handle_t *nh,
				url_t const *aor,
				struct register_usage *ru,
				sip_contact_t *m);

static void unregister_expires_contacts(msg_t *msg, sip_t *sip);

static
sip_contact_t *nua_contact_make_from_via(nua_handle_t *nh,
					 sip_via_t const *via,
					 sip_via_t const *pair);

static void start_keepalive(nua_handle_t *nh, struct register_usage *ru);
static void stop_keepalive(nua_handle_t *nh, struct register_usage *ru);

static
int nua_stack_register_natify(nua_handle_t *nh,
			      struct register_usage *ru,
			      sip_t const *sip);

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
  ru = nua_dialog_usage_private(du);

  if (du->du_msg)
    cr->cr_msg = msg_ref_create(du->du_msg);

  msg = nua_creq_msg(nua, nh, cr, cr->cr_msg != NULL,
		     SIP_METHOD_REGISTER,
		     TAG_IF(!terminating, NUTAG_USE_DIALOG(1)),
		     TAG_NEXT(tags));
  sip = sip_object(msg);

  if (sip) {
    du->du_terminating = terminating;

    if (sip->sip_contact) {
      register_add_contact(nh, sip->sip_to->a_url, ru, sip->sip_contact);
      ru->ru_by_application = 1;
    }

    if (!NH_PGET(nh, natify) && !ru->ru_contact) {
      register_add_contact(nh, sip->sip_to->a_url, ru, NULL);
      ru->ru_add_contact = 1;
    }

    if (terminating)
      /* Add Expires: 0 and remove expire parameter from contacts */
      unregister_expires_contacts(msg, sip);

    cr->cr_orq =
      nta_outgoing_mcreate(nua->nua_nta,
			   process_response_to_register, nh, NULL,
			   msg,
			   TAG_IF(ru->ru_add_contact,
				  SIPTAG_CONTACT(ru->ru_contact)),
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
      contact = ru->ru_contact;
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

  if (NH_PGET(nh, natify)) {
    int reregister = nua_stack_register_natify(nh, ru, sip);

    if (reregister < 0)
      SET_STATUS2(500, nua_500_error);
    else if (reregister > 0) {
      if (!nua_creq_check_restart(nh, cr, orq, sip, restart_register))
	nua_creq_restart_with(nh, cr, orq, 100, "Updated Contact",
			      restart_register,
			      TAG_END());
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
  } else {
    su_free(nh->nh_home, ru->ru_route);
    ru->ru_route = NULL;
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
    start_keepalive(nh, ru);
  else
    stop_keepalive(nh, ru);

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

/** Check if there is a NAT between us and registrar */
int
nua_stack_register_natify(nua_handle_t *nh,
			  struct register_usage *ru,
			  sip_t const *sip)
{
  sip_via_t *v = sip->sip_via;
  int one = 1;
  int use_rport = v->v_rport && !v->v_maddr;
  char const *received = v->v_received;
  char const *rport = sip_via_port(v, &one);
  sip_contact_t *m = ru->ru_contact;

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
      if (!ru->ru_contact)
	register_add_contact(nh, sip->sip_to->a_url, ru, NULL);
      if (!ru->ru_contact)
	return -1;
      return 0;
    }
  }
#endif

  if (received) {
    if (!ru->ru_nat_detected || strcasecmp(received, ru->ru_nat_detected)) {
      char *nat_detected = ru->ru_nat_detected;
      if (!nat_detected)
	SU_DEBUG_1(("nua_register: detected NAT: %s != %s\n",
		    v->v_host, received));
      else
	SU_DEBUG_1(("nua_register: NAT binding changed: %s != %s\n",
		    nat_detected, received));

      ru->ru_nat_detected = su_strdup(nh->nh_home, received);
      if (ru->ru_nat_detected)
	su_free(nh->nh_home, nat_detected);
      else
	ru->ru_nat_detected = nat_detected;
    }
  }

  /* Contact was set by application, do not change it */
  if (ru->ru_by_application)
    return 0;

  /* We had contact, did not detect nat */
  if (!ru->ru_nat_detected && m)
    return 0;

  if (!ru->ru_nat_detected) {
    register_add_contact(nh, sip->sip_to->a_url, ru, NULL);
    ru->ru_add_contact = 1;
    return 1;
  }

  /* If our Contact and Via do not agree, ask for reregistration */
  if (!m ||
      /* NAT binding changed?! */
      (received && str0casecmp(received, m->m_url->url_host)) ||
      (received && use_rport && str0cmp(rport, url_port(m->m_url)))) {
    sip_via_t via[1];

    *via = *v, via->v_next = NULL;

    m = nua_contact_make_from_via(nh, v, NULL);
    if (!m)
      return -1;

    if (ru->ru_previous)
      msg_header_free(nh->nh_home, (void *)ru->ru_previous);
    ru->ru_previous = ru->ru_contact;
    ru->ru_contact = m;
    ru->ru_add_contact = 1;
    ru->ru_via = sip_via_dup(nh->nh_home, via);

    if (ru->ru_previous)
      msg_header_replace_param(nh->nh_home, (void*)ru->ru_previous,
			       "expires=0");

    return 1;
  }

  return 0;
}

/* ---------------------------------------------------------------------- */

static void start_keepalive(nua_handle_t *nh, struct register_usage *ru)
{
  (void)nh, (void)ru;
}

static void stop_keepalive(nua_handle_t *nh, struct register_usage *ru)
{
  (void)nh, (void)ru;
}

/* ---------------------------------------------------------------------- */

static
nua_registration_t *nua_registration_from_via(nua_t *nua,
					      sip_via_t const *via,
					      int public);

int
nua_stack_registrations_init(nua_t *nua)
{
  /* Create initial identities: peer-to-peer, public, sips */
  sip_via_t const *v;

  v = nta_agent_public_via(nua->nua_nta);
  if (v) {
    nua_registration_from_via(nua, v, 1);
  }

  v = nta_agent_via(nua->nua_nta);
  if (v) {
    nua_registration_from_via(nua, v, 0);
  }
  else {
    sip_via_t v[2];

    sip_via_init(v)->v_next = v + 1;
    v[0].v_protocol = sip_transport_udp;
    v[0].v_host = "addr.is.invalid.";
    sip_via_init(v + 1);
    v[1].v_protocol = sip_transport_tcp;
    v[1].v_host = "addr.is.invalid.";

    nua_registration_from_via(nua, v, 0);
  }

  return 0;
}

nua_registration_t *nua_registration_from_via(nua_t *nua,
					      sip_via_t const *via,
					      int public)
{
  sip_via_t *v, *vias, **vv, **prev;
  nua_registration_t *ru = NULL, **next;
  sip_contact_t *m;

  vias = sip_via_dup(nua->nua_home, via);
  if (vias == NULL)
    return NULL;

  for (next = &nua->nua_registrations; *next; next = &(*next)->ru_next)
    ;

  for (vv = &vias; (v = *vv);) {
    char const *protocol;
    *vv = v->v_next, v->v_next = NULL;

    if (v->v_protocol == sip_transport_tcp)
      protocol = sip_transport_udp;
    else if (v->v_protocol == sip_transport_udp)
      protocol = sip_transport_tcp;
    else
      protocol = NULL;

    if (protocol) {
      for (prev = vv; *prev; prev = &(*prev)->v_next) {
	if (protocol != (*prev)->v_protocol)
	  continue;
	if (strcasecmp(v->v_host, (*prev)->v_host))
	  continue;
	if (str0cmp(v->v_port, (*prev)->v_port))
	  continue;
	break;
      }
      if (*prev) {
	v->v_next = *prev, *prev = (*prev)->v_next;
	v->v_next->v_next = NULL;
	protocol = NULL;
      }
    }

    /* Don't use protocol if we have both udp and tcp */
    protocol = v->v_next ? NULL : v->v_protocol;

    ru = su_zalloc(nua->nua_home, sizeof *ru);
    if (!ru)
      break;

    m = sip_contact_create_from_via_with_transport(nua->nua_home, v, NULL,
						   protocol);
    if (!m) {
      su_free(nua->nua_home, ru);
      break;
    }

    ru->ru_default = 1, ru->ru_public = public;
    ru->ru_secure = m->m_url->url_type == url_sips;
    ru->ru_contact = m;
    ru->ru_via = v;
    ru->ru_next = *next, ru->ru_prev = next; *next = ru, next = &ru->ru_next;
  }

  if (*vv)
    msg_header_free(nua->nua_home, (void *)*vv);

  return ru;
}

nua_registration_t *nua_registration_by_aor(nua_t *nua,
					    url_t const *aor,
					    int only_default)
{
  int secure = aor && aor->url_type == url_sips;
  nua_registration_t *ru, *public = NULL;

  for (ru = nua->nua_registrations; ru; ru = ru->ru_next) {
    if (only_default && !ru->ru_default)
      continue;

    if (!ru->ru_via)
      continue;

    if (public == NULL && ru->ru_public)
      public = ru;

    if (secure) {
      if (ru->ru_secure)
	return ru;
    }
    else {
      if (!ru->ru_secure)
	return ru;
    }
  }

  if (public)
    return public;

  return NULL;
}

sip_contact_t *nua_registration_contact(nua_registration_t *ru)
{
  if (ru == NULL)
    return NULL;
  if (ru->ru_gruu)
    return ru->ru_gruu;
  else
    return ru->ru_contact;
}

sip_contact_t const *nua_contact_by_aor(nua_t *nua,
					url_t const *aor,
					int only_default)
{
  nua_registration_t *ru = nua_registration_by_aor(nua, aor, only_default);

  return nua_registration_contact(ru);
}

/* ---------------------------------------------------------------------- */

/** Create a contact suitable for registration. */
static
sip_contact_t *nua_contact_make_from_via(nua_handle_t *nh,
					 sip_via_t const *via,
					 sip_via_t const *pair)
{
  su_strlst_t *l = su_strlst_create(NULL);
  su_home_t *home = su_strlst_home(l);
  char *uri;
  sip_contact_t *m;
  char const *transport;
  int i;

  if (!l)
    return NULL;

  if (pair)
    /* Don't use protocol if we have both udp and tcp */
    transport = NULL;
  else
    transport = via->v_protocol;

  uri = sip_contact_string_from_via(home, via, NULL, transport);
  su_strlst_append(l, uri);

  if (NH_PGET(nh, instance))
    su_slprintf(l, ";+sip.instance=\"<%s>\"", NH_PGET(nh, instance));

  if (NH_PGET(nh, callee_caps)) {
    sip_allow_t const *allow = NH_PGET(nh, allow);

    if (allow) {
      su_strlst_append(l, ";methods=\"");
      if (allow->k_items) {
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

  m = sip_contact_make(nh->nh_home, su_strlst_join(l, home, ""));

  su_strlst_destroy(l);

  return m;
}

static
int register_add_contact(nua_handle_t *nh,
			 url_t const *aor,
			 struct register_usage *ru,
			 sip_contact_t *m)
{
  if (m) {
    m = sip_contact_dup(nh->nh_home, m);
  }
  else {
    if (!ru->ru_via) {
      struct register_usage *ru0;
      ru0 = nua_registration_by_aor(nh->nh_nua, aor, 1);
      if (!ru0)
	return -1;
      ru->ru_via = sip_via_dup(nh->nh_home, ru0->ru_via);
    }

    m = nua_contact_make_from_via(nh, ru->ru_via, ru->ru_via->v_next);
  }

  if (!m)
    return -1;

  su_free(nh->nh_home, ru->ru_contact);
  ru->ru_contact = m;

  return 0;
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
