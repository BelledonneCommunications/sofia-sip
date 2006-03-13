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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <assert.h>

#include <sofia-sip/string0.h>
#include <sofia-sip/sip_protos.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s

#include "nua_stack.h"

#if HAVE_SIGCOMP
#include <sigcomp.h>
#endif

#if !defined(random) && defined(_WIN32)
#define random rand
#endif

/* ====================================================================== */
/* Register usage */

struct register_usage {
  struct sigcomp_compartment *ru_compartment;
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
#if HAVE_SIGCOMP
  struct register_usage *ru = nua_dialog_usage_private(du);

  if (ru->ru_compartment)
    sigcomp_compartment_unref(ru->ru_compartment);
  ru->ru_compartment = NULL;
#endif

  ds->ds_has_register = 0;	/* There can be only one */
}

/* ======================================================================== */
/* REGISTER */

static void 
register_expires_contacts(msg_t *msg, sip_t *sip),
  refresh_register(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t),
  restart_register(nua_handle_t *nh, tagi_t *tags);

static int process_response_to_register(nua_handle_t *nh,
					nta_outgoing_t *orq,
					sip_t const *sip);

int
nua_stack_register(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_dialog_usage_t *du;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg = NULL;
  sip_t *sip;
  int registering = e == nua_r_register;

  if (nh->nh_special && nh->nh_special != nua_r_register)
    return UA_EVENT2(e, 500, "Invalid handle for REGISTER");
  if (cr->cr_orq)
    return UA_EVENT2(e, 500, "Request already in progress");

  /* Initialize allow and auth */
  nua_stack_init_handle(nua, nh, nh_has_register, "", TAG_NEXT(tags));	  
  nh->nh_special = nua_r_register;

  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_register_usage, NULL);

  if (du) {
    if (du->du_msg)
      cr->cr_msg = msg_ref_create(du->du_msg);

    msg = nua_creq_msg(nua, nh, cr, cr->cr_msg != NULL,
		     SIP_METHOD_REGISTER,
		     NUTAG_ADD_CONTACT(1),
		     TAG_IF(!registering, NUTAG_USE_DIALOG(1)),
		     TAG_NEXT(tags));
  }

  sip = sip_object(msg);

  /* Validate contacts and expires */
  if (registering) {
    du->du_terminating = 0;
  }
  else /*  if (e == nua_r_unregister) */ {
    /* Expire all of our contacts */
    du->du_terminating = 1;
    register_expires_contacts(msg, sip);
  }

  if (du && msg)
    cr->cr_orq = 
      nta_outgoing_mcreate(nua->nua_nta,
			   process_response_to_register, nh, NULL,
			   msg,
			   SIPTAG_END(), 
			   TAG_IF(!registering, NTATAG_SIGCOMP_CLOSE(1)),
			   TAG_IF(registering, NTATAG_COMP("sigcomp")),
			   TAG_NEXT(tags));

  if (!cr->cr_orq) {
    msg_destroy(msg);
    msg_destroy(cr->cr_msg), cr->cr_msg = NULL;
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  cr->cr_usage = du;

  return cr->cr_event = e;
}

static void 
register_expires_contacts(msg_t *msg, sip_t *sip)
{
  su_home_t *h = msg_home(msg);
  sip_contact_t *m;

  if (sip->sip_contact) {
    for (m = sip->sip_contact; m; m = m->m_next) {
      if (m->m_url->url_type == url_any) {
	int others = m != sip->sip_contact || m->m_next;
	sip_add_tl(msg, sip, 
		   /* Remove existing contacts */
		   TAG_IF(others, SIPTAG_CONTACT(NONE)),
		   /* Add '*' contact and Expires: 0 */
		   TAG_IF(others, SIPTAG_CONTACT_STR("*")),
		   SIPTAG_EXPIRES_STR("0"), 
		   TAG_END());
	break;
      }
    }

    if (m == NULL)		/* No '*' was found */
      for (m = sip->sip_contact; m; m = m->m_next) {
	msg_header_replace_param(h, m->m_common, "expires=0");
      }
  }

  /* Remove payload */
  while (sip->sip_payload)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_payload);
  while (sip->sip_content_type)
    sip_header_remove(msg, sip, (sip_header_t *)sip->sip_content_type);
}

static void
restart_register(nua_handle_t *nh, tagi_t *tags)
{
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg;

  cr->cr_restart = NULL;

  if (!cr->cr_msg)
    return;

  msg = nua_creq_msg(nh->nh_nua, nh, cr, 1,
		   SIP_METHOD_UNKNOWN, 
		   TAG_NEXT(tags));

  if (msg && cr->cr_usage && cr->cr_usage->du_terminating)
    register_expires_contacts(msg, sip_object(msg));

  cr->cr_orq = nta_outgoing_mcreate(nh->nh_nua->nua_nta, 
				    process_response_to_register, nh, NULL, msg,
				    SIPTAG_END(), TAG_NEXT(tags));

  if (!cr->cr_orq)
    msg_destroy(msg);
}

static
int process_response_to_register(nua_handle_t *nh,
				 nta_outgoing_t *orq,
				 sip_t const *sip)
{
  nua_t *nua = nh->nh_nua;
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  struct register_usage *ru = nua_dialog_usage_private(du);
  int status = sip->sip_status->st_status;

  assert(du && du->du_class == nua_register_usage); (void)ru;

  if (du && status >= 200 && status < 300) {
    sip_t *req = sip_object(cr->cr_msg);

    du->du_ready = 1;

    if (!du->du_terminating && req && req->sip_contact && sip->sip_contact) {
      sip_time_t now = sip_now(), delta, mindelta;
      sip_contact_t const *m, *m0;

      /** Search for lowest delta of SIP contacts in sip->sip_contact */
      mindelta = 24 * 3600;	/* XXX */

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

      nua_dialog_usage_set_refresh(du, mindelta);
      du->du_pending = refresh_register;

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

      su_free(nua->nua_home, nua->nua_service_route);
      nua->nua_service_route =
	sip_service_route_dup(nua->nua_home, sip->sip_service_route);

      if (du->du_msg)
	msg_destroy(du->du_msg);
      du->du_msg = msg_ref_create(cr->cr_msg);

#if HAVE_SIGCOMP
      {
	struct sigcomp_compartment *cc;
	cc = nta_outgoing_compartment(orq);
	sigcomp_compartment_unref(ru->ru_compartment);
	ru->ru_compartment = cc;
      }
#endif
    }

    if (du->du_terminating) {
      if (nua->nua_service_route)
	su_free(nua->nua_home, nua->nua_service_route);
      nua->nua_service_route = NULL;
      /* nua_stack_process_response() removes the dialog usage */
    }
    else {
      nta_tport_keepalive(orq);
      
    }
  }
  else if (status >= 300) {
    if (nua_creq_check_restart(nh, cr, orq, sip, restart_register))
      return 0;
  }

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
    if (now == 0)
      register_expires_contacts(msg, sip);
    
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
