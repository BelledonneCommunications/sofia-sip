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

/**@CFILE nua_publish.c
 * @brief PUBLISH and publications
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Mar  8 17:01:32 EET 2006 ppessi
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <assert.h>

#include <sofia-sip/string0.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_status.h>

#define NTA_LEG_MAGIC_T      struct nua_handle_s
#define NTA_OUTGOING_MAGIC_T struct nua_handle_s

#include "nua_stack.h"

/* ====================================================================== */
/* Publish usage */

struct publish_usage {
  sip_etag_t *pu_etag;
};

static char const *nua_publish_usage_name(nua_dialog_usage_t const *du);
static int nua_publish_usage_add(nua_handle_t *nh, 
				  nua_dialog_state_t *ds,
				  nua_dialog_usage_t *du);
static void nua_publish_usage_remove(nua_handle_t *nh, 
				      nua_dialog_state_t *ds,
				      nua_dialog_usage_t *du);

static nua_usage_class const nua_publish_usage[1] = {
  {
    sizeof (struct publish_usage),
    sizeof nua_publish_usage,
    nua_publish_usage_add,
    nua_publish_usage_remove,
    nua_publish_usage_name,
  }};

static
char const *nua_publish_usage_name(nua_dialog_usage_t const *du)
{
  return "publish";
}

static 
int nua_publish_usage_add(nua_handle_t *nh, 
			   nua_dialog_state_t *ds,
			   nua_dialog_usage_t *du)
{
  if (ds->ds_has_publish)
    return -1;			/* There can be only one */
  ds->ds_has_publish = 1;
  return 0;
}

static 
void nua_publish_usage_remove(nua_handle_t *nh, 
			       nua_dialog_state_t *ds,
			       nua_dialog_usage_t *du)
{
  struct publish_usage *pu = nua_dialog_usage_private(du);

  su_free(nh->nh_home, pu->pu_etag);

  ds->ds_has_publish = 0;	/* There can be only one */
}

/* ======================================================================== */
/* PUBLISH */

static int process_response_to_publish(nua_handle_t *nh,
				       nta_outgoing_t *orq,
				       sip_t const *sip);

static void refresh_publish(nua_handle_t *nh, nua_dialog_usage_t *, sip_time_t now);

int
nua_stack_publish(nua_t *nua, nua_handle_t *nh, nua_event_t e, tagi_t const *tags)
{
  nua_dialog_usage_t *du;
  struct publish_usage *pu;
  struct nua_client_request *cr = nh->nh_cr;
  msg_t *msg = NULL;
  sip_t *sip;

  if (nh->nh_special && nh->nh_special != nua_r_publish) {
    return UA_EVENT2(e, 500, "Invalid handle for PUBLISH");
  }
  else if (cr->cr_orq) {
    return UA_EVENT2(e, 500, "Request already in progress");
  }

  nua_stack_init_handle(nua, nh, nh_has_nothing, NULL, TAG_NEXT(tags));

  du = nua_dialog_usage_add(nh, nh->nh_ds, nua_publish_usage, NULL);

  if (!du)
    return UA_EVENT1(e, NUA_500_ERROR);

  pu = nua_dialog_usage_private(du);
  msg = nua_creq_msg(nua, nh, cr, cr->cr_retry_count,
			 SIP_METHOD_PUBLISH,
			 SIPTAG_IF_MATCH(pu->pu_etag),
			 NUTAG_ADD_CONTACT(0),
			 TAG_NEXT(tags));
  sip = sip_object(msg);

  du->du_terminating = 
    e != nua_r_publish ||
    (sip && sip->sip_expires && sip->sip_expires->ex_delta == 0);

  cr->cr_orq = nta_outgoing_mcreate(nua->nua_nta,
				    process_response_to_publish, nh, NULL,
				    msg,
				    TAG_IF(e != nua_r_publish,
					   SIPTAG_EXPIRES_STR("0")),
				    SIPTAG_END(), TAG_NEXT(tags));

  if (!cr->cr_orq) {
    msg_destroy(msg);
    if (!du->du_ready)
      nua_dialog_usage_remove(nh, nh->nh_ds, du);
    return UA_EVENT1(e, NUA_500_ERROR);
  }

  nh->nh_special = nua_r_publish;
  cr->cr_usage = du;

  return cr->cr_event = e;
}


static void 
restart_publish(nua_handle_t *nh, tagi_t *tags)
{
  nua_creq_restart(nh, nh->nh_cr, process_response_to_publish, tags);
}


static 
int process_response_to_publish(nua_handle_t *nh,
				nta_outgoing_t *orq,
				sip_t const *sip)
{
  int status = sip->sip_status->st_status;
  struct nua_client_request *cr = nh->nh_cr;
  nua_dialog_usage_t *du = cr->cr_usage;
  struct publish_usage *pu = nua_dialog_usage_private(du);

  if (nua_creq_check_restart(nh, cr, orq, sip, restart_publish))
    return 0;

  if (du && status >= 200) {
    if (pu->pu_etag)
      su_free(nh->nh_home, pu->pu_etag), 
	pu->pu_etag = NULL;

    if (sip->sip_expires == 0 || sip->sip_expires->ex_delta == 0)
      du->du_terminating = 1;

    if (!du->du_terminating && status < 300) {
      pu->pu_etag = sip_etag_dup(nh->nh_home, sip->sip_etag);
      nua_dialog_usage_set_refresh(du, sip->sip_expires->ex_delta);
      du->du_pending = refresh_publish;
    }
  }

  return nua_stack_process_response(nh, nh->nh_cr, orq, sip, TAG_END());
}


static
void refresh_publish(nua_handle_t *nh, nua_dialog_usage_t *du, sip_time_t now)
{
  if (du)
    du->du_terminating = now == 0;

  if (now > 0)
    nua_stack_publish(nh->nh_nua, nh, nua_r_publish, NULL);
  else
    nua_stack_publish(nh->nh_nua, nh, nua_r_destroy, NULL);
}


int nua_stack_process_publish(nua_t *nua,
			      nua_handle_t *nh,
			      nta_incoming_t *irq,
			      sip_t const *sip)
{
  if (nh == NULL)
    if (!(nh = nua_stack_incoming_handle(nua, irq, sip, nh_has_nothing, 0)))
      return 500;

  nua_stack_event(nh->nh_nua, nh, nta_incoming_getrequest(irq),
		  nua_i_publish, SIP_501_NOT_IMPLEMENTED, TAG_END());

  return 501; /* Respond automatically with 501 Not Implemented */
}


