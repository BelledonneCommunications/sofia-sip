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

/**@CFILE nua_dialog.c
 * @brief Dialog and dialog usage handling
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
#include "nua_dialog.h"

/* ======================================================================== */
/* Dialog handling */

static void nua_dialog_usage_remove_at(nua_handle_t*, nua_dialog_state_t*, 
				       nua_dialog_usage_t**);
static void nua_dialog_log_usage(nua_handle_t *, nua_dialog_state_t *);

/** UAS tag and route */
void nua_dialog_uas_route(nua_handle_t *nh, sip_t const *sip, int rtag)
{
  struct nua_dialog_state *ds = nh->nh_ds;
  int established = nua_dialog_is_established(ds);

  if (!established && sip->sip_from->a_tag)
    ds->ds_remote_tag = su_strdup(nh->nh_home, sip->sip_from->a_tag);

  if (ds->ds_leg == NULL)
    return;

  nta_leg_server_route(ds->ds_leg, sip->sip_record_route, sip->sip_contact);
  ds->ds_route = ds->ds_route || sip->sip_record_route || sip->sip_contact;

  if (rtag && !established && sip->sip_from->a_tag)
    nta_leg_rtag(ds->ds_leg, sip->sip_from->a_tag);
}

/** UAC tag and route.
 *
 * Update dialog tags and route on the UAC side.
 *
 * @param nh   NUA handle
 * @param sip  SIP message containing response used to update dialog
 * @param rtag if true, set remote tag within the leg
 */
void nua_dialog_uac_route(nua_handle_t *nh, sip_t const *sip, int rtag)
{
  struct nua_dialog_state *ds = nh->nh_ds;
  int established = nua_dialog_is_established(ds);

  if (!established && sip->sip_to->a_tag)
    ds->ds_remote_tag = su_strdup(nh->nh_home, sip->sip_to->a_tag);

  if (ds->ds_leg == NULL)
    return;

  nta_leg_client_route(ds->ds_leg, sip->sip_record_route, sip->sip_contact);
  ds->ds_route = ds->ds_route || sip->sip_record_route || sip->sip_contact;

  if (rtag && !established && sip->sip_to->a_tag)
    nta_leg_rtag(ds->ds_leg, sip->sip_to->a_tag);
}

/** Store information from remote endpoint. */
void nua_dialog_get_peer_info(nua_handle_t *nh, sip_t const *sip)
{
  nua_remote_t *nr = nh->nh_ds->ds_remote_ua, old[1];

  *old = *nr;

  if (sip->sip_allow) {
    nr->nr_allow = sip_allow_dup(nh->nh_home, sip->sip_allow);
    su_free(nh->nh_home, old->nr_allow);
  }

  if (sip->sip_accept) {
    nr->nr_accept = sip_accept_dup(nh->nh_home, sip->sip_accept);
    su_free(nh->nh_home, old->nr_accept);
  }

  if (sip->sip_require) {
    nr->nr_require = sip_require_dup(nh->nh_home, sip->sip_require);
    su_free(nh->nh_home, old->nr_require);
  }

  if (sip->sip_supported) {
    nr->nr_supported = sip_supported_dup(nh->nh_home, sip->sip_supported);
    su_free(nh->nh_home, old->nr_supported);
  }

  if (sip->sip_user_agent) {
    nr->nr_user_agent = sip_user_agent_dup(nh->nh_home, sip->sip_user_agent);
    su_free(nh->nh_home, old->nr_user_agent);
  }
}

/** Get dialog usage slot */
nua_dialog_usage_t **
nua_dialog_usage_at(nua_dialog_state_t const *ds, 
		    nua_usage_class const *kind,
		    sip_event_t const *event)
{
  static nua_dialog_usage_t *none = NULL;

  if (ds) {
    nua_dialog_usage_t *du, * const * prev;
    sip_event_t const *o;

    for (prev = &ds->ds_usage; (du = *prev); prev = &du->du_next) {
      if (du->du_class != kind)
	continue;

      if (event == NONE)
	return (nua_dialog_usage_t **)prev;

      o = du->du_event;

      if (!event && !o)
	return (nua_dialog_usage_t **)prev;

      if (event != o) {
	if (event == NULL || o == NULL)
	  continue;
	if (strcmp(event->o_type, o->o_type))
	  continue;
	if (str0casecmp(event->o_id, o->o_id))
	  continue;
      }

      return (nua_dialog_usage_t **)prev;
    }
  }

  return &none;
}

/** Get a dialog usage */ 
nua_dialog_usage_t *nua_dialog_usage_get(nua_dialog_state_t const *ds, 
					 nua_usage_class const *kind,
					 sip_event_t const *event)
{
  return *nua_dialog_usage_at(ds, kind, event);
}

/** Get dialog usage name */
char const *nua_dialog_usage_name(nua_dialog_usage_t const *du)
{
  if (du == NULL)
    return "<NULL>";
  return du->du_class->usage_name(du);
} 

/** Add dialog usage */
nua_dialog_usage_t *nua_dialog_usage_add(nua_handle_t *nh, 
					 struct nua_dialog_state *ds, 
					 nua_usage_class const *uclass,
					 sip_event_t const *event)
{
  if (ds) {
    sip_event_t *o;
    nua_dialog_usage_t *du, **prev_du;

    prev_du = nua_dialog_usage_at(ds, uclass, event);
    du = *prev_du;
    if (du) {		/* Already exists */
      SU_DEBUG_5(("nua(%p): adding already existing %s usage%s%s\n",
		  nh, nua_dialog_usage_name(du), 
		  event ? "  with event " : "", event ? event->o_type : ""));
      
      if (prev_du != &ds->ds_usage) {
	/* Move as a first usage in the list */
	*prev_du = du->du_next;
	du->du_next = ds->ds_usage;
	ds->ds_usage = du;
      }
      return du;
    }

    o = event ? sip_event_dup(nh->nh_home, event) : NULL;

    if (o != NULL || event == NULL)
      du = su_zalloc(nh->nh_home, sizeof *du + uclass->usage_size);

    if (du) {
      du->du_class = uclass;
      du->du_event = o;

      if (uclass->usage_add(nh, ds, du) < 0) {
	su_free(nh->nh_home, o);
	su_free(nh->nh_home, du);
	return NULL;
      }
	
      SU_DEBUG_5(("nua(%p): adding %s usage%s%s\n",
		  nh, nua_dialog_usage_name(du), 
		  o ? " with event " : "", o ? o->o_type :""));

      nua_handle_ref(nh);
      du->du_next = ds->ds_usage, ds->ds_usage = du;

      return du;
    }

    su_free(nh->nh_home, o);
  }

  return NULL;
}

/** Remove dialog usage. */
void nua_dialog_usage_remove(nua_handle_t *nh, 
			     nua_dialog_state_t *ds,
			     nua_dialog_usage_t *du)
{
  nua_dialog_usage_t **at;

  assert(nh); assert(ds); assert(du);

  for (at = &ds->ds_usage; *at; at = &(*at)->du_next)
    if (du == *at)
      break;

  assert(*at);

  nua_dialog_usage_remove_at(nh, ds, at);
}

/** Remove dialog usage.
 *
 * Zap dialog state (leg, tag and route) if no usages remain. 
*/
static 
void nua_dialog_usage_remove_at(nua_handle_t *nh, 
				nua_dialog_state_t *ds,
				nua_dialog_usage_t **at)
{
  if (*at) {
    nua_dialog_usage_t *du = *at;
    sip_event_t const *o = NULL;

    *at = du->du_next;

    o = du->du_event;

    SU_DEBUG_5(("nua(%p): removing %s usage%s%s\n",
		nh, nua_dialog_usage_name(du), 
		o ? " with event " : "", o ? o->o_type :""));
    du->du_class->usage_remove(nh, ds, du);
    msg_destroy(du->du_msg);
    nua_handle_unref(nh);
    su_free(nh->nh_home, du);
  }

  /* Zap dialog if there is no more usages */
  if (ds->ds_usage == NULL) {
    nta_leg_destroy(ds->ds_leg), ds->ds_leg = NULL;
    su_free(nh->nh_home, (void *)ds->ds_remote_tag), ds->ds_remote_tag = NULL;
    ds->ds_route = 0;
    ds->ds_has_events = 0;
    ds->ds_terminated = 0;
    return;
  }
  else if (!ds->ds_terminated) {
    nua_dialog_log_usage(nh, ds);
  }
}

static
void nua_dialog_log_usage(nua_handle_t *nh, nua_dialog_state_t *ds)
{
  nua_dialog_usage_t *du;

  if (nua_log->log_level >= 3) {
    char buffer[160];
    int l = 0, n, N = sizeof buffer;
    
    buffer[0] = '\0';

    for (du = ds->ds_usage; du; du = du->du_next) {
      msg_header_t const *h = (void *)du->du_event;

      if (!h)
	continue;

      n = sip_event_e(buffer + l, N - l, h, 0);
      if (n == -1)
	break;
      l += n;
      if (du->du_next && l + 2 < sizeof(buffer)) {
	strcpy(buffer + l, ", ");
	l += 2;
      }
    }
    
    SU_DEBUG_3(("nua(%p): handle with %s%s%s\n", nh,
		ds->ds_has_session ? "session and " : "", 
		ds->ds_has_events ? "events " : "",
		buffer));
  }
}

/** Dialog has been terminated. */
void nua_dialog_terminated(nua_handle_t *nh,
			   struct nua_dialog_state *ds,
			   int status,
			   char const *phrase)
{

  ds->ds_terminated = 1;

  while (ds->ds_usage) {
#if 0
    int call = 0;

    if (ds->ds_usage->du_kind == nua_session_usage)
      call = 1;			/* Delay sending the event */
    else
      /* XXX */;
#endif
    nua_dialog_usage_remove_at(nh, ds, &ds->ds_usage);
  }
}


/** Set refresh value suitably.
 *
 * The refresh time is set either at half of the @a delta interval or if @a
 * delta is less than 5 minutes, 30 seconds before end of interval. $
 *
 * If @a delta is 0, the refresh time is set at the end of the world
 * (maximum time, for 32-bit systems sometimes during 2036).
 */
void nua_dialog_usage_set_refresh(nua_dialog_usage_t *du, unsigned delta)
{
  sip_time_t target = sip_now();

  if (delta > 60 && delta < 5 * 60)
    /* refresh 30 seconds before deadline */
    delta -= 30;
  else 
    /* refresh at half time before deadline */
    delta /= 2;

  if (target + delta >= target)
    target = target + delta;
  else
    target = SIP_TIME_MAX;

  du->du_refresh = target;
}

#if 0

    switch (kind) {
    case nua_session_usage:  
      ds->ds_has_session = 0;
      break;

    case nua_notifier_usage:
      su_free(nh->nh_home, (void *)du->du_event);
      ds->ds_has_notifier = NULL != *nua_dialog_usage_at(ds, kind, NONE);
      ds->ds_has_events = ds->ds_has_notifier || ds->ds_has_subscription;
      break;

    case nua_subscriber_usage:
      su_free(nh->nh_home, (void *)du->du_event);
      ds->ds_has_subscription = NULL != *nua_dialog_usage_at(ds, kind, NONE);
      ds->ds_has_events = ds->ds_has_subscription || ds->ds_has_notifier;
      msg_destroy(du->du_subscriber->de_msg);
      break;

    case nua_register_usage:
      ds->ds_has_register = 0;
      msg_destroy(du->du_register->ru_msg);
      break;

    case nua_publish_usage:
      ds->ds_has_publish = 0;
      su_free(nh->nh_home, du->du_publisher->pu_etag);
      break;

    case nua_transaction_usage:
    default:
      break;
    }


      switch (kind) {
      case nua_session_usage:  
	ds->ds_has_session = 1; 
	break;
      case nua_notifier_usage:
	ds->ds_has_events = 1;
	ds->ds_has_notifier = 1;
	break;
      case nua_subscriber_usage:
	ds->ds_has_events = 1;
	ds->ds_has_subscription = 1;
	break;
      case nua_register_usage:
	ds->ds_has_register = 1;
	break;
      case nua_publish_usage:
	ds->ds_has_publish = 1;
	break;
      case nua_transaction_usage:
      default:
	break;
      }


typedef struct {
  void (*nua_dialog_destructor)(nua_handle_t *nh, 
				nua_dialog_usage_t *du);
} nua_usage_class;

#endif
