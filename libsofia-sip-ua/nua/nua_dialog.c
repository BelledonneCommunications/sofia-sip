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
#include <sofia-sip/su_uniqueid.h>

#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_status.h>

#define SU_TIMER_ARG_T struct nua_usage_queue
#include <sofia-sip/su_wait.h>

#define NUA_OWNER_T su_home_t

#include "nua_dialog.h"

#define SU_LOG (nua_log)
#include <sofia-sip/su_debug.h>

#ifndef NONE
#define NONE ((void *)-1)
#endif

/* ======================================================================== */
/* Dialog handling */

static void nua_dialog_usage_remove_at(nua_owner_t*, nua_dialog_state_t*, 
				       nua_dialog_usage_t**);
static void nua_dialog_log_usage(nua_owner_t *, nua_dialog_state_t *);

/**@internal
 * UAS tag and route.
 *
 * Update dialog tags and route on the UAS side.
 *
 * @param own  dialog owner
 * @param ds   dialog state
 * @param sip  SIP message containing response used to update dialog
 * @param rtag if true, set remote tag within the leg
 */
void nua_dialog_uas_route(nua_owner_t *own, 
			  nua_dialog_state_t *ds,
			  sip_t const *sip, 
			  int rtag)
{
  int established = nua_dialog_is_established(ds);

  if (!established && sip->sip_from->a_tag)
    ds->ds_remote_tag = su_strdup(own, sip->sip_from->a_tag);

  if (ds->ds_leg == NULL)
    return;

  nta_leg_server_route(ds->ds_leg, sip->sip_record_route, sip->sip_contact);
  ds->ds_route = ds->ds_route || sip->sip_record_route || sip->sip_contact;

  if (rtag && !established && sip->sip_from->a_tag)
    nta_leg_rtag(ds->ds_leg, sip->sip_from->a_tag);
}

/**@internal
 * UAC tag and route.
 *
 * Update dialog tags and route on the UAC side.
 *
 * @param own  dialog owner
 * @param ds   dialog state
 * @param sip  SIP message containing response used to update dialog
 * @param rtag if true, set remote tag within the leg
 */
void nua_dialog_uac_route(nua_owner_t *own, 
			  nua_dialog_state_t *ds,
			  sip_t const *sip,
			  int rtag)
{
  int established = nua_dialog_is_established(ds);

  if (!established && sip->sip_to->a_tag)
    ds->ds_remote_tag = su_strdup(own, sip->sip_to->a_tag);

  if (ds->ds_leg == NULL)
    return;

  nta_leg_client_route(ds->ds_leg, sip->sip_record_route, sip->sip_contact);
  ds->ds_route = ds->ds_route || sip->sip_record_route || sip->sip_contact;

  if (rtag && !established && sip->sip_to->a_tag)
    nta_leg_rtag(ds->ds_leg, sip->sip_to->a_tag);
}

/**@internal Store information from remote endpoint. */
void nua_dialog_store_peer_info(nua_owner_t *own, 
				nua_dialog_state_t *ds,
				sip_t const *sip)
{
  nua_dialog_peer_info_t *nr = ds->ds_remote_ua;
  nua_dialog_usage_t *du;
  nua_dialog_peer_info_t old[1];

  *old = *nr;

  if (sip && sip->sip_status &&
      sip->sip_status->st_status >= 300 &&
      sip->sip_status->st_status <= 399)
    sip = NULL;			/* Redirected */

  if (sip == NULL) {
    nr->nr_allow = NULL, su_free(own, old->nr_allow);
    nr->nr_accept = NULL, su_free(own, old->nr_accept);
    nr->nr_require = NULL, su_free(own, old->nr_require);
    nr->nr_supported = NULL, su_free(own, old->nr_supported);
    nr->nr_user_agent = NULL, su_free(own, old->nr_user_agent);
    return;
  }

  if (sip->sip_allow) {
    nr->nr_allow = sip_allow_dup(own, sip->sip_allow);
    su_free(own, old->nr_allow);
  }

  if (sip->sip_accept) {
    nr->nr_accept = sip_accept_dup(own, sip->sip_accept);
    su_free(own, old->nr_accept);
  }

  if (sip->sip_require) {
    nr->nr_require = sip_require_dup(own, sip->sip_require);
    su_free(own, old->nr_require);
  }

  if (sip->sip_supported) {
    nr->nr_supported = sip_supported_dup(own, sip->sip_supported);
    su_free(own, old->nr_supported);
  }

  if (sip->sip_user_agent) {
    nr->nr_user_agent = sip_user_agent_dup(own, sip->sip_user_agent);
    su_free(own, old->nr_user_agent);
  }
  else if (sip->sip_server) {
    nr->nr_user_agent = sip_user_agent_dup(own, sip->sip_server);
    su_free(own, old->nr_user_agent);
  }

  for (du = ds->ds_usage; du; du = du->du_next) {
    if (du->du_class->usage_peer_info)
      du->du_class->usage_peer_info(du, ds, sip);
  }
}

/** Remove dialog (if there is no other usages). */
int nua_dialog_remove(nua_owner_t *own,
		      nua_dialog_state_t *ds,
		      nua_dialog_usage_t *usage)
{
  if (ds->ds_usage == usage && (usage == NULL || usage->du_next == NULL)) {
    nua_dialog_store_peer_info(own, ds, NULL); /* zap peer info */
    nta_leg_destroy(ds->ds_leg), ds->ds_leg = NULL;
    su_free(own, (void *)ds->ds_remote_tag), ds->ds_remote_tag = NULL;
    ds->ds_route = 0;
  }
  return 0;
}


/** @internal Get dialog usage slot. */
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
	if (str0casecmp(event->o_id, o->o_id)) {
	  if (event->o_id || strcmp(event->o_type, "refer"))
	    continue;
	}
      }

      return (nua_dialog_usage_t **)prev;
    }
  }

  return &none;
}

/** @internal Get a dialog usage */
nua_dialog_usage_t *nua_dialog_usage_get(nua_dialog_state_t const *ds, 
					 nua_usage_class const *kind,
					 sip_event_t const *event)
{
  return *nua_dialog_usage_at(ds, kind, event);
}

/** @internal Get dialog usage name */
char const *nua_dialog_usage_name(nua_dialog_usage_t const *du)
{
  if (du == NULL)
    return "<NULL>";
  return du->du_class->usage_name(du);
} 

/** @internal Add dialog usage */
nua_dialog_usage_t *nua_dialog_usage_add(nua_owner_t *own, 
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
		  (void *)own, nua_dialog_usage_name(du), 
		  event ? "  with event " : "", event ? event->o_type : ""));
      
      if (prev_du != &ds->ds_usage) {
	/* Move as a first usage in the list */
	*prev_du = du->du_next;
	du->du_next = ds->ds_usage;
	ds->ds_usage = du;
      }
      return du;
    }

    o = event ? sip_event_dup(own, event) : NULL;

    if (o != NULL || event == NULL)
      du = su_zalloc(own, sizeof *du + uclass->usage_size);

    if (du) {
      su_home_ref(own);
      du->du_dialog = ds; 
      du->du_class = uclass;
      du->du_event = o;

      if (uclass->usage_add(own, ds, du) < 0) {
	su_free(own, o);
	su_free(own, du);
	return NULL;
      }
	
      SU_DEBUG_5(("nua(%p): adding %s usage%s%s\n",
		  (void *)own, nua_dialog_usage_name(du), 
		  o ? " with event " : "", o ? o->o_type :""));

      du->du_next = ds->ds_usage, ds->ds_usage = du;

      return du;
    }

    su_free(own, o);
  }

  return NULL;
}

/** @internal Remove dialog usage. */
void nua_dialog_usage_remove(nua_owner_t *own, 
			     nua_dialog_state_t *ds,
			     nua_dialog_usage_t *du)
{
  nua_dialog_usage_t **at;

  assert(own); assert(ds); assert(du);

  for (at = &ds->ds_usage; *at; at = &(*at)->du_next)
    if (du == *at)
      break;

  assert(*at);

  nua_dialog_usage_remove_at(own, ds, at);
}

/** @internal Remove dialog usage. 
 *
 * Zap dialog state (leg, tag and route) if no usages remain. 
*/
static 
void nua_dialog_usage_remove_at(nua_owner_t *own, 
				nua_dialog_state_t *ds,
				nua_dialog_usage_t **at)
{
  if (*at) {
    nua_dialog_usage_t *du = *at;
    sip_event_t const *o = NULL;
    nua_client_request_t *cr, *cr_next;
    nua_server_request_t *sr, *sr_next;

    *at = du->du_next;

    o = du->du_event;

    SU_DEBUG_5(("nua(%p): removing %s usage%s%s\n",
		(void *)own, nua_dialog_usage_name(du), 
		o ? " with event " : "", o ? o->o_type :""));
    du->du_class->usage_remove(own, ds, du);

    /* Destroy saved client request */
    if (nua_client_is_bound(du->du_cr)) {
      nua_client_bind(cr = du->du_cr, NULL);
      if (!nua_client_is_queued(cr) &&
	  !nua_client_is_reporting(cr))
	nua_client_request_destroy(cr);
    }

    /* Clean references from queued client requests */
    for (cr = ds->ds_cr; cr; cr = cr_next) {
      cr_next = cr->cr_next;
      if (cr->cr_usage == du)
	cr->cr_usage = NULL;
    }

    for (sr = ds->ds_sr; sr; sr = sr_next) {
      sr_next = sr->sr_next;
      if (sr->sr_usage == du)
	nua_server_request_destroy(sr);
    }

    if (du->du_queued)
      nua_dialog_usage_reset_refresh(du);

    su_home_unref(own);
    su_free(own, du);
  }

  /* Zap dialog if there are no more usages */
  if (ds->ds_terminating)
    ;
  else if (ds->ds_usage == NULL) {
    nua_dialog_remove(own, ds, NULL);
    ds->ds_has_events = 0;
    return;
  }
  else {
    nua_dialog_log_usage(own, ds);
  }
}

static
void nua_dialog_log_usage(nua_owner_t *own, nua_dialog_state_t *ds)
{
  nua_dialog_usage_t *du;

  if (SU_LOG->log_level >= 3) {
    char buffer[160];
    size_t l = 0, N = sizeof buffer;
    ssize_t n;
    
    buffer[0] = '\0';

    for (du = ds->ds_usage; du; du = du->du_next) {
      msg_header_t const *h = (void *)du->du_event;

      if (!h)
	continue;

      n = sip_event_e(buffer + l, N - l, h, 0);
      if (n == -1)
	break;
      l += (size_t)n;
      if (du->du_next && l + 2 < sizeof(buffer)) {
	strcpy(buffer + l, ", ");
	l += 2;
      }
    }
    
    SU_DEBUG_3(("nua(%p): handle with %s%s%s\n", (void *)own,
		ds->ds_has_session ? "session and " : "", 
		ds->ds_has_events ? "events " : "",
		buffer));
  }
}

/**@internal
 * Set refresh value suitably. 
 *
 * The refresh time is set either around half of the @a delta interval or,
 * if @a delta is less than 5 minutes but longer than 90 seconds, 30..60
 * seconds before end of interval.
 *
 * If @a delta is 0, the refresh time is set at the end of the world
 * (maximum time, for 32-bit systems sometimes during 2036).
 */
void nua_dialog_usage_set_refresh(nua_dialog_usage_t *du, unsigned delta)
{
  if (delta == 0)
    nua_dialog_usage_reset_refresh(du);
  else if (delta > 90 && delta < 5 * 60)
    /* refresh 30..60 seconds before deadline */
    nua_dialog_usage_set_refresh_range(du, delta - 60, delta - 30);
  else {
    /* By default, refresh around half time before deadline */
    unsigned min = (delta + 2) / 4;
    unsigned max = (delta + 2) / 4 + (delta + 1) / 2;
    if (min == 0)
      min = 1;
    nua_dialog_usage_set_refresh_range(du, min, max);
  }
}

/**@internal Set refresh in range min..max seconds in the future. */
void nua_dialog_usage_set_refresh_range(nua_dialog_usage_t *du, 
					unsigned min, unsigned max)
{
  su_time_t now = su_now();
  su_time_t target = now;
  unsigned delta;

  if (max < min)
    max = min;

  if (min != max)
    delta = su_randint(min, max);
  else
    delta = min;

  if (now.tv_sec + delta >= now.tv_sec)
    target.tv_sec = now.tv_sec + delta;
  else
    target.tv_sec = SIP_TIME_MAX;

  SU_DEBUG_7(("nua(): refresh %s@%p after %u seconds (in [%u..%u])\n",
	      nua_dialog_usage_name(du), du->du_dialog->ds_usage,
	      delta, min, max));

  nua_dialog_usage_set_refresh_at(du, target);
}

/** @internal Refresh usage or shutdown usage if @a now is 0. */
void nua_dialog_usage_refresh(nua_owner_t *owner,
			      nua_dialog_state_t *ds,
			      nua_dialog_usage_t *du, 
			      sip_time_t now)
{
  assert(du && du->du_class->usage_refresh);
  du->du_class->usage_refresh(owner, ds, du, now);
}

/** Terminate all dialog usages gracefully. */
int nua_dialog_shutdown(nua_owner_t *owner, nua_dialog_state_t *ds)
{
  nua_dialog_usage_t *du;

  ds->ds_terminating = 1;

  do {
    for (du = ds->ds_usage; du; du = du->du_next) {
      if (!du->du_shutdown) {
	nua_dialog_usage_shutdown(owner, ds, du);
	break;
      }
    }
  } while (du);

  return 1;
}

/** (Gracefully) terminate usage.
 *
 * @retval >0  shutdown done
 * @retval 0   shutdown in progress
 * @retval <0  try again later
 */
int nua_dialog_usage_shutdown(nua_owner_t *owner,
			      nua_dialog_state_t *ds,
			      nua_dialog_usage_t *du)
{
  if (du) {
    if (du->du_queued)
      nua_dialog_usage_reset_refresh(du);
    du->du_shutdown = 1;
    assert(du->du_class->usage_shutdown);
    return du->du_class->usage_shutdown(owner, ds, du);
  }
  else
    return 200;
}


/** Repeat shutdown all usage.
 *
 * @note Caller must have a reference to nh
 */
int nua_dialog_repeat_shutdown(nua_owner_t *owner, nua_dialog_state_t *ds)
{
  nua_dialog_usage_t *du;
  nua_server_request_t *sr, *sr_next;

  for (sr = ds->ds_sr; sr; sr = sr_next) {
    sr_next = sr->sr_next;

    if (nua_server_request_is_pending(sr)) {
      SR_STATUS1(sr, SIP_410_GONE); /* 410 terminates dialog */
      nua_server_respond(sr, NULL);
      nua_server_report(sr);
    }
  }

  for (du = ds->ds_usage; du ;) {
    nua_dialog_usage_t *du_next = du->du_next;

    nua_dialog_usage_shutdown(owner, ds, du);

    if (du_next == NULL)
      break;

    for (du = ds->ds_usage; du; du = du->du_next) {
      if (du == du_next)
	break;
      else if (!du->du_shutdown)
	break;
    }
  }

  return ds->ds_usage != NULL;
}

/** Deinitialize dialog and its usage. @internal */
void nua_dialog_deinit(nua_owner_t *own,
		       nua_dialog_state_t *ds)
{
  ds->ds_terminating = 1;

  while (ds->ds_usage) {
    nua_dialog_usage_remove_at(own, ds, &ds->ds_usage);
  }

  nua_dialog_remove(own, ds, NULL);

  ds->ds_has_events = 0;
  ds->ds_terminating = 0;
}

/* ---------------------------------------------------------------------- */

static void nua_usage_queue_run(nua_usage_queue_t *queue,
				su_timer_t *t);
static void nua_usage_queue_timer(su_root_magic_t *magic,
				  su_timer_t *t,
				  nua_usage_queue_t *queue);

#include <sofia-sip/heap.h>

HEAP_DECLARE(su_inline,
	     struct nua_usage_heap,
	     nua_usage_queue_,
	     nua_dialog_usage_t *);

int nua_usage_queue_init(nua_usage_queue_t *queue,
			 su_root_t *root)
{
  queue->queue_timer = su_timer_create(su_root_task(root), 0);
  nua_usage_queue_resize(NULL, queue->queue_heap, 0);
  return queue->queue_timer != NULL ? 0 : -1;
}

int nua_usage_queue_deinit(nua_usage_queue_t *queue)
{
  su_timer_destroy(queue->queue_timer), queue->queue_timer = NULL;
  nua_usage_queue_free(NULL, queue->queue_heap);
  return 0;
}

/** Run queue */
static
void nua_usage_queue_run(nua_usage_queue_t *queue, su_timer_t *t)
{
  short i;
  nua_dialog_usage_t *du;
  nua_dialog_state_t *ds;
  su_time_t now;

  su_time(&now);

  if (queue->queue_shutdown)
    return;

  for (i = 0; ; i++) {
    du = nua_usage_queue_get(queue->queue_heap[0], 1);
    
    if (du == NULL 
	|| now.tv_sec < du->du_refresh.tv_sec 
	|| (now.tv_sec == du->du_refresh.tv_sec 
	    && now.tv_usec < du->du_refresh.tv_usec))
      break;

    ds = du->du_dialog;
    nua_dialog_usage_refresh(ds->ds_owner, ds, du, now.tv_sec);

    if (t && (i & 31) == 31)
      su_root_yield(su_timer_root(t));	/* Handle received packets */
  }

  if (du) {
    su_timer_set_at(queue->queue_timer, nua_usage_queue_timer, queue,
		    du->du_refresh);
  }
  else {
    /* No need to reset timer */
  }

#if 0
  if (du)
    SU_DEBUG_0(("nua(): refresh %s@%p at %.3f s\n", 
		nua_dialog_usage_name(du), du->du_dialog->ds_owner,
		su_time_diff(du->du_refresh, su_now())));
  else
    SU_DEBUG_0(("nua(): no refresh\n"));

  for (i = 2; ; i++) {
    du = nua_usage_queue_get(queue->queue_heap[0], i);
    if (!du) break;
    SU_DEBUG_0(("\t%s@%p at %.3f s\n", 
		nua_dialog_usage_name(du), du->du_dialog->ds_owner,
		su_time_diff(du->du_refresh, su_now())));
  }
#endif
}

/** Set absolute refresh time */
void nua_dialog_usage_set_refresh_at(nua_dialog_usage_t *du,
				     su_time_t target)
{
  nua_usage_queue_t *queue;
  int first;

  SU_DEBUG_7(("nua(): refresh %s after %lu milliseconds\n",
	      nua_dialog_usage_name(du), 
	      su_duration(target, su_now())));

  assert(du); if (!du) return;

  queue = nua_usage_queue_by_owner(du->du_dialog->ds_owner);
  assert(queue);

  first = du->du_queued == 1;

  if (du->du_queued) {
    nua_usage_queue_remove(queue->queue_heap[0], du->du_queued);
  }

  du->du_refresh = target;

  if (queue->queue_shutdown)
    return;
    
  if (nua_usage_queue_is_full(queue->queue_heap[0]))
    nua_usage_queue_resize(NULL, queue->queue_heap, 0);
  nua_usage_queue_add(queue->queue_heap[0], du);

  if (du->du_queued == 1)
    du = du;
  else if (first)
    du = nua_usage_queue_get(queue->queue_heap[0], 1);
  else
    return;			/* No need to reschedule */

  if (du) {
    su_timer_set_at(queue->queue_timer, nua_usage_queue_timer, queue,
		    du->du_refresh);
  }
  else {
    su_timer_reset(queue->queue_timer);
  }

#if 0
  if (du)
    SU_DEBUG_0(("nua(): refresh %s@%p at %.3f s\n", 
		nua_dialog_usage_name(du), du->du_dialog->ds_owner,
		su_time_diff(du->du_refresh, su_now())));
  else
    SU_DEBUG_0(("nua(): no refresh\n"));

  for (first = 2; ; first++) {
    du = nua_usage_queue_get(queue->queue_heap[0], first);
    if (!du) break;
    SU_DEBUG_0(("\t%s@%p at %.3f s\n", 
		nua_dialog_usage_name(du), du->du_dialog->ds_owner,
		su_time_diff(du->du_refresh, su_now())));
  }
#endif
} 

void nua_dialog_usage_reset_refresh(nua_dialog_usage_t *du)
{
  nua_usage_queue_t *queue;
  int first;
  
  assert(du); if (!du) return;

  SU_DEBUG_7(("nua(): reset refresh %s@%p\n",
	      nua_dialog_usage_name(du), du->du_dialog->ds_owner));

  queue = nua_usage_queue_by_owner(du->du_dialog->ds_owner);
  assert(queue);

  first = du->du_queued == 1;

  nua_usage_queue_remove(queue->queue_heap[0], du->du_queued);

  if (!first)
    return;			/* No need to reschedule */

  if (queue->queue_shutdown)
    return;			

  du = nua_usage_queue_get(queue->queue_heap[0], 1);

  if (du) {
    su_timer_set_at(queue->queue_timer, nua_usage_queue_timer, queue,
		    du->du_refresh);
  }
  else {
    su_timer_reset(queue->queue_timer);
  }

#if 0
  if (du)
    SU_DEBUG_0(("nua(): refresh %s@%p at %.3f s\n", 
		nua_dialog_usage_name(du), du->du_dialog->ds_owner,
		su_time_diff(du->du_refresh, su_now())));
  else
    SU_DEBUG_0(("nua(): no refresh\n"));

  for (first = 2; ; first++) {
    du = nua_usage_queue_get(queue->queue_heap[0], first);
    if (!du) break;
    SU_DEBUG_0(("\t%s@%p at %.3f s\n", 
		nua_dialog_usage_name(du), du->du_dialog->ds_owner,
		su_time_diff(du->du_refresh, su_now())));
  }
#endif
}

static void nua_usage_queue_timer(su_root_magic_t *magic,
				  su_timer_t *t,
				  nua_usage_queue_t *queue)
{
  nua_usage_queue_run(queue, t);
}

su_inline void nua_usage_heap_set(nua_dialog_usage_t **array,
				  size_t index,
				  nua_dialog_usage_t *du)
{
  array[du->du_queued = index] = du;
}

su_inline int nua_usage_heap_less(nua_dialog_usage_t *a, nua_dialog_usage_t *b)
{
  return
    a->du_refresh.tv_sec < b->du_refresh.tv_sec
    || (a->du_refresh.tv_sec == b->du_refresh.tv_sec 
	&& a->du_refresh.tv_usec < b->du_refresh.tv_usec);
}

su_inline void *nua_usage_heap_alloc(void *argument, void *memory, size_t size)
{
  (void)argument;

  if (size)
    return realloc(memory, size);
  else
    return free(memory), NULL;
}

HEAP_BODIES(su_inline,
	    struct nua_usage_heap,
	    nua_usage_queue_,
	    nua_dialog_usage_t *,
	    nua_usage_heap_less,
	    nua_usage_heap_set,
	    nua_usage_heap_alloc,
	    NULL);
