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

#ifndef NUA_DIALOG_H /** Defined when <nua_dialog.h> has been included. */
#define NUA_DIALOG_H

/**@IFILE nua_dialog.h 
 * @brief Dialog and dialog usage handling
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 *
 * @date Created: Wed Mar  8 11:38:18 EET 2006  ppessi
 */

typedef struct nua_dialog_state nua_dialog_state_t;
typedef struct nua_dialog_usage nua_dialog_usage_t;
typedef struct nua_remote_s nua_remote_t;

#ifndef NUA_OWNER_T
#define NUA_OWNER_T struct nua_owner_s
#endif
typedef NUA_OWNER_T nua_owner_t;

#ifndef NTA_H
#include <sofia-sip/nta.h>
#endif

struct nua_dialog_state
{
  /** Dialog usages. */
  nua_dialog_usage_t     *ds_usage;

  /* Dialog and subscription state */
  unsigned ds_route:1;		/**< We have route */
  unsigned ds_terminated:1;	/**< Being terminated */

  unsigned ds_has_session:1;	/**< We have session */
  unsigned ds_has_register:1;	/**< We have registration */
  unsigned ds_has_publish:1;	/**< We have publish */
  unsigned :0;

  unsigned ds_has_events;	/**< We have events */
  unsigned ds_has_subscribes;   /**< We have subscriptions */
  unsigned ds_has_notifys;	/**< We have notifiers */

  sip_from_t const *ds_local;		/**< Local address */
  sip_to_t const *ds_remote;		/**< Remote address */
  nta_leg_t      *ds_leg;
  char const     *ds_remote_tag;	/**< Remote tag (if any). 
					 * Should be non-NULL 
					 * if dialog is established.
					 */

  struct nua_remote_s {
    sip_allow_t      *nr_allow;
    sip_accept_t     *nr_accept;
    sip_require_t    *nr_require;
    sip_supported_t  *nr_supported;
    sip_user_agent_t *nr_user_agent;
  } ds_remote_ua[1];
};

typedef void nh_pending_f(nua_owner_t *, 
			  nua_dialog_usage_t *du,
			  sip_time_t now);

typedef struct {
  unsigned usage_size, usage_class_size;
  int (*usage_add)(nua_owner_t *, 
		   nua_dialog_state_t *ds,
		   nua_dialog_usage_t *du);
  void (*usage_remove)(nua_owner_t *, 
		       nua_dialog_state_t *ds,
		       nua_dialog_usage_t *du);
  char const *(*usage_name)(nua_dialog_usage_t const *du);
  void (*usage_peer_info)(nua_dialog_usage_t *du,
			  nua_dialog_state_t const *ds,
			  sip_t const *sip);
  void (*usage_refresh)(nua_owner_t *, nua_dialog_usage_t *, sip_time_t now);
  int (*usage_shutdown)(nua_owner_t *, nua_dialog_usage_t *);
} nua_usage_class;

struct nua_dialog_usage {
  nua_dialog_usage_t *du_next;
  nua_usage_class const *du_class;

  unsigned     du_terminating:1;	/**< Now trying to terminate usage */
  unsigned     du_ready:1;	        /**< Established usage */
  unsigned     du_shutdown:1;	        /**< Shutdown in progress */
  unsigned:0;

  /** Pending operation.
   *
   * The du_pending() is called 
   * a) when current time sip_now() will soon exceed du_refresh (now > 1)
   * b) when operation is restarted (now is 1)
   * c) when usage is destroyed (now is 0)
   */
  nh_pending_f   *du_pending;
  sip_time_t      du_refresh;		/**< When execute du_pending */

  sip_event_t const *du_event;		/**< Event of usage */
  msg_t *du_msg;			/**< Template message */
};

void nua_dialog_uac_route(nua_owner_t *, nua_dialog_state_t *ds,
			  sip_t const *sip, int rtag);
void nua_dialog_uas_route(nua_owner_t *, nua_dialog_state_t *ds,
			  sip_t const *sip, int rtag);
void nua_dialog_store_peer_info(nua_owner_t *, nua_dialog_state_t *ds,
				sip_t const *sip);

char const *nua_dialog_usage_name(nua_dialog_usage_t const *du);

nua_dialog_usage_t *nua_dialog_usage_add(nua_owner_t *, 
					 struct nua_dialog_state *ds,
					 nua_usage_class const *uclass,
					 sip_event_t const *event);

nua_dialog_usage_t *nua_dialog_usage_get(nua_dialog_state_t const *ds, 
					 nua_usage_class const *uclass,
					 sip_event_t const *event);

void nua_dialog_usage_remove(nua_owner_t *, 
			     nua_dialog_state_t *ds,
			     nua_dialog_usage_t *du);

void nua_dialog_terminated(nua_owner_t *,
			   struct nua_dialog_state *ds,
			   int status,
			   char const *phrase);

void nua_dialog_usage_set_refresh(nua_dialog_usage_t *du, unsigned delta);

void nua_dialog_usage_refresh(nua_owner_t *owner,
			      nua_dialog_usage_t *du, 
			      sip_time_t now);


static inline
int nua_dialog_is_established(nua_dialog_state_t const *ds)
{
  return ds->ds_remote_tag != NULL;
}

#if 0
static inline
void *nua_dialog_usage_private(nua_dialog_usage_t const *du)
{
  return du ? (void *)(du + 1) : NULL;
}

static inline
nua_dialog_usage_t *nua_dialog_usage_public(void const *p)
{
  return p ? (nua_dialog_usage_t *)p - 1 : NULL;
}
#else
#define nua_dialog_usage_private(du) ((du) ? (void*)((du) + 1) : NULL)
#define nua_dialog_usage_public(p) ((p) ? (nua_dialog_usage_t*)(p) - 1 : NULL)
#endif

#endif /* NUA_DIALOG_H */
