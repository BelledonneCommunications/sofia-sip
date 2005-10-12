/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
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

/**@CFILE soa_static.c
 *
 * @brief Static implementation of Sofia SDP Offer/Answer Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Aug 16 17:06:06 EEST 2005
 * $Date: 2005/10/12 18:32:48 $
 *
 * @par Use-cases
 *  1. no existing session
 *    a) generating offer (upgrade with user-SDP)
 *    b) generating answer (upgrade with remote-SDP, rejects with user-SDP)
 *  2. session exists
 *    a) generating offer: 
 *       upgrades with user-SDP
 *    b) generating answer: 
 *       upgrades with remote-SDP, rejects with user-SDP
 *    c) processing answer: 
 *       rejects with user-SDP, no upgrades
 *
 * Upgrading session with user SDP:
 */

#include "config.h"

const char soa_static_c_id[] =
"$Id: soa_static.c,v 1.6 2005/10/12 18:32:48 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

struct soa_static_complete;

#define SU_MSG_ARG_T struct soa_static_completed

#include <su_wait.h>
#include <su_tag_class.h>
#include <su_tag_class.h>
#include <su_tagarg.h>
#include <su_strlst.h>

#include "soa.h"
#include <sdp.h>
#include "soa_session.h"

#define NONE ((void *)-1)
#define XXX assert(!"implemented")

#define str0cmp(a, b) strcmp(a ? a : "", b ? b : "")

typedef struct soa_static_session
{
  soa_session_t sss_session[1];
}
soa_static_session_t;

static int soa_static_init(char const *, soa_session_t *, soa_session_t *);
static void soa_static_deinit(soa_session_t *);
static int soa_static_set_params(soa_session_t *ss, tagi_t const *tags);
static int soa_static_get_params(soa_session_t const *ss, tagi_t *tags);
static tagi_t *soa_static_get_paramlist(soa_session_t const *ss,
					tag_type_t tag, tag_value_t value, 
					...);
static int soa_static_set_capability_sdp(soa_session_t *ss, 
				       sdp_session_t *sdp,
				       char const *, int);
static int soa_static_set_remote_sdp(soa_session_t *ss, 
				   int new_version,
				   sdp_session_t *sdp,
				   char const *, int);
static int soa_static_set_user_sdp(soa_session_t *ss, 
				   sdp_session_t *sdp,
				   char const *, int);
static int soa_static_generate_offer(soa_session_t *ss, soa_callback_f *);
static int soa_static_generate_answer(soa_session_t *ss, soa_callback_f *);
static int soa_static_process_answer(soa_session_t *ss, soa_callback_f *);
static int soa_static_process_reject(soa_session_t *ss, soa_callback_f *);

static int soa_static_activate(soa_session_t *ss, char const *option);
static int soa_static_deactivate(soa_session_t *ss, char const *option);
static void soa_static_terminate(soa_session_t *ss, char const *option);

struct soa_session_actions const soa_default_actions = 
  {
    (sizeof soa_default_actions),
    sizeof (struct soa_static_session),
    soa_static_init,
    soa_static_deinit,
    soa_static_set_params,
    soa_static_get_params,
    soa_static_get_paramlist,
    soa_base_media_features,
    soa_base_sip_required,
    soa_base_sip_support,
    soa_base_remote_sip_features,
    soa_static_set_capability_sdp,
    soa_static_set_remote_sdp,
    soa_static_set_user_sdp,
    soa_static_generate_offer,
    soa_static_generate_answer,
    soa_static_process_answer,
    soa_static_process_reject,
    soa_static_activate,
    soa_static_deactivate,
    soa_static_terminate
  };

/* Initialize session */
static int soa_static_init(char const *name,
			   soa_session_t *ss,
			   soa_session_t *parent)
{
  return soa_base_init(name, ss, parent);
}

static void soa_static_deinit(soa_session_t *ss)
{
  soa_base_deinit(ss);
}

static int soa_static_set_params(soa_session_t *ss, tagi_t const *tags)
{
  return soa_base_set_params(ss, tags);
}

static int soa_static_get_params(soa_session_t const *ss, tagi_t *tags)
{
  
  return soa_base_get_params(ss, tags);
}

static tagi_t *soa_static_get_paramlist(soa_session_t const *ss,
					tag_type_t tag, tag_value_t value, 
					...)
{
  ta_list ta;
  tagi_t *tl;

  ta_start(ta, tag, value);

  tl = soa_base_get_paramlist(ss, TAG_NEXT(ta_args(ta)));

  ta_end(ta);

  return tl;
}

static int soa_static_set_capability_sdp(soa_session_t *ss, 
					 sdp_session_t *sdp,
					 char const *sdp_str, 
					 int sdp_len)
{
  return soa_base_set_capability_sdp(ss, sdp, sdp_str, sdp_len);
}


static int soa_static_set_remote_sdp(soa_session_t *ss, 
				     int new_version,
				     sdp_session_t *sdp,
				     char const *sdp_str, 
				     int sdp_len)
{
  return soa_base_set_remote_sdp(ss, new_version, sdp, sdp_str, sdp_len);
}


static int soa_static_set_user_sdp(soa_session_t *ss, 
				   sdp_session_t *sdp,
				   char const *sdp_str, 
				   int sdp_len)
{
  return soa_base_set_user_sdp(ss, sdp, sdp_str, sdp_len);
}

/** Generate a rejected m= line */
sdp_media_t *soa_sdp_make_rejected_media(su_home_t *home, 
					 sdp_media_t const *m,
					 sdp_session_t *sdp)
{
  sdp_media_t rejected[1] = {{ sizeof (rejected) }};
  sdp_list_t  format[1] = {{ sizeof (format), NULL, "x" }};
  sdp_rtpmap_t rtpmap[1] = {{ sizeof (rtpmap) }};

  rejected->m_type = m->m_type;
  rejected->m_type_name = m->m_type_name;
  rejected->m_port = 0;
  rejected->m_proto = m->m_proto;
  rejected->m_proto_name = m->m_proto_name;
  if (m->m_proto == sdp_proto_rtp) {
    rtpmap->rm_predef = 1; rtpmap->rm_pt = 9;
    rtpmap->rm_encoding = "*"; rtpmap->rm_rate = 8000;
    rejected->m_rtpmaps = rtpmap;
  }
  else {
    rejected->m_format = format;
  }
  rejected->m_rejected = 1;

  return sdp_media_dup(home, rejected, sdp);
}

/** Expand a @a truncated SDP.
 */
sdp_session_t *soa_sdp_expand_media(su_home_t *home,
				    sdp_session_t const *truncated,
				    sdp_session_t const *complete)
{
  sdp_session_t *expanded;
  sdp_media_t **m0;
  sdp_media_t * const *m1;

  expanded = sdp_session_dup(home, truncated);

  if (expanded) {
    for (m0 = &expanded->sdp_media, m1 = &complete->sdp_media;
	 *m1;
	 m1 = &(*m1)->m_next) {
      if (!*m0) {
	*m0 = soa_sdp_make_rejected_media(home, *m1, expanded);
	if (!*m0)
	  return NULL;
      }
      m0 = &(*m0)->m_next;
    }
  }

  return expanded;
}

/** Check if @a session should be upgraded with @a remote */ 
int soa_sdp_upgrade_is_needed(sdp_session_t const *session,
			      sdp_session_t const *remote)
{
  sdp_media_t const *rm, *lm;

  if (!remote)
    return 0;
  if (!session)
    return 1;

  for (rm = remote->sdp_media, lm = session->sdp_media; 
       rm && lm ; rm = rm->m_next, lm = lm->m_next) {
    if (rm->m_rejected)
      continue;
    if (lm->m_rejected)
      break;
  }

  return rm != NULL;
}


/** Find first matching media in table. */
sdp_media_t *soa_sdp_matching(sdp_media_t *mm[], sdp_media_t const *with)
{
  int i;
  sdp_media_t *m;

  for (i = 0; mm[i]; i++) {
    if (sdp_media_match_with(mm[i], with)) {
      for (m = mm[i]; mm[i]; i++)
	mm[i] = mm[i + 1];
      return m;
    }
  }
  return NULL;
}

/** Upgrade m= lines within session */ 
int soa_sdp_upgrade(soa_session_t *ss,
		    su_home_t *home,
		    sdp_session_t *session,
		    sdp_session_t const *caps,
		    sdp_session_t const *upgrader)
{
  int Ns, Nc, Nu, size, i, j;
  sdp_media_t *m, **mm, *cm;
  sdp_media_t **s_media, **o_media, **c_media;
  sdp_media_t const **u_media;

  Ns = sdp_media_count(session, sdp_media_any, 0, 0, 0);
  Nc = sdp_media_count(caps, sdp_media_any, 0, 0, 0);
  Nu = sdp_media_count(upgrader, sdp_media_any, 0, 0, 0);

  if (caps == upgrader)
    size = Ns + Nc + 1;
  else if (Ns < Nu)
    size = Nu + 1;
  else
    size = Ns + 1;

  s_media = su_zalloc(home, size * (sizeof *s_media));
  o_media = su_zalloc(home, (Ns + 1) * (sizeof *o_media));
  c_media = su_zalloc(home, (Nc + 1) * (sizeof *c_media));
  u_media = su_zalloc(home, (Nu + 1) * (sizeof *u_media));

  cm = sdp_media_dup_all(home, caps->sdp_media, session); 

  if (!s_media || !c_media || !u_media || !cm)
    return -1;

  for (i = 0, m = session->sdp_media; m && i < Ns; m = m->m_next)
    o_media[i++] = m;
  assert(i == Ns);
  for (i = 0, m = cm; m && i < Nc; m = m->m_next)
    c_media[i++] = m;
  assert(i == Nc);
  for (i = 0, m = upgrader->sdp_media; m && i < Nu; m = m->m_next)
    u_media[i++] = m;
  assert(i == Nu);

  if (caps != upgrader) {
    /* Update session according to remote */
    for (i = 0; i < Nu; i++) {
      m = soa_sdp_matching(c_media, u_media[i]);
      if (!m || u_media[i]->m_rejected)
	m = soa_sdp_make_rejected_media(home, u_media[i], session);
      s_media[i] = m;
    }
  }
  else {
    /* Update session according to local */
    for (i = 0; i < Ns; i++) {
      m = soa_sdp_matching(c_media, o_media[i]);
      if (!m)
	m = soa_sdp_make_rejected_media(home, o_media[i], session);
      s_media[i] = m;
    }
    /* Here we just append new media at the end */
    for (j = 0; c_media[j]; j++)
      s_media[i++] = c_media[j];
    assert(i <= size);
  }

  mm = &session->sdp_media;
  for (i = 0; s_media[i]; i++) {
    m = s_media[i]; *mm = m; mm = &m->m_next;
  }
  *mm = NULL;

  return 0;
}

/** Check if @a session contains media that are rejected by @a remote. */ 
int soa_sdp_reject_is_needed(sdp_session_t const *session,
			     sdp_session_t const *remote)
{
  sdp_media_t const *sm, *rm;

  if (!remote)
    return 1;
  if (!session)
    return 0;

  for (sm = session->sdp_media, rm = remote->sdp_media; 
       sm && rm; sm = sm->m_next, rm = rm->m_next) {
    if (rm->m_rejected) {
      if (!sm->m_rejected)
	return 1;
    }
    else {
      sdp_mode_t send_mode = (rm->m_mode & sdp_recvonly) ? sdp_sendonly : 0;
      if (send_mode != (sm->m_mode & sdp_sendonly))
	return 1;
    }
  }

  if (sm)
    return 1;

  return 0;
}

/** If m= line is rejected by, remote mark m= line rejected within session */ 
int soa_sdp_reject(su_home_t *home,
		   sdp_session_t *session,
		   sdp_session_t const *remote)
{
  sdp_media_t *sm;
  sdp_media_t const *rm;

  if (!session || !session->sdp_media || !remote)
    return 0;

  rm = remote->sdp_media;

  for (sm = session->sdp_media; sm; sm = sm->m_next) {
    if (!rm || rm->m_rejected) {
      sm->m_rejected = 1;
      sm->m_mode = 0;
      sm->m_port = 0;
      sm->m_number_of_ports = 1;
      if (sm->m_format)
	sm->m_format->l_next = NULL;
      if (sm->m_rtpmaps)
	sm->m_rtpmaps->rm_next = NULL;
      sm->m_information = NULL;
      if (sm->m_connections)
	sm->m_connections->c_next = NULL;
      sm->m_bandwidths = NULL;
      sm->m_key = NULL;
      sm->m_attributes = NULL;
      sm->m_user = NULL;
    }

    if (rm)
      rm = rm->m_next;
  }

  return 0;
}

/** Check if @a session mode should be changed. */ 
int soa_sdp_mode_set_is_needed(sdp_session_t const *session,
			       sdp_session_t const *remote,
			       char const *hold)
{
  sdp_media_t const *sm, *rm, *rm_next;
  int hold_all;
  sdp_mode_t send_mode, recv_mode;

  SU_DEBUG_7(("soa_sdp_mode_set_is_needed(%p, %p, \"%s\"): called\n",
	      session, remote, hold ? hold : ""));

  if (!session )
    return 0;

  hold_all = str0cmp(hold, "*") == 0;

  rm = remote ? remote->sdp_media : NULL, rm_next = NULL;

  for (sm = session->sdp_media; sm; sm = sm->m_next, rm = rm_next) {
    rm_next = rm ? rm->m_next : NULL;

    if (sm->m_rejected)
      continue;

    if (rm) {
      send_mode = (rm->m_mode & sdp_recvonly) ? sdp_sendonly : 0;
      if (send_mode != (sm->m_mode & sdp_sendonly))
	return 1;
    }

    recv_mode = sm->m_mode & sdp_recvonly;
    if (recv_mode && hold &&
	(hold_all || strcasestr(hold, sm->m_type_name)))
      return 1;
  }

  return 0;
}


/** Update mode within session */ 
int soa_sdp_mode_set(sdp_session_t *session,
		     sdp_session_t const *remote,
		     char const *hold)
{
  sdp_media_t *sm;
  sdp_media_t const *rm, *rm_next;
  int hold_all;
  sdp_mode_t send_mode, recv_mode;

  SU_DEBUG_7(("soa_sdp_mode_set(%p, %p, \"%s\"): called\n",
	      session, remote, hold ? hold : ""));

  if (!session || !session->sdp_media)
    return 0;

  rm = remote ? remote->sdp_media : NULL, rm_next = NULL;

  hold_all = str0cmp(hold, "*") == 0;

  for (sm = session->sdp_media; sm; sm = sm->m_next, rm = rm_next) {
    rm_next = rm ? rm->m_next : NULL;

    if (sm->m_rejected)
      continue;

    send_mode = sdp_sendonly;
    if (rm)
      send_mode = (rm->m_mode & sdp_recvonly) ? sdp_sendonly : 0;

    recv_mode = sm->m_mode & sdp_recvonly;
    if (recv_mode && hold && (hold_all || strcasestr(hold, sm->m_type_name)))
      recv_mode = 0;

    sm->m_mode = recv_mode | send_mode;
  }

  return 0;
}

enum offer_answer_action {
  generate_offer,
  generate_answer,
  process_answer
};

/**
 * Updates the modified copy of local SDP based
 * on application provided local SDP and remote SDP.
 */
static int offer_answer_step(soa_session_t *ss,
			     enum offer_answer_action action,
			     char const *by)
{
  char c_address[64];
  sdp_session_t *local = ss->ss_local->ssd_sdp;
  sdp_session_t local0[1];

  sdp_session_t *user = ss->ss_user->ssd_sdp;
  unsigned user_version = ss->ss_user_version;

  sdp_session_t *remote = ss->ss_remote->ssd_sdp;
  unsigned remote_version = ss->ss_remote_version;

  sdp_origin_t o[1] = {{ sizeof(o) }};
  sdp_connection_t *c, c0[1] = {{ sizeof(c0) }};
  sdp_time_t t[1] = {{ sizeof(t) }};

  char const *phrase = "Internal Media Error";

  su_home_t tmphome[SU_HOME_AUTO_SIZE(8192)];

  su_home_auto(tmphome, sizeof tmphome);

  SU_DEBUG_7(("soa_static_offer_answer_action(%p, %s): called\n", ss, by));

  if (user == NULL)
    return soa_set_status(ss, 500, "No session set by user");

  if (action == generate_offer)
    remote = NULL;

  /* Pre-negotiation Step: Expand truncated remote SDP */
  if (local && remote) switch (action) {
  case generate_answer:
  case process_answer:
    if (sdp_media_count(remote, sdp_media_any, "*", 0, 0) < 
	sdp_media_count(local, sdp_media_any, "*", 0, 0)) {
      SU_DEBUG_5(("%s: remote %s is truncated: expanding\n",
		  by, action == generate_answer ? "offer" : "answer"));
      remote = soa_sdp_expand_media(tmphome, remote, local);
    }
  default:
    break;
  }
  
  /* Step A: Create local SDP (based on user-supplied SDP) */
  if (local == NULL) switch (action) {
  case generate_offer:
  case generate_answer:
    SU_DEBUG_7(("soa_static(%p, %s): generating local description\n", ss, by));

    local = local0;
    *local = *user, local->sdp_media = NULL;

    if (local->sdp_origin) {
      o->o_username = local->sdp_origin->o_username;
      /* o->o_address = local->sdp_origin->o_address; */
    }
    if (!o->o_address)
      o->o_address = c0; 
    local->sdp_origin = o;

    if (soa_init_sdp_origin(ss, o, c_address) < 0) {
      phrase = "Cannot Get IP Address for Media";
      goto internal_error;
    }

    break;

  case process_answer:
  default:
    goto internal_error;
  }

  /* Step B: upgrade local SDP (add m= lines to it)  */
  switch (action) {
  case generate_offer:
    /* Upgrade local SDP based on user SDP */
    if (local != local0 && ss->ss_local_user_version == user_version)
      break;
    if (local != local0)
      *local0 = *local, local = local0;
    SU_DEBUG_7(("soa_static(%p, %s): upgrade with local description\n", ss, by));
    soa_sdp_upgrade(ss, tmphome, local, user, user);
    break;
  case generate_answer:
    /* Upgrade local SDP based on remote SDP */
    if (ss->ss_local_remote_version == remote_version)
      break;
    if (soa_sdp_upgrade_is_needed(local, remote)) {
      if (local != local0)
	*local0 = *local, local = local0;
      SU_DEBUG_7(("soa_static(%p, %s): upgrade with remote description\n", ss, by));
      soa_sdp_upgrade(ss, tmphome, local, user, remote);
    }
    break;
  default:
    break;
  }

  /* Step C: reject media */
  switch (action) {
  case generate_offer:
    /* Local media is marked as rejected already in upgrade phase */
    break;
  case generate_answer:
  case process_answer:
    if (ss->ss_local_remote_version == remote_version)
      break;
    if (soa_sdp_reject_is_needed(local, remote)) {
      if (local != local0) {
	*local0 = *local, local = local0;
#define DUP_LOCAL(local)					 \
	do {							 \
	  if (!local->sdp_media) break;				 \
	  local->sdp_media =					 \
	    sdp_media_dup_all(tmphome, local->sdp_media, local); \
	  if (!local->sdp_media)				 \
	    goto internal_error;				 \
	} while (0)

	DUP_LOCAL(local);
      }
      SU_DEBUG_7(("soa_static(%p, %s): marking rejected media\n", ss, by));
      soa_sdp_reject(tmphome, local, remote);
    }
    break;
  default:
    break;
  }

  /* Step D: Set media mode bits */
  switch (action) {
  case generate_offer:
  case generate_answer:
  case process_answer:
    if (soa_sdp_mode_set_is_needed(local, remote, ss->ss_hold)) {
      if (local != local0) {
	*local = *local, local = local0;
	DUP_LOCAL(local);
      }

      soa_sdp_mode_set(local, remote, ss->ss_hold);
    }
    break;
  default:
    break;
  }

  soa_description_free(ss, ss->ss_previous);

  if (local == local0) {
    /* We have modfied local session: update origin-line */
    if (local->sdp_origin != o)
      *o = *local->sdp_origin, local->sdp_origin = o;
    o->o_version++;

    /* Do sanity checks for the created SDP */
    if (!local->sdp_subject)	/* s= is mandatory */
      local->sdp_subject = "-";
    if (!local->sdp_time)	/* t= is mandatory */
      local->sdp_time = t;

    /* Every m= line (even rejected one) must have a c= line 
     * or there must be a c= line at session level
     */
    c = local->sdp_origin->o_address;

    if (local->sdp_connection == NULL) {
      sdp_media_t *m;

      for (m = local->sdp_media; m; m = m->m_next)
	if (m->m_connections == NULL)
	  break;
      if (m)
	local->sdp_connection = c;
    }

    if (action == generate_offer) {
      /* Keep a copy of previous session state */
      *ss->ss_previous = *ss->ss_local;
      memset(ss->ss_local, 0, (sizeof *ss->ss_local));
      ss->ss_previous_user_version = ss->ss_local_user_version;
      ss->ss_previous_remote_version = ss->ss_local_remote_version;
    }

    SU_DEBUG_7(("soa_static(%p, %s): storing local description\n", ss, by));

    /* Update the unparsed and pretty-printed descriptions  */
    if (soa_description_set(ss, ss->ss_local, local, NULL, 0) < 0) {
      goto internal_error;
    }
  }

  /* Update version numbers */
  switch (action) {
  case generate_offer:
    ss->ss_local_user_version = user_version;
    break;
  case generate_answer:
    ss->ss_local_user_version = user_version;
    ss->ss_local_remote_version = remote_version;
    break;
  case process_answer:
    ss->ss_local_remote_version = remote_version;
  default:
    break;
  }

  su_home_deinit(tmphome);
  return 0;

 internal_error:
  su_home_deinit(tmphome);
  return soa_set_status(ss, 500, phrase);
}

/**
 * Generates offer based on local SDP.
 */
static int soa_static_generate_offer(soa_session_t *ss,
				     soa_callback_f *completed)
{
  if (!ss->ss_user->ssd_sdp)
    return soa_set_status(ss, 500, "No session set by user");

  if (offer_answer_step(ss, generate_offer, "soa_generate_offer") < 0)
    return -1;

  return soa_base_generate_offer(ss, NULL);
}

static int soa_static_generate_answer(soa_session_t *ss,
				      soa_callback_f *completed)
{
  /* NOTE:
   * - local SDP might have changed
   * - remote SDP might have been updated 
   */

  if (offer_answer_step(ss, generate_answer, "soa_generate_answer") < 0)
    return -1;

  return soa_base_generate_answer(ss, NULL);
}

static int soa_static_process_answer(soa_session_t *ss,
				     soa_callback_f *completed)
{
  /* NOTE:
   * - both local and remote information is available
   * - local SDP might have changed
   * - remote SDP might have been updated 
   */
  if (offer_answer_step(ss, process_answer, "soa_process_answer") < 0)
    return -1;

  return soa_base_process_answer(ss, NULL);
}

/** Process rejected offer */
static int soa_static_process_reject(soa_session_t *ss,
				     soa_callback_f *completed)
{
  struct soa_description d[1];

  *d = *ss->ss_local;
  *ss->ss_local = *ss->ss_previous;
  memset(ss->ss_previous, 0, (sizeof *ss->ss_previous));
  soa_description_free(ss, d);

  return soa_base_process_reject(ss, NULL);
}

static int soa_static_activate(soa_session_t *ss, char const *option)
{
  return soa_base_activate(ss, option);
}

static int soa_static_deactivate(soa_session_t *ss, char const *option)
{
  return soa_base_deactivate(ss, option);
}

static void soa_static_terminate(soa_session_t *ss, char const *option)
{
  soa_description_free(ss, ss->ss_user);
  soa_base_terminate(ss, option);
}
