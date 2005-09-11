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
 * $Date: 2005/09/09 10:56:31 $
 */

#include "config.h"

const char soa_static_c_id[] =
"$Id: soa_static.c,v 1.2 2005/09/09 10:56:31 ppessi Exp $";

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

typedef struct soa_static_session
{
  soa_session_t sss_session[1];
}
soa_static_session_t;

static int soa_static_init(char const *, soa_session_t *, soa_session_t *);
static void soa_static_deinit(soa_session_t *);
static int soa_static_set_params(soa_session_t *ss, tagi_t const *tags);
static int soa_static_get_params(soa_session_t const *ss, tagi_t *tags);
static tagi_t *soa_static_get_paramlist(soa_session_t const *ss);
static int soa_static_generate_offer(soa_session_t *ss,
				    soa_callback_f *completed);
static int soa_static_generate_answer(soa_session_t *ss,
				     soa_callback_f *completed);
static int soa_static_process_answer(soa_session_t *ss,
					    soa_callback_f *completed);
static void soa_static_activate(soa_session_t *ss, char const *option);
static void soa_static_terminate(soa_session_t *ss, char const *option);

struct soa_session_actions const soa_static_actions =
  {
    (sizeof soa_static_actions),
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
    soa_base_set_capability_sdp,
    soa_base_set_remote_sdp,
    soa_base_set_local_sdp,
    soa_static_generate_offer,
    soa_static_generate_answer,
    soa_static_process_answer,
    soa_static_activate,
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

static tagi_t *soa_static_get_paramlist(soa_session_t const *ss)
{
  return soa_base_get_paramlist(ss);
}

static int soa_static_generate_offer(soa_session_t *ss,
				     soa_callback_f *completed)
{
  sdp_session_t *sdp;
  sdp_media_t *m;
  uint16_t port = 5004;

  if (ss->ss_local->ssd_sdp == NULL) {
    if (ss->ss_caps->ssd_unparsed == NULL)
      return soa_set_status(ss, 500, "No local session available");
  }

  if (ss->ss_local->ssd_sdp)
    return 0;			/* We are done */

  /* Generate a dummy SDP offer based on our capabilities */
  if (soa_set_local_sdp(ss, ss->ss_caps->ssd_unparsed, -1) < 0)
    return -1;
  sdp = ss->ss_local->ssd_sdp; assert(ss->ss_local->ssd_sdp);

  for (m = sdp->sdp_media; m; m = m->m_next)
    if (m->m_port == 0)
      m->m_port = port, port += 2;

  return soa_base_generate_offer(ss, NULL);
}

static int soa_static_generate_answer(soa_session_t *ss,
				      soa_callback_f *completed)
{
  sdp_session_t *sdp;
  sdp_media_t *m;
  uint16_t port = 5004;

  if (ss->ss_local->ssd_sdp == NULL) {
    if (ss->ss_caps->ssd_unparsed == NULL)
      return soa_set_status(ss, 500, "No local session available");
  }

  if (ss->ss_local->ssd_sdp)
    return 0;			/* We are done */

  /* Generate a dummy SDP offer based on our capabilities */
  if (soa_set_local_sdp(ss, ss->ss_caps->ssd_unparsed, -1) < 0)
    return -1;
  sdp = ss->ss_local->ssd_sdp; assert(ss->ss_local->ssd_sdp);

  for (m = sdp->sdp_media; m; m = m->m_next)
    if (m->m_port == 0)
      m->m_port = port, port += 2;

  return soa_base_generate_answer(ss, NULL);
}

static int soa_static_process_answer(soa_session_t *ss,
					    soa_callback_f *completed)
{
  return soa_base_process_answer(ss, NULL);
}

static void soa_static_activate(soa_session_t *ss, char const *option)
{
  soa_base_activate(ss, option);
}

static void soa_static_terminate(soa_session_t *ss, char const *option)
{
  soa_description_free(ss, ss->ss_local);
  soa_base_terminate(ss, option);
}
