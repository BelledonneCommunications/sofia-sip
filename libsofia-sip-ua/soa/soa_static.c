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
 * $Date: 2005/08/17 14:51:23 $
 */

#include "config.h"

const char soa_static_c_id[] =
"$Id: soa_static.c,v 1.1 2005/08/17 14:51:23 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <su_tag_class.h>
#include <su_tag_class.h>
#include <su_tagarg.h>
#include <su_strlst.h>

#include "soa.h"
#include <sdp.h>
#include "soa_session.h"

#define NONE ((void *)-1)
#define XXX assert(!"implemented")

struct soa_static_session 
{
  soa_session_t session[1];
};

static int soa_static_init(char const *, soa_session_t *, soa_session_t *);
static void soa_static_deinit(soa_session_t *);
static int soa_static_set_params(soa_session_t *ss, tagi_t const *tags);
static int soa_static_get_params(soa_session_t const *ss, tagi_t *tags);
static tagi_t *soa_static_get_paramlist(soa_session_t const *ss);
static int soa_static_generate_offer(soa_session_t *ss, 
				    soa_callback_f *completed);
static int soa_static_generate_answer(soa_session_t *ss, 
				     soa_callback_f *completed);
static void soa_static_activate_session(soa_session_t *ss, char const *option);
static void soa_static_terminate_session(soa_session_t *ss, char const *option);

struct soa_session_actions const soa_static_actions = 
  {
    (sizeof soa_static_actions),
    sizeof (struct soa_static_session),
    soa_static_init,
    soa_static_deinit,
    soa_static_set_params,
    soa_static_get_params,
    soa_static_get_paramlist,
    soa_default_media_features,
    soa_default_sip_required,
    soa_default_sip_support,
    soa_default_remote_sip_features,
    soa_static_generate_offer,
    soa_static_generate_answer,
    soa_static_activate_session,
    soa_static_terminate_session
  };

/* Initialize session */
static int soa_static_init(char const *name, 
			   soa_session_t *ss, 
			   soa_session_t *parent)
{
  return soa_default_init(name, ss, parent);
}

static void soa_static_deinit(soa_session_t *ss)
{
  soa_default_deinit(ss);
}

static int soa_static_set_params(soa_session_t *ss, tagi_t const *tags)
{
  return soa_default_set_params(ss, tags);
}

static int soa_static_get_params(soa_session_t const *ss, tagi_t *tags)
{
  return soa_default_get_params(ss, tags);
}

static tagi_t *soa_static_get_paramlist(soa_session_t const *ss)
{
  return soa_default_get_paramlist(ss);
}

static int soa_static_generate_offer(soa_session_t *ss,
				  soa_callback_f *completed)
{
  return soa_default_generate_offer(ss, completed);
}

static int soa_static_generate_answer(soa_session_t *ss, 
				     soa_callback_f *completed)
{
  return soa_default_generate_answer(ss, completed);
}

static void soa_static_activate_session(soa_session_t *ss, char const *option)
{
  return soa_default_activate_session(ss, option);
}

static void soa_static_terminate_session(soa_session_t *ss, char const *option)
{
  return soa_default_terminate_session(ss, option);
}
