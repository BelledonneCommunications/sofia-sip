/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * * This library is free software; you can redistribute it and/or
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

/**
 * @file nua_common.c
 * @brief 
 * 
 * @author Pekka.Pessi@nokia.com
 * 
 * @date Created: Tue Apr 26 13:23:17 2005 ppessi
 * 
 * $Date: 2005/09/21 11:58:19 $
 */

#include "config.h"

const char nua_common_c_id[] = 
  "$Id: nua_common.c,v 1.2 2005/09/21 11:58:19 kaiv Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <su_tag_class.h>
#include <su_tag_class.h>
#include <su_tagarg.h>

#include <stdio.h>

#include <su_tag_io.h>

#define SU_LOG (nua_log)
#include <su_debug.h>

#define SU_ROOT_MAGIC_T   struct nua_s
#define SU_MSG_ARG_T      struct event_s

#include <su_wait.h>

#include <su_strlst.h>

#include "nua.h"
#include "nua_tag.h"

#include <sip_protos.h>
#include <nta.h>
#include <nea.h>

#include <auth_client.h>
#if HAVE_SMIME 		/* Start NRC Boston */
#include "smimec.h"
#endif                  /* End NRC Boston */

#include <sdp.h>

#include "nua_stack.h"

/** Create an operation handle 
 *
 * Allocates a new operation handle and associated storage.
 *
 * @param nua         Pointer to NUA stack object
 * @param hmagic      Pointer to callback context
 * @param tags        List of tagged parameters
 *
 * @retval non-NULL  Pointer to operation handle
 * @retval NULL    Creation failed
 *
 * @par Related tags:
 *     Creates a copy of provided tags and they will 
 *     be used with every operation.
 *
 * @par Events:
 *     none
 *
 * @note
 * This function is called by both stack and application sides.
 */
nua_handle_t *nh_create_handle(nua_t *nua, nua_hmagic_t *hmagic,
			       tagi_t *tags)
{
  nua_handle_t *nh;

  enter;

  assert(nua->nua_home);

  if ((nh = su_home_clone(nua->nua_home, sizeof(*nh)))) {
    url_string_t const *url = NULL;
    sip_to_t to[1];
    sip_to_t const *p_to = NULL;
    sip_from_t from[1];
    sip_from_t const *p_from = NULL;

    tl_gets(tags,	/* These does not change while nh lives */
	    SIPTAG_FROM_REF(p_from),
	    SIPTAG_TO_REF(p_to),
	    NUTAG_URL_REF(url),
	    TAG_END());

    if (!p_from && nua->nua_from) {
      *from = *nua->nua_from;
      from->a_params = NULL;
    } else {
      p_from = (void *)-1;
    }

    if (!p_to && url) {
      void *tbf = NULL;

      if (url_is_string(url))
	url = tbf = url_hdup(nh->nh_home, url->us_url);

      *sip_to_init(to)->a_url = *url->us_url;

      to->a_url->url_params = NULL;
      to->a_url->url_headers = NULL;

      nh->nh_ds->ds_remote = sip_to_dup(nh->nh_home, to);
      
      if (tbf)
	su_free(nh->nh_home, tbf);
    } else {
      p_to = (void *)-1;
    }

#if HAVE_PTHREAD_H
    pthread_rwlock_init(nh->nh_refcount, NULL);
#endif

    nh->nh_valid = nua_handle;
    nh->nh_nua = nua;
    nh->nh_magic = hmagic;
    nh->nh_tags = tl_tlist(nh->nh_home, 
			   TAG_IF(!p_from, SIPTAG_FROM(from)),
			   TAG_IF(!p_to, SIPTAG_TO(to)),
			   TAG_NEXT(tags));

    tl_gets(nh->nh_tags,	/* These does not change while nh lives */
	    SIPTAG_FROM_REF(nh->nh_ds->ds_local),
	    SIPTAG_TO_REF(nh->nh_ds->ds_remote),
	    TAG_END());
  }

  return nh_incref(nh);
}
