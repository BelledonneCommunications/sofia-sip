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

/**@ingroup msg_parser
 * @file msg_generic.c
 * @brief Functions for generic headers
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Thu Jan 23 20:08:00 2003 ppessi
 * 
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#include <sofia-sip/su_alloc.h>

#include "sofia-sip/msg.h"
#include "sofia-sip/bnf.h"
#include "sofia-sip/msg_parser.h"
#include "sofia-sip/msg_header.h"

/**
 * Parse a generic header.
 *
 * The function msg_generic_d() parses a generic header structure.
 *
 * @param home memory home [IN]
 * @param h    header structure [IN/OUT]
 * @param s    string to be parsed [IN]
 * @param slen length of the string [IN]
 *
 * @retval 0 when successful, 
 * @retval -1 upon an error.
 */
int msg_generic_d(su_home_t *home,
		  msg_header_t *h,
		  char *s, 
		  int slen)
{
  h->sh_generic->g_string = s;
  return 0;
}

/**
 * Encode a generic header.
 *
 * The function @c msg_generic_e encodes a generic header.
 *
 */
int msg_generic_e(char b[], int bsiz, msg_header_t const *h, int flags)
{
  msg_generic_t const *g = h->sh_generic;  
  int n = strlen(g->g_string);
  
  if (bsiz > n)
    strcpy(b, g->g_string);

  return n;
}

/** Calculate the size of strings associated with a @c msg_generic_t object. */
int msg_generic_dup_xtra(msg_header_t const *h, int offset)
{
  msg_generic_t const *g = h->sh_generic;
  return offset + MSG_STRING_SIZE(g->g_string);
}

/** Duplicate one @c msg_generic_t object. */
char *msg_generic_dup_one(msg_header_t *dst,
			  msg_header_t const *src,
			  char *b,
			  int xtra)
{
  char *end = b + xtra;
  MSG_STRING_DUP(b, dst->sh_generic->g_string, src->sh_generic->g_string);
  assert(b <= end);
  return b;
}

int msg_numeric_d(su_home_t *home,
		  msg_header_t *h,
		  char *s,
		  int slen)
{
  int retval;

  retval = msg_uint32_d(&s, (uint32_t *)&h->sh_numeric->x_value);

  if (*s)
    return -1;

  return retval;
}

int msg_numeric_e(char b[], int bsiz, msg_header_t const *h, int flags)
{
  return snprintf(b, bsiz, "%lu", h->sh_numeric->x_value);
}

/* ====================================================================== */
/* Comma-separated list */

int msg_list_d(su_home_t *home, msg_header_t *h, char *s, int slen)
{
  return msg_commalist_d(home, &s, &h->sh_list->k_items, NULL);
}

int msg_list_e(char b[], int bsiz, msg_header_t const *h, int flags)
{
  int compact = MSG_IS_COMPACT(flags);
  char *b0 = b, *end = b + bsiz;
  
  MSG_COMMALIST_E(b, end, h->sh_list->k_items, compact);
  MSG_TERM_E(b, end);

  return b - b0;
}

/**@internal 
 * Extra size of a msg_auth_t object.
 *
 * This function calculates extra size required by a msg_auth_t object.
 *
 * @param a pointer to a msg_auth_t object
 *
 * @return
 *   Size of strings related to msg_auth_t object.
 */
int msg_list_dup_xtra(msg_header_t const *h, int offset)
{
  MSG_PARAMS_SIZE(offset, h->sh_list->k_items);
  return offset;
}

char *msg_list_dup_one(msg_header_t *dst,
		       msg_header_t const *src,
		       char *b, 
		       int xtra)
{
  char *end = b + xtra;
  msg_param_t const ** items = (msg_param_t const **)&dst->sh_list->k_items;

  b = msg_params_dup(items, src->sh_list->k_items, b, xtra);
    
  assert(b <= end);

  return b;
}

/** Append a list of constant items to a list. */
int msg_list_append_items(su_home_t *home, 
			  msg_list_t *k, 
			  msg_param_t const items[])
{
  int i;

  if (k == NULL) return -1;
  if (items == NULL) return 0;

  for (i = 0; items[i]; i++) {
    if (msg_params_add(home, (msg_param_t **)&k->k_items, items[i]) < 0)
      return -1;
  }

  if (i > 0)
    msg_fragment_clear(k->k_common);

  return 0;
}

/** Replace a list of constant items */
int msg_list_replace_items(su_home_t *home, msg_list_t *k, 
			   msg_param_t const items[])
{
  int i;

  if (k == NULL) return -1;
  if (items == NULL) return 0;

  for (i = 0; items[i]; i++) {
    if (msg_params_replace(home, (msg_param_t **)&k->k_items, items[i]) < 0)
      return -1;
  }

  if (i > 0)
    msg_fragment_clear(k->k_common);

  return 0;
}
