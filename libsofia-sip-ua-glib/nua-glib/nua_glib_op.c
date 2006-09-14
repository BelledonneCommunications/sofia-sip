/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005-2006 Nokia Corporation.
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * Copyright (C) 2005 Collabora Ltd.
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

/**@file nua_glib.c Interface towards libsofia-sip-ua.
 * 
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 * @author Rob Taylor <rob.taylor@collabora.co.uk>
 * @author Pekka Pessi <pekka.pessi@nokia.com>
 */

#include <sofia-sip/nua_glib.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "nua_glib_priv.h"
#include "nua_glib_op.h"

static void priv_oper_assign(NuaGlibOp *op, sip_method_t method);

/**
 * Creates a new operation object and stores it the list of
 * active operations for 'self'.
 */
NuaGlibOp *nua_glib_op_create(NuaGlib *self, 
			      sip_method_t method,
			      const char *address,
			      tag_type_t tag, tag_value_t value, ...)
{
  NuaGlibOp *op, *old;
  const char* method_name = sip_method_name(method, "<NONE>");

  ta_list ta;
   
  enter;

  for (old = self->priv->operations; old; old = old->op_next)
    if (!old->op_persistent)
      break;

  if (address) {
    int have_url = 1;
    sip_to_t *to;

    to = sip_to_make(self->priv->home, address);

    if (to == NULL) {
      /*TODO, error returns*/
      g_warning("%s: %s: invalid address: %s\n", self->priv->name, method_name, address);
      return NULL;
    }

    /* Try to make sense out of the URL */
    if (url_sanitize(to->a_url) < 0) {
      /*TODO, error returns*/
      g_warning("%s: %s: invalid address\n", self->priv->name, method_name);
      return NULL;
    }

    if (!(op = su_zalloc(self->priv->home, sizeof(*op)))) {
      /*TODO, error returns*/
      g_warning("%s: %s: cannot create handle\n", self->priv->name, method_name);
      return NULL;
    }

    op->op_parent = self;
    op->op_next = self->priv->operations;
    op->op_prev_state = -1;
    self->priv->operations = op;      

    if (method == sip_method_register)
      have_url = 0;
    
    ta_start(ta, tag, value); 
     
    op->op_handle = nua_handle(self->priv->nua, op, 
                               TAG_IF(have_url, NUTAG_URL(to->a_url)), 
                               SIPTAG_TO(to),
                               ta_tags(ta));

    ta_end(ta);  
     
    op->op_ident = sip_header_as_string(self->priv->home, (sip_header_t *)to);

    priv_oper_assign(op, method);
    
    if (!op->op_persistent) {
      NuaGlibOp *old_next;
      for (; old; old = old_next) {      /* Clean old handles */
        old_next = old->op_next;
        if (!old->op_persistent && !old->op_callstate)
          nua_glib_op_destroy(self, old);
      }
    }
    
    su_free(self->priv->home, to);
  }
  else if (method) 
    priv_oper_assign(op = old, method);
  else
    return old;

  if (!op) {
    if (address)
      /*TODO, error returns*/
      g_warning("%s: %s: invalid destination\n", self->priv->name, method_name);
    else
      /*TODO, error returns*/
      g_warning("%s: %s: no destination\n", self->priv->name, method_name);
    return NULL;
  }

  return op;
}

/**
 * Creates an operation handle and binds it to an existing handle 
 * 'nh' (does not create a new nua handle with nua_handle()).
 */
NuaGlibOp *nua_glib_op_create_with_handle(NuaGlib *self, 
					  sip_method_t method,
					  nua_handle_t *nh,
					  sip_from_t const *from)
{
  NuaGlibOp *op;

  enter;

  if ((op = su_zalloc(self->priv->home, sizeof(*op)))) {
    op->op_parent = self;
    op->op_next = self->priv->operations;
    self->priv->operations = op;      

    priv_oper_assign(op, method);
    nua_handle_bind(op->op_handle = nh, op);
    op->op_ident = sip_header_as_string(self->priv->home, (sip_header_t*)from);
  }
  else {
    SU_DEBUG_1(("%s: cannot create operation object for method=%d\n", 
		self->priv->name, (int)method));
  }

  return op;
}

/** Delete operation and attached handles and identities */
void nua_glib_op_destroy(NuaGlib *self, NuaGlibOp *op)
{
  NuaGlibOp **prev;

  if (!op)
    return;

  g_assert(op->data == NULL);

  /* Remove from queue */
  for (prev = &self->priv->operations; 
       *prev && *prev != op; 
       prev = &(*prev)->op_next)
    ;
  if (*prev)
    *prev = op->op_next, op->op_next = NULL;

  if (op->op_authlist)
    nua_glib_auth_clear(self, op);

  if (op->op_handle)
    nua_handle_destroy(op->op_handle), op->op_handle = NULL;

  su_free(self->priv->home, op);
}

/**
 * Finds an operation by nua handle.
 */
NuaGlibOp *nua_glib_op_find_by_handle(NuaGlib *self, nua_handle_t *handle)
{
  NuaGlibOp *op;

  for (op = self->priv->operations; op; op = op->op_next)
    if (op->op_handle == handle)
      break;

  return op;
}

/**
 * Finds a call/session operation (an operation that has non-zero
 * op_callstate).
 */
NuaGlibOp *nua_glib_op_find_session(NuaGlib *self)
{
  NuaGlibOp *op;

  for (op = self->priv->operations; op; op = op->op_next)
    if (op->op_callstate)
      break;

  return op;
}


/**
 * Checks whether 'op' is a valid handle or not.
 *
 * @return op if valid, NULL otherwise
 */
NuaGlibOp *nua_glib_op_check(NuaGlib *self, NuaGlibOp *op)
{
  NuaGlibOp *tmp;

  for (tmp = self->priv->operations; tmp; tmp = tmp->op_next)
    if (tmp == op)
      return op;

  return NULL;
}

/* ====================================================================== 
 * static functions 
* ====================================================================== */

static void 
priv_oper_assign(NuaGlibOp *op, sip_method_t method)
{
  if (!op)
    return;

  op->op_method = method;

  op->op_persistent = 
    method == sip_method_subscribe ||
    method == sip_method_register ||
    method == sip_method_publish;
}

