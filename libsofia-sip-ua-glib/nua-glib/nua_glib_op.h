/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005,2006 Nokia Corporation.
 * Copyright (C) 2005 Collabora Ltd.
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

#ifndef __NUA_GLIB_OP_H__
#define __NUA_GLIB_OP_H__

#include <sofia-sip/nua_glib.h>

G_BEGIN_DECLS

NuaGlibOp *nua_glib_op_create(NuaGlib *self, 
			      sip_method_t method,
			      const char *address,
			      tag_type_t tag, tag_value_t value, ...);
NuaGlibOp *nua_glib_op_create_with_handle(NuaGlib *self, 
			       sip_method_t method,
			       nua_handle_t *nh,
			       sip_from_t const *from);
void nua_glib_op_destroy(NuaGlib *self, NuaGlibOp *op);
NuaGlibOp *nua_glib_op_find_by_handle(NuaGlib *self, nua_handle_t *handle);
NuaGlibOp *nua_glib_op_find_session(NuaGlib *self);
NuaGlibOp *nua_glib_op_check(NuaGlib *self, NuaGlibOp *op);

G_END_DECLS

#endif /* __NUA_GLIB_OP_H__ */
