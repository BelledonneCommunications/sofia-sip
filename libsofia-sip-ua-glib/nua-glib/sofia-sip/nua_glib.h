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

#ifndef __NUA_GLIB_H__
#define __NUA_GLIB_H__

#include <glib-object.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_status.h>

G_BEGIN_DECLS

/**@file nua_glib.h Glib Interface for Sofia-SIP User-Agent API (NUA)
 *
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 * @author Rob Taylor <rob.taylor@collabora.co.uk>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 */

typedef struct _NuaGlibClass NuaGlibClass;
typedef struct _NuaGlib NuaGlib;
typedef struct _NuaGlibPrivate NuaGlibPrivate;
typedef struct _NuaGlibOp NuaGlibOp;

struct _NuaGlibClass {
  GObjectClass parent_class;
};

struct _NuaGlib {
  GObject parent;
  NuaGlibPrivate *priv;
};

GType nua_glib_get_type(void);

/* TYPE MACROS */
#define NUA_GLIB_TYPE \
  (nua_glib_get_type())
#define NUA_GLIB(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), NUA_GLIB_TYPE, NuaGlib))
#define NUA_GLIB_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), NUA_GLIB_TYPE, NuaGlibClass))
#define NUA_GLIB_IS(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), NUA_GLIB_TYPE))
#define NUA_GLIB_IS_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), NUA_GLIB_TYPE))
#define NUA_GLIB_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), NUA_GLIB_TYPE, NuaGlibClass))

/*value enums*/

/**
 * enum for describing media availiability
 */
typedef enum {
  NUA_GLIB_MEDIA_DISABLED = -4, /**< Media not negotiated */
  NUA_GLIB_MEDIA_REJECTED = -8, /**< Media rejected in negotiation */
  NUA_GLIB_MEDIA_INACTIVE = 0,  /**< SDP O-A state for media */
  NUA_GLIB_MEDIA_SENDONLY = 1,  /**< SDP O-A state for media */
  NUA_GLIB_MEDIA_RECVONLY = 2,  /**< SDP O-A state for media */
  NUA_GLIB_MEDIA_SENDRECV = NUA_GLIB_MEDIA_SENDONLY 
                            | NUA_GLIB_MEDIA_RECVONLY
} NuaGlibMediaActive;

NuaGlibOp * nua_glib_invite (NuaGlib *self, const char *destination, const char *local_sdp);

void nua_glib_answer (NuaGlib *self, NuaGlibOp *op, int status, const char *phrase, const char *sdp);

void nua_glib_bye (NuaGlib *cli, NuaGlibOp *op);

void nua_glib_cancel (NuaGlib *cli, NuaGlibOp *op);

NuaGlibOp* nua_glib_options (NuaGlib *self, const char *destination_uri);

NuaGlibOp* nua_glib_message (NuaGlib *self, const char *destination_uri, const char *message);

void nua_glib_info (NuaGlib *self, NuaGlibOp *op, const char *content_type, const char *message);

void nua_glib_refer (NuaGlib *self, NuaGlibOp *op, const char* destination);

void nua_glib_follow_refer (NuaGlib *cli, NuaGlibOp *op);

void nua_glib_hold (NuaGlib *self, NuaGlibOp *op, int hold);

void nua_glib_notify (NuaGlib *self, NuaGlibOp* op);

NuaGlibOp* nua_glib_watch (NuaGlib *self, char *event);

NuaGlibOp* nua_glib_subscribe (NuaGlib *self, const char *uri, gboolean eventlist);

void nua_glib_unsubscribe (NuaGlib *self, NuaGlibOp *op);

void nua_glib_reregister (NuaGlib *self, NuaGlibOp *op);

NuaGlibOp* nua_glib_register (NuaGlib *self, const char *registrar);

void nua_glib_unregister (NuaGlib *self, NuaGlibOp *op);

NuaGlibOp *nua_glib_unregister_direct (NuaGlib *self, const char *registrar);

void nua_glib_republish (NuaGlib *self, NuaGlibOp *op, const char *note);

NuaGlibOp* nua_glib_publish (NuaGlib *self, const char *note);

void nua_glib_unpublish (NuaGlib *cli, NuaGlibOp *op);

NuaGlibOp* nua_glib_unpublish_direct (NuaGlib *self);

void nua_glib_redirect(NuaGlib *self, NuaGlibOp *op, const char *contact);

void nua_glib_auth_add(NuaGlib *self, NuaGlibOp *op, const char *method, const char *realm, const char *user, const char *password);

void nua_glib_auth_clear(NuaGlib *self, NuaGlibOp *op);

/*helper functions*/

gpointer nua_glib_op_get_data(NuaGlibOp *op);
void nua_glib_op_set_data (NuaGlibOp *op, gpointer data);
NuaGlib *nua_glib_op_owner (NuaGlibOp *op);
sip_method_t nua_glib_op_method_type (NuaGlibOp *op);
const gchar * nua_glib_op_get_identity(NuaGlibOp *op);

G_END_DECLS

#endif /* __NUA_GLIB_H__ */
