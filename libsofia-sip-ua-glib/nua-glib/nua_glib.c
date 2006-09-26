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
 * @author Martti Mela <martti.mela@nokia.com>
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include <glib.h>

#include "sofia-sip/nua_glib.h"
#include "nua_glib_priv.h"
#include "nua_glib_op.h"
#include "nua_glib_marshal.h"

/*=============== Class and Object init ===============*/
G_DEFINE_TYPE(NuaGlib, nua_glib, G_TYPE_OBJECT);
  
/*signal enum*/
enum
{
  NGSIG_CALL_FORKED = 1,
  NGSIG_INCOMING_INVITE,
  NGSIG_INCOMING_REINVITE,
  NGSIG_CALL_STATE_CHANGED,
  NGSIG_INCOMING_ACTIVE,
  NGSIG_CALL_TERMINATED,
  NGSIG_INCOMING_PRACK,
  NGSIG_INCOMING_BYE,
  NGSIG_INCOMING_CANCEL,
  NGSIG_INCOMING_MESSAGE,
  NGSIG_INCOMING_INFO,
  NGSIG_INCOMING_REFER,
  NGSIG_INCOMING_NOTIFY,

  NGSIG_ERROR,
  NGSIG_SHUTDOWN,

  NGSIG_REGISTER_ANSWERED,
  NGSIG_UNREGISTER_ANSWERED,
  NGSIG_PUBLISH_ANSWERED,
  NGSIG_INVITE_ANSWERED,
  NGSIG_BYE_ANSWERED,
  NGSIG_CANCEL_ANSWERED,
  NGSIG_MESSAGE_ANSWERED,
  NGSIG_INFO_ANSWERED,
  NGSIG_REFER_ANSWERED,
  NGSIG_SUBSCRIBE_ANSWERED,
  NGSIG_UNSUBSCRIBE_ANSWERED,
  NGSIG_NOTIFY_ANSWERED,
  NGSIG_OPTIONS_ANSWERED,

  NGSIG_AUTH_REQUIRED,

  NGSIG_LAST_SIGNAL
};

/*=============== Static variables ===============*/

static guint signals[NGSIG_LAST_SIGNAL] = {0};

enum
{
  PROP_ADDRESS = 1,
  PROP_PASSWORD,
  PROP_CONTACT,
  PROP_PROXY,
  PROP_REGISTRAR,
  PROP_STUN_SERVER,
  LAST_PROPERTY
};

static GObjectClass *parent_class=NULL;  

/*=============== Private function declarations ===============*/

static int sof_init(NuaGlibPrivate *priv, const char *contact);
static void priv_submit_authlist(NuaGlibOp *op);
static void priv_oper_handle_auth (NuaGlib *self, NuaGlibOp *op, sip_t const *sip, tagi_t *tags);
static void priv_oper_check_response_for_auth(NuaGlib *self, NuaGlibOp *op, int status, sip_t const *sip, tagi_t *tags);
static void sof_callback(nua_event_t event,
		  int status, char const *phrase,
		  nua_t *nua, NuaGlib *self,
		  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		  tagi_t tags[]);

static void sof_r_register(int status, char const *phrase,
		      nua_t *nua, NuaGlib *self,
		      nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		      tagi_t tags[]);

static void sof_r_unregister(int status, char const *phrase,
		      nua_t *nua, NuaGlib *self,
		      nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		      tagi_t tags[]);

static void sof_r_publish(int status, char const *phrase,
		   nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_r_invite(int status, char const *phrase,
		  nua_t *nua, NuaGlib *self,
		  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		  tagi_t tags[]);
static void sof_i_fork(int status, char const *phrase,
		nua_t *nua, NuaGlib *self,
		nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		tagi_t tags[]);

static void sof_i_invite(nua_t *nua, NuaGlib *self,
			 nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
			 tagi_t tags[]);

static void sof_i_state(int status, char const *phrase, 
			nua_t *nua, NuaGlib *self,
			nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
			tagi_t tags[]);

static void sof_i_active(nua_t *nua, NuaGlib *self,
		    nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		    tagi_t tags[]);

static void sof_i_terminated(int status, char const *phrase, 
		      nua_t *nua, NuaGlib *self,
		      nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		      tagi_t tags[]);

static void sof_i_prack(nua_t *nua, NuaGlib *self,
		 nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		 tagi_t tags[]);

static void sof_r_bye(int status, char const *phrase, 
		      nua_t *nua, NuaGlib *self,
		      nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		      tagi_t tags[]);

static void sof_i_bye(nua_t *nua, NuaGlib *self,
		 nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		 tagi_t tags[]);

static void sof_i_cancel(nua_t *nua, NuaGlib *self,
		    nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		    tagi_t tags[]);

static void sof_r_cancel(int status, char const *phrase, 
			 nua_t *nua, NuaGlib *self,
			 nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
			 tagi_t tags[]);

static void sof_r_message(int status, char const *phrase,
		   nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_i_message(nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_r_info(int status, char const *phrase,
		nua_t *nua, NuaGlib *self,
		nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		tagi_t tags[]);

static void sof_i_info(nua_t *nua, NuaGlib *self,
		nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		tagi_t tags[]);

static void sof_r_refer(int status, char const *phrase,
		   nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_i_refer(nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_r_subscribe(int status, char const *phrase,
		     nua_t *nua, NuaGlib *self,
		     nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		     tagi_t tags[]);

static void sof_r_unsubscribe(int status, char const *phrase,
		       nua_t *nua, NuaGlib *self,
		       nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		       tagi_t tags[]);

static void sof_r_notify(int status, char const *phrase,
		   nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_i_notify(nua_t *nua, NuaGlib *self,
		    nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		    tagi_t tags[]);

static void sof_r_options(int status, char const *phrase,
		   nua_t *nua, NuaGlib *self,
		   nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		   tagi_t tags[]);

static void sof_r_shutdown(int status, char const *phrase, 
		    nua_t *nua, NuaGlib *self,
		    nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		    tagi_t tags[]);

static void sof_r_get_params(int status, char const *phrase,
		      nua_t *nua, NuaGlib *self,
		      nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		      tagi_t tags[]);

static void sof_i_error(nua_t *nua, NuaGlib *self, nua_handle_t *nh, NuaGlibOp *op, 
		 int status, char const *phrase,
		 tagi_t tags[]);

/*=============== Function definitions ===============*/

void final_shutdown(NuaGlib *self)
{
  g_object_unref(self);
}

static GObject *
nua_glib_constructor (GType                  type,
		      guint                  n_construct_properties,
		      GObjectConstructParam *construct_properties)
{
  GObject *obj;
  int res = 0;
  GSource *gsource;
  NuaGlib *self;

  {
    /* Invoke parent constructor.
     * this calls our init, and then set_property with any
     * CONSTRUCT params
     */
    NuaGlibClass *klass;
    klass = NUA_GLIB_CLASS (g_type_class_peek (NUA_GLIB_TYPE));
    parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
    obj = parent_class->constructor (type,
                                     n_construct_properties,
                                     construct_properties);
  }
  
  self = NUA_GLIB(obj);

  /* create a su event loop and connect it to glib */
  self->priv->root = su_root_source_create(self);
  assert(self->priv->root);
  gsource = su_root_gsource(self->priv->root);
  assert(gsource);
  g_source_attach(gsource, NULL);

  /*check address has been set*/
  g_assert(strcmp(self->priv->address, "no-address-set")!=0);

  res = sof_init(self->priv, self->priv->contact);

  if (res != -1) {
    self->priv->nua = nua_create(self->priv->root, 
				 sof_callback, self,
				 NUTAG_SOA_NAME("default"),
				 TAG_IF(self->priv->stun_server,
					STUNTAG_SERVER(self->priv->stun_server)),
				 TAG_IF(self->priv->contact,
					NUTAG_URL(self->priv->contact)),
				 /* XXX: SOATAG_CAPS_SDP_STR(local_caps), */
				 TAG_NULL());
    if (self->priv->nua) {

      nua_set_params(self->priv->nua,
                     TAG_IF(self->priv->proxy, NUTAG_PROXY(self->priv->proxy)),
                     TAG_IF(self->priv->registrar, NUTAG_REGISTRAR(self->priv->registrar)),
                     NUTAG_ENABLEMESSAGE(1),
                     NUTAG_ENABLEINVITE(1),
                     /* NUTAG_SESSION_TIMER(s_e), */
                     /* NUTAG_MIN_SE(min_se), */
                     SOATAG_AF(SOA_AF_IP4_IP6),
                     SIPTAG_FROM_STR(self->priv->address),
                     /* NUTAG_CERTIFICATE_DIR(getenv("SIPCERTDIR")),*/
                     TAG_NULL());
      nua_get_params(self->priv->nua, TAG_ANY(), TAG_NULL());

      self->priv->init=TRUE;
      g_signal_connect_after(self, "shutdown", (GCallback)final_shutdown, NULL);
    }
  }
  return obj;
}

static void
nua_glib_init(NuaGlib *self)
{
  self->priv =  g_new0(NuaGlibPrivate, 1);
 /* initialize sofia su OS abstraction layer */
  su_init();
  su_home_init(self->priv->home);
}

static void
nua_glib_dispose(GObject *obj)
{
  NuaGlib *self = NUA_GLIB(obj);

  if (self->priv->init)
  {
    g_free((gpointer)self->priv->contact);

    nua_shutdown(self->priv->nua);

    self->priv->init = FALSE;
    /*now hold a ref to ourselves that we drop when distruction is complete*/
    g_object_ref (obj);

    /* XXX: some start/stop nua funtions to do su_init/de_init?  su_deinit();*/
  }

  /* Chain up to the parent class */
  G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
nua_glib_finalize (GObject *obj)
{
  NuaGlib *self = NUA_GLIB(obj);
  su_root_break(self->priv->root);
  nua_destroy(self->priv->nua);
  su_root_destroy(self->priv->root), self->priv->root = NULL;
  su_home_deinit(self->priv->home);
  g_free(self->priv);

  /* Chain up to the parent class */
  G_OBJECT_CLASS (parent_class)->finalize (obj); 
}

static
void nua_glib_set_property(GObject      *object,
			   guint         property_id,
			   const GValue *value,
			   GParamSpec   *pspec)
{
  NuaGlib *self = (NuaGlib*) object;

#define STORE_PARAM(s, x)			\
  g_free ((gpointer)(s)->priv->x);		\
  (s)->priv->x = g_value_dup_string (value)

  switch (property_id) {
  case PROP_ADDRESS: {
    if (self->priv->nua)
    {
      nua_set_params(self->priv->nua,
                     SIPTAG_FROM_STR(self->priv->address),
                     TAG_NULL());
      nua_get_params(self->priv->nua, TAG_ANY(), TAG_NULL());
    }
    else /*setting in constructor*/
    {
      self->priv->address = su_strdup(self->priv->home, g_value_get_string (value));
    }
    break;
  }
  case PROP_PASSWORD: {
    STORE_PARAM(self, password);
    break;
  }
  case PROP_CONTACT: {
    STORE_PARAM(self, contact);
    break;
  }
  case PROP_PROXY: {
    STORE_PARAM(self, proxy);
    if (self->priv->nua)
    {
      nua_set_params(self->priv->nua,
                     NUTAG_PROXY(self->priv->proxy),
                     TAG_NULL());
    }
    break;
  }
  case PROP_REGISTRAR: {
    STORE_PARAM(self, registrar);
    if (self->priv->nua)
    {
      nua_set_params(self->priv->nua,
                     NUTAG_REGISTRAR(self->priv->registrar),
                     TAG_NULL());
    }
    break;
  }
  case PROP_STUN_SERVER: {
    STORE_PARAM(self, stun_server);
    break;
  }
 default:
    /* We don't have any other property... */
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object,property_id,pspec);
    break;
  }
}

static void
nua_glib_get_property (GObject      *object,
                        guint         property_id,
                        GValue       *value,
                        GParamSpec   *pspec)
{
  NuaGlib *self = (NuaGlib *) object;

  switch (property_id) {
  case PROP_ADDRESS: {
    g_value_set_string (value, self->priv->address);
    break;
  }
  case PROP_PASSWORD: {
    g_value_set_string (value, self->priv->password);
    break;
  }
  case PROP_CONTACT: {
    g_value_set_string (value, self->priv->contact);
    break;
  }
  case PROP_PROXY: {
    g_value_set_string (value, self->priv->proxy);
    break;
  }
  case PROP_REGISTRAR: {
    g_value_set_string (value, self->priv->registrar);
    break;
  }
  case PROP_STUN_SERVER: {
    g_value_set_string (value, self->priv->stun_server);
    break;
  }
  default:
    /* We don't have any other property... */
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object,property_id,pspec);
    break;
  }
}


static void
nua_glib_class_init (NuaGlibClass *nua_glib_class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(nua_glib_class);
  GParamSpec *param_spec;
 
  gobject_class->constructor = nua_glib_constructor;
  gobject_class->dispose = nua_glib_dispose;
  gobject_class->finalize = nua_glib_finalize;

  gobject_class->set_property = nua_glib_set_property;
  gobject_class->get_property = nua_glib_get_property;
  
  param_spec = g_param_spec_string("address",
                                   "NuaGlib construction property",
                                   "The address-of-record for this UA (e.g. 'sip:first.surname@myprovider.com')",
                                   "no-address-set", /*default value*/
                                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT);
  g_object_class_install_property (gobject_class,
                                   PROP_ADDRESS,
                                   param_spec);

  param_spec = g_param_spec_string("password",
                                   "NuaGlib construction property",
                                   "SIP account password",
                                   NULL, /*default value*/
                                   G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   PROP_PASSWORD,
                                   param_spec);

  param_spec = g_param_spec_string("contact",
                                   "NuaGlib construction property",
                                   "local bind interface (e.g. 'sip:0.0.0.0:*') [optional]",
                                   NULL, /*default value*/
                                   G_PARAM_READWRITE );
  g_object_class_install_property (gobject_class,
                                   PROP_CONTACT,
                                   param_spec);

  param_spec = g_param_spec_string("proxy",
                                   "NuaGlib construction property",
                                   "SIP outgoing proxy URI (e.g. 'sip:sipproxy.myprovider.com') [optional]",
                                   NULL, /*default value*/
                                   G_PARAM_READWRITE );
  g_object_class_install_property (gobject_class,
                                   PROP_PROXY,
                                   param_spec);

  param_spec = g_param_spec_string("registrar",
                                   "NuaGlib construction property",
                                   "SIP registrar URI (e.g. 'sip:sip.myprovider.com') [optional]",
                                   NULL, /*default value*/
                                   G_PARAM_READWRITE );
  g_object_class_install_property (gobject_class,
                                   PROP_REGISTRAR,
                                   param_spec);

  param_spec = g_param_spec_string("stun-server",
                                   "NuaGlib construction property",
                                   "STUN server address (FQDN or dotted-decimal) [optional]",
                                   "", /*default value*/
                                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
  g_object_class_install_property (gobject_class,
                                   PROP_STUN_SERVER,
                                   param_spec);

  /**
   * NuaGlib::call-forked:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the call that was forked
   * @status: SIP status of fork (see SIP RFC)
   * @phrase: Reason for fork
   *
   * Emitted when an outgoing call has been forked.
   * This is when an INVITE request is answered with multiple 200 responses.
   */
  signals[NGSIG_CALL_FORKED] =
   g_signal_new("call-forked",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);


  /**
   * NuaGlib::incoming-invite:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation created to represent this 
   *      call (also contains the sender information)
   * @display: the display name of the invite recipient
   * @url: the url of the invite recipient
   * @subject: the subject of the invite (can be NULL)
   *
   * Emitted when an call invite is received
   * Should be answered with nua_glib_answer or nua_glib_decline
   *
   * XXX: a bit ugly that sender information is carried in 'op', while
   *      recipient display name and URI are as arguments
   */
  signals[NGSIG_INCOMING_INVITE] =
   g_signal_new("incoming-invite",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_STRING_STRING_STRING,
    G_TYPE_NONE, 4, G_TYPE_POINTER , G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

  /**
   * NuaGlib::incoming-reinvite:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   *
   * Emitted when an call invite is received for a call already in progress
   * Usually represents
   */
  signals[NGSIG_INCOMING_REINVITE] =
   g_signal_new("incoming-reinvite",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    g_cclosure_marshal_VOID__POINTER,
    G_TYPE_NONE, 1, G_TYPE_POINTER);

  /**
   * NuaGlib::call-state-changed:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @audio: #NuaGlibMediaActive describing audio availiablity
   * @video: #NuaGlibMediaActive describing video availiablity
   * @image: #NuaGlibMediaActive describing image availiablity
   * @chat: #NuaGlibMediaActive describing chat availiablity
   * @l_sdp: String containing any new local caps as SDP, can be NULL
   * @r_sdp: String containing any new remote cap as SDP, can be NULL
   *
   * Emitted when call state changes.
   */
 
  signals[NGSIG_CALL_STATE_CHANGED] =
   g_signal_new("call-state-changed",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_INT_INT_INT_STRING_STRING,
    G_TYPE_NONE, 7, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT,
                    G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING);

  /**
   * NuaGlib::incoming-active:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   *
   * Emitted when a call goes active.
   */
 
  signals[NGSIG_INCOMING_ACTIVE] =
   g_signal_new("incoming-active",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    g_cclosure_marshal_VOID__POINTER,
    G_TYPE_NONE, 1, G_TYPE_POINTER);

  /**
   * NuaGlib::call-terminated:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing callA
   * @status: SIP status of termination (see SIP RFC)
   *
   * This will be emitted after a call has been terminated.
   * 
   * A call is terminated, when
   * 1) an error response (300..599) is sent to an incoming initial INVITE 
   * 2) a reliable response (200..299 or reliable preliminary response) to an 
   * incoming initial INVITE is not acknowledged with ACK or PRACK 
   * 3) BYE is received or sent
   *
   * Any references you hold to @op should be dropped at this point
   */
 
  signals[NGSIG_CALL_TERMINATED] =
   g_signal_new("call-terminated",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT,
    G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_INT);

  /**
   * NuaGlib::incoming-prack:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @rack: pointer to RAck that was PRACKed FIXME!!!
   *
   * Emitted when a PRACK is received
   */
 
  signals[NGSIG_INCOMING_PRACK] =
   g_signal_new("incoming-prack",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_POINTER,
    G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_POINTER);

  /**
   * NuaGlib::incoming-bye:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   *
   */
  signals[NGSIG_INCOMING_BYE] =
   g_signal_new("incoming-bye",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    g_cclosure_marshal_VOID__POINTER,
    G_TYPE_NONE, 1, G_TYPE_POINTER);

  /**
   * NuaGlib::incoming-cancel:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of cancel (see SIP RFC)
   * @phrase: Reason for cancel 
   *
   * Emitted when incoming INVITE has been cancelled or no ACK has 
   * been received for an accepted call.
   */
 
  signals[NGSIG_INCOMING_CANCEL] =
   g_signal_new("incoming-cancel",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    g_cclosure_marshal_VOID__POINTER,
    G_TYPE_NONE, 1, G_TYPE_POINTER);

  /**
   * NuaGlib::incoming-message:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation created to represent this 
   *      call (also contains the sender information)
   * @display: the display name of the invite recipient
   * @url: the url of the invite recipient
   * @subject: the subject of the invite (can be NULL)
   *
   * Emitted when a message is received
   *
   * XXX: a bit ugly that sender information is carried in 'op', while
   *      recipient display name and URI are as arguments
   */
  signals[NGSIG_INCOMING_MESSAGE] =
   g_signal_new("incoming-message",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_STRING_STRING_STRING_STRING,
    G_TYPE_NONE, 5, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

  /**
   * NuaGlib::incoming-info:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation created to represent this 
   *      call (also contains the sender information)
   * @display_name: the display name of the info sender
   * @address: the address of the info sender
   * @subject: the subject of the invite (can be NULL)
   *
   * Emitted when an INFO message is received
   *
   * XXX: a bit ugly that sender information is carried in 'op', while
   *      recipient display name and URI are as arguments
   */
  signals[NGSIG_INCOMING_INFO] =
   g_signal_new("incoming-info",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_STRING_STRING_STRING,
    G_TYPE_NONE, 4, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

  /**
   * NuaGlib::incoming-refer:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation for the call that originated this refer
   * @display: the display name of the REFERER 
   * @address: the address of the REFERER 
   * @refer_address: the address you have been requested to refer to
   * @op2: a pointer to an operation to use to respond to this refer, NULL if 
   *       REFER url was not a SIP uri.
   *
   * Emitted when a REFER message is received
   * You should reply to this with #nua_glib_notify to cancel it or 
   * #nua_glib_follow_refer, and probably close * the call that referred 
   * you to follow it.
   */
  signals[NGSIG_INCOMING_REFER] =
   g_signal_new("incoming-refer",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_STRING_STRING_STRING_POINTER,
    G_TYPE_NONE, 5, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                    G_TYPE_POINTER);

  /**
   * NuaGlib::incoming-notify:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation created to represent this call, NULL if 
   *      this was a rogue notify
   * @event: name of event, can be NULL
   * @content-type: content type of event, can be NULL
   * @payload: payload of event
   *
   * Emitted when an NOTIFY message is received
   */
 
  signals[NGSIG_INCOMING_NOTIFY] =
   g_signal_new("incoming-notify",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_STRING_STRING_STRING,
    G_TYPE_NONE, 4, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

  /**
   * NuaGlib::error:
   * @nua_glib: the object that received the signal
   * @status: SIP status for error (see SIP RFC)
   * @phrase: Reason for error
   *
   * If you get this, run around waving your hands and screaming.
   */
 
  signals[NGSIG_ERROR] =
   g_signal_new("error",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__INT_STRING,
    G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::register-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of REGISTER answer (see SIP RFC)
   * @phrase: Reason for REGISTER answer 
   *
   * if status >=300 and not 401 or 407, you should drop any references you hold 
   * on @op
   */
  signals[NGSIG_REGISTER_ANSWERED] =
   g_signal_new("register-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::unregister-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of REGISTER answer (see SIP RFC)
   * @phrase: Reason for REGISTER answer 
   *
   * if status >=300 and not 401 or 407, you should drop any references you hold 
   * on @op
   */
 
  signals[NGSIG_UNREGISTER_ANSWERED] =
   g_signal_new("unregister-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::publish-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of PUBLISH answer (see SIP RFC)
   * @phrase: Reason for PUBLISH answer 
   *
   * if status >=300 and not 401 or 407, you should drop any references you hold 
   * on @op
   */
 
  signals[NGSIG_PUBLISH_ANSWERED] =
   g_signal_new("publish-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::invite-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of INVITE answer (see SIP RFC)
   * @phrase: Reason for INVITE answer 
   *
   */
  signals[NGSIG_INVITE_ANSWERED] =
   g_signal_new("invite-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::bye-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of bye answer (see SIP RFC)
   * @phrase: Reason for bye answer 
   *
   */
  signals[NGSIG_BYE_ANSWERED] =
   g_signal_new("bye-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::cancel-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of CANCEL answer (see SIP RFC)
   * @phrase: Reason for CANCEL answer 
   *
   */
  signals[NGSIG_CANCEL_ANSWERED] =
   g_signal_new("cancel-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::message-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of message answer (see SIP RFC)
   * @phrase: Reason for message answer
   *
   */
  signals[NGSIG_MESSAGE_ANSWERED] =
   g_signal_new("message-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::info-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of INFO answer (see SIP RFC)
   * @phrase: Reason for INFO answer
   *
   */
  signals[NGSIG_INFO_ANSWERED] =
   g_signal_new("info-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::refer-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of REFER answer (see SIP RFC)
   * @phrase: Reason for REFER answer 
   *
   * XXX: should we pass the even header as param (see nua_refer()
   * documentation and SIPTAG_EVENT())
   */
  signals[NGSIG_REFER_ANSWERED] =
   g_signal_new("refer-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::subscribe-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of SUBSCRIBE answer (see SIP RFC)
   * @phrase: Reason for SUBSCRIBE answer
   *
   */
  signals[NGSIG_SUBSCRIBE_ANSWERED] =
   g_signal_new("subscribe-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::unsubscribe-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of UNSUBSCRIBE answer (see SIP RFC)
   * @phrase: Reason for UNSUBSCRIBE answer
   *
   *You should remove any references you have to @op after receiving this signal
   */
  signals[NGSIG_UNSUBSCRIBE_ANSWERED] =
   g_signal_new("unsubscribe-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::notify-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of NOTIFY answer (see SIP RFC)
   * @phrase: Reason for NOTIFY answer 
   *
   */
  signals[NGSIG_NOTIFY_ANSWERED] =
   g_signal_new("notify-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::options-answered:
   * @nua_glib: the object that received the signal
   * @op: pointer to the operation representing the existing call
   * @status: SIP status of options answer (see SIP RFC)
   * @phrase: Reason for options answer 
   *
   * XXX: not OPTIONS response payload is not delivered to the application
   */
  signals[NGSIG_OPTIONS_ANSWERED] =
   g_signal_new("options-answered",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_INT_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_INT, G_TYPE_STRING);

  /**
   * NuaGlib::shutdown:
   * @nua_glib: the object that received the signal
   *
   * The sip stack is shutting down, 
   * drop all #NuaGlibOp references you hold
   * and unref the object it was emited on
   */
 signals[NGSIG_SHUTDOWN] =
   g_signal_new("shutdown",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    g_cclosure_marshal_VOID__VOID,
    G_TYPE_NONE, 0, NULL);

  /**
   * NuaGlib::auth_required:
   * @nua_glib: the object that received the signal
   * @op: pointer to the related operation
   * @method: string describing the method (RFC2617: "Basic", "Digest", ..)
   * @realm: realm of the challenge (RFC2617) 
   *
   * The sip stack is shutting down, 
   * drop all #NuaGlibOp references you hold
   * and unref the object it was emited on
   */
 signals[NGSIG_AUTH_REQUIRED] =
   g_signal_new("auth-required",
    G_OBJECT_CLASS_TYPE (nua_glib_class),
    G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
    0, NULL, NULL,
    nua_glib_marshal_VOID__POINTER_STRING_STRING,
    G_TYPE_NONE, 3, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_STRING);
}

/* ====================================================================== */
int sof_init(NuaGlibPrivate *priv, const char *contact)
{
  priv->name = "UA";
  priv->contact = g_strdup(contact);

  su_root_threading(priv->root, 0);

  return 0;
}


static void 
sof_callback(nua_event_t event,
                    int status, char const *phrase,
                    nua_t *nua, NuaGlib *self,
                    nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                    tagi_t tags[])
{
  g_return_if_fail(self);

  switch (event) {
  case nua_r_shutdown:    
    sof_r_shutdown(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_r_get_params:    
    sof_r_get_params(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_r_register:
    sof_r_register(status, phrase, nua, self, nh, op, sip, tags);
    return;
    
  case nua_r_unregister:
    sof_r_unregister(status, phrase, nua, self, nh, op, sip, tags);
    return;
    
  case nua_r_options:
    sof_r_options(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_r_invite:
    sof_r_invite(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_i_fork:
    sof_i_fork(status, phrase, nua, self, nh, op, sip, tags);
    return;
    
  case nua_i_invite:
    sof_i_invite(nua, self, nh, op, sip, tags);
    return;

  case nua_i_prack:
    sof_i_prack(nua, self, nh, op, sip, tags);
    return;

  case nua_i_active:
    sof_i_active(nua, self, nh, op, sip, tags);
    return;

  case nua_i_state:
    sof_i_state(status, phrase, nua, self, nh, op, sip, tags);
    return;
    
  case nua_i_terminated:
    sof_i_terminated(status, phrase, nua, self, nh, op, sip, tags);
    return;
    
  case nua_r_bye:
    sof_r_bye(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_i_bye:
    sof_i_bye(nua, self, nh, op, sip, tags);
    return;

  case nua_r_cancel:
    sof_r_cancel(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_r_message:
    sof_r_message(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_i_message:
    sof_i_message(nua, self, nh, op, sip, tags);
    return;

  case nua_r_info:
    sof_r_info(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_i_info:
    sof_i_info(nua, self, nh, op, sip, tags);
    return;

  case nua_r_refer:
    sof_r_refer(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_i_refer:
    sof_i_refer(nua, self, nh, op, sip, tags);
    return;
     
  case nua_r_subscribe:
    sof_r_subscribe(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_r_unsubscribe:
    sof_r_unsubscribe(status, phrase, nua, self, nh, op, sip, tags);
    return;

  case nua_r_publish:
    sof_r_publish(status, phrase, nua, self, nh, op, sip, tags);
    return;
    
  case nua_r_notify:
    sof_r_notify(status, phrase, nua, self, nh, op, sip, tags);
    return;
     
  case nua_i_notify:
    sof_i_notify(nua, self, nh, op, sip, tags);
    return;

  case nua_i_cancel:
    sof_i_cancel(nua, self, nh, op, sip, tags);
    return;

  case nua_i_error:
    sof_i_error(nua, self, nh, op, status, phrase, tags);
    return;

  default:
    break;
  }

  if (status > 100)
    g_warning("%s: unknown event %d: %03d %s\n", 
           self->priv->name, event, status, phrase);
  else
    g_warning("%s: unknown event %d\n", self->priv->name, event);

  tl_print(stderr, "", tags);

  if (nua_glib_op_find_by_handle(self, nh) == NULL) {
    /* note: unknown handle, not associated to any existing call,
     *       message, registration, etc, so it can be safely destroyed */
    nua_handle_destroy(nh);
  }
}

/* ====================================================================== */

/**
 * Helper function called from all response callback handler.
 * Checks whether authentication is needed, and handles it if 
 * require. Marks succesful authentications as completed.
 */
static void priv_oper_check_response_for_auth(NuaGlib *self, NuaGlibOp *op, int status, sip_t const *sip, tagi_t *tags)
{
  if (status == 401 || status == 407) {
    priv_oper_handle_auth(self, op, sip, tags);
  }
  else if (status >= 200 && status <= 299){
    if (op->op_authstate != opa_none && 
	op->op_authstate != opa_auth_ok) {
      op->op_authstate = opa_auth_ok;
      SU_DEBUG_3(("%s: authorization of %s (%p) was succesful\n", 
		  self->priv->name, sip_method_name(op->op_method, "<NONE>"), op));
    }
  }
}

/**
 * Handles authentication challenge for operation 'op'.
 */
static void priv_oper_handle_auth (NuaGlib *self, NuaGlibOp *op, sip_t const *sip, tagi_t *tags)
{
  sip_www_authenticate_t const *wa = sip->sip_www_authenticate;
  sip_proxy_authenticate_t const *pa = sip->sip_proxy_authenticate;
  sip_from_t const *sipfrom = sip->sip_from;
  const char *realm = NULL;

  enter;

  tl_gets(tags, 
          SIPTAG_WWW_AUTHENTICATE_REF(wa),
          SIPTAG_PROXY_AUTHENTICATE_REF(pa),
          TAG_NULL());

  SU_DEBUG_3(("%s: %s (%p) was unauthorized\n", self->priv->name, sip_method_name(op->op_method, "<NONE>"), op));

  /* step: the initial challenge */
  if (op->op_authstate == opa_none) {
    if (wa) {
      sl_header_print(stdout, "Server auth: %s\n", (sip_header_t *)wa);
      realm = msg_params_find(wa->au_params, "realm=");  
      nua_glib_auth_add(self, op, wa->au_scheme, realm, sipfrom->a_url->url_user, self->priv->password);
    }
    if (pa) {
      sl_header_print(stdout, "Proxy auth: %s\n", (sip_header_t *)pa);
      realm = msg_params_find(pa->au_params, "realm=");  
      nua_glib_auth_add(self, op, pa->au_scheme, realm, sipfrom->a_url->url_user, self->priv->password);
    }

    op->op_authstate = opa_try_derived;
    priv_submit_authlist(op);
  }
  /* step: a new challenge and local credentials updated since last attempt */
  else if (op->op_authstate == opa_retry) {
    priv_submit_authlist(op);
  }
  /* step: a new challenge, ask for matching credentials */
  else if (op->op_authstate == opa_try_derived) {
    g_message("Requesting for additional authentication credentials %s(%s)",
	      self->priv->name, sip_method_name(op->op_method, "<NONE>"));
    op->op_authstate = opa_auth_req;
    g_signal_emit(self, signals[NGSIG_AUTH_REQUIRED], 0, op, sip_method_name(op->op_method, "<NONE>"), realm);
  }
  /* step: a new challenge, ask for matching credentials */
  else if (op->op_authstate == opa_auth_req) {
    g_message("Failed auth for %s by %s",
	      sip_method_name(op->op_method, "<NONE>"), self->priv->name);
    op->op_authstate = opa_failed;
  }
}


/**
 * nua_glib_op_owner:
 *
 * get the owning NuaGlib for a given NuaGlibOp
 */
NuaGlib* 
nua_glib_op_owner(NuaGlibOp *op)
{
  g_assert(op);
  return op->op_parent;
}

sip_method_t
nua_glib_op_method_type(NuaGlibOp *op)
{
  g_assert(op);
  return op->op_method;
}
/**
 * nua_glib_op_set_data:
 * @op: op to attach data to
 * @data: data to attach
 *
 * Attach an applciation specific blob of data to a NuaGlibOp
 * The application is in charge of deleting the data when it 
 * removes any internal references to the @op. When it has done 
 * so, it should call this function with @data set to NULL
 * Failing to do so will cause an assertion.
 */
void
nua_glib_op_set_data(NuaGlibOp *op, gpointer data)
{
  g_assert(op);
  op->data = data;
}

/**
 * nua_glib_op_get_data:
 * @op: op to get data from
 *
 * Get an application specific blob of data from a NuaGlibOp
 * Returns: attached data
 */
gpointer
nua_glib_op_get_data(NuaGlibOp *op)
{
  g_assert(op);
  return op->data ;
}

/**
 * nua_glib_op_get_identity:
 * @op: op to get data from
 *
 * Get the identity of an operation
 * This is the contents of To: when initiating, From: when receiving.
 * Returns: the identity
 */
const gchar *
nua_glib_op_get_identity(NuaGlibOp *op)
{
  g_assert(op);
  return op->op_ident;
}


static void 
sof_i_error(nua_t *nua, NuaGlib *self, nua_handle_t *nh, NuaGlibOp *op, 
            int status, char const *phrase,
            tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_ERROR], status, phrase);
}

/**
 * nua_glib_invite:
 * @destination sip address to invite
 * @local_sdp an SDP blob describing local capabilites
 * 
 * Invites 'destination_uri' to a new call.
 *
 * Incomplete sessions can be hung-up with nua_glib_cancel(). Complete or
 * incomplete calls can be hung-up with nua_glib_bye()
 *
 * @see nua_invite() (libsofia-sip-ua/nua)
 *
 * Return value: operation descriptor for this operation, NULL if failure
 */
NuaGlibOp *nua_glib_invite(NuaGlib *self, const char *destination_uri, const char *local_sdp)
{
  NuaGlibOp *op;

  op = nua_glib_op_create(self, sip_method_invite, destination_uri, TAG_END());

  /* SDP O/A note: 
   *  - pass media information to nua_invite() in the 
   *    SOATAG_USER_SDP_STR() tag
   *  - see also: sof_i_state() and nua_glib_answer()
   */ 

  if (op) {
    nua_invite(op->op_handle,
               SOATAG_USER_SDP_STR(local_sdp),
               TAG_END());

    op->op_callstate |= opc_sent;
    return op;
  }

  return NULL;
}

/*
 * invite response handler
 */
static void 
sof_r_invite(int status, char const *phrase, 
             nua_t *nua, NuaGlib *self,
             nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
             tagi_t tags[])
{
  if (status >= 300) {
    op->op_callstate &= ~opc_sent;
    priv_oper_check_response_for_auth(self, op, status, sip, tags);
  }
  g_signal_emit(self, signals[NGSIG_INVITE_ANSWERED],0, op, status, phrase);
}

/*
 * Stack callback: incoming call-forked
 *
 * Releases forked calls
 */
static void 
sof_i_fork(int status, char const *phrase,
           nua_t *nua, NuaGlib *self,
           nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
           tagi_t tags[])
{
  nua_handle_t *nh2 = NULL;

  g_signal_emit(self, signals[NGSIG_CALL_FORKED], 0, status, phrase, op);
  
  g_warning("%s: call fork: %03d %s\n", self->priv->name, status, phrase);

  /* We just release forked calls. */
  tl_gets(tags, NUTAG_HANDLE_REF(nh2), TAG_END());
  g_return_if_fail(nh2);

  nua_bye(nh2, TAG_END());
  nua_handle_destroy(nh2);
}

/*
 * Stack callback: incoming invite handler
 */
static void 
sof_i_invite(nua_t *nua, NuaGlib *self,
             nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
             tagi_t tags[])
{
  /* Incoming call */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_subject_t const *subject;
  char *to_url;

  g_assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  subject = sip->sip_subject;

  g_assert(from); g_assert(to);

  if (op) {
    op->op_callstate |= opc_recv;
  }
  else if ((op = nua_glib_op_create_with_handle(self, sip_method_invite, nh, from))) {
    op->op_callstate = opc_recv;
  }
  else {
    nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
    nua_handle_destroy(nh);
  }

  if (op) {
    if (op->op_callstate == opc_recv) {
      to_url = url_as_string(self->priv->home, to->a_url);
      g_signal_emit(self, signals[NGSIG_INCOMING_INVITE], 0, op, to->a_display, to_url, subject?subject->g_value:NULL); 
      su_free(self->priv->home, to_url);
    }
    else {
      g_signal_emit(self, signals[NGSIG_INCOMING_REINVITE], 0, op); 
    }
  }

}

/**
 * nua_glib_redirect:
 * @op: call to redirect
 * @contact: contact to redirect to
 * Redirect a call
 */
void
nua_glib_redirect(NuaGlib *self, 
                    NuaGlibOp *op, 
                    const char *contact)

{
  g_assert(nua_glib_op_check(self, op));

  nua_respond(op->op_handle, SIP_302_MOVED_TEMPORARILY, 
              SIPTAG_CONTACT_STR(contact),
              TAG_END());
}

/** 
 * nua_glib_answer:
 * @op: operation returned from the incoming-invite signal
 * @status: SIP response status (see RFCs of SIP)
 * @phrase: Reponse text (default response phrase used if NULL)
 * @sdp: SDP description of local media capabilites
 *
 * Answer a incoming call.
 * 
 * @see nua_respond() (libsofia-sip-ua/nua)
 */
void nua_glib_answer(NuaGlib *self, 
		     NuaGlibOp *op,                         
		     int status, 
		     const char *phrase, 
		     const char *sdp)
{
  /* SDP O/A note: 
   *  - pass SDP information to nua_respond() in
   *    the SOATAG_USER_SDP_STR() tag
   *  - see also: sof_i_state() and nua_glib_invite()
   */ 
  
  g_assert(self); g_assert(op);
  g_assert(op->op_method == sip_method_invite);

  if (status >= 200 && status < 300)
    op->op_callstate |= opc_sent;
  else
    op->op_callstate = opc_none;

  nua_respond(op->op_handle, status, phrase, 
              SOATAG_USER_SDP_STR(sdp),
              TAG_END());
}

static void 
sof_i_prack(nua_t *nua, NuaGlib *self,
            nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
            tagi_t tags[])
{
  /* Incoming PRACK */
  sip_rack_t const *rack;

  g_return_if_fail(sip);

  rack = sip->sip_rack;

  g_signal_emit(self, signals[NGSIG_INCOMING_PRACK], 0, op, rack ? rack->ra_response : 0);

  if (op == NULL)
    nua_handle_destroy(nh);
}

static void 
sof_i_state(int status, char const *phrase, 
            nua_t *nua, NuaGlib *self,
            nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
            tagi_t tags[])
{
  char const *l_sdp = NULL, *r_sdp = NULL;
  int audio = NUA_GLIB_MEDIA_INACTIVE;
  int video = NUA_GLIB_MEDIA_INACTIVE;
  int image = NUA_GLIB_MEDIA_INACTIVE;
  int chat = NUA_GLIB_MEDIA_INACTIVE;
  int offer_recv = 0, answer_recv = 0, offer_sent = 0, answer_sent = 0;
  int ss_state = nua_callstate_init;

  g_return_if_fail(op);

  tl_gets(tags, 
          NUTAG_CALLSTATE_REF(ss_state),
          NUTAG_ACTIVE_AUDIO_REF(audio), 
          NUTAG_ACTIVE_VIDEO_REF(video), 
          NUTAG_ACTIVE_IMAGE_REF(image), 
          NUTAG_ACTIVE_CHAT_REF(chat), 
          NUTAG_OFFER_RECV_REF(offer_recv),
          NUTAG_ANSWER_RECV_REF(answer_recv),
          NUTAG_OFFER_SENT_REF(offer_sent),
          NUTAG_ANSWER_SENT_REF(answer_sent),
          SOATAG_LOCAL_SDP_STR_REF(l_sdp),
          SOATAG_REMOTE_SDP_STR_REF(r_sdp),
          TAG_END());

  /* SDP O/A note: 
   *  - check the O/A state and whether local and/or remote SDP 
   *    is available (and whether it is updated)
   *  - inform media subsystem of the changes in configuration
   *  - see also: sof_i_state() and nua_glib_invite()
   */ 

  if (l_sdp) {
    g_return_if_fail(answer_sent || offer_sent);
  }

  if (r_sdp) {
    g_return_if_fail(answer_recv || offer_recv);
  }

  if (op->op_prev_state != ss_state) {
    /* note: only emit if state has changed */
    g_signal_emit(self, signals[NGSIG_CALL_STATE_CHANGED], 0, op, audio, video, image, chat, l_sdp, r_sdp); 
    op->op_prev_state = ss_state;
  }
}

static void 
sof_i_active(nua_t *nua, NuaGlib *self,
             nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
             tagi_t tags[])
{
  assert(op);

  op->op_callstate = opc_active;
  g_signal_emit(self, signals[NGSIG_INCOMING_ACTIVE], 0, op);
}

static gboolean 
idle_kill_op (gpointer data)
{
  NuaGlibOp* op = (NuaGlibOp *)data;

  nua_glib_op_destroy(op->op_parent, op);
  return FALSE;
}

static void 
sof_i_terminated(int status, char const *phrase, 
                 nua_t *nua, NuaGlib *self,
                 nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                 tagi_t tags[])
{
  if (op) {
    g_signal_emit(self, signals[NGSIG_CALL_TERMINATED], 0, op, status);
    op->op_callstate = 0;
    g_idle_add(idle_kill_op, op);
  }
}

/**
 * nua_glib_bye:
 * @op the call to bye
 *
 * Terminates the call 'op' with SIP BYE method. A 'bye-answered'
 * signal will emitted with the response to the bye.
 *
 * @see nua_bye() (libsofia-sip-ua/nua)
 */
void nua_glib_bye(NuaGlib *self, NuaGlibOp *op)
{
  g_assert(nua_glib_op_check(self, op));

  nua_bye(op->op_handle, TAG_END());
  op->op_callstate = 0;
}

void sof_r_bye(int status, char const *phrase, 
               nua_t *nua, NuaGlib *self,
               nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
               tagi_t tags[])
{
  assert(op); assert(op->op_handle == nh);

  g_signal_emit(self, signals[NGSIG_BYE_ANSWERED], 0, op, status, phrase);
}

static void 
sof_i_bye(nua_t *nua, NuaGlib *self,
          nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
          tagi_t tags[])
{
  assert(op); assert(op->op_handle == nh);

  g_signal_emit(self, signals[NGSIG_INCOMING_BYE], 0, op);
}

/**
 * nua_glib_cancel:
 * @op the call to cancel
 *
 * Cancel a request.
 * A 'cancel-answered' signal will be emitted with the response to the
 * cancel.
 * 
 * @see nua_cancel() (libsofia-sip-ua/nua) 
 */
void nua_glib_cancel(NuaGlib *self, NuaGlibOp *op)
{
  g_assert(nua_glib_op_check(self, op));
  nua_cancel(op->op_handle, TAG_END());
}

void sof_i_cancel(nua_t *nua, NuaGlib *self,
                    nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                    tagi_t tags[])
{
  assert(op); assert(op->op_handle == nh);
  
  g_signal_emit(self, signals[NGSIG_INCOMING_CANCEL], 0, op);
}

void sof_r_cancel(int status, char const *phrase, 
		  nua_t *nua, NuaGlib *self,
		  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
		  tagi_t tags[])
{
  g_assert(op); g_assert(op->op_handle == nh);

  g_signal_emit(self, signals[NGSIG_CANCEL_ANSWERED], 0, op, status, phrase);
}


/**
 * nua_glib_options:
 * @destination: URI to set options for
 * Makes a SIP OPTIONS request to the destination to query
 * capabilities. The results are delivered with the 'options-answered' signal.
 *
 * Return value: operation created for request
 */
NuaGlibOp *
nua_glib_options(NuaGlib *self, const char *destination_uri)
{
  NuaGlibOp *op = nua_glib_op_create(self, sip_method_options, destination_uri, TAG_END());

  if (op) {
    nua_options(op->op_handle, TAG_END());
    return op;
  }
  else
    return NULL; 
}

static void 
sof_r_options(int status, char const *phrase,
              nua_t *nua, NuaGlib *self,
              nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
              tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_OPTIONS_ANSWERED], 0, op, status, phrase);

  priv_oper_check_response_for_auth(self, op, status, sip, tags);
}

/**
 * nua_glib_message:
 * @destination destination address
 * @message: message to send
 * 
 * Send a message to a given destination address
 * Return value: operation created for the message, NULL cif failure
 */
NuaGlibOp * 
nua_glib_message(NuaGlib *self, const char *destination_uri, const char *message)
{
  NuaGlibOp *op = nua_glib_op_create(self, sip_method_message, destination_uri, TAG_END());

  if (op) {
    nua_message(op->op_handle,
                SIPTAG_CONTENT_TYPE_STR("text/plain"),
                SIPTAG_PAYLOAD_STR(message),
                TAG_END());
    return op;
  }
  else
    return NULL;
}

static void 
sof_r_message(int status, char const *phrase,
              nua_t *nua, NuaGlib *self,
              nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
              tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_MESSAGE_ANSWERED], 0, op, status, phrase);
  if (status < 200)
    return;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);
}

static void 
sof_i_message(nua_t *nua, NuaGlib *self,
              nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
              tagi_t tags[])
{
  /* Incoming message */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_subject_t const *subject;
  GString *message;
  char *to_url;

  g_assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  subject = sip->sip_subject;

  assert(from && to);

  if (sip->sip_payload && sip->sip_payload->pl_len > 0)
    message = g_string_new_len(sip->sip_payload->pl_data, sip->sip_payload->pl_len);
  else
    message = NULL;
  
  to_url = url_as_string(self->priv->home, to->a_url);

  if (op == NULL)
    op = nua_glib_op_create_with_handle(self, sip_method_message, nh, from);

  g_signal_emit(self, signals[NGSIG_INCOMING_MESSAGE], 0, op, from->a_display, to_url,
		subject ? subject->g_value : NULL,
		message ? message->str : NULL); 

  su_free(self->priv->home, to_url);

  if (message)
    g_string_free(message, TRUE);

  if (op == NULL)
    nua_handle_destroy(nh);
}

/**
 * nua_glib_info:
 * @op operation representing existing call to send INFO in
 * @message INFO message to send
 *
 * Sends on INFO request to recipient associated with call 'op'.
 * INFO is used to send call related information like DTMF digit input
 * events. See RFC 2976.
 */
void
nua_glib_info (NuaGlib *self, NuaGlibOp *op, const char *content_type,
                 const char *message)
{
  g_assert(nua_glib_op_check(self, op));
  nua_info(op->op_handle,
           SIPTAG_CONTENT_TYPE_STR(content_type),
           SIPTAG_PAYLOAD_STR(message),
           TAG_END());
}

static void 
sof_r_info(int status, char const *phrase,
           nua_t *nua, NuaGlib *self,
           nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
           tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_INFO_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);
}

static void 
sof_i_info(nua_t *nua, NuaGlib *self,
           nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
           tagi_t tags[])
{
  /* Incoming info */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_subject_t const *subject;
  GString *message;
  char *to_url;

  assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  subject = sip->sip_subject;

  assert(from && to);

  if (sip->sip_payload)
    message=g_string_new_len(sip->sip_payload->pl_data, sip->sip_payload->pl_len);
  else
    message=NULL;

  to_url = url_as_string(self->priv->home, to->a_url);
  g_signal_emit(self, signals[NGSIG_INCOMING_INFO], 0, op, to->a_display, to_url, subject?subject->g_value:NULL, message); 
  su_free(self->priv->home, to_url);
  g_string_free(message, TRUE);

  if (op == NULL)
    op = nua_glib_op_create_with_handle(self, sip_method_info, nh, from);
  if (op == NULL)
    nua_handle_destroy(nh);

}

/*=======================================*/

/**
 * nua_glib_refer:
 * @op: operation representing existing call
 * @destination: destination to REFER them to
 *
 * Sends a REFER request asking the recipient to transfer the call. The
 * REFER request also establishes a subscription to the "refer" event.
 * The "refer" event will have an "id" parameter, which has the value of
 * CSeq number in the REFER request. After initiating the REFER request,
 * the nua-glib engine will emit the 'refer-answered' signal with
 * status 100.
 */
void nua_glib_refer (NuaGlib *self, NuaGlibOp *op, const char* destination)
{
  g_assert(nua_glib_op_check(self, op));
  
  nua_refer(op->op_handle,
	    SIPTAG_REFER_TO_STR(destination),
	    TAG_END());
}


static void 
sof_r_refer (int status, char const *phrase,
             nua_t *nua, NuaGlib *self,
             nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
             tagi_t tags[])
{

  g_signal_emit(self, signals[NGSIG_REFER_ANSWERED], 0, op, status, phrase );

  if (status < 200)
    return;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);
}

/*---------------------------------------*/
static void 
sof_i_refer (nua_t *nua, NuaGlib *self,
             nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
             tagi_t tags[])
{
  /* Incoming refer */
  sip_from_t const *from;
  sip_to_t const *to;
  sip_refer_to_t const *refer_to;
  NuaGlibOp *op2;
  char *refer_to_str;
  char *to_url;
  char *refer_url;

  assert(sip);

  from = sip->sip_from;
  to = sip->sip_to;
  refer_to = sip->sip_refer_to;

  assert(from && to);

  to_url = url_as_string(self->priv->home, to->a_url);
  refer_url = url_as_string(self->priv->home, refer_to->r_url);

   if (refer_to->r_url->url_type == url_sip) {
      refer_to_str = sip_header_as_string(self->priv->home, (sip_header_t*)refer_to);
      op2 = nua_glib_op_create(self, sip_method_invite, refer_to_str,
			       NUTAG_NOTIFY_REFER(nh), TAG_END());
      su_free(self->priv->home, refer_to_str);
      
      g_signal_emit(self, signals[NGSIG_INCOMING_REFER], 0, op, to->a_display, to_url, refer_url, op2);
   }
   else {
      g_signal_emit(self, signals[NGSIG_INCOMING_REFER], 0, op, to->a_display, to_url, refer_url, NULL);
   }

  su_free(self->priv->home, to_url);
  su_free(self->priv->home, refer_url);
 }

/**
 * nua_glib_follow_refer:
 * @op: operation returned in incoming-refer signal
 *
 * Follow a received REFER
 */
void 
nua_glib_follow_refer(NuaGlib *self, NuaGlibOp *op)
{
  g_assert(nua_glib_op_check(self, op));
}


/**
 * nua_glib_hold:
 * @op: operation representing the call
 * @hold: TRUE to hold, FALSE to take off hold
 * 
 * Change the hold status of a call
 */
void 
nua_glib_hold(NuaGlib *self, NuaGlibOp *op, int hold)
{
  g_assert(nua_glib_op_check(self, op));

  nua_invite(op->op_handle, NUTAG_HOLD(hold), TAG_END());
      
  op->op_callstate = opc_sent_hold;
}

/**
 * nua_glib_subscribe:
 * @uri: URI to subscribe to
 * @eventlist: request eventlists
 *
 * Subscribe to presence notifications for a given URI
 * Return value: operation representing this presence notifcation channel
 */

NuaGlibOp *
nua_glib_subscribe(NuaGlib *self, const char *uri, gboolean eventlist)
{
  NuaGlibOp *op;
  char const *event = "presence";
  char const *supported = NULL;

  if (eventlist)
    supported="eventlist";
  
  op = nua_glib_op_create(self, sip_method_subscribe, uri, TAG_END());

  if (op) {
    nua_subscribe(op->op_handle, 
                  SIPTAG_EXPIRES_STR("3600"),
                  SIPTAG_ACCEPT_STR("application/cpim-pidf+xml;q=0.5, "
                                    "application/pidf-partial+xml"),
                  TAG_IF(supported, 
                         SIPTAG_ACCEPT_STR("multipart/related, "
                                           "application/rlmi+xml")),
                  SIPTAG_SUPPORTED_STR(supported),
                  SIPTAG_EVENT_STR(event),
                  TAG_END());
      return op;
  }
  else
      return NULL;
}

/**
 * nua_glib_watch:
 * @event string descriptor of event to watch for
 * XXX: needs some funky signal registering, i *think*
 *
 * Subscribe to watch
 * Returns: Operation representing this watch, NULL if failure
 */
NuaGlibOp *
nua_glib_watch(NuaGlib *self, char *event)
{
  NuaGlibOp *op;
  char *destination;

  destination = strchr(event, ' ');
  while (destination && *destination == ' ')
    *destination++ = '\0';

  op = nua_glib_op_create(self, sip_method_subscribe, destination, TAG_END());

  if (op) {
    nua_subscribe(op->op_handle, 
                  SIPTAG_EVENT_STR(event),
                  TAG_END());
  }
  return op;
}

static void 
sof_r_subscribe (int status, char const *phrase,
                 nua_t *nua, NuaGlib *self,
                 nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                 tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_SUBSCRIBE_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;
  if (status >= 300)
    op->op_persistent = 0;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);
}
/**
 * nua_glib_notify:
 * @op: operation returned in refer-incoming signal
 *
 * send a NOTIFY in response to a REFER
 *
 * This cancels the REFER
 * You should remove any refernces you hold to @op after calling this function
 */
void
nua_glib_notify(NuaGlib *self, NuaGlibOp* op)
{
  SU_DEBUG_1(("%s: not follow refer, NOTIFY(503)\n", self->priv->name));

  g_assert(nua_glib_op_check(self, op));

  nua_cancel(op->op_handle, TAG_END());
  nua_glib_op_destroy(self, op);
}

static void 
sof_i_notify(nua_t *nua, NuaGlib *self,
                  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                  tagi_t tags[])
{
  sip_event_t const *event = sip->sip_event;
  sip_content_type_t const *content_type = sip->sip_content_type;
  GString *message;
  assert(sip);

  if (sip->sip_payload)
    message=g_string_new_len(sip->sip_payload->pl_data, sip->sip_payload->pl_len);
  else
    message=NULL;

  g_signal_emit(self, signals[NGSIG_INCOMING_NOTIFY], 0, op, (event?event->o_type:NULL), (content_type?content_type->c_type:NULL),  message); 
  g_string_free(message, TRUE);
}
/*---------------------------------------*/
static void 
sof_r_notify(int status, char const *phrase,
             nua_t *nua, NuaGlib *self,
             nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
             tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_NOTIFY_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);
}

/*---------------------------------------*/

/**
 * nua_glib_unsubscribe:
 * @op: operation representing subscribtion to unsubscribe
 *
 * Unsubscribe a subscription
 */

void 
nua_glib_unsubscribe(NuaGlib *self, NuaGlibOp *op)
{
  nua_unsubscribe(op->op_handle, TAG_END());
}

static void 
sof_r_unsubscribe(int status, char const *phrase,
                  nua_t *nua, NuaGlib *self,
                  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                  tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_UNSUBSCRIBE_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;

  nua_glib_op_destroy(self, op);
}

/**
 * nua_glib_reregister:
 * @op: op from original register.  
 *
 * reregister to the current registrar with same contact
 */

void
nua_glib_reregister(NuaGlib *self, NuaGlibOp *op)
{

  nua_register(op->op_handle, TAG_NULL());
  return;
}

/**
 * nua_glib_register:
 * @registrar: registrar to use,NULL to use current registrar set for this stack
 *
 * send a REGISTER
 * Returns: REGISTER operation
 */
NuaGlibOp*
nua_glib_register(NuaGlib *self, const char *registrar)
{
  NuaGlibOp *op = NULL;
  char *address;
  address = su_strdup(self->priv->home, self->priv->address);

  if ((op = nua_glib_op_create(self, sip_method_register, address, TAG_END()))) {
    SU_DEBUG_3(("%s: REGISTER %s\n", self->priv->name, op->op_ident));
    nua_register(op->op_handle, 
		 SIPTAG_FROM_STR(self->priv->address),
                 TAG_IF(registrar, NUTAG_REGISTRAR(registrar)), 
                 TAG_NULL());
  }
  su_free(self->priv->home, address);
  return op;
}

static void 
sof_r_register (int status, char const *phrase, 
                nua_t *nua, NuaGlib *self,
                nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_REGISTER_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);

  if (status >= 300 && status != 401 && status != 407)
    nua_glib_op_destroy(self, op);
}

/**
 * nua_glib_unregister:
 * @op: operation returned from register
 *
 * unregister
 */
void 
nua_glib_unregister(NuaGlib *self, NuaGlibOp *op)
{
  SU_DEBUG_3(("%s: un-REGISTER %s\n", self->priv->name, op->op_ident));
  nua_unregister(op->op_handle, TAG_NULL());
}

/**
 * nua_glib_unregister_direct:
 * @op: operation returned from register
 *
 * unregister
 * Returns: operation used for this UNREGISTER
 */
NuaGlibOp *
nua_glib_unregister_direct(NuaGlib *self, const char *registrar)
{
  NuaGlibOp *op;
  char *address = su_strdup(self->priv->home, self->priv->address);

  op = nua_glib_op_create(self, sip_method_register, address, TAG_END());
  su_free(self->priv->home, address);

  if (op) {
    nua_unregister(op->op_handle,
                   TAG_IF(registrar, NUTAG_REGISTRAR(registrar)),
                   SIPTAG_CONTACT_STR("*"),
                   SIPTAG_EXPIRES_STR("0"),
                   TAG_NULL());
    return op;
  }
  else
    return NULL;
}


static void 
sof_r_unregister (int status, char const *phrase, 
                  nua_t *nua, NuaGlib *self,
                  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                  tagi_t tags[])
{
  sip_contact_t *m;

  g_signal_emit(self, signals[NGSIG_UNREGISTER_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;

  if (status == 200)
    for (m = sip ? sip->sip_contact : NULL; m; m = m->m_next)
      sl_header_print(stdout, "\tContact: %s\n", (sip_header_t *)m);

  priv_oper_check_response_for_auth(self, op, status, sip, tags);

  if (status >= 300 && status != 401 && status != 407)
    nua_glib_op_destroy(self, op);
}

/**
 * nua_glib_republish:
 * @op: call to publish info in
 * @note: note to publish
 *
 * Publish information in an existing channel
 */
void 
nua_glib_republish(NuaGlib *self, NuaGlibOp *op, const char *note)
{
  sip_payload_t *pl = NULL;
  char *xmlnote = NULL;
  int open;

  open = ((note == NULL) || note[0] != '-');

  if (note && strcmp(note, "-") != 0)
    xmlnote = su_sprintf(self->priv->home, "<note>%s</note>\n", 
                         open ? note : note + 1);

  pl = sip_payload_format
    (self->priv->home, 
     "<?xml version='1.0' encoding='UTF-8'?>\n"
     "<presence xmlns='urn:ietf:params:xml:ns:cpim-pidf'\n"
     "          entity='%s'>\n"
     "  <tuple id='%s'>\n"
     "    <status><basic>%s</basic></status>\n"
     "%s"
     "  </tuple>\n"
     "</presence>\n",
     self->priv->address, self->priv->name, 
     open ? "open" : "closed", 
     xmlnote ? xmlnote : "");

  nua_publish(op->op_handle, 
              SIPTAG_PAYLOAD(pl),
              TAG_IF(pl, SIPTAG_CONTENT_TYPE_STR("application/cpim-pidf+xml")),
              TAG_NULL());

  su_free(self->priv->home, pl);
}

/**
 * nua_glib_publish:
 * @note: note to publish
 *
 * Publish information
 */
NuaGlibOp *
nua_glib_publish(NuaGlib *self, const char *note)
{
  NuaGlibOp *op = NULL;
  sip_payload_t *pl = NULL;
  char *xmlnote = NULL;
  int open;
  char *address;

  open = ((note == NULL) || note[0] != '-');

  if (note && strcmp(note, "-") != 0)
    xmlnote = su_sprintf(self->priv->home, "<note>%s</note>\n", 
                         open ? note : note + 1);

  pl = sip_payload_format
    (self->priv->home, 
     "<?xml version='1.0' encoding='UTF-8'?>\n"
     "<presence xmlns='urn:ietf:params:xml:ns:cpim-pidf'\n"
     "          entity='%s'>\n"
     "  <tuple id='%s'>\n"
     "    <status><basic>%s</basic></status>\n"
     "%s"
     "  </tuple>\n"
     "</presence>\n",
     self->priv->address, self->priv->name, 
     open ? "open" : "closed", 
     xmlnote ? xmlnote : "");

  address = su_strdup(self->priv->home, self->priv->address);

  if ((op = nua_glib_op_create(self, sip_method_publish, address, 
			       SIPTAG_EVENT_STR("presence"),
			       TAG_END()))) {
    nua_publish(op->op_handle, 
                SIPTAG_CONTENT_TYPE_STR("application/cpim-pidf+xml"),
                SIPTAG_PAYLOAD(pl),
                TAG_END());
  }
  su_free(self->priv->home, pl);
  su_free(self->priv->home, address);

  return op;
}

/**
 * nua_glib_unpublish:
 * @op: operation from a previous publish
 *
 * Clear published information
 */
void 
nua_glib_unpublish(NuaGlib *self, NuaGlibOp *op)
{
  nua_publish(op->op_handle, 
              SIPTAG_EXPIRES_STR("0"),
              TAG_NULL());
}

/**
 * nua_glib_unpublish_direct:
 *
 * Clear published information without an existing publish operation
 */
NuaGlibOp *
nua_glib_unpublish_direct(NuaGlib *self)
{
  NuaGlibOp *op=NULL;
  char *address;
  address = su_strdup(self->priv->home, self->priv->address);

  if ((op = nua_glib_op_create(self, sip_method_publish, address, 
			       SIPTAG_EVENT_STR("presence"),
			       TAG_END()))) {
    nua_publish(op->op_handle, 
                SIPTAG_EXPIRES_STR("0"),
                TAG_END());
  }
  
  su_free(self->priv->home, address);

  return op;
}

static void 
sof_r_publish (int status, char const *phrase, 
               nua_t *nua, NuaGlib *self,
               nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
               tagi_t tags[])
{
  g_signal_emit(self, signals[NGSIG_PUBLISH_ANSWERED], 0, op, status, phrase);

  if (status < 200)
    return;

  priv_oper_check_response_for_auth(self, op, status, sip, tags);

  if (status >= 300 && status != 401 && status != 407)
    nua_glib_op_destroy(self, op);
  else if (!sip->sip_expires || sip->sip_expires->ex_delta == 0)
    nua_glib_op_destroy(self, op);
}

static void 
sof_r_shutdown (int status, char const *phrase, 
                nua_t *nua, NuaGlib *self,
                nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                tagi_t tags[])
{

  if (status < 200)
    return;
  /*drop the ref we held in dispose. 
   * needs to be done in a signal so it happens from the glib main loop*/

  g_signal_emit(self, signals[NGSIG_SHUTDOWN],0);
  g_warning("%s: nua_shutdown: %03d %s\n", self->priv->name, status, phrase);
  
}

static void 
sof_r_get_params (int status, char const *phrase, 
                  nua_t *nua, NuaGlib *self,
                  nua_handle_t *nh, NuaGlibOp *op, sip_t const *sip,
                  tagi_t tags[])
{
  sip_from_t const *from = NULL;


  tl_gets(tags, SIPTAG_FROM_REF(from), TAG_END());

  if (from) {
    char *new_address = 
      sip_header_as_string(self->priv->home, (sip_header_t *)from);
    if (new_address) {
      su_free(self->priv->home, self->priv->address);
      self->priv->address = new_address;
    }      
  }

}

/**
 * Submit all authentication credentials stored for
 * operation handle 'op'
 */
static void priv_submit_authlist(NuaGlibOp *op)
{
  GSList *i = op->op_authlist;

  while(i) {
    GString *tmp = (GString*)i->data;
    if (tmp && tmp->str) {
      g_assert(tmp->len > 0);
      SU_DEBUG_3(("submitting authitem (op=%p): %s.\n", op, tmp->str));
      nua_authenticate(op->op_handle, NUTAG_AUTH(tmp->str), TAG_END());
    }
    i = g_slist_next(i);
  }
}

/**
 * nua_glib_auth_add:
 * @op: operation to which the auth credentials are added
 * @method: auth method (RFC2617)
 * @method: auth realm (RFC2617)
 * @method: auth username (RFC2617)
 * @method: auth passwrod (RFC2617)
 *
 * Attach new authentication credentials to operation 'op'.
 *
 * @see nua_glib_auth_clear()
 */
void nua_glib_auth_add(NuaGlib *self, NuaGlibOp *op, const char *method, const char *realm, const char *user, const char *password)
{
  GString *tmp = g_string_new(NULL);

  /* XXX: we should prune the auth-cred database in case scheme, realm
     and username match */
  
  if (realm[0] == '"')
    g_string_printf(tmp, "%s:%s:%s:%s", 
		    method, realm, user, password);
  else
    g_string_printf(tmp, "%s:\"%s\":%s:%s", 
		    method, realm, user, password);

  op->op_authlist = g_slist_append(op->op_authlist, tmp);
  op->op_authstate = opa_retry;
 
  priv_submit_authlist(op);
}

/**
 * nua_glib_auth_clear:
 * @op: operation to which the auth credentials are added
 *
 * Clears the authentication credentials for operation 'op'.
 *
 * @see nua_glib_auth_add()
 */
void nua_glib_auth_clear(NuaGlib *self, NuaGlibOp *op)
{
  GSList *i = op->op_authlist;

  while(i) {
    GString *tmp = (GString*)i->data;
    g_string_free(tmp, TRUE);
    i = g_slist_next(i);
  }

  g_slist_free(op->op_authlist), op->op_authlist = NULL;
  op->op_authstate = opa_none;
}
