/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005-2006 Nokia Corporation.
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

#ifndef __NUA_GLIB_PRIVATE_H__
#define __NUA_GLIB_PRIVATE_H__

/**@file nua_glib_priv.h Private implementation header for Sofia Glib
 *
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 * @author Rob Taylor <rob.taylor@collabora.co.uk>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 */

#include <glib.h>

#define SU_ROOT_MAGIC_T NuaGlib
#define NUA_MAGIC_T     NuaGlib
#define NUA_IMAGIC_T    NuaGlibOp
#define NUA_HMAGIC_T    NuaGlibOp
#define SOA_MAGIC_T     NuaGlib

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/stun_tag.h>
#include <sofia-sip/soa.h>
#include <sofia-sip/su_tag_io.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/sl_utils.h>

#include <sofia-sip/su_source.h>
#include <sofia-sip/su_debug.h>

#if HAVE_FUNC
#define enter (void)SU_DEBUG_9(("%s: entering\n", __func__))
#elif HAVE_FUNCTION
#define enter (void)SU_DEBUG_9(("%s: entering\n", __FUNCTION__))
#else
#define enter (void)0
#endif

struct _NuaGlibOp {
  NuaGlibOp *op_next;
  NuaGlib   *op_parent;		/**< Backpointer */

  /**< Remote end identity
   *
   * Contents of To: when initiating, From: when receiving.
   */
  char const   *op_ident;	

  /** NUA handle */ 
  nua_handle_t *op_handle;

  /** How this handle was used initially */
  sip_method_t  op_method;	/**< REGISTER, INVITE, MESSAGE, or SUBSCRIBE */

  /** Call state. 
   *
   * - opc_sent when initial INVITE has been sent
   * - opc_recv when initial INVITE has been received
   * - opc_complate when 200 Ok has been sent/received
   * - opc_active when media is used
   * - opc_sent when re-INVITE has been sent
   * - opc_recv when re-INVITE has been received
   */
  enum { 
    opc_none, 
    opc_sent = 1, 
    opc_recv = 2, 
    opc_complete = 3, 
    opc_active = 4,
    opc_sent_hold = 8,             /**< Call put on hold */
    opc_pending = 16               /**< Waiting for local resources */
  } op_callstate;

  /** Authentication state.
   *
   * - opa_try_derived when using account password
   * - opa_auth_req when requesting for additional credentials
   * - opa_retry when additional credentials have been provided
   * - opa_auth_ok if auth was succesful
   * - opa_failed if auth failed
   */
  enum {
    opa_none = 0,
    opa_try_derived,
    opa_auth_req,
    opa_retry,
    opa_auth_ok,
    opa_failed
  } op_authstate;

  int           op_prev_state;     /**< Previous call state */

  unsigned      op_persistent : 1; /**< Is this handle persistent? */
  unsigned      op_referred : 1;
  unsigned :0;

  GSList       *op_authlist; 

  gpointer      data;
};


struct _NuaGlibPrivate {

  /* private: maybe this should be really private?*/
  su_home_t   home[1];   /**< Our memory home */
  char const *name;      /**< Our name */
  su_root_t  *root;      /**< Pointer to application root */

  unsigned    init : 1;  /**< True if class is inited */

  gchar      *address;     /**< our SIP address (address-of-record) */  
  gchar      *password;    /**< SIP account password */  
  gchar      *contact;     /**< contact URI (local address) */
  gchar      *proxy;       /**< outgoing proxy URI (optional, otherwise from DNS) */
  gchar      *registrar;   /**< registrar URI (optional, otherwise from DNS) */
  gchar      *stun_server; /**< STUN server URI (optional, otherwise from DNS) */

  nua_t      *nua;         /**< Pointer to NUA object */
  NuaGlibOp  *operations;  /**< Remote destinations */
};



#endif /* __NUA_GLIB_PRIVATE_H__ */
