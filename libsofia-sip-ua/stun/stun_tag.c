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

/**@CFILE stun_tag.c  Tags and tag lists for Offer/Answer Engine
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Aug  3 20:28:17 EEST 2005
 */

#include "config.h"

#define TAG_NAMESPACE "stun"

#include <su_tag_class.h>

/**@def STUNTAG_ANY()
 * 
 * Filter tag matching any STUNTAG_*().
 */
tag_typedef_t stuntag_any = NSTAG_TYPEDEF(*);

/**@def STUNTAG_SERVER(x)
 *
 * Pass media address.
 *
 * @par Used with
 *    nua_set_params() \n
 *    nua_get_params() \n
 *    nua_invite() \n
 *    nua_respond()
 *
 * @par Parameter type
 *    char const *
 *
 * @par Values
 *    NULL terminated character string containing a domain name,
 *    IPv4 address, or IPv6 address.
 *
 * Corresponding tag taking reference parameter is STUNTAG_SERVER_REF()
*/
tag_typedef_t stuntag_server = STRTAG_TYPEDEF(server);

/**@def STUNTAG_INTEGRITY(x)
 *  
 * Enable integrity protection.
 *
 * @par Used with
 *    nua_create() \n
 *
 * @par Parameter type
 *    int (boolean)
 *
 * @par Values
 *    @c !=0 enable
 *    @c 0 disable
 *
 * Corresponding tag taking reference parameter is STUNTAG_INTEGRITY_REF()
 */
tag_typedef_t stuntag_integrity = BOOLTAG_TYPEDEF(srtp_integrity);

/**@def STUNTAG_SOCKET(x)
 *  
 * Bind socket for STUN.
 *
 * @par Used with
 *    stun_handle_bind() \n
 *
 * @par Parameter type
 *    int (su_socket_t)
 *
 * @par Values
 *    IPv4 (AF_INET) socket
 *
 * Corresponding tag taking reference parameter is STUNTAG_SOCKET_REF()
 */
tag_typedef_t stuntag_socket = INTTAG_TYPEDEF(socket);

/**@def STUNTAG_ACTION(x)
 *  
 * Command action for STUN request.
 *
 * @par Used with
 *    stun_handle_bind() \n
 *
 * @par Parameter type
 *    int (stun_action_t)
 *
 * @par Values
 *    See types for stun_action_t in stun.h
 *
 * Corresponding tag taking reference parameter is STUNTAG_ACTION_REF()
 */
tag_typedef_t stuntag_action = INTTAG_TYPEDEF(action);

/* ---------------------------------------------------------------------- */

/**@def STUNTAG_CHANGE_IP(x)
 *  
 * Add CHANGE-REQUEST attribute with "change IP" flag to the request.
 *
 * @par Used with
 *    stun_make_binding_req() \n
 *
 * @par Parameter type
 *    bool
 *
 * Corresponding tag taking reference parameter is STUNTAG_CHANGE_IP_REF()
 */
tag_typedef_t stuntag_change_ip = BOOLTAG_TYPEDEF(change_ip);

/**@def STUNTAG_CHANGE_PORT(x)
 *  
 * Add CHANGE-REQUEST attribute with "change port" flag to the request.
 *
 * @par Used with
 *    stun_make_binding_req() \n
 *
 * @par Parameter type
 *    bool
 *
 * Corresponding tag taking reference parameter is STUNTAG_CHANGE_PORT_REF()
 */
tag_typedef_t stuntag_change_port = BOOLTAG_TYPEDEF(change_port);
