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

#ifndef STUN_TAG_H
#define STUN_TAG_H
/**@file stun_tag.h  Tags for STUN.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Oct 18 20:13:50 EEST 2005 ppessi
 */

#ifndef SU_TAG_H
#include <su_tag.h>
#endif

SOFIA_BEGIN_DECLS

#define STUNTAG_ANY()         stuntag_any, ((tag_value_t)0)
extern tag_typedef_t stuntag_any;

#define STUNTAG_SERVER(x)  stuntag_server, tag_str_v(x)
extern tag_typedef_t stuntag_server;
#define STUNTAG_SERVER_REF(x) stuntag_server_ref, tag_str_vr(&(x))
extern tag_typedef_t stuntag_server_ref;

#define STUNTAG_INTEGRITY(x) stuntag_integrity, tag_int_v(x)
extern tag_typedef_t stuntag_integrity;
#define STUNTAG_INTEGRITY_REF(x) stuntag_integrity_ref, tag_int_vr(&(x))
extern tag_typedef_t stuntag_integrity_ref;

#define STUNTAG_SOCKET(x) stuntag_socket, tag_int_v(x)
extern tag_typedef_t stuntag_socket;
#define STUNTAG_SOCKET_REF(x) stuntag_socket_ref, tag_int_vr(&(x))
extern tag_typedef_t stuntag_socket_ref;

#define STUNTAG_ACTION(x) stuntag_action, tag_int_v(x)
extern tag_typedef_t stuntag_action;
#define STUNTAG_ACTION_REF(x) stuntag_action_ref, tag_int_vr(&(x))
extern tag_typedef_t stuntag_action_ref;

#define STUNTAG_CHANGE_IP(x) stuntag_change_ip, tag_bool_v(x)
extern tag_typedef_t stuntag_change_ip;
#define STUNTAG_CHANGE_IP_REF(x) stuntag_change_ip_ref, tag_bool_vr(&(x))
extern tag_typedef_t stuntag_change_ip_ref;

#define STUNTAG_CHANGE_PORT(x) stuntag_change_port, tag_bool_v(x)
extern tag_typedef_t stuntag_change_port;
#define STUNTAG_CHANGE_PORT_REF(x) stuntag_change_port_ref, tag_bool_vr(&(x))
extern tag_typedef_t stuntag_change_port_ref;

SOFIA_END_DECLS

#endif /* STUN_TAG_H */
