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

#ifndef TPORT_PLUGINS_H
/** Defined when <sofia-sip/tport_plugins.h> has been included. */
#define TPORT_PLUGINS_H

/**@file tport_plugins.h
 * @brief Transport plugin interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Fri Mar 31 12:22:22 EEST 2006 ppessi
 */

/* -- STUN Plugin ------------------------------------------------------- */

#ifndef TPORT_STUN_SERVER_T
#define TPORT_STUN_SERVER_T struct tport_stun_server_s
#endif
/** Safe type for tport server object */
typedef TPORT_STUN_SERVER_T tport_stun_server_t;

typedef struct {
  int vst_size;
  tport_stun_server_t *(*vst_create)(su_root_t *root, tagi_t const *tags);
  void (*vst_destroy)(tport_stun_server_t *);
  int (*vst_add_socket)(tport_stun_server_t *, int socket);
  int (*vst_remove_socket)(tport_stun_server_t *, int socket);
  void (*vst_request)(tport_stun_server_t *server, int socket,
		     void *msg, ssize_t msglen,
		     void *addr, socklen_t addrlen);
} tport_stun_server_vtable_t;

SOFIAPUBFUN int tport_plug_in_stun_server(tport_stun_server_vtable_t const *);


/* -- SigComp Plugin ---------------------------------------------------- */

#ifndef TPORT_COMP_T
#define TPORT_COMP_T struct tport_compress
#endif

typedef TPORT_COMP_T tport_comp_t;

/* We already use these SigComp types in applications */

struct sigcomp_udvm;
struct sigcomp_compartment;

typedef struct tport_comp_vtable_s tport_comp_vtable_t;

SOFIAPUBFUN int tport_plug_in_comp(tport_comp_vtable_t const *);

#endif /* !defined(TPORT_PLUGINS_H) */
