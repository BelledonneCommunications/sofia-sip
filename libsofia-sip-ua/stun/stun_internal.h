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

#ifndef STUN_INTERNAL_H /** Defined when stun_internal.h has been included. */
#define STUN_INTERNAL_H
/**@file stun_internal.h STUN client interface
 *
 * @author Tat Chan <Tat.Chan@nokia.com>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 */

#ifndef SU_WAIT_H
#include <su_wait.h>
#endif

#ifndef SU_TAG_H
#include <su_tag.h>
#endif

#ifndef STUN_H
#include "stun.h"
#endif

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif
#define SU_LOG (stun_log)
#include <su_debug.h>

extern char const STUN_DEBUG[]; /* dummy declaration for Doxygen */


#define STUN_LIFETIME_EST 350      /**< 6 min? */
#define STUN_LIFETIME_MAX 1800     /**< 30 min? */
#define STUN_LIFETIME_CI  5        /**< 5 sec confidence interval */

#define STUN_ERROR(errno, what) \
        { int err = errno; \
        SU_DEBUG_5(("%s: %s: %s\n", __func__, #what, su_strerror(err))); \
        }


int stun_is_requested(tag_type_t tag, tag_value_t value, ...);

int stun_poll(stun_socket_t *ss);
int stun_get_lifetime(stun_socket_t *ss, 
		      su_localinfo_t *my_addr, int *addrlen,
		      int *lifetime);

/** other functions */
int stun_set_uname_pwd(stun_engine_t *se, const char *uname, int len_uname, 
		       const char *pwd, int len_pwd);

/* internal functions declaration */
int stun_connect_start(stun_engine_t *se, su_addrinfo_t *ai);
int stun_make_sharedsecret_req(stun_msg_t *msg);

int stun_bind_test(stun_socket_t *ss,
		   su_localinfo_t *srvr_addr,
		   su_localinfo_t *clnt_addr,
		   int chg_ip,
		   int chg_port);
int stun_send_message2(stun_socket_t *ss, struct sockaddr_in *srvr, stun_msg_t *msg); /* client version */
int stun_make_binding_req(stun_socket_t *ss, stun_msg_t *msg, int chg_ip, int chg_port);
int stun_process_response(stun_msg_t *msg);

int stun_process_binding_response(stun_msg_t *msg);
int stun_process_error_response(stun_msg_t *msg);

int stun_atoaddr(struct sockaddr_in *addr, char const *in);
int stun_add_response_address(stun_msg_t *req, struct sockaddr_in *mapped_addr);

#endif /* !defined(STUN_INTERNAL_H) */
