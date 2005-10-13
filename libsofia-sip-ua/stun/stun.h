/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
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

#ifndef STUN_H /** Defined when stun.h has been included. */
#define STUN_H
/**@file stun.h STUN client interface
 *
 * @author Tat Chan <Tat.Chan@nokia.com>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Jul 24 17:08:32 2003 pessi
 * @date Last modified: Wed Jul 20 20:35:55 2005 kaiv
 */

#include <su_wait.h>
#include "stun_common.h"

#define STUN_LIFETIME_EST 350 /* 6 min? */
#define STUN_LIFETIME_MAX 1800 /* 30 min? */
#define STUN_LIFETIME_CI  5 /* 5 sec confidence interval */

typedef struct stun_engine_s stun_engine_t;
typedef struct stun_socket_s stun_socket_t;

stun_engine_t *stun_engine_create(char const *server, int use_msgint); 
/* stun_engine_t *stun_engine_create(struct sockaddr_in *server); */


void stun_engine_destroy(stun_engine_t *);

stun_socket_t *stun_socket_create(stun_engine_t *se, int sockfd);
void stun_socket_destroy(stun_socket_t *ss);

/** Bind a socket using STUN.  */
int stun_bind(stun_socket_t *ss, 
	      struct sockaddr *addr, 
	      socklen_t *return_addrlen,
	      int *return_lifetime);

int stun_get_nattype(stun_socket_t *ss,
		     struct sockaddr *my_addr, int *addrlen);

int stun_poll(stun_socket_t *ss);
int stun_get_lifetime(stun_socket_t *ss, 
		      struct sockaddr *my_addr, int *addrlen,
		      int *lifetime);

/** other functions */
int stun_set_uname_pwd(stun_engine_t *se, const unsigned char *uname, int len_uname, 
		       const unsigned char *pwd, int len_pwd);


/* internal functions declaration */
int stun_get_sharedsecret(stun_engine_t *se);
int stun_make_sharedsecret_req(stun_msg_t *msg);

int stun_bind_test(stun_socket_t *ss, struct sockaddr_in *srvr, struct sockaddr_in *cli, 
		   int chg_ip, int chg_port);
int stun_send_message2(stun_socket_t *ss, struct sockaddr_in *srvr, stun_msg_t *msg); /* client version */
int stun_make_binding_req(stun_socket_t *ss, stun_msg_t *msg, int chg_ip, int chg_port);
int stun_process_response(stun_msg_t *msg);

int stun_process_binding_response(stun_msg_t *msg);
int stun_process_error_response(stun_msg_t *msg);

int stun_atoaddr(struct sockaddr_in *addr, char const *in);
char const *stun_nattype(stun_engine_t *se);
int stun_add_response_address(stun_msg_t *req, struct sockaddr_in *mapped_addr);


#endif /* !defined(STUN_H) */
