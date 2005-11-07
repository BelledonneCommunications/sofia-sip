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

#ifndef AUTH_CLIENT_H /** Defined when <auth_client.h> has been included. */
#define AUTH_CLIENT_H 


/**@file auth_client.h
 * @brief Client-side authenticator library.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Feb 14 17:09:44 2001 ppessi
 */

#ifndef MSG_TYPES_H
#include <msg_types.h>
#endif
#ifndef AUTH_DIGEST_H
#include <auth_digest.h>
#endif
#ifndef URL_H
#include <url.h>
#endif

/** Authenticator object. */
typedef struct auth_client_s auth_client_t;

int auc_challenge(auth_client_t **auc, su_home_t *home, 
		  msg_auth_t const *auth,
		  msg_hclass_t *crcl);
int auc_credentials(auth_client_t **auc, su_home_t *home, char const *data);

int auc_all_credentials(auth_client_t **auc_list, 
			char const *scheme,
			char const *realm, 
			char const *user,
			char const *pass);

int auc_clear_credentials(auth_client_t **auc_list, 
			  char const *scheme,
			  char const *realm);

int auc_authorization(auth_client_t **auc_list, msg_t *msg, msg_pub_t *pub,
		      char const *method, 
		      url_t const *url, 
		      msg_payload_t const *body);

int auc_authorization_headers(auth_client_t **auc_list, 
			      su_home_t *home,
			      char const *method, 
			      url_t const *url, 
			      msg_payload_t const *body,
			      msg_header_t **return_headers);
struct uicc_s;
struct sip_s;

int auc_with_uicc(auth_client_t **auc, su_home_t *home, struct uicc_s *uicc);
int auc_authorize(auth_client_t **auc, msg_t *msg, struct sip_s *sip);

#endif 
