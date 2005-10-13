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

/**@CFILE auth_client.c  Authenticators for SIP client
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Feb 14 18:32:58 2001 ppessi
 * @date Last modified: Wed Jul 20 20:35:21 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <su.h>
#include <su_md5.h>

#include "auth_client.h"

#include <msg_header.h>

#include <auth_digest.h>
#include <base64.h>
#include <su_uniqueid.h>

#include <su_debug.h>

#if HAVE_SC_CRED_H
#include <sc_creds.h>
#endif

#if HAVE_UICC_H
#include <uicc.h>
#endif

struct auth_client_s {
  su_home_t     ca_home[1];
  auth_client_t*ca_next;

  msg_param_t   ca_scheme;
  msg_param_t   ca_realm;
  msg_param_t   ca_user;
  msg_param_t   ca_pass;

#if  0
  msg_hclass_t *ca_challenge_class;
  msg_auth_t   *ca_challenge;
#endif

  msg_hclass_t *ca_credential_class;

  auth_challenge_t ca_ac[1];
  int           ca_ncount;
  char const   *ca_cnonce;
  msg_header_t *(*ca_authorize)(auth_client_t *ca, 
				su_home_t *h,
				char const *method, 
				url_t const *url, 
				msg_payload_t const *body);
};

static auth_client_t *ca_create(su_home_t *home);
static int ca_challenge(auth_client_t *ca, 
			msg_auth_t const *auth, 
			msg_hclass_t *credential_class,
			msg_param_t scheme, 
			msg_param_t realm);
static int ca_credentials(auth_client_t *ca, 
			  char const *scheme,
			  char const *realm, 
			  char const *user,
			  char const *pass);
static int ca_clear_credentials(auth_client_t *ca, 
				char const *scheme,
				char const *realm);
static msg_header_t *auc_basic_authorization(auth_client_t *ca,
					     su_home_t *h,
					     char const *method, 
					     url_t const *url, 
					     msg_payload_t const *body);
static msg_header_t *auc_digest_authorization(auth_client_t *ca, 
					      su_home_t *h,
					      char const *method, 
					      url_t const *url, 
					      msg_payload_t const *body);

/** Allocate a dummy auth_client_t structure. */
auth_client_t *ca_create(su_home_t *home)
{
  auth_client_t *ca;

  if ((ca = su_home_clone(home, sizeof(*ca)))) {
    ca->ca_scheme = ca->ca_realm = "";
  }

  return ca;
}

void ca_destroy(su_home_t *home, auth_client_t *ca)
{
  su_free(home, ca);
}

/** Initialize AKA authenticator.
 *
 * The function auc_with_uicc() initializes the AKA authenticator to the
 * list of authenticators @a auc_list.
 *
 * @param auc_list [in/out] list of authenticators to be updated
 * @param home     [in/out] memory home used for allocating authenticators
 * @param uicc     [in]     UICC object
 * 
 * @retval 0 when successful
 * @retval -1 upon an error
 */
int auc_with_uicc(auth_client_t **auc_list,
		  su_home_t *home, 
		  struct uicc_s *uicc)
{
#if HAVE_UICC_H
  /* Xyzzy. */
#endif

  return -1;
}

/** Initialize authenticators.
 *
 * The function auc_challenge() merges the challenge @a ch to the list of
 * authenticators @a auc_list.  
 *
 * @param auc_list [in/out] list of authenticators to be updated
 * @param home     [in/out] memory home used for allocating authenticators
 * @param ch       [in] challenge to be processed
 * @param crcl     [in] credential class
 * 
 * @retval 1 when challenge was updated
 * @retval 0 when there was no new challenges
 * @retval -1 upon an error
 */
int auc_challenge(auth_client_t **auc_list,
		  su_home_t *home, 
		  msg_auth_t const *ch,
		  msg_hclass_t *crcl)
{
  auth_client_t **cca;
  int retval = 0;

  for (; ch; ch = ch->au_next) {
    msg_param_t scheme = ch->au_scheme;
    msg_param_t realm = msg_params_find(ch->au_params, "realm=");
    int updated = 0, updated0;

    if (!scheme || !realm)
      continue;

    for (cca = auc_list; (*cca); cca = &(*cca)->ca_next) {
      updated0 = ca_challenge((*cca), ch, crcl, scheme, realm);
      if (updated0 < 0)
	continue;
      updated = 1;
      retval = retval || updated0 > 0;
    }

    if (!updated) {
      *cca = ca_create(home);
      if (ca_challenge((*cca), ch, crcl, scheme, realm) != -1) {
	updated = 1;
      } else {
	ca_destroy(home, *cca), *cca = NULL;
	retval = -1;
	break;
      } 
    }

    retval = retval || updated;
  }

  return retval;
}

static
int ca_challenge(auth_client_t *ca, 
		 msg_auth_t const *ch,
		 msg_hclass_t *credential_class,
		 msg_param_t scheme, 
		 msg_param_t realm)
{
  su_home_t *home = ca->ca_home;
  auth_challenge_t *ac = ca->ca_ac;
  int existing = ca->ca_authorize != NULL;

  assert(ca); assert(ch);

  if (!ca || !ch)
    return -1;

  ca->ca_ac->ac_size = sizeof(ca->ca_ac);

  if (ca->ca_scheme[0] && strcmp(ca->ca_scheme, scheme))
    return -1;
  if (ca->ca_realm[0] && strcmp(ca->ca_realm, realm))
    return -1;

  if (strcasecmp(scheme, "Basic") == 0) {
    ca->ca_authorize = auc_basic_authorization;
  }
  else if (strcasecmp(scheme, "Digest") == 0) {
    ca->ca_authorize = auc_digest_authorization;
  }
  else
    return -1;

#if 0
  if (ca->ca_challenge_class && 
      ca->ca_challenge_class != ch->au_common->h_class)
    return -1;
#endif

  if (ca->ca_credential_class && 
      ca->ca_credential_class != credential_class)
    return -1;

  ca->ca_credential_class = credential_class;
#if 0
  ca->ca_challenge = msg_header_dup(home, (msg_header_t *)ch)->sh_auth;
  ca->ca_challenge_class = ca->ca_challenge->au_common->h_class;
  ca->ca_scheme = ca->ca_challenge->au_scheme;
  ca->ca_realm = msg_params_find(ca->ca_challenge->au_params, "realm=");
#else
  ca->ca_scheme = su_strdup(home, ch->au_scheme);
  ca->ca_realm = su_strdup(home, msg_params_find(ch->au_params, "realm="));
#endif

  if (auth_digest_challenge_get(home, ac, ch->au_params) < 0)
    return -1;

  /* Check that we can handle this */
  if (!ac->ac_md5 && !ac->ac_md5sess)
    return -1;
  if (ac->ac_qop && !ac->ac_auth && !ac->ac_auth_int)
    return -1;

  if (ac->ac_qop && (ca->ca_cnonce == NULL || ac->ac_stale)) {
    /* XXX - generate cnonce */
    su_guid_t guid[1];
    char *cnonce;
    su_guid_generate(guid);
    ca->ca_cnonce = cnonce = su_alloc(home, BASE64_SIZE(sizeof(guid)) + 1);
    base64_e(cnonce, BASE64_SIZE(sizeof(guid)) + 1, guid, sizeof(guid));
    ca->ca_ncount = 0;
  }

  return !existing || ac->ac_stale != NULL;
}

/**Feed authentication data to the authenticator.
 *
 * The function auc_credentials() is used to provide the authenticators in
 * with authentication data (user name, secret).  The authentication data
 * has format as follows:
 *
 * scheme:"realm":user:pass
 *
 * For instance, @c Basic:"nokia-proxy":ppessi:verysecret
 *
 * @todo The authentication data format sucks.
 *
 * @param auc_list [in/out] list of authenticators 
 * @param home     [in/out] memory home used for allocations
 * @param data     [in]     colon-separated authentication data
 * 
 * @retval 0 when successful
 * @retval -1 upon an error
 */
int auc_credentials(auth_client_t **auc_list, su_home_t *home, 
		    char const *data)
{
  int retval = 0, match;
  char *s0, *s;
  char *scheme = NULL, *user = NULL, *pass = NULL, *realm = NULL;

  s0 = s = su_strdup(NULL, data);

  /* Parse authentication data */
  /* Data is string like "Basic:\"agni\":user1:secret" */
  if (s && (s = strchr(scheme = s, ':')))
    *s++ = 0;
  if (s && (s = strchr(realm = s, ':')))
    *s++ = 0;
  if (s && (s = strchr(user = s, ':')))
    *s++ = 0;
  if (s && (s = strchr(pass = s, ':')))
    *s++ = 0;

  if (scheme && realm && user && pass) {
    for (; *auc_list; auc_list = &(*auc_list)->ca_next) {
      match = ca_credentials(*auc_list, scheme, realm, user, pass);
      if (match < 0) {
	retval = -1;
	break;
      }
      if (match) 
	retval++;
    }
  }

  su_free(NULL, s0);

  return retval;
}

/**Feed authentication data to the authenticator.
 *
 * The function auc_credentials() is used to provide the authenticators in
 * with authentication tuple (scheme, realm, user name, secret).  
 *
 * scheme:"realm":user:pass
 *
 * @todo The authentication data format sucks.
 *
 * @param auc_list [in/out] list of authenticators 
 * @param scheme   [in]     scheme to use (NULL, if any)
 * @param realm    [in]     realm to use (NULL, if any)
 * @param user     [in]     username 
 * @param pass     [in]     password
 * 
 * @retval number of matching clients
 * @retval 0 when no matching client was found
 * @retval -1 upon an error
 */
int auc_all_credentials(auth_client_t **auc_list, 
			char const *scheme,
			char const *realm, 
			char const *user,
			char const *pass)
{
  int retval = 0, match;

#if HAVE_SC_CRED_H
  /* XXX: add */
#endif

  if (user && pass) {
    for (; *auc_list; auc_list = &(*auc_list)->ca_next) {
      match = ca_credentials(*auc_list, scheme, realm, user, pass);
      if (match < 0)
	return -1;
      if (match) 
	retval++;
    }
  }

  return retval;
}

int ca_credentials(auth_client_t *ca, 
		   char const *scheme,
		   char const *realm, 
		   char const *user,
		   char const *pass)
{
  assert(ca);

  if (!ca || !ca->ca_scheme || !ca->ca_realm)
    return -1;

  if ((scheme != NULL && strcasecmp(scheme, ca->ca_scheme)) ||
      (realm != NULL && strcmp(realm, ca->ca_realm)))
    return -1;

  ca->ca_user = su_strdup(ca->ca_home, user);
  ca->ca_pass = su_strdup(ca->ca_home, pass);

  if (!ca->ca_user || !ca->ca_pass)
    return -1;

  return 1;
}

/**Clear authentication data from the authenticator.
 *
 * The function auc_clear_credentials() is used to remove the credentials
 * from the authenticators.
 *
 * @param auc_list [in/out] list of authenticators 
 * @param scheme   [in] scheme (if non-null, remove only matching credentials) 
 * @param realm    [in] realm (if non-null, remove only matching credentials)
 *
 * @retval 0 when successful
 * @retval -1 upon an error
 */
int auc_clear_credentials(auth_client_t **auc_list, 
			 char const *scheme,
			 char const *realm)
{
  int retval = 0;

  for (; *auc_list; auc_list = &(*auc_list)->ca_next) {
    int match = ca_clear_credentials(*auc_list, scheme, realm);
    if (match < 0) {
      retval = -1;
      break;
    }
    if (match) 
      retval++;
  }

  return retval;
}

static
int ca_clear_credentials(auth_client_t *ca, 
			 char const *scheme,
			 char const *realm)
{
  assert(ca);

  if (!ca || !ca->ca_scheme || !ca->ca_realm)
    return -1;

  if ((scheme != NULL && strcasecmp(scheme, ca->ca_scheme)) ||
      (realm != NULL && strcmp(realm, ca->ca_realm)))
    return -1;

  su_free(ca->ca_home, (void *)ca->ca_user), ca->ca_user = NULL;
  su_free(ca->ca_home, (void *)ca->ca_pass), ca->ca_pass = NULL;

  return 1;
}

/**Authorize a request.
 *
 * The function auc_authorization() is used to add correct authentication
 * headers to a request. The authentication headers will contain the
 * credentials generated by the list of authenticators.
 *
 * @param auc_list [in/out] list of authenticators 
 * @param msg      [out]    message to be authenticated
 * @param pub      [out]    headers of the message
 * @param method   [in]     request method
 * @param url      [in]     request URI
 * @param body     [in]     message body (NULL if empty)
 * 
 * @retval 1 when successful
 * @retval 0 when there is not enough credentials
 * @retval -1 upon an error
 */
int auc_authorization(auth_client_t **auc_list, msg_t *msg, msg_pub_t *pub,
		      char const *method, 
		      url_t const *url, 
		      msg_payload_t const *body)
{
  auth_client_t *ca;
  msg_mclass_t const *mc = msg_mclass(msg);

  /* Make sure every challenge has credentials */
  for (ca = *auc_list; ca; ca = ca->ca_next) {
    if (!ca->ca_user || !ca->ca_pass || !ca->ca_authorize)
      return 0;
  }

  /* Remove existing credentials */
  for (ca = *auc_list; ca; ca = ca->ca_next) {
    msg_header_t **hh = msg_hclass_offset(mc, pub, ca->ca_credential_class);

    while (hh && *hh)
      msg_header_remove(msg, pub, *hh);
  }

  /* Insert new credentials */
  for (; *auc_list; auc_list = &(*auc_list)->ca_next) {
    msg_header_t *h;

    h = (*auc_list)->ca_authorize(*auc_list, msg_home(msg), method, url, body);

    if (!h || msg_header_insert(msg, pub, h) < 0)
      return 0;
  }

  return 1;
}

/**Generate headers authorizing a request.
 *
 * The function auc_authorization_headers() is used to generate
 * authentication headers for a request. The list of authentication headers
 * will contain the credentials generated by the list of authenticators.
 *
 * @param auc_list [in/out] list of authenticators 
 * @param home     [in]     memory home used to allocate headers
 * @param method   [in]     request method
 * @param url      [in]     request URI
 * @param body     [in]     message body (NULL if empty)
 * @param return_headers [out] authorization headers
 * 
 * @retval 1 when successful
 * @retval 0 when there is not enough credentials
 * @retval -1 upon an error
 */
int auc_authorization_headers(auth_client_t **auc_list, 
			      su_home_t *home,
			      char const *method, 
			      url_t const *url, 
			      msg_payload_t const *body,
			      msg_header_t **return_headers)
{
  auth_client_t *ca;

  /* Make sure every challenge has credentials */
  for (ca = *auc_list; ca; ca = ca->ca_next) {
    if (!ca->ca_user || !ca->ca_pass || !ca->ca_authorize)
      return 0;
  }

  /* Insert new credentials */
  for (; *auc_list; auc_list = &(*auc_list)->ca_next) {
    msg_header_t *h;

    h = (*auc_list)->ca_authorize(*auc_list, home, method, url, body);

    if (!h)
      return -1;

    *return_headers = h;

    return_headers = &h->sh_next;
  }

  return 1;
}

/**Create a basic authorization header.
 *
 * The function auc_basic_authorization() creates a basic authorization
 * header from username @a user and password @a pass. The authorization
 * header type is determined by @a hc - it can be sip_authorization_class,
 * sip_proxy_authorization_class, http_authorization_class, or
 * http_proxy_authorization_class, for instance.
 *
 * @param home memory home used to allocate memory for the new header
 * @param hc   header class for the header to be created
 * @param user user name
 * @param pass password
 * 
 * @return
 * The function auc_basic_authorization() returns a pointer to newly created 
 * authorization header, or NULL upon an error.
 */
msg_header_t *auc_basic_authorization(auth_client_t *ca, 
				      su_home_t *home,
				      char const *method, 
				      url_t const *url, 
				      msg_payload_t const *body)
{
  char userpass[49];		/* "reasonable" maximum */
  char base64[65];
  msg_hclass_t *hc = ca->ca_credential_class;
  char const *user = ca->ca_user;
  char const *pass = ca->ca_pass;

  userpass[sizeof(userpass) - 1] = 0;
  base64[sizeof(base64) - 1] = 0;
    
  /*
   * Basic authentication consists of username and password separated by
   * colon and then base64 encoded.
   */
  snprintf(userpass, sizeof(userpass) - 1, "%s:%s", user, pass);
  base64_e(base64, sizeof(base64), userpass, strlen(userpass));

  return msg_header_format(home, hc, "Basic %s", base64);
}

/**Create a digest authorization header.
 *
 * The function auc_digest_authorization() creates a digest authorization
 * header from username @a user and password @a pass, client nonce @a
 * cnonce, client nonce count @a nc, request method @a method, request URI
 * @a uri and message body @a data. The authorization header type is
 * determined by @a hc - it can be either sip_authorization_class or
 * sip_proxy_authorization_class, as well as http_authorization_class or
 * http_proxy_authorization_class.
 *
 * @param home 	  memory home used to allocate memory for the new header
 * @param hc   	  header class for the header to be created
 * @param user 	  user name
 * @param pass 	  password
 * @param ac      challenge structure
 * @param cnonce  client nonce
 * @param nc      client nonce count 
 * @param method  request method
 * @param uri     request uri
 * @param data    message body
 * @param dlen    length of message body
 *
 * @return
 * The function auc_digest_authorization() returns a pointer to newly created 
 * authorization header, or NULL upon an error.
 */
msg_header_t *auc_digest_authorization(auth_client_t *ca, 
				       su_home_t *home,
				       char const *method, 
				       url_t const *url, 
				       msg_payload_t const *body)
{
  msg_hclass_t *hc = ca->ca_credential_class;
  char const *user = ca->ca_user;
  char const *pass = ca->ca_pass;
  auth_challenge_t const *ac = ca->ca_ac;
  char const *cnonce = ca->ca_cnonce;
  char *uri = url_as_string(home, url);
  void const *data = body ? body->pl_data : "";
  int dlen = body ? body->pl_len : 0;

  msg_header_t *h;
  auth_hexmd5_t sessionkey, response;
  auth_response_t ar[1] = {{ 0 }};
  char ncount[17];

  ar->ar_size = sizeof(ar);
  ar->ar_username = user;
  ar->ar_realm = ac->ac_realm;
  ar->ar_nonce = ac->ac_nonce;
  ar->ar_algorithm = NULL;
  ar->ar_md5 = ac->ac_md5;
  ar->ar_md5sess = ac->ac_md5sess;
  ar->ar_opaque = ac->ac_opaque;
  ar->ar_qop = NULL;
  ar->ar_auth = ac->ac_auth;
  ar->ar_auth_int = ac->ac_auth_int;
  ar->ar_uri = uri;

  /* If there is no qop, we MUST NOT include cnonce or nc */
  if (!ar->ar_auth && !ar->ar_auth_int)
    cnonce = NULL;

  if (cnonce) {
    snprintf(ncount, sizeof(ncount), "%08x", ++ca->ca_ncount);
    ar->ar_cnonce = cnonce;
    ar->ar_nc = ncount;
  }

  auth_digest_sessionkey(ar, sessionkey, pass);
  auth_digest_response(ar, response, sessionkey, method, data, dlen);

  h = msg_header_format(home, hc, 
			"Digest "
			"username=\"%s\", "
			"realm=\"%s\", "
			"nonce=\"%s"
			"%s%s"
			"%s%s"
			"%s%s, "
			"uri=\"%s\", "
			"response=\"%s\""
			"%s%s"
			"%s%s",
			ar->ar_username, 
			ar->ar_realm,
			ar->ar_nonce,
			cnonce ? "\",  cnonce=\"" : "", 
			cnonce ? cnonce : "",
			ar->ar_opaque ? "\",  opaque=\"" : "", 
			ar->ar_opaque ? ar->ar_opaque : "",
			ar->ar_algorithm ? "\", algorithm=" : "",
			ar->ar_algorithm ? ar->ar_algorithm : "",
			ar->ar_uri,
			response,
			ar->ar_auth || ar->ar_auth_int ? ", qop=" : "", 
			ar->ar_auth_int ? "auth-int" : 
			(ar->ar_auth ? "auth" : ""),
			cnonce ? ", nc=" : "", 
			cnonce ? ncount : "");

  su_free(home, uri);
  return h;
}

#if HAVE_SOFIA_SIP
#include <sip.h>

/**Authorize a SIP request.
 *
 * The function auc_authorize() is used to add correct authentication
 * headers to a SIP request. The authentication headers will contain the
 * credentials generated by the list of authenticators.
 *
 * @param auc_list [in/out] list of authenticators 
 * @param msg      [in/out] message to be authenticated
 * @param sip      [in/out] sip headers of the message
 * 
 * @retval 1 when successful
 * @retval 0 when there is not enough credentials
 * @retval -1 upon an error
 */
int auc_authorize(auth_client_t **auc_list, msg_t *msg, sip_t *sip)
{
  sip_request_t *rq = sip->sip_request;

  return auc_authorization(auc_list, msg, (msg_pub_t *)sip, 
			   rq->rq_method_name, 
			   /* XXX - why this was needed?
			      rq->rq_method == sip_method_register 
			      ? sip->sip_to->a_url : */
			   rq->rq_url, 
			   sip->sip_payload);
}
#endif
