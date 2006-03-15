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

#ifndef SIP_UTIL_H /** Defined when <sip_util.h> has been included. */
#define SIP_UTIL_H 

/**@file sip_util.h 
 * @brief SIP utility functions
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Thu Jun  8 19:28:55 2000 ppessi
 */

#ifndef SIP_H
#include <sofia-sip/sip.h>
#endif

#ifndef STRING0_H
#include <sofia-sip/string0.h>
#endif

SOFIA_BEGIN_DECLS

char const *sip_params_find(sip_param_t const pp[], char const *token);
int sip_params_add(su_home_t *sh, sip_param_t **pparams, char const *param);
int sip_params_cmp(sip_param_t const a[], sip_param_t const b[]);
int sip_params_replace(su_home_t *, sip_param_t **pparams, char const *param);

sip_contact_t *
sip_contact_create_from_via_with_transport(su_home_t *home, 
					   sip_via_t const *v,
					   char const *user,
					   char const *transport);

sip_contact_t *sip_contact_create_from_via(su_home_t *, sip_via_t const *,
					   char const *user);

char *
sip_contact_string_from_via(su_home_t *home,
			    sip_via_t const *v,
			    char const *user,
			    char const *transport);

int sip_transport_has_tls(char const *transport_name);

int sip_response_terminates_dialog(int response_code,
				   sip_method_t method,
				   int *return_graceful_terminate);

int sip_sanity_check(sip_t const *sip);

unsigned sip_q_value(char const * q);

url_t *sip_url_dup(su_home_t *sh, url_t const *o);

/**Add optional prefix and string to argument list if @a s is non-NULL. 
 * @HIDE
 */
#define SIP_STRLOG(prefix, s) ((s) ? (prefix) : ""), ((s) ? (s) : "")

int sip_addr_match(sip_addr_t const *a, sip_addr_t const *b);

/* ----------------------------------------------------------------------
 * Header-specific functions below
 */

int sip_route_is_loose(sip_route_t const *r);
sip_route_t *sip_route_remove(msg_t *msg, sip_t *sip);
sip_route_t *sip_route_pop(msg_t *msg, sip_t *sip);
sip_route_t *sip_route_follow(msg_t *msg, sip_t *sip);
sip_route_t *sip_route_reverse(su_home_t *home, sip_route_t const *route);
sip_route_t *sip_route_fixdup(su_home_t *home, sip_route_t const *route);
sip_route_t *sip_route_fix(sip_route_t *route);

sip_via_t *sip_via_remove(msg_t *msg, sip_t *sip);

/* ---------------------------------------------------------------------- */
/* Caller preferences */

/** Check callerprefs. */
int sip_prefs_matching(char const *pvalue,
		       char const *nvalue, 		       
		       int *return_parse_error);
int sip_is_callerpref(char const *param);

/** Type of the SIP media tag */
enum sp_type { 
  sp_error = -1, 
  sp_init,
  sp_literal,
  sp_string,
  sp_range,
};


/** Possible values for SIP media tags */
union sip_pref
{
  /** Type of the media tag */
  enum sp_type sp_type;

  /** Literal (tag="foo"). */
  struct sp_literal {
    enum sp_type spl_type; 
    char const *spl_value;
    unsigned spl_length;
  } sp_literal;

  /** String (tag="&lt;foo&gt;"). */
  struct sp_string {
    enum sp_type sps_type;
    char const *sps_value;
    unsigned sps_length;
  } sp_string;

  /** Numeric value or range (tag="#=1"; tag="#<=3"; tag="#>=-2"; tag="#1:6").
   */
  struct sp_range {
    enum sp_type spr_type;
    double spr_lower;
    double spr_upper;
  } sp_range;
};

/** Parse a single preference */
int sip_prefs_parse(union sip_pref *sp, 
		    char const **in_out_s, 
		    int *return_negation);

/** Match preferences */
int sip_prefs_match(union sip_pref const *a, union sip_pref const *b);

int sip_contact_immune(sip_contact_t const *m);
sip_contact_t *sip_contact_immunize(su_home_t *home, 
				    sip_contact_t const *m);

int sip_contact_reject(sip_contact_t const *m, 
		       sip_reject_contact_t const *rc);

int sip_contact_accept(sip_contact_t const *m, 
		       sip_accept_contact_t const *cp,
		       unsigned *return_S,
		       unsigned *return_N,
		       int *return_error);

int sip_contact_score(sip_contact_t const *m,
		      sip_accept_contact_t const *ac,
		      sip_reject_contact_t const *rc);

int sip_aor_strip(url_t *url);

int sip_security_verify_compare(sip_security_server_t const *s,
				sip_security_verify_t const *v,
				char const **return_d_ver);

sip_security_client_t const *
sip_security_client_select(sip_security_client_t const *client,
			   sip_security_server_t const *server);

SOFIA_END_DECLS

#endif /** !defined(SIP_UTIL_H) */
