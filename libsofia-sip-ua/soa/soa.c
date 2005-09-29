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

/**@CFILE soa.c
 * @brief Sofia SDP Offer/Answer Engine interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Wed Aug  3 20:27:15 EEST 2005
 * $Date: 2005/09/29 18:35:22 $
 */

#include "config.h"

const char soa_c_id[] =
"$Id: soa.c,v 1.7 2005/09/29 18:35:22 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <su_tag_class.h>
#include <su_wait.h>

#include "soa.h"
const char soa_h_id[] = SOA_H;
#include "sdp.h"
#include "soa_session.h"
const char soa_session_h_id[] = SOA_SESSION_H;
#include "soa_add.h"
const char soa_add_h_id[] = SOA_ADD_H;

#include <su_tagarg.h>
#include <su_localinfo.h>
#include <su_uniqueid.h>

#include <string0.h>

#define NONE ((void *)-1)
#define XXX assert(!"implemented")

typedef unsigned longlong ull;

/* ======================================================================== */

/* Internal prototypes */
void soa_set_activity(soa_session_t *ss,
		      sdp_media_t const *,
		      int remote);

static inline int soa_media_is_ready(soa_session_t const *ss);

enum soa_sdp_kind { 
  soa_capability_sdp_kind,
  soa_user_sdp_kind,
  soa_remote_sdp_kind
};

static int soa_set_sdp(soa_session_t *ss, 
		       enum soa_sdp_kind what,
		       sdp_session_t const *sdp0,
		       char const *sdp_str, int str_len);

/* ======================================================================== */

#define SOA_VALID_ACTIONS(a)					\
  ((a)->sizeof_soa_session_actions >= sizeof (*actions) &&	\
   (a)->sizeof_soa_session >= sizeof(soa_session_t) &&		\
   (a)->soa_init != NULL &&					\
   (a)->soa_set_params != NULL &&				\
   (a)->soa_get_params != NULL &&				\
   (a)->soa_generate_offer != NULL &&				\
   (a)->soa_generate_answer != NULL &&				\
   (a)->soa_activate_session != NULL &&				\
   (a)->soa_terminate_session != NULL)

/* ======================================================================== */

/**@var SOA_DEBUG
 *
 * Environment variable determining the default debug log level.
 *
 * The SOA_DEBUG environment variable is used to determine the default
 * debug logging level. The normal level is 3.
 *
 * @sa <su_debug.h>, su_log_global, SOFIA_DEBUG
 */
extern char const SOA_DEBUG[];

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif

/**Debug log for @b soa module.
 *
 * The soa_log is the log object used by @b soa module. The level of
 * #soa_log is set using #SOA_DEBUG environment variable.
 */
su_log_t soa_log[] = { SU_LOG_INIT("soa", "SOA_DEBUG", SU_DEBUG) };

/* ======================================================================== */

/* API Functions */

struct soa_namenode
{
  struct soa_namenode const *next;
  char const *basename;
  struct soa_session_actions const *actions;
};

#define SOA_NAMELISTLEN (16)

static struct soa_namenode const soa_default_node =
  {
    NULL, "default", &soa_default_actions
  };

static struct soa_namenode const *soa_namelist = &soa_default_node;

/** Add a named soa backend */
int soa_add(char const *name,
	    struct soa_session_actions const *actions)
{
  struct soa_namenode const *n;
  struct soa_namenode *e;

  if (name == NULL || actions == NULL)
    return (errno = EFAULT), -1;

  if (!SOA_VALID_ACTIONS(actions))
    return (errno = EINVAL), -1;

  for (n = soa_namelist; n; n = n->next) {
    if (strcasecmp(name, n->basename) == 0)
      return 0;
  }

  e = malloc(sizeof *e); if (!e) return -1;

  e->next = soa_namelist;
  e->basename = name;
  e->actions = actions;

  soa_namelist = e;

  return 0;
}

/** Search for a named backend */
struct soa_session_actions const *soa_find(char const *name)
{
  if (name) {
    struct soa_namenode const *n;
    size_t baselen = strcspn(name, ":/");

    for (n = soa_namelist; n; n = n->next) {
      if (strncasecmp(name, n->basename, baselen) == 0)
	break;
    }

    if (n == NULL)
      return (void)(errno = ENOENT), NULL;

    return n->actions;
  }

  return NULL;
}

/* ======================================================================== */

soa_session_t *soa_create(char const *name,
			  su_root_t *root,
			  soa_magic_t *magic)
{
  struct soa_session_actions const *actions = &soa_default_actions;

  soa_session_t *ss;
  size_t namelen;

  if (name && name[0]) {
    struct soa_namenode const *n;
    size_t baselen = strcspn(name, ":/");

    for (n = soa_namelist; n; n = n->next) {
      if (strncasecmp(name, n->basename, baselen) == 0)
	break;
    }
    if (n == NULL)
      return (void)(errno = ENOENT), NULL;

    actions = n->actions; assert(actions);
  }
  else
    name = "default";

  assert(SOA_VALID_ACTIONS(actions));

  if (root == NULL)
    return (void)(errno = EFAULT), NULL;

  namelen = strlen(name) + 1;
  
  ss = su_home_new(actions->sizeof_soa_session + namelen);
  if (ss) {
    ss->ss_root = root;
    ss->ss_magic = magic;
    ss->ss_actions = actions;
    ss->ss_name = strcpy((char *)ss + actions->sizeof_soa_session, name);

    if (ss->ss_actions->soa_init(name, ss, NULL) < 0)
      ss->ss_actions->soa_deinit(ss), ss = NULL;
  }

  return ss;
}

soa_session_t *soa_clone(soa_session_t *parent_ss,
			 su_root_t *root,
			 soa_magic_t *magic)
{
  soa_session_t *ss;
  size_t namelen;

  if (parent_ss == NULL || root == NULL)
    return (void)(errno = EFAULT), NULL;

  namelen = strlen(parent_ss->ss_name) + 1;

  ss = su_home_new(parent_ss->ss_actions->sizeof_soa_session + namelen);
  if (ss) {
    ss->ss_root = root;
    ss->ss_magic = magic;
    ss->ss_actions = parent_ss->ss_actions;
    ss->ss_name = strcpy((char *)ss + ss->ss_actions->sizeof_soa_session,
			 parent_ss->ss_name);

    if (ss->ss_actions->soa_init(NULL, ss, parent_ss) < 0)
      ss->ss_actions->soa_deinit(ss), ss = NULL;
  }

  return ss;
}

/** Increase reference count */
soa_session_t *soa_session_ref(soa_session_t *ss)
{
  return su_home_ref(ss->ss_home);
}

/** Decrease reference count */
void soa_session_unref(soa_session_t *ss)
{
  su_home_unref(ss->ss_home);
}

/* Initialize session */
int soa_base_init(char const *name,
		     soa_session_t *ss,
		     soa_session_t *parent)
{
  if (parent) {
#define DUP(d, dup, s) if ((s) && !((d) = dup(ss->ss_home, (s)))) return -1
    su_home_t *h = ss->ss_home;

    if (soa_description_dup(h, ss->ss_caps, parent->ss_caps) < 0)
      return -1;
    if (soa_description_dup(h, ss->ss_user, parent->ss_user) < 0)
      return -1;
    if (soa_description_dup(h, ss->ss_local, parent->ss_local) < 0)
      return -1;
    if (soa_description_dup(h, ss->ss_remote, parent->ss_remote) < 0)
      return -1;

    DUP(ss->ss_address, su_strdup, parent->ss_address);
    ss->ss_af = parent->ss_af;
    DUP(ss->ss_hold, su_strdup, parent->ss_hold);

    DUP(ss->ss_cname, su_strdup, parent->ss_cname);

    ss->ss_srtp_enable = parent->ss_srtp_enable;
    ss->ss_srtp_confidentiality = parent->ss_srtp_confidentiality;
    ss->ss_srtp_integrity = parent->ss_srtp_integrity;
  }

  return 0;
}

/** Destroy a session. */
void soa_destroy(soa_session_t *ss)
{
  if (ss) {
    ss->ss_active = 0;
    ss->ss_terminated++;
    ss->ss_actions->soa_deinit(ss);
    su_home_unref(ss->ss_home);
  }
}

void soa_base_deinit(soa_session_t *ss)
{
  (void)ss;
}

/** Set tagged parameters */
int soa_set_params(soa_session_t *ss, tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int n;

  if (ss == NULL)
    return (errno = EFAULT), -1;

  ta_start(ta, tag, value);

  n = ss->ss_actions->soa_set_params(ss, ta_args(ta));

  ta_end(ta);

  return n;
}

int soa_base_set_params(soa_session_t *ss, tagi_t const *tags)
{
  int n, change_session = 0;

  int af;

  sdp_session_t const *caps_sdp, *user_sdp;
  char const *caps_sdp_str, *user_sdp_str;

  char const *media_address, *hold;
  int srtp_enable, srtp_confidentiality, srtp_integrity;

  af = ss->ss_af;

  hold = ss->ss_hold;
  media_address = ss->ss_address;

  srtp_enable = ss->ss_srtp_enable;
  srtp_confidentiality = ss->ss_srtp_confidentiality;
  srtp_integrity = ss->ss_srtp_integrity;

  caps_sdp = user_sdp = NONE;
  caps_sdp_str = user_sdp_str = NONE;

  n = tl_gets(tags,

	      SOATAG_CAPS_SDP_REF(caps_sdp),
	      SOATAG_CAPS_SDP_STR_REF(caps_sdp_str),

	      SOATAG_USER_SDP_REF(user_sdp),
	      SOATAG_USER_SDP_STR_REF(user_sdp_str),

	      SOATAG_AF_REF(af),
	      SOATAG_ADDRESS_REF(media_address),
	      SOATAG_HOLD_REF(hold),

	      SOATAG_SRTP_ENABLE_REF(srtp_enable),
	      SOATAG_SRTP_CONFIDENTIALITY_REF(srtp_confidentiality),
	      SOATAG_SRTP_INTEGRITY_REF(srtp_integrity),

	      TAG_END());

  if (n <= 0)
    return n;

  if (caps_sdp != NONE || caps_sdp_str != NONE) {
    if (caps_sdp == NONE) caps_sdp = NULL;
    if (caps_sdp_str == NONE) caps_sdp_str = NULL;

    if (caps_sdp || caps_sdp_str) {
      if (soa_set_capability_sdp(ss, caps_sdp, caps_sdp_str, -1) < 0) {
	return -1;
      }
    }
    else {
      soa_description_free(ss, ss->ss_caps);
    }
  }

  if (user_sdp != NONE || user_sdp_str != NONE) {
    if (user_sdp == NONE) user_sdp = NULL;
    if (user_sdp_str == NONE) user_sdp_str = NULL;

    if (user_sdp || user_sdp_str) {
      if (soa_set_user_sdp(ss, user_sdp, user_sdp_str, -1) < 0) {
	return -1;
      }
      if (ss->ss_caps->ssd_str == NULL)
	soa_set_capability_sdp(ss, user_sdp, user_sdp_str, -1);
    }
    else {
      soa_description_free(ss, ss->ss_user);
    }
  }

  if (af != ss->ss_af &&
      af >= SOA_AF_ANY && af <= SOA_AF_IP6_IP4) {
    ss->ss_af = af;
    change_session = 1;
  }

  if (str0casecmp(media_address, ss->ss_address)) {
    su_free(ss->ss_home, (void *)ss->ss_address);
    ss->ss_address = su_strdup(ss->ss_home, media_address);
    change_session = 1;
  }

  if (hold == (char const *)1)
    hold = "*";

  if (str0casecmp(hold, ss->ss_hold)) {
    su_free(ss->ss_home, (void *)ss->ss_hold);
    ss->ss_hold = su_strdup(ss->ss_home, hold);
    change_session = 1;
  }

  if (change_session)
    ss->ss_user_version++;

  return n;
}

/** Get tagged parameters */
int soa_get_params(soa_session_t const *ss,
		   tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  int n;

  if (ss == NULL)
    return (errno = EFAULT), -1;

  ta_start(ta, tag, value);

  n = ss->ss_actions->soa_get_params(ss, ta_args(ta));

  ta_end(ta);

  return n;
}

int soa_base_get_params(soa_session_t const *ss, tagi_t *tags)
{
  int n;

  n = tl_tgets(tags,
	       SOATAG_CAPS_SDP(ss->ss_caps->ssd_sdp),
	       SOATAG_CAPS_SDP_STR(ss->ss_caps->ssd_str),

	       SOATAG_USER_SDP(ss->ss_user->ssd_sdp),
	       SOATAG_USER_SDP_STR(ss->ss_user->ssd_str),

	       SOATAG_LOCAL_SDP(ss->ss_local->ssd_sdp),
	       SOATAG_LOCAL_SDP_STR(ss->ss_local->ssd_str),

	       SOATAG_REMOTE_SDP(ss->ss_remote->ssd_sdp),
	       SOATAG_REMOTE_SDP_STR(ss->ss_remote->ssd_str),

	       SOATAG_AF(ss->ss_af),
	       SOATAG_ADDRESS(ss->ss_address),
	       SOATAG_HOLD(ss->ss_hold),

	       SOATAG_SRTP_ENABLE(ss->ss_srtp_enable),
	       SOATAG_SRTP_CONFIDENTIALITY(ss->ss_srtp_confidentiality),
	       SOATAG_SRTP_INTEGRITY(ss->ss_srtp_integrity),

	       TAG_END());

  return n;
}

/** Return a list of parameters */
tagi_t *soa_get_paramlist(soa_session_t const *ss,
			  tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  tagi_t *params = NULL;

  if (ss) {
    ta_start(ta, tag, value);
    params = ss->ss_actions->soa_get_paramlist(ss, ta_tags(ta));
    ta_end(ta);
  }

  return params;
}


tagi_t *soa_base_get_paramlist(soa_session_t const *ss, 
			       tag_type_t tag, tag_value_t value, 
			       ...)
{
  ta_list ta;
  tagi_t *params;

  if (ss == NULL)
    return NULL;
  
  ta_start(ta, tag, value);

  params = tl_list(
		   TAG_IF(ss->ss_caps->ssd_sdp,
			  SOATAG_CAPS_SDP(ss->ss_caps->ssd_sdp)),
		   TAG_IF(ss->ss_caps->ssd_str,
			  SOATAG_CAPS_SDP_STR(ss->ss_caps->ssd_str)),

		   TAG_IF(ss->ss_user->ssd_sdp,
			  SOATAG_USER_SDP(ss->ss_user->ssd_sdp)),
		   TAG_IF(ss->ss_user->ssd_str,
			  SOATAG_USER_SDP_STR(ss->ss_user->ssd_str)),

		   TAG_IF(ss->ss_local->ssd_sdp,
			  SOATAG_LOCAL_SDP(ss->ss_local->ssd_sdp)),
		   TAG_IF(ss->ss_user->ssd_str,
			  SOATAG_LOCAL_SDP_STR(ss->ss_local->ssd_str)),

		   TAG_IF(ss->ss_remote->ssd_sdp,
			  SOATAG_REMOTE_SDP(ss->ss_remote->ssd_sdp)),
		   TAG_IF(ss->ss_remote->ssd_str,
			  SOATAG_REMOTE_SDP_STR(ss->ss_remote->ssd_str)),

		   SOATAG_AF(ss->ss_af),
		   TAG_IF(ss->ss_address, 
			  SOATAG_ADDRESS(ss->ss_address)),

		   SOATAG_SRTP_ENABLE(ss->ss_srtp_enable),
		   SOATAG_SRTP_CONFIDENTIALITY(ss->ss_srtp_confidentiality),
		   SOATAG_SRTP_INTEGRITY(ss->ss_srtp_integrity),

		   ta_tags(ta));

  ta_end(ta);

  return params;
}

#include <sip_status.h>

int soa_error_as_sip_response(soa_session_t *ss,
			      char const **return_phrase)
{
  if (ss == NULL) {
    if (return_phrase)
      *return_phrase = sip_500_Internal_server_error;
    return 500;
  }

  if (return_phrase)
    *return_phrase = sip_501_Not_implemented;

  return 501;
}

char const *soa_error_as_sip_reason(soa_session_t *ss)
{
  return "SIP;cause=501;text=\"Unimplemented media\"";
}


/** Return SDP description of capabilities.
 *
 * @retval 0 if there is no description to return
 * @retval 1 if description is returned
 * @retval -1 upon an error
 */
int soa_get_capability_sdp(soa_session_t const *ss,
			   char const **return_sdp,
			   int *return_len)
{
  char const *sdp;

  if (ss == NULL)
    return (void)(errno = EFAULT), -1;

  sdp = ss->ss_caps->ssd_str;

  if (sdp == NULL)
    return 0;
  if (return_sdp)
    *return_sdp = sdp;
  if (return_len)
    *return_len = strlen(sdp);

  return 1;
}


int soa_set_capability_sdp(soa_session_t *ss, 
			   sdp_session_t const *sdp,
			   char const *str, int len)
{
  return soa_set_sdp(ss, soa_capability_sdp_kind, sdp, str, len);
}

/** Set capabilities */
int 
soa_base_set_capability_sdp(soa_session_t *ss, 
			    sdp_session_t *sdp, char const *str0, int len0)
{
  sdp_origin_t o[1] = {{ sizeof(o) }};
  sdp_connection_t *c, c0[1] = {{ sizeof(c0) }};
  char c_address[64];
  sdp_time_t t[1] = {{ sizeof(t) }};
  sdp_media_t *m;

  if (sdp->sdp_origin)
    *o = *sdp->sdp_origin;
  else
    o->o_address = c0;

  sdp->sdp_origin = o;

  if (soa_init_sdp_origin(ss, o, c_address) < 0)
    return -1;

  if (!sdp->sdp_subject)
    sdp->sdp_subject = "-";

  sdp->sdp_time = t;

  /* Set port to zero - or should we check that port is already zero? */
  for (m = sdp->sdp_media; m; m = m->m_next)
    m->m_port = 0;

  c = sdp->sdp_origin->o_address;

  if (sdp->sdp_connection == NULL) {
    for (m = sdp->sdp_media; m; m = m->m_next)
      if (m->m_connections == NULL)
	break;
    if (m)
      sdp->sdp_connection = c;
  }

  return soa_description_set(ss, ss->ss_caps, sdp, str0, len0);
}

/** Return SDP description of the session.
 *
 * @retval 0 if there is no description to return
 * @retval 1 if description is returned
 * @retval -1 upon an error
 */
int soa_get_user_sdp(soa_session_t const *ss,
		      char const **return_sdp,
		      int *return_len)
{
  char const *sdp_str;

  if (ss == NULL)
    return (void)(errno = EFAULT), -1;

  /* return modified user SDP if available */
  if (ss->ss_local->ssd_str)
    sdp_str = ss->ss_local->ssd_str;
  else
    sdp_str = ss->ss_user->ssd_str;

  if (sdp_str == NULL)
    return 0;
  if (return_sdp)
    *return_sdp = sdp_str;
  if (return_len)
    *return_len = strlen(sdp_str);

  return 1;
}

/** 
 * Returns the version number of user session
 * description. The version numbering starts from
 * zero and is incremented for each modification.
 */
int soa_get_user_version(soa_session_t const *ss)
{
  assert(ss != NULL);
  return ss->ss_user_version;
} 

int soa_set_user_sdp(soa_session_t *ss, 
		     sdp_session_t const *sdp,
		     char const *str, int len)
{
  return soa_set_sdp(ss, soa_user_sdp_kind, sdp, str, len);
}

/** Set user SDP (base version). */
int soa_base_set_user_sdp(soa_session_t *ss, 
			   sdp_session_t *sdp, char const *str0, int len0)
{
  ++ss->ss_user_version;
  return soa_description_set(ss, ss->ss_user, sdp, str0, len0);
}

/** Return remote SDP description of the session.
 *
 * @retval 0 if there is no description to return
 * @retval 1 if description is returned
 * @retval -1 upon an error
 */
int soa_get_remote_sdp(soa_session_t const *ss,
		       char const **return_sdp,
		       int *return_len)
{
  char const *sdp;

  if (ss == NULL)
    return (void)(errno = EFAULT), -1;

  sdp = ss->ss_remote->ssd_str;

  if (sdp == NULL)
    return 0;
  if (return_sdp)
    *return_sdp = sdp;
  if (return_len)
    *return_len = strlen(sdp);

  return 1;
}

/** 
 * Returns the version number of remote session
 * description. The version numbering starts from
 * zero and is incremented for each modification.
 */
int soa_get_remote_version(soa_session_t const *ss)
{
  assert(ss != NULL);
  return ss->ss_remote_version;
} 

int soa_set_remote_sdp(soa_session_t *ss, 
		       sdp_session_t const *sdp,
		       char const *str, int len)
{
  return soa_set_sdp(ss, soa_remote_sdp_kind, sdp, str, len);
}

/** Set remote SDP (base version). */
int soa_base_set_remote_sdp(soa_session_t *ss,
			    int new_version,
			    sdp_session_t *sdp, char const *str0, int len0)
{
  /* This is cleared in soa_generate_answer() or soa_process_answer(). */
  ss->ss_unprocessed_remote = 1;

  if (!new_version)
    return 0;
    
  soa_set_activity(ss, sdp->sdp_media, 1);

  ss->ss_remote_version++;
  
  return soa_description_set(ss, ss->ss_remote, sdp, str0, len0);
}

int soa_clear_remote_sdp(soa_session_t *ss)
{
  if (!ss)
    return (void)(errno = EFAULT), -1;

  ss->ss_unprocessed_remote = 0;

  return 0;
}

int soa_get_local_sdp(soa_session_t const *ss,
		      char const **return_sdp,
		      int *return_len)
{
  char const *sdp;

  if (ss == NULL)
    return (void)(errno = EFAULT), -1;

  sdp = ss->ss_local->ssd_str;

  if (sdp == NULL)
    return 0;
  if (return_sdp)
    *return_sdp = sdp;
  if (return_len)
    *return_len = strlen(sdp);

  return 1;
}

/** Initialize offer/answer state machine */
int soa_init_offer_answer(soa_session_t *ss)
{
  int complete;

  if (!ss)
    return 0;

  complete = ss->ss_complete;

  ss->ss_complete = 0;
  ss->ss_offer_sent = 0;
  ss->ss_offer_recv = 0;
  ss->ss_answer_sent = 0;
  ss->ss_answer_recv = 0;

  ss->ss_unprocessed_remote = 0;

  return complete;
}

char **soa_media_features(soa_session_t *ss, int live, su_home_t *home)
{
  if (ss)
    return ss->ss_actions->soa_media_features(ss, live, home);
  else
    return (void)(errno = EFAULT), NULL;
}

char **soa_base_media_features(soa_session_t *ss, int live, su_home_t *home)
{
  return su_zalloc(home, 8 * sizeof (char **));
}

char const * const * soa_sip_required(soa_session_t const *ss)
{
  if (ss)
    return ss->ss_actions->soa_sip_required(ss);
  else
    return (void)(errno = EFAULT), NULL;
}

char const * const * soa_base_sip_required(soa_session_t const *ss)
{
  static char const *null = NULL;
  return &null;
}

char const * const * soa_sip_support(soa_session_t const *ss)
{
  if (ss)
    return ss->ss_actions->soa_sip_support(ss);
  else
    return (void)(errno = EFAULT), NULL;
}

char const * const * soa_base_sip_support(soa_session_t const *ss)
{
  static char const *null = NULL;
  return &null;
}

int soa_remote_sip_features(soa_session_t *ss,
			    char const * const * support,
			    char const * const * required)
{
  if (ss)
    return ss->ss_actions->soa_remote_sip_features(ss, support, required);
  else
    return (void)(errno = EFAULT), -1;
}

int soa_base_remote_sip_features(soa_session_t *ss,
				    char const * const * support,
				    char const * const * required)
{
  return 0;
}


/** Run Offer step.
 *
 * @param ss pointer to session object
 * @param always always send offer (even if offer/answer has been completed)
 * @param completed pointer to callback function which is invoked when
 *                  operation is completed
 *
 * @retval 1 when operation is successful
 * @retval 0 when operation is not needed
 * @retval -1 upon an error
 *
 * @ERRORS
 */
int soa_generate_offer(soa_session_t *ss,
		       int always,
		       soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address. */
  if (ss == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have received offer, now we should send answer */
  if (ss->ss_offer_recv && !ss->ss_answer_sent)
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have received SDP, but it has not been processed */
  if (soa_has_received_sdp(ss))
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have sent an offer, but have received no answer */
  if (ss->ss_offer_sent && !ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have received offer. */
  if (ss->ss_unprocessed_remote)
    return (errno = EPROTO), -1;

  /* We should avoid actual operation unless always is true */
  (void)always;  /* We always regenerate offer */

  return ss->ss_actions->soa_generate_offer(ss, completed);
}

int soa_base_generate_offer(soa_session_t *ss,
			    soa_callback_f *completed)
{
  sdp_session_t const *sdp = ss->ss_user->ssd_sdp;

  (void)completed;

  if (!sdp)
    return -1;

  soa_set_activity(ss, sdp->sdp_media, 0);

  ss->ss_offer_sent = 1;
  ss->ss_answer_recv = 0;

  return 0;
}

/* Generate answer */
int soa_generate_answer(soa_session_t *ss,
			soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress. */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have sent an offer, but have received no answer. */
  if (ss->ss_offer_sent && !ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have not received offer. */
  if (!ss->ss_unprocessed_remote)
    return (errno = EPROTO), -1;

  return ss->ss_actions->soa_generate_answer(ss, completed);
}

int soa_base_generate_answer(soa_session_t *ss,
			     soa_callback_f *completed)
{
  sdp_session_t const *l_sdp = ss->ss_user->ssd_sdp;
  sdp_session_t const *r_sdp = ss->ss_remote->ssd_sdp;
  sdp_session_t *rsession;

  (void)completed;

  if (!l_sdp || !r_sdp)
    return -1;
  rsession = sdp_session_dup(ss->ss_home, r_sdp);
  if (!rsession)
    return -1;

  if (ss->ss_rsession)
    su_free(ss->ss_home, ss->ss_rsession);
  ss->ss_rsession = rsession;

  soa_set_activity(ss, l_sdp->sdp_media, 0);
  soa_set_activity(ss, r_sdp->sdp_media, 1);

  ss->ss_offer_recv = 1;
  ss->ss_answer_sent = 1;
  ss->ss_complete = 1;
  ss->ss_unprocessed_remote = 0;

  return 0;
}

/** Complete offer-answer after receiving answer */
int soa_process_answer(soa_session_t *ss,
		       soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress. */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have not sent an offer 
      or already have received answer. */
  if (!ss->ss_offer_sent || ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have not received answer. */
  if (!ss->ss_unprocessed_remote)
    return (errno = EPROTO), -1;

  return ss->ss_actions->soa_process_answer(ss, completed);
}

/** 
 * Processes answer from remote end.
 */
int soa_base_process_answer(soa_session_t *ss,
			    soa_callback_f *completed)
{
  sdp_session_t const *l_sdp = ss->ss_local->ssd_sdp;
  sdp_session_t const *r_sdp = ss->ss_remote->ssd_sdp;
  sdp_session_t *rsession;

  (void)completed;

  if (!l_sdp || !r_sdp)
    return -1;
  rsession = sdp_session_dup(ss->ss_home, r_sdp);
  if (!rsession)
    return -1;

  if (ss->ss_rsession)
    su_free(ss->ss_home, ss->ss_rsession);
  ss->ss_rsession = rsession;

  soa_set_activity(ss, l_sdp->sdp_media, 0);
  soa_set_activity(ss, r_sdp->sdp_media, 1);

  ss->ss_answer_recv = 1;
  ss->ss_complete = 1;
  ss->ss_unprocessed_remote = 0;

  return 0;
}

/** Process rejection of offer */
int soa_process_reject(soa_session_t *ss,
		       soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress. */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have not sent an offer 
      or already have received answer. */
  if (!ss->ss_offer_sent || ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  return ss->ss_actions->soa_process_reject(ss, completed);
}

/** 
 * Process reject from remote end.
 */
int soa_base_process_reject(soa_session_t *ss,
			    soa_callback_f *completed)
{
  sdp_session_t const *l_sdp = ss->ss_local->ssd_sdp;

  (void)completed;

  if (!l_sdp)
    return -1;

  soa_set_activity(ss, l_sdp->sdp_media, 0);

  ss->ss_offer_sent = 0;

  return 0;
}

/** Activate session */
int soa_activate(soa_session_t *ss, char const *option)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return -1;

  ss->ss_active = 1;

  return ss->ss_actions->soa_activate_session(ss, option);
}

int soa_base_activate(soa_session_t *ss, char const *option)
{
  (void)ss;
  (void)option;
  return 0;
}

/** Deactivate session */
int soa_deactivate(soa_session_t *ss, char const *option)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return -1;

  ss->ss_active = 0;

  return ss->ss_actions->soa_deactivate_session(ss, option);
}

int soa_base_deactivate(soa_session_t *ss, char const *option)
{
  (void)ss;
  (void)option;
  return 0;
}

/** Terminate session */
void soa_terminate(soa_session_t *ss, char const *option)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return;

  ss->ss_active = 0;
  ss->ss_terminated++;

  ss->ss_actions->soa_terminate_session(ss, option);
}

void soa_base_terminate(soa_session_t *ss, char const *option)
{
  (void)option;

  soa_init_offer_answer(ss);
  ss->ss_oa_rounds = 0;

  soa_description_free(ss, ss->ss_remote);
  soa_set_activity(ss, NULL, 0);
  soa_set_activity(ss, NULL, 1);
}

int soa_has_received_sdp(soa_session_t const *ss)
{
  return ss && ss->ss_unprocessed_remote;
}

int soa_is_complete(soa_session_t const *ss)
{
  return ss && ss->ss_complete;
}

int soa_is_audio_active(soa_session_t const *ss)
{
  return ss ? ss->ss_local_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_video_active(soa_session_t const *ss)
{
  return ss ? ss->ss_local_activity->ma_video : SOA_ACTIVE_DISABLED;
}

int soa_is_image_active(soa_session_t const *ss)
{
  return ss ? ss->ss_local_activity->ma_image : SOA_ACTIVE_DISABLED;
}

int soa_is_chat_active(soa_session_t const *ss)
{
  return ss ? ss->ss_local_activity->ma_chat : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_audio_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_video_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_video : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_image_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_image : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_chat_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_chat : SOA_ACTIVE_DISABLED;
}

/* ======================================================================== */

int soa_set_status(soa_session_t *ss, int status, char const *phrase)
{
  if (ss)
    ss->ss_status = status, ss->ss_phrase = phrase;
  return -1;
}

static inline
int soa_media_is_ready(soa_session_t const *ss)
{
  XXX;
  return 0;
  /* return ss && ss->ss_session != NULL; */
}

void soa_set_activity(soa_session_t *ss,
		      sdp_media_t const *m,
		      int remote)
{
  struct soa_media_activity *ma;
  sdp_connection_t const *c;
  int mode;
  int ma_audio = SOA_ACTIVE_DISABLED;
  int ma_video = SOA_ACTIVE_DISABLED;
  int ma_chat = SOA_ACTIVE_DISABLED;
  int ma_image = SOA_ACTIVE_DISABLED;
  int *p;

  remote = !!remote;

  ma = remote ? ss->ss_remote_activity : ss->ss_local_activity;

  for (; m; m = m->m_next) {
    if (m->m_type == sdp_media_audio)
      p = &ma_audio;
    else if (m->m_type == sdp_media_video)
      p = &ma_video;
    else if (m->m_type == sdp_media_image)
      p = &ma_image;
    else if (strcasecmp(m->m_type_name, "message") == 0)
      p = &ma_chat;
    else
      continue;

    if (m->m_rejected) {
      if (*p < 0)
	*p = SOA_ACTIVE_REJECTED;
      continue;
    }

    mode = m->m_mode;

    c = sdp_media_connections((sdp_media_t *)m);

    if (remote != (c && c->c_mcast))
      mode = ((mode << 1) & 2) | ((mode >> 1) & 1);

    if (*p < 0)
      *p = mode;
    else
      *p |= mode;
  }

  ma->ma_audio = ma_audio;
  ma->ma_video = ma_video;
  ma->ma_image = ma_image;
  ma->ma_chat = ma_chat;
}

/* ----------------------------------------------------------------------*/
/* Handle SDP */


/**
 * Parses and stores session description
 * 
 * @param ss instance pointer
 * @param what caps, local or remote
 * @param sdp0 new sdp (parsed)
 * @param sdp_str new sdp (unparsed)
 * @param str_len length on unparsed data
 **/
static
int soa_set_sdp(soa_session_t *ss, 
		enum soa_sdp_kind what,
		sdp_session_t const *sdp0,
		char const *sdp_str, int str_len)
{
  struct soa_description *ssd;
  int flags, new_version;
  sdp_parser_t *parser = NULL;
  sdp_session_t sdp[1];

  switch (what) {
  case soa_capability_sdp_kind:
    ssd = ss->ss_caps;
    flags = sdp_f_config;
    break;
  case soa_user_sdp_kind:
    ssd = ss->ss_user;
    flags = sdp_f_config;
    break;
  case soa_remote_sdp_kind:
    ssd = ss->ss_remote;
    flags = sdp_f_mode_0000;
    break;
  default:
    return -1;
  }

  if (sdp0)
    new_version = sdp_session_cmp(sdp0, ssd->ssd_sdp) != 0;
  else if (sdp_str)
    new_version = str0cmp(sdp_str, ssd->ssd_unparsed) != 0;
  else
    return (void)(errno = EINVAL), -1;

  if (sdp_str && str_len == -1)
    str_len = strlen(sdp_str);

  if (!new_version) {
    if (what == soa_remote_sdp_kind) {
      *sdp = *ssd->ssd_sdp;
      /* XXX - should check changes by soa_set_remote_sdp */
      return ss->ss_actions->soa_set_remote_sdp(ss, new_version, 
						sdp, sdp_str, str_len);
    }
    return 0;
  } 

  if (sdp0) {
    /* note: case 1 - src in parsed form */
    *sdp = *sdp0;
  } 
  else /* if (sdp_str) */ {
    /* note: case 2 - src in unparsed form */
    parser = sdp_parse(ss->ss_home, sdp_str, str_len, flags | sdp_f_anynet);

    if (sdp_parsing_error(parser)) {
      sdp_parser_free(parser);
      return soa_set_status(ss, 400, "Bad Session Description");
    }

    *sdp = *sdp_session(parser);
  }
 
  switch (what) {
  case soa_capability_sdp_kind:
    return ss->ss_actions->soa_set_capability_sdp(ss, sdp, sdp_str, str_len);
  case soa_user_sdp_kind:
    return ss->ss_actions->soa_set_user_sdp(ss, sdp, sdp_str, str_len);
  case soa_remote_sdp_kind:
    return ss->ss_actions->soa_set_remote_sdp(ss, 1, sdp, sdp_str, str_len);
  default:
    return -1;
  }
}


/** Set session descriptions. */
int soa_description_set(soa_session_t *ss,
			struct soa_description *ssd,
			sdp_session_t *sdp,
			char const *sdp_str,
			int str_len)
{
  int retval = -1;

  sdp_printer_t *printer = NULL;
  sdp_session_t *sdp_new;
  char *sdp_str_new;
  char *sdp_str0_new;

  void *tbf1, *tbf2, *tbf3, *tbf4;

  /* Store description in three forms: unparsed, parsed and reprinted */

  sdp_new = sdp_session_dup(ss->ss_home, sdp);
  printer = sdp_print(ss->ss_home, sdp, NULL, 0, 0);
  sdp_str_new = (char *)sdp_message(printer);
  if (sdp_str)
    sdp_str0_new = su_strndup(ss->ss_home, sdp_str, str_len);
  else
    sdp_str0_new = sdp_str_new;
  
  if (sdp_new && printer && sdp_str_new && sdp_str0_new) {
    tbf1 = ssd->ssd_sdp, tbf2 = ssd->ssd_printer;
    tbf3 = (void *)ssd->ssd_str, tbf4 = (void *)ssd->ssd_unparsed;

    ssd->ssd_sdp = sdp_new;
    ssd->ssd_printer = printer;
    ssd->ssd_str = sdp_str_new;
    ssd->ssd_unparsed = sdp_str0_new;      

    retval = 1;
  }
  else {
    tbf1 = sdp_new, tbf2 = printer, tbf3 = sdp_str_new, tbf4 = sdp_str0_new;
  }
  
  su_free(ss->ss_home, tbf1);
  sdp_printer_free(tbf2);
  if (tbf3 != tbf4)
    su_free(ss->ss_home, tbf4);

  return retval;
}


/** Duplicate a session descriptions. */
int soa_description_dup(su_home_t *home, 
			struct soa_description *ssd,
			struct soa_description const *ssd0)
{
  if (ssd0->ssd_sdp) {
    int len = ssd0->ssd_str ? strlen(ssd0->ssd_str) + 1 : 0;

    ssd->ssd_sdp = sdp_session_dup(home, ssd0->ssd_sdp);
    ssd->ssd_printer = sdp_print(home, ssd->ssd_sdp, NULL, len, 0);
    ssd->ssd_str = (char *)sdp_message(ssd->ssd_printer);
    if (ssd0->ssd_str != ssd0->ssd_unparsed)
      ssd->ssd_unparsed = su_strdup(home, ssd0->ssd_unparsed);
    else
      ssd->ssd_unparsed = ssd->ssd_str;
  }

  return 0;
}

/** Free session descriptions. */
void soa_description_free(soa_session_t *ss, 
			  struct soa_description *ssd)
{
  void *tbf1, *tbf2, *tbf3, *tbf4;

  tbf1 = ssd->ssd_sdp, tbf2 = ssd->ssd_printer;
  tbf3 = (void *)ssd->ssd_str, tbf4 = (void *)ssd->ssd_unparsed;

  memset(ssd, 0, sizeof *ssd);

  su_free(ss->ss_home, tbf1);
  sdp_printer_free(tbf2);
  if (tbf3 != tbf4)
    su_free(ss->ss_home, tbf4);
}


/** Initialize SDP o= line */
int
soa_init_sdp_origin(soa_session_t *ss, sdp_origin_t *o, char buffer[64])
{
  sdp_connection_t *c;

  if (ss == NULL || o == NULL)
    return (errno = EFAULT), -1;

  assert(o->o_address);

  if (!o->o_username)
    o->o_username = "-";

  if (o->o_id == 0)
    su_randmem(&o->o_id, sizeof o->o_id);
  o->o_id &= 0x7fffffffffffffffULL;

  if (o->o_version == 0)
    su_randmem(&o->o_version, sizeof o->o_version);
  o->o_version &= 0x7fffffffffffffffULL;

  c = o->o_address;

  if (!c->c_nettype ||
      !c->c_address ||
      strcmp(c->c_address, "") == 0 ||
      strcasecmp(c->c_address, "localhost") == 0 ||
      strcasecmp(c->c_address, "localhost.localdomain") == 0 ||
      strcmp(c->c_address, "0.0.0.0") == 0 ||
      strcmp(c->c_address, "127.0.0.1") == 0 ||
      strcmp(c->c_address, "::") == 0 ||
      strcmp(c->c_address, "::1") == 0) {
    return soa_init_sdp_connection(ss, c, buffer);
  }

  return 0;
}

/** Search for an local address item from string provided by user */
static
su_localinfo_t *li_in_list(su_localinfo_t *li0, char const **llist)
{
  char const *list = *llist;
  int n;

  if (!list)
    return NULL;

  while ((n = strcspn(list, ", "))) {
    su_localinfo_t *li;

    for (li = li0; li; li = li->li_next) {
      if (strncasecmp(li->li_canonname, list, n) == 0 &&
	  li->li_canonname[n] == '\0')
	break;
    }

    list += n; while (list[0] == ' ' || list[0] == ',') list++;
    *llist = list;

    if (li)
      return li;
  }

  return NULL;
}


/** Obtain a local address for SDP connection structure */
int
soa_init_sdp_connection(soa_session_t *ss,
			sdp_connection_t *c,
			char buffer[64])
{
  su_localinfo_t *res, hints[1] = {{ LI_CANONNAME | LI_NUMERIC }};
  su_localinfo_t *li, *li4, *li6;
  char const *address;
  int ip4, ip6, error;

  if (ss == NULL || c == NULL)
    return (errno = EFAULT), -1;

  /* XXX - using LI_SCOPE_LINK requires some tweaking */
  hints->li_scope = LI_SCOPE_GLOBAL | LI_SCOPE_SITE /* | LI_SCOPE_LINK */;

  switch (ss->ss_af) {
  case SOA_AF_IP4_ONLY:
    hints->li_family = AF_INET, ip4 = 1, ip6 = 0;
    break;
  case SOA_AF_IP6_ONLY:
    hints->li_family = AF_INET6, ip6 = 1, ip4 = 0;
    break;
  case SOA_AF_IP4_IP6:
    ip4 = 2, ip6 = 1;
    break;
  case SOA_AF_IP6_IP4:
    ip4 = 1, ip6 = 2;
    break;
  default:
    ip4 = ip6 = 1;
  }

  for (res = NULL; res == NULL;) {
    if ((error = su_getlocalinfo(hints, &res)) < 0 
	&& error != ELI_NOADDRESS) {
      SU_DEBUG_1(("%s: su_localinfo: %s\n", __func__,
		  su_gli_strerror(error)));
      return -1;
    }
    if (hints->li_scope & LI_SCOPE_HOST)
      break;
    hints->li_scope |= LI_SCOPE_HOST;
  }

  if (!(ip4 & ip6 && c->c_nettype == sdp_net_in))
    /* Use ss_af preference */;
  else if (c->c_addrtype == sdp_addr_ip4)
    ip4 = 2, ip6 = 1;
  else if (c->c_addrtype == sdp_addr_ip6)
    ip6 = 2, ip4 = 1;

  address = ss->ss_address;

  if (address)
    SU_DEBUG_3(("%s: searching for %s from list \"%s\"\n",
		__func__, ip6 && !ip4 ? "IP6 " : !ip6 && ip4 ? "IP4 " : "",
		address));

  li = res, li4 = NULL, li6 = NULL;

  for (;;) {
    if (address)
      li = li_in_list(li, &address);

    if (!li)
      break;
    else if (li->li_family == AF_INET6) {
      if (ip6 >= ip4)
	break;
      else if (!li6)
	li6 = li;		/* Best IP6 address */
    }
    else if (li->li_family == AF_INET) {
      if (ip4 > ip6)
	break;
      else if (!li4)
	li4 = li;		/* Best IP4 address */
    }

    if (!address)
      li = li->li_next;
  }

  if (li == NULL)
    li = li4;
  if (li == NULL)
    li = li6;

  if (li == NULL)
    ;
  else if (li->li_family == AF_INET)
    c->c_nettype = sdp_net_in,  c->c_addrtype = sdp_addr_ip4;
  else if (li->li_family == AF_INET6)
    c->c_nettype = sdp_net_in,  c->c_addrtype = sdp_addr_ip6;

  if (li) {
    assert(strlen(li->li_canonname) < 64);
    c->c_address = strcpy(buffer, li->li_canonname);
  }

  su_freelocalinfo(res);

  if (!li)
    return -1;
  else
    return 0;
}
