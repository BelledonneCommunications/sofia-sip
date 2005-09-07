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
 * $Date: 2005/08/17 14:51:22 $
 */

#include "config.h"

const char soa_c_id[] =
"$Id: soa.c,v 1.2 2005/08/17 14:51:22 ppessi Exp $";

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <su_tag_class.h>

#include "soa.h"
const char soa_h_id[] = SOA_H;
#include "sdp.h"
#include "soa_session.h"
const char soa_session_h_id[] = SOA_SESSION_H;
#include "soa_add.h"
const char soa_add_h_id[] = SOA_ADD_H;

#include <su_tagarg.h>

#define NONE ((void *)-1)
#define XXX assert(!"implemented")
typedef long long unsigned llu;

/* ======================================================================== */

/* Internal prototypes */
static inline 
int soa_set_status(soa_session_t *ss, int status, char const *phrase);

static void soa_set_activity(soa_session_t *ss,
			     sdp_media_t const *, 
			     int remote);

static inline int soa_media_is_ready(soa_session_t const *ss);

static
char const *soa_recv_offer_answer(soa_session_t *ss,
				  sdp_session_t const *sdp,
				  int *return_new_version);
static
char const *soa_sent_offer_answer(soa_session_t *soa,
				  sdp_session_t const *sdp,
				  int reliable);

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

struct soa_session_actions const soa_default_actions = 
  {
    (sizeof soa_default_actions),
    sizeof (struct soa_session),
    soa_default_init,
    soa_default_deinit,
    soa_default_set_params,
    soa_default_get_params,
    soa_default_get_paramlist,
    soa_default_media_features,
    soa_default_sip_required,
    soa_default_sip_support,
    soa_default_remote_sip_features,
    soa_default_generate_offer,
    soa_default_generate_answer,
    soa_default_activate_session,
    soa_default_terminate_session
  };

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
int soa_add_backend(char const *name, 
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

/* ======================================================================== */

soa_session_t *soa_create(su_root_t *root, char const *name)
{
  struct soa_session_actions const *actions = &soa_default_actions;

  soa_session_t *ss;
  
  if (name) {
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

  assert(SOA_VALID_ACTIONS(actions));

  if (root == NULL)
    return (void)(errno = EFAULT), NULL;

  ss = su_home_clone(NULL, actions->sizeof_soa_session);
  if (ss) {
    ss->ss_root = root;
    ss->ss_actions = actions;
    ss->ss_actions->soa_init(name, ss, NULL);
  }

  return ss;
}

soa_session_t *soa_clone(soa_session_t *ss, su_root_t *root)
{
  soa_session_t *new_ss;
  
  if (ss == NULL || root == NULL);
    return (void)(errno = EFAULT), NULL;

  new_ss = su_home_clone(NULL, ss->ss_actions->sizeof_soa_session);
  if (new_ss) {
    new_ss->ss_root = root;
    new_ss->ss_actions = ss->ss_actions;
    new_ss->ss_actions->soa_init(NULL, new_ss, ss);
  }
  
  return new_ss;
}

/* Initialize session */
int soa_default_init(char const *name, 
		     soa_session_t *ss, 
		     soa_session_t *parent)
{
  if (parent) {
#define DUP(d, dup, s) if ((s) && !((d) = dup(ss->ss_home, (s)))) return -1
    static char const *null = NULL;

    DUP(ss->ss_caps, sdp_session_dup, parent->ss_caps);
    DUP(ss->ss_path, su_strdup, parent->ss_path);

    DUP(ss->ss_address, su_strdup, parent->ss_address);
    ss->ss_af = parent->ss_af;

    DUP(ss->ss_cname, su_strdup, parent->ss_cname);
    DUP(ss->ss_mss_sdp, su_strdup, parent->ss_mss_sdp);
    DUP(ss->ss_mss_cfg, su_strdup, parent->ss_mss_cfg);

    DUP(ss->ss_video_local, su_strdup, parent->ss_video_local);
    DUP(ss->ss_video_remote, su_strdup, parent->ss_video_remote);

    DUP(ss->ss_image_local, su_strdup, parent->ss_image_local);
    DUP(ss->ss_image_remote, su_strdup, parent->ss_image_remote);
    DUP(ss->ss_image_name, su_strdup, parent->ss_image_name);
    
    DUP(ss->ss_events, su_strlst_dup, parent->ss_events);

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
    ss->ss_actions->soa_deinit(ss);
    su_home_zap(ss->ss_home);
  }
}

void soa_default_deinit(soa_session_t *ss)
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

int soa_default_set_params(soa_session_t *ss, tagi_t const *tags)
{
  int n;

  int af;

  char const *media_address, *media_profile, *mss_sdp, *mss_cfg;
  char const *media_event_path;
  char const *image_local, *image_remote, *image_name;
  char const *video_local, *video_remote;

  int srtp_enable, srtp_confidentiality, srtp_integrity;

  af = ss->ss_af;

  media_address = ss->ss_address;
  mss_sdp = ss->ss_mss_sdp;
  mss_cfg = ss->ss_mss_cfg;
  media_event_path = NONE;

  image_local = ss->ss_image_local;
  image_remote = ss->ss_image_remote;
  image_name = ss->ss_image_name;

  video_local = ss->ss_video_local;
  video_remote = ss->ss_video_remote;

  srtp_enable = ss->ss_srtp_enable;
  srtp_confidentiality = ss->ss_srtp_confidentiality;
  srtp_integrity = ss->ss_srtp_integrity;

  n = tl_gets(tags,
	      SOATAG_AF_REF(af),
	      SOATAG_ADDRESS_REF(media_address),
	      SOATAG_MEDIA_PROFILE_REF(media_profile),
	      SOATAG_MSS_SDP_REF(mss_sdp),
	      SOATAG_MSS_CFG_REF(mss_cfg),
	      SOATAG_MEDIA_EVENT_PATH_REF(media_event_path),

	      SOATAG_IMAGE_LOCAL_REF(image_local),
	      SOATAG_IMAGE_REMOTE_REF(image_remote),
	      SOATAG_TARGET_IMAGE_NAME_REF(image_name),

	      SOATAG_VIDEO_LOCAL_REF(video_local),
	      SOATAG_VIDEO_REMOTE_REF(video_remote),

	      SOATAG_SRTP_ENABLE_REF(srtp_enable),
	      SOATAG_SRTP_CONFIDENTIALITY_REF(srtp_confidentiality),
	      SOATAG_SRTP_INTEGRITY_REF(srtp_integrity),
	      
	      TAG_END());

  if (n <= 0)
    return n;

  if (af != ss->ss_af &&
      af >= SOA_AF_ANY && af <= SOA_AF_IP6_IP4)
    ss->ss_af = af;

  if (str0casecmp(media_address, ss->ss_address)) {
    su_free(ss->ss_home, (void *)ss->ss_address);
    ss->ss_address = su_strdup(ss->ss_home, media_address);
  }

  if (str0casecmp(mss_sdp, ss->ss_mss_sdp)) {
    su_free(ss->ss_home, (void *)ss->ss_mss_sdp);
    ss->ss_mss_sdp = su_strdup(ss->ss_home, mss_sdp);
  }

  if (str0casecmp(mss_cfg, ss->ss_mss_cfg)) {
    su_free(ss->ss_home, (void *)ss->ss_mss_cfg);
    ss->ss_mss_cfg = su_strdup(ss->ss_home, mss_cfg);
  }

  if (media_profile == NULL) media_profile = "/";
  if (str0casecmp(mss_sdp, ss->ss_path)) {
    su_free(ss->ss_home, (void *)ss->ss_path);
    ss->ss_path = su_strdup(ss->ss_home, media_profile);
  }

  if (media_event_path != NONE) {
    su_strlst_t *events = ss->ss_events;
    tagi_t const *tl;
    
    for (tl = tags; tl; tl = tl_next(tl)) {
      if ((tl = tl_find(tl, soatag_media_event_path))) {
	char const *path = (char const *)tl->t_value;
	size_t i, len = su_strlst_len(events);

	for (i = 0; i < len; i++) 
	  if (str0cmp(path, su_strlst_item(events, i)) == 0)
	    break;

	if (i == len)
	  su_strlst_dup_append(events, path);
      }
    }
  }

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

int soa_default_get_params(soa_session_t const *ss, tagi_t *tags)
{
  int n;

  char const *media_event_path = NULL;

  if (ss->ss_events)
    media_event_path = su_strlst_item(ss->ss_events, 0);

  n = tl_tgets(tags,
	       SOATAG_AF(ss->ss_af),
	       SOATAG_ADDRESS(ss->ss_address),
	       SOATAG_MEDIA_PROFILE(ss->ss_path),
	       SOATAG_MSS_SDP(ss->ss_mss_sdp),
	       SOATAG_MSS_CFG(ss->ss_mss_cfg),
	       SOATAG_MEDIA_EVENT_PATH(media_event_path),
	       
	       SOATAG_IMAGE_LOCAL(ss->ss_image_local),
	       SOATAG_IMAGE_REMOTE(ss->ss_image_remote),
	       SOATAG_TARGET_IMAGE_NAME(ss->ss_image_name),
	       
	       SOATAG_VIDEO_LOCAL(ss->ss_video_local),
	       SOATAG_VIDEO_REMOTE(ss->ss_video_remote),
	       
	       SOATAG_SRTP_ENABLE(ss->ss_srtp_enable),
	       SOATAG_SRTP_CONFIDENTIALITY(ss->ss_srtp_confidentiality),
	       SOATAG_SRTP_INTEGRITY(ss->ss_srtp_integrity),

	       TAG_END());

  return n;
}

/** Return a list of parameters */
tagi_t *soa_get_paramlist(soa_session_t const *ss)
{
  if (ss)
    return ss->ss_actions->soa_get_paramlist(ss);
  else
    return (void)(errno = EFAULT), NULL;
}


tagi_t *soa_default_get_paramlist(soa_session_t const *ss)
{
  tagi_t *params, *media_events = NULL;

  if (ss == NULL)
    return NULL;

  if (ss->ss_events) {
    su_strlst_t *events = ss->ss_events;
    size_t i, len = su_strlst_len(events);

    media_events = malloc((len + 1) * sizeof *media_events);

    if (media_events) {
      for (i = 0; i < len; i++) {
	media_events[i].t_tag = soatag_media_event_path;
	media_events[i].t_value = (tag_value_t)su_strlst_item(events, i);
      }
      media_events[len].t_tag = NULL;
      media_events[len].t_value = 0;
    }
  }
  
  params = tl_list(SOATAG_AF(ss->ss_af),
		   SOATAG_ADDRESS(ss->ss_address),
		   SOATAG_MEDIA_PROFILE(ss->ss_path),
		   SOATAG_MSS_SDP(ss->ss_mss_sdp),
		   SOATAG_MSS_CFG(ss->ss_mss_cfg),
	       
		   SOATAG_IMAGE_LOCAL(ss->ss_image_local),
		   SOATAG_IMAGE_REMOTE(ss->ss_image_remote),
		   SOATAG_TARGET_IMAGE_NAME(ss->ss_image_name),
		   
		   SOATAG_VIDEO_LOCAL(ss->ss_video_local),
		   SOATAG_VIDEO_REMOTE(ss->ss_video_remote),
		   
		   SOATAG_SRTP_ENABLE(ss->ss_srtp_enable),
		   SOATAG_SRTP_CONFIDENTIALITY(ss->ss_srtp_confidentiality),
		   SOATAG_SRTP_INTEGRITY(ss->ss_srtp_integrity),
		   
		   TAG_NEXT(media_events));

  free(media_events);

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

/**Parse and store session description received from remote end.
 *
 * @param ss session handle
 * @param sdp pointer to session description
 * @param len length of session description
 * 
 * @retval 1 when description is new
 * @retval 0 when description is old
 * @retval -1 upon an error
 */
int soa_parse_sdp(soa_session_t *ss, 
		  char const *sdp,
		  int len)
{
  sdp_parser_t *parser;
  sdp_session_t *parsed;
  sdp_origin_t const *o;
  char const *verdict;
  int new_version = 0;

  if (ss == NULL || sdp == NULL || len == 0)
    return -1;

  parser = sdp_parse(ss->ss_home, sdp, len, sdp_f_mode_0000);

  if (sdp_parsing_error(parser)) {
    sdp_parser_free(parser);
    return soa_set_status(ss, 400, "Bad Session Description");
  }
   
  soa_clear_sdp(ss);

  parsed = sdp_session(parser); assert(parsed);

  soa_set_activity(ss, parsed->sdp_media, 1);

  o = parsed->sdp_origin; 

  if (sdp_origin_cmp(o, ss->ss_o_remote)) {
    new_version = 1;
    if (ss->ss_o_remote)
      su_free(ss->ss_home, ss->ss_o_remote);
    ss->ss_o_remote = sdp_origin_dup(ss->ss_home, o);
  } 

  if (ss->ss_offer_sent && !ss->ss_answer_recv) {
    verdict = "answer";
    ss->ss_answer_recv = 1 + new_version;
  }
  else {
    verdict = "offer";
    ss->ss_complete = 0;
    ss->ss_offer_recv = 1 + new_version; 
    ss->ss_answer_sent = 0;
  }

  SU_DEBUG_5(("%s(%p): %s%s (o=%s %llu %llu)\n",
	      "soa_parse_sdp", ss, new_version ? "new " : "", verdict,
	      o->o_username, (llu)o->o_id, (llu)o->o_version));
  
  return 0;
}

void 
soa_clear_sdp(soa_session_t *ss)
{
  if (ss && ss->ss_parser)
    sdp_parser_free(ss->ss_parser), ss->ss_parser = NULL;
}

/** Return SDP description of the session.
 *
 * If @a live is 0, return media capabilities (as per RFC 3264 section 9). 
 *
 */
int soa_print_sdp(soa_session_t *ss, 
		  int live,
		  su_home_t *home,
		  char **return_sdp,
		  int *return_len)
{
  if (ss == NULL || return_sdp == NULL || return_len == NULL)
    return (errno = EFAULT), -1;

  XXX;

  if (live) {
    return -1;
  }
  else {
    return -1;
  }
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

  return complete;
}

char **soa_media_features(soa_session_t *ss, int live, su_home_t *home)
{
  if (ss) 
    return ss->ss_actions->soa_media_features(ss, live, home);
  else
    return (void)(errno = EFAULT), NULL;
}

char **soa_default_media_features(soa_session_t *ss, int live, su_home_t *home)
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

char const * const * soa_default_sip_required(soa_session_t const *ss)
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

char const * const * soa_default_sip_support(soa_session_t const *ss)
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

int soa_default_remote_sip_features(soa_session_t *ss, 
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
int soa_offer(soa_session_t *ss, 
	      int always,
	      soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address as @a ss or @s completed. */
  if (ss == NULL || completed == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have received offer, now we should send answer */
  if (ss->ss_offer_recv && !ss->ss_answer_sent)
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have received SDP, but it has not been processed */
  if (soa_has_received_sdp(ss->ss_parser))
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have sent an offer, but have received no answer */
  if (ss->ss_offer_sent && !ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  if (ss->ss_offer_sent && !always)
    return 0;

  return ss->ss_actions->soa_generate_offer(ss, completed);
}

/* Run answer step */
int soa_answer(soa_session_t *ss, 
	       int always,
	       soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address as @a ss or @s completed. */
  if (ss == NULL || completed == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress. */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have sent an offer, but have received no answer. */
  if (ss->ss_offer_sent && !ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  /** @ERROR EPROTO We have not received offer. */
  if (!ss->ss_offer_recv)
    return (errno = EPROTO), -1;

  /* We should avoid actual operation unless always is given */
  (void)always;  /* We always regenerate answer */

  return ss->ss_actions->soa_generate_answer(ss, completed);
}

int soa_default_generate_offer(soa_session_t *ss,
				  soa_callback_f *completed)
{
  (void)completed;
  soa_set_status(ss, 501, "Not Implemented");
  return -1;
}


/* Run Offer or Answer step */
int soa_offer_answer(soa_session_t *ss, 
		     int always,
		     soa_callback_f *completed)
{
  /** @ERROR EFAULT Bad address as @a ss or @s completed. */
  if (ss == NULL || completed == NULL)
    return (errno = EFAULT), -1;

  /** @ERROR An operation is already in progress. */
  if (ss->ss_in_progress)
    return (errno = EALREADY), -1;

  /** @ERROR EPROTO We have sent an offer, but have received no answer. */
  if (ss->ss_offer_sent && !ss->ss_answer_recv)
    return (errno = EPROTO), -1;

  if (ss->ss_offer_recv && !ss->ss_answer_sent) {
    return ss->ss_actions->soa_generate_answer(ss, completed);
  }
  else if (always || !ss->ss_offer_sent) {
    return ss->ss_actions->soa_generate_offer(ss, completed);
  }
  return 0;
}

int soa_default_generate_answer(soa_session_t *ss, 
				     soa_callback_f *completed)
{
  (void)completed;
  soa_set_status(ss, 501, "Not Implemented");
  return -1;
}

/** Activate session */
void soa_activate(soa_session_t *ss, char const *option)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return;

  ss->ss_active = 1;

  ss->ss_actions->soa_activate_session(ss, option);
}

void soa_default_activate_session(soa_session_t *ss, 
					 char const *option)
{
  (void)ss;
  (void)option;
}

/** Terminate session */
void soa_terminate(soa_session_t *ss, char const *option)
{
  /** @ERROR EFAULT Bad address as @a ss. */
  if (ss == NULL)
    return;

  ss->ss_active = 0;

  ss->ss_actions->soa_terminate_session(ss, option);
}

void soa_default_terminate_session(soa_session_t *ss, char const *option)
{
  (void)ss;
  (void)option;
}

int soa_has_received_sdp(soa_session_t const *ss)
{
  return ss && ss->ss_parser;
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
  return ss ? ss->ss_local_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_image_active(soa_session_t const *ss)
{
  return ss ? ss->ss_local_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_chat_active(soa_session_t const *ss)
{
  return ss ? ss->ss_local_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_audio_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_video_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_image_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

int soa_is_remote_chat_active(soa_session_t const *ss)
{
  return ss ? ss->ss_remote_activity->ma_audio : SOA_ACTIVE_DISABLED;
}

/* ======================================================================== */

static inline 
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

static void soa_set_activity(soa_session_t *ss,
			     sdp_media_t const *m,
			     int remote)
{
  struct soa_media_activity *ma;
  sdp_connection_t const *c;
  int mode;

  remote = !!remote;

  ma = remote ? ss->ss_remote_activity : ss->ss_local_activity;

  ma->ma_audio = ma->ma_video = ma->ma_chat = ma->ma_image = 
    SOA_ACTIVE_DISABLED;
      
  for (; m; m = m->m_next) {
    if (m->m_rejected)
      continue;

    mode = m->m_mode;

    c = sdp_media_connections((sdp_media_t *)m);

    if (remote != (c && c->c_mcast))
      mode = ((mode << 1) & 2) | ((mode >> 1) & 1);

    if (m->m_type == sdp_media_audio)
      ma->ma_audio |= mode;
    else if (m->m_type == sdp_media_video)
      ma->ma_video |= mode;
    else if (m->m_type == sdp_media_image)
      ma->ma_image |= mode;
    else if (strcasecmp(m->m_type_name, "message") == 0)
      ma->ma_chat |= mode;
  }
  
  if (ma->ma_audio != SOA_ACTIVE_DISABLED)
    ma->ma_audio &= ~SOA_ACTIVE_DISABLED;
  if (ma->ma_video != SOA_ACTIVE_DISABLED)
    ma->ma_video &= ~SOA_ACTIVE_DISABLED;
  if (ma->ma_image != SOA_ACTIVE_DISABLED)
    ma->ma_image &= ~SOA_ACTIVE_DISABLED;
  if (ma->ma_chat != SOA_ACTIVE_DISABLED)
    ma->ma_chat &= ~SOA_ACTIVE_DISABLED;
}
