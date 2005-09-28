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

#ifndef SOA_SESSION_H
#define SOA_SESSION_H "$Id: soa_session.h,v 1.4 2005/09/22 19:38:05 kaiv Exp $"
/**@file soa_session.h  Internal API for SDP Offer/Answer Interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Mon Aug 1 15:43:53 EEST 2005 ppessi
 * $Date: 2005/09/22 19:38:05 $
 */

#ifndef SOA_H
#include "soa.h"
#endif
#ifndef SDP_H
#include <sdp.h>
#endif
#ifndef SU_STRLST_H
#include <su_strlst.h>
#endif

struct soa_session_actions
{
  int sizeof_soa_session_actions;
  int sizeof_soa_session;
  int (*soa_init)(char const *name, soa_session_t *ss, soa_session_t *parent);
  void (*soa_deinit)(soa_session_t *ss);
  int (*soa_set_params)(soa_session_t *ss, tagi_t const *tags);
  int (*soa_get_params)(soa_session_t const *ss, tagi_t *tags);
  tagi_t *(*soa_get_paramlist)(soa_session_t const *ss);
  char **(*soa_media_features)(soa_session_t *, int live, su_home_t *);
  char const * const *(*soa_sip_required)(soa_session_t const *ss);
  char const * const *(*soa_sip_support)(soa_session_t const *ss);
  int (*soa_remote_sip_features)(soa_session_t *ss,
				 char const * const * support,
				 char const * const * required);
  int (*soa_set_capability_sdp)(soa_session_t *, sdp_session_t *,
				char const *, int);
  int (*soa_set_remote_sdp)(soa_session_t *, int new_version,
			    sdp_session_t *, char const *, int);
  int (*soa_set_local_sdp)(soa_session_t *, sdp_session_t *,
			   char const *, int);
  int (*soa_generate_offer)(soa_session_t *ss, soa_callback_f *completed);
  int (*soa_generate_answer)(soa_session_t *ss, soa_callback_f *completed);
  int (*soa_process_answer)(soa_session_t *ss, 
				   soa_callback_f *completed);
  int (*soa_activate_session)(soa_session_t *ss, char const *option);
  int (*soa_deactivate_session)(soa_session_t *ss, char const *option);
  void (*soa_terminate_session)(soa_session_t *ss, char const *option);
};

soa_session_t *soa_session_ref(soa_session_t *ss);
void soa_session_unref(soa_session_t *ss);

int soa_base_init(char const *name, soa_session_t *, soa_session_t *parent);
void soa_base_deinit(soa_session_t *ss);
int soa_base_set_params(soa_session_t *ss, tagi_t const *tags);
int soa_base_get_params(soa_session_t const *ss, tagi_t *tags);
tagi_t *soa_base_get_paramlist(soa_session_t const *ss);
char **soa_base_media_features(soa_session_t *, int live, su_home_t *);
char const * const * soa_base_sip_required(soa_session_t const *ss);
char const * const * soa_base_sip_support(soa_session_t const *ss);
int soa_base_remote_sip_features(soa_session_t *ss,
				    char const * const * support,
				    char const * const * required);
int soa_base_set_capability_sdp(soa_session_t *ss, 
				sdp_session_t *sdp,
				char const *, int);
int soa_base_set_remote_sdp(soa_session_t *ss, 
			    int new_version,
			    sdp_session_t *sdp,
			    char const *, int);
int soa_base_set_local_sdp(soa_session_t *ss, 
			   sdp_session_t *sdp,
			   char const *, int);
int soa_base_generate_offer(soa_session_t *ss, soa_callback_f *completed);
int soa_base_generate_answer(soa_session_t *ss, soa_callback_f *completed);
int soa_base_process_answer(soa_session_t *ss, 
				   soa_callback_f *completed);
int soa_base_activate(soa_session_t *ss, char const *option);
int soa_base_deactivate(soa_session_t *ss, char const *option);
void soa_base_terminate(soa_session_t *ss, char const *option);

int soa_default_generate_offer(soa_session_t *ss,
			       soa_callback_f *completed);
int soa_default_generate_answer(soa_session_t *ss,
				soa_callback_f *completed);
int soa_default_process_answer(soa_session_t *ss, 
				      soa_callback_f *completed);

struct soa_description 
{
  int             ssd_version;  /**< Version incremented at each change */
  sdp_session_t  *ssd_sdp;	/**< Session description  */
  char const     *ssd_unparsed;	/**< Original session description as string */
  char const     *ssd_str;	/**< Session description as string */
  sdp_printer_t  *ssd_printer;	/**< SDP printer object */
};

struct soa_session
{
  su_home_t ss_home[1];

  struct soa_session_actions const *ss_actions;

  su_root_t *ss_root;
  soa_magic_t *ss_magic;	/**< Application data */

  soa_callback_f *ss_in_progress;/**< Operation in progress */

  /** Incremented once each time session is terminated */
  unsigned  ss_terminated;

  unsigned  ss_active:1;	/**< Session has been activated */

  /* Current Offer-Answer status */
  unsigned  ss_complete:1;	/**< Completed SDP offer-answer */

  unsigned  ss_unprocessed_remote:1; /**< We have received remote SDP */

  unsigned  ss_offer_sent:2;	/**< We have offered SDP */
  unsigned  ss_answer_recv:2;	/**< We have received SDP answer */

  unsigned  ss_offer_recv:2;	/**< We have received an offer */
  unsigned  ss_answer_sent:2;	/**< We have answered (reliably, if >1) */
  unsigned  :0;			/* Pad */

  unsigned  ss_oa_rounds;	/**< Number of O/A rounds completed */

  struct soa_media_activity
  {
    int ma_audio:3; /**< Audio activity (send/recv) */
    int ma_video:3; /**< Video activity (send/recv) */
    int ma_image:3; /**< Image activity (send/recv) for JPIP */
    int ma_chat:3;  /**< Chat activity (send/recv) */
  } ss_local_activity[1], ss_remote_activity[1];

  /** Capabilities as specified by application */
  struct soa_description ss_caps[1];
  /** Local session description */
  struct soa_description ss_local[1];
  /** Remote session description */
  struct soa_description ss_remote[1];
  /** Session description */
  struct soa_description ss_desc[1];

  sdp_session_t *ss_rsession;	/**< Processed remote SDP */

  /** SIP features required */
  char const * const *ss_local_required;
  /** SIP features supported */
  char const * const *ss_local_support;

  /** SIP features required by remote */
  char const **ss_remote_required;
  /** SIP features supported */
  char const **ss_remote_support;

  int             ss_status;	/**< Status from last media operation */
  char const     *ss_phrase;	/**< Phrase from last media operation */
  char const     *ss_warning;	/**< Warnings from last media operation */

  /* Media parameters */
  char const     *ss_address;
  enum soa_af     ss_af;
  char const     *ss_hold;	/**< Media on hold locally */

  char const     *ss_cname;

  unsigned ss_srtp_enable:1,
    ss_srtp_confidentiality:1,
    ss_srtp_integrity:1;
};

/* ====================================================================== */

int soa_has_received_sdp(soa_session_t const *ss);

int soa_set_status(soa_session_t *ss, int status, char const *phrase);

void soa_set_activity(soa_session_t *ss, sdp_media_t const *m, int remote);

int soa_set_capability_sdp_str(soa_session_t *ss, 
			       sdp_session_t const *sdp,
			       char const *str, int len);

int soa_set_remote_sdp_str(soa_session_t *ss, 
			   sdp_session_t const *sdp,
			   char const *str, int len);

int soa_set_local_sdp_str(soa_session_t *ss, 
			  sdp_session_t const *sdp,
			  char const *str, int len);

int soa_description_set(soa_session_t *ss, 
			struct soa_description *ssd,
			sdp_session_t *sdp,
			char const *sdp_str,
			int sdp_len);

void soa_description_free(soa_session_t *, struct soa_description *ssd);

int soa_description_dup(su_home_t *, 
			struct soa_description *ssd,
			struct soa_description const *ssd0);

int soa_init_sdp_origin(soa_session_t *ss, sdp_origin_t *o, char buf[64]);
int soa_init_sdp_connection(soa_session_t *, sdp_connection_t *, char buf[64]);

/* ====================================================================== */
/* Debug log settings */

#define SU_LOG   soa_log

#ifdef SU_DEBUG_H
#error <su_debug.h> included directly.
#endif
#include <su_debug.h>
extern su_log_t soa_log[];

#endif
