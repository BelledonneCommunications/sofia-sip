/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2006 Nokia Corporation.
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

/**@CFILE tport_connect.c Transport using HTTP CONNECT.
 *
 * See tport.docs for more detailed description of tport interface.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Martti Mela <Martti.Mela@nokia.com>
 *
 * @date Created: Fri Mar 24 08:45:49 EET 2006 ppessi
 */

#include "config.h"

#include "tport_internal.h"

#include <sofia-sip/string0.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

/**@var TPORT_LOG
 *
 * Environment variable determining if parsed message contents are logged.
 *
 * If the TPORT_LOG environment variable is set, the tport module logs the
 * contents of parsed messages. This eases debugging the signaling greatly.
 * 
 * @sa TPORT_DUMP, TPORT_DEBUG, tport_log
 */
extern char const TPORT_LOG[];	/* dummy declaration for Doxygen */

/**@var TPORT_DUMP
 *
 * Environment variable for transport data dump.
 *
 * The received and sent data is dumped to the file specified by TPORT_DUMP
 * environment variable. This can be used to save message traces and help
 * hairy debugging tasks.
 * 
 * @sa TPORT_LOG, TPORT_DEBUG, tport_log
 */
extern char const TPORT_DUMP[];	/* dummy declaration for Doxygen */

/**@var TPORT_DEBUG
 *
 * Environment variable determining the debug log level for @b tport module.
 *
 * The TPORT_DEBUG environment variable is used to determine the debug logging
 * level for @b tport module. The default level is 3.
 * 
 * @sa <su_debug.h>, tport_log, SOFIA_DEBUG
 */
extern char const TPORT_DEBUG[]; /* dummy declaration for Doxygen */

/**Debug log for @b tport module. 
 * 
 * The tport_log is the log object used by @b tport module. The level of
 * #tport_log is set using #TPORT_DEBUG environment variable.
 */
su_log_t tport_log[] = { 
  SU_LOG_INIT("tport", "TPORT_DEBUG", SU_DEBUG)
};


/** Initialize logging. */
void tport_open_log(tport_master_t *mr, tagi_t *tags)
{
  char const *log;
  
  mr->mr_log = 
    getenv("MSG_STREAM_LOG") != NULL ||
    getenv("TPORT_LOG") != NULL 
    ? MSG_DO_EXTRACT_COPY : 0;
    
  if ((log = getenv("TPORT_DUMP")) || (log = getenv("MSG_DUMP"))) {
    time_t now;

    if (strcmp(log, "-")) 
      mr->mr_dump_file = fopen(log, "ab"); /* XXX */
    else
      mr->mr_dump_file = stdout;

    if (mr->mr_dump_file) {
      time(&now);
      fprintf(mr->mr_dump_file, "dump started at %s\n\n", ctime(&now));
    }
  }
}

/** Create log stamp */
void tport_stamp(tport_t const *self, msg_t *msg, 
		 char stamp[128], char const *what, 
		 int n, char const *via,
		 su_time_t now)
{
  char label[24] = "";
  char *comp = "";
  char name[SU_ADDRSIZE] = "";
  su_sockaddr_t const *su = msg_addr(msg);
  unsigned short second, minute, hour;

  second = (unsigned short)(now.tv_sec % 60);
  minute = (unsigned short)((now.tv_sec / 60) % 60);
  hour = (unsigned short)((now.tv_sec / 3600) % 24);

#if SU_HAVE_IN6
  if (su->su_family == AF_INET6) {
    if (su->su_sin6.sin6_flowinfo)
      snprintf(label, sizeof(label), "/%u", ntohl(su->su_sin6.sin6_flowinfo));
  }
#endif

  if (msg_addrinfo(msg)->ai_flags & TP_AI_COMPRESSED)
    comp = ";comp=sigcomp";

  inet_ntop(su->su_family, SU_ADDR(su), name, sizeof(name));

  snprintf(stamp, 128,
	   "%s %d bytes %s %s/[%s]:%u%s%s at %02u:%02u:%02u.%06lu:\n",
	   what, n, via, self->tp_name->tpn_proto,
	   name, ntohs(su->su_port), label[0] ? label : "", comp,
	   hour, minute, second, now.tv_usec);

}

/** Dump the data from the iovec */
void tport_dump_iovec(tport_t const *self, msg_t *msg, 
		      int n, su_iovec_t const iov[], int iovused,
		      char const *what, char const *how)
{
  tport_master_t *mr = self->tp_master;
  char stamp[128];
  int i;

  if (!mr->mr_dump_file)
    return;

  tport_stamp(self, msg, stamp, what, n, how, su_now());
  fputs(stamp, mr->mr_dump_file);

  for (i = 0; i < iovused && n > 0; i++) {
    int len = iov[i].mv_len;
    if (len > n)
      len = n;
    fwrite(iov[i].mv_base, len, 1, mr->mr_dump_file);
    n -= len;
  }

  fputs("\v\n", mr->mr_dump_file);
  fflush(mr->mr_dump_file);
}

/** Log the message. */
void tport_log_msg(tport_t *self, msg_t *msg, 
		   char const *what, char const *via,
		   char const *first, su_time_t now)
{
  char stamp[128];
  msg_iovec_t iov[80];
  int i, n, iovlen = msg_iovec(msg, iov, 80);
  int skip_lf = 0, linelen = 0;
  char const *prefix = first;

  if (iovlen < 0) return;

  for (i = n = 0; i < iovlen && i < 80; i++)
    n += iov[i].mv_len;

  tport_stamp(self, msg, stamp, what, n, via, now);
  su_log(stamp);

  for (i = 0; i < iovlen && i < 80; i++) {
    char *s = iov[i].mv_base, *end = s + iov[i].mv_len;
    int n;

    if (skip_lf && s < end && s[0] == '\n') { s++; skip_lf = 0; }

    while (s < end) {
      if (s[0] == '\0') {
	int j, len = s - (char *)iov[i].mv_base;
	for (j = 0; j < i; j++)
	  len += iov[j].mv_len;
	su_log("\n%s*** message truncated at %d\n", prefix, len);
	return;
      }

      n = strncspn(s, end - s, "\r\n");
      if (prefix) {
	su_log("%s", prefix); linelen = n;
      } else {
	linelen += n;
      }
      su_log("%.*s", n, s);
      if (s + n < end) {
	su_log("\n");
	prefix = first;
      }
      else {
	prefix = "";
      }
      s += n;
      /* Skip a eol */
      if (s < end) {
	if (s + 1 < end && s[0] == '\r' && s[1] == '\n')
	  s += 2;
	else if (s[0] == '\r')
	  s++, (skip_lf = s + 1 == end);
	else if (s[0] == '\n')
	  s++;
      }
    }
  }

  if (linelen) su_log("\n");

  if (i == 80) {
    int j, len = 0;
    for (j = 0; j < i; j++)
      len += iov[j].mv_len;
    su_log("\n%s*** message truncated at %d\n", prefix, len);
    return;
  }
}
