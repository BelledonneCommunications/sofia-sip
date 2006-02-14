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

/**@ingroup sl_utils
 *
 * @CFILE sl_utils_print.c  
 * @brief Implementation of SIP library utility print functions.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created:  Thu Oct  5 15:38:39 2000 ppessi
 */

#include "config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sofia-sip/sip_header.h>
#include "sofia-sip/sl_utils.h"

/**Print a SIP message. 
 *
 * The function sl_message_log() prints shorthand information identifying
 * the SIP message to the given output @a stream.  The shorthand information
 * include the method and URL by default.  If @a details is nonzero, topmost
 * @b Via, @b CSeq, @b To @b and @From is included, too.
 *
 * @param stream   output stream (if @c NULL, @c stdout is used).
 * @param prefix   string printed before the first line.
 * @param sip      message to be logged.
 * @param details  flag specifying if detailed output is desired.
 */
void sl_message_log(FILE *stream, 
		    char const *prefix, sip_t const *sip, int details)
{
  sip_cseq_t const *cs = sip->sip_cseq;

  if (stream == NULL)
    stream = stdout;

  assert(cs);
  
  if (sip->sip_request) {
    fprintf(stream,
	    "%s%s "URL_FORMAT_STRING" (CSeq %d %s)\n",
	    prefix,
	    sip->sip_request->rq_method_name,
	    URL_PRINT_ARGS(sip->sip_request->rq_url),
	    cs->cs_seq,
	    cs->cs_method_name);

    if (!details)
      return;

    if (sip->sip_via) {
      fputs(prefix, stream);
      sl_via_print(stream, "Via: %s\n", sip->sip_via);
    }
  }
  else {
    fprintf(stream,
	    "%s%03u %s (CSeq %d %s)\n",
	    prefix,
	    sip->sip_status->st_status,
	    sip->sip_status->st_phrase,
	    cs->cs_seq,
	    cs->cs_method_name);
    if (!details)
      return;
  }

  if (sip->sip_from)
    sl_from_print(stream, "\tFrom: %s\n", sip->sip_from);

  if (sip->sip_to)
    sl_to_print(stream, "\tTo: %s\n", sip->sip_to);
}

/** Print @b From header. 
 *
 * The function sl_from_print() prints the contents of @a from header to
 * the output @a stream.  The @a fmt specifies the output format, where %s
 * is replaced with header contents. If @a fmt is @c NULL, only the header
 * contents are printed.
 * 
 * @param stream   output stream
 * @param fmt      output format 
 * @param from     header object
 * 
 * @return 
 * The function sl_from_print() returns number of bytes printed,
 * or -1 upon an error.
 */
int sl_from_print(FILE *stream, char const *fmt, sip_from_t const *from)
{
  char s[1024];

  char const *d = from->a_display;

  snprintf(s, sizeof(s), "%s%s<" URL_FORMAT_STRING ">",
	   d ? d : "", d ? " " : "",
	   URL_PRINT_ARGS(from->a_url));

  if (fmt && strcmp(fmt, "%s"))
    return fprintf(stream, fmt, s);
  if (fputs(s, stream) >= 0)
    return strlen(s);
  return -1;
}

/** Print @b To header.
 *
 * The function sl_to_print() prints the contents of @a to header to
 * the output @a stream.  The @a fmt specifies the output format, where %s
 * is replaced with header contents. If @a fmt is @c NULL, only the header
 * contents are printed.
 * 
 * @param stream   output stream
 * @param fmt      output format 
 * @param to       header object
 * 
 * @return 
 * The function sl_to_print() returns number of bytes printed,
 * or -1 upon an error.
 */
int sl_to_print(FILE *stream, char const *fmt, sip_to_t const *to)
{
  return sl_from_print(stream, fmt, (sip_from_t const *)to);
}

/** Print @b Contact header. 
 *
 * The function sl_contact_print() prints the contents of @a contact
 * header to the output @a stream.  The @a fmt specifies the output format,
 * where %s is replaced with header contents. If @a fmt is @c NULL, only the
 * header contents are printed.
 * 
 * @param stream   output stream
 * @param fmt      output format 
 * @param contact  header object
 * 
 * @return 
 * The function sl_contact_print() returns number of bytes printed,
 * or -1 upon an error.
*/
int sl_contact_print(FILE *stream, char const *fmt, sip_contact_t const *m)
{
  return sl_from_print(stream, fmt, (sip_from_t const *)m);
}

/** Print @b Allow header(s). 
 *
 * The function sl_allow_print() prints the contents of @a allow header to
 * the output @a stream.  The @a fmt specifies the output format, where %s
 * is replaced with header contents. If @a fmt is @c NULL, only the header
 * contents are printed.
 * 
 * @param stream   output stream
 * @param fmt      output format 
 * @param allow    header object
 * 
 * @return 
 * The function sl_allow_print() returns number of bytes printed,
 * or -1 upon an error.
*/
int sl_allow_print(FILE *stream, char const *fmt, sip_allow_t const *allow)
{
  char *s, b[1024], *end = b + sizeof(b) - 1;
  msg_param_t const *p;
  sip_allow_t const *k = allow;

  s = b; *end = '\0';

  for (; k; k = k->k_next) {
    for (p = k->k_items; p && *p; p++) {
      strncpy(s, s == b ? "" : ",", end - s);
      strncat(s, *p, end - s);
      s += strlen(s);
    }
  }

  if (fmt && strcmp(fmt, "%s"))
    return fprintf(stream, fmt, b);
  if (fputs(b, stream) >= 0)
    return strlen(b);
  return -1;
}


/** Print message payload. 
 *
 * The function sl_payload_print() prints the contents of @a payload
 * object to the output @a stream.  The @a fmt specifies the output format,
 * where %s is replaced with header contents. If @a fmt is @c NULL, only the
 * header contents are printed.
 * 
 * @param stream   output stream
 * @param prefix   prefix appended to each payload line 
 * @param pl       payload object
 * 
 * @return 
 * The function sl_payload_print() returns number of bytes printed,
 * or -1 upon an error.
*/
int sl_payload_print(FILE *stream, char const *prefix, sip_payload_t const *pl)
{
  char *s = pl->pl_data, *end = pl->pl_data + pl->pl_len;
  int n, crlf = 1, total = 0;

  while (s < end && *s != '\0') {
    n = strncspn(s, end - s, "\r\n");
    crlf = strnspn(s + n, end - s - n, "\r\n");
    if (prefix)
      fputs(prefix, stream), total += strlen(prefix);
    fwrite(s, 1, n + crlf, stream);
    s += n + crlf;
    total += n + crlf;
  }
  if (crlf == 0)
    fputs("\n", stream), total++;

  return total;
}

/** Print @b Via header. 
 *
 * The function sl_via_print() prints the contents of @a via header to
 * the output @a stream.  The @a fmt specifies the output format, where %s
 * is replaced with header contents. If @a fmt is @c NULL, only the header
 * contents are printed.
 * 
 * @param stream   output stream
 * @param fmt      output format 
 * @param v        header object
 * 
 * @return 
 * The function sl_via_print() returns number of bytes printed,
 * or -1 upon an error.
 */
int sl_via_print(FILE *stream, char const *fmt, sip_via_t const *v)
{
  char s[1024];

  sip_header_field_e(s, sizeof(s), (sip_header_t const *)v, 0);
  s[sizeof(s) - 1] = '\0';

  if (fmt && strcmp(fmt, "%s"))
    return fprintf(stream, fmt, s);
  if (fputs(s, stream) >= 0)
    return strlen(s);
  return -1;
}

/** Print an header. 
 *
 * The function sl_header_print() prints the contents of an header to the
 * output @a stream.  The @a fmt specifies the output format, where %s is
 * replaced with header contents. If @a fmt is @c NULL, only the header
 * contents are printed.
 * 
 * @param stream   output stream
 * @param fmt      output format 
 * @param v        header object
 * 
 * @return 
 * The function sl_header_print() returns number of bytes printed,
 * or -1 upon an error.
 */
int sl_header_print(FILE *stream, char const *fmt, sip_header_t const *h)
{
  char s[1024];

  sip_header_field_e(s, sizeof(s), h, 0);
  s[sizeof(s) - 1] = '\0';

  if (fmt && strcmp(fmt, "%s"))
    return fprintf(stream, fmt, s);
  if (fputs(s, stream) >= 0)
    return strlen(s);
  return -1;
}
