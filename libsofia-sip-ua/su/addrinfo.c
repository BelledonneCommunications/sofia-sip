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

/**@ingroup su_programs
 * @CFILE addrinfo.c
 *
 * Resolve network address.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Sun Jul 14 09:17:21 2002 ppessi
 * @date Last modified: Wed Jul 20 20:35:55 2005 kaiv
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "su.h"
#include "su_module_debug.h"

/**@ingroup su_programs
 * <hr>
 * @page addrinfo addrinfo - resolve network services
 * 
 * @par Name    
 * addrinfo - resolve network services
 *
 * @par Synopsis
 *
 * <tt>addrinfo [-pcn46] host service</tt>
 *
 * @par Description
 * 
 * The @em addrinfo utility will use su_getaddrinfo() to resolve the network
 * services and print resolved names.
 *
 * @par Options
 *
 * The @e addrinfo utility accepts following ccommand line options:
 * <dl>
 * <dt>-p</dt>
 * <dd>use passive open.</dd>
 * <dt>-c</dt>
 * <dd>get canonic name.</dd>
 * <dt>-n</dt>
 * <dd>use numeric host names.</dd>
 * <dt>-4</dt>
 * <dd>IPv4 only.</dd>
 * <dt>-6</dt>
 * <dd>IPv6 only (but including mapped IPv4 addresses).</dd>
 * </dl>
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 */

char const help[] =
"usage: addrinfo [-imdn46gslh] [domainname]\n"
"\t-p query for passive open\n"
"\t-n use numeric host names\n"
"\t-c ask for canonic names\n"
"\t-4 IPv4 only\n"
"\t-6 IPv6 only (but including mapped IPv4 addresses)\n"
;

int getopt(int argc, char * const argv[], char const *opstring);
extern int optind;

void usage(void)
{
  fputs(help, stderr);
  exit(1);
}

int main(int argc, char *argv[])
{
  char buffer[INET6_ADDRSTRLEN];
  su_addrinfo_t hints[1] = {{ 0 }};
  su_addrinfo_t *ai, *res = NULL;
  char const *host, *service;
  int error;

  for (;;) {
    switch(getopt(argc, argv, "ndp4c")) {
    case '4': hints->ai_family = AF_INET; break;
    case '6': hints->ai_family = AF_INET6; break;
    case 'p': hints->ai_flags |= AI_PASSIVE; break;
    case 'n': hints->ai_flags |= AI_NUMERICHOST; break;
    case 'c': hints->ai_flags |= AI_CANONNAME; break;

    case -1:
      goto main;

    default:
      usage();
    }
  }

 main:
  if (optind + 1 >= argc)
    usage();

  service = argv[optind++];
  host = argv[optind++];

  su_init();

  if ((error = su_getaddrinfo(host, service, hints, &res)) == 0) {
    for (ai = res; ai; ai = ai->ai_next) {
      su_sockaddr_t const *su = (su_sockaddr_t const *)ai->ai_addr;
      unsigned port;

      if (su->su_family != AF_INET6 && su->su_family != AF_INET)
	continue;

      port = ntohs(su->su_port);
      inet_ntop(ai->ai_family, SU_ADDR(su), buffer, sizeof(buffer));
      printf("%d@[%s]:%u", ai->ai_protocol, buffer, port);

      if (ai->ai_flags & AI_CANONNAME)
        printf(" canon=%s", ai->ai_canonname);

      puts("");
    }
    su_freeaddrinfo(res);
  }
  else {
    fprintf(stderr, "addrinfo: %s\n", su_gai_strerror(error));
    error = 1;
  }

  su_deinit();

  return error;
}
