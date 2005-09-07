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

/**@ingroup su
 * 
 * @file su_torture.c
 *
 * Testing functions for su socket functions.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Thu May  2 18:17:46 2002 ppessi
 * $Date: 2005/07/20 20:35:59 $
 */

#include "config.h"

const char su_torture_c_id[] =
"$Id: su_torture.c,v 1.1.1.1 2005/07/20 20:35:59 kaiv Exp $";

#include <stdio.h>
#include <string.h>

#include <su.h>
#include <su_localinfo.h>

int tstflags;

#define TSTFLAGS tstflags
#include <tstdef.h>

char const *name = "su_torture";

static int test_sockaddr(void);

void usage(void)
{
  fprintf(stderr, "usage: %s [-v]\n", name);
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  su_init();

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else
      usage();
  }
  
  retval |= test_sockaddr();

  su_deinit();

  return retval;
}

/**  */
int test_sockaddr(void)
{
  su_localinfo_t hints[1] = {{ LI_CANONNAME }};
  su_localinfo_t *li, *res = NULL;
  int s;
  su_sockaddr_t  su[1], a[1], b[1];

  BEGIN();
  
  hints->li_family = AF_INET;

  TEST(su_getlocalinfo(hints, &res), 0);

  for (li = res; li; li = li->li_next) {
    if (li->li_addrlen != res->li_addrlen ||
	memcmp(li->li_addr, res->li_addr, li->li_addrlen) != 0)
      TEST_1(su_cmp_sockaddr(li->li_addr, res->li_addr) != 0);
    else 
      TEST_1(su_cmp_sockaddr(li->li_addr, res->li_addr) == 0);
  }

  memset(su, 0, sizeof su);
  TEST(su_getlocalip(su), 0);

  if (res->li_family == AF_INET)
    TEST(su_cmp_sockaddr(res->li_addr, su), 0);

  TEST_1(su_gli_strerror(ELI_NOERROR));
  TEST_1(su_gli_strerror(ELI_NOADDRESS));
  TEST_1(su_gli_strerror(ELI_FAMILY));
  TEST_1(su_gli_strerror(ELI_MEMORY));
  TEST_1(su_gli_strerror(ELI_RESOLVER));
  TEST_1(su_gli_strerror(ELI_SYSTEM));
  TEST_1(su_gli_strerror(-100));

  li = su_copylocalinfo(res); TEST_1(li);
  su_freelocalinfo(li);

  s = su_socket(res->li_family, SOCK_DGRAM, 0); TEST_1(s != -1);
  TEST(su_setblocking(s, 0), 0);
  TEST(su_setblocking(s, 1), 0);
  TEST(su_close(s), 0);

  su_freelocalinfo(res);

#if SU_HAVE_IN6
  hints->li_family = AF_INET6;
  hints->li_flags &= ~LI_CANONNAME;
  hints->li_flags |= LI_V4MAPPED;

  TEST(su_getlocalinfo(hints, &res), 0);
  for (li = res; li; li = li->li_next)
    TEST(li->li_family, AF_INET6);

  su_freelocalinfo(res);
#endif

  hints->li_flags |= LI_NUMERIC;
  TEST(su_getlocalinfo(hints, &res), 0);

  hints->li_flags |= LI_NAMEREQD;
  res = NULL;
  su_getlocalinfo(hints, &res);
  su_freelocalinfo(res);

  memset(a, 0, sizeof *a); 
  memset(b, 0, sizeof *b); 

  TEST_1(su_match_sockaddr(a, b));
  b->su_family = AF_INET;
  TEST_1(su_match_sockaddr(a, b));
  a->su_port = htons(12);
  TEST_1(!su_match_sockaddr(a, b));
  b->su_port = htons(12);
  TEST_1(su_match_sockaddr(a, b));
  a->su_sin.sin_addr.s_addr = htonl(0x7f000001);
  TEST_1(su_match_sockaddr(a, b));
  a->su_family = AF_INET;
  TEST_1(!su_match_sockaddr(a, b));
  b->su_sin.sin_addr.s_addr = htonl(0x7f000001);
  TEST_1(su_match_sockaddr(a, b));
  a->su_sin.sin_addr.s_addr = 0;
  TEST_1(su_match_sockaddr(a, b));
  a->su_family = AF_INET6;
  TEST_1(!su_match_sockaddr(a, b));
  b->su_family = AF_INET6;
  TEST_1(su_match_sockaddr(a, b));
  b->su_sin6.sin6_addr.s6_addr[15] = 1;
  TEST_1(su_match_sockaddr(a, b));
  TEST_1(!su_match_sockaddr(b, a));
  a->su_sin6.sin6_addr.s6_addr[15] = 2;
  TEST_1(!su_match_sockaddr(a, b));
  a->su_family = 0;
  TEST_1(su_match_sockaddr(a, b));
  TEST_1(!su_match_sockaddr(b, a));

  END();
}
