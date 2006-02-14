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

/**
 * @file torture_su_port.c
 * @brief Test su_port interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @date Created: Wed Mar 10 17:05:23 2004 ppessi
 */

#include "config.h"

#include "su_port.c"

#if HAVE_FUNC
#elif HAVE_FUNCTION
#define __func__ __FUNCTION__
#else
static char const __func__[] = "torture_su_port";
#endif

int tstflags;

#define TSTFLAGS tstflags

#include <stdio.h>
#include <sofia-sip/tstdef.h>

char const *name = "torture_su_port";

static int callback(su_root_magic_t *magic, 
		    su_wait_t *w,
		    su_wakeup_arg_t *arg)
{
  return 0;
}

int test_sup_indices(su_port_t const *port)
{
  int i, n = 0;

  for (i = 0; i < port->sup_size_waits; i++) {
    if (port->sup_indices[i] >= 0) {
      if (port->sup_reverses[port->sup_indices[i]] != i)
	return 0;
      n++;
    }
  }

  for (i = port->sup_free_index; i != -1; i = port->sup_indices[i]) {
    if (i >= 0)
      return 0;

    n++;
    i = -2 - i;

    if (i >= port->sup_size_waits)
      return 0;
  }

  return n == port->sup_size_waits;
}

int test_register(void)
{
  su_port_t *port;
  su_sockaddr_t su[1];
  int i;
  int sockets[32] = { 0 };
  int reg[32] = { 0 };
  su_wait_t wait[32];

  BEGIN();

  memset(su, 0, sizeof su);
  su->su_len = sizeof su->su_sin;
  su->su_family = AF_INET;

  memset(wait, 0, sizeof wait);

  su_root_size_hint = 16;

  TEST_1(port = su_port_create());
  TEST(su_port_threadsafe(port), 0);
  SU_PORT_INCREF(port, __func__);

  TEST_1(test_sup_indices(port));

  for (i = 1; i < 16 + !SU_HAVE_MBOX; i++) {
    sockets[i] = su_socket(AF_INET, SOCK_DGRAM, 0); TEST_1(sockets[i] != -1);

    TEST(bind(sockets[i], &su->su_sa, sizeof su->su_sin), 0);
    
    TEST(su_wait_create(wait + i, sockets[i], SU_WAIT_IN), 0);

    reg[i] = su_port_register(port, NULL, wait + i, callback, port, 0);

    TEST_1(reg[i] > 0);
  }

  TEST(port->sup_free_index, -1);
  TEST_1(test_sup_indices(port));

  for (i = 1; i < 16; i += 2) {
    TEST(su_port_deregister(port, reg[i]), reg[i]);
  }

  TEST_1(test_sup_indices(port));

  for (i = 15; i > 0; i -= 2) {
    TEST(su_wait_create(wait + i, sockets[i], SU_WAIT_IN), 0);
    reg[i] = su_port_register(port, NULL, wait + i, callback, port, 1);
    TEST_1(reg[i] > 0);
    TEST_M(wait + i, port->sup_waits, sizeof wait[0]);
  }

  TEST(port->sup_free_index, -1);

  TEST_M(wait + 15, port->sup_waits + 7, sizeof wait[0]);
  TEST_M(wait + 13, port->sup_waits + 6, sizeof wait[0]);
  TEST_M(wait + 11, port->sup_waits + 5, sizeof wait[0]);
  TEST_M(wait + 9, port->sup_waits + 4, sizeof wait[0]);
  TEST_M(wait + 7, port->sup_waits + 3, sizeof wait[0]);
  TEST_M(wait + 5, port->sup_waits + 2, sizeof wait[0]);
  TEST_M(wait + 3, port->sup_waits + 1, sizeof wait[0]);
  TEST_M(wait + 1, port->sup_waits + 0, sizeof wait[0]);

  TEST_1(test_sup_indices(port));

  for (i = 1; i <= 8; i++) {
    TEST(su_port_deregister(port, reg[i]), reg[i]);
  }

  TEST(port->sup_pri_offset, 4);

  TEST_1(test_sup_indices(port));

  TEST(su_port_deregister(port, 0), -1);
  TEST(su_port_deregister(port, -1), -1);
  TEST(su_port_deregister(port, 20), -1);

  TEST_1(test_sup_indices(port));

  for (i = 1; i <= 8; i++) {
    TEST(su_port_deregister(port, reg[i]), -1);
  }

  TEST_VOID(su_port_decref(port, 1, __func__));

  END();
}

void usage(void)
{
  fprintf(stderr,
	  "usage: %s [-v]\n",
	  name);
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else
      usage();
  }

  su_init();

  retval |= test_register(); fflush(stdout);

  su_deinit();

  return retval;
}
