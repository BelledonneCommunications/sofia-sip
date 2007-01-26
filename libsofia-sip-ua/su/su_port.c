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

/**@ingroup su_wait
 * @CFILE su_port.c
 *
 * OS-Independent Socket Syncronization Interface.
 *
 * This looks like nth reincarnation of "reactor". It implements the
 * poll/select/WaitForMultipleObjects and message passing functionality. 
 * This is virtual implementation:
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 *
 * @date Created: Tue Sep 14 15:51:04 1999 ppessi
 */

#include "config.h"

#include "su_port.h"

#include <string.h>
#include <stdlib.h>

static su_port_t *(*preferred_su_port_create)(void);

/** Explicitly set the preferred su_port_t implementation.
 *
 * @sa su_epoll_port_create(), su_poll_port_create(), su_select_port_create()
 */
void su_port_prefer(su_port_t *(*implementation)(void))
{
  preferred_su_port_create = implementation;
}

/** Create the preferred su_port_t implementation.
 */
su_port_t *su_port_create(void)
{
  if (preferred_su_port_create == NULL) {
    char const *SU_PORT = getenv("SU_PORT");
    su_port_t *(*create)(void) = NULL;

    if (SU_PORT == NULL)
      ;
#if HAVE_POLL_PORT
#if HAVE_EPOLL
    else if (strcmp(SU_PORT, "epoll") == 0)
      create = su_epoll_port_create;
#endif
    else if (strcmp(SU_PORT, "poll") == 0)
      create = su_poll_port_create;
#else
#error no poll!
#endif
#if HAVE_SELECT
    else if (strcmp(SU_PORT, "select") == 0)
      create = su_select_port_create;
#endif

    if (create == NULL) {
      create = su_epoll_port_create;
#if HAVE_POLL_PORT
#if HAVE_EPOLL
      create = su_epoll_port_create;
#else
      create = su_poll_port_create;
#endif
#else
#if HAVE_SELECT
      create = su_select_port_create;
#endif
#endif
    }

    if (create)
      preferred_su_port_create = create;
  }

  if (preferred_su_port_create)
    return preferred_su_port_create();

  return NULL;
}
