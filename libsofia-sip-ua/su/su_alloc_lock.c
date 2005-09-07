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

/**@ingroup su_alloc
 * @CFILE su_alloc_lock.c 
 * @brief Thread-locking for su_alloc module.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Fri Feb 23 17:38:11 2001 ppessi
 * $Date: 2005/07/20 20:35:57 $
 */

#include "config.h"

char const su_alloc_lock_c_id[] = 
"$Id: su_alloc_lock.c,v 1.1.1.1 2005/07/20 20:35:57 kaiv Exp $";

#include <su_alloc.h>

#if SU_HAVE_PTHREADS
#include <pthread.h>
#include <assert.h>

extern void (*su_home_locker)(void *mutex);
extern void (*su_home_unlocker)(void *mutex);

/** Convert su_home_t object to a thread-safe one.
 *
 * The function su_home_threadsafe() converts a memory home object
 * as thread-safe.
 *
 * @param home memory home object to be converted thread-safe.
 *
 * @return The function su_home_threadsafe() return 0 when successful,
 * or -1 upon an error.
 */
int su_home_threadsafe(su_home_t *home)
{
  static int locker_set = 0;
  pthread_mutex_t *mutex;

  if (!locker_set) {
    /* Avoid linking pthread library just for memory management...  */
    su_home_locker = (void *)pthread_mutex_lock;
    su_home_unlocker = (void *)pthread_mutex_unlock;
    locker_set = 1;
  }

  if (home == NULL || home->suh_lock)
    return 0;

  mutex = su_alloc(home, sizeof (pthread_mutex_t));
  if (mutex) {
    pthread_mutex_init(mutex, NULL);
    home->suh_lock = (void *)mutex;
    return 0;
  }

  assert(mutex);
  return -1;
}

#else
int su_home_threadsafe(su_home_t *h)
{
  return -1;
}
#endif
