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

/**@ingroup su_alloc
 * @CFILE su_alloc_lock.c 
 * @brief Thread-locking for su_alloc module.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Fri Feb 23 17:38:11 2001 ppessi
 */

#include "config.h"

#include <su_alloc.h>

#if SU_HAVE_PTHREADS
#include <pthread.h>
#include <assert.h>

extern void (*su_home_locker)(void *mutex);
extern void (*su_home_unlocker)(void *mutex);

extern void (*su_home_mutex_locker)(void *mutex);
extern void (*su_home_mutex_unlocker)(void *mutex);

/** Mutex */
static void mutex_locker(void *_mutex)
{
  pthread_mutex_t *mutex = _mutex;
  pthread_mutex_lock(mutex + 1);
}

static void mutex_unlocker(void *_mutex)
{
  pthread_mutex_t *mutex = _mutex;
  pthread_mutex_unlock(mutex + 1);
}

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
  pthread_mutex_t *mutex;

  if (home == NULL || home->suh_lock)
    return 0;

  assert(!su_home_has_parent(home));
  if (su_home_has_parent(home))
    return -1;

  if (!su_home_unlocker) {
    /* Avoid linking pthread library just for memory management */
    su_home_mutex_locker = mutex_locker;
    su_home_mutex_unlocker = mutex_unlocker;
    su_home_locker = (void *)pthread_mutex_lock;
    su_home_unlocker = (void *)pthread_mutex_unlock;
  }

  mutex = su_alloc(home, 2 * sizeof (pthread_mutex_t));
  if (mutex) {
    /* Mutex for memory operations */
    pthread_mutex_init(mutex, NULL);
    /* Mutex used for explicit locking */ 
    pthread_mutex_init(mutex + 1, NULL);
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
