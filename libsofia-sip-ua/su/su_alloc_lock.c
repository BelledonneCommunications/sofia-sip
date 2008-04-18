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

#include <sofia-sip/su_alloc.h>
#include <sofia-sip/su.h>

#if SU_HAVE_PTHREADS
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>

v v v v v v v
extern int (*_su_home_locker)(void *mutex);
extern int (*_su_home_unlocker)(void *mutex);
*************
struct su_alock
{
  pthread_mutex_t mutex[1];	/* Used by su_home_lock()/unlock */

  pthread_mutex_t refmutex[1];	/* Used by reference counting */
  pthread_cond_t  cond[1];
  int signal_on_unlock;
};

extern void (*su_home_locker)(void *alock);
extern void (*su_home_unlocker)(void *alock);
^ ^ ^ ^ ^ ^ ^

v v v v v v v
extern int (*_su_home_mutex_locker)(void *mutex);
extern int (*_su_home_mutex_trylocker)(void *mutex);
extern int (*_su_home_mutex_unlocker)(void *mutex);
*************
extern int (*su_home_wait)(void *alock);
^ ^ ^ ^ ^ ^ ^

v v v v v v v
extern void (*_su_home_destroy_mutexes)(void *mutex);
*************
extern void (*su_home_mutex_locker)(void *alock);
extern void (*su_home_mutex_unlocker)(void *alock);

extern void (*su_home_destroy_mutexes)(void *alock);
^ ^ ^ ^ ^ ^ ^

/** Mutex */
v v v v v v v
static int mutex_locker(void *_mutex)
*************
static void mutex_locker(void *alock)
{
  struct su_alock *a = alock;
  pthread_mutex_lock(a->refmutex);
}

static void mutex_unlocker(void *alock)
^ ^ ^ ^ ^ ^ ^
{
v v v v v v v
  pthread_mutex_t *mutex = _mutex;
  return pthread_mutex_lock(mutex + 1);
*************
  struct su_alock *a = alock;
  if (a->signal_on_unlock)
    pthread_cond_signal(a->cond);
  pthread_mutex_unlock(a->refmutex);
^ ^ ^ ^ ^ ^ ^
}

v v v v v v v
/** @internal
 *
 * Call after mutex_locker().
 */
static int mutex_wait(void *alock)
*************
int mutex_trylocker(void *_mutex)
^ ^ ^ ^ ^ ^ ^
{
v v v v v v v
  pthread_mutex_t *mutex = _mutex;
  return pthread_mutex_trylock(mutex + 1);
}

static int mutex_unlocker(void *_mutex)
{
  pthread_mutex_t *mutex = _mutex;
  return pthread_mutex_unlock(mutex + 1);
*************
  struct su_alock *a = alock;
  a->signal_on_unlock = 1;
  pthread_cond_wait(a->cond, a->refmutex);
  return 1;
^ ^ ^ ^ ^ ^ ^
}

static void mutex_destroy(void *alock)
{
  struct su_alock *a = alock;
  pthread_cond_destroy(a->cond);
  pthread_mutex_destroy(a->mutex);
  pthread_mutex_destroy(a->refmutex);
  free(a);
}
v v v v v v v
*************


^ ^ ^ ^ ^ ^ ^
#endif


/** Convert su_home_t object to a thread-safe one.
 *
 * Convert a memory home object as thread-safe by allocating mutexes and
 * modifying function pointers in su_alloc.c module.
 *
 * @param home memory home object to be converted thread-safe.
 *
 * @retval 0 when successful,
 * @retval -1 upon an error.
 */
int su_home_threadsafe(su_home_t *home)
{
  struct su_alock *a;

  if (home == NULL)
    return su_seterrno(EFAULT);
  if (home->suh_lock)		/* Already? */
    return 0;

#if SU_HAVE_PTHREADS
  if (!_su_home_unlocker) {
    /* Avoid linking pthread library just for memory management */
v v v v v v v
    _su_home_mutex_locker = mutex_locker;
    _su_home_mutex_trylocker = mutex_trylocker;
    _su_home_mutex_unlocker = mutex_unlocker;
    _su_home_locker = (int (*)(void *))pthread_mutex_lock;
    _su_home_unlocker = (int (*)(void *))pthread_mutex_unlock;
    _su_home_destroy_mutexes = mutex_destroy;
*************
    su_home_mutex_locker = (void (*)(void *))pthread_mutex_lock;
    su_home_mutex_unlocker = (void (*)(void *))pthread_mutex_unlock;
    su_home_locker = mutex_locker;
    su_home_unlocker = mutex_unlocker;
    su_home_wait = mutex_wait;
    su_home_destroy_mutexes = mutex_destroy;
^ ^ ^ ^ ^ ^ ^
  }

  a = calloc(1, (sizeof *a)); assert(a);
  if (!a)
    return -1;
  
  /* Mutex used for explicit locking */ 
  pthread_mutex_init(a->mutex, NULL);
  
  /* Mutex for memory operations */
  pthread_mutex_init(a->refmutex, NULL);
  pthread_cond_init(a->cond, NULL);
  
  home->suh_lock = (void *)a;

  return 0;
#else
  (void *)a;
  su_seterrno(ENOSYS);
  return -1;
#endif
}
