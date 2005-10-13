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

/**@CFILE su_timer.c
 *
 * Timer interface for su_root.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * Created: Fri Apr 28 15:45:41 2000 ppessi
 * @date Last modified: Wed Aug  3 17:24:28 2005 ppessi
 */

#include "config.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "su.h"
#include "su_wait.h"
#include "su_alloc.h"
#include "su_module_debug.h"

/**@ingroup su_wait
 * 
 * @page su_timer_t Timer Objects
 *
 *  Timers are used to schedule some task to be executed at given time or
 *  after a default interval. The default interval is specified when the
 *  timer is created. We call timer activation "setting the timer", and
 *  deactivation "resetting the timer" (as in SDL). When the given time has
 *  arrived or the default interval has elapsed, the timer expires and 
 *  it is ready for execution.
 *
 *  The functions used to create, destroy, activate, and manage timers are
 *  as follows:
 *   - su_timer_create(),
 *   - su_timer_destroy(),
 *   - su_timer_set(),
 *   - su_timer_run(),
 *   - su_timer_set_at(),
 *   - su_timer_reset(), and
 *   - su_timer_root().
 *
 * @note 
 * Timers use poll() to wake up waiting thread. On Linux, the timer
 * granularity is determined by HZ kernel parameter, which decided when the
 * kernel was compiled. With kernel 2.4 the default granularity is 10
 * milliseconds, and minimum duration of a timer is approximately 20
 * milliseconds. Naturally, using RTC would give better timing results, but
 * RTC usage above 64 Hz is privileged operation.
 *
 * @par
 * On Windows, the granularity is determined by the real-time clock timer.
 * By default, it uses the 18.78 Hz granularity.  That timer can be adjusted
 * up to 1000 Hz using Windows multimedia library.
 *
 * @section su_timer_usage Using Timers
 *
 * A timer is created by calling su_timer_create():
 * @code
 *   timer = su_timer_create(su_root_task(root), 200);
 * @endcode
 * The default duration is given in milliseconds.
 *
 * Usually, timer wakeup function should be called at regular intervals. In
 * such case, the timer is activated using function su_timer_run(). When the
 * timer is run it is given the wakeup function and pointer to context
 * data:
 * @code
 *   su_timer_run(timer, timer_wakeup, args);
 * @endcode
 *
 * When run, the timer invokes the wakeup function approximately at the
 * intervals of the default duration given in su_timer_create(). When the
 * interval has passed, the root event loop calls the wakeup function:
 * @code
 *   timer_wakeup(root, timer, args);
 * @endcode
 *
 * Timer ceases running when su_timer_reset() is called.
 * 
 * @note While the timer tries to compensate for delays occurred before and
 * during the callback, it cannot be used as an exact source of timing
 * information.
 *
 * Alternatively, the timer can be @b set for one-time event invocation. 
 * When the timer is set, it is given the wakeup function and pointer to
 * context data. The actual duration can also be specified using
 * su_timer_set_at(). @code su_timer_set(timer, timer_wakeup, args);
 * @endcode
 *
 * When the timer expires, the root event loop calls the wakeup function:
 * @code
 *   timer_wakeup(root, timer, args);
 * @endcode
 *
 * If the timed event is not needed anymore, the timer can be reset:
 * @code
 *   su_timer_reset(timer);
 * @endcode
 *
 * If the timer is expected to be called at regular intervals, it is
 * possible to set ro run continously with su_timer_run().  While such a
 * continously running timer is active it @b must @b not @b be @b set using
 * su_timer_set() or su_timer_set_at().
 *
 * When the timer is not needed anymore, the timer object itself should be
 * destroyed:
 * @code
 *   su_timer_destroy(timer);
 * @endcode
 */

struct su_timer_s {
  su_timer_t     *sut_next;	/**< Pointer to next */
  su_timer_t    **sut_prev;	/**< Pointer to previous */
  su_task_r       sut_task;	/**< Task reference */
  su_time_t       sut_when;	/**< When timer should be waken up next time */
  su_duration_t   sut_duration;	/**< Timer duration */
  su_timer_f      sut_wakeup;	/**< Function to call when waken up */
  su_timer_arg_t *sut_arg;	/**< Pointer to argument data */
  unsigned        sut_running;	/**< Timer is running */
  su_time_t       sut_run;	/**< When this timer started to run */
  unsigned        sut_woken;	/**< Timer has waken up this many times */
};

enum {
  reset = 0,
  run_at_intervals = 1,
  run_for_ever = 2
};

/**Create a timer.
 *
 * Allocate and initialize an instance of su_timer_t.
 * 
 * @param task a task for root object with which the timer will be associated
 * @param msec the default duration of the timer
 * 
 * @return A pointer to allocated timer instance, NULL on error.
 */
su_timer_t *su_timer_create(su_task_r const task, su_duration_t msec)
{
  su_timer_t *retval;

  assert(msec >= 0);

  if (su_task_cmp(task, su_task_null))
    retval = su_zalloc(NULL, sizeof(*retval));
  else
    retval = NULL;

  if (retval) {
    su_task_copy(retval->sut_task, task);
    retval->sut_duration = msec;
  }

  return retval;
}

/** Destroy a timer.
 *
 * Deinitialize and free an instance of su_timer_t.
 * 
 * @param t pointer to the timer object
 */
void su_timer_destroy(su_timer_t *t)
{
  if (t) {
    su_task_deinit(t->sut_task);
    su_timer_reset(t);
    su_free(NULL, t);
  }
}

/** Set the timer for an interval.
 *
 *  Sets (starts) the given timer to expire after the default duration.  
 *
 *  The timer must have an default duration.
 * 
 * @param t       pointer to the timer object
 * @param wakeup  pointer to the wakeup function
 * @param arg     argument given to the wakeup function
 * 
 * @return 0 if successful, -1 otherwise.
 */
int su_timer_set(su_timer_t *t, 
		 su_timer_f wakeup, 
		 su_timer_arg_t *arg)
{
  if (t == NULL) {
    SU_DEBUG_1(("su_timer_set: NULL argument\n"));
    return -1;
  }

  assert(t->sut_duration > 0);
  if (t->sut_duration == 0) {
    SU_DEBUG_1(("su_timer_set: timer without default duration\n")); 
    return -1;
  }

  return su_timer_set_at(t, wakeup, arg, 
			 su_time_add(su_now(), t->sut_duration));
}

/** Set timer at known time.
 *
 *  Sets the timer to expire at given time.  
 * 
 * @param t       pointer to the timer object
 * @param wakeup  pointer to the wakeup function
 * @param arg     argument given to the wakeup function
 * @param when    time structure defining the wakeup time
 * 
 * @return 0 if successful, -1 otherwise.
 */
int su_timer_set_at(su_timer_t *t, 
		    su_timer_f wakeup, 
		    su_wakeup_arg_t *arg,
		    su_time_t when)
{
  su_timer_t **t0;

  if (t == NULL) {
    SU_DEBUG_1(("su_timer_set_at: NULL argument\n")); 
    return -1;
  }

  if (t->sut_prev)
    su_timer_reset(t);

  t->sut_wakeup = wakeup;
  t->sut_arg = arg;
  t->sut_when = when;

  for (t0 = su_task_timers(t->sut_task); 
       t0 && *t0 && su_time_cmp((*t0)->sut_when, when) <= 0; 
       t0 = &(*t0)->sut_next)
    ;
  
  if ((t->sut_next = *t0))
    t->sut_next->sut_prev = &t->sut_next;
  t->sut_prev = t0;
  *t0 = t;

  return 0;
}

/** Set the timer for regular intervals.
 *
 * Run the given timer continuously, call wakeup function repeately in the
 * default interval. If a wakeup call is missed, try to make it up (in other
 * words, this kind of timer fails miserably if time is adjusted and it
 * should really use /proc/uptime instead of gettimeofday()). 
 *
 * While a continously running timer is active it @b must @b not @b be @b
 * set using su_timer_set() or su_timer_set_at().
 *
 * The timer must have an non-zero default interval.
 * 
 * @param t       pointer to the timer object
 * @param wakeup  pointer to the wakeup function
 * @param arg     argument given to the wakeup function
 * 
 * @return 0 if successful, -1 otherwise.
 */
int su_timer_run(su_timer_t *t, 
		 su_timer_f wakeup, 
		 su_timer_arg_t *arg)
{
  su_time_t now = su_now();

  if (t == NULL) {
    SU_DEBUG_1(("su_timer_run: NULL argument\n")); 
    return -1;
  }

  assert(t->sut_duration > 0);
  if (t->sut_duration == 0) {
    SU_DEBUG_1(("su_timer_run: timer without default duration\n")); 
    return -1;
  }

  if (su_timer_set_at(t, wakeup, arg, su_time_add(now, t->sut_duration)) < 0)
    return -1;

  t->sut_running = run_at_intervals;
  t->sut_run = now;
  t->sut_woken = 0;

  return 0;
}

/**Set the timer for regular intervals.
 *
 * Run the given timer continuously, call wakeup function repeately in the
 * default interval. While a continously running timer is active it @b must
 * @b not @b be @b set using su_timer_set() or su_timer_set_at(). Unlike
 * su_timer_run(), the timer does not try to catchup missed callbacks..
 *
 * The timer must have an non-zero default interval.
 * 
 * @param t       pointer to the timer object
 * @param wakeup  pointer to the wakeup function
 * @param arg     argument given to the wakeup function
 * 
 * @return 0 if successful, -1 otherwise.
 */
int su_timer_set_for_ever(su_timer_t *t, 
			  su_timer_f wakeup, 
			  su_timer_arg_t *arg)
{
  su_time_t now = su_now();

  if (t == NULL) {
    SU_DEBUG_1(("su_timer_run: NULL argument\n")); 
    return -1;
  }

  assert(t->sut_duration > 0);
  if (t->sut_duration == 0) {
    SU_DEBUG_1(("su_timer_run: timer without default duration\n")); 
    return -1;
  }

  if (su_timer_set_at(t, wakeup, arg, su_time_add(now, t->sut_duration)) < 0)
    return -1;

  t->sut_running = run_for_ever;

  return 0;
}


/**Reset the timer.
 *
 * Resets (stops) the given timer.
 *
 * @param t  pointer to the timer object
 * 
 * @return 0 if successful, -1 otherwise.
 */
int su_timer_reset(su_timer_t *t)
{
  if (t == NULL) {
    SU_DEBUG_1(("su_timer_reset: NULL argument\n")); 
    return -1;
  }

  if (t) {
    if (t->sut_prev) {
      su_timer_t **t0 = t->sut_prev;

      assert(*t0 == t);

      if ((*t0 = t->sut_next)) t->sut_next->sut_prev = t0;

      t->sut_next = NULL; t->sut_prev = NULL;
    }

    t->sut_wakeup = NULL;
    t->sut_arg = NULL;
    t->sut_running = reset;
    memset(&t->sut_run, 0, sizeof(t->sut_run));

    return 0;
  }

  return -1;
}

/** @internal Check for expired timers in queue.
 * 
 * The function su_timer_expire() checks a timer queue and executes and
 * removes expired timers from the queue. It also calculates the time when
 * the next timer expires.
 *
 * @param t0       pointer to the timer queue
 * @param timeout  timeout  in milliseconds [IN/OU]
 * @param now      current timestamp
 * 
 * @return 
 * The number of expired timers.
 */
int su_timer_expire(su_timer_t ** const t0, 
		    su_duration_t *timeout,
		    su_time_t now)
{
  su_timer_t *t;
  su_timer_f f;
  int n = 0;

  if (!*t0)
    return n;

  while ((t = *t0) != NULL) {
    if (su_time_cmp(t->sut_when, now) > 0)
      break;
    if ((*t0 = t->sut_next)) t->sut_next->sut_prev = t0;
    t->sut_next = NULL; t->sut_prev = NULL;
    f = t->sut_wakeup; t->sut_wakeup = NULL;
    t->sut_when = now;
    assert(f);

    if (t->sut_running == run_for_ever) {
      f(su_root_magic(su_task_root(t->sut_task)), t, t->sut_arg); n++;
      if (t->sut_running)
	su_timer_set_at(t, f, t->sut_arg, 
			su_time_add(t->sut_run, 
				    (t->sut_woken + 1) * t->sut_duration));
    } 
    else if (t->sut_running == run_at_intervals) {
      unsigned times = (unsigned)
	((1000.0 * su_time_diff(now, t->sut_run) + t->sut_duration * 0.5) /
	  (double)t->sut_duration);
      while (t->sut_woken < times) {
	t->sut_woken++;
	f(su_root_magic(su_task_root(t->sut_task)), t, t->sut_arg); n++;
      }
      if (t->sut_running)
	su_timer_set_at(t, f, t->sut_arg, 
			su_time_add(t->sut_run, 
				    (t->sut_woken + 1) * t->sut_duration));
    }
    else {
      f(su_root_magic(su_task_root(t->sut_task)), t, t->sut_arg); n++;
    }
  }

  if (t) {
    su_duration_t at = su_duration(t->sut_when, now);

    if (at < *timeout)
      *timeout = at;
  }

  return n;
}


su_duration_t su_timer_next_expires(su_timer_t const * t, su_time_t now)
{
  su_duration_t tout;
  
  if (!t)
    return SU_DURATION_MAX;

  tout = su_duration(t->sut_when, now);

  return tout > 0 ? tout : 0 ;
}

/**
 * Resets and frees all timers belonging to a task.
 *
 * The function su_timer_destroy_all() resets and frees all timers belonging
 * to the specified task in the queue.
 *
 * @param t0   pointer to the timer queue
 * @param task task owning the timers
 *
 * @return Number of timers reset. 
 */
int su_timer_reset_all(su_timer_t **t0, su_task_r task)
{
  su_timer_t *t;
  int n = 0;

  while ((t = *t0) != NULL) {
    if (su_task_cmp(task, t->sut_task)) {
      t0 = &t->sut_next;
    }
    else {
      if ((*t0 = t->sut_next)) t->sut_next->sut_prev = t0;
      n++;
      su_free(NULL, t);
    }
  }

  return n;
}

/** Get the root object owning the timer.
 *
 *   The function su_timer_root() return pointer to the root object owning the
 *   timer.
 *
 * @param t pointer to the timer
 * 
 * @return Pointer to the root object owning the timer.
 */
su_root_t *su_timer_root(su_timer_t const *t)
{
  return su_task_root(t->sut_task);
}
