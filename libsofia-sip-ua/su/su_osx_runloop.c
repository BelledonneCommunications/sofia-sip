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
 * @file su_osx_runloop.c
 * @brief Wrapper for OS X Core Foundation Run Loop.
 *  
 * @author Martti Mela <Martti.Mela@nokia.com>.
 * 
 * @date Created: Tue Sep 19 17:16:00 EEST 2006 mela
 * 
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

/* Use Posix stuff */
#define _XOPEN_SOURCE  (500)

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <AvailabilityMacros.h>
#include <sys/cdefs.h>
#include <CoreFoundation/CoreFoundation.h>

#if HAVE_GETTIMEOFDAY
#include <sys/time.h>
#else
#error "You need sys/time.h header installed"
#endif

#define SU_PORT_IMPLEMENTATION 1

#define SU_MSG_ARG_T union { char anoymous[4]; }

#define su_port_s su_port_osx_s

#include "sofia-sip/su_osx_runloop.h"

#include "sofia-sip/su.h"
#include "su_port.h"
#include "sofia-sip/su_alloc.h"

#if SU_HAVE_PTHREADS
#include <pthread.h>
#endif

static su_port_t *su_osx_runloop_create(void) __attribute__((__malloc__));

#if 0
static gboolean su_source_prepare(GSource *gs, gint *return_tout);
static gboolean su_source_check(GSource *gs);
static gboolean su_source_dispatch(GSource *gs,
			    GSourceFunc callback,
			    gpointer user_data);
static void su_source_finalize(GSource *source);
#endif

static int su_port_osx_getmsgs(su_port_t *self);

/* Callbacks of Source Context */
/* static const void *su_port_osx_retain(const void *info); */
static void        su_port_osx_release(const void *info);
static const void *su_port_osx_copy_description(const void *info);
static CFHashCode  su_port_osx_hash(const void *info);
static void        su_port_osx_schedule(void *info, CFRunLoopRef rl, CFStringRef mode);
static void        su_port_osx_cancel(void *info, CFRunLoopRef rl, CFStringRef mode);
static void        su_port_osx_perform(const void *info);

#if 0
static
GSourceFuncs su_port_osx_funcs[1] = {{
    su_port_osx_prepare,
    su_port_osx_check,
    su_port_osx_dispatch,
    su_port_osx_finalize,
    NULL,
    NULL
  }};
#else
static
CFRunLoopSourceContext su_port_osx_funcs[1] = {{
    0, /* type */
    NULL, /* context */
    NULL, /* su_port_osx_retain, */ /* CFAllocatorRetainCallBack */
    su_port_osx_release, /* CFAllocatorReleaseCallBack */
    NULL, /* su_port_osx_copyDescription, */ /* CFAllocatorCopyDescriptionCallBack */
    NULL, /* su_port_osx_equal, */ /* CFRunLoopEqualCallBack */
    NULL, /* su_port_osx_hash, */ /* CFRunLoopHashCallBack */
    su_port_osx_schedule, /* CFRunLoopScheduleCallBack */
    su_port_osx_cancel, /* CFRunLoopCancelCallBack */
    su_port_osx_perform /* CFRunLoopPerformCallBack */
}};
#endif


static void su_port_osx_lock(su_port_t *self, char const *who);
static void su_port_osx_unlock(su_port_t *self, char const *who);
static void su_port_osx_incref(su_port_t *self, char const *who);
static void su_port_osx_decref(su_port_t *self, int blocking, char const *who);

static CFRunLoopSourceRef su_port_osx_runloop_source(su_port_t *port);

static int su_port_osx_send(su_port_t *self, su_msg_r rmsg);

static int su_port_osx_register(su_port_t *self,
			    su_root_t *root, 
			    su_wait_t *wait, 
			    su_wakeup_f callback,
			    su_wakeup_arg_t *arg,
			    int priority);
static int su_port_osx_unregister(su_port_t *port,
			      su_root_t *root, 
			      su_wait_t *wait,	
			      su_wakeup_f callback, 
			      su_wakeup_arg_t *arg);
static int su_port_osx_deregister(su_port_t *self, int i);
static int su_port_osx_unregister_all(su_port_t *self,
				  su_root_t *root);
static int su_port_osx_eventmask(su_port_t *self, 
			     int index, int socket, int events);
static void su_port_osx_run(su_port_t *self);
static void su_port_osx_break(su_port_t *self);
static su_duration_t su_port_osx_step(su_port_t *self, su_duration_t tout);
static int su_port_osx_own_thread(su_port_t const *port);
static int su_port_osx_add_prepoll(su_port_t *port,
			       su_root_t *root, 
			       su_prepoll_f *, 
			       su_prepoll_magic_t *);
static int su_port_osx_remove_prepoll(su_port_t *port,
				  su_root_t *root);
static su_timer_t **su_port_osx_timers(su_port_t *port);
static int su_port_osx_multishot(su_port_t *self, int multishot);
static int su_port_osx_threadsafe(su_port_t *port);

static
su_port_vtable_t const su_port_osx_vtable[1] =
  {{
      /* su_vtable_size: */ sizeof su_port_osx_vtable,
      su_port_osx_lock,
      su_port_osx_unlock,
      su_port_osx_incref,
      su_port_osx_decref,

      su_port_osx_runloop_source, /* XXX - was: gsource, */

      su_port_osx_send,
      su_port_osx_register,
      su_port_osx_unregister,
      su_port_osx_deregister,
      su_port_osx_unregister_all,
      su_port_osx_eventmask,
      su_port_osx_run,
      su_port_osx_break,
      su_port_osx_step,
      su_port_osx_own_thread,
      su_port_osx_add_prepoll,
      su_port_osx_remove_prepoll,
      su_port_osx_timers,
      su_port_osx_multishot,
      su_port_osx_threadsafe

    }};

/** 
 * Port is a per-thread reactor.  
 *
 * Multiple root objects executed by single thread share a su_port_t object. 
 */
struct su_port_osx_s {
  su_home_t        sup_home[1];
  su_port_vtable_t const *sup_vtable;

#if SU_HAVE_PTHREADS
  pthread_t        sup_tid;
  pthread_mutex_t  sup_mutex[1];
  pthread_rwlock_t sup_ref[1];
#endif

  CFRunLoopSourceRef sup_source;
  CFRunLoopRef       sup_main_loop;
  
  /* Message list - this is protected by lock  */
  su_msg_t        *sup_head;
  su_msg_t       **sup_tail;

  /* Waits */
  unsigned         sup_registers; /** Counter incremented by 
				      su_port_register() or 
				      su_port_unregister()
				  */
  unsigned         sup_n_waits; 
  unsigned         sup_size_waits; 
  unsigned         sup_max_index;
  unsigned        *sup_indices; 
  su_wait_t       *sup_waits; 
  su_wakeup_f     *sup_wait_cbs; 
  su_wakeup_arg_t**sup_wait_args; 
  su_root_t      **sup_wait_roots; 

  /* Timer list */
  su_timer_t      *sup_timers;
};

typedef struct _SuSource
{
  CFRunLoopSourceRef ss_source[1];
  su_port_t          ss_port[1];
} SuSource;


#if SU_HAVE_PTHREADS

#define SU_PORT_OSX_OWN_THREAD(p)   (pthread_equal((p)->sup_tid, pthread_self()))

#define SU_PORT_OSX_INITREF(p)      (pthread_rwlock_init(p->sup_ref, NULL))
#define SU_PORT_OSX_INCREF(p, f)    (pthread_rwlock_rdlock(p->sup_ref))
#define SU_PORT_OSX_DECREF(p, f)    do { pthread_rwlock_unlock(p->sup_ref); \
  if (pthread_rwlock_trywrlock(p->sup_ref) == 0) su_port_osx_destroy(p); } while(0)

#define SU_PORT_OSX_ZAPREF(p, f)    do { pthread_rwlock_unlock(p->sup_ref); \
  if (pthread_rwlock_trywrlock(p->sup_ref) != 0) { \
    assert(!"SU_PORT_OSX_ZAPREF"); pthread_rwlock_wrlock(p->sup_ref); } \
  su_port_osx_destroy(p); } while(0)

#define SU_PORT_OSX_INITLOCK(p)     (pthread_mutex_init((p)->sup_mutex, NULL))
#define SU_PORT_OSX_LOCK(p, f)      (pthread_mutex_lock((p)->sup_mutex))
#define SU_PORT_OSX_UNLOCK(p, f)    (pthread_mutex_unlock((p)->sup_mutex))

#endif /* !SU_HAVE_PTHREADS */

#if HAVE_FUNC
#define enter (void)SU_DEBUG_9(("%s: entering\n", __func__))
#elif HAVE_FUNCTION
#define enter (void)SU_DEBUG_9(("%s: entering\n", __FUNCTION__))
#else
#define enter (void)0
#endif

static void su_port_osx_destroy(su_port_t *self);

/** Create a root that uses GSource as reactor */
su_root_t *su_root_osx_runloop_create(su_root_magic_t *magic)
{
  return su_root_create_with_port(magic, su_osx_runloop_create());
}

/**@internal
 *
 * Allocates and initializes a reactor and message port object.
 *
 * @return
 *   If successful a pointer to the new message port is returned, otherwise
 *   NULL is returned.  
 */
su_port_t *su_osx_runloop_create(void)
{
  SuSource *ss;

  SU_DEBUG_9(("su_osx_runloop_create() called\n"));

  ss = (SuSource *) CFRunLoopSourceCreate(kCFAllocatorDefault, 0, su_port_osx_funcs);

  if (ss) {
    su_port_t *self = ss->ss_port;

    self->sup_vtable = su_port_osx_vtable;
    self->sup_source = ss->ss_source;
    
    SU_PORT_OSX_INITLOCK(self);

    self->sup_tail = &self->sup_head;

#if SU_HAVE_PTHREADS
    self->sup_tid = pthread_self();
#endif

    SU_DEBUG_9(("su_port_osx_with_main_context() returns %p\n", self));

    return self;
  } else {
    su_perror("su_port_osx_with_main_context(): su_home_clone");
    SU_DEBUG_9(("su_port_osx_with_main_context() fails\n"));
    return NULL;
  }
}

/** @internal Destroy a port. */
/* XXX -- static void su_port_osx_finalize(GSource *gs) */
static void su_port_osx_release(const void *info)

{
  SuSource *ss = (SuSource *) info;
  su_port_t *self = ss->ss_port;

  assert(ss);

  SU_DEBUG_9(("su_port_osx_release() called\n"));

  if (self->sup_waits) 
    free(self->sup_waits), self->sup_waits = NULL;
  if (self->sup_wait_cbs)
    free(self->sup_wait_cbs), self->sup_wait_cbs = NULL;
  if (self->sup_wait_args)
    free(self->sup_wait_args), self->sup_wait_args = NULL;
  if (self->sup_wait_roots)
    free(self->sup_wait_roots), self->sup_wait_roots = NULL;
  if (self->sup_indices)
    free(self->sup_indices), self->sup_indices = NULL;

  su_home_deinit(self->sup_home);
}

/* Seconds from 1.1.1900 to 1.1.1970 */
#define NTP_EPOCH 2208988800UL 

/* gboolean su_port_osx_prepare(void *info, int *return_tout); */
static
void su_port_osx_schedule(void *info, CFRunLoopRef rl, CFStringRef mode)
{
  SuSource *ss = (SuSource *) info; /* XXX -- was: gs */
  su_port_t *self = ss->ss_port;

  enter;
  
  if (self->sup_head)
    return;

  /* *return_tout = -1; */

  if (self->sup_timers) {
    su_time_t now;
    struct timeval tval;
    su_duration_t tout;

    tout = SU_DURATION_MAX;

#if 1 /* XXX -- mela: add header + ifdefs */
    gettimeofday(&tval, NULL);
#endif

    now.tv_sec = tval.tv_sec + 2208988800UL;
    now.tv_usec = tval.tv_usec;

    tout = su_timer_next_expires(self->sup_timers, now);
#if 0
    if (tout == 0)
      return TRUE;

    if ((int)tout < 0 || tout > (su_duration_t)G_MAXINT)
      tout = -1;

    *return_tout = (int)tout;
#endif
  }
  
  return;
}


static
void su_port_osx_cancel(void *info, CFRunLoopRef rl, CFStringRef mode)
{
  
  su_port_osx_release(info);

  return;
}


#if 0
static
gboolean su_port_osx_check(GSource *gs)
{
  SuSource *ss = (SuSource *)gs;
  su_port_t *self = ss->ss_port;
  gint tout;
  unsigned i, I;

  enter;

  I = self->sup_n_waits;

#if 0
#if SU_HAVE_POLL
  for (i = 0; i < I; i++) {
    if (self->sup_waits[i].revents)
      return TRUE;
  }
#endif
#endif

  return su_port_osx_prepare(gs, &tout);
}
#endif

#if 0
static 
gboolean su_port_osx_dispatch(GSource *gs,
			    GSourceFunc callback,
			    gpointer user_data)
#endif

static void su_port_osx_perform(const void *info)
{
  SuSource *ss = (SuSource *) info; /* gs; */
  su_port_t *self = ss->ss_port;

  enter;

  if (self->sup_head)
    su_port_osx_getmsgs(self);

  if (self->sup_timers) {
    su_time_t now;
    struct timeval tval;
    su_duration_t tout;
    int timers = 0;

    tout = SU_DURATION_MAX;

    gettimeofday(&tval, NULL);

    now.tv_sec = tval.tv_sec + 2208988800UL;
    now.tv_usec = tval.tv_usec;

    timers = su_timer_expire(&self->sup_timers, &tout, now);
  }

#if 0 /* XXX -- mela: not needed? */
#if SU_HAVE_POLL
  {
    su_root_t *root;
    su_wait_t *waits = self->sup_waits;
    unsigned i, n = self->sup_n_waits;
    unsigned version = self->sup_registers;

    for (i = 0; i < n; i++) {
      if (waits[i].revents) {
	root = self->sup_wait_roots[i];
	self->sup_wait_cbs[i](root ? su_root_magic(root) : NULL, 
			      &waits[i], 
			      self->sup_wait_args[i]);
	/* Callback used su_register()/su_unregister() */
	if (version != self->sup_registers)
	  break;
      }
    }
  }
#endif
#endif

  return;
}

/** @internal Destroy a port. */
void su_port_osx_destroy(su_port_t *self)
{
  assert(self);

  SU_DEBUG_9(("su_port_osx_destroy() called\n"));

#if SU_HAVE_MBOX
  if (self->sup_mbox[0] != INVALID_SOCKET) {
    su_port_unregister(self, NULL, &self->sup_mbox_wait, NULL, 
		       (su_wakeup_arg_t *)self->sup_mbox);
    su_wait_destroy(&self->sup_mbox_wait);
    su_close(self->sup_mbox[0]); self->sup_mbox[0] = INVALID_SOCKET;
#if HAVE_SOCKETPAIR
    su_close(self->sup_mbox[1]); self->sup_mbox[1] = INVALID_SOCKET;
#endif
    SU_DEBUG_9(("su_port_osx_destroy() close mailbox\n"));
  }
#endif
  if (self->sup_waits) 
    free(self->sup_waits), self->sup_waits = NULL;
  if (self->sup_wait_cbs)
    free(self->sup_wait_cbs), self->sup_wait_cbs = NULL;
  if (self->sup_wait_args)
    free(self->sup_wait_args), self->sup_wait_args = NULL;
  if (self->sup_wait_roots)
    free(self->sup_wait_roots), self->sup_wait_roots = NULL;
#if 0
  if (self->sup_reverses)
    free(self->sup_reverses), self->sup_reverses = NULL;
#endif
  if (self->sup_indices)
    free(self->sup_indices), self->sup_indices = NULL;

  SU_DEBUG_9(("su_port_osx_destroy() freed registrations\n"));

  su_home_zap(self->sup_home);

  SU_DEBUG_9(("su_port_osx_destroy() returns\n"));

}

static void su_port_osx_lock(su_port_t *self, char const *who)
{
  SU_PORT_OSX_LOCK(self, who);
}

static void su_port_osx_unlock(su_port_t *self, char const *who)
{
  SU_PORT_OSX_UNLOCK(self, who);
}

static void su_port_osx_incref(su_port_t *self, char const *who)
{
  SU_PORT_OSX_INCREF(self, who);
}

static void su_port_osx_decref(su_port_t *self, int blocking, char const *who)
{
  /* XXX - blocking? */
  SU_PORT_OSX_DECREF(self, who);
}

CFRunLoopSourceRef su_port_osx_runloop_source(su_port_t *self)
{
  return self->sup_source;
}

/** @internal Send a message to the port. */
int su_port_osx_send(su_port_t *self, su_msg_r rmsg)
{
  enter;
  
  if (self) {
    su_msg_t *msg;
    CFRunLoopRef rl;
    /* CFRunLoopSourceContext rlsc[1]; */
    /* GMainContext *gmc; */

    SU_PORT_OSX_LOCK(self, "su_port_osx_send");

    msg = rmsg[0]; rmsg[0] = NULL;
    *self->sup_tail = msg;
    self->sup_tail = &msg->sum_next;

    SU_PORT_OSX_UNLOCK(self, "su_port_osx_send");

    /* CFRunLoopSourceGetContext(self->sup_source, rlsc); */
    
    /* gmc = g_source_get_context(self->sup_source); */

    rl = CFRunLoopGetCurrent();
    if (rl)
      CFRunLoopWakeUp(rl);

    /* g_main_context_wakeup(gmc); */

    return 0;
  }
  else {
    su_msg_destroy(rmsg);
    return -1;
  }
}

/** @internal
 * Execute the messages in the incoming queue until the queue is empty..
 *
 * @param self - pointer to a port object
 *
 * @retval 0 if there was a signal to handle, 
 * @retval -1 otherwise.
 */
static
int su_port_osx_getmsgs(su_port_t *self)
{
  enter;
  
  if (self && self->sup_head) {
    su_root_t *root;
    su_msg_f f;

    SU_PORT_OSX_INCREF(self, "su_port_osx_getmsgs");
    SU_PORT_OSX_LOCK(self, "su_port_osx_getmsgs");

    while (self->sup_head) {
      su_msg_t *msg = self->sup_head;
      self->sup_head = msg->sum_next;
      if (!self->sup_head) {
	assert(self->sup_tail == &msg->sum_next);
	self->sup_tail = &self->sup_head;
      }
      root = msg->sum_to->sut_root;
      f = msg->sum_func;
      SU_PORT_OSX_UNLOCK(self, "su_port_osx_getmsgs");
      if (f) 
	f(su_root_magic(root), &msg, msg->sum_data);
      if (msg && msg->sum_report)
	su_msg_delivery_report(&msg);
      else
	su_msg_destroy(&msg);
      SU_PORT_OSX_LOCK(self, "su_port_osx_getmsgs");
    }

    SU_PORT_OSX_UNLOCK(self, "su_port_osx_getmsgs");
    SU_PORT_OSX_DECREF(self, "su_port_osx_getmsgs");

    return 0;
  }
  else
    return -1;
}

/** @internal
 *
 *  Register a @c su_wait_t object. The wait object, a callback function and
 *  a argument pointer is stored in the port object.  The callback function
 *  will be called when the wait object is signaled.
 *
 *  Please note if identical wait objects are inserted, only first one is
 *  ever signalled.
 * 
 * @param self	     pointer to port
 * @param root	     pointer to root object
 * @param waits	     pointer to wait object
 * @param callback   callback function pointer
 * @param arg	     argument given to callback function when it is invoked
 * @param priority   relative priority of the wait object 
 *              (0 is normal, 1 important, 2 realtime)
 * 
 * @return
 *   The function @su_port_osx_register returns nonzero index of the wait object, 
 *   or -1 upon an error.  */
int su_port_osx_register(su_port_t *self,
		       su_root_t *root, 
		       su_wait_t *wait, 
		       su_wakeup_f callback,
		       su_wakeup_arg_t *arg,
		       int priority)
{
  unsigned i, j, I;
  unsigned n;
  CFRunLoopRef rl;

  enter;
  
  assert(SU_PORT_OSX_OWN_THREAD(self));

  n = self->sup_n_waits;

  if (n >= self->sup_size_waits) {
    /* Reallocate size arrays */
    int size;
    unsigned *indices;
    su_wait_t *waits;
    su_wakeup_f *wait_cbs;
    su_wakeup_arg_t **wait_args;
    su_root_t **wait_tasks;

    if (self->sup_size_waits == 0)
      size = SU_MIN_WAITS;
    else 
      size = 2 * self->sup_size_waits;

    indices = realloc(self->sup_indices, size * sizeof(*indices));
    if (indices) {
      self->sup_indices = indices;

      for (i = self->sup_size_waits; i < size; i++)
	indices[i] = UINT_MAX;
    }

    rl = CFRunLoopGetCurrent();

    for (i = 0; i < self->sup_n_waits; i++)
      CFRunLoopRemoveSource(rl, self->sup_waits[i].w_source,
			    kCFRunLoopDefaultMode);
    /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[i]); */
      
    waits = realloc(self->sup_waits, size * sizeof(*waits));
    if (waits)
      self->sup_waits = waits;

    for (i = 0; i < self->sup_n_waits; i++)
      CFRunLoopAddSource(rl, waits[i].w_source, kCFRunLoopDefaultMode);
    /* g_source_add_poll(self->sup_source, (GPollFD*)&waits[i]); */
      
    wait_cbs = realloc(self->sup_wait_cbs, size * sizeof(*wait_cbs));
    if (wait_cbs)
      self->sup_wait_cbs = wait_cbs;

    wait_args = realloc(self->sup_wait_args, size * sizeof(*wait_args));
    if (wait_args)
      self->sup_wait_args = wait_args;

    /* Add sup_wait_roots array, if needed */
    wait_tasks = realloc(self->sup_wait_roots, size * sizeof(*wait_tasks));
    if (wait_tasks) 
      self->sup_wait_roots = wait_tasks;

    if (!(indices && waits && wait_cbs && wait_args && wait_tasks)) {
      return -1;
    }

    self->sup_size_waits = size;
  }

  self->sup_n_waits++;

  if (priority > 0) {
    /* Insert */
    for (; n > 0; n--) {
      CFRunLoopRemoveSource(rl, self->sup_waits[n-1].w_source, kCFRunLoopDefaultMode);
      /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[n-1]); */
      self->sup_waits[n] = self->sup_waits[n-1];
      CFRunLoopAddSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
      /* g_source_add_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */
      self->sup_wait_cbs[n] = self->sup_wait_cbs[n-1];
      self->sup_wait_args[n] = self->sup_wait_args[n-1];
      self->sup_wait_roots[n] = self->sup_wait_roots[n-1];	
    }
  }
  else {
    /* Append - no need to move anything */
  }

  self->sup_waits[n] = *wait;
  CFRunLoopAddSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
  /* g_source_add_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */
  self->sup_wait_cbs[n] = callback;
  self->sup_wait_args[n] = arg;
  self->sup_wait_roots[n] = root;

  I = self->sup_max_index;

  for (i = 0; i < I; i++)  
    if (self->sup_indices[i] == UINT_MAX)
      break;
    else if (self->sup_indices[i] >= n)
      self->sup_indices[i]++;

  if (i == I) 
    self->sup_max_index++;

  if (n + 1 < self->sup_n_waits)
    for (j = i; j < I; j++)
      if (self->sup_indices[j] != UINT_MAX &&
	  self->sup_indices[j] >= n)
	self->sup_indices[j]++;

  self->sup_indices[i] = n;

  self->sup_registers++;

  return i + 1;			/* 0 is failure */
}

/** Unregister a su_wait_t object.
 *  
 *  The function su_port_osx_unregister() unregisters a su_wait_t object. The
 *  wait object, a callback function and a argument are removed from the
 *  port object.
 * 
 * @param self     - pointer to port object
 * @param root     - pointer to root object
 * @param wait     - pointer to wait object
 * @param callback - callback function pointer (may be NULL)
 * @param arg      - argument given to callback function when it is invoked 
 *                   (may be NULL)
 * 
 * @return Nonzero index of the wait object, or -1 upon an error.
 */
int su_port_osx_unregister(su_port_t *self,
			 su_root_t *root, 
			 su_wait_t *wait,	
			 su_wakeup_f callback, /* XXX - ignored */
			 su_wakeup_arg_t *arg)
{
  unsigned n, N;
  unsigned i, I, j, *indices;
  CFRunLoopRef rl;

  enter;
  
  assert(self);
  assert(SU_PORT_OSX_OWN_THREAD(self));

  i = (unsigned)-1;
  N = self->sup_n_waits;
  I = self->sup_max_index;
  indices = self->sup_indices;

  rl = CFRunLoopGetCurrent();

  for (n = 0; n < N; n++) {
    if (SU_WAIT_CMP(wait[0], self->sup_waits[n]) != 0)
      continue;

    /* Found - delete it */
    if (indices[n] == n)
      i = n;
    else for (i = 0; i < I; i++)
      if (indices[i] == n)
	break;

    assert(i < I);

    indices[i] = UINT_MAX;

    CFRunLoopRemoveSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
    /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */

    self->sup_n_waits = N = N - 1;

    if (n < N)
      for (j = 0; j < I; j++)
	if (self->sup_indices[j] != UINT_MAX &&
	    self->sup_indices[j] > n)
	  self->sup_indices[j]--;
    
    for (; n < N; n++) {
      CFRunLoopRemoveSource(rl, self->sup_waits[n+1].w_source, kCFRunLoopDefaultMode);
      /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[n+1]); */
      self->sup_waits[n] = self->sup_waits[n+1];
      CFRunLoopAddSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
      /* g_source_add_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */
      self->sup_wait_cbs[n] = self->sup_wait_cbs[n+1];
      self->sup_wait_args[n] = self->sup_wait_args[n+1];
      self->sup_wait_roots[n] = self->sup_wait_roots[n+1];	  
    }

    i += 1;	/* 0 is failure */

    if (i == I)
      self->sup_max_index--;

    break;
  }

  self->sup_registers++;

  return (int)i;
}

/** Deregister a su_wait_t object.
 *  
 *  The function su_port_osx_deregister() deregisters a su_wait_t registrattion. 
 *  The wait object, a callback function and a argument are removed from the
 *  port object.
 * 
 * @param self     - pointer to port object
 * @param i        - registration index
 * 
 * @return Index of the wait object, or -1 upon an error.
 */
int su_port_osx_deregister(su_port_t *self, int i)
{
  unsigned j, n, N;
  unsigned I, *indices;
  su_wait_t wait[1];
  CFRunLoopRef rl;

  enter;
  
  assert(self);
  assert(SU_PORT_OSX_OWN_THREAD(self));

  if (i <= 0)
    return -1;

  N = self->sup_n_waits;
  I = self->sup_max_index;
  indices = self->sup_indices;

  assert(i < I + 1);

  n = indices[i - 1];

  if (n == UINT_MAX)
    return -1;

  self->sup_n_waits = N = N - 1;

  wait[0] = self->sup_waits[n];

  rl = CFRunLoopGetCurrent();
  CFRunLoopRemoveSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
  /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */

  if (n < N)
    for (j = 0; j < I; j++)
      if (self->sup_indices[j] != UINT_MAX &&
	  self->sup_indices[j] > n)
	self->sup_indices[j]--;

  for (; n < N; n++) {
    CFRunLoopRemoveSource(rl, self->sup_waits[n + 1].w_source, kCFRunLoopDefaultMode);
    /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[n + 1]); */
    self->sup_waits[n] = self->sup_waits[n+1];
    CFRunLoopAddSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
    /* g_source_add_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */
    self->sup_wait_cbs[n] = self->sup_wait_cbs[n+1];
    self->sup_wait_args[n] = self->sup_wait_args[n+1];
    self->sup_wait_roots[n] = self->sup_wait_roots[n+1];	  
  }

  indices[i - 1] = UINT_MAX;

  if (i == I)
    self->sup_max_index--;

  su_wait_destroy(wait);

  self->sup_registers++;

  return (int)i;
}

/** @internal
 * Unregister all su_wait_t objects.
 *
 * The function su_port_osx_unregister_all() unregisters all su_wait_t objects
 * associated with given root object destroys all queued timers.
 * 
 * @param  self     - pointer to port object
 * @param  root     - pointer to root object
 * 
 * @return Number of wait objects removed.
 */
int su_port_osx_unregister_all(su_port_t *self, 
			   su_root_t *root)
{
  unsigned i, j;
  unsigned         n_waits;
  su_wait_t       *waits;
  su_wakeup_f     *wait_cbs;
  su_wakeup_arg_t**wait_args;
  su_root_t      **wait_roots;
  CFRunLoopRef rl;

  enter;
  
  assert(SU_PORT_OSX_OWN_THREAD(self));

  n_waits    = self->sup_n_waits;
  waits      = self->sup_waits; 
  wait_cbs   = self->sup_wait_cbs; 
  wait_args  = self->sup_wait_args;
  wait_roots = self->sup_wait_roots; 

  rl = CFRunLoopGetCurrent();
  
  for (i = j = 0; (unsigned)i < n_waits; i++) {
    if (wait_roots[i] == root) {
      /* XXX - we should free all resources associated with this */
      CFRunLoopRemoveSource(rl, waits[i].w_source, kCFRunLoopDefaultMode);
      /* g_source_remove_poll(self->sup_source, (GPollFD*)&waits[i]); */
      continue;
    }
    if (i != j) {
      CFRunLoopRemoveSource(rl, waits[i].w_source, kCFRunLoopDefaultMode);
      /* g_source_remove_poll(self->sup_source, (GPollFD*)&waits[i]); */
      waits[j] = waits[i];
      wait_cbs[j] = wait_cbs[i];
      wait_args[j] = wait_args[i];
      wait_roots[j] = wait_roots[i];
      CFRunLoopAddSource(rl, waits[i].w_source, kCFRunLoopDefaultMode);
      /* g_source_add_poll(self->sup_source, (GPollFD*)&waits[i]); */
    }
    j++;
  }
  
  self->sup_n_waits = j;
  self->sup_registers++;

  return n_waits - j;
}

/**Set mask for a registered event. @internal
 *
 * The function su_port_osx_eventmask() sets the mask describing events that can
 * signal the registered callback.
 *
 * @param port   pointer to port object
 * @param index  registration index
 * @param socket socket
 * @param events new event mask
 *
 * @retval 0 when successful,
 * @retval -1 upon an error.
 */
int su_port_osx_eventmask(su_port_t *self, int index, int socket, int events)
{
  unsigned n;
  int retval;
  CFRunLoopRef rl;

  enter;
  
  assert(self);
  assert(SU_PORT_OSX_OWN_THREAD(self));
  assert(index <= self->sup_max_index);

  if (index <= 0 || index > self->sup_max_index)
    return -1;

  n = self->sup_indices[index - 1];

  if (n == UINT_MAX)
    return -1;

  rl = CFRunLoopGetCurrent();
  CFRunLoopRemoveSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
  /* g_source_remove_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */

  retval = su_wait_mask(&self->sup_waits[n], socket, events);

  CFRunLoopAddSource(rl, self->sup_waits[n].w_source, kCFRunLoopDefaultMode);
  /* g_source_add_poll(self->sup_source, (GPollFD*)&self->sup_waits[n]); */

  return retval;
}

static
int su_port_osx_multishot(su_port_t *self, int multishot)
{
  if (multishot == -1)
    return 1;
  else if (multishot == 0 || multishot == 1)
    return 1;			/* Always enabled */
  else 
    return (errno = EINVAL), -1;
}

/** @internal Enable threadsafe operation. */
static
int su_port_osx_threadsafe(su_port_t *port)
{
  return su_home_threadsafe(port->sup_home);
}


/** @internal Main loop.
 * 
 * The function @c su_port_osx_run() runs the main loop
 * 
 * The function @c su_port_osx_run() runs until @c su_port_osx_break() is called
 * from a callback.
 * 
 * @param self     pointer to root object
 * */
void su_port_osx_run(su_port_t *self)
{
  /* GMainContext *gmc; */
  /* GMainLoop *gml; */
  CFRunLoopRef rl;

  rl = CFRunLoopGetCurrent();

  enter;

  self->sup_main_loop = rl;
  CFRunLoopRun();
  self->sup_main_loop = NULL;

#if 0  
  gmc = g_source_get_context(self->sup_source);
  if (gmc && g_main_context_acquire(gmc)) {
    gml = g_main_loop_new(gmc, TRUE);
    self->sup_main_loop = gml;
    g_main_loop_run(gml);
    g_main_loop_unref(gml);
    self->sup_main_loop = NULL;
    g_main_context_release(gmc);
  }
#endif
}

/** @internal
 * The function @c su_port_osx_break() is used to terminate execution of @c
 * su_port_osx_run(). It can be called from a callback function.
 * 
 * @param self     pointer to port
 * 
 */
void su_port_osx_break(su_port_t *self)
{
  enter;
  
  if (self->sup_main_loop)
    CFRunLoopStop(self->sup_main_loop);
    /* g_main_loop_quit(self->sup_main_loop); */
}

/** @internal Block until wait object is signaled or timeout.
 *
 * This function waits for wait objects and the timers associated with 
 * the root object.  When any wait object is signaled or timer is
 * expired, it invokes the callbacks. 
 * 
 *   This function returns when a callback has been invoked or @c tout
 *   milliseconds is elapsed. 
 *
 * @param self     pointer to port
 * @param tout     timeout in milliseconds
 * 
 * @Return
 *   Milliseconds to the next invocation of timer, or @c SU_WAIT_FOREVER if
 *   there are no active timers.
 */
su_duration_t su_port_osx_step(su_port_t *self, su_duration_t tout)
{
  /* GMainContext *gmc; */
  CFRunLoopRef rl;
  CFStringRef mode = CFSTR("MyCustomMode");
  int ret, timeout = tout > INT32_MAX ? INT32_MAX : tout;
  CFAbsoluteTime start, soon, next;

  enter;

  rl = CFRunLoopGetCurrent();

  if (!rl)
    return -1;

  if (CFRunLoopIsWaiting(rl) == FALSE)
    CFRunLoopWakeUp(rl);

  if (tout < timeout)
    timeout = tout;

  start = CFAbsoluteTimeGetCurrent();
  for (;;) {
    /* Check how long to run this loop */
    if (CFAbsoluteTimeGetCurrent() >= start + timeout)
      return SU_WAIT_TIMEOUT;
    
    /* Run loop with only one pass, indicate if a source was processed */
    ret = CFRunLoopRunInMode(kCFRunLoopDefaultMode,
			     0,
			     TRUE);

    if (ret == kCFRunLoopRunHandledSource)
      break;
  }

  soon = CFRunLoopGetNextTimerFireDate(rl, kCFRunLoopDefaultMode);

  return (next = soon - CFAbsoluteTimeGetCurrent()) > 0 ? next : SU_WAIT_FOREVER;
  
#if 0
  if (gmc && g_main_context_acquire(gmc)) {
    gint priority = G_MAXINT;
    if (g_main_context_prepare(gmc, &priority)) {
      g_main_context_dispatch(gmc);
    } else {
      gint timeout = tout > G_MAXINT ? G_MAXINT : tout;
      gint i, n = 0;
      GPollFD *fds = NULL;

      priority = G_MAXINT;

      n = g_main_context_query(gmc, priority, &timeout, fds, n);
      if (n > 0) {
	fds = g_alloca(n * (sizeof *fds));
	n = g_main_context_query(gmc, priority, &timeout, fds, n);	
      }

      if (tout < timeout)
	timeout = tout;

      i = su_wait((su_wait_t *)fds, n, timeout);

      if (g_main_context_check(gmc, priority, fds, n))
	g_main_context_dispatch(gmc);
    }
    g_main_context_release(gmc);
  }
#endif

  return 0;
}


/** @internal
 * Checks if the calling thread owns the port object.
 *
 * @param self pointer to a port object
 *
 * @retval true (nonzero) if the calling thread owns the port,
 * @retval false (zero) otherwise.
 */
int su_port_osx_own_thread(su_port_t const *self)
{
  return self == NULL || SU_PORT_OSX_OWN_THREAD(self);
}

#if 0
/** @internal
 *  Prints out the contents of the port.
 *
 * @param self pointer to a port
 * @param f    pointer to a file (if @c NULL, uses @c stdout).
 */
void su_port_osx_dump(su_port_t const *self, FILE *f)
{
  int i;
#define IS_WAIT_IN(x) (((x)->events & SU_WAIT_IN) ? "IN" : "")
#define IS_WAIT_OUT(x) (((x)->events & SU_WAIT_OUT) ? "OUT" : "")
#define IS_WAIT_ACCEPT(x) (((x)->events & SU_WAIT_ACCEPT) ? "ACCEPT" : "")

  if (f == NULL)
    f = stdout;

  fprintf(f, "su_port_t at %p:\n", self);
  fprintf(f, "\tport is%s running\n", self->sup_running ? "" : "not ");
  fprintf(f, "\tport tid %p\n", (void *)self->sup_tid);
  fprintf(f, "\t%d wait objects\n", self->sup_n_waits);
  for (i = 0; i < self->sup_n_waits; i++) {
    
  }
}

#endif

/* =========================================================================
 * Pre-poll() callback
 */

int su_port_osx_add_prepoll(su_port_t *port,
			su_root_t *root, 
			su_prepoll_f *callback, 
			su_prepoll_magic_t *magic)
{
#if 0
  if (port->sup_prepoll)
    return -1;

  port->sup_prepoll = callback;
  port->sup_pp_magic = magic;
  port->sup_pp_root = root;

  return 0;
#else
  return -1;
#endif
}

int su_port_osx_remove_prepoll(su_port_t *port,
			   su_root_t *root)
{
#if 0
  if (port->sup_pp_root != root)
    return -1;

  port->sup_prepoll = NULL;
  port->sup_pp_magic = NULL;
  port->sup_pp_root = NULL;

  return 0;
#else
  return -1;
#endif
}

/* =========================================================================
 * Timers
 */

static
su_timer_t **su_port_osx_timers(su_port_t *self)
{
  return &self->sup_timers;
}
