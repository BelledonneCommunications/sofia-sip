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

#ifndef SU_ALLOC_H  /** Defined when su_alloc.h has been included. */
#define SU_ALLOC_H "$Id: su_alloc.h,v 1.1.1.1 2005/07/20 20:35:57 kaiv Exp $"

/**@ingroup su_alloc
 *
 * @file su_alloc.h Home-based memory management interface
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Aug 19 01:12:25 1999 ppessi
 * $Date: 2005/07/20 20:35:57 $
 */

#ifndef SU_CONFIG_H
#include <su_config.h>
#endif

#ifndef SU_HOME_T
#define SU_HOME_T struct su_home_s
#endif

#include <stdarg.h>

/** Memory home type. */
typedef SU_HOME_T su_home_t;
typedef struct su_block_s su_block_t;

/** Thread-locking function. @internal */
typedef void (su_alock_f)(int what);

/** Memory home structure */
struct su_home_s { 
  int         suh_size;
  su_block_t *suh_blocks;
  su_alock_f *suh_lock;
};

#define SU_HOME_INIT(obj) { sizeof (obj), 0 }

SU_DLL su_home_t *su_home_create(void)
     __attribute__((__malloc__));
SU_DLL void su_home_destroy(su_home_t *h);

SU_DLL int  su_home_init(su_home_t *h);
SU_DLL void su_home_deinit(su_home_t *h);

SU_DLL void su_home_preload(su_home_t *h, int n, int size);

SU_DLL void *su_home_clone(su_home_t *, int n)
     __attribute__((__malloc__));

SU_DLL void su_home_zap(su_home_t *);

SU_DLL int su_home_move(su_home_t *dst, su_home_t *src);

SU_DLL int su_home_threadsafe(su_home_t *home);

SU_DLL void su_home_check(su_home_t const *home);

SU_DLL int su_home_mutex_lock(su_home_t *home);

SU_DLL int su_home_mutex_unlock(su_home_t *home);

SU_DLL void *su_alloc(su_home_t *h, int size)
     __attribute__((__malloc__));
SU_DLL void *su_zalloc(su_home_t *h, int size)
     __attribute__((__malloc__));
SU_DLL void *su_salloc(su_home_t *h, int size)
     __attribute__((__malloc__));
SU_DLL void *su_realloc(su_home_t *h, void *data, int size)
     __attribute__((__malloc__));

SU_DLL char *su_strdup(su_home_t *home, char const *s)
     __attribute__((__malloc__));
SU_DLL char *su_strcat(su_home_t *home, char const *s1, char const *s2)
     __attribute__((__malloc__));
SU_DLL char *su_strndup(su_home_t *home, char const *s, int n)
     __attribute__((__malloc__));

SU_DLL char *su_sprintf(su_home_t *home, char const *fmt, ...)
     __attribute__ ((__malloc__, __format__ (printf, 2, 3)));

SU_DLL char *su_vsprintf(su_home_t *home, char const *fmt, va_list ap)
     __attribute__((__malloc__));

/* free an independent block */
SU_DLL void su_free(su_home_t *h, void *);		

/** Add a thread-locking function to the home. @internal */
SU_DLL int su_home_set_locker_(su_home_t *h, su_alock_f locker);

#endif /* ! defined(SU_ALLOC_H) */
