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

#ifndef SU_ERRNO_H /** Defined when su_errno.h has been included. */
#define SU_ERRNO_H

/**@file su_errno.h Errno handling
 *
 * Source-code compatibility with Windows (having separate errno for
 * socket library and C libraries).
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Dec 22 18:16:06 EET 2005 pessi
 */

#ifndef SU_CONFIG_H
#include "su_config.h"
#endif

#include <errno.h>

/** Return string describing su error code. */
char const *su_strerror(int e);

/** The latest su error. */
int su_errno(void);

/** Set the su error. */
int su_seterrno(int);

#if !SU_HAVE_WINSOCK
#define su_errno() (errno)
#define su_seterrno(n) ((errno = (n)), -1)
#endif

#endif
