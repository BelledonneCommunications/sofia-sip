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

#ifndef SU_SOURCE_H /** Defined when su_source.h has been included. */
#define SU_SOURCE_H

/**
 * @file su_source.h
 * @brief 
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *  
 * @date Created: Thu Mar  4 19:58:50 2004 ppessi
 * 
 * @date Last modified: Wed Jul 20 20:35:58 2005 kaiv
 */

#ifndef SU_WAIT_H
#include <su_wait.h>
#endif
#ifndef __GLIB_H__
#include <glib.h>
#endif

su_root_t *su_root_source_create(su_root_magic_t *);
GSource *su_root_source(su_root_t *);

#endif /* !defined SU_SOURCE_H */
