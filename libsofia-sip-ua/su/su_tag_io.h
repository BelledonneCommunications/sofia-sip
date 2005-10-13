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

#ifndef SU_TAG_IO_H /** Defined when su_tag_io.h has been included */
#define SU_TAG_IO_H 


/**@SU_TAG
 * @file su_tag_io.h
 * @brief I/O interface for tag lists
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Wed Feb 21 12:10:06 2001 ppessi
 * @date Last modified: Wed Jul 20 20:35:58 2005 kaiv
 */

#ifndef SU_TAG_H
#include <su_tag.h>
#endif

void tl_print(FILE *f, char const *title, tagi_t const lst[]);

#endif
