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

#ifndef RC4_H /** Defined when rc4.h has been included. */
#define RC4_H

/**@file rc4.h
 * @brief 
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *  
 * @date Created: Sun Jun  9 14:32:58 1996 ppessi
 */

/** Byte. */
typedef unsigned char rc4_u8;

/** RC4 context. 
 * 
 * The RC4 context is accessed and modified through rc4_init() and rc4()
 * functions only.
 */
typedef struct {      
  rc4_u8 rc4_i;        
  rc4_u8 rc4_j;
  rc4_u8 rc4_array[256];       
} rc4_t;

/** Key RC4 context. */
void rc4_init(const void *seed, int seed_len, rc4_t *state);

/** Generate RC4 stream. */ 
void rc4(void *buffer, int len, rc4_t *state);

#endif /* !defined RC4_H */
