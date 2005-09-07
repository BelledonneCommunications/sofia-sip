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

#ifndef SU_TYPES_H /** Defined when su_types.h has been included */
#define SU_TYPES_H "$Id: su_types.h,v 1.1.1.1 2005/07/20 20:35:59 kaiv Exp $"
/**@file su_types.h Basic integer types for @b su library.
 *
 * This include file provides <stdint.h> or <inttypes.h> types.
 *  
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @date Created: Thu Mar 18 19:40:51 1999 pessi
 * $Date: 2005/07/20 20:35:59 $
 */

#ifndef SU_CONFIG_H
#include "su_config.h"
#endif

#if SU_HAVE_STDINT
#include <stdint.h>
#elif SU_HAVE_INTTYPES
#include <inttypes.h>
#endif

#if SU_HAVE_SYS_TYPES
#include <sys/types.h>
#endif

#if SU_HAVE_STDINT || SU_HAVE_INTTYPES
#define SU_S64_T int64_t
#define SU_U64_T uint64_t
#define SU_S32_T int32_t
#define SU_U32_T uint32_t
#define SU_S16_T int16_t
#define SU_U16_T uint16_t
#define SU_S8_T  int8_t
#define SU_U8_T  uint8_t
#elif SU_HAVE_WIN32 || DOCUMENTATION_ONLY
/* Use macros defined in <su_configure_win32.h> */
/** Integer large enough for pointers */
typedef SU_INTPTR_T intptr_t;
/** 64-bit unsigned integer */ 
typedef SU_U64_T uint64_t;
/** 64-bit signed integer */   
typedef SU_S64_T int64_t;
/** 32-bit unsigned integer */ 
typedef SU_U32_T uint32_t;
/** 32-bit signed integer */   
typedef SU_S32_T int32_t;
/** 16-bit unsigned integer */ 
typedef SU_U16_T uint16_t;
/** 16-bit signed integer */   
typedef SU_S16_T int16_t;
/** 8-bit unsigned integer */  
typedef SU_U8_T  uint8_t;
/** 8-bit signed integer */    
typedef SU_S8_T  int8_t;
#else
#error "no integer types available."
#endif

#endif /* SU_TYPES_H */
