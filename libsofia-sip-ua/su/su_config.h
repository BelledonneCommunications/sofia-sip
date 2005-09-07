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

#ifndef SU_CONFIG_H /** Defined when su_config.h has been included. */
#define SU_CONFIG_H "$Id: su_config.h,v 1.1.1.1 2005/07/20 20:35:57 kaiv Exp $"
/**@file su_config.h 
 * 
 * @b su library configuration
 * 
 * This file includes an appropriate <su_configure*.h> include file.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu Mar 18 19:40:51 1999 pessi
 * $Date: 2005/07/20 20:35:57 $
 */

#if !defined(_WIN32)
#  include <su_configure.h>
#  define SU_DLL
#else
#  include <su_configure_win32.h>
#  if !defined(_DLL)
#    define SU_DLL  
#  elif defined(SU_EXPORTS)
#    define SU_DLL __declspec(dllexport)
#  else
#    define SU_DLL __declspec(dllimport)
#  endif
#endif

#if defined(__GNUC__)
#if __GNUC__ < 3 && (!defined(__GNUC_MINOR__) || __GNUC_MINOR__ < 96)
#define __malloc__		/* avoid spurious warnigns */
#endif
#elif !defined(__attribute__)
#  define __attribute__(x) 
#endif

#endif /* SU_CONFIG_H */
