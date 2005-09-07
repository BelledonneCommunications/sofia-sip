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

#ifndef AUTH_DLL_H /** Defined when @b <auth_dll.h> has been included. */
#define AUTH_DLL_H "$Id: auth_dll.h,v 1.1.1.1 2005/07/20 20:35:21 kaiv Exp $"

/**Define declaration specifications for exporting things from @b iptsec.dll.
 */
#if !defined(WIN32)
#define AUTH_DLL
#elif defined(IPTSEC_EXPORTS)
#define AUTH_DLL  __declspec(dllexport)
#else
#define AUTH_DLL __declspec(dllimport)
#endif

#endif 
