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

#ifndef URL_DLL_H /** Defined when url_dll.h has been included. */
#define URL_DLL_H
/**@file url_dll.h
 * Define declaration specification for exporting things from @b url.dll.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *  
 * @date Created: Thu Jan 30 12:36:06 2003 ppessi
 * 
 * @date Last modified: Fri Aug 12 10:42:44 2005 ppessi
 */

#ifndef URL_DLL
#ifndef WIN32
#define URL_DLL
#else
#define URL_DLL __declspec(dllimport)
#endif
#endif

#endif /* !defined URL_DLL_H */

