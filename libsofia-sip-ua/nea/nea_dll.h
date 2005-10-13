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

#ifndef NEA_DLL_H /** Defined when <nea_dll.h> has been included. */
#define NEA_DLL_H

/**@file nea_dll.h
 *
 * Define declaration specifications for exporting things from @b nea.dll.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Fri Feb 22 15:57:00 2002 ppessi
 * @date Last modified: Wed Jul 20 20:35:27 2005 kaiv
 */

#if !defined(WIN32)
#define NEA_DLL
#elif defined(NEA_EXPORTS)
#define NEA_DLL __declspec(dllexport)
#else
#define NEA_DLL __declspec(dllimport)
#endif

#endif  /* !defined(NEA_DLL_H) */
