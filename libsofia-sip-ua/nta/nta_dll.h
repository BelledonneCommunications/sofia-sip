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

#ifndef NTA_DLL_H /** Defined when <nta_dll.h> has been included. */
#define NTA_DLL_H "$Id: nta_dll.h,v 1.1.1.1 2005/07/20 20:35:30 kaiv Exp $"

/**@file nta_dll.h
 *
 * Define declaration specifications for exporting things from @b nta.dll.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Fri Feb 22 15:57:00 2002 ppessi
 * $Date: 2005/07/20 20:35:30 $
 */
#if !defined(WIN32)
#define NTA_DLL
#elif defined(NTA_EXPORTS)
#define NTA_DLL __declspec(dllexport)
#else
#define NTA_DLL __declspec(dllimport)
#endif

#endif  /* !defined(NTA_DLL_H) */
