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

#ifndef SIP_DLL_H /** Defined when @b <sip_dll.h> has been included. */
#define SIP_DLL_H "$Id: sip_dll.h,v 1.1.1.1 2005/07/20 20:35:41 kaiv Exp $"

/**@file sip_dll.h
 *
 * Define declaration specification for exporting things from @b sip.dll.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 */

#if !defined(WIN32)
/** Attribute for symbols exported from sip() library */
#define SIP_DLL
#elif defined(SIP_EXPORTS)
#define SIP_DLL      __declspec(dllexport)
#else
#define SIP_DLL     __declspec(dllimport)
#endif

#endif 
