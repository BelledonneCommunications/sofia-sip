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

#ifndef MSG_DLL_H /** Defined when msg_dll.h has been included. */
#define MSG_DLL_H
/**@ingroup msg
 * @file msg_dll.h
 *
 * Define declaration specification for exporting things from @b msg.dll.
 *
 */

#ifndef MSG_DLL
#ifndef WIN32
/** Attribute for symbols exported from msg library */
#define MSG_DLL
#else
#define MSG_DLL __declspec(dllimport)
#endif
#endif

/** Attribute for msg test symbols */
#define MSG_TEST_DLL

#endif /** !defined(MSG_DLL_H) */
