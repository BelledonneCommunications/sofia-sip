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

#ifndef SIP_EXTENSIONS_H
/** Defined when @b <sip_extensions.h> has been included. */
#define SIP_EXTENSIONS_H \
"$Id: sip_extensions.h,v 1.1.1.1 2005/07/20 20:35:41 kaiv Exp $"

/**@file sip_extensions.h
 * @brief Macros extending SIP objects
 *
 * This extension method has been obsoleted.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Mon Jun 19 21:58:00 2000 ppessi
 * 
 */

#ifndef SIP_METHODS_EXTENSIONS
/** Declare new SIP methods. */
#define SIP_METHODS_EXTENSIONS
#endif

#ifndef SIP_HDR_EXTENSIONS
/** Declare new SIP header IDs. */
#define SIP_HDR_EXTENSIONS
#endif

#ifndef SIP_EXTENSIONS_T
/** Declare new SIP headers in sip_t structure. */
#define SIP_EXTENSIONS_T
#endif

#ifndef SIP_EXTENSIONS_U
/** Declare new SIP headers in sip_header_t union. */
#define SIP_EXTENSIONS_U
#endif

#endif
