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

// -*- mode: C++; tab-width: 4; indent-tabs-mode: nil -*- (for GNU Emacs)
//
// Copyright (c) 1985-2000 Microsoft Corporation
//
// This file is part of the Microsoft Research IPv6 Network Protocol Stack.
// You should have received a copy of the Microsoft End-User License Agreement
// for this software along with this release; see the file "license.txt".
// If not, please see http://www.research.microsoft.com/msripv6/license.htm,
// or write to Microsoft Research, One Microsoft Way, Redmond, WA 98052-6399.
//

#include <su.h>
#define ulong ULONG

//* inet6_addr - Converts a string into a binary IPv6 address.
//
//  This function is NOT defined in RFC 2553.
//  Use inet_pton (below) if you want to be portable.
//
//  Returns TRUE if successful, FALSE otherwise.
//
int WSAAPI
inet6_addr(
    const char *InputString,   // IPv6 address (in "colon" representation).
    struct in6_addr *Address)  // Where to return binary representation.
{
#if SU_HAVE_IN6
    struct sockaddr_in6 sin6;
    int AddressLength = sizeof sin6;

    sin6.sin6_family = AF_INET6;  // Shouldn't be required but is.

    if ((WSAStringToAddress((char *)InputString,
                            AF_INET6,
                            NULL,       // LPWSAPROTOCOL_INFO
                            (struct sockaddr *) &sin6,
                            &AddressLength)
         == SOCKET_ERROR) ||
        (sin6.sin6_port != 0) ||
        (sin6.sin6_scope_id != 0))
        return FALSE;

    *Address = sin6.sin6_addr;
    return TRUE;
#else
    return FALSE;
#endif
}

//* inet_pton - Converts an address from a string to binary.
//
//  As specified in RFC 2553, Section 6.6.
//
//  Returns 1 upon success, 0 upon invalid string,
//  and -1 for unknown address family.
//
int WSAAPI
inet_pton(
    int AddressFamily,        // Address family to which the address belongs.
    const char *InputString,  // Address (numeric string) to convert.
    void *Address)            // Where to return the binary address.
{
    //
    // REVIEW: It's not specified that we should even bother to perform
    // REVIEW: this check, much less what the error should be if it fails.
    //
    if (Address == NULL)
        return 0;

    if (AddressFamily == AF_INET) {
        //
        // IPv4 address.
        //

        //
        // REVIEW: The spec says only "ddd.ddd.ddd.ddd" is to be accepted,
        // REVIEW: where ddd is a decimal number: 0-255.
        // BUGBUG: NT's inet_addr is more accepting, so we shouldn't use it.
        //
        if ((*(ulong *)Address = inet_addr(InputString)) == INADDR_NONE) {
            return 0;
        }

#if SU_HAVE_IN6
    } else if (AddressFamily == AF_INET6) {
        //
        // IPv6 address.
        //
        struct sockaddr_in6 sin6;
        int AddressLength = sizeof sin6;

        sin6.sin6_family = AF_INET6;  // Shouldn't be required but is.
            
        if ((WSAStringToAddress((char *)InputString, AF_INET6, NULL,
                                (struct sockaddr *)&sin6, &AddressLength)
             == SOCKET_ERROR) ||
            (sin6.sin6_port != 0) ||
            (sin6.sin6_scope_id != 0)) {
            return 0;
        }

        *(struct in6_addr *)Address = sin6.sin6_addr;
#endif

    } else {
        //
        // Address type not supported.
        //
        SetLastError(WSAEAFNOSUPPORT);
        return -1;
    }

    return 1;
}
