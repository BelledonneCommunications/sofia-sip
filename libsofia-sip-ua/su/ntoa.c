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
#include <windows.h>
#include <winsock2.h>
//#include <ws2ip6.h>


//* inet6_ntoa - Converts a binary IPv6 address into a string.
//
//  This function is NOT defined in RFC 2553.
//  Use inet_ntop (below) if you want to be portable.
//
//  Returns a pointer to the output string.
//
char * WSAAPI
inet6_ntoa(const struct in6_addr *Address)
{
    static char buffer[128];       // REVIEW: Use 128 or INET6_ADDRSTRLEN?
    DWORD buflen = sizeof buffer;
    struct sockaddr_in6 sin6;

    memset(&sin6, 0, sizeof sin6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = *Address;

    if (WSAAddressToString((struct sockaddr *) &sin6,
                           sizeof sin6,
                           NULL,       // LPWSAPROTOCOL_INFO
                           buffer,
                           &buflen) == SOCKET_ERROR)
        strcpy(buffer, "<invalid>");

    return buffer;
}


//* inet_ntop - Converts a binary address into a string.
//
//  As specified in RFC 2553, Section 6.6.
//
//  Returns a pointer to the output string if successful, NULL otherwise.
//
const char * WSAAPI
inet_ntop(
    int AddressFamily,     // Address family to which the address belongs.
    const void *Address,   // Address (binary) to convert.
    char *OutputString,    // Where to return the output string.
    int OutputBufferSize)  // Size of above buffer.
{
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr *SocketAddress;
    int SocketAddressLength;

    //
    // All we do is insert the user's in*_addr into a sockaddr
    // and then let WSAAdressToString handle the rest.
    //
    if (OutputString != NULL) {
        if (AddressFamily == AF_INET) {
            //
            // IPv4 address.
            //
            memset(&sin, 0, sizeof sin);
            sin.sin_family = AF_INET;
            sin.sin_addr = *(struct in_addr *)Address;
            SocketAddress = (struct sockaddr *)&sin;
            SocketAddressLength = sizeof(sin);

        } else if (AddressFamily == AF_INET6) {
            //
            // IPv6 address.
            //
            memset(&sin6, 0, sizeof sin6);
            sin6.sin6_family = AF_INET6;
            sin6.sin6_addr = *(struct in6_addr *)Address;
            SocketAddress = (struct sockaddr *)&sin6;
            SocketAddressLength = sizeof(sin6);

        } else {
            //
            // Address type not supported.
            //
            SetLastError(WSAEAFNOSUPPORT);
            return NULL;
        }

        //
        // Do the actual lookup.  WSAAdressToString will check
        // that the OutputBufferSize is big enough.
        //
        if (WSAAddressToString(SocketAddress, SocketAddressLength,
                               NULL, OutputString,
                               &OutputBufferSize) == SOCKET_ERROR) {
            return NULL;
        }
    }

    return OutputString;
}
