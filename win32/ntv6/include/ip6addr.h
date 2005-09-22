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
// Abstract:
//
// Defines the IPv6 address structure.
//

#ifndef IP6ADDR_INCLUDED
#define IP6ADDR_INCLUDED 1

//
// Basic types.
// REVIEW: These really belong somewhere else.
//
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef unsigned int uint;
typedef unsigned __int64 uint64;
typedef __int64 int64;


//
// An IPv6 address is 128 bits long.
//
struct in6_addr {
    union {
        uchar Byte[16];
        ushort Word[8];
        ulong DWord[4];
        uint64 QWord[2];
    } u;
};

//
// Defines to match RFC 2553.
//
#define _S6_un     u
#define _S6_u8     Byte
#define _S6_u32    DWord
#define _S6_u64    QWord
#define s6_addr    _S6_un._S6_u8

//
// Defines for our implementation.
//
#define s6_bytes   u.Byte
#define s6_words   u.Word
#define s6_dwords  u.DWord
#define s6_qwords  u.QWord

#endif // IP6ADDR_INCLUDED
