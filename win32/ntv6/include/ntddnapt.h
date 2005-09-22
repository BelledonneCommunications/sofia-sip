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
// Network Address Protocol Translator (NAPT) definitions.
//

#ifndef __NTDDNAPT_INCLUDE__
#define __NTDDNAPT_INCLUDE__ 1

//
// Names for accessing the Napt device from NT and Win32.
//
#define DD_NAPT_DEVICE_NAME L"\\Device\\Napt"
#define WIN_NAPT_LINK_NAME L"\\??\\Napt"
#define WIN_NAPT_DEVICE_NAME L"\\\\.\\Napt"


//
// Data structure used for the mapping ioctls.
//
typedef struct NaptMapping {
    struct in6_addr ip6addr;
    in_addr ip4addr;
} NaptMapping;

//
// IOCTL to add a mapping.
//
#define IOCTL_NAPT_ADD_MAPPING                \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 1,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)

//
// IOCTL to delete a mapping.
//
#define IOCTL_NAPT_DEL_MAPPING                \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 2,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)

//
// IOCTLs to read existing mappings.
//
#define IOCTL_NAPT_GET_IP6TOIP4_MAPPINGS      \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 3,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)

#define IOCTL_NAPT_GET_IP4TOIP6_MAPPINGS      \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 4,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)


//
// Data structure used for the filtering ioctls.
//
typedef struct NaptIP4Filter {
    in_addr lower;
    in_addr upper;
} NaptIP4Filter;

#define IOCTL_NAPT_ADD_IP4FILTER              \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 5,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)

#define IOCTL_NAPT_DEL_IP4FILTER              \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 6,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)


#define IOCTL_NAPT_LIST_IP4FILTERS            \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 7,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)

#define IOCTL_NAPT_READ_REGISTRY              \
        CTL_CODE(FILE_DEVICE_DISK,            \
                 8,                           \
                 METHOD_BUFFERED,             \
                 FILE_ANY_ACCESS)

#endif  // __NTDDNAPT_INCLUDE__
