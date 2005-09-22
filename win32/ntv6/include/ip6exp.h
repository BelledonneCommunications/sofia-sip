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
// Public definitions exported to transport layer and application
// software for Internet Protocol Version 6.
//
// Things we want visible to both user and kernel, yet aren't part of the
// official specifications (i.e. are implementation specific) go here.
//


#ifndef IP6EXP_INCLUDED
#define IP6EXP_INCLUDED 1

#include <ip6addr.h>

//
// Kernel code mostly uses the IPv6Addr typedef
// because it better fits NT naming conventions.
//
typedef struct in6_addr IPv6Addr;

//
// The IP APIs return status codes of this type.
//
typedef unsigned long IP_STATUS;


//
// IP_STATUS codes returned from IP APIs.
//
#define IP_STATUS_BASE              11000

#define IP_SUCCESS                  0
#define IP_BUF_TOO_SMALL            (IP_STATUS_BASE + 1)
#define IP_DEST_NO_ROUTE            (IP_STATUS_BASE + 2)
#define IP_DEST_ADDR_UNREACHABLE    (IP_STATUS_BASE + 3)
#define IP_DEST_PROHIBITED          (IP_STATUS_BASE + 4)
#define IP_DEST_PORT_UNREACHABLE    (IP_STATUS_BASE + 5)
#define IP_NO_RESOURCES             (IP_STATUS_BASE + 6)
#define IP_BAD_OPTION               (IP_STATUS_BASE + 7)
#define IP_HW_ERROR                 (IP_STATUS_BASE + 8)
#define IP_PACKET_TOO_BIG           (IP_STATUS_BASE + 9)
#define IP_REQ_TIMED_OUT            (IP_STATUS_BASE + 10)
#define IP_BAD_REQ                  (IP_STATUS_BASE + 11)
#define IP_BAD_ROUTE                (IP_STATUS_BASE + 12)
#define IP_HOP_LIMIT_EXCEEDED       (IP_STATUS_BASE + 13)
#define IP_REASSEMBLY_TIME_EXCEEDED (IP_STATUS_BASE + 14)
#define IP_PARAMETER_PROBLEM        (IP_STATUS_BASE + 15)
#define IP_OPTION_TOO_BIG           (IP_STATUS_BASE + 17)
#define IP_BAD_DESTINATION          (IP_STATUS_BASE + 18)
//  was IP_DEST_NOT_NEIGHBOR        (IP_STATUS_BASE + 19)
#define IP_DEST_UNREACHABLE         (IP_STATUS_BASE + 20)
#define IP_TIME_EXCEEDED            (IP_STATUS_BASE + 21)
#define IP_BAD_HEADER               (IP_STATUS_BASE + 22)
#define IP_UNRECOGNIZED_NEXT_HEADER (IP_STATUS_BASE + 23)
#define IP_ICMP_ERROR               (IP_STATUS_BASE + 24)

//
// The next group are status codes passed up on status indications to
// transport layer protocols.
//
#define IP_ADDR_DELETED             (IP_STATUS_BASE + 40)
#define IP_SPEC_MTU_CHANGE          (IP_STATUS_BASE + 41)
#define IP_MTU_CHANGE               (IP_STATUS_BASE + 42)
#define IP_UNLOAD                   (IP_STATUS_BASE + 43)
#define IP_ADDR_ADDED               (IP_STATUS_BASE + 44)

#define IP_GENERAL_FAILURE          (IP_STATUS_BASE + 50)
#define MAX_IP_STATUS               IP_GENERAL_FAILURE
#define IP_PENDING                  (IP_STATUS_BASE + 255)

//
// Parameter for AO_OPTION_ADD_MCAST and AO_OPTION_DEL_MCAST
// TDI set-information call and for the IPV6_JOIN/LEAVE_GROUP
// socket options.
//
typedef struct ipv6_mreq {
    IPv6Addr ipv6mr_multiaddr;      // IPv6 multicast address.
    unsigned int ipv6mr_interface;  // Interface index.
} IPV6_MREQ;

#endif // IP6EXP_INCLUDED
