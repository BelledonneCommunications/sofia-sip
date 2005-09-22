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
// Per RFC 2553.
//
// This file contains IPv6 specific information for use
// by Winsock2 compatible applications.
//
// It also declares functionality exported from wship6.lib,
// an application helper library for IPv6.
//

#ifndef WS2IP6_INCLUDED
#define WS2IP6_INCLUDED 1

#include <ip6exp.h>

#ifdef _MSC_VER
#define WS2IP6_INLINE __inline
#else
#define WS2IP6_INLINE extern inline /* GNU style */
#endif

#ifdef __cplusplus
#define WS2IP6_EXTERN extern "C"
#else
#define WS2IP6_EXTERN extern
#endif

typedef struct in6_addr IN6_ADDR;
typedef struct in6_addr *PIN6_ADDR;
typedef struct in6_addr FAR *LPIN6_ADDR;

//
// Avoid introducing padding because sin6_addr includes a 64-bit member.
//
#include <packon.h>
struct sockaddr_in6 {
    ushort sin6_family;
    ushort sin6_port;
    ulong sin6_flowinfo;
    struct in6_addr sin6_addr;
    ulong sin6_scope_id;
};
#include <packoff.h>

typedef struct sockaddr_in6 SOCKADDR_IN6;
typedef struct sockaddr_in6 *PSOCKADDR_IN6;
typedef struct sockaddr_in6 FAR *LPSOCKADDR_IN6;

//
// Little helper functions to copy between SOCKADDR_IN6 and TDI_ADDRESS_IP6.
// Only enabled if TDI_ADDRESS_IP6 has been defined.
// By design, the two structures are identical except for sin6_family.
//
#ifdef TDI_ADDRESS_LENGTH_IP6
WS2IP6_INLINE void
CopyTDIFromSA6(TDI_ADDRESS_IP6 *To, SOCKADDR_IN6 *From)
{
    memcpy(To, &From->sin6_port, sizeof *To);
}

WS2IP6_INLINE void
CopySAFromTDI6(SOCKADDR_IN6 *To, TDI_ADDRESS_IP6 *From)
{
    To->sin6_family = AF_INET6;
    memcpy(&To->sin6_port, From, sizeof *From);
}
#endif

//
// Portable socket structure.
//

//
// Desired design of maximum size and alignment.
// These are implementation specific.
//
#define _SS_MAXSIZE 128                // Maximum size.
#define _SS_ALIGNSIZE (sizeof(int64))  // Desired alignment. 

//
// Definitions used for sockaddr_storage structure paddings design.
//
#define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof (short))
#define _SS_PAD2SIZE (_SS_MAXSIZE - (sizeof (short) + _SS_PAD1SIZE \
                                                    + _SS_ALIGNSIZE))

struct sockaddr_storage {
    short ss_family;               // Address family.
    char __ss_pad1[_SS_PAD1SIZE];  // 6 byte pad, this is to make
                                   // implementation specific pad up to
                                   // alignment field that follows explicit
                                   // in the data structure.
    int64 __ss_align;              // Field to force desired structure.
    char __ss_pad2[_SS_PAD2SIZE];  // 112 byte pad to achieve desired size;
                                   // _SS_MAXSIZE value minus size of
                                   // ss_family, __ss_pad1, and
                                   // __ss_align fields is 112.
};

WS2IP6_INLINE int
IN6_IS_ADDR_UNSPECIFIED(const struct in6_addr *a)
{
    return ((a->s6_dwords[0] == 0) &&
            (a->s6_dwords[1] == 0) &&
            (a->s6_dwords[2] == 0) &&
            (a->s6_dwords[3] == 0));
}

WS2IP6_INLINE int
IN6_IS_ADDR_LOOPBACK(const struct in6_addr *a)
{
    return ((a->s6_dwords[0] == 0) &&
            (a->s6_dwords[1] == 0) &&
            (a->s6_dwords[2] == 0) &&
            (a->s6_dwords[3] == htonl(1)));
}

WS2IP6_INLINE int
IN6_IS_ADDR_MULTICAST(const struct in6_addr *a)
{
    return (a->s6_bytes[0] == 0xff);
}

WS2IP6_INLINE int
IN6_IS_ADDR_LINKLOCAL(const struct in6_addr *a)
{
    return ((a->s6_bytes[0] == 0xfe) &&
            ((a->s6_bytes[1] & 0xc0) == 0x80));
}

WS2IP6_INLINE int
IN6_IS_ADDR_SITELOCAL(const struct in6_addr *a)
{
    return ((a->s6_bytes[0] == 0xfe) &&
            ((a->s6_bytes[1] & 0xc0) == 0xc0));
}

WS2IP6_INLINE int
IN6_IS_ADDR_V4MAPPED(const struct in6_addr *a)
{
    return ((a->s6_dwords[0] == 0) &&
            (a->s6_dwords[1] == 0) &&
            (a->s6_dwords[2] == htonl(0xffff)));
}

WS2IP6_INLINE int
IN6_IS_ADDR_V4COMPAT(const struct in6_addr *a)
{
    return ((a->s6_dwords[0] == 0) &&
            (a->s6_dwords[1] == 0) &&
            (a->s6_dwords[2] == 0) &&
            (a->s6_dwords[3] != 0) &&
            (a->s6_dwords[3] != htonl(1)));
}

WS2IP6_INLINE int
IN6_IS_ADDR_MC_NODELOCAL(const struct in6_addr *a)
{
    return IN6_IS_ADDR_MULTICAST(a) && ((a->s6_bytes[1] & 0xf) == 1);
}

WS2IP6_INLINE int
IN6_IS_ADDR_MC_LINKLOCAL(const struct in6_addr *a)
{
    return IN6_IS_ADDR_MULTICAST(a) && ((a->s6_bytes[1] & 0xf) == 2);
}

WS2IP6_INLINE int
IN6_IS_ADDR_MC_SITELOCAL(const struct in6_addr *a)
{
    return IN6_IS_ADDR_MULTICAST(a) && ((a->s6_bytes[1] & 0xf) == 5);
}

WS2IP6_INLINE int
IN6_IS_ADDR_MC_ORGLOCAL(const struct in6_addr *a)
{
    return IN6_IS_ADDR_MULTICAST(a) && ((a->s6_bytes[1] & 0xf) == 8);
}

WS2IP6_INLINE int
IN6_IS_ADDR_MC_GLOBAL(const struct in6_addr *a)
{
    return IN6_IS_ADDR_MULTICAST(a) && ((a->s6_bytes[1] & 0xf) == 0xe);
}

WS2IP6_INLINE int
IN6_ADDR_EQUAL(const struct in6_addr *a, const struct in6_addr *b)
{
    return (memcmp(a, b, sizeof(struct in6_addr)) == 0);
}


#define IPPROTO_IPV6 41

//
// Socket options at the IPPROTO_IPV6 level.
//
#define IPV6_MULTICAST_IF       9  // Set/get IP multicast interface.
#define IPV6_MULTICAST_HOPS     10 // Set/get IP multicast ttl.
#define IPV6_MULTICAST_LOOP     11 // Set/get IP multicast loopback.
#define IPV6_ADD_MEMBERSHIP     12 // Add an IP group membership.
#define IPV6_DROP_MEMBERSHIP    13 // Drop an IP group membership.
#define IPV6_JOIN_GROUP         IPV6_ADD_MEMBERSHIP
#define IPV6_LEAVE_GROUP        IPV6_DROP_MEMBERSHIP

//
// Socket options at the IPPROTO_UDP level.
//
#define UDP_CHECKSUM_COVERAGE   20  // Set/get UDP-Lite checksum coverage.

//
// Definitions for exports from wship6.lib.
//

// 
// Flag values for getipnodebyname().
//
#define AI_V4MAPPED     1
#define AI_ALL          2
#define AI_ADDRCONFIG   4
#define AI_DEFAULT      (AI_V4MAPPED | AI_ADDRCONFIG)

#define INET_ADDRSTRLEN    16
#define INET6_ADDRSTRLEN   46

WS2IP6_EXTERN struct hostent * WSAAPI
getipnodebyaddr(const void *src, int len, int af, int *error_num);

WS2IP6_EXTERN void WSAAPI
freehostent(struct hostent *ptr);

#define IN6ADDR_ANY_INIT        (uint64)0
#define IN6ADDR_LOOPBACK_INIT   (uint64)1

WS2IP6_EXTERN const struct in6_addr in6addr_any;
WS2IP6_EXTERN const struct in6_addr in6addr_loopback;

WS2IP6_EXTERN int WSAAPI
inet_pton(int af, const char *src, void *dst);

WS2IP6_EXTERN const char * WSAAPI
inet_ntop(int af, const void *src, char *dst, int size);

WS2IP6_EXTERN int WSAAPI
getaddrinfo(const char *nodename, const char *servname,
            const struct addrinfo *hints, struct addrinfo **res);

//
// Error codes from getaddrinfo().
//
#define EAI_ADDRFAMILY  1   // Address family for nodename not supported.
#define EAI_AGAIN       2   // Temporary failure in name resolution.
#define EAI_BADFLAGS    3   // Invalid value for ai_flags.
#define EAI_FAIL        4   // Non-recoverable failure in name resolution.
#define EAI_FAMILY      5   // Address family ai_family not supported.
#define EAI_MEMORY      6   // Memory allocation failure.
#define EAI_NODATA      7   // No address associated with nodename.
#define EAI_NONAME      8   // Nodename nor servname provided, or not known.
#define EAI_SERVICE     9   // Servname not supported for ai_socktype.
#define EAI_SOCKTYPE    10  // Socket type ai_socktype not supported.
#define EAI_SYSTEM      11  // System error returned in errno.

//
// Structure used in getaddrinfo() call.
//
struct addrinfo {
    int ai_flags;              // AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST.
    int ai_family;             // PF_xxx.
    int ai_socktype;           // SOCK_xxx.
    int ai_protocol;           // 0 or IPPROTO_xxx for IPv4 and IPv6.
    size_t ai_addrlen;         // Length of ai_addr.
    char *ai_canonname;        // Canonical name for nodename.
    struct sockaddr *ai_addr;  // Binary address.
    struct addrinfo *ai_next;  // Next structure in linked list.
};

//
// Flags used in "hints" argument to getaddrinfo().
//
#define AI_PASSIVE     0x1  // Socket address will be used in bind() call.
#define AI_CANONNAME   0x2  // Return canonical name in first ai_canonname.
#define AI_NUMERICHOST 0x4  // Nodename must be a numeric address string.

WS2IP6_EXTERN void WSAAPI
freeaddrinfo(struct addrinfo *ai);

WS2IP6_EXTERN char * WSAAPI
gai_strerror(int ecode);

typedef int socklen_t;

WS2IP6_EXTERN int WSAAPI
getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, 
            size_t hostlen, char *serv, size_t servlen, int flags);

#define NI_MAXHOST  1025  // Max size of a fully-qualified domain name.
#define NI_MAXSERV    32  // Max size of a service name.

//
// Flags for getnameinfo().
//
#define NI_NOFQDN       0x01  // Only return nodename portion for local hosts. 
#define NI_NUMERICHOST  0x02  // Return numeric form of the host's address.
#define NI_NAMEREQD     0x04  // Error if the host's name not in DNS.
#define NI_NUMERICSERV  0x08  // Return numeric form of the service (port #).
#define NI_DGRAM        0x10  // Service is a datagram service.

#endif // WS2IP6_INCLUDED
