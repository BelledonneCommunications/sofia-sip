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
// This header file defines constants and types for accessing
// the MSR IPv6 driver via ioctls.
//


#ifndef _NTDDIP6_
#define _NTDDIP6_

#include <ip6exp.h>

//
// We need a definition of CTL_CODE for use below.
// When compiling kernel components in the DDK environment,
// ntddk.h supplies this definition. Otherwise get it
// from devioctl.h in the SDK environment.
//
#ifndef CTL_CODE
#include <devioctl.h>
#endif

//
// We also need a definition of TDI_ADDRESS_IP6.
// In the DDK environment, tdi.h supplies this.
// We provide a definition here for the SDK environment.
//
#ifndef TDI_ADDRESS_LENGTH_IP6
#include <packon.h>
typedef struct _TDI_ADDRESS_IP6 {
    ushort sin6_port;
    ulong  sin6_flowinfo;
    ushort sin6_addr[8];
    ulong  sin6_scope_id;
} TDI_ADDRESS_IP6, *PTDI_ADDRESS_IP6;
#include <packoff.h>

#define TDI_ADDRESS_LENGTH_IP6 sizeof (TDI_ADDRESS_IP6)
#endif

//
// This is the key name of the TCP/IPv6 protocol stack in the registry.
// The protocol driver and the winsock helper both use it.
//
#define TCPIPV6_NAME L"Tcpip6"

//
// Device Name - this string is the name of the device.  It is the name
// that should be passed to NtCreateFile when accessing the device.
//
#define DD_TCPV6_DEVICE_NAME      L"\\Device\\Tcp6"
#define DD_UDPV6_DEVICE_NAME      L"\\Device\\Udp6"
#define DD_RAW_IPV6_DEVICE_NAME   L"\\Device\\RawIp6"
#define DD_IPV6_DEVICE_NAME       L"\\Device\\Ip6"

//
// The Windows-accessible device name.  It is the name that
// (prepended with "\\\\.\\") should be passed to CreateFile.
//
#define WIN_IPV6_BASE_DEVICE_NAME L"Ip6"
#define WIN_IPV6_DEVICE_NAME      L"\\\\.\\" WIN_IPV6_BASE_DEVICE_NAME


//
// IPv6 IOCTL code definitions.
//

#define FSCTL_IPV6_BASE FILE_DEVICE_NETWORK

#define _IPV6_CTL_CODE(function, method, access) \
            CTL_CODE(FSCTL_IPV6_BASE, function, method, access)


//
// This IOCTL is used to send an ICMPv6 Echo request.
// It returns the reply (unless there was a timeout or TTL expired).
//
#define IOCTL_ICMPV6_ECHO_REQUEST \
            _IPV6_CTL_CODE(0, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct icmpv6_echo_request {
    TDI_ADDRESS_IP6 DstAddress; // Destination address.
    TDI_ADDRESS_IP6 SrcAddress; // Source address.
    unsigned int Timeout;       // Request timeout in milliseconds.
    unsigned char TTL;          // TTL or Hop Count.
    unsigned int Flags;
    // Request data follows this structure in memory.
} ICMPV6_ECHO_REQUEST, *PICMPV6_ECHO_REQUEST;

#define ICMPV6_ECHO_REQUEST_FLAG_REVERSE        0x1     // Use routing header.

typedef struct icmpv6_echo_reply {
    TDI_ADDRESS_IP6 Address;    // Replying address.
    IP_STATUS Status;           // Reply IP_STATUS.
    unsigned int RoundTripTime; // RTT in milliseconds.
    // Reply data follows this structure in memory.
} ICMPV6_ECHO_REPLY, *PICMPV6_ECHO_REPLY;


//
// This IOCTL retrieves information about an interface,
// given an interface index.
//
#define IOCTL_IPV6_QUERY_INTERFACE \
            _IPV6_CTL_CODE(1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_interface {
    unsigned int Index;
} IPV6_QUERY_INTERFACE;

typedef struct ipv6_info_interface {
    IPV6_QUERY_INTERFACE Query;

    unsigned int SiteIndex;
    unsigned int TrueLinkMTU;
    unsigned int LinkMTU;
    unsigned int CurHopLimit;
    unsigned int BaseReachableTime;       // Milliseconds.
    unsigned int ReachableTime;           // Milliseconds.
    unsigned int RetransTimer;            // Milliseconds.
    unsigned int DupAddrDetectTransmits;

    int Discovers;                        // Boolean - uses ND?
    int Advertises;                       // Boolean - sends RAs?
    int Forwards;                         // Boolean - forwards packets?
    uint MediaConnected;                  // 0 - yes, 1 - no, 2 - reconnected

    unsigned int LinkLevelAddressLength;
    // Link-level address follows.
} IPV6_INFO_INTERFACE;


//
// This IOCTL retrieves information about a source address
// on an interface.
//
#define IOCTL_IPV6_QUERY_ADDRESS \
            _IPV6_CTL_CODE(2, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_address {
    IPV6_QUERY_INTERFACE IF;  // Fields that identify an interface.
    IPv6Addr Address;
} IPV6_QUERY_ADDRESS;

typedef struct ipv6_info_address {
    IPV6_QUERY_ADDRESS Query;

    unsigned int Type;
    unsigned int Scope;

    union {
        struct {  // If it's a unicast address.
            unsigned int DADState;
            int AutoConfigured;                    // Boolean.
            unsigned int ValidLifetime;            // Seconds.
            unsigned int PreferredLifetime;        // Seconds.
        };
        struct {  // If it's a multicast address.
            unsigned int MCastRefCount;
            unsigned int MCastFlags;
            unsigned int MCastTimer;               // Seconds.
        };
    };
} IPV6_INFO_ADDRESS;


//
// This IOCTL retrieves information from the neighbor cache.
//
#define IOCTL_IPV6_QUERY_NEIGHBOR_CACHE \
            _IPV6_CTL_CODE(3, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_neighbor_cache {
    IPV6_QUERY_INTERFACE IF;  // Fields that identify an interface.
    IPv6Addr Address;
} IPV6_QUERY_NEIGHBOR_CACHE;

typedef struct ipv6_info_neighbor_cache {
    IPV6_QUERY_NEIGHBOR_CACHE Query;

    unsigned int IsRouter;                // Whether neighbor is a router.
    unsigned int IsUnreachable;           // Whether neighbor is unreachable.
    unsigned int NDState;                 // Current state of entry.
    unsigned int ReachableTimer;          // Reachable time remaining (in ms).

    unsigned int LinkLevelAddressLength;  // Address type assumed from length.
    // Link-level address follows.
} IPV6_INFO_NEIGHBOR_CACHE;


//
// This IOCTL retrieves information from the route cache.
//
#define IOCTL_IPV6_QUERY_ROUTE_CACHE \
            _IPV6_CTL_CODE(4, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_route_cache {
    IPV6_QUERY_INTERFACE IF;  // Fields that identify an interface.
    IPv6Addr Address;
} IPV6_QUERY_ROUTE_CACHE;

typedef struct ipv6_info_route_cache {
    IPV6_QUERY_ROUTE_CACHE Query;

    unsigned int Type;
    unsigned int Flags;
    int Valid;                      // Boolean - FALSE means it is stale.
    IPv6Addr SourceAddress;
    IPv6Addr NextHopAddress;
    unsigned int NextHopInterface;
    unsigned int PathMTU;
    unsigned int PMTUProbeTimer;    // Time until next PMTU probe (in ms).
    unsigned int ICMPLastError;     // Time since last ICMP error sent (in ms).
    unsigned int BindingSeqNumber;
    unsigned int BindingLifetime;   // Seconds.
    IPv6Addr CareOfAddress;
} IPV6_INFO_ROUTE_CACHE;


#if 0 // obsolete
//
// This IOCTL retrieves information from the prefix list.
//
#define IOCTL_IPV6_QUERY_PREFIX_LIST \
            _IPV6_CTL_CODE(5, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// This IOCTL retrieves information from the default router list.
//
#define IOCTL_IPV6_QUERY_ROUTER_LIST \
            _IPV6_CTL_CODE(6, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// This IOCTL adds a multicast group to the desired interface.
//
#define IOCTL_IPV6_ADD_MEMBERSHIP \
            _IPV6_CTL_CODE(7, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// This IOCTL drops a multicast group.
//
#define IOCTL_IPV6_DROP_MEMBERSHIP \
            _IPV6_CTL_CODE(8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

//
// This IOCTL adds an SP to the SP list.
//
#define IOCTL_IPV6_CREATE_SECURITY_POLICY \
            _IPV6_CTL_CODE(9, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_create_security_policy_result {
    unsigned long Status;
} IPV6_CREATE_SECURITY_POLICY_RESULT;

typedef struct ipv6_create_security_policy {
    IPV6_CREATE_SECURITY_POLICY_RESULT Result;
    unsigned long SPIndex;                 // Index of IOCTL create.

    unsigned int RemoteAddrField;
    unsigned int RemoteAddrSelector;
    IPv6Addr RemoteAddr;                  // Remote IP Address.
    IPv6Addr RemoteAddrData;

    unsigned int LocalAddrField;          // Single, range, or wildcard.
    unsigned int LocalAddrSelector;       // Packet or policy.
    IPv6Addr LocalAddr;                   // Start of range or single value.
    IPv6Addr LocalAddrData;               // End of range.

    unsigned int TransportProtoSelector;  // Packet or policy.
    unsigned short TransportProto;

    unsigned int RemotePortField;         // Single, range, or wildcard.
    unsigned int RemotePortSelector;      // Packet or policy.
    unsigned short RemotePort;            // Start of range or single value.
    unsigned short RemotePortData;        // End of range.

    unsigned int LocalPortField;          // Single, range, or wildcard.
    unsigned int LocalPortSelector;       // Packet or policy.
    unsigned short LocalPort;             // Start of range or single value.
    unsigned short LocalPortData;         // End of range.

    unsigned int IPSecProtocol;
    unsigned int IPSecMode;
    IPv6Addr RemoteSecurityGWAddr;
    unsigned int Direction;
    unsigned int IPSecAction;
    unsigned long SABundleIndex;
    unsigned int SPInterface;
    unsigned long InsertIndex;
} IPV6_CREATE_SECURITY_POLICY;


//
// This IOCTL adds an SA to the SA list.
//
#define IOCTL_IPV6_CREATE_SECURITY_ASSOCIATION \
            _IPV6_CTL_CODE(10, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_create_security_association_result {
    unsigned long Status;
} IPV6_CREATE_SECURITY_ASSOCIATION_RESULT;

typedef struct ipv6_create_security_association {
    IPV6_CREATE_SECURITY_ASSOCIATION_RESULT Result;
    unsigned long SAIndex;
    unsigned long SPI;              // Security Parameter Index.
    IPv6Addr SADestAddr;
    IPv6Addr DestAddr;
    IPv6Addr SrcAddr;
    unsigned short TransportProto;
    unsigned short DestPort;
    unsigned short SrcPort;
    unsigned int Direction;
    unsigned long SecPolicyIndex;
    unsigned int AlgorithmId;
    unsigned char *RawKey;
    unsigned int RawKeySize;
} IPV6_CREATE_SECURITY_ASSOCIATION;


//
// This IOCTL gets all the SPs from the SP list.
//
#define IOCTL_IPV6_QUERY_SECURITY_POLICY_LIST \
            _IPV6_CTL_CODE(11, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_security_policy_list {
    unsigned int SPInterface;
    unsigned long Index;
} IPV6_QUERY_SECURITY_POLICY_LIST;

typedef struct ipv6_info_security_policy_list {
    IPV6_QUERY_SECURITY_POLICY_LIST Query;
    unsigned long SPIndex;
    unsigned long NextSPIndex;

    unsigned int RemoteAddrField;
    unsigned int RemoteAddrSelector;
    IPv6Addr RemoteAddr;                  // Remote IP Address.
    IPv6Addr RemoteAddrData;

    unsigned int LocalAddrField;          // Single, range, or wildcard.
    unsigned int LocalAddrSelector;       // Packet or policy.
    IPv6Addr LocalAddr;                   // Start of range or single value.
    IPv6Addr LocalAddrData;               // End of range.

    unsigned int TransportProtoSelector;  // Packet or policy.
    unsigned short TransportProto;

    unsigned int RemotePortField;         // Single, range, or wildcard.
    unsigned int RemotePortSelector;      // Packet or policy.
    unsigned short RemotePort;            // Start of range or single value.
    unsigned short RemotePortData;        // End of range.

    unsigned int LocalPortField;          // Single, range, or wildcard.
    unsigned int LocalPortSelector;       // Packet or policy.
    unsigned short LocalPort;             // Start of range or single value.
    unsigned short LocalPortData;         // End of range.

    unsigned int IPSecProtocol;
    unsigned int IPSecMode;
    IPv6Addr RemoteSecurityGWAddr;
    unsigned int Direction;
    unsigned int IPSecAction;
    unsigned long SABundleIndex;
    unsigned int SPInterface;
} IPV6_INFO_SECURITY_POLICY_LIST;


//
// This IOCTL gets all the SAs from the SA list.
//
#define IOCTL_IPV6_QUERY_SECURITY_ASSOCIATION_LIST \
            _IPV6_CTL_CODE(12, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_security_association_list {
    unsigned long Index;
} IPV6_QUERY_SECURITY_ASSOCIATION_LIST;

typedef struct ipv6_info_security_association_list {
    IPV6_QUERY_SECURITY_ASSOCIATION_LIST Query;
    unsigned long SAIndex;
    unsigned long NextSAIndex;
    unsigned long SPI;              // Security Parameter Index.
    IPv6Addr SADestAddr;  
    IPv6Addr DestAddr;
    IPv6Addr SrcAddr;
    unsigned short TransportProto;
    unsigned short DestPort;
    unsigned short SrcPort;    
    unsigned int Direction;   
    unsigned long SecPolicyIndex;
    unsigned int AlgorithmId;
} IPV6_INFO_SECURITY_ASSOCIATION_LIST;


//
// This IOCTL retrieves information from the route table.
//
#define IOCTL_IPV6_QUERY_ROUTE_TABLE \
            _IPV6_CTL_CODE(13, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_route_table {
    IPv6Addr Prefix;
    unsigned int PrefixLength;
    IPV6_QUERY_NEIGHBOR_CACHE Neighbor;
} IPV6_QUERY_ROUTE_TABLE;

typedef struct ipv6_info_route_table {
    IPV6_QUERY_ROUTE_TABLE Query;

    unsigned int SitePrefixLength;
    unsigned int ValidLifetime;  // Seconds.
    unsigned int Preference;     // Smaller is better.
    int Publish;                 // Boolean.
    int Immortal;                // Boolean.
} IPV6_INFO_ROUTE_TABLE;


//
// This IOCTL adds/removes a route in the route table.
// It uses the IPV6_INFO_ROUTE_TABLE structure.
//
#define IOCTL_IPV6_UPDATE_ROUTE_TABLE \
            _IPV6_CTL_CODE(14, METHOD_BUFFERED, FILE_ANY_ACCESS)


//
// This IOCTL adds/removes an address on an interface.
// It uses the IPV6_UPDATE_ADDRESS structure.
//
#define IOCTL_IPV6_UPDATE_ADDRESS \
            _IPV6_CTL_CODE(15, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_update_address {
    IPV6_QUERY_ADDRESS Query;
    unsigned int Type;               // Unicast or anycast.
    int AutoConfigured;              // Boolean.
    unsigned int PreferredLifetime;  // Seconds.
    unsigned int ValidLifetime;      // Seconds.
} IPV6_UPDATE_ADDRESS;


//
// This IOCTL retrieves information from the binding cache.
//
#define IOCTL_IPV6_QUERY_BINDING_CACHE \
            _IPV6_CTL_CODE(16, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_binding_cache {
    IPv6Addr HomeAddress;
} IPV6_QUERY_BINDING_CACHE;

typedef struct ipv6_info_binding_cache {
    IPV6_QUERY_BINDING_CACHE Query;

    IPv6Addr HomeAddress;
    IPv6Addr CareOfAddress;
    unsigned int BindingSeqNumber;
    unsigned int BindingLifetime;   // Seconds.
} IPV6_INFO_BINDING_CACHE;


//
// This IOCTL controls some attributes of an interface.
// It uses the IPV6_CONTROL_INTERFACE structure.
//
#define IOCTL_IPV6_CONTROL_INTERFACE \
            _IPV6_CTL_CODE(17, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_control_interface {
    IPV6_QUERY_INTERFACE Query;

    int Advertises;     // -1 means no change, -2 means resolicit/readvertise,
                        // else boolean.
    int Forwards;       // -1 means no change, else boolean.

    unsigned int LinkMTU;       // 0 means no change.
    unsigned int SiteIndex;     // 0 means no change.
} IPV6_CONTROL_INTERFACE;


//
// This IOCTL flushes entries from the neighbor cache.
// It uses the IPV6_QUERY_NEIGHBOR_CACHE structure.
//
#define IOCTL_IPV6_FLUSH_NEIGHBOR_CACHE \
            _IPV6_CTL_CODE(18, METHOD_BUFFERED, FILE_ANY_ACCESS)


//
// This IOCTL flushes entries from the route cache.
// It uses the IPV6_QUERY_ROUTE_CACHE structure.
//
#define IOCTL_IPV6_FLUSH_ROUTE_CACHE \
            _IPV6_CTL_CODE(19, METHOD_BUFFERED, FILE_ANY_ACCESS)


//
// This IOCTL deletes SA entries from the SA list.
// It uses the IPV6_QUERY_SECURITY_ASSOCIATION_LIST structure.
//
#define IOCTL_IPV6_DELETE_SECURITY_ASSOCIATION \
             _IPV6_CTL_CODE(20, METHOD_BUFFERED, FILE_ANY_ACCESS)


//
// This IOCTL deletes SP entries from the SP list.
// It uses the IPV6_QUERY_SECURITY_POLICY_LIST structure.
//
#define IOCTL_IPV6_DELETE_SECURITY_POLICY \
             _IPV6_CTL_CODE(21, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// This IOCTL deletes an interface.
// It uses the IPV6_QUERY_INTERFACE structure.
//
#define IOCTL_IPV6_DELETE_INTERFACE \
            _IPV6_CTL_CODE(22, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// This IOCTL sets the mobility security to either on or off.
// When mobility security is turned on, Binding Cache Updates
// must be protected via IPsec.
//
#define IOCTL_IPV6_SET_MOBILITY_SECURITY \
            _IPV6_CTL_CODE(23, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_set_mobility_security {
    uint MobilitySecurity;      // See MOBILITY_SECURITY values in ipsec.h.
} IPV6_SET_MOBILITY_SECURITY;

//
// This IOCTL sorts a list of destination addresses.
// The returned list may contain fewer addresses.
// It uses an array of TDI_ADDRESS_IP6 in/out.
//
#define IOCTL_IPV6_SORT_DEST_ADDRS \
            _IPV6_CTL_CODE(24, METHOD_BUFFERED, FILE_ANY_ACCESS)


//
// This IOCTL retrieves information from the site prefix table.
//
#define IOCTL_IPV6_QUERY_SITE_PREFIX \
            _IPV6_CTL_CODE(25, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct ipv6_query_site_prefix {
    IPv6Addr Prefix;
    unsigned int PrefixLength;
    IPV6_QUERY_INTERFACE IF;
} IPV6_QUERY_SITE_PREFIX;

typedef struct ipv6_info_site_prefix {
    IPV6_QUERY_SITE_PREFIX Query;

    unsigned int ValidLifetime;  // Seconds.
} IPV6_INFO_SITE_PREFIX;


//
// This IOCTL adds/removes a prefix in the site prefix table.
// It uses the IPV6_INFO_SITE_PREFIX structure.
//
#define IOCTL_IPV6_UPDATE_SITE_PREFIX \
            _IPV6_CTL_CODE(26, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif  // ifndef _NTDDIP6_
