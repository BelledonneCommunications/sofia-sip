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
// TDI Query/SetInfo and Action definitons.
// This file contains definitions for information
// returned from TCP/UDP.
//


#ifndef TCP6_INFO_INCLUDED
#define TCP6_INFO_INCLUDED

typedef unsigned long ulong;
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned int uint;


typedef struct TCPStats {
    ulong ts_rtoalgorithm;
    ulong ts_rtomin;
    ulong ts_rtomax;
    ulong ts_maxconn;
    ulong ts_activeopens;
    ulong ts_passiveopens;
    ulong ts_attemptfails;
    ulong ts_estabresets;
    ulong ts_currestab;
    ulong ts_insegs;
    ulong ts_outsegs;
    ulong ts_retranssegs;
    ulong ts_inerrors;
    ulong ts_outrsts;
    ulong ts_numconns;
} TCPStats;

#define TCP_RTO_OTHER    1
#define TCP_RTO_CONSTANT 2
#define TCP_RTO_RSRE     3
#define TCP_RTO_VANJ     4

#define TCP_MAXCONN_DYNAMIC -1

typedef struct UDPStats {
    ulong us_indatagrams;
    ulong us_noports;
    ulong us_inerrors;
    ulong us_outdatagrams;
    ulong us_numaddrs;
} UDPStats;

typedef struct TCPConnTableEntry {
    ulong tct_state;
    IPv6Addr tct_localaddr;
    ulong tct_localscopeid;
    ulong tct_localport;
    IPv6Addr tct_remoteaddr;
    ulong tct_remotescopeid;
    ulong tct_remoteport;
} TCPConnTableEntry;

//
// Definitions for the tct_state variable.
// BUGBUG: These really shouldn't be definied in two seperate places in
// BUGBUG: in the code (one for internal use, one for external).
//
#define TCP_CONN_CLOSED     1   // Closed.
#define TCP_CONN_LISTEN     2   // Listening.
#define TCP_CONN_SYN_SENT   3   // SYN Sent.
#define TCP_CONN_SYN_RCVD   4   // SYN received.
#define TCP_CONN_ESTAB      5   // Established.
#define TCP_CONN_FIN_WAIT1  6   // FIN-WAIT-1
#define TCP_CONN_FIN_WAIT2  7   // FIN-WAIT-2
#define TCP_CONN_CLOSE_WAIT 8   // Close waiting.
#define TCP_CONN_CLOSING    9   // Closing state.
#define TCP_CONN_LAST_ACK   10  // Last ack state.
#define TCP_CONN_TIME_WAIT  11  // Time wait state.
#define TCP_DELETE_TCB      12  // Set to delete this TCB.


typedef struct UDPEntry {
    IPv6Addr ue_localaddr;
    ulong ue_localport;
} UDPEntry;


#define TCP_MIB_STAT_ID 1
#define UDP_MIB_STAT_ID 1
#define TCP_MIB_TABLE_ID 0x101
#define UDP_MIB_TABLE_ID 0x101

//
// Sockets based identifiers for connections.
//

typedef struct TCPSocketOption {
    ulong tso_value;
} TCPSocketOption;

//
// Structure passed in/returned from the SOCKET_ATMARK call. The tsa_offset
// field indicate how far back or forward in the data stream urgent data
// was or will be returned. A negative value means inline urgent data has
// already been given to the client, -tsa_offset bytes ago. A positive value
// means that inline urgent data is available tsa_offset bytes down the
// data stream. The tsa_size field is the size in bytes of the urgent data.
// This call when always return a 0 size and offset if the connection is not
// in the urgent inline mode.
//
typedef struct TCPSocketAMInfo {
    ulong tsa_size;   // Size of urgent data returned.
    long tsa_offset;  // Offset of urgent data returned.
} TCPSocketAMInfo;

#define TCP_SOCKET_NODELAY   1
#define TCP_SOCKET_KEEPALIVE 2
#define TCP_SOCKET_OOBINLINE 3
#define TCP_SOCKET_BSDURGENT 4
#define TCP_SOCKET_ATMARK    5
#define TCP_SOCKET_WINDOW    6

//
// Address object identifies.  All but AO_OPTION_MCASTIF take single boolean
// character value.  That one expects a pointer to an IP address.
//
#define AO_OPTION_TTL             1
#define AO_OPTION_MCASTTTL        2
#define AO_OPTION_MCASTIF         3
#if 0
#define AO_OPTION_XSUM            4     // Not used for IPv6.
#endif
#define AO_OPTION_IPOPTIONS       5
#define AO_OPTION_ADD_MCAST       6
#define AO_OPTION_DEL_MCAST       7
#define AO_OPTION_TOS             8
#define AO_OPTION_IP_DONTFRAGMENT 9
#define AO_OPTION_MCASTLOOP       10
#define AO_OPTION_UDP_CKSUM_COVER 11

//
// Information relating to setting/deleting IP multicast addresses.
//
typedef struct UDPMCastReq {
    IPv6Addr umr_addr;  // MCast address to add/delete.
    IPv6Addr umr_if;    // I/F on which to join.
} UDPMCastReq;

//
// Structure defining what is passed in to AO_OPTION_MCASTIF request.
//
typedef struct UDPMCastIFReq {
    IPv6Addr umi_addr;
} UDPMCastIFReq;


//
// Structures used in connection list enumeration.
//
// All values are in HOST byte order!!!
//
typedef struct TCPConnectionListEntry {
    IPv6Addr tcf_address;  // IP address.
    uint tcf_ticks;        // Tick Count remaining.
} TCPConnectionListEntry;

typedef struct TCPConnectionListEnum {
    ULONG tce_entries_returned;  // Number of TCPConnectionListEntry structs
                                 // returned in the subsequent array.

    ULONG tce_entries_available; // Number of TCPConnectionListEntry structs
                                 // currently available from the transport.
} TCPConnectionListEnum;

#endif // TCP6_INFO_INCLUDED
