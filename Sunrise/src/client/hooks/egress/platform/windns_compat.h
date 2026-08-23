#pragma once

#include <windns.h>

// MinGW-family windns.h omits the DNS query options and async types used by
// the egress DNS hook; full Windows SDKs already define everything below.
#if defined(__MINGW32__) || defined(__MINGW64__)

// MinGW-w64's windns.h omits SDK query options; guard each so a newer header
// that does define them wins.
#ifndef DNS_QUERY_NO_HOSTS_FILE
#define DNS_QUERY_NO_HOSTS_FILE 0x00000004
#endif
#ifndef DNS_QUERY_NO_NETBT
#define DNS_QUERY_NO_NETBT 0x00000008
#endif
#ifndef DNS_QUERY_WIRE_ONLY
#define DNS_QUERY_WIRE_ONLY 0x00000010
#endif
#ifndef DNS_QUERY_BYPASS_CACHE
#define DNS_QUERY_BYPASS_CACHE 0x00004000
#endif
#ifndef DNS_QUERY_NO_LOCAL_NAME
#define DNS_QUERY_NO_LOCAL_NAME 0x00100000
#endif
#ifndef DNS_QUERY_NO_WIRE_QUERY
#define DNS_QUERY_NO_WIRE_QUERY 0x00200000
#endif

// Extended async query types absent from MinGW's windns.h.
typedef struct _DNS_QUERY_CANCEL {
    CHAR Reserved[32];
} DNS_QUERY_CANCEL, *PDNS_QUERY_CANCEL;

typedef struct _DNS_QUERY_REQUEST {
    ULONG Version;
    PCWSTR QueryName;
    WORD QueryType;
    ULONG64 QueryOptions;
    PVOID pDnsServerList;
    ULONG InterfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE pQueryCompletionCallback;
    PVOID pQueryContext;
} DNS_QUERY_REQUEST, *PDNS_QUERY_REQUEST;

typedef struct _DNS_QUERY_RAW_REQUEST DNS_QUERY_RAW_REQUEST;

typedef struct _DNS_QUERY_RAW_CANCEL {
    CHAR reserved[32];
} DNS_QUERY_RAW_CANCEL;

extern "C" DNS_STATUS WINAPI DnsQueryEx(PDNS_QUERY_REQUEST,
                                         PDNS_QUERY_RESULT,
                                         PDNS_QUERY_CANCEL);
extern "C" DNS_STATUS WINAPI DnsQueryRaw(DNS_QUERY_RAW_REQUEST*, DNS_QUERY_RAW_CANCEL*);
#endif  // __MINGW32__/__MINGW64__
