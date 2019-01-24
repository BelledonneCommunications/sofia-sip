/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef CONFIG_H
#define CONFIG_H

#define VERSION "${PROJECT_VERSION}"
#define PACKAGE_VERSION "${PROJECT_VERSION}"
#define PACKAGE_NAME "${PROJECT_NAME}"

#cmakedefine HAVE_CHECK 1
#define HAVE_NEW_TCASE_ADD_TEST 1

/** Define as 1 if you have sa_len field in struct sockaddr */
#define HAVE_SOCKADDR_SA_LEN 0

/** Define as 1 if you have struct sockaddr_storage */
#define HAVE_SOCKADDR_STORAGE 1

/* Define to 1 if you have addrinfo structure. */
#define HAVE_ADDRINFO 1

/* Define to 1 if you have addrinfo structure. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have addrinfo structure. */
#define HAVE_FREEADDRINFO 1

/* Define to 1 if you have IPv6 structures and constants */
#define HAVE_SIN6 1

/** Define as 1 if you have <stdint.h> */
#define HAVE_STDINT_H 1

/** Define as 1 if you have <inttypes.h> */
#define HAVE_INTTYPES_H 1

/** Define as 1 if you have <sys/types.h> */
#define HAVE_SYS_TYPES_H 1

#define HAVE_GAI_STRERROR 1
#define HAVE_MEMMEM 1

#define HAVE_SYS_TIME_H 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_NETINET_IN_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_POLL 1
#define HAVE_EPOLL 1
#define HAVE_SOFIA_SIP 1
#define HAVE_INET_PTON 1
#define HAVE_INET_NTOP 1

#define HAVE_ALARM 1
#define RETSIGTYPE void

/* Define to 1 if printf supports C99 size specifiers */
#define HAVE_C99_FORMAT 1

/* Format (%llu) for unsigned long long */
#define LLU "%llu"

/* Format (%lli) for long long */
#define LLI "%lli"

/* Format (%llx) for long long hex */
#define LLX "%llx"

/* Define printf() modifier for ssize_t */
#define MOD_ZD "%zd"

/* Define printf() modifier for size_t */
#define MOD_ZU "%zu"

/* Define to a at least 64-bit int type */
#define longlong long long

/** Define this in order to get GNU extensions. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

/* Define to 1 if the C compiler supports __func__ */
#define HAVE_FUNC 1

/* Define to 1 if the C compiler supports __FUNCTION__ */
#define HAVE_FUNCTION 1

#define HAVE_TLS 1

#endif /* CONFIG_H */
