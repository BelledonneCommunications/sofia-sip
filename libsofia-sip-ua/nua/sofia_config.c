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

/**@file sofia_config.c Provide sofia-sip features.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Mon Oct 24 14:51:32 2005 ppessi
 */

#include "config.h" 

#include <stddef.h>

#include "su_configure.h"
#include "sofia_config.h"

char const *sofia_name_version = PACKAGE_STRING;

#if HAVE_SOFIA_SIGCOMP
#include <sigcomp.h>
char const *sofia_has_sigcomp = sigcomp_package_version;
#else
char const *sofia_has_sigcomp = NULL;
#endif

#if HAVE_OPENSSL
#include <tport_tls.h>
char const *sofia_has_tls = tls_version;
#else
char const *sofia_has_tls = NULL;
#endif

#if HAVE_SOFIA_STUN
char const *sofia_has_stun = NULL;
#else
char const *sofia_has_stun = NULL;
#endif

#if SU_HAVE_IN6
char const *sofia_has_ipv6 = "v6";
#else
char const *sofia_has_ipv6 = NULL;
#endif

char const *sofia_has_smime = NULL;

