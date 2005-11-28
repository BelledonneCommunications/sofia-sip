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

#ifndef NEA_TAG_H /** Defined when <nea_tag.h> has been included. */
#define NEA_TAG_H

/**@file nea_tag.h
 * @brief Tags for Nokia User Agent Library
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Mon Feb 19 18:54:26 EET 2001 ppessi
 */

#ifndef SU_TAG_H
#include <su_tag.h>
#endif
#ifndef URL_TAG_H
#include <url_tag.h>
#endif
#ifndef SIP_TAG_H
#include <sip_tag.h>
#endif
#ifndef NTA_TAG_H
#include <nta_tag.h>
#endif

/** Event states */
typedef enum {
  nea_extended = -1,
  nea_embryonic = 0,		/** Before first notify */
  nea_pending,
  nea_active,
  nea_terminated
} nea_state_t;


/** List of all NEA tags. */
/* extern tag_type_t nea_tag_list[]; */







#endif
