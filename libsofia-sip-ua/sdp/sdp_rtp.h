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

#ifndef SDP_RTP_H
#define SDP_RTP_H 

/**@file sdp_rtp.h Well-known RTP payload types
 *
 * @author Pekka Pessi <Pekka.Pessi@research.nokia.com>
 *
 * @date Created: Tue Mar  7 14:51:14 2000 ppessi
 * @date Last modified: Wed Jul 20 20:35:36 2005 kaiv
 */

enum {
  pt_g711u   = 0,
  pt_1016    = 1,
  pt_g726    = 2,
  pt_gsm     = 3,
  pt_g723    = 4,
  pt_dvi4    = 5,
  pt_dvi4_16 = 6,
  pt_lpc     = 7,
  pt_g711a   = 8,
  pt_g722    = 9,
  pt_l_16    = 10,
  pt_l_16_2  = 11,
  pt_qcelp   = 12,
  pt_mpa     = 14,
  pt_g728    = 15,
  pt_dvi4_11 = 16,
  pt_dvi4_22 = 17,
  pt_g729    = 18,
  pt_cn      = 19,

  /* Video */
  pt_celb    = 25,
  pt_jpeg    = 26,
  pt_nv      = 28,
  pt_h261    = 31,
  pt_mpv     = 32,
  pt_mp2t    = 33,
  pt_h263    = 34
};

#endif /* SDP_RTP_H */
