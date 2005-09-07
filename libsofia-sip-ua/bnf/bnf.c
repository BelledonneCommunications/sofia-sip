/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2005 Nokia Corporation.
 *
 * Contact: Pekka Pessi <pekka.pessi@nokia.com>
 *
 * * This library is free software; you can redistribute it and/or
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

/**@CFILE bnf.c
 * @brief Character syntax table for HTTP-like protocols.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Thu Jun  8 19:28:55 2000 ppessi
 * $Date: 2005/07/20 20:34:54 $
 */

#include "config.h"

const char bnf_c_id[] =
"$Id: bnf.c,v 1.1.1.1 2005/07/20 20:34:54 kaiv Exp $";

#include <string.h>

/* include bodies of inline functions */
#if !HAVE_INLINE
#define BNF_INLINE
#endif

#include "bnf.h"

const char bnf_h_id[] = BNF_H;

#define ws    bnf_ws
#define crlf  bnf_crlf
#define alpha bnf_alpha
#define digit bnf_mark|bnf_token0|bnf_safe
#define sep   bnf_separator
#define msep  bnf_mark|bnf_separator
#define psep  bnf_param0|bnf_separator
#define tok   bnf_token0
#define mtok  bnf_mark|bnf_token0
#define smtok bnf_mark|bnf_token0|bnf_safe
#define safe  bnf_safe


unsigned char const _bnf_table[256] = {
  0,     0,     0,     0,     0,     0,     0,     0,
  0,     ws,    crlf,  0,     0,     crlf,  0,     0,
  0,     0,     0,     0,     0,     0,     0,     0,
  0,     0,     0,     0,     0,     0,     0,     0,
  ws,    mtok,  sep,   0,     safe,  mtok,  0,     mtok,  /*  !"#$%&' */
  msep,  msep,  mtok,  tok,   sep,   smtok, smtok, psep,  /* ()*+,-./ */
  digit, digit, digit, digit, digit, digit, digit, digit, /* 01234567 */
  digit, digit, psep,  sep,   sep,   sep,   sep,   sep,   /* 89:;<=>? */
  sep,   alpha, alpha, alpha, alpha, alpha, alpha, alpha, /* @ABCDEFG */
  alpha, alpha, alpha, alpha, alpha, alpha, alpha, alpha, /* HIJKLMNO */ 
  alpha, alpha, alpha, alpha, alpha, alpha, alpha, alpha, /* PQRSTUVW */
  alpha, alpha, alpha, psep,  sep,   psep,  0,     smtok, /* XYZ[\]^_ */
  tok,   alpha, alpha, alpha, alpha, alpha, alpha, alpha, /* `abcdefg */
  alpha, alpha, alpha, alpha, alpha, alpha, alpha, alpha, /* hijklmno */ 
  alpha, alpha, alpha, alpha, alpha, alpha, alpha, alpha, /* pqrstuvw */
  alpha, alpha, alpha, sep,   0,     sep,   mtok,  0,     /* xyz{|}~  */
};
