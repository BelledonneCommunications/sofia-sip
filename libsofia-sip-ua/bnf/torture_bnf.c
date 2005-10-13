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

/**@CFILE torture_bnf.c
 *
 * Torture tests for BNF functions.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Aug 21 15:18:26 2001 ppessi
 * @date Last modified: Wed Jul 20 20:34:54 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>

#include "bnf.h"

static int test_flags = 0;
#define TSTFLAGS test_flags

#include <tstdef.h>

char const name[] = "torture_bnf";

void usage(void)
{
  fprintf(stderr, "usage: %s [-v]\n", name);
}

static int bnf_test(void);

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      test_flags |= tst_verbatim;
    else
      usage();
  }

  retval |= bnf_test(); fflush(stdout);

  return retval;
}

int count_bnf(int bnf_flags)
{
  int i, n;

  for (i = 0, n = 0; i < 128; i++)
    if (_bnf_table[i] & bnf_flags)
      n++;

  return n;
}

int bnf_test(void)
{
  BEGIN();
  TEST_1(IS_TOKEN('a'));
  TEST_1(IS_TOKEN('b'));
  TEST(span_lws("  \r\n \r\nLoppuu"), 7);
  TEST(span_lws("  \r\r\nLoppuu"), 5);
  TEST(span_lws("  \n\r\nLoppuu"), 5);
  TEST(span_token(SIP_TOKEN), strlen(SIP_TOKEN));
  TEST(count_bnf(bnf_token), strlen(SIP_TOKEN "$"));
  #define SIP_PARAM SIP_TOKEN "[:]/"
  TEST(span_param(SIP_PARAM), strlen(SIP_PARAM));
  TEST(count_bnf(bnf_param), strlen(SIP_PARAM "$"));

  TEST(span_unreserved(URL_UNRESERVED URL_ESCAPED), 
       strlen(URL_UNRESERVED URL_ESCAPED));

  TEST(count_bnf(bnf_unreserved),
       strlen(URL_UNRESERVED URL_ESCAPED));

  {
    char word[] = ALPHA DIGIT "-.!%*_+`'~()<>:\\\"/[]?{}";
    TEST(span_word(word), strlen(word));
  }

  END();
}
