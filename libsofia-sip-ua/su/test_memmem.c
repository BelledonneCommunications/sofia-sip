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

/**@ingroup test_memmem
 *
 * @CFILE test_memmem.c
 *
 * Torture tests for memmem().
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Tue Aug 21 15:18:26 2001 ppessi
 *
 * @date Last modified: Wed Jul 20 20:36:00 2005 kaiv
 */

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>

void *memmem(const void *haystack, size_t haystacklen,
	     const void *needle, size_t needlelen);

#include <string.h>

static int test_flags = 0;
#define TSTFLAGS test_flags

#include <tstdef.h>

char const name[] = "test_memmem";

void usage(void)
{
  fprintf(stderr, "usage: %s [-v]\n", name);
}

static int test_notfound(void);
static int test_pattern(void);

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

  retval |= test_notfound(); fflush(stdout);
  retval |= test_pattern(); fflush(stdout);

  return retval;
}

static int test_notfound(void)
{
  char const haystack[12] = "abcabcabcabc";
  char const needle[3] = "cab";
  char const *a;
  BEGIN();

  TEST(memmem(haystack, sizeof haystack, needle, sizeof needle), haystack + 2);
  TEST(memmem(needle, sizeof needle, haystack, sizeof haystack), NULL);
  TEST(memmem(haystack, sizeof haystack, "", 0), haystack);
  TEST(memmem(haystack, sizeof haystack, NULL, 0), haystack);
  TEST(memmem(haystack, 0, "", 0), haystack);
  TEST(memmem(haystack, 0, NULL, 0), haystack);

  TEST(memmem(haystack + 2, 3, needle, 3), haystack + 2);
  TEST(memmem(a = "a\0bc", 4, "a\0bc", 4), a);

  END();
}

static int test_pattern(void)
{
  BEGIN();
  END();
}

