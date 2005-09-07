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

/**
 * @file torture_su_memmem.c
 * @brief Test string search with Boyer-Moore algorithm 
 *  
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @date Created: Sun Apr 17 21:02:10 2005 ppessi
 * $Date: 2005/07/20 20:36:00 $
 */

#include "config.h"

const char torture_su_memmem_c_id[] = 
  "$Id: torture_su_memmem.c,v 1.1.1.1 2005/07/20 20:36:00 kaiv Exp $";

#define TSTFLAGS tstflags

#include <stdio.h>
#include <string.h>
#include <tstdef.h>

char const *name = "torture_su_memmem";
int tstflags;

#define TORTURELOG(x)		       \
  do {				       \
    if (tstflags & (2 * tst_verbatim)) \
      printf x;			       \
  } while(0)
    
#include "su_memmem.c"

int test_bm(void)
{
  BEGIN();
  
  {
    char const hs[] = 
      "A Boyer-Moore string searching test consisting of a Long String";
    char const *s;

    s = bm_memmem(hs, strlen(hs), "sting", 5, NULL);

    TEST_S(s, hs + 41);

    s = bm_memmem(hs, strlen(hs), "String", 6, NULL);
    TEST_S(s, hs + 57);

    s = bm_memmem(hs, strlen(hs), "S", 1, NULL);
    TEST_S(s, hs + 57);

    s = bm_memmem(hs, strlen(hs), "M", 1, NULL);
    TEST_S(s, hs + 8);

    s = bm_memcasemem(hs, strlen(hs), "M", 1, NULL);
    TEST_S(s, hs + 8);

    s = bm_memcasemem(hs, strlen(hs), "trings", 6, NULL);
    TEST_1(s == NULL);

    s = bm_memcasemem(hs, strlen(hs), "String", 6, NULL);
    TEST_S(s, hs + 14);

    s = bm_memcasemem(hs, strlen(hs), "StRiNg", 6, NULL);
    TEST_S(s, hs + 14);

    s = bm_memcasemem(hs, strlen(hs), "OnG", 3, NULL);
    TEST_S(s, hs + 53);
  }

  END();
}


void usage(void)
{
  fprintf(stderr, 
	  "usage: %s [-v]\n", 
	  name);
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  /* Set our name */
  if (strchr(argv[0], '/')) 
    name = strrchr(argv[0], '/') + 1;
  else
    name = argv[0];

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-l") == 0)
      tstflags |= 2 * tst_verbatim;
    else
      usage();
  }

  retval |= test_bm(); fflush(stdout);

  return retval;
}
