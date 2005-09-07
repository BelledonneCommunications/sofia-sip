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

/**@file memspn.c
 * @brief The memspn() and memcspn() functions 
 *        - search memory for a set of characters.
 *  
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Sat Apr 12 19:32:33 2003 ppessi
 * 
 * $Date: 2005/07/20 20:35:21 $
 */

#include "config.h"

const char memspn_c_id[] = 
  "$Id: memspn.c,v 1.1.1.1 2005/07/20 20:35:21 kaiv Exp $";

#include <string.h>
#include <limits.h>

#if !HAVE_MEMSPN
/**Scan memory for a set of bytes.
 *
 * The memspn() function calculates the length of the memory area @a mem
 * which consists entirely of bytes in @a accept.
 *
 * @param mem        pointer to memory area
 * @param memlen     size of @a mem in bytes
 * @param accept     pointer to table containing bytes to accept
 * @param acceptlen  size of @a accept table
 *
 * @return
 * The memspn() function returns the number of bbytes in the memory area @a
 * which consists entirely of bytes in @a accept.
 */
size_t memspn(const void *mem, size_t memlen,
	      const void *accept, size_t acceptlen)
{
  size_t i;

  unsigned char const *m = mem, *a = accept;

  char accepted[UCHAR_MAX + 1];

  if (mem == NULL || memlen == 0 || acceptlen == 0 || accept == NULL)
    return 0;

  memset(accepted, 0, sizeof accepted);

  for (i = 0; i < acceptlen; i++)
    accepted[a[i]] = 1;

  for (i = 0; i < memlen; i++)
    if (!accepted[m[i]])
      break;

  return i;
}
#endif

#if !HAVE_MEMCSPN
/**Search memory for bytes not in a given set.
 *
 * The memcspn() function calculates the length of the memory area @a mem
 * which consists entirely of bytes not in @a reject.
 *
 * @param mem        pointer to memory area
 * @param memlen     size of @a mem in bytes
 * @param reject     pointer to table containing bytes to reject
 * @param rejectlen  size of @a reject table
 *
 * @return
 * The memspn() function returns the number of bytes in the memory area @a
 * which consists entirely of bytes not in @a reject.
 * @par 
 * If @a rejectlen is 0, or @a reject is NULL, it returns @a memlen, size of
 * the memory area.
 */
size_t memcspn(const void *mem, size_t memlen,
	       const void *reject, size_t rejectlen)
{
  size_t i;

  unsigned char const *m = mem, *r = reject;

  char rejected[UCHAR_MAX + 1];

  if (rejectlen == 0 || reject == 0)
    return memlen;

  if (mem == NULL || memlen == 0)
    return 0;

  memset(rejected, 0, sizeof rejected);

  for (i = 0; i < rejectlen; i++)
    rejected[r[i]] = 1;

  for (i = 0; i < memlen; i++)
    if (rejected[m[i]])
      break;

  return i;
}
#endif
