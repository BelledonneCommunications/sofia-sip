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

#ifndef SOFIA_SIP_HEAP_H
/** Defined when <sofia-sip/heap.h> has been included. */
#define SOFIA_SIP_HEAP_H

/**@file sofia-sip/heap.h
 *
 * Heap implementation.
 *
 * Note: this version can handle structures as entries, and it can be used
 * without <su_alloc.h>.
 * 
 * This file contain a hash table template for C.  The hash tables are
 * resizeable, and they usually contain pointers to entries.  The
 * declaration for template datatypes is instantiated with macro
 * HEAP_DECLARE().  The prototypes for hashing functions are instantiated
 * with macro HEAP_PROTOS().  The implementation is instantiated with
 * macro HEAP_BODIES().
 *
 * The hash table template is most efficient when the hash value is
 * precalculated and stored in each entry.  The hash "function" given to the
 * HEAP_BODIES() would then be something like macro
 * @code
 * #define HEAP_ENTRY_HASH(e) ((e).e_hash_value)
 * @endcode
 *
 * When a entry with new identical hash key is added to the table, it can be
 * either @e inserted (before any other entry with same key value) or
 * @e appended.
 * 
 * Example code can be found from <htable_test.c>.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 *
 * @date Created: Tue Sep 25 17:42:40 2001 ppessi
 *
 */

/** Minimum size of heap */
#define HEAP_MIN_SIZE 31

/** Declare heap structure type.
 * 
 * The macro HEAP_DECLARE() expands to a declaration for heap
 * structure.  The its typedef will be <em>prefix</em><code>_t</code>, the
 * field names start with @a pr.  The entry type is @a entrytype.
 *
 * @param sname     name of struct
 * @param pr        heap type prefix
 * @param entrytype entry type
 */
#define HEAP_DECLARE(sname, pr, entrytype)	\
struct sname { \
  unsigned pr##size; \
  unsigned pr##used; \
  entrytype *pr##heap; /**< Heap table itself */ \
}

/** Prototypes for heap.
 *
 * The macro HEAP_PROTOS() expands to the prototypes of heap
 * functions.  The function and type names start with @a prefix, the field
 * names start with @a pr.  The entry type is @a entrytype.
 *
 * @param scope     scope of functions
 * @param type      heap type or typedef
 * @param prefix    function prefix
 * @param entrytype entry type
 */
#define HEAP_PROTOS(scope, type, prefix, entrytype)	\
scope int prefix##resize(void *a, type pr[1], size_t); \
scope int prefix##is_full(type const *); \
scope int prefix##add(type *pr, entrytype e); \
scope int prefix##remove(type *, size_t index)

/** Hash table implementation.
 *
 * The macro HEAP_BODIES() expands the heap functions.  The function
 * and type names start with @a prefix, the field names start with @a pr.
 * The entry type is @a entrytype.  The function (or macro) name returning
 * hash value of each entry is given as @a hfun.
 *
 * @param scope     scope of functions
 * @param type      hash table type
 * @param prefix    function prefix for heap
 * @param pr        field prefix for heap structure
 * @param entrytype type of element
 * @param cmp       function or macro comparing two entries
 * @param set       function or macro assigning entry to array
 * @param halloc    function allocating or freeing memory
 */
#define HEAP_BODIES(scope, type, prefix, pr, entrytype, cmp, set, alloc) \
/** Resize heap. */ \
scope int prefix##resize(void *realloc_arg, \
			  type pr[1],	     \
			  size_t new_size)   \
{ \
  entrytype *heap; \
  size_t bytes; \
 \
  (void)realloc_arg; \
 \
  if (new_size == 0) \
    new_size = 2 * pr->pr##size + 1; \
  if (new_size < HEAP_MIN_SIZE) \
    new_size = HEAP_MIN_SIZE; \
 \
  bytes = new_size * (sizeof heap[0]); \
 \
  heap = alloc(realloc_arg, pr->pr##heap, bytes); \
  if (!heap) \
    return -1; \
 \
  pr->pr##size = new_size; \
  if (pr->pr##used > new_size) \
    pr->pr##used = new_size; \
  pr->pr##heap = heap; \
 \
  return 0; \
} \
 \
/** Check if heap is full */ \
scope \
int prefix##is_full(type const *pr) \
{ \
  return pr->pr##heap == NULL || pr->pr##used >= pr->pr##size; \
} \
 \
/** Sort heap from element at index upwards */ \
scope \
void prefix##sort(type *pr, size_t index) \
{ \
  size_t top, left, right; \
  entrytype *heap = pr->pr##heap; \
  size_t used = pr->pr##used; \
 \
  top = index; \
 \
  for (;;) { \
    entrytype swap; \
 \
    left = 2 * top; \
    right = left + 1; \
 \
    if (left < used && cmp(heap[top], heap[left]) > 0) \
      top = left; \
    if (right < used && cmp(heap[top], heap[right]) > 0) \
      top = right; \
 \
    if (top == index) \
      break; \
 \
    swap = heap[index]; \
    set(heap, index, heap[top]); \
    set(heap, top, swap); \
    index = top; \
  } \
} \
 \
/** Add an element to the heap */ \
scope \
int prefix##add(type *pr, entrytype e) \
{ \
  size_t i, parent; \
  entrytype *heap = pr->pr##heap; \
 \
  if (pr->pr##used >= pr->pr##size) \
    return -1; \
 \
  for (i = pr->pr##used++; i > 0; i = parent) { \
    parent = i / 2; \
    if (cmp(e, heap[parent]) >= 0) \
      break; \
    set(heap, i, heap[parent]); \
  } \
 \
  set(heap, i, e); \
 \
  return 0; \
} \
 \
/** Remove element from heap */ \
scope \
int prefix##remove(type *pr, size_t index) \
{ \
  entrytype *heap = pr->pr##heap; \
 \
  if (index >= pr->pr##used) \
    return -1; \
 \
  set(heap, index, heap[--pr->pr##used]); \
 \
  prefix##sort(pr, index); \
 \
  return 0; \
} \
extern int const prefix##dummy

#endif /** !defined(HEAP_H) */
