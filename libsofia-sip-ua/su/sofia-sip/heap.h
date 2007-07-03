/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2007 Nokia Corporation.
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
 * Heap implemented with dynamic array.
 *
 * This file contain template macros implementing heap in C. The @a heap
 * keeps its element in a known order and it can be used to implement, for
 * example, a prioritye queue or an ordered queue. 
 *
 * The ordering within the heap is defined as follows:
 * - for each element with index @a [i] in the heap there are two descendant
 *   elements with indices @a [2*i+1] and @a [2*i+2],
 * - the heap guarantees that the descendant elements are never smaller than
 *   their parent element.
 * There is no element smaller than element at index [0] in the
 * rest of the heap.
 *
 * Adding and removing elements to the heap is an @a O(logN)
 * operation.
 *
 * The heap array is resizeable, and it usually contain pointers to the
 * actual entries. The template macros define two functions used to add and
 * remove entries to the heap. The @a add() function takes the element to be
 * added as its argument, the @a remove() function the index of the element
 * to be removed. The template defines also a predicate used to check if the
 * heap is full, and a function used to resize the heap.
 *
 * The heap user must define three primitives: 
 * - less than comparison 
 * - array setter
 * - heap array allocator
 *
 * Please note that in order to remove an entry in the heap, the application
 * must know its index in the heap array. 
 *
 * The heap struct is declared with macro HEAP_DECLARE(). The prototypes for
 * heap functions are instantiated with macro HEAP_PROTOS(). The
 * implementation is instantiated with macro HEAP_BODIES().
 *
 * Example code can be found from <su/torture_heap.c> and
 * <sresolv/sres_cache.c>.
 * 
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>.
 * @NEW_1_12_7.
 */

/** Minimum size of heap */
#define HEAP_MIN_SIZE 31

/** Declare heap structure type.
 * 
 * The macro HEAP_DECLARE() expands to the declaration of the heap
 * structure. The field names start with @a pr. The type of heap array
 * element is @a entrytype.
 *
 * @param sname     name of struct
 * @param pr        heap type prefix
 * @param entrytype entry type
 * 
 * @showinitializer
 */
#define HEAP_DECLARE(sname, pr, entrytype)	\
struct sname { \
  size_t pr##size;     /**< Number of elements in pr##heap */ \
  size_t pr##used;     /**< Number of elements used from pr##heap */ \
  entrytype *pr##heap; /**< Array of entries in the heap */ \
}

/** Prototypes for heap.
 *
 * The macro HEAP_PROTOS() expands to the prototypes of heap functions:
 * - prefix ## resize(argument, heap, size)
 * - prefix ## is_full(heap)
 * - prefix ## add(heap, entry)
 * - prefix ## remove(heap, index)
 *
 * @param scope     scope of functions
 * @param type      heap type or typedef
 * @param prefix    function prefix
 * @param entrytype entry type
 * 
 * The declared functions will have scope @a scope (for example, @c static
 * or @c static inline). The declared function names will have prefix @a
 * prefix. The heap structure has type @a type. The heap element type is @a
 * entrytype.
 *
 * @showinitializer
 */
#define HEAP_PROTOS(scope, type, prefix, entrytype)	\
scope int prefix##resize(void *argument, type heap[1], size_t size); \
scope int prefix##is_full(type const *heap); \
scope int prefix##add(type *heap, entrytype entry); \
scope int prefix##remove(type *heap, size_t index)

/**Heap implementation.
 *
 * The macro HEAP_BODIES() expands to the bodies of heap functions:
 * - prefix ## resize(argument, heap, size)
 * - prefix ## is_full(heap)
 * - prefix ## add(heap, entry)
 * - prefix ## remove(heap, index)
 *
 * @param scope     scope of functions
 * @param type      hash table type
 * @param prefix    function prefix for heap
 * @param pr        field prefix for heap structure
 * @param entrytype type of element
 * @param less      function or macro comparing two entries
 * @param set       function or macro assigning entry to array
 * @param halloc    function allocating or freeing memory
 *
 * Functions have scope @a scope, e.g., @c static @c inline.
 * The heap structure has type @a type.
 * The function names start with @a prefix, the field names start
 * with @a pr. The entry type is @a entrytype. 

 * The function (or macro) @a less compares two entries in heap. It gets two
 * arguments and it returns true if its left argument is less than its right
 * argument.

 * The function (or macro) @a set stores an entry in heap array. It gets
 * three arguments, first is heap array, second index to the array and third
 * the element to store at the given index.
 *
 * The function (or macro) @a halloc re-allocates the heap array. It
 * receives three arguments, first is the first @a argument given to @a
 * resize(), second the pointer to existing heap and third is the number of
 * bytes in the heap.
 */
#define HEAP_BODIES(scope, type, prefix, pr, entrytype, less, set, alloc) \
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
    parent = (i - 1) / 2; \
    if (!less(e, heap[parent])) \
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
  entrytype e; \
  size_t top, left, right;   \
  size_t used = pr->pr##used; \
\
  if (index >= used) \
    return -1; \
\
  pr->pr##used = --used; \
  top = index; \
\
  for (;;) { \
    left = 2 * top + 1; \
    right = 2 * top + 2; \
\
    if (right >= used) \
      break; \
    if (less(heap[right], heap[left])) \
      top = right; \
    else \
      top = left; \
    set(heap, index, heap[top]); \
    index = top; \
  } \
\
  if (index == used) \
    return 0; \
\
  e = heap[used]; \
  for (; index > 0; index = top) { \
    top = (index - 1) / 2; \
    if (!less(e, heap[top])) \
      break; \
    set(heap, index, heap[top]); \
  } \
\
  set(heap, index, e); \
\
  return 0; \
} \
extern int const prefix##dummy_heap

#endif /** !defined(SOFIA_SIP_HEAP_H) */
