#include "config.h"

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct {
  unsigned key, value;
  size_t index;
} entrytype;

#include <sofia-sip/heap.h>

typedef struct Heap Heap;

HEAP_DECLARE(Heap, pr_, entrytype);

HEAP_PROTOS(static inline, Heap, heapXX_, entrytype);

static inline
int less_than(entrytype a, entrytype b)
{
  return a.key < b.key;
}

static inline
void set_entry(entrytype *heap, size_t index, entrytype entry)
{
  entry.index = index;
  heap[index] = entry;
}  

#define alloc(a, o, size) realloc((o), (size))

HEAP_BODIES(static inline, Heap, heapXX_, pr_, entrytype,
	    less_than, set_entry, alloc);

/* ====================================================================== */

int tstflags;

#define TSTFLAGS tstflags

#include <sofia-sip/tstdef.h>

char name[] = "torture_heap";

int test_speed()
{
  BEGIN();
  
  Heap heap[1];
  unsigned i, previous, n, N;
  unsigned char *tests;

  N = 300000;

  memset(heap, 0, sizeof heap);

  TEST_1(tests = calloc(sizeof (unsigned char), N + 1));

  TEST(heapXX_resize(NULL, heap, 0), 0);

  /* Add N entries in reverse order */
  for (i = N; i > 0; i--) {
    entrytype e = { i / 10, i };
    if (heapXX_is_full(heap))
      TEST(heapXX_resize(NULL, heap, 0), 0);
    TEST(heapXX_is_full(heap), 0);
    TEST(heapXX_add(heap, e), 0);
    tests[i] |= 1;
  }

  TEST(heap->pr_used, N);

  for (i = 0; i < N; i++) {
    TEST(heap->pr_heap[i].index, i);
    TEST(tests[heap->pr_heap[i].value] & 2, 0);
    tests[heap->pr_heap[i].value] |= 2;
  }

  for (i = 0; i < N; i++) {
    size_t left = 2 * i + 1, right = left + 1;
    if (left < heap->pr_used)
      TEST_1(heap->pr_heap[i].key <= heap->pr_heap[left].key);
    if (right < heap->pr_used)
      TEST_1(heap->pr_heap[i].key <= heap->pr_heap[right].key);
  }

  for (i = 0; i < N; i++) {
    TEST(heap->pr_heap[i].index, i);
  }

  /* Remove N entries */
  previous = 0;

  for (n = 0; heap->pr_used > 0; n++) {
    TEST_1(previous <= heap->pr_heap[0].key);

    TEST(tests[heap->pr_heap[0].value] & 4, 0);
    tests[heap->pr_heap[0].value] |= 4;

    previous = heap->pr_heap[0].key;
    TEST(heapXX_remove(heap, 0), 0);
  }
  TEST(n, N);

  /* Add N entries in reverse order */
  for (i = N; i > 0; i--) {
    entrytype e = { i / 10, i };
    if (heapXX_is_full(heap))
      TEST(heapXX_resize(NULL, heap, 0), 0);
    TEST(heapXX_is_full(heap), 0);
    TEST(heapXX_add(heap, e), 0);
  }

  TEST(heap->pr_used, N);

  /* Remove 1000 entries from random places */
  previous = 0;

  for (i = 0; i < 1000 && heap->pr_used > 0; i++) {
    n = i * 397651 % heap->pr_used;
    TEST(tests[heap->pr_heap[n].value] & 8, 0);
    tests[heap->pr_heap[n].value] |= 8;
    TEST(heapXX_remove(heap, n), 0);
  }

  for (i = 0; i < N; i++) {
    size_t left = 2 * i + 1, right = left + 1;
    if (left < heap->pr_used)
      TEST_1(heap->pr_heap[i].key <= heap->pr_heap[left].key);
    if (right < heap->pr_used)
      TEST_1(heap->pr_heap[i].key <= heap->pr_heap[right].key);
  }

  /* Remove rest */
  for (n = 0, previous = 0; heap->pr_used > 0; n++) {
    TEST(tests[heap->pr_heap[0].value] & 8, 0);
    tests[heap->pr_heap[0].value] |= 8;
    TEST_1(previous <= heap->pr_heap[0].key);
    previous = heap->pr_heap[0].key;
    heapXX_remove(heap, 0);
  }

  for (i = 1; i <= N; i++) {
    TEST(tests[i], 8 | 4 | 2 | 1);
  }

  TEST(heapXX_resize(NULL, heap, 31), 0);

  END();
}

void usage(int exitcode)
{
  fprintf(stderr,
	  "usage: %s [-v] [-a]\n",
	  name);
  exit(exitcode);
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else if (strcmp(argv[i], "-a") == 0)
      tstflags |= tst_abort;
    else
      usage(1);
  }

  retval |= test_speed(); fflush(stdout);

  return retval;
}
