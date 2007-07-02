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
int cmp_entry(entrytype a, entrytype b)
{
  if (a.key < b.key)
    return -1;
  else if (a.key > b.key)
    return 1;
  else
    return 0;
}

static inline
void set_entry(entrytype *heap, size_t index, entrytype entry)
{
  entry.index = index;
  heap[index] = entry;
}  

#define alloc(a, o, size) realloc((o), (size))

HEAP_BODIES(static inline, Heap, heapXX_, pr_, entrytype,
	    cmp_entry, set_entry, alloc);

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

  memset(heap, 0, sizeof heap);

  TEST(heapXX_resize(NULL, heap, 0), 0);

  N = 300000;

  /* Add N entries in reverse order */

  for (i = N; i > 0; i--) {
    entrytype e = { i / 10, i };
    if (heapXX_is_full(heap))
      TEST(heapXX_resize(NULL, heap, 0), 0);
    TEST(heapXX_is_full(heap), 0);
    TEST(heapXX_add(heap, e), 0);
  }

  TEST(heap->pr_used, N);

  for (i = 0; i < N; i++) {
    TEST(heap->pr_heap[i].index, i);
  }

  for (i = 0; i < N; i++) {
    heapXX_sort(heap, i);
  }

  for (i = 0; i < N; i++) {
    TEST(heap->pr_heap[i].index, i);
  }

  /* Remove N entries */
  previous = 0;

  for (n = 0; heap->pr_used > 0; n++) {
    TEST_1(previous <= heap->pr_heap[0].key);
    previous = heap->pr_heap[0].key;
    heapXX_remove(heap, 0);
  }
  TEST(n, N);

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
