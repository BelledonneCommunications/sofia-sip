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

/**@ingroup su_alloc
 * 
 * @file su_alloc_test.c
 *
 * Testing functions for su_alloc functions.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * 
 * @date Created: Thu May  2 18:17:46 2002 ppessi
 * $Date: 2005/08/17 14:43:13 $
 */

#include "config.h"

const char su_alloc_test_c_id[] =
"$Id: su_alloc_test.c,v 1.2 2005/08/17 14:43:13 ppessi Exp $";

#include <stdio.h>
#include <string.h>

#include <su_alloc.h>
#include <su_strlst.h>

#define TSTFLAGS tstflags
#include <tstdef.h>

int tstflags;

char const *name = "su_alloc_test";

static int test_alloc(void);
static int test_strdupcat(void);
static int test_strlst(void);
static int test_vectors(void);

void usage(void)
{
  fprintf(stderr, "usage: %s [-v]\n", name);
}

int main(int argc, char *argv[])
{
  int retval = 0;
  int i;

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      tstflags |= tst_verbatim;
    else
      usage();
  }
  
  retval |= test_alloc();
  retval |= test_strdupcat();
  retval |= test_strlst();
  retval |= test_vectors();

  return retval;
}

/** Test tl_list and tl_dup */
int test_alloc(void)
{
  su_home_t *h0, *h1, *h2, *h3;
  su_home_t home[1] = { SU_HOME_INIT(home) };
  enum { N = 40 };
  void *m0[N], *m1[N], *m;
  char *c, *c0, *p0, *p1;
  int i;

  BEGIN();

  TEST_1(h0 = su_home_new(sizeof(*h0)));
  TEST_1(h1 = su_home_clone(h0, sizeof(*h1)));
  TEST_1(h2 = su_home_ref(h0));
  su_home_unref(h0);
  su_home_unref(h2);

  TEST_1(h0 = su_home_new(sizeof(*h0)));
  TEST_1(h1 = su_home_clone(h0, sizeof(*h1)));
  TEST_1(h2 = su_home_clone(h1, sizeof(*h2)));
  TEST_1(h3 = su_home_clone(h2, sizeof(*h3)));

  TEST(su_home_threadsafe(h0), 0);

  for (i = 0; i < N; i++) {
    TEST_1(m0[i] = su_zalloc(h3, 20));
    TEST_1(m1[i] = su_zalloc(h2, 20));
  }

  TEST_1(m = su_zalloc(h2, 20));

  TEST(su_home_move(home, NULL), 0);
  TEST(su_home_move(NULL, home), 0);
  TEST(su_home_move(home, h3), 0);
  TEST(su_home_move(h2, h3), 0);
  TEST(su_home_move(h1, h2), 0);

  su_home_preload(home, 1, 1024 + 2 * 8);

  TEST_1(c = su_zalloc(home, 64)); p0 = c; p1 = c + 1024;
  TEST(c = su_realloc(home, c0 = c, 127), c0); 

  TEST_1(c = c0 = su_zalloc(home, 1024 - 128)); 
  TEST_1(p0 <= c); TEST_1(c < p1);
  TEST(c = su_realloc(home, c, 128), c0);
  TEST(c = su_realloc(home, c, 1023 - 128), c0);
  TEST(c = su_realloc(home, c, 1024 - 128), c0);
  TEST_1(c = su_realloc(home, c, 1024));
  TEST_1(c = su_realloc(home, c, 2 * 1024));

  TEST(c = su_realloc(home, p0, 126), p0);
  TEST_1(c = su_realloc(home, p0, 1024));
  TEST(c = su_realloc(home, c, 0), NULL);

  su_home_check(home);
  su_home_deinit(home);

  su_home_check(h0);
  su_home_zap(h2);
  su_home_check(h0);
  su_home_zap(h0);

  END();
}

static int test_strdupcat(void)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };

  BEGIN();

  TEST_S(su_strdup(home, "foo"), "foo");
  TEST_S(su_strcat(home, "foo", "bar"), "foobar");
  TEST_S(su_strndup(home, "foobar", 3), "foo");

  su_home_deinit(home);
  
  END();
}

static int test_strlst(void)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  su_strlst_t *l, *l1, *l2;
  char *s;
  char foo[] = "foo";
  char bar[] = "bar";
  char baz[] = "baz";

  BEGIN();

  /* Test API for invalid arguments */
  TEST_1(l = su_strlst_create(NULL));
  TEST_1(l2 = su_strlst_dup(home, l));
  TEST_VOID(su_strlst_destroy(l2));
  TEST_1(!su_strlst_dup(home, NULL));
  TEST_1(l1 = su_strlst_copy(home, l));
  TEST_VOID(su_strlst_destroy(l1));
  TEST_1(!su_strlst_copy(home, NULL));

  TEST_VOID(su_strlst_destroy(NULL));
  TEST_VOID(su_strlst_destroy(l));

  TEST_1(!su_strlst_dup_append(NULL, "aa"));
  TEST_1(!su_strlst_append(NULL, "bee"));
  TEST_1(!su_strlst_item(NULL, 1));
  TEST_1(!su_strlst_set_item(NULL, 1, "cee"));
  TEST_1(!su_strlst_remove(NULL, 1));
  TEST_S(s = su_strlst_join(NULL, home, "a"), "");
  TEST_VOID(su_free(home, s));

  TEST_1(!su_strlst_split(home, NULL, "."));

  TEST_1(s = su_strdup(home, "aaa"));
  TEST_1(l = su_strlst_split(home, s, NULL));
  TEST_S(su_strlst_item(l, 0), "aaa");
  TEST_VOID(su_strlst_destroy(l));

  TEST_VOID(su_free(home, s));

  TEST_1(!su_strlst_dup_split(home, NULL, "."));

  TEST_1(l1 = su_strlst_dup_split(home, "aaa", ""));
  TEST_S(su_strlst_item(l1, 0), "aaa");
  TEST_VOID(su_strlst_destroy(l1));

  TEST(su_strlst_len(NULL), 0);
  TEST_1(!su_strlst_get_array(NULL));
  TEST_VOID(su_strlst_free_array(NULL, NULL));


  TEST_1(l = su_strlst_create(home));
  TEST_VOID(su_strlst_free_array(l, NULL));
  TEST_S(su_strlst_dup_append(l, "oh"), "oh");
  TEST_VOID(su_strlst_free_array(l, NULL));
  TEST_VOID(su_strlst_destroy(l));

  /* Test functionality */
  TEST_1(l = su_strlst_create(home));
  TEST_S(su_strlst_join(l, home, "bar"), "");  
  TEST_S(su_strlst_append(l, foo), "foo");
  TEST_S(su_strlst_dup_append(l, bar), "bar");
  TEST_S(su_strlst_append(l, baz), "baz");
  TEST_S((s = su_strlst_join(l, home, "!")), "foo!bar!baz");  

  TEST_S(su_strlst_item(l, 0), foo);
  TEST_S(su_strlst_item(l, 1), bar);
  TEST_S(su_strlst_item(l, 2), baz);
  TEST(su_strlst_item(l, 3), NULL);
  TEST(su_strlst_item(l, (unsigned)-1), NULL);

  TEST_1(l1 = su_strlst_copy(su_strlst_home(l), l));
  TEST_1(l2 = su_strlst_dup(su_strlst_home(l), l));
    
  strcpy(foo, "hum"); strcpy(bar, "pah"); strcpy(baz, "hah");
    
  TEST_S((s = su_strlst_join(l, home, ".")), "hum.bar.hah");  
  TEST_S((su_strlst_join(l1, home, ".")), "hum.bar.hah");  
  TEST_S((su_strlst_join(l2, home, ".")), "foo.bar.baz");  

  su_strlst_destroy(l);

  TEST_S(s, "hum.bar.hah");

  TEST_1(l = su_strlst_create(home));
  TEST_S(su_strlst_join(l, home, "bar"), "");
  TEST_S(su_strlst_append(l, "a"), "a");
  TEST_S(su_strlst_append(l, "b"), "b");
  TEST_S(su_strlst_append(l, "c"), "c");
  TEST_S(su_strlst_append(l, "d"), "d");
  TEST_S(su_strlst_append(l, "e"), "e");
  TEST_S(su_strlst_append(l, "f"), "f");
  TEST_S(su_strlst_append(l, "g"), "g");
  TEST_S(su_strlst_append(l, "h"), "h");
  TEST_S(su_strlst_append(l, "i"), "i");
  TEST_S(su_strlst_append(l, "j"), "j");

  TEST_S((s = su_strlst_join(l, home, "")), "abcdefghij");  
  TEST_S(su_strlst_append(l, "a"), "a");
  TEST_S(su_strlst_append(l, "b"), "b");
  TEST_S(su_strlst_append(l, "c"), "c");
  TEST_S(su_strlst_append(l, "d"), "d");
  TEST_S(su_strlst_append(l, "e"), "e");
  TEST_S(su_strlst_append(l, "f"), "f");
  TEST_S(su_strlst_append(l, "g"), "g");
  TEST_S(su_strlst_append(l, "h"), "h");
  TEST_S(su_strlst_append(l, "i"), "i");
  TEST_S(su_strlst_append(l, "j"), "j");

  TEST_S((s = su_strlst_join(l, home, "")), "abcdefghijabcdefghij");  

  su_strlst_destroy(l);
    
  su_home_check(home);
  su_home_deinit(home);

  su_home_init(home);

  {
    char s[] = "foo\nfaa\n";
    TEST_1((l = su_strlst_split(home, s, "\n")));
    TEST(su_strlst_len(l), 3);
    TEST_1(su_strlst_append(l, "bar"));
    TEST_S(su_strlst_join(l, home, "\n"), "foo\nfaa\n\nbar");
  }

  {
    char s[] = "foo";
    TEST_1((l = su_strlst_split(home, s, "\n")));
    TEST(su_strlst_len(l), 1);
  }

  {
    char s[] = "\n\n";
    TEST_1((l = su_strlst_split(home, s, "\n")));
    TEST(su_strlst_len(l), 3);
  }

  {
    char s[] = "";
    TEST_1((l = su_strlst_split(home, s, "\n")));
    TEST(su_strlst_len(l), 1);
  }
  
  {
    int i;

#define S \
      "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\n" \
      "n\no\np\nq\nr\ns\nt\nu\nv\nw\nx\ny\nz\n" \
      "A\nB\nC\nD\nE\nF\nG\nH\nI\nJ\nK\nL\nM\n" \
      "N\nO\nP\nQ\nR\nS\nT\nU\nV\nW\nX\nY\nZ\n"

    char s[] = S;

    TEST_1((l = su_strlst_split(home, s, "\n")));
    TEST(su_strlst_len(l), 53);
    TEST_1(su_strlst_append(l, "bar"));
    TEST_S(su_strlst_join(l, home, "\n"), S "\nbar");

    TEST_1(!su_strlst_remove(l, 54));

    for (i = 0; i < 54; i++) {
      TEST_1(su_strlst_remove(l, 0));
      TEST_1(!su_strlst_remove(l, 53 - i));
      TEST(su_strlst_len(l), 53 - i);
    }

    TEST_1(!su_strlst_remove(l, 0));
    TEST(su_strlst_len(l), 0);
  }

  su_home_deinit(home);

  END();
}

#include <su_vector.h>

typedef struct test_data_s {
  su_home_t test_home[1];
  int data;
} test_data_t;

static void test_vector_free(void *data)
{
  su_home_zap((su_home_t *) data);
}

static int test_vectors(void)
{
  su_home_t home[1] = { SU_HOME_INIT(home) };
  su_vector_t *v, *w;
  test_data_t *data1, *data2, *data3, *data4;
  char foo[] = "foo";
  char bar[] = "bar";
  char baz[] = "baz";
  void **a;
  int i;

  BEGIN();

  TEST_1(v = su_vector_create(home, NULL));
  TEST_1(su_vector_is_empty(v));
  TEST(su_vector_append(v, foo), 0);
  TEST(su_vector_append(v, bar), 0);
  TEST(su_vector_insert(v, 0, baz), 0);

  TEST(su_vector_item(v, 0), baz);
  TEST(su_vector_item(v, 1), foo);
  TEST(su_vector_item(v, 2), bar);
  TEST(su_vector_item(v, 3), NULL);
  TEST(su_vector_item(v, (unsigned)-1), NULL);
  TEST_1(!su_vector_is_empty(v));
    
  su_vector_destroy(v);

  TEST_1(v = su_vector_create(home, NULL));
  TEST(su_vector_insert(v, 0, "j"), 0);
  TEST(su_vector_insert(v, 0, "i"), 0);
  TEST(su_vector_insert(v, 0, "h"), 0);
  TEST(su_vector_insert(v, 0, "g"), 0);
  TEST(su_vector_insert(v, 0, "f"), 0);
  TEST(su_vector_insert(v, 0, "e"), 0);
  TEST(su_vector_insert(v, 0, "d"), 0);
  TEST(su_vector_insert(v, 0, "c"), 0);
  TEST(su_vector_insert(v, 0, "b"), 0);
  TEST(su_vector_insert(v, 0, "a"), 0);

  TEST(su_vector_len(v), 10);
  TEST_1(a = su_vector_get_array(v));

  for (i = 0; i < 10; i++) {
    TEST_S(su_vector_item(v, i), a[i]);
  }

  TEST(su_vector_item(v, 10), NULL);
  TEST(a[10], NULL);

  TEST_1(w = su_vector_create(home, NULL));
  TEST(su_vector_append(w, "a"), 0);
  TEST(su_vector_append(w, "b"), 0);
  TEST(su_vector_append(w, "c"), 0);
  TEST(su_vector_append(w, "d"), 0);
  TEST(su_vector_append(w, "e"), 0);
  TEST(su_vector_append(w, "f"), 0);
  TEST(su_vector_append(w, "g"), 0);
  TEST(su_vector_append(w, "h"), 0);
  TEST(su_vector_append(w, "i"), 0);
  TEST(su_vector_append(w, "j"), 0);

  TEST(su_vector_len(w), 10);

  for (i = 0; i < 10; i++) {
    TEST_S(su_vector_item(v, i), a[i]);
  }

  su_vector_empty(w);
  TEST_1(su_vector_is_empty(w));

  su_vector_destroy(v);
  su_vector_destroy(w);
    
  TEST_1(v = su_vector_create(home, test_vector_free));
  data1 = su_home_clone(home, sizeof(test_data_t));
  data1->data = 1;

  data2 = su_home_clone(home, sizeof(test_data_t));
  data2->data = 2;

  data3 = su_home_clone(home, sizeof(test_data_t));
  data3->data = 3;

  data4 = su_home_clone(home, sizeof(test_data_t));
  data4->data = 4;

  TEST(su_vector_append(v, data1), 0);
  TEST(su_vector_append(v, data2), 0);
  TEST(su_vector_append(v, data3), 0);
  TEST(su_vector_append(v, data4), 0);  

  TEST(su_vector_len(v), 4);

  TEST(su_vector_item(v, 0), data1);
  TEST(su_vector_item(v, 1), data2);
  TEST(su_vector_item(v, 2), data3);
  TEST(su_vector_item(v, 3), data4);

  TEST(data1->data, 1);
  TEST(data2->data, 2);
  TEST(data3->data, 3);
  TEST(data4->data, 4);

  TEST(su_vector_remove(v, 2), 0);

  TEST(su_vector_len(v), 3);

  TEST(su_vector_item(v, 0), data1);
  TEST(su_vector_item(v, 1), data2);
  TEST(su_vector_item(v, 2), data4);

  TEST(data1->data, 1);
  TEST(data2->data, 2);
  TEST(data4->data, 4);

  su_vector_destroy(v);

  su_home_check(home);
  su_home_deinit(home);

  END();
}
