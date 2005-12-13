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

/**
 * @file torture_stun.c STUN module testing
 * 
 * @author Tat Chan <Tat.Chan@nokia.com>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Ismo H. Puustinen
 *
 * @date Created: Thu Jul 24 17:21:00 2003 ppessi
 * @date Last modified: Wed Jul 20 20:35:55 2005 kaiv
 *
 * Examples of use:
 *
 * sh> ./torture_stun -c local-IP -s sip-stun.openlaboratory.net -v
 * sh> ./torture_stun -c local-IP -s sip-stun.openlaboratory.net -l
 */

#include "config.h" 

#include <stdio.h>
#include <string.h>

typedef struct torture_s torture_t;
#define SU_ROOT_MAGIC_T  torture_t
#define STUN_MAGIC_T     torture_t

#include "stun.h"

#include <su.h>
#include <su_debug.h>

#define TSTFLAGS tstflags
#include <tstdef.h>


struct torture_s {
  int kakka;
};

char const *name = "torture_stun";

static int test_init(su_root_t *root, char *addr);
static int test_sync_stun(char *addr);
static int test_get_nattype(char *addr);
static int test_get_lifetime(char *addr);

static int test_deinit(void);
int atonetaddr(struct sockaddr_in *addr, char *in);

void usage(void)
{
  fprintf(stderr, "usage: %s [-v] [-c clientip[:port]] [-s serverip[:port]] [-f] [-n] [-l] [-b]\n", name);
  fprintf(stderr, "-v: test basic STUN binding.\n");
  fprintf(stderr, "-n: test NAT type determination.\n");
  fprintf(stderr, "-l: test lifetime determination.\n");
  fprintf(stderr, "-f: use fake username/password for message integrity.\n");
  fprintf(stderr, "-b: bypass message integrity.\n");
}

int tstflags = 0;
int test_bind = 0;
int test_nat = 0;
int test_lifetime = 0;
int fake_msg_int=0; /* use fake username password */
int bypass_msg_int=0; 

int main(int argc, char *argv[])
{

  torture_t torture[1];
  su_root_t *root = su_root_create(torture);
  int retval = 0;
  int i;
  char *clntaddr = "127.0.0.1", *srvraddr = "127.0.0.1";

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      /*      tstflags |= tst_verbatim; */
      test_bind = 1;
    else if(strcmp(argv[i], "-c") == 0) 
      clntaddr = argv[++i];
    else if(strcmp(argv[i], "-s") == 0)
      srvraddr = argv[++i];
    else if(strcmp(argv[i], "-f") == 0)
      fake_msg_int = 1; /* test message integrity, use normal
			   procedure otherwise */
    else if(strcmp(argv[i], "-n") == 0)
      test_nat = 1; /* test nat type */
    else if(strcmp(argv[i], "-l") == 0)
      test_lifetime = 1; /* test life time */
    else if(strcmp(argv[i], "-b") == 0)
      bypass_msg_int = 1;
    else {
      usage();
      return -1;
    }
  }

  if(!test_bind && !test_nat && !test_lifetime) {usage(); return -1;}

  if (!(retval |= test_init(root, srvraddr))) {
    su_root_run(root);
    if(test_bind) {
      retval |= test_sync_stun(clntaddr);
    }
    if(test_nat) {
      retval |= test_get_nattype(clntaddr);
    }
    if(test_lifetime) {
      retval |= test_get_lifetime(clntaddr);
    }
  }

  test_deinit();

  return retval;
}

stun_engine_t *se;

void torture_callback(torture_t *torturer, stun_engine_t *en, stun_states_t ev);


void torture_callback(torture_t *torturer, stun_engine_t *en, stun_states_t ev)
{
  SU_DEBUG_3(("%s: called\n", __func__));

  su_root_break(stun_engine_root(en));

  return;
}

int test_init(su_root_t *root, char *server)
{

  torture_t torturer[1];
  BEGIN();

  /* Running this test requires a local STUN server on default port */
  se = stun_engine_create(torturer,
			  root,
			  torture_callback,
			  server, !bypass_msg_int); TEST_1(se);

  END();
}

int test_sync_stun(char *localaddr)
{
  int result;
  int s, lifetime;
  socklen_t addrlen, locallen;
  su_localinfo_t addr;
  stun_socket_t *ss;
  struct sockaddr_in *my_addr, local;

  BEGIN();

  s = socket(AF_INET, SOCK_DGRAM, 0); TEST_1(s != -1);

  ss = stun_socket_create(se, s); TEST_1(ss != NULL);

  /* test message integrity? */
  if(fake_msg_int) {
    FILE *pwd;
    
    pwd = fopen("pwd.txt", "r");
    if(pwd) {
      char username[256], password[256];
      if(fscanf(pwd, "\"%[^\"]\",\"%[^\"]\"", username, password)) {
	printf("Read username, password from pwd.txt: \"%s\", \"%s\"\n", username, password);
	stun_set_uname_pwd(se, username, (int)strlen(username), password, (int)strlen(password));
      }
      fclose(pwd);
    }
  }
  
  memset(&addr, 0, sizeof(addr));
  /* addrlen = sizeof(addr); */
  lifetime = 0;

  my_addr = (struct sockaddr_in *) &addr.li_addr;

  atonetaddr(my_addr, localaddr);
  /*
  my_addr->sin_addr.s_addr = inet_addr(localaddr);
  my_addr->sin_family = AF_INET;
  my_addr->sin_port = 0;
  */
  
  addrlen = sizeof(*my_addr);
  result = stun_bind(ss, &addr, &lifetime); TEST(result, 0);

  /* Just a check that getsockname() returns same address as stun_bind */
  memset(&local, 0, sizeof(local)); locallen = sizeof(local);
  
  TEST(getsockname(s, (struct sockaddr *)&local, &locallen), 0);
  TEST(locallen, addrlen);
  my_addr = (struct sockaddr_in *) &addr.li_addr;

  printf("*** stun_bind returns %s:%u\n", inet_ntoa(my_addr->sin_addr), (unsigned)ntohs(my_addr->sin_port));
  printf("*** getsockname returns %s:%u\n", inet_ntoa(local.sin_addr), (unsigned)ntohs(local.sin_port));

  TEST(memcmp(&local, (struct sockaddr_in *)&addr.li_addr, 8), 0); 

  su_close(s);

  END();
}

int test_get_lifetime(char *localaddr)
{
  int result, lifetime;
  int s, addrlen;
  su_localinfo_t addr;
  stun_socket_t *ss;
  su_localinfo_t *my_addr;

  BEGIN();

  s = socket(AF_INET, SOCK_DGRAM, 0); TEST_1(s != -1);

  ss = stun_socket_create(se, s); TEST_1(ss != NULL);

  /* test message integrity? */
  if(fake_msg_int) {
    FILE *pwd;
    
    pwd = fopen("pwd.txt", "r");
    if(pwd) {
      char username[256], password[256];
      if(fscanf(pwd, "\"%[^\"]\",\"%[^\"]\"", username, password)) {
	printf("Read username, password from pwd.txt: \"%s\", \"%s\"\n", username, password);
	stun_set_uname_pwd(se, username, strlen(username), password, strlen(password));
      }
      fclose(pwd);
    }
  }
  
  memset(&addr, 0, sizeof(addr)); /* addrlen = sizeof(addr); */

  my_addr = &addr.li_addr;

  atonetaddr(my_addr, localaddr);
  addrlen = sizeof(*my_addr);
  result = stun_get_lifetime(ss, &addr.li_addr, &addrlen, &lifetime); TEST(result, 0);
  printf("Binding Lifetime determined to be: %d seconds\n", lifetime);

  su_close(s);

  END();
}



int test_get_nattype(char *localaddr)
{
  int result;
  int s, addrlen;
  su_sockaddr_t addr;
  stun_socket_t *ss;
  struct sockaddr_in *my_addr;

  BEGIN();

  s = socket(AF_INET, SOCK_DGRAM, 0); TEST_1(s != -1);

  ss = stun_socket_create(se, s); TEST_1(ss != NULL);

  /* test message integrity? */
  /* test message integrity? */
  if(fake_msg_int) {
    FILE *pwd;
    
    pwd = fopen("pwd.txt", "r");
    if(pwd) {
      char username[256], password[256];
      if(fscanf(pwd, "\"%[^\"]\",\"%[^\"]\"", username, password)) {
	printf("Read username, password from pwd.txt: \"%s\", \"%s\"\n", username, password);
	stun_set_uname_pwd(se, username, strlen(username), password, strlen(password));
      }
      fclose(pwd);
    }
  }
  
  memset(&addr, 0, sizeof(addr)); /* addrlen = sizeof(addr); */

  my_addr = (struct sockaddr_in *)&addr.su_sa;

  atonetaddr(my_addr, localaddr);
  addrlen = sizeof(*my_addr);
  result = stun_get_nattype(ss, &addr.su_sa, &addrlen); TEST(result, 0);
  printf("NAT type is: %s\n", stun_nattype(se));

  su_close(s);

  END();
}

#include <poll.h>

/* XXX: Not used in the test set yet. */
#if 0
/*
 * Run test asynchronously (with non-blocking socket).
 * stun_bind() is called repeteadly until it returns 0 (or -1 with errno 
 * something else than EAGAIN), poll() is called meanwhile in order to wait
 * data from server.
 */
int test_async_stun(void)
{
  int result;
  int s, lifetime;
  socklen_t addrlen, locallen;
  su_sockaddr_t addr, local;
  stun_socket_t *ss;

  BEGIN();

  s = socket(AF_INET, SOCK_DGRAM, 0); TEST_1(s != -1);
  
  ss = stun_socket_create(se, s); TEST_1(ss != NULL);
  
  memset(&addr, 0, sizeof(addr)); addrlen = sizeof(addr);
  lifetime = 0;

  su_setblocking(s, 0);		/* non-blocking socket */

  for (;;) {
    struct pollfd pollv[1];

    result = stun_bind(ss, &addr.su_sa, &addrlen, &lifetime);
    if (result == 0)
      break;
    if (errno != EAGAIN) {
      perror("stun_bind");
      break;
    }
    
    pollv->fd = s;
    pollv->events = POLLIN;

    poll(pollv, 1, 10 * 1000);
  }

  TEST(result, 0);

  memset(&local, 0, sizeof(local)); locallen = sizeof(local);
  
  TEST(getsockname(s, &local.su_sa, &locallen), 0);
  TEST(locallen, addrlen);

  TEST(memcmp(&local, &addr, locallen), 0);

  su_close(s);

  END();
}
#endif

static int test_deinit(void)
{
  BEGIN();

  stun_engine_destroy(se);

  END();
}

/* convert character address format to sockaddr_in */
/* this function is just for testing convenience within the scope of
 * torture_stun. It is only used by converting client address
 * input. Server address of the form "a.b.c.d:port" is passed directly to
 * stun_engine_create(). */
int atonetaddr(struct sockaddr_in *addr, char *in)
{
  char *p, tmp[64];
  int port_len;

  addr->sin_family = AF_INET;
  p = strstr(in, ":");
  if(p==NULL) {
    addr->sin_addr.s_addr = inet_addr(in);
    addr->sin_port = 0;
  }
  else {
    memcpy(tmp, in, p-in);
    tmp[p-in] = '\0';
    addr->sin_addr.s_addr = inet_addr(tmp);
    port_len = strlen(in)-(p-in)-1;
    memcpy(tmp, p+1, port_len);
    tmp[port_len] = '\0';
    addr->sin_port = htons(atoi(tmp));
  }
  return 0;
}
