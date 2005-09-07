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

/**@internal
 *
 * @CFILE sdp_torture.c  
 *
 * Testing sdp module.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <kai.vehmanen@nokia.com>
 *
 * @date Created: Tue Mar  6 18:33:42 2001 ppessi
 * $Date: 2005/07/20 20:35:37 $
 */

#include "config.h"

const char sdp_torture_c_id[] =
"$Id: sdp_torture.c,v 1.1.1.1 2005/07/20 20:35:37 kaiv Exp $";

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <su_types.h>

#include <sdp.h>

#include <su_tag.h>
#include <su_tag_io.h>
#include <sdp_tag.h>

#define TSTFLAGS flags

#include <tstdef.h>

char const *name = "sdp_torture.c";

FILE *null;

static char const e0_msg[] = 
"foo";

static char const e1_msg[] = 
    "v=1\n"
    "s=/sdp_torture\n"
    "o=sdp_torture 0 0 IN IP4 0.0.0.0\n"
    "m=audio 0 RTP/AVP 96 97 98 10 99 8 0\n"
    "a=rtpmap:96 X-AMR-WB/16000\n"
    "a=rtpmap:97 X-AMR/8000\n"
    "a=rtpmap:98 GSM-EFR/8000\n"
    "a=rtpmap:10 L16/16000\n"
    "a=rtpmap:99 G723/8000\n"
    "a=rtpmap:8 PCMA/8000\n"
    "a=rtpmap:0 PCMU/8000\n"
    "m=video 0 *";

static int test_error(int flags)
{
  su_home_t *home = su_home_create();
  sdp_parser_t *parser;

  BEGIN();

  su_home_check(home); TEST0(home);

  TEST_1((parser = sdp_parse(home, e0_msg, sizeof(e0_msg), 0)));
  TEST_1(sdp_session(parser) == NULL);
  TEST_1(sdp_parsing_error(parser));
  sdp_parser_free(parser);

  TEST_1((parser = sdp_parse(home, e1_msg, sizeof(e1_msg), 0)));
  TEST_1(sdp_session(parser) == NULL);
  TEST_1(sdp_parsing_error(parser));
  sdp_parser_free(parser);


  /* destroy the home objects */
  su_home_check(home); su_home_zap(home);

  END();
}

static char const s0_msg[] = 
    "v=0\n"
    "s=/sdp_torture\n"
    "o=sdp_torture 0 0 IN IP4 0.0.0.0\n"
    "m=audio 0 RTP/AVP 96 97 98 10 99 8 0\n"
    "a=rtpmap:96 X-AMR-WB/16000\n"
    "a=rtpmap:97 X-AMR/8000\n"
    "a=rtpmap:98 GSM-EFR/8000\n"
    "a=rtpmap:10 L16/16000\n"
    "a=rtpmap:99 G723/8000\n"
    "a=rtpmap:8 PCMA/8000\n"
    "a=rtpmap:0 PCMU/8000\n"
    "m=video 0 *\n"
    "m=* 0 RTP/AVP *\n"
  ;

static int test_session(int flags)
{
  su_home_t *home = su_home_create(), *home2 = su_home_create();
  sdp_session_t *sdp_src, *sdp_target;
  sdp_session_t const *sdp = NULL;
  sdp_parser_t *parser;
  sdp_printer_t *printer;
  sdp_media_t *m;
  char buffer[512];
  tagi_t *lst, *dup;

  BEGIN();

  su_home_check(home);
  TEST_1(home);

  su_home_check(home2);
  TEST_1(home2);
  
  TEST_1((parser = sdp_parse(home, s0_msg, sizeof(s0_msg), sdp_f_config)));
  TEST_1((sdp_src = sdp_session(parser)));
  TEST_1(sdp_src->sdp_media);
  TEST_1(sdp_src->sdp_media->m_session);
  TEST(sdp_src->sdp_media->m_session, sdp_src);

  /* clone the session using 'home2' */
  TEST_1((sdp_target = sdp_session_dup(home2, sdp_src)));

  /* check the cloned session */
  TEST_1(sdp_target->sdp_subject);
  TEST_S(sdp_target->sdp_subject, "/sdp_torture");
  strcpy((char*)sdp_target->sdp_subject, "garbage");
  TEST_S(sdp_src->sdp_subject, "/sdp_torture");

  TEST_1(sdp_target->sdp_origin);
  TEST_1(sdp_target->sdp_origin->o_username);
  TEST_S(sdp_target->sdp_origin->o_username, "sdp_torture");
  strcpy((char*)sdp_target->sdp_origin->o_username, "garbage");
  TEST_S(sdp_src->sdp_origin->o_username, "sdp_torture");

  TEST_1(m = sdp_target->sdp_media);
  TEST_1(m->m_session);
  TEST(m->m_session, sdp_target);
  TEST_1(sdp_src->sdp_media->m_session != sdp_target->sdp_media->m_session);

  TEST(m->m_type, sdp_media_audio);
  TEST_S(m->m_type_name, "audio");
  TEST(m->m_port, 0);
  TEST(m->m_number_of_ports, 0);
  TEST(m->m_proto, sdp_proto_rtp);
  TEST_S(m->m_proto_name, "RTP/AVP");
  /* FIXME: add more tests */

  /* frees all data created by the parser including 'sdp_src' */
  sdp_parser_free(parser);

  /* destroy the first home instance */
  su_home_check(home);
  su_home_destroy(home);
    
  /* access all cloned data by printing it */
  printer = sdp_print(home2, sdp_target, buffer, sizeof(buffer), 0);
  if (printer != NULL) {
    char const *msg = sdp_message(printer);

    if (flags & tst_verbatim) {
      printf("sdp_torture.c: parsed SDP message:\"%s\".\n", msg);
    }
      
    sdp_printer_free(printer);
  }

  TEST_1(lst = tl_list(SDPTAG_SESSION(sdp_target), TAG_NULL()));

  TEST_1(dup = tl_adup(home2, lst));

  if (flags & tst_verbatim)
    tl_print(stdout, "dup:\n", dup);
  else
    tl_print(null, "dup:\n", dup);

  TEST(tl_gets(dup, SDPTAG_SESSION_REF(sdp), TAG_END()), 1);

  /* access all copied data by printing it */
  printer = sdp_print(home2, sdp, buffer, sizeof(buffer), 0);
  if (printer != NULL) {
    char const *msg = sdp_message(printer);
    if (flags & tst_verbatim) {
      printf("sdp_torture.c: "
	     "SDP message passed through tag list:\n\"%s\".\n", msg);
    }
    sdp_printer_free(printer);
  }

  su_free(home2, dup);
  tl_vfree(lst);

  /* destroy the second home object */
  su_home_check(home2);
  su_home_destroy(home2);

  END();
}

static char const s1_msg[] = 
  "v=0\r\n"
  "o=- 2435697 2435697 IN IP4 172.21.137.44\r\n"
  "s=-\r\n"
  "c=IN IP4 172.21.137.44\r\n"
  "t=0 0\r\n"
  "a=sendonly\r\n"
  "m=video 49154 RTP/AVP 96\r\n"
  "a=rtpmap:96 H263-1998/90000\r\n"
  "m=audio 49152 RTP/AVP 97\r\n"
  "a=rtpmap 97 AMR/8000\r\n"
  "a=fmtp:97 mode-set=\"0,1,2,3,4\"\r\n"
  "a=ptime:400\r\n";

static char const s2_msg[] = 
  "v=0\r\n"
  "o=- 308519342 2 IN IP4 172.168.1.55\r\n"
  "s=-\r\n"
  "c=IN IP4 172.168.1.55\r\n"
  "t=0 0\r\n"
  "a=recvonly\r\n"
  "m=video 59154 RTP/AVP 96\r\n"
  "b=AS:64\r\n"
  "a=rtpmap:96 H263-1998/90000\r\n"
  "a=framerate:8\r\n"
  "a=fmtp:96 QCIF=4\r\n"
  "m=audio 59152 RTP/AVP 97\r\n"
  "b=AS:8\r\n"
  "a=rtpmap:97 AMR/8000\r\n"
  "a=fmtp:97 mode-set=\"0\"\r\n"
  "a=maxptime:500\r\n";

static int test_session2(int flags)
{
  su_home_t *home = su_home_create();
  sdp_session_t const *sdp = NULL;
  sdp_parser_t *parser;
  sdp_media_t *m;

  BEGIN();

  su_home_check(home); TEST_1(home);

  TEST_1((parser = sdp_parse(home, s1_msg, sizeof(s1_msg), 0)));
  TEST_1((sdp = sdp_session(parser)));
  TEST_1(m = sdp->sdp_media);
  TEST(m->m_mode, sdp_sendonly);
  TEST_1(m->m_session);
  TEST(m->m_session, sdp);
  TEST_1(m->m_rtpmaps);
  TEST(m->m_rtpmaps->rm_pt, 96);
  TEST_S(m->m_rtpmaps->rm_encoding, "H263-1998");
  TEST(m->m_rtpmaps->rm_rate, 90000);
  TEST_1(m = m->m_next);
  TEST(m->m_mode, sdp_sendonly);
  TEST_1(m->m_session);
  TEST(m->m_session, sdp);
  TEST_1(m->m_rtpmaps);
  TEST(m->m_rtpmaps->rm_pt, 97);
  TEST_S(m->m_rtpmaps->rm_encoding, "AMR");
  TEST(m->m_rtpmaps->rm_rate, 8000);
  TEST_S(m->m_rtpmaps->rm_fmtp, "mode-set=\"0,1,2,3,4\"");

  TEST_1((parser = sdp_parse(home, s2_msg, sizeof (s2_msg), 0)));
  TEST_1((sdp = sdp_session(parser)));
  TEST_1(m = sdp->sdp_media);
  TEST(m->m_mode, sdp_recvonly);
  TEST_1(m->m_session);
  TEST(m->m_session, sdp);
  TEST_1(m->m_rtpmaps);
  TEST(m->m_rtpmaps->rm_pt, 96);
  TEST_S(m->m_rtpmaps->rm_encoding, "H263-1998");
  TEST(m->m_rtpmaps->rm_rate, 90000);
  TEST_S(m->m_rtpmaps->rm_fmtp, "QCIF=4");
  TEST_1(m = sdp->sdp_media->m_next);
  TEST(m->m_mode, sdp_recvonly);
  TEST_1(m->m_session);
  TEST(m->m_session, sdp);
  TEST_1(m->m_rtpmaps);
  TEST(m->m_rtpmaps->rm_pt, 97);
  TEST_S(m->m_rtpmaps->rm_encoding, "AMR");
  TEST(m->m_rtpmaps->rm_rate, 8000);
  TEST_S(m->m_rtpmaps->rm_fmtp, "mode-set=\"0\"");

  su_home_destroy(home);

  END();
}

static char const s3_msg[] = 
  "v=0\r\n"
  "o=- 2435697 2435697 IN IP4 172.21.137.44\r\n"
  "s=-\r\n"
  "t=0 0\r\n"
  "m=video 49154 RTP/AVP 34\r\n"
  "c=IN IP4 172.21.137.44\r\n"
  "m=audio 49152 RTP/AVP 8 0\r\n"
  "c=IN IP4 172.21.137.44\r\n"
  "m=message 0 MSRP/TCP *\r\n"
  ;


static int test_sanity(int flags)
{
  su_home_t *home = su_home_create();
  sdp_parser_t *parser;

  BEGIN();

  su_home_check(home); TEST_1(home);

  TEST_1((parser = sdp_parse(home, s3_msg, sizeof(s1_msg), 0)));
  
  TEST_1(sdp_sanity_check(parser) == 0);

  su_home_destroy(home);

  END();
}

static sdp_list_t const l0[1] = {{ sizeof(l0), NULL, "foo" }};
static sdp_list_t const l1[1] = {{ sizeof(l1), (sdp_list_t *)l0, "bar" }};

/** Test list things */
int test_list(int flags)
{
  su_home_t *home = su_home_create();
  sdp_list_t *l;

  BEGIN();

  su_home_check(home);

  TEST_1(home);

  TEST_1((l = sdp_list_dup(home, l0)));
  TEST(l->l_next, NULL);
  TEST_S(l->l_text, "foo");

  TEST_1((l = sdp_list_dup(home, l1)));
  TEST_1(l->l_next != NULL);
  TEST_1(l->l_next->l_next == NULL);
  TEST_S(l->l_text, "bar");
  TEST_S(l->l_next->l_text, "foo");

  su_home_check(home);

  su_home_destroy(home);

  END();
}

static
sdp_rtpmap_t const rm0[1] = 
  {{ 
      sizeof(rm0), NULL, 0, 96, 0, "AMR", 8000, "1",
      "mode-set=4,5,6 interleaving crc use-redundancy=1"
  }};

static
sdp_rtpmap_t const rm1[1] = 
  {{ 
      sizeof(rm1), (sdp_rtpmap_t *)rm0, 1, 8, 0, "PCMA", 8000, "1", NULL
  }};

/** Test rtpmap-related things */
int test_rtpmap(int flags)
{
  su_home_t *home = su_home_create();
  sdp_rtpmap_t *rm;

  BEGIN();

  su_home_check(home);

  TEST_1(home);

  TEST_1((rm = sdp_rtpmap_dup(home, rm0)));
  TEST(rm->rm_next, NULL);
  TEST_S(rm->rm_encoding, "AMR");
  TEST_S(rm->rm_params, "1");
  TEST_S(rm->rm_fmtp, "mode-set=4,5,6 interleaving crc use-redundancy=1");

  TEST_1((rm = sdp_rtpmap_dup(home, rm1)));
  TEST_1(rm->rm_next != NULL);
  TEST_1(rm->rm_next->rm_next == NULL);
  TEST_S(rm->rm_encoding, "PCMA");
  TEST_S(rm->rm_params, "1");

  su_home_check(home);

  su_home_destroy(home);

  END();
}

static sdp_attribute_t const a0[1] =
  {{ sizeof(a0), NULL, "foo", "2"}};
static sdp_attribute_t const a1[1] = 
  {{ sizeof(a1), (sdp_attribute_t *)a0, "bar", "1" }};

static int test_attribute(int flags)
{
  su_home_t *home = su_home_create();
  sdp_attribute_t *a;

  BEGIN();

  su_home_check(home);

  TEST_1(home);

  TEST_1((a = sdp_attribute_dup(home, a0)));
  TEST(a->a_next, NULL);
  TEST_S(a->a_name, "foo");
  TEST_S(a->a_value, "2");

  strcpy((char *)a->a_name, "FOO");
  TEST_S(a0->a_name, "foo");

  strcpy((char *)a->a_value, "X");
  TEST_S(a0->a_value, "2");

  TEST_1((a = sdp_attribute_dup(home, a1)));
  TEST_1(a->a_next != NULL);
  TEST_1(a->a_next->a_next == NULL);
  TEST_S(a->a_name, "bar");
  TEST_S(a->a_value, "1");
  TEST_S(a->a_next->a_name, "foo");
  TEST_S(a->a_next->a_value, "2");

  su_home_check(home);

  su_home_destroy(home);

  END();
}

static int test_connection(int flags)
{
  BEGIN();
  END();
}

static char const media_msg[] = 
"v=0\n"
"s=/sdp_torture\n"
"o=sdp_torture 0 0 IN IP4 1.2.3.4\n"
"c=IN IP4 1.2.3.4\n"
"m=audio 0 RTP/AVP 96 97 98 10 99 8 0\n"
"a=rtpmap:96 X-AMR-WB/16000\n"
"a=rtpmap:97 X-AMR/8000\n"
"a=rtpmap:98 GSM-EFR/8000\n"
"a=rtpmap:10 L16/16000\n"
"a=rtpmap:99 G723/8000\n"
"a=rtpmap:8 PCMA/8000\n"
"a=rtpmap:0 PCMU/8000\n"
"m=video 0 RTP/AVP 31\n"
"c=IN IP4 2.3.4.5\n";

static sdp_media_t const m0[1] =
  {{ sizeof(m0), 
     NULL, 
     NULL,
     sdp_media_audio,
     NULL, 
     1234, 
     5, 
     sdp_proto_udp,
     "udp",
  }};

static int test_media(int flags)
{
  su_home_t *home = su_home_create();
  sdp_media_t *media;
  sdp_session_t *sdp;
  sdp_parser_t *parser;

  BEGIN();

  su_home_check(home);
  TEST_1(home);

  TEST_1((parser = sdp_parse(home, media_msg, sizeof(media_msg), 0)));
  TEST_1((sdp = sdp_session(parser)));
  TEST_1((media = sdp_media_dup(home, m0, sdp)));

  TEST(media->m_type, sdp_media_audio);
  TEST(media->m_port, 1234);
  TEST(media->m_number_of_ports, 5);
  TEST(media->m_session, sdp);
  /* FIXME: add more tests */

  media->m_next = (sdp_media_t *)m0;
  TEST_1((media = sdp_media_dup_all(home, media, sdp)));
  TEST(media->m_connections, NULL);
  TEST_1(media->m_next);
  TEST(media->m_next->m_connections, NULL);
  TEST(sdp_media_connections(media), sdp->sdp_connection);
  TEST(sdp_media_connections(media->m_next), sdp->sdp_connection);

  sdp_parser_free(parser);

  su_home_check(home);
  su_home_destroy(home);

  END();
}

static int test_origin(int flags)
{
  BEGIN();
  END();
}

static int test_bandwidth(int flags)
{
  BEGIN();
  END();
}

static char const t_msg[] =
"v=0\n"
"s=/sdp_torture\n"
"o=sdp_torture 1 1 IN IP4 1.2.3.4\n"
"c=IN IP4 1.2.3.4\n"
"t=3309789956 3309793556\n"
"t=3309789956 3309793557\n"
"t=3309789955 3309793557\n"
"r=604800 3600 0 90000\n"
"z=2882844526 -1h 2898848070 0\n"
"t=3309789955 3309793557\n"
"r=604800 3600 0 90000\n"
"z=2882844526 -1h 2898848070 0\n"
  ;

static int test_time(int flags)
{
  sdp_parser_t *parser;
  sdp_session_t *sdp;
  sdp_time_t *t, t1[1], t2[1];

  BEGIN();

  TEST_1((parser = sdp_parse(NULL, t_msg, sizeof(t_msg), 0)));
  TEST_1((sdp = sdp_session(parser)));
  TEST_1((t = sdp->sdp_time)); *t1 = *t; t1->t_next = NULL; *t2 = *t1;
  TEST_1(sdp_time_cmp(t1, t1) == 0);
  TEST_1(sdp_time_cmp(t1, t2) == 0);
  TEST_1(sdp_time_cmp(t2, t1) == 0);
  TEST_1((t = t->t_next)); *t1 = *t; t1->t_next = NULL; 
  TEST_1(sdp_time_cmp(t1, t2) > 0);
  TEST_1(sdp_time_cmp(t2, t1) < 0);
  TEST_1((t = t->t_next)); *t2 = *t; t2->t_next = NULL; 
  TEST_1(t2->t_zone); TEST_1(t2->t_repeat);
  TEST_1(sdp_time_cmp(t2, t2) == 0);
  TEST_1(sdp_time_cmp(t1, t2) > 0);
  TEST_1(sdp_time_cmp(t2, t1) < 0);
  TEST_1((t = t->t_next)); *t1 = *t; t1->t_next = NULL; 
  TEST_1(t1->t_zone); TEST_1(t1->t_repeat);
  TEST_1(sdp_time_cmp(t1, t1) == 0);
  TEST_1(sdp_time_cmp(t2, t2) == 0);
  TEST_1(sdp_time_cmp(t1, t2) == 0);
  
  sdp_parser_free(parser);

  END();
}

static int test_key(int flags)
{
  BEGIN();
  END();
}

#include <time.h>
#include <stdlib.h>

static int test_build(int flags)
{
  sdp_session_t *sdp, *dup;
  sdp_origin_t *o;
  sdp_time_t *t;
  sdp_connection_t *c;
  sdp_media_t *m, *m1;
  sdp_rtpmap_t *rm;
  sdp_list_t *l, *l1;
  sdp_attribute_t *a;
  su_home_t *home;
  sdp_printer_t *printer;
  char const *data;

  BEGIN();

  srand(time(NULL));

  TEST_1(home = su_home_create());

  /* 
   * Allocate an SDP structure using su_salloc().
   * su_salloc() puts memory area size to the beginning of structure 
   * and zeroes rest of the structure.
   */
  TEST_1(sdp = su_salloc(home, sizeof(*sdp)));
  TEST_1(o = su_salloc(home, sizeof(*o)));
  TEST_1(t = su_salloc(home, sizeof(*t)));
  TEST_1(c = su_salloc(home, sizeof(*c)));
  TEST_1(m = su_salloc(home, sizeof(*m)));
  TEST_1(rm = su_salloc(home, sizeof(*rm)));

  sdp->sdp_origin = o;
  sdp->sdp_time = t;		/* zero time is fine for SIP */
  sdp->sdp_connection = c;
  sdp->sdp_media = m;

  o->o_username = "test";
  o->o_id = rand();
  o->o_version = 1;
  o->o_address = c;
  
  c->c_nettype = sdp_net_in;
  c->c_addrtype = sdp_addr_ip4;
  c->c_address = "172.21.40.40";

  m->m_session = sdp;
  m->m_type = sdp_media_audio; m->m_type_name = "audio";
  m->m_port = 5004;
  m->m_proto = sdp_proto_rtp; m->m_proto_name = "RTP/AVP";
  m->m_rtpmaps = rm;
  
  rm->rm_predef = 1;
  rm->rm_pt = 8;
  rm->rm_encoding = "PCMA"; 
  rm->rm_rate = 8000;

  TEST_1(m1 = su_salloc(home, sizeof(*m1)));
  TEST_1(l = su_salloc(home, sizeof(*l)));
  TEST_1(l1 = su_salloc(home, sizeof(*l1)));
  TEST_1(a = su_salloc(home, sizeof(*a)));

  m->m_next = m1;

  m1->m_session = sdp;
  m1->m_type = sdp_media_message; m->m_type_name = "message";
  m1->m_port = 5060;
  m1->m_proto = sdp_proto_tcp; m->m_proto_name = "TCP";
  m1->m_format = l;
  m1->m_attributes = a;

  l->l_text = "sip";

  l->l_next = l1;
  l1->l_text = "cpim";

  a->a_name = "user";
  a->a_value = "chat-81273845";

  TEST_1(dup = sdp_session_dup(home, sdp));

  TEST_1(printer = sdp_print(home, dup, NULL, 0, 0));
  TEST_1(data = sdp_message(printer));

  if (flags & tst_verbatim)
    printf("sdp_torture.c: built SDP message:\"%s\".\n", data);

  sdp_printer_free(printer);

  END();
}

void usage(void)
{
  fprintf(stderr, "usage: %s [-v]\n", name);
}

char *lastpart(char *path)
{
  if (strchr(path, '/')) 
    return strrchr(path, '/') + 1;
  else
    return path;
}

int main(int argc, char *argv[])
{
  int flags = 0;
  int retval = 0;
  int i;

  name = lastpart(argv[0]);  /* Set our name */

  for (i = 1; argv[i]; i++) {
    if (strcmp(argv[i], "-v") == 0)
      flags |= tst_verbatim;
    else
      usage();
  }

  null = fopen("/dev/null", "ab");

  retval |= test_error(flags); fflush(stdout);
  retval |= test_session(flags); fflush(stdout);
  retval |= test_session2(flags); fflush(stdout);
  retval |= test_sanity(flags); fflush(stdout);
  retval |= test_list(flags); fflush(stdout);
  retval |= test_rtpmap(flags); fflush(stdout);
  retval |= test_origin(flags); fflush(stdout);
  retval |= test_connection(flags); fflush(stdout);
  retval |= test_bandwidth(flags); fflush(stdout);
  retval |= test_time(flags); fflush(stdout);
  retval |= test_key(flags); fflush(stdout);
  retval |= test_attribute(flags); fflush(stdout);
  retval |= test_media(flags); fflush(stdout);
  retval |= test_build(flags); fflush(stdout);

  return retval;
}
