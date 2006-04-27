/*
 * This file is part of the Sofia-SIP package
 *
 * Copyright (C) 2006 Nokia Corporation.
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

/**@file sip-dig.c Use sresolv library to resolve a SIP or SIPS domain.
 *
 * This is an example program for @b sresolv library in synchronous mode.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Original Created: Tue Jul 16 18:50:14 2002 ppessi
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include "sofia-resolv/sres.h"
#include "sofia-resolv/sres_record.h"

#include "sofia-sip/url.h"
#include "sofia-sip/su_alloc.h"
#include "sofia-sip/hostdomain.h"

char const name[] = "sip-dig";

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

enum { N_TPORT = 16 };

struct transport { char const *name, *service, *srv; };

struct dig {
  sres_resolver_t *sres;

  unsigned preference, ip4, ip6, sips, print;

  struct transport tports[N_TPORT];
};

int dig_naptr(struct dig *dig, char const *host, double weight);

int dig_all_srvs(struct dig *dig, char const *tport, char const *host,
		 double weight);

int dig_srv(struct dig *dig, char const *tport, char const *host,
	    double weight);

int dig_srv_at(struct dig *dig,
	       char const *tport, sres_record_t **answers, 
	       double weight, int pweight,
	       int priority);

int dig_addr(struct dig *dig, 
	     char const *tport, char const *host, char const *port,
	     double weight);

void print_addr_results(struct transport const *tports,
			char const *tport, char const *tport2,
			sres_record_t **answers, int type, int af,
			char const *port,
			double weight, int preference);

void print_result(char const *addr, char const *port, char const *tport,
		  double weight,
		  unsigned preference);

int prepare_transport(struct transport tports[N_TPORT], char const *tport);

int count_transports(struct transport const *, char const *tp1, char const *tp2);

void usage(int exitcode)
{
  fprintf(stderr, "usage: %s [OPTIONS] [@dnsserver] uri\n", name);
  exit(exitcode);
}

int main(int argc, char *argv[])
{
  int exitcode = 1;
  int o_sctp = 1, o_tls_sctp = 1, o_verbatim = 1;
  int family = 0;
  char const *dnsserver = NULL;
  char const *string;
  url_t *uri = NULL;

  char const *host;
  char const *port;
  char *transport = NULL, tport[32];

  struct dig dig[1] = {{ NULL }};

  while (argv[1] && argv[1][0] == '-') {
    if (strcmp(argv[1], "-v") == 0)
      o_verbatim++;
    else if (strcmp(argv[1], "-6") == 0)
      dig->ip6 = ++family;
    else if (strcmp(argv[1], "-4") == 0)
      dig->ip4 = ++family;
    else if (strcmp(argv[1], "--udp") == 0)
      prepare_transport(dig->tports, "udp");
    else if (strcmp(argv[1], "--tcp") == 0)
      prepare_transport(dig->tports, "tcp");
    else if (strcmp(argv[1], "--tls") == 0)
      prepare_transport(dig->tports, "tls");
    else if (strcmp(argv[1], "--sctp") == 0)
      prepare_transport(dig->tports, "sctp");
    else if (strcmp(argv[1], "--tls-sctp") == 0)
      prepare_transport(dig->tports, "tls-sctp");
    else if (strcmp(argv[1], "--tls-udp") == 0)
      prepare_transport(dig->tports, "tls-udp");
    else if (strcmp(argv[1], "--no-sctp") == 0)
      o_sctp = 0, o_tls_sctp = 0;
    else if (strcmp(argv[1], "--help") == 0)
      usage(0);
    else if (strcmp(argv[1], "-h") == 0)
      usage(0);
    else if (strcmp(argv[1], "-?") == 0)
      usage(0);
    else if (strcmp(argv++[1], "-") == 0)
      break;
    else
      usage(1);
    argv++;
  }

  if (!family)
    dig->ip4 = 1, dig->ip6 = 2;

  if (argv[1] && argv[1][0] == '@')
    dnsserver = argv++[1] + 1;

  string = argv[1];

  if (!string)
    usage(1);

  uri = url_hdup(NULL, (void *)string);
  if (!uri)
    usage(1);

  if (uri->url_type == url_any)
    url_sanitize(uri);

  if (uri->url_type != url_sip && uri->url_type != url_sips) {
    fprintf(stderr, "%s: invalid uri\n", string);
    exit(1);
  }

  port = url_port(uri);
  if (port && !port[0]) port = NULL;
  if (url_param(uri->url_params, "transport=", tport, sizeof tport) > 0)
    transport = tport;

  host = uri->url_host;

  if (!count_transports(dig->tports, NULL, NULL)) {
    prepare_transport(dig->tports, "udp");
    prepare_transport(dig->tports, "tcp");
    if (o_sctp)
      prepare_transport(dig->tports, "sctp");
    prepare_transport(dig->tports, "tls");
    if (o_tls_sctp)
      prepare_transport(dig->tports, "tls-sctp");
  }

  if (host_is_ip_address(host)) {
    if (transport) {
      print_result(host, port, transport, 1.0, 1);
    }
    else if (uri->url_type == url_sips) {
      print_result(host, port, "tls", 1.0, 1);
    }
    else {
      print_result(host, port, "udp", 1.0, 1);
      print_result(host, port, "tcp", 1.0, 2);
    }
    exit(0);
  }

  if (!host_is_domain(host)) {
    fprintf(stderr, "%s: invalid host\n", string);
    exit(1);
  }

  dig->sres = sres_resolver_new(getenv("SRESOLV_CONF"));
  if (!dig->sres)
    perror("sres_resolver_new"), exit(1);

  dig->sips = uri->url_type == url_sips;
  dig->preference = 1;

  if (!port && !transport && dig_naptr(dig, host, 1.0))
    exitcode = 0 /* resolved naptr */;
  else if (!port && dig_all_srvs(dig, transport, host, 1.0))
    exitcode = 0 /* resolved srv */;
  else if (dig_addr(dig, transport, host, port, 1.0))
    exitcode = 0 /* resolved a/aaaa */;
  else
    fprintf(stderr, "%s: not found\n", string);

  sres_resolver_unref(dig->sres);

  return exitcode;
}


int transport_is_secure(char const *tportname)
{
  return tportname && strncasecmp(tportname, "tls", 3) == 0;
}

int prepare_transport(struct transport tports[N_TPORT], char const *tport)
{
  int j;

  for (j = 0; j < N_TPORT - 1; j++) {
    if (!tports[j].name)
      break;
    if (strcasecmp(tports[j].name, tport) == 0)
      return 1;
  }

  if (j == N_TPORT)
    return 0;

  if (strcasecmp(tport, "udp") == 0) {
    tports[j].service = "SIP+D2U";
    tports[j].srv = "_sip._udp.";
    tports[j++].name = "udp";
  }
  else if (strcasecmp(tport, "tcp") == 0) {
    tports[j].service = "SIP+D2T";
    tports[j].srv = "_sip._tcp.";
    tports[j++].name = "tcp";
  }
  else if (strcasecmp(tport, "tls") == 0) {
    tports[j].service = "SIPS+D2T";
    tports[j].srv = "_sips._tcp.";
    tports[j++].name = "tls";
  }
  else if (strcasecmp(tport, "sctp") == 0) {
    tports[j].service = "SIP+D2S";
    tports[j].srv = "_sip._sctp.";
    tports[j++].name = "sctp";
  }
  else if (strcasecmp(tport, "tls-sctp") == 0) {
    tports[j].service = "SIPS+D2S";
    tports[j].srv = "_sips._sctp.";
    tports[j++].name = "tls-sctp";
  }
  else {
    fprintf(stderr, "%s: ignoring unknown transport \"%s\" with NAPTR\n",
	    name, tport);
    return 0;
  }

  tports[j].service = tports[j].srv = tports[j].name = NULL;

  return 1;
}

int
count_transports(struct transport const *tports,
		 char const *tport,
		 char const *tport2)
{
  int i, tcount = 0;

  for (i = 0; tports[i].name; i++) {
    if (!tport || strcasecmp(tport, tports[i].name) == 0)
      tcount++;
    if (tport2 && strcasecmp(tport2, tports[i].name) == 0)
      tcount++;
  }

  return tcount;
}

struct transport const *
transport_by_service(struct transport const *tports, char const *s)
{
  int i;

  for (i = 0; tports[i].name; i++) {
    if (strcasecmp(tports[i].service, s) == 0)
      return tports + i;
  }

  return NULL;
}

int dig_naptr(struct dig *dig,
	      char const *host,
	      double weight)
{
  sres_record_t **answers = NULL;
  struct transport const *tp;
  int i, error;
  int order = 0, count = 0, nacount = 0, scount = 0;

  error = sres_blocking_query(dig->sres, sres_type_naptr, host, &answers);
  if (error < 0)
    return 0;

  /* Sort by priority */
  sres_sort_answers(dig->sres, answers);

  /* Count number of matching naptrs */
  for (i = 0; answers[i]; i++) {
    sres_naptr_record_t const *na = answers[i]->sr_naptr;

    if (na->na_record->r_type != sres_type_naptr || na->na_record->r_status)
      continue;

    if (dig->print)
      printf("%s\n\t%d IN NAPTR %u %u \"%s\" \"%s\" \"%s\" %s\n",
	     na->na_record->r_name, na->na_record->r_ttl,
	     na->na_order, na->na_prefer,
	     na->na_flags, na->na_services,
	     na->na_regexp, na->na_replace);

    if (strcasecmp(na->na_flags, "s") && strcasecmp(na->na_flags, "a"))
      continue;

    if (nacount && order != na->na_order)
      continue;

    if (dig->sips && strncasecmp(na->na_services, "SIPS+", 5))
      continue;

    if (!transport_by_service(dig->tports, na->na_services))
      continue;

    order = na->na_order, nacount++;
  }

  if (nacount == 0) {
    sres_free_answers(dig->sres, answers);
    return 0;
  }

  for (i = 0; answers[i]; i++) {
    sres_naptr_record_t const *na = answers[i]->sr_naptr;

    if (na->na_record->r_type != sres_type_naptr || na->na_record->r_status)
      continue;
    if (order != na->na_order)
      continue;
    if (strcasecmp(na->na_flags, "s") && strcasecmp(na->na_flags, "a"))
      continue;
    if (dig->sips && strncasecmp(na->na_services, "SIPS+", 5))
      continue;

    tp = transport_by_service(dig->tports, na->na_services);
    if (!tp)
      continue;

    if (strcasecmp(na->na_flags, "s") == 0) {
      scount = dig_srv(dig, tp->name, na->na_replace, weight / nacount);
    }
    else if (strcasecmp(na->na_flags, "a") == 0) {
      scount = dig_addr(dig, tp->name, na->na_replace, NULL, weight / nacount);
    }
    else 
      scount = 0;

    count += scount;
  }

  return count;
}

int dig_all_srvs(struct dig *dig,
		 char const *tport,
		 char const *host,
		 double weight)
{
  int i;
  int tcount, count = 0, scount;
  char *domain;

  tcount = count_transports(dig->tports, tport, NULL);
  if (!tcount)
    return 0;

  for (i = 0; dig->tports[i].name; i++) {
    if (tport && strcasecmp(dig->tports[i].name, tport))
      continue;

    domain = su_strcat(NULL, dig->tports[i].srv, host);

    scount = dig_srv(dig, dig->tports[i].name, domain, weight);
    if (scount) {
      dig->preference++;
      count += scount;
    }

    free(domain);
  }

  return count;
}

int dig_srv(struct dig *dig,
	    char const *tport,
	    char const *domain,
	    double weight)
{
  sres_record_t **answers = NULL;
  int j, n, error;
  int count = 0, scount = 0;

  uint32_t priority, pweight;

  assert(tport && domain);

  error = sres_blocking_query(dig->sres, sres_type_srv, domain, &answers);
  if (error < 0)
    return 0;

  /* Sort by priority */
  sres_sort_answers(dig->sres, answers);

  priority = 0; pweight = 0; n = 0;

  for (j = 0; answers[j]; j++) {
    sres_srv_record_t const *srv = answers[j]->sr_srv;

    if (srv->srv_record->r_type != sres_type_srv)
      continue;
    if (srv->srv_record->r_status != 0)
      continue;

    if (srv->srv_priority != priority && pweight != 0) {
      scount = dig_srv_at(dig, tport, answers, weight, pweight,
			  priority);
      if (scount) dig->preference++;
      count += scount;
      pweight = 0, n = 0;
    }

    priority = srv->srv_priority, pweight += srv->srv_weight, n++;
  }

  if (n) {
    scount = dig_srv_at(dig, tport, answers, weight, pweight,
			priority);
    if (scount) dig->preference++;
    count += scount;
  }

  sres_free_answers(dig->sres, answers);

  return count;
}

int dig_srv_at(struct dig *dig,
	       char const *tport,
	       sres_record_t **answers,
	       double weight, int pweight,
	       int priority)
{
  int count = 0;
  int i;
  char port[8];

  if (pweight == 0)
    pweight = 1;

  for (i = 0; answers[i]; i++) {
    sres_srv_record_t const *srv = answers[i]->sr_srv;
    if (srv->srv_record->r_type != sres_type_srv)
      continue;
    if (srv->srv_record->r_status != 0)
      continue;
    if (srv->srv_priority != priority)
      continue;
    snprintf(port, sizeof port, "%u", srv->srv_port);

    count += dig_addr(dig, tport, srv->srv_target, port,
		      weight * srv->srv_weight / pweight);
  }

  return count;
}

int dig_addr(struct dig *dig,
	     char const *tport,
	     char const *host,
	     char const *port,
	     double weight)
{
  int error, i;
  char const *tport2 = NULL;
  sres_record_t **answers1 = NULL, **answers2 = NULL;
  unsigned count1 = 0, count2 = 0, tcount = 0;
  int type1 = 0, type2 = 0, family1 = 0, family2 = 0;

  if (dig->ip6 > dig->ip4) {
    type1 = sres_type_aaaa, family1 = AF_INET6;
    if (dig->ip4)
      type2 = sres_type_a, family2 = AF_INET;
  }
  else {
    type1 = sres_type_a, family1 = AF_INET;
    if (dig->ip6)
      type2 = sres_type_aaaa, family2 = AF_INET6;
  }

  if (tport == NULL) {
    if (dig->sips)
      tport = "tls";
    else
      tport = "udp", tport2 = "tcp";
  }

  tcount = count_transports(dig->tports, tport, tport2);
  if (!tcount)
    return 0;

  if (type1) {
    error = sres_blocking_query(dig->sres, type1, host, &answers1);
    if (error >= 0)
      for (i = 0; answers1[i]; i++) {
	sres_common_t *r = answers1[i]->sr_record;
	count1 += r->r_type == type1 &&	r->r_status == 0;
      }
  }

  if (type2) {
    error = sres_blocking_query(dig->sres, type2, host, &answers2);
    if (error >= 0)
      for (i = 0; answers2[i]; i++) {
	sres_common_t *r = answers2[i]->sr_record;
	count2 += r->r_type == type2 &&	r->r_status == 0;
      }
  }

  if (count1 + count2) {
    double w = weight / (count1 + count2) / tcount;

    if (count1)
      print_addr_results(dig->tports, tport, tport2,
			 answers1, type1, family1, port,
			 w, dig->preference);
    if (count2)
      print_addr_results(dig->tports, tport, tport2,
			 answers2, type2, family2, port,
			 w, dig->preference);
  }

  sres_free_answers(dig->sres, answers1);
  sres_free_answers(dig->sres, answers2);

  return count1 + count2;
}

void
print_addr_results(struct transport const *tports,
		   char const *tport, char const *tport2,
		   sres_record_t **answers, int type, int af,
		   char const *port,
		   double weight, int preference)
{
  int i, j;
  char addr[64];

  for (i = 0; answers[i]; i++) {
    if (answers[i]->sr_record->r_type != type)
      continue;
    if (answers[i]->sr_record->r_status != 0)
      continue;

    inet_ntop(af, &answers[i]->sr_a->a_addr, addr, sizeof addr);

    for (j = 0; tports[j].name; j++) {
      if (strcasecmp(tport, tports[j].name) == 0)
	print_result(addr, port, tport, weight, preference);
      if (tport2 && strcasecmp(tport2, tports[j].name) == 0)
	print_result(addr, port, tport2, weight, preference);
    }
  }
}

void print_result(char const *addr,
		  char const *port,
		  char const *tport,
		  double weight,
		  unsigned preference)
{
  if (!port || !port[0])
    port = transport_is_secure(tport) ? "5061" : "5060";

  printf("\t%u %.3f %s %s %s\n", preference, weight, tport, port, addr);
}
