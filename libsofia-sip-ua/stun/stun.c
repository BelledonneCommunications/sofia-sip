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
 * @file stun.c STUN client module
 *
 * See RFC 3489 for further information.
 *
 * @author Tat Chan <Tat.Chan@nokia.com>
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 * @author Kai Vehmanen <Kai.Vehmanen@nokia.com>
 * @author Martti Mela <Martti.Mela@nokia.com>
 * 
 * @date Created: Thu Jul 24 17:21:00 2003 ppessi
 */

#include "config.h" 

#include <assert.h>

#define SU_ROOT_MAGIC_T struct stun_engine_s
#define SU_WAKEUP_ARG_T struct stun_engine_s

#include "stun.h"
#include "stun_internal.h"
#include "stun_tag.h"

#include <su_alloc.h>
#include <su_tagarg.h>
#include <su_log.h>
#include <su.h>
#include <su_localinfo.h>

#ifndef SU_DEBUG
#define SU_DEBUG 3
#endif
#define SU_LOG (stun_log)
#include <su_debug.h>

#include <openssl/opensslv.h>

extern char const STUN_DEBUG[]; /* dummy declaration for Doxygen */

/** STUN log. */
su_log_t stun_log[] = { SU_LOG_INIT("stun", "STUN_DEBUG", SU_DEBUG) }; 

#define STUN_ERROR(errno, what) \
        { int err = errno; \
        SU_DEBUG_5(("%s: %s: %s\n", __func__, #what, su_strerror(err))); \
        }

char const stun_nat_unknown[] = "NAT type undetermined",
  stun_open_internet[] = "Open Internet",
  stun_udp_blocked[] = "UDP traffic is blocked, or Server unreachable",
  stun_sym_udp_fw[] = "Symmetric UDP Firewall",
  stun_nat_full_cone[] = "Full-Cone NAT",
  stun_nat_sym[] = "Symmetric NAT",
  stun_nat_res_cone[] = "Restricted Cone NAT",
  stun_nat_port_res_cone[] = "Port Restricted Cone NAT";

/**
 * States of the STUN client->server query process.
 */ 
enum stun_client_state_e {
  stun_cstate_init,             /**< Initial state */
  stun_cstate_started,          /**< Discovery process started */
  stun_cstate_received,         /**< Received server reply */
  stun_cstate_processing,       /**< Processing server reply */
  stun_cstate_done,             /**< Initial state */
};

struct stun_engine_s
{
  su_home_t       st_home[1];
  su_root_t      *st_root;
  su_wait_t       st_waiter[1];   /**< for async socket operations */
  su_sockaddr_t   st_srvr4[2];    /**< primary and secondary addresses */
  su_socket_t     st_socket;
  
  stun_socket_t  *st_stun_socket;

  stun_event_f    st_callback;    /**< callback for calling application */ 
  stun_magic_t   *st_context;

  stun_buffer_t   st_username;
  stun_buffer_t   st_passwd;

  int             st_use_msgint;  /**< use message integrity? */
  int             st_nattype;     /**< NAT-type, see stun_common.h */
};

struct stun_socket_s
{
  stun_engine_t *ss_engine;
  int            ss_sockfd;
  int            ss_state;      /**< State for STUN protocol ? */
};

char const stun_version[] = 
 "sofia-sip-stun using " OPENSSL_VERSION_TEXT;

/**
 * Return su_root_t assigned to stun_engine_t.
 *
 * @param self stun_engine_t object
 * @return su_root_t object, NULL if self not given.
 */
su_root_t *stun_root(stun_engine_t *self)
{
  return self ? self->st_root : NULL;
}


/**
 * Check if a STUN engine should be created.
 *
 * Return true either there is a tag STUNTAG_SERVER() in list or if
 * STUN_SERVER environment variable is set.
 *
 * @param tag,value,... tag-value list
 */
int stun_is_requested(tag_type_t tag, tag_value_t value, ...)
{
  ta_list ta;
  tagi_t const *t;
  char const *stun_server;

  ta_start(ta, tag, value);
  t = tl_find(ta_args(ta), stuntag_server);
  stun_server = t && t->t_value ? (char *)t->t_value : getenv("STUN_SERVER");
  ta_end(ta);

  return stun_server != NULL;
}

/** 
 * Creates a STUN engine 
 *
 * @param server hostname or IPv4 address 
 * @param msg_integrity true if msg integr. should be used
 *
 */
stun_engine_t *stun_engine_create(stun_magic_t *context,
				  su_root_t *root,
				  stun_event_f cb,
				  char const *server, 
				  int msg_integrity)
{
  return stun_engine_tcreate(context,
			     root,
			     cb,
			     STUNTAG_SERVER(server), 
			     STUNTAG_INTEGRITY(msg_integrity), 
			     TAG_END());
}

/** 
 * Create a STUN engine 
 *
 * @param tag,value,... tag-value list 
 *
 * @TAGS
 * @TAG STUNTAG_SERVER() stun server hostname or dotted IPv4 address
 * @TAG STUNTAG_INTEGRITY() true if msg integrity should be used
 *
 */
stun_engine_t *stun_engine_tcreate(stun_magic_t *context,
				   su_root_t *root,
				   stun_event_f cb,
				   tag_type_t tag, tag_value_t value, ...)
{
  stun_engine_t *stun;
  char const *server = NULL;
  char *port;
  int msg_integrity = 1;
  ta_list ta;
  su_sockaddr_t su[1];
  su_addrinfo_t *ai, *res, hints[1];
  
  

  ta_start(ta, tag, value);

  tl_gets(ta_args(ta),
	  STUNTAG_SERVER_REF(server),
	  STUNTAG_INTEGRITY_REF(msg_integrity),
	  TAG_END());

  /* Enviroment overrides */
  if (getenv("STUN_SERVER")) {
    server = getenv("STUN_SERVER");
    SU_DEBUG_5(("stun: using STUN_SERVER=%s\n", server));
  }

  SU_DEBUG_5(("%s(\"%s\"): called\n", 
	      "stun_engine_tcreate", server));

  memset(su, 0, (sizeof su));
  
  if (server) {
    int err;
    port = "";
    hints->ai_protocol = IPPROTO_TCP;
    hints->ai_socktype = SOCK_STREAM;
    hints->ai_family = AF_INET;
    hints->ai_flags = AI_PASSIVE;

    if ((err = su_getaddrinfo(server, port, hints, &res)) != 0) {
      STUN_ERROR(err, su_getaddrinfo);
#if 0
    if (stun_atoaddr(&su->su_sin, server) != 0)
#endif
      return NULL;
    }
  }

  for (ai = res; ai; ai = ai->ai_next) {
    /* Skip non-internet (AF_LOCAL) addresses */
    if (ai->ai_family != AF_INET)
      continue;

    ai->ai_socktype = hints->ai_socktype;
    ai->ai_protocol = hints->ai_protocol;
    break;
  }

  stun = su_home_clone(NULL, sizeof(*stun));

  if (stun) {
    /* Store server address in *stun, run discovery process?? 
     * I suppose this may block for the moment
     */

    /* memset(&stun->st_srvr4[0], 0, sizeof(stun->st_srvr4[0])); */

    stun->st_root     = root;
    stun->st_context  = context;
    stun->st_callback = cb;

#if 0
    if (server) {
      if (su->su_sin.sin_port == 0)
	su->su_sin.sin_port = htons(STUN_DEFAULT_PORT);
      stun->st_srvr4[0] = su[0];
    }

    /* alternative address set to 0 */

    memset(&stun->st_srvr4[1], 0, sizeof(stun->st_srvr4[1]));

#endif


    /* initialize username and password */
    stun_init_buffer(&stun->st_username);
    stun_init_buffer(&stun->st_passwd);

    stun->st_nattype = STUN_NAT_UNKNOWN;

    /* initialize random number generator */
    srand(time(NULL));

    stun->st_use_msgint = 0;
    if (msg_integrity) {
      /* get shared secret */ 
      SU_DEBUG_3(("Contacting Server to obtain shared secret. " \
		  "Please wait.\n"));
      if (stun_connect_start(stun, ai) == 0) {
	SU_DEBUG_3(("Shared secret obtained from server.\n"));
	stun->st_use_msgint = 1;
      }
      else {
	SU_DEBUG_3(("Shared secret NOT obtained from server. " \
		    "Proceed without username/password.\n"));
      } 
    }
  }

  return stun;
}

/** Destroy a STUN client */ 
void stun_engine_destroy(stun_engine_t *stun)
{ 
  su_home_zap(stun->st_home);
}

void stun_engine_set_stun_socket(stun_engine_t *se, stun_socket_t *ss)
{

  assert(se && ss);
  se->st_stun_socket = ss;
  return;
}

stun_socket_t *stun_socket_create(stun_engine_t *se, int sockfd)
{
  stun_socket_t *ss;

  if (se == NULL) return errno = EINVAL, NULL;

  ss = su_zalloc(se->st_home, sizeof *ss);

  if (ss) {
    ss->ss_engine = se;
    ss->ss_sockfd = sockfd;
  }
  stun_engine_set_stun_socket(se, ss);

  return ss;
}

void stun_socket_destroy(stun_socket_t *ss)
{
  if (ss)
    su_free(ss->ss_engine->st_home, ss);
}

/** Bind a socket using STUN client. 
 *
 * The function stun_bind() obtains a global address for a UDP socket using
 * a STUN server. 
 * 
 * @param ss       dpointer to a STUN client object (IN)
 * @param my_addr  public address for socket (IN/OUT)
 * @param addrlen  length of pub_addr (IN/OUT)
 * @param lifetime return value pointer to lifetime of 
 *                 binding, -1 if no STUN not used (OUT)
 *
 * @return
 * On success, zero is returned.  Upon error, -1 is returned, and @e errno is
 * set appropriately.
 * 
 * @ERRORS
 * @ERROR EFAULT          An invalid address is given as argument
 * @ERROR EPROTONOSUPPORT Not a UDP socket.
 * @ERROR EINVAL          The socket is already bound to an address.
 * @ERROR EACCESS   	  The address is protected, and the user is not 
 *                  	  the super-user.
 * @ERROR ENOTSOCK  	  Argument is a descriptor for a file, not a socket.
 * @ERROR EAGAIN          Operation in progress. Application should call 
 *                        stun_bind() again when there is data available on 
 *                        the socket.
 * 
 */
int stun_bind(stun_socket_t *ss,
#if 1
	      su_sockaddr_t *my_addr,
#else
	      struct sockaddr *my_addr, 
	      socklen_t *addrlen,
#endif
	      int *lifetime)
{
  int retval = -1, sockfd;
  struct sockaddr_in *clnt_addr = 0, bind_addr;
  socklen_t bind_len;

  /* testing su_getlocalinfo() */
  su_localinfo_t  hints[1] = {{ LI_CANONNAME | LI_NUMERIC }}, *li, *res = NULL;
  int i, error, found=0;
  
  if (ss == NULL) 
    return errno = EFAULT, -1;

  clnt_addr = (void *) my_addr;

  if (clnt_addr == NULL || clnt_addr->sin_addr.s_addr == 0) {
    
    if((error = su_getlocalinfo(hints, &res)) == 0) {

      /* try to bind to the first available address */
      for (i = 0, li = res; li; li = li->li_next) {
        if (li->li_family == AF_INET) {
	  /* xxx - mela: is these needed */
	  hints->li_family = AF_INET;
	  hints->li_flags = AI_PASSIVE;

          memcpy(clnt_addr, &li->li_addr->su_sin, sizeof(li->li_addr->su_sin));
          SU_DEBUG_3(("stun: local address found to be %s:%u\n", 
		      inet_ntoa(clnt_addr->sin_addr),
		      (unsigned) ntohs(clnt_addr->sin_port)));
          found = 1;
          break;
        }
      }


      if (!found) {
        SU_DEBUG_5(("stun: su_getlocalinfo: %s\n", su_gli_strerror(error)));
	return errno = EFAULT, -1;
      }
    }
    else {
      SU_DEBUG_5(("stun: su_getlocalinfo: %s\n", su_gli_strerror(error)));
      return errno = EFAULT, -1;
    }
    if (res)
      su_freelocalinfo(res);
  }

  /* run protocol here... */
  sockfd = ss->ss_sockfd;

  if (bind(sockfd, (struct sockaddr *)clnt_addr, my_addr->su_len)<0) {
    SU_DEBUG_3(("stun: Error binding to %s:%u\n", inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
    return -1;
  }

  bind_len = sizeof(bind_addr);
  getsockname(sockfd, (struct sockaddr *) &bind_addr, &bind_len);
  
  SU_DEBUG_3(("stun: Local socket bound to: %s:%u\n", inet_ntoa(bind_addr.sin_addr), 
	      (unsigned) ntohs(bind_addr.sin_port)));


  retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[0], 
			  clnt_addr, 0, 0);

  if (ss->ss_state != stun_cstate_done) {
    SU_DEBUG_3(("stun: Error in STUN discovery process (error state: %d).\n", (int)ss->ss_state));
    /* make sure the returned clnt_addr matches the local socket */
    if (my_addr->su_len < bind_len)
      return errno = EFAULT, -1;
    else 
      memcpy(my_addr, &bind_addr, bind_len);
  }

  if (lifetime) {
    if (retval == 0)
      *lifetime = 3600;
    else
      *lifetime = -1;
  }

  /* note: we always report success if bind() succeeds */
  return 0;

}

/** Return type of NAT
 *  This function may take a long time to finish.
 *  XXX - mela: not for long!!!
 *  NAT type is set in ss->se_engine.st_nattype
 */
int stun_get_nattype(stun_socket_t *ss, struct sockaddr *my_addr, int *addrlen)
{
  int nattype = STUN_NAT_UNKNOWN;
  int retval, lifetime, sockfd;
  socklen_t locallen, len;
  struct sockaddr_in local, mapped_addr1, mapped_addr2;
  
  sockfd = ss->ss_sockfd;
  
  len = sizeof(mapped_addr1);
  memcpy(&mapped_addr1, my_addr, len); 
  mapped_addr1.sin_port = 0; /* wild card for get_nattype */
  retval = stun_bind(ss, (struct sockaddr *)&mapped_addr1, &len, &lifetime);
  if(retval==-1) {
    if(errno==ETIMEDOUT) {
      /* No Response: Type 2 - UDP Blocked */
      retval = 0; /* time out is a legitimate response */
      nattype = STUN_UDP_BLOCKED;
    } /* otherwise unknown nat type */
  }
  else { /* Response comes back */
    memset(&local, 0, sizeof(local)); locallen = sizeof(local);
    getsockname(sockfd, (struct sockaddr *)&local, &locallen);
    if(memcmp(&local, &mapped_addr1, 8)==0) { /* Same IP and port*/
      /* conduct TEST II */      
      memset(&mapped_addr2, 0, sizeof(mapped_addr2));
      retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[0],
			      &mapped_addr2, 1, 1);
      if(retval==-1) {
	if(errno==ETIMEDOUT) {
	  /* No Response: Type 3 - Sym UDP FW */
	  retval = 0;
	  nattype = STUN_SYM_UDP_FW;	  
	} /* otherwise unknown nat type */
      } 
      else {
	/* Response: Type 1 - Open Internet */
	nattype = STUN_OPEN_INTERNET;
      }
    }
    else { /* Different IP */
      memset(&mapped_addr2, 0, sizeof(mapped_addr2));
      retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[0],
			      &mapped_addr2, 1, 1);
      if(retval==-1) {
	if(errno==ETIMEDOUT) {
	  /* No Response */
	  retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[1], 
				  &mapped_addr2, 0, 0);
	  if(retval==0) { /* response comes back, has to be the case */
	    if(memcmp(&mapped_addr1, &mapped_addr2, 8)==0) {
	      /* Same Public IP and port, Test III, server ip 0 or 1 should be
		 same */
	      retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[0],
				      &mapped_addr2, 0, 1);
	      if(retval==0) {
		/* Response: Type 6 - Restricted */
		nattype = STUN_NAT_RES_CONE;
	      }
	      else if(errno==ETIMEDOUT) {
		/* No response: Type 7 - Port Restricted */
		retval = 0;
		nattype = STUN_NAT_PORT_RES_CONE;
	      }
	    }
	    else {
	      /* Different Public IP: Type 5 - Sym NAT */
	      nattype = STUN_NAT_SYM;
	    }
	  } /* otherwise there is a sudden network problem */	  
	} /* otherwise unknown nat type */
      }
      else {
	/* Response: Type 4 - Full Cone */
	nattype = STUN_NAT_FULL_CONE;
      }
    }
  }
  
  ss->ss_engine->st_nattype = nattype;
  return retval;
}

/** Application should call this at regular intervals 
 *  while binding is active.
 */
int stun_poll(stun_socket_t *ss)
{
  return 0;
}

/********************************************************************
 * Internal functions
 *******************************************************************/

static 

int stun_connected(su_root_magic_t *m, su_wait_t *w, stun_engine_t *self)
{
  stun_msg_t req, resp;
  int z, err;
  int events = su_wait_events(w, self->st_socket);
  SSL_CTX* ctx;
  SSL *ssl;
  X509* server_cert;
  unsigned char buf[512];
  stun_attr_t *password, *username;

  SU_DEBUG_7(("%s(%p): events%s%s\n", __func__, self,
	      events & SU_WAIT_CONNECT ? " CONNECTED" : "",
	      events & SU_WAIT_ERR ? " ERR" : ""));

  if (!(events & SU_WAIT_CONNECT)) {
    /* Inform application about the current state */
    /* xxx - mela: which index? */
    su_wait_destroy(w);
    self->st_callback(self->st_context, self, stun_no_shared_secret_obtained);
    return 0;
  }

  /* compose shared secret request */
  if (stun_make_sharedsecret_req(&req) != 0) {
    STUN_ERROR(errno, stun_make_sharedsecret_req);
    stun_free_buffer(&req.enc_buf);
    return -1;
  }

  /* openssl initiation */
  SSLeay_add_ssl_algorithms();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(TLSv1_client_method());

  if (ctx == NULL) {
    STUN_ERROR(errno, SSL_CTX_new);
    stun_free_buffer(&req.enc_buf);
    return -1;
  }

  if (SSL_CTX_set_cipher_list(ctx, "AES128-SHA") == 0) {
    STUN_ERROR(errno, SSL_CTX_set_cipher_list);
    stun_free_buffer(&req.enc_buf);
    return -1;
  }

  /* Start TLS negotiation */
  ssl = SSL_new(ctx);
  if (SSL_set_fd(ssl, self->st_socket) == 0) {
    STUN_ERROR(err, connect);
    stun_free_buffer(&req.enc_buf);
    return -1;
  }

  SSL_connect(ssl);
  err = su_errno();
  if (err != EINPROGRESS && err != EAGAIN && err != EWOULDBLOCK) {
    int e;
    e = SSL_get_error(ssl, err);
    printf("SSL_get_error: %d\n", e);
    STUN_ERROR(err, connect);fflush(stdout);

    stun_free_buffer(&req.enc_buf);
    return -1;
  }

  /* Inform application about the progress  */
  if (self->st_callback)
    self->st_callback(self->st_context, self, stun_ready);
  
  SU_DEBUG_3(("TLS connection using %s\n", SSL_get_cipher(ssl)));
  
  server_cert = SSL_get_peer_certificate(ssl); 
  if(server_cert) {
    SU_DEBUG_3(("\t subject: %s\n", X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0)));
    SU_DEBUG_3(("\t issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0)));
  }
  X509_free(server_cert);

  if(SSL_write(ssl, req.enc_buf.data, req.enc_buf.size)==-1) {
    perror("SSL_write"); stun_free_buffer(&req.enc_buf); return -1;
  }
  SU_DEBUG_5(("Shared Secret Request sent to server:\n"));
  debug_print(&req.enc_buf);

  z = SSL_read(ssl, buf, sizeof(buf));
  if(z<=0) {
    if (z < 0) {
      perror("SSL_read");
    }
    stun_free_buffer(&req.enc_buf);
    return -1;
  }
  resp.enc_buf.size = z;
  resp.enc_buf.data = malloc(z);
  memcpy(resp.enc_buf.data, buf, z);
  SU_DEBUG_5(("Shared Secret Response received from server:\n"));
  debug_print(&resp.enc_buf);

  /* closed TLS connection */
  SSL_shutdown(ssl);
  su_close(self->st_socket);

  SSL_free(ssl);
  SSL_CTX_free(ctx);

  stun_free_buffer(&req.enc_buf);
  
  /* process response */
  if(stun_parse_message(&resp) < 0) {
    perror("stun_parse_message"); stun_free_buffer(&resp.enc_buf); return -1;
  }

  switch(resp.stun_hdr.msg_type) {
  case SHARED_SECRET_RESPONSE:
    username = stun_get_attr(resp.stun_attr, USERNAME);
    password = stun_get_attr(resp.stun_attr, PASSWORD);
    if(username!=NULL && password!=NULL) {
      /* move result to se */
      stun_copy_buffer(&self->st_username, username->pattr);
      stun_copy_buffer(&self->st_passwd, password->pattr);
    }
    break;
  case SHARED_SECRET_ERROR_RESPONSE:
    if(stun_process_error_response(&resp) <0) {
      SU_DEBUG_5(("Error in Shared Secret Error Response.\n")); 
    }
    stun_free_buffer(&resp.enc_buf);
    return -1;
    
    break;
  default:
    break;
  }

  return 0;
}

/** Shared secret request/response processing */
int stun_connect_start(stun_engine_t *se, su_addrinfo_t *ai)
{
  int events = SU_WAIT_IN | SU_WAIT_ERR;
  int one, err;
  su_wait_t wait[1] = { SU_WAIT_INIT };
  su_socket_t s = SOCKET_ERROR;
  int family;

  /* open tcp connection to server */
  s = su_socket(family = AF_INET, SOCK_STREAM, 0);
  if (se->st_socket == -1) {
    STUN_ERROR(errno, socket);
    return -1;
  }

  /* asynchronous connect() */
  if (su_setblocking(s, 0) < 0) {
    STUN_ERROR(errno, su_setblocking);
    return -1;
  }
  if (setsockopt(s, SOL_TCP, TCP_NODELAY,
		 (void *)&one, sizeof one) == -1) {
    STUN_ERROR(errno, setsockopt);
    return -1;
  }
  SU_DEBUG_3(("%s: %s: %s\n", __func__, "setsockopt",
	      su_strerror(errno)));

  events = SU_WAIT_CONNECT | SU_WAIT_ERR;

  if (su_wait_create(wait, s, events) == -1)
    STUN_ERROR(errno, su_wait_create);


#if 0
  if (bind(s, (struct sockaddr *)&name, namelen) < 0) {
    STUN_ERROR(errno, bind);
  }
  SU_DEBUG_3(("%s: %s: %s\n", __func__, "bind",
	      su_strerror(errno)));

  /* Do an asynchronous connect(). Three error codes are ok,
   * others cause return -1. */
  if (connect(s, (struct sockaddr *)&se->st_srvr4[0].su_sin, 
	      namelen) == SOCKET_ERROR) {
    err = su_errno();
    if (err != EINPROGRESS && err != EAGAIN && err != EWOULDBLOCK) {
      STUN_ERROR(err, connect);
      return -1;
    }
  }
#else
  /* Do an asynchronous connect(). Three error codes are ok,
   * others cause return -1. */
  if (connect(s, ai->ai_addr, 
	      ai->ai_addrlen) == SOCKET_ERROR) {
    err = su_errno();
    if (err != EINPROGRESS && err != EAGAIN && err != EWOULDBLOCK) {
      STUN_ERROR(err, connect);
      return -1;
    }
  }
#endif


  SU_DEBUG_3(("%s: %s: %s\n", __func__, "connect",
	      su_strerror(err)));

  if (su_root_register(se->st_root, 
		       wait,
		       stun_connected, 
		       se, 
		       0) == -1) {
    STUN_ERROR(errno, su_root_register);
    return -1;
  }

  se->st_socket = s;

  return 0;
}

/** Compose a STUN message of the format defined by stun_msg_t
 *  result encoded in enc_buf ready for sending as well.
 */
int stun_make_sharedsecret_req(stun_msg_t *msg)
{

  int i, len; 
  uint16_t tmp;

  /* compose header */
  msg->stun_hdr.msg_type = SHARED_SECRET_REQUEST;
  msg->stun_hdr.msg_len = 0; /* actual len computed by
				stun_send_message */
  for(i=0; i<8; i++) {
    msg->stun_hdr.tran_id[i] = (1+rand()%RAND_MAX_16);
  } 
  
  /* no buffer assigned yet */
  stun_init_buffer(&msg->enc_buf);
  
  msg->enc_buf.data = malloc(20);
  msg->enc_buf.size = 20;

  tmp = htons(msg->stun_hdr.msg_type); len = 0;
  memcpy(msg->enc_buf.data, &tmp, sizeof(tmp)); len+=sizeof(tmp);
  tmp = htons(msg->stun_hdr.msg_len);
  memcpy(msg->enc_buf.data+len, &tmp, sizeof(tmp)); len+=sizeof(tmp);
  for(i=0; i<8; i++) {
    tmp = htons(msg->stun_hdr.tran_id[i]);
    memcpy(msg->enc_buf.data+len, &tmp, sizeof(tmp)); len+=sizeof(tmp);
  }
  
  return 0;
}

static stun_socket_t *stun_engine_get_stun_socket(stun_engine_t *se)
{
  assert(se);
  return se->st_stun_socket;
}


int stun_send_wait(su_root_magic_t *m, su_wait_t *w, stun_engine_t *self)
{
  int retval = -1, sockfd, z = 0, clnt_addr_len;
  stun_msg_t bind_req, bind_resp;
  unsigned char dgram[512];
  stun_attr_t *mapped_addr, *chg_addr;
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_len;
  /* for retransmission */
  int num_retrx=0;
  long retrx_int=100000;
  fd_set rfds;
  struct timeval tv;
  int events = 0;  
  su_wakeup_f wakeup = NULL;
  su_wait_t wait[1] = { SU_WAIT_INIT };
  stun_socket_t *ss = stun_engine_get_stun_socket(self);

  ss->ss_state = stun_cstate_init;


  while(num_retrx < STUN_MAX_RETRX && z <= 0) {
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds); /* Set sockfd for read monitoring */

    if(retrx_int < 1000000) {
      tv.tv_sec = 0;
      tv.tv_usec = retrx_int;
      retrx_int *= 2; /* double retransmission period */
    }
    else {
      tv.tv_sec = 1;
      tv.tv_usec = retrx_int - 1000000;
    }

    if(select(sockfd+1, &rfds, NULL, NULL, &tv)) {
      /* response received */
      recv_addr_len = sizeof(recv_addr);
      z = recvfrom(sockfd, dgram, 512, 0,
		   (struct sockaddr *)&recv_addr, &recv_addr_len);
      if(z<0) {
	stun_free_message(&bind_req);
	return retval;
      }
      bind_resp.enc_buf.data = (unsigned char *)malloc(z);
      bind_resp.enc_buf.size = z;
      memcpy(bind_resp.enc_buf.data, dgram, z);
      SU_DEBUG_3(("stun: response from server %s:%u\n", inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port)));
      debug_print(&bind_resp.enc_buf);      
    }
    else {
      SU_DEBUG_3(("stun: Time out no. %d, retransmitting.\n", ++num_retrx));
      if(stun_send_message(sockfd, srvr_addr, &bind_req, &(ss->ss_engine->st_passwd))<0) {
	stun_free_message(&bind_req);
	return retval;
      }
      z = 0;
    }
  }

  ss->ss_state = stun_cstate_received;

  if(num_retrx == STUN_MAX_RETRX) {
    stun_free_message(&bind_req);
    return errno = ETIMEDOUT, retval;
  }

  /* process response */
  if(stun_parse_message(&bind_resp) < 0) {
    SU_DEBUG_5(("stun: Error parsing response.\n"));
    stun_free_message(&bind_req);
    stun_free_message(&bind_req);
    return retval;
  }

  ss->ss_state = stun_cstate_processing;

  switch(bind_resp.stun_hdr.msg_type) {
  case BINDING_RESPONSE:
    if(stun_validate_message_integrity(&bind_resp, &ss->ss_engine->st_passwd) <0) {
      stun_free_message(&bind_req);
      stun_free_message(&bind_resp);
      return retval;
    }
    memset(clnt_addr, 0, sizeof(*clnt_addr)); clnt_addr_len = sizeof(*clnt_addr);
    mapped_addr = stun_get_attr(bind_resp.stun_attr, MAPPED_ADDRESS);
    if(mapped_addr!=NULL) {
      /* mapped address is the response */      
      memcpy(clnt_addr, mapped_addr->pattr, clnt_addr_len);

      retval = 0;
    }
    /* update alternative server address */
    if(ss->ss_engine->st_srvr4[1].su_sin.sin_family==0) {
      /* alternative server address not present */
      chg_addr = stun_get_attr(bind_resp.stun_attr, CHANGED_ADDRESS);
      if(chg_addr!=NULL) {
	memcpy(&ss->ss_engine->st_srvr4[1].su_sin, chg_addr->pattr, sizeof(struct sockaddr_in));
      }
    }
    break;
  case BINDING_ERROR_RESPONSE:
    if(stun_process_error_response(&bind_resp)<0) {
      SU_DEBUG_3(("stun: Error in Binding Error Response.\n"));
    }
    break;
  default:
    break;
  }
  /* return result */

  stun_free_message(&bind_resp);
  stun_free_message(&bind_req);

  ss->ss_state = stun_cstate_done;

  return retval;

}

static stun_engine_t *stun_socket_get_engine(stun_socket_t *ss)
{
  return ss->ss_engine;
}


/** This function send a binding request to the address at serv (ip,
 *  port). which could be the original or alternative socket addresses
 *  of the STUN server. Local address is provided in cli, and
 *  resulting mapped address is also saved in cli.
 *  Return 0 if successful, -1 if failed
 *
 * @return
 * On success, zero is returned.  Upon error, -1 is returned, and @e errno is
 * set appropriately.
 * 
 * @ERRORS
 * @ERROR EBADF           @a sockfd is not a valid deseriptor.
 * @ERROR EPROTONOSUPPORT @a sockfd is not an UDP socket.
 * @ERROR EINVAL          The socket is already bound to an address.
 * @ERROR EACCESS   	  The address is protected, and the user is not 
 *                  	  the super-user.
 * @ERROR ENOTSOCK  	  Argument is a descriptor for a file, not a socket.
 * @ERROR EAGAIN          Operation in progress. Application should call 
 *                        stun_bind() again when there is data available on 
 *                        the socket.
 * @ERROR ETIMEDOUT       Request timed out.
 * 
 */   
int stun_bind_test(stun_socket_t *ss,
#if 1
		   struct sockaddr_storage *srvr_addr,
		   struct sockaddr_storage *clnt_addr,
#else
		   struct sockaddr_in *srvr_addr,
		   struct sockaddr_in *clnt_addr,
#endif
		   int chg_ip,
		   int chg_port)
{
  int retval = -1, s;
  stun_msg_t bind_req;
  struct sockaddr_in recv_addr;
  int events = 0;  
  su_wait_t wait[1] = { SU_WAIT_INIT };
  unsigned rmem = 0, wmem = 0;
  stun_engine_t *se = stun_socket_get_engine(ss);

  ss->ss_state = stun_cstate_init;

  if (ss == NULL || srvr_addr == NULL || clnt_addr == NULL) 
    return errno = EFAULT, retval;

  /* run protocol here... */
  s = ss->ss_sockfd;

  SU_DEBUG_3(("stun: sending to %s:%u (req-flags: msgint=%d, ch-addr=%d, chh-port=%d)\n", 
	      inet_ntoa(srvr_addr->sin_addr), ntohs(srvr_addr->sin_port),
	      ss->ss_engine->st_use_msgint, chg_ip, chg_port));

  /* compose binding request */
  if(stun_make_binding_req(ss, &bind_req, chg_ip, chg_port)<0) 
    return retval;

  ss->ss_state = stun_cstate_started;

  events = SU_WAIT_IN;

#if HAVE_IP_RECVERR
  if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
    int const one = 1;
    if (setsockopt(s, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0) {
      if (ai->ai_family == AF_INET)
	return TPORT_LISTEN_ERROR(su_errno(), IP_RECVERR);
    }
    events |= SU_WAIT_ERR;
  }
#endif
    
  if (rmem != 0 && 
      setsockopt(s, SOL_SOCKET,
		 SO_RCVBUF, (void *)&rmem, sizeof rmem) < 0) {
    SU_DEBUG_3(("setsockopt(SO_RCVBUF): %s\n", 
		su_strerror(su_errno())));
  }
  
  if (wmem != 0 && 
      setsockopt(s, SOL_SOCKET,
		 SO_SNDBUF, (void *)&wmem, sizeof wmem) < 0) {
    SU_DEBUG_3(("setsockopt(SO_SNDBUF): %s\n", 
		su_strerror(su_errno())));
  }

  if(stun_send_message(s, srvr_addr, &bind_req, &(ss->ss_engine->st_passwd))<0) {
    stun_free_message(&bind_req);
    return retval;
  }

  if (su_wait_create(wait, s, events) == -1)
    return TPORT_LISTEN_ERROR(su_errno(), su_wait_create);

  /* Register receiving or accepting function with events specified above */
  su_root_register(se->st_root, wait, stun_send_wait, se, 0);
  
  return 0;
}

/** Compose a STUN message of the format defined by stun_msg_t */
int stun_make_binding_req(stun_socket_t *ss, stun_msg_t *msg, int chg_ip, int chg_port)
{

  int i;
  stun_attr_t *tmp, **p; 

  /* compose header */
  msg->stun_hdr.msg_type = BINDING_REQUEST;
  msg->stun_hdr.msg_len = 0; /* actual len computed by
				stun_send_message */
  for(i=0; i<8; i++) {
    msg->stun_hdr.tran_id[i] = (1+rand()%RAND_MAX_16);
  } 
  
  /* optional attributes:
   * - Response Address
   * - Change Request X
   * - Username
   * - Message-Integrity */
  msg->stun_attr = NULL;
  /* CHANGE_REQUEST */
  p = &(msg->stun_attr);
  if(chg_ip || chg_port) {
    stun_attr_changerequest_t *attr_cr;
    tmp = (stun_attr_t *) malloc(sizeof(stun_attr_t));
    tmp->attr_type = CHANGE_REQUEST;
    attr_cr = (stun_attr_changerequest_t *) malloc(sizeof(stun_attr_changerequest_t));
    attr_cr->value = (chg_ip? STUN_CR_CHANGE_IP:0)|(chg_port? STUN_CR_CHANGE_PORT:0);
    tmp->pattr = attr_cr;
    tmp->next = NULL;
    *p = tmp; p = &(tmp->next);
  }

  /* USERNAME */
  if(ss->ss_engine->st_use_msgint &&
     ss->ss_engine->st_username.data && 
     ss->ss_engine->st_passwd.data) {
    tmp = (stun_attr_t *) malloc(sizeof(stun_attr_t));
    tmp->attr_type = USERNAME;
    tmp->pattr = &ss->ss_engine->st_username;
    tmp->next = NULL;
    *p = tmp; p = &(tmp->next);

    /* dummy MESSAGE_INTEGRITY attribute, computed later */
    tmp = (stun_attr_t *) malloc(sizeof(stun_attr_t));
    tmp->attr_type = MESSAGE_INTEGRITY;
    tmp->pattr = NULL;
    tmp->next = NULL;
    *p = tmp; p = &(tmp->next);
  }

  /* no buffer assigned yet */
  msg->enc_buf.data = NULL;
  msg->enc_buf.size = 0;
  return 0;
}

int stun_process_response(stun_msg_t *msg)
{

  /* parse msg first */
  if(stun_parse_message(msg)<0) {
    SU_DEBUG_3(("stun: Error parsing response.\n"));
    return -1;
  }

  /* check message digest if exists */
  switch(msg->stun_hdr.msg_type) {
  case BINDING_RESPONSE:
    if(stun_process_binding_response(msg) < 0) 
      return -1;
    break;
  case BINDING_ERROR_RESPONSE:
    if(stun_process_error_response(msg) < 0)
      return -1;
    break;
  default:
    return -1;
  }

  return 0;
}


/** process binding response */
int stun_process_binding_response(stun_msg_t *msg) {
  /* currently not needed. */
  return 0;
}

/** process binding error response
 *  Report error and return
 */
int stun_process_error_response(stun_msg_t *msg)
{
  stun_attr_t *attr;
  stun_attr_errorcode_t *ec;

  attr = stun_get_attr(msg->stun_attr, ERROR_CODE);
  if(attr==NULL) {perror("stun_process_error_response"); return -1;}

  ec = (stun_attr_errorcode_t *)attr->pattr;
  
  SU_DEBUG_5(("stun: Received Binding Error Response:\n"));
  SU_DEBUG_5(("stun: Error: %d %s\n", ec->code, ec->phrase));

  return 0;
}

int stun_set_uname_pwd(stun_engine_t *se, const char *uname, int len_uname, const char *pwd, int len_pwd)
{
  se->st_username.data = (unsigned char *) malloc(len_uname);
  memcpy(se->st_username.data, uname, len_uname);
  se->st_username.size = len_uname;
  
  se->st_passwd.data = (unsigned char *) malloc(len_pwd);
  memcpy(se->st_passwd.data, pwd, len_pwd);
  se->st_passwd.size = len_pwd;

  se->st_use_msgint = 1; /* turn on message integrity ussage */
  
  return 0;
}
  
/* convert character address format to sockaddr_in */
int stun_atoaddr(struct sockaddr_in *addr, char const *in)
{
  su_addrinfo_t *ai_res = NULL, *ai, hints[1] = {{ 0 }};
  char const *host;
  char *port, tmp[SU_ADDRSIZE];
  int res;

  hints->ai_family = AF_INET;

  port = strstr(in, ":");
  if (port == NULL) {
    /* no port specified */
    host = in;
  }
  else {
    assert(port - in < strlen(in) + 1);
    memcpy(tmp, in, port - in);
    tmp[port - in] = 0;
    host = tmp;
    ++port;
  }
    
  res = su_getaddrinfo(host, NULL, hints, &ai_res);
  for (ai = ai_res; 
       ai;
       ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      memcpy(addr, ai_res->ai_addr, sizeof(struct sockaddr));
      break;
    }
  }

  if (port) 
    addr->sin_port = htons(atoi(port));

  if (ai_res)
    su_freeaddrinfo(ai_res);

  return res;
}

char const *stun_nattype(stun_engine_t *se)
{
  switch(se->st_nattype) {
  case STUN_NAT_UNKNOWN: return stun_nat_unknown;
  case STUN_OPEN_INTERNET: return stun_open_internet;
  case STUN_UDP_BLOCKED: return stun_udp_blocked;
  case STUN_SYM_UDP_FW: return stun_sym_udp_fw;
  case STUN_NAT_FULL_CONE: return stun_nat_full_cone;
  case STUN_NAT_SYM: return stun_nat_sym;
  case STUN_NAT_RES_CONE: return stun_nat_res_cone;
  case STUN_NAT_PORT_RES_CONE: return stun_nat_port_res_cone;
  default: return "INVALID NAT TYPE";
  }
}

int stun_get_lifetime(stun_socket_t *ss, struct sockaddr *my_addr, int *addrlen, int *lifetime)
{
  int retval = -1, sockfdx, sockfdy;
  socklen_t x_len, y_len, recv_addr_len, mapped_len;
  struct sockaddr_in *clnt_addr=0, x_addr, y_addr, recv_addr, mapped_addr;
  int lt_cur=0, lt=STUN_LIFETIME_EST, lt_max = STUN_LIFETIME_MAX;
  stun_attr_t *mapped_addr_attr;
  /* testing su_getlocalinfo() */
  su_localinfo_t  hints[1] = {{ LI_CANONNAME | LI_NUMERIC }}, *li, *res = NULL;
  int i, error, found=0, z;
  fd_set rfds;
  struct timeval tv;
  stun_msg_t bind_req, bind_resp;
  unsigned char dgram[512];


  if (ss == NULL) 
    return errno = EFAULT, -1;

  SU_DEBUG_3(("stun: determining binding life time, this may take a while.\n"));

  /* get local ip address */
  clnt_addr = (struct sockaddr_in *)my_addr;

  if(clnt_addr==NULL || clnt_addr->sin_addr.s_addr == 0) {
    if((error = su_getlocalinfo(hints, &res)) == 0) {
      /* try to bind to the first available address */
      for(i=0, li = res; li; li = li->li_next) {
	if(li->li_family == AF_INET) {
	  memcpy(clnt_addr, &li->li_addr->su_sin, sizeof(li->li_addr->su_sin));
	  SU_DEBUG_3(("stun: local address found to be %s:%u\n", 
		      inet_ntoa(clnt_addr->sin_addr), 
		      (unsigned)ntohs(clnt_addr->sin_port)));
	  found=1;
	  break;
	}
      }
      if(!found) {
	SU_DEBUG_5(("stun: su_getlocalinfo: %s\n", su_gli_strerror(error)));
	return errno = EFAULT, -1;
      }
    }
    else {
      SU_DEBUG_5(("stun: su_getlocalinfo: %s\n", su_gli_strerror(error)));
      return errno = EFAULT, -1;
    }
  }

  /* run protocol here... */
  sockfdx = ss->ss_sockfd;

  clnt_addr->sin_port = 0;
  /* initialize socket x */
  if(bind(sockfdx, (struct sockaddr *)clnt_addr, *addrlen)<0) {
    SU_DEBUG_3(("stun: Error binding to %s:%u\n", inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
    return retval;
  }
  x_len = sizeof(x_addr);
  getsockname(sockfdx, (struct sockaddr *)&x_addr, &x_len);  
  SU_DEBUG_3(("stun: Local socket x bound to: %s:%u\n", inet_ntoa(x_addr.sin_addr),
	      (unsigned)ntohs(x_addr.sin_port)));

  /* initialize socket y */
  sockfdy = socket(AF_INET, SOCK_DGRAM, 0);
  if(bind(sockfdy, (struct sockaddr *)clnt_addr, *addrlen)<0) {
    SU_DEBUG_3(("stun: Error binding to %s:%u\n", inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
    return retval;
  }
  y_len = sizeof(y_addr);
  getsockname(sockfdy, (struct sockaddr *)&y_addr, &y_len);  
  SU_DEBUG_3(("stun: Local socket y bound to: %s:%u\n", inet_ntoa(y_addr.sin_addr), 
	      (unsigned)ntohs(y_addr.sin_port)));
   
  i=1;
  while(abs(lt_cur-lt) > STUN_LIFETIME_CI) {
    SU_DEBUG_3(("stun: Lifetime determination round %d, testing lifetime of %d sec.\n", i++, lt));
    /* send request from X */
    if(stun_make_binding_req(ss, &bind_req, 0, 0) <0)
      return retval;
    if(stun_send_message(sockfdx, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[0], &bind_req, &(ss->ss_engine->st_passwd))<0)
      return retval;

    FD_ZERO(&rfds);
    FD_SET(sockfdx, &rfds); /* Set sockfdx for read monitoring */
    z = 0;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(select(sockfdx+1, &rfds, NULL, NULL, &tv)) {
      /* response received */
      recv_addr_len = sizeof(recv_addr);
      z = recvfrom(sockfdx, dgram, 512, 0,
		   (struct sockaddr *)&recv_addr, &recv_addr_len);
      if(z<0) {
	return retval;
      }
      bind_resp.enc_buf.data = (unsigned char *)malloc(z);
      bind_resp.enc_buf.size = z;
      memcpy(bind_resp.enc_buf.data, dgram, z);
      SU_DEBUG_3(("stun: response from server %s:%u\n", inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port)));
      debug_print(&bind_resp.enc_buf);      
    }
    else {
      SU_DEBUG_3(("stun: No response from server. Check configuration.\n"));
      return retval;
    }
    /* process response */
    if(stun_parse_message(&bind_resp) < 0) {
      SU_DEBUG_5(("stun: Error parsing response.\n"));
      return retval;
    }
    if(bind_resp.stun_hdr.msg_type==BINDING_RESPONSE) {
      memset(&mapped_addr, 0, sizeof(mapped_addr)); mapped_len = sizeof(mapped_addr);
      mapped_addr_attr = stun_get_attr(bind_resp.stun_attr, MAPPED_ADDRESS);
      if(mapped_addr_attr!=NULL) {
	memcpy(&mapped_addr, mapped_addr_attr->pattr, mapped_len);
      }
      else {
	return retval;
      }
    }
    stun_free_message(&bind_req);
    stun_free_message(&bind_resp);
    sleep(lt);
    /* send from sockfdy */
    if(stun_make_binding_req(ss, &bind_req, 0, 0) <0)
      return retval;
    stun_add_response_address(&bind_req, &mapped_addr);
    if(stun_send_message(sockfdy, (struct sockaddr_in *)&ss->ss_engine->st_srvr4[0], &bind_req, &(ss->ss_engine->st_passwd))<0)
      return retval;

    FD_ZERO(&rfds);
    FD_SET(sockfdx, &rfds); /* Set sockfdx for read monitoring */
    z = 0;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(select(sockfdx+1, &rfds, NULL, NULL, &tv)) {
      /* response received */
      recv_addr_len = sizeof(recv_addr);
      z = recvfrom(sockfdx, dgram, 512, 0,
		   (struct sockaddr *)&recv_addr, &recv_addr_len);
      if(z<0) {
	return retval;
      }
      /* mapping with X still valid */
      lt_cur = lt;
      lt = (int) (lt+lt_max)/2;
      SU_DEBUG_3(("stun: Response received from socket X, lifetime at least %d sec, next trial: %d sec\n\n", 
		  lt_cur, lt));
    }
    else {
      /* no response */
      lt_max = lt;
      lt = (int) (lt+lt_cur)/2;
      SU_DEBUG_3(("stun: No response received from socket X, lifetime at most %d sec, next trial: %d sec\n\n", 
		  lt_max, lt));
    }
  }

  *lifetime = lt_cur;
  return 0;
}

int stun_add_response_address(stun_msg_t *req, struct sockaddr_in *mapped_addr)
{
  stun_attr_sockaddr_t *addr;
  stun_attr_t *tmp;

  tmp = (stun_attr_t *)malloc(sizeof(stun_attr_t));
  tmp->attr_type = RESPONSE_ADDRESS;
  addr = malloc(sizeof(stun_attr_sockaddr_t));
  memcpy(addr, mapped_addr, sizeof(stun_attr_sockaddr_t));
  tmp->pattr = addr;
  
  if(req->stun_attr==NULL) {
    tmp->next = NULL;
  }
  else {
    tmp->next = req->stun_attr;
  }
  req->stun_attr = tmp;

  return 0;
}
