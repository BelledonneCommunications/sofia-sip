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
 * 
 * @date Created: Thu Jul 24 17:21:00 2003 ppessi
 * @date Last modified: Mon Aug  8 19:10:15 2005 ppessi
 */

#include "config.h" 

#include <assert.h>

#include "stun.h"
#include "stun_tag.h"

#include <su_alloc.h>
#include <su_tagarg.h>
#include <su_log.h>
#include <su.h>
#include <su_localinfo.h>

#define STUN_DEBUG 5		/* default log level */

/** STUN log. */
su_log_t stun_log[] = { SU_LOG_INIT("stun", "STUN_DEBUG", STUN_DEBUG) }; 
#define SU_LOG (stun_log)

#include <su_debug.h>

char const stun_nat_unknown[] = "NAT type undetermined",
  stun_open_internet[] = "Open Internet",
  stun_udp_blocked[] = "UDP traffic is blocked, or Server unreachable",
  stun_sym_udp_fw[] = "Symmetric UDP Firewall",
  stun_nat_full_cone[] = "Full-Cone NAT",
  stun_nat_sym[] = "Symmetric NAT",
  stun_nat_res_cone[] = "Restricted Cone NAT",
  stun_nat_port_res_cone[] = "Port Restricted Cone NAT";

struct stun_engine_s
{
  su_home_t      stun_home[1];
  su_sockaddr_t  stun_srvr4[2]; /* primary and secondary addresses */
  int           use_msgint;     /* use message integrity? */
  stun_buffer_t username;
  stun_buffer_t password;
  int nattype; 
};

struct stun_socket_s
{
  stun_engine_t *ss_engine;
  int            ss_sockfd;
  /* State for STUN protocol ? */
  int            ss_state;
};

/** 
 * Creates a STUN engine 
 *
 * @param stun server hostname or IPv4 address 
 * @param msg_integrity true if msg integr. should be used
 *
 *
 */
stun_engine_t *stun_engine_create(char const *server, 
				  int msg_integrity)
{
  return stun_engine_tcreate(STUNTAG_SERVER(server), 
			     STUNTAG_INTEGRITY(msg_integrity), 
			     TAG_END());
}

/** 
 * Creates a STUN engine 
 *
 * @param tag,value,... tag-value list 
 *
 * @TAGS 
 * @TAG STUNTAG_SERVER() stun server hostname or dotted IPv4 address
 * @TAG STUNTAG_INTEGRITY() true if msg integrity should be used
 *
 */
stun_engine_t *stun_engine_tcreate(tag_type_t tag, tag_value_t value, ...)
{
  stun_engine_t *stun;
  char const *server = NULL;
  int msg_integrity = 1;
  ta_list ta;

  SU_DEBUG_5(("%s(\"%s\"): called\n", 
	      "stun_engine_tcreate", server));

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
  
  stun = su_home_clone(NULL, sizeof(*stun));

  if (stun) {
    /* Store server address in *stun, run discovery process?? 
     * I suppose this may block for the moment
     */
    memset(&stun->stun_srvr4[0], 0, sizeof(stun->stun_srvr4[0]));
    if(server) {
      stun_atoaddr((struct sockaddr_in *)&(stun->stun_srvr4[0]), server);
      if(stun->stun_srvr4[0].su_sin.sin_port == 0) {
	stun->stun_srvr4[0].su_sin.sin_port = htons(STUN_DEFAULT_PORT);
      }
    }

    /* alternative address set to 0 */
    memset(&stun->stun_srvr4[1], 0, sizeof(stun->stun_srvr4[1])); 
    /* initialize username and password */
    stun_init_buffer(&stun->username);
    stun_init_buffer(&stun->password);

    stun->nattype = STUN_NAT_UNKNOWN;

    /* initialize random number generator */
    srand(time(NULL));

    stun->use_msgint = 0;
    if(msg_integrity) {
      /* get shared secret */ 
      SU_DEBUG_3(("Contacting Server to obtain shared secret. Please wait.\n"));
      if(stun_get_sharedsecret(stun)==0) {
	SU_DEBUG_3(("Shared secret obtained from server.\n"));
	stun->use_msgint = 1;
      }
      else {
	SU_DEBUG_3(("Shared secret NOT obtained from server. Proceed without username/password.\n"));
      } 
    }

  
  }

  return stun;
}

/** Destroy a STUN client */ 
void stun_engine_destroy(stun_engine_t *stun)
{ 
  su_home_zap(stun->stun_home);
}

stun_socket_t *stun_socket_create(stun_engine_t *se, int sockfd)
{
  stun_socket_t *ss;

  if (se == NULL) return errno = EINVAL, NULL;

  ss = su_zalloc(se->stun_home, sizeof *ss);

  if (ss) {
    ss->ss_engine = se;
    ss->ss_sockfd = sockfd;
  }

  return ss;
}

void stun_socket_destroy(stun_socket_t *ss)
{
  if (ss)
    su_free(ss->ss_engine->stun_home, ss);
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
	      struct sockaddr *my_addr, 
	      socklen_t *addrlen,
	      int *lifetime)
{
  int retval = -1, sockfd;
  struct sockaddr_in *clnt_addr=0, bind_addr;
  socklen_t bind_len;
  /* testing su_getlocalinfo() */
  su_localinfo_t  hints[1] = {{ LI_CANONNAME | LI_NUMERIC }}, *li, *res = NULL;
  int i, error, found=0;
  
  /*   if (ss == NULL || my_addr == NULL || addrlen == NULL) */
  if (ss == NULL) 
    return errno = EFAULT, -1;

  clnt_addr = (struct sockaddr_in *)my_addr;

  if (clnt_addr==NULL || clnt_addr->sin_addr.s_addr == 0) {
    if((error = su_getlocalinfo(hints, &res)) == 0) {
      /* try to bind to the first available address */
      for(i=0, li = res; li; li = li->li_next) {
        if(li->li_family == AF_INET) {
          memcpy(clnt_addr, &li->li_addr->su_sin, sizeof(li->li_addr->su_sin));
          SU_DEBUG_3(("stun: local address found to be %s:%u\n", 
          inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
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
    if (res) su_freelocalinfo(res);
  }

  /* run protocol here... */
  sockfd = ss->ss_sockfd;

  if(bind(sockfd, (struct sockaddr *)clnt_addr, *addrlen)<0) {
    SU_DEBUG_3(("Error binding to %s:%u\n", inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
    return -1;
  }

  bind_len = sizeof(bind_addr);
  getsockname(sockfd, (struct sockaddr *)&bind_addr, &bind_len);
  
  SU_DEBUG_3(("Local socket bound to: %s:%u\n", inet_ntoa(bind_addr.sin_addr), 
	      (unsigned)ntohs(bind_addr.sin_port)));
  

  retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[0], 
			  clnt_addr, 0, 0);
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
 *  NAT type is set in ss->se_engine.nattype
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
      retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[0],
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
      retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[0],
			      &mapped_addr2, 1, 1);
      if(retval==-1) {
	if(errno==ETIMEDOUT) {
	  /* No Response */
	  retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[1], 
				  &mapped_addr2, 0, 0);
	  if(retval==0) { /* response comes back, has to be the case */
	    if(memcmp(&mapped_addr1, &mapped_addr2, 8)==0) {
	      /* Same Public IP and port, Test III, server ip 0 or 1 should be
		 same */
	      retval = stun_bind_test(ss, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[0],
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
  
  ss->ss_engine->nattype = nattype;
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

/** Shared secret request/response processing */
int stun_get_sharedsecret(stun_engine_t *se)
{
  stun_msg_t req, resp;
  int sockfd, z;
  SSL_CTX* ctx;
  SSL *ssl;
  X509* server_cert;
  unsigned char buf[512];
  stun_attr_t *password, *username;

  /* compose shared secret request */
  if(stun_make_sharedsecret_req(&req)!=0) {
    perror("shared secret request"); stun_free_buffer(&req.enc_buf); return -1;
  }

  /* openssl initiation */
  SSLeay_add_ssl_algorithms();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(TLSv1_client_method());

  if(ctx==NULL) {
    perror("openssl"); stun_free_buffer(&req.enc_buf); return -1;
  }

  if(SSL_CTX_set_cipher_list(ctx, "AES128-SHA")==0) {
    perror("openssl"); stun_free_buffer(&req.enc_buf); return -1;
  }

  /* open tcp connection to server */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1) {
    perror("socket"); stun_free_buffer(&req.enc_buf); return -1;
  }

  if(connect(sockfd, (struct sockaddr *)&se->stun_srvr4[0].su_sin, 
	     sizeof(struct sockaddr))==-1) {
    perror("connect"); stun_free_buffer(&req.enc_buf); return -1;
  }

  /* Start TLS negotiation */
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);
  if(SSL_connect(ssl)==-1) {
    perror("SSL_connect"); stun_free_buffer(&req.enc_buf); return -1;
  }
  
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
  close(sockfd);

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
      stun_copy_buffer(&se->username, username->pattr);
      stun_copy_buffer(&se->password, password->pattr);
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
int stun_bind_test(stun_socket_t *ss, struct sockaddr_in *srvr_addr, struct sockaddr_in *clnt_addr, 
		   int chg_ip, int chg_port) 
{
  int retval = -1, sockfd, z, clnt_addr_len;
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
  
  if (ss == NULL || srvr_addr == NULL || clnt_addr == NULL) 
    return errno = EFAULT, retval;

  /* run protocol here... */
  sockfd = ss->ss_sockfd;

  /* compose binding request */
  if(stun_make_binding_req(ss, &bind_req, chg_ip, chg_port)<0) 
    return retval;

  if(stun_send_message(sockfd, srvr_addr, &bind_req, &(ss->ss_engine->password))<0) {
    stun_free_message(&bind_req);
    return retval;
  }

  FD_ZERO(&rfds);
  FD_SET(sockfd, &rfds); /* Set sockfd for read monitoring */
  z = 0;
  while(num_retrx < STUN_MAX_RETRX && z <= 0) {
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
      SU_DEBUG_5(("response from server %s:%u\n", inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port)));
      debug_print(&bind_resp.enc_buf);      
    }
    else {
      SU_DEBUG_3(("Time out no. %d, retransmitting.\n", ++num_retrx));
      if(stun_send_message(sockfd, srvr_addr, &bind_req, &(ss->ss_engine->password))<0) {
	stun_free_message(&bind_req);
	return retval;
      }
    }
  }

  if(num_retrx == STUN_MAX_RETRX) {
    stun_free_message(&bind_req);
    return errno = ETIMEDOUT, retval;
  }

  /* process response */
  if(stun_parse_message(&bind_resp) < 0) {
    SU_DEBUG_5(("Error parsing response.\n"));
    stun_free_message(&bind_req);
    stun_free_message(&bind_req);
    return retval;
  }

  switch(bind_resp.stun_hdr.msg_type) {
  case BINDING_RESPONSE:
    if(stun_validate_message_integrity(&bind_resp, &ss->ss_engine->password) <0) {
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
    if(ss->ss_engine->stun_srvr4[1].su_sin.sin_family==0) {
      /* alternative server address not present */
      chg_addr = stun_get_attr(bind_resp.stun_attr, CHANGED_ADDRESS);
      if(chg_addr!=NULL) {
	memcpy(&ss->ss_engine->stun_srvr4[1].su_sin, chg_addr->pattr, sizeof(struct sockaddr_in));
      }
    }
    break;
  case BINDING_ERROR_RESPONSE:
    if(stun_process_error_response(&bind_resp)<0) {
      SU_DEBUG_3(("Error in Binding Error Response.\n"));
    }
    break;
  default:
    break;
  }
  /* return result */

  stun_free_message(&bind_resp);
  stun_free_message(&bind_req);

  return retval;
}

/** Compose a STUN message of the format defined by stun_msg_t */
int stun_make_binding_req(stun_socket_t *ss, stun_msg_t *msg, int chg_ip, int chg_port) {

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
  if(ss->ss_engine->use_msgint &&
     ss->ss_engine->username.data && 
     ss->ss_engine->password.data) {
    tmp = (stun_attr_t *) malloc(sizeof(stun_attr_t));
    tmp->attr_type = USERNAME;
    tmp->pattr = &ss->ss_engine->username;
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

int stun_process_response(stun_msg_t *msg) {

  /* parse msg first */
  if(stun_parse_message(msg)<0) {
    SU_DEBUG_3(("Error parsing response.\n"));
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
int stun_process_error_response(stun_msg_t *msg) {
  stun_attr_t *attr;
  stun_attr_errorcode_t *ec;

  attr = stun_get_attr(msg->stun_attr, ERROR_CODE);
  if(attr==NULL) {perror("stun_process_error_response"); return -1;}

  ec = (stun_attr_errorcode_t *)attr->pattr;
  
  SU_DEBUG_5(("Received Binding Error Response:\n"));
  SU_DEBUG_5(("Error: %d %s\n", ec->code, ec->phrase));

  return 0;
}

int stun_set_uname_pwd(stun_engine_t *se, const unsigned char *uname, int len_uname, 
		       const unsigned char *pwd, int len_pwd) {
  se->username.data = (unsigned char *) malloc(len_uname);
  memcpy(se->username.data, uname, len_uname);
  se->username.size = len_uname;
  
  se->password.data = (unsigned char *) malloc(len_pwd);
  memcpy(se->password.data, pwd, len_pwd);
  se->password.size = len_pwd;

  se->use_msgint = 1; /* turn on message integrity ussage */
  
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
  switch(se->nattype) {
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
    SU_DEBUG_3(("Error binding to %s:%u\n", inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
    return retval;
  }
  x_len = sizeof(x_addr);
  getsockname(sockfdx, (struct sockaddr *)&x_addr, &x_len);  
  SU_DEBUG_3(("Local socket x bound to: %s:%u\n", inet_ntoa(x_addr.sin_addr),
	      (unsigned)ntohs(x_addr.sin_port)));

  /* initialize socket y */
  sockfdy = socket(AF_INET, SOCK_DGRAM, 0);
  if(bind(sockfdy, (struct sockaddr *)clnt_addr, *addrlen)<0) {
    SU_DEBUG_3(("Error binding to %s:%u\n", inet_ntoa(clnt_addr->sin_addr), (unsigned)ntohs(clnt_addr->sin_port)));
    return retval;
  }
  y_len = sizeof(y_addr);
  getsockname(sockfdy, (struct sockaddr *)&y_addr, &y_len);  
  SU_DEBUG_3(("Local socket y bound to: %s:%u\n", inet_ntoa(y_addr.sin_addr), 
	      (unsigned)ntohs(y_addr.sin_port)));
   
  i=1;
  while(abs(lt_cur-lt) > STUN_LIFETIME_CI) {
    SU_DEBUG_3(("STUN Lifetime determination round %d, testing lifetime of %d sec.\n", i++, lt));
    /* send request from X */
    if(stun_make_binding_req(ss, &bind_req, 0, 0) <0)
      return retval;
    if(stun_send_message(sockfdx, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[0], &bind_req, &(ss->ss_engine->password))<0)
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
      SU_DEBUG_3(("response from server %s:%u\n", inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port)));
      debug_print(&bind_resp.enc_buf);      
    }
    else {
      SU_DEBUG_3(("No response from server. Check configuration.\n"));
      return retval;
    }
    /* process response */
    if(stun_parse_message(&bind_resp) < 0) {
      SU_DEBUG_5(("Error parsing response.\n"));
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
    if(stun_send_message(sockfdy, (struct sockaddr_in *)&ss->ss_engine->stun_srvr4[0], &bind_req, &(ss->ss_engine->password))<0)
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
      SU_DEBUG_3(("Response received from socket X, lifetime at least %d sec, next trial: %d sec\n\n", 
		  lt_cur, lt));
    }
    else {
      /* no response */
      lt_max = lt;
      lt = (int) (lt+lt_cur)/2;
      SU_DEBUG_3(("No response received from socket X, lifetime at most %d sec, next trial: %d sec\n\n", 
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
