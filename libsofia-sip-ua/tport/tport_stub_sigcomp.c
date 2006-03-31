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

/**@CFILE tport_stub_sigcomp.c Stub interface for SigComp
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>
 *
 * @date Created: Fri Mar 31 12:31:36 EEST 2006
 */

#include "config.h"

#include "tport_internal.h"

struct tport_comp_vtable_s {
  /* NOTE: this will change! Unstable! Do not use! */
  int vsc_size;
  struct sigcomp_compartment *
  (*vsc_init_comp)(tport_t *master_tport,
		   tport_comp_t **inout_sc,
		   char const *algorithm);
				 
  void (*vsc_deinit_comp)(tport_t *master_tport,
			  tport_comp_t **in_sc);

  char const *(*vsc_comp_name)(tport_comp_t const *master_sc,
			       char const *compression,
			       tagi_t const *tags);

  /* Mapping of public tport API */

  int (*vsc_can_send_comp)(tport_comp_t const *);
  int (*vsc_can_recv_comp)(tport_comp_t const *);

  int (*vsc_set_comp_name)(tport_t const *self, 
			   tport_comp_t const *return_sc,
			   char const *comp);

  int (*vsc_sigcomp_option)(tport_t const *self,
			    struct sigcomp_compartment *cc,
			    char const *option);

  struct sigcomp_compartment *
  (*vsc_sigcomp_compartment)(tport_t *self,
			     char const *name, int namelen,
			     int create_if_needed);

  struct sigcomp_compartment * 
  (*vsc_compartment_incref)(struct sigcomp_compartment *cc);

  void (*vsc_compartment_decref)(struct sigcomp_compartment **pointer_to_cc);

  int (*vsc_sigcomp_assign)(tport_t *self, 
			    tport_comp_t **,
			    struct sigcomp_compartment *);

  int (*vsc_has_sigcomp_assigned)(tport_comp_t const *comp);

  int (*vsc_sigcomp_accept)(tport_t *self,
			    tport_comp_t const *comp,
			    struct sigcomp_compartment *cc,
			    msg_t *msg);

  int (*vsc_delivered_using_udvm)(tport_t *tp,
				  msg_t const *msg,
				  struct sigcomp_udvm **return_pointer_to_udvm,
				  int remove);

  int (*vsc_sigcomp_close)(tport_t *self,
			   struct sigcomp_compartment *cc,
			   int how);

  int (*vsc_sigcomp_lifetime)(tport_t *self,
			      struct sigcomp_compartment *,
			      unsigned lifetime_in_ms,
			      int only_expand);

  /* Internal API */

  struct sigcomp_udvm **(*vsc_get_udvm_slot)(tport_t *self);

  struct sigcomp_compartment *
  (*vsc_sigcomp_assign_if_needed)(tport_t *self,
				  struct sigcomp_compartment *cc);

  void (*vsc_try_accept_sigcomp)(tport_t const *self, 
				 tport_comp_t *sc,
				 msg_t *msg);

  int (*vsc_recv_comp)(tport_t const *self, int N);

  int (*vsc_send_comp)(tport_t const *self,
		       msg_t *msg, 
		       msg_iovec_t iov[], 
		       int iovused,
		       struct sigcomp_compartment *cc,
		       tport_comp_t *sc);


};

tport_comp_vtable_t const *tport_comp_vtable = NULL;

int tport_plug_in_compress(tport_comp_vtable_t const *vsc)
{
  return -1;
}

char const tport_sigcomp_name[] = "sigcomp";

/** Canonize compression string */
char const *tport_canonize_comp(char const *comp)
{
  if (comp && strcasecmp(comp, tport_sigcomp_name) == 0)
    return tport_sigcomp_name;
  return NULL;
}

/** Initialize Sigcomp and the master compartment */
struct sigcomp_compartment *
tport_init_comp(tport_t *mr, char const *algorithm_name)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc && tport_is_master(mr))
    return vsc->vsc_init_comp(mr, &mr->tp_comp, algorithm_name);

  return NULL;
}

void tport_deinit_comp(tport_master_t *mr)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    vsc->vsc_deinit_comp(mr->mr_master, &mr->mr_master->tp_comp);
}

char const *tport_comp_name(tport_primary_t *pri,
			    char const *name,
			    tagi_t const *tags)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;
  tport_comp_t const *comp = pri->pri_master->mr_master->tp_comp;

  if (vsc)
    return vsc->vsc_comp_name(comp, name, tags);

  return NULL;
}

/** Check if transport can receive compressed messages */
int tport_can_recv_sigcomp(tport_t const *self)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    return vsc->vsc_can_recv_comp(self->tp_comp);

  return 0;
}

/** Check if transport can send compressed messages */
int tport_can_send_sigcomp(tport_t const *self)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    return vsc->vsc_can_send_comp(self->tp_comp);

  return 0;
}

/** Check if transport supports named compression */
int tport_has_compression(tport_t const *self, char const *comp)
{
  return
    self && comp && 
    self->tp_name->tpn_comp == tport_canonize_comp(comp);
}

int tport_set_compression(tport_t *self, char const *comp)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    return vsc->vsc_set_comp_name(self, self->tp_comp, comp);

  return (self == NULL || comp) ? -1 : 0;
}

/** Set options to SigComp */
int tport_sigcomp_option(tport_t const *self,
			 struct sigcomp_compartment *cc,
			 char const *option)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    return vsc->vsc_sigcomp_option(self, cc, option);

  return -1;
}


/** Assign a SigComp compartment (to a possibly connected tport). 
 *
 * @related tport_s
 */
int tport_sigcomp_assign(tport_t *self, struct sigcomp_compartment *cc)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    return vsc->vsc_sigcomp_assign(self, &self->tp_comp, cc);

  return 0;
}

/** Test if tport has a SigComp compartment assigned to it. */
int tport_has_sigcomp_assigned(tport_t const *self)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc && self)
    return vsc->vsc_has_sigcomp_assigned(self->tp_comp);
    
  return 0;
}

int 
tport_sigcomp_accept(tport_t *self, 
		     struct sigcomp_compartment *cc, 
		     msg_t *msg)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (self == NULL)
    return su_seterrno(EFAULT);

  if (vsc)
    return vsc->vsc_sigcomp_accept(self, self->tp_comp, cc, msg);

  return 0;
}

/* Internal API */

void tport_try_accept_sigcomp(tport_t *self, msg_t *msg)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    vsc->vsc_try_accept_sigcomp(self, self->tp_comp, msg);
}

struct sigcomp_udvm **tport_get_udvm_slot(tport_t *self)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc && self)
    return vsc->vsc_get_udvm_slot(self);

  return NULL;
}

struct sigcomp_compartment *
tport_sigcomp_assign_if_needed(tport_t *self,
			       struct sigcomp_compartment *cc)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    return vsc->vsc_sigcomp_assign_if_needed(self, cc);
    
  return NULL;
}			   

/** Receive data from datagram using SigComp. */
int tport_recv_comp_dgram(tport_t *self, int N)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  char dummy[1];
  int error = EBADMSG;

  if (vsc)
    return vsc->vsc_recv_comp(self, N);

  recv(self->tp_socket, dummy, 1, 0); /* remove msg from socket */

  return su_seterrno(error);     
}


int tport_send_comp(tport_t const *self,
		    msg_t *msg, 
		    msg_iovec_t iov[], 
		    int iovused,
		    struct sigcomp_compartment *cc,
		    tport_comp_t *comp)
{
  tport_comp_vtable_t const *vsc = tport_comp_vtable;

  if (vsc)
    vsc->vsc_send_comp(self, msg, iov, iovused, cc, comp);

  msg_addrinfo(msg)->ai_flags &= ~TP_AI_COMPRESSED;
  return self->tp_pri->pri_vtable->vtp_send(self, msg, iov, iovused);
}
