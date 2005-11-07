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

#ifndef TEST_PROXY_H
#define TEST_PROXY_H

#include <su_wait.h>
#include <nta.h>

struct proxy;
struct proxy_transaction;
struct registration_entry;

struct proxy {
  su_home_t    home[1];
  su_clone_r   clone;
  su_root_t   *root;
  nta_agent_t *agent;
  url_t const *uri;
  
  nta_leg_t *defleg;

  struct proxy_transaction *transactions;
  struct registration_entry *entries;
};

struct proxy *test_proxy_create(su_root_t *);
void test_proxy_destroy(struct proxy *);

#endif
