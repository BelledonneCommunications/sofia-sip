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

#ifndef SOFIA_RESOLV_SRES_CACHE_H
/** Defined when <sofia-resolv/sres_cache.h> has been included. */
#define SOFIA_RESOLV_SRES_CACHE_H
/**
 * @file sofia-resolv/sres_cache.h Sofia DNS Resolver Cache.
 *
 * @author Pekka Pessi <Pekka.Pessi@nokia.com>,
 *
 * @par Include Context
 * @code
 * #include <stdint.h>
 * #include <sys/types.h>
 * #include <netinet/in.h>
 * #include <sofia-resolv/sres_cache.h>
 * @endcode
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SRES_CACHE_T
#define SRES_CACHE_T
typedef struct sres_cache_s sres_cache_t;
#endif

#ifndef SRES_RECORD_T
#define SRES_RECORD_T
typedef union sres_record sres_record_t;
#endif

enum {
  /** Cache cleanup interval in seconds. */
  SRES_CACHE_TIMER_INTERVAL = 30,
#define SRES_CACHE_TIMER_INTERVAL (SRES_CACHE_TIMER_INTERVAL)
};

sres_cache_t *sres_cache_new(int n);

sres_cache_t *sres_cache_ref(sres_cache_t *);

void sres_cache_unref(sres_cache_t *);

/** Get a list of matching records from cache. */
int sres_cache_get(sres_cache_t *cache,
		   uint16_t type,
		   char const *domain,
		   sres_record_t ***return_cached);

/** Free answers not matching with type */
int sres_cache_filter(sres_cache_t *cache,
		      sres_record_t **answers, 
		      uint16_t type);

/** Free the list records. */
void sres_cache_free_answers(sres_cache_t *cache, sres_record_t **answers);

/** Free and zero one record. */
void sres_cache_free_one(sres_cache_t *cache, sres_record_t *answer);

/** Allocate a cache record */
sres_record_t *
sres_cache_alloc_record(sres_cache_t *cache, 
			char const *name, size_t name_length,
			uint16_t qtype, uint16_t rdlen);

/** Store a record to cache */
void sres_cache_store(sres_cache_t *cache, sres_record_t *rr, time_t now);

#ifdef __cplusplus
}
#endif

#endif /* SOFIA_RESOLV_SRES_CACHED_H */
