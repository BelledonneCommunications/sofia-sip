#include "config.h"

#define SU_TIMER_ARG_T  struct sres_sofia_s
#define SU_WAKEUP_ARG_T struct sres_sofia_register_s
#define SRES_ASYNC_T    struct sres_sofia_s

#include <sofia-sip/sresolv.h>

#define SU_LOG sresolv_log
#include <sofia-sip/su_debug.h>

#include <string.h>
#include <assert.h>

/* ====================================================================== */
/* Glue functions for Sofia root (reactor) */

#define TAG_NAMESPACE "sres"

#include <sofia-sip/su_tag_class.h>
#include <sofia-sip/su_tagarg.h>

tag_typedef_t srestag_any = NSTAG_TYPEDEF(*);
tag_typedef_t srestag_resolv_conf = STRTAG_TYPEDEF(resolv_conf);
tag_typedef_t srestag_resolv_conf_ref = REFTAG_TYPEDEF(srestag_resolv_conf);

typedef struct sres_sofia_s sres_sofia_t;
typedef struct sres_sofia_register_s sres_sofia_register_t;

struct sres_sofia_register_s {
  sres_sofia_t *srsr_ptr;
  int srsr_socket;
  int srsr_index;		/**< Registration index */
};

struct sres_sofia_s {
  sres_resolver_t *srs_resolver;
  su_root_t  	  *srs_root;
  su_timer_t 	  *srs_timer;
  sres_sofia_register_t srs_reg[SRES_MAX_NAMESERVERS];
};

static int sres_sofia_update(sres_sofia_t *, 
			     int new_socket,
			     int old_socket);

static void sres_sofia_timer(su_root_magic_t *magic, 
			     su_timer_t *t,
			     sres_sofia_t *arg);

static int sres_sofia_poll(su_root_magic_t *, su_wait_t *, 
			   sres_sofia_register_t *);

/**Create a resolver.
 *
 * The function sres_resolver_create() is used to allocate and initialize
 * the resolver object using the Sofia asynchronous reactor #su_root_t.
 */
sres_resolver_t *
sres_resolver_create(su_root_t *root, 
		     char const *conf_file_path,
		     tag_type_t tag, tag_value_t value, ...)
{
  sres_resolver_t *res;
  sres_sofia_t *srs;
  ta_list ta;

  if (root == NULL)
    return su_seterrno(EFAULT), (void *)NULL;

  ta_start(ta, tag, value);
  tl_gets(ta_args(ta),
	  SRESTAG_RESOLV_CONF_REF(conf_file_path),
	  TAG_END());
  ta_end(ta);

  res = sres_resolver_new(conf_file_path, NULL);
  srs = res ? su_zalloc(0, sizeof *srs) : NULL;

  if (res && srs) {
    su_timer_t *t;

    srs->srs_resolver = res;
    srs->srs_root = root;

    sres_resolver_set_async(res, sres_sofia_update, srs, 0);
    
    t = su_timer_create(su_root_task(root), SRES_RETRANSMIT_INTERVAL);
    srs->srs_timer = t;

    if (!srs->srs_timer)
      SU_DEBUG_3(("sres: cannot create timer\n"));
    else if (su_timer_set_for_ever(t, sres_sofia_timer, srs) < 0)
      SU_DEBUG_3(("sres: cannot set timer\n"));
    else
      return res;		/* Success! */

    sres_resolver_destroy(res), res = NULL;
  }

  return res;
}

/** Destroy a resolver object. */
int 
sres_resolver_destroy(sres_resolver_t *res)
{
  sres_sofia_t *srs;

  if (res == NULL)
    return su_seterrno(EFAULT);

  srs = sres_resolver_get_async(res, sres_sofia_update);
  if (srs == NULL)
    return su_seterrno(EINVAL);

  su_timer_destroy(srs->srs_timer), srs->srs_timer = NULL;

  sres_resolver_set_async(res, sres_sofia_update, NULL, 0);
  sres_resolver_unref(srs->srs_resolver); 

  su_free(NULL, srs);

  return 0;
}

/**Update registered socket.
 *
 * @retval 0 if success
 * @retval -1 upon failure
 */
static int sres_sofia_update(sres_sofia_t *srs,
			     int new_socket,
			     int old_socket)
{
  char const *what = NULL;
  su_wait_t wait[1];
  sres_sofia_register_t *srsr = NULL;
  sres_sofia_register_t *old_srsr = NULL;
  int i, index = -1, error = 0;
  int N = SRES_MAX_NAMESERVERS;

  if (old_socket == new_socket)
    return 0;

  if (old_socket != -1)
    for (i = 0; i < N; i++)
      if ((srs->srs_reg + i)->srsr_socket == old_socket) {
	old_srsr = srs->srs_reg + i;
	break;
      }

  if (new_socket != -1) {
    if (old_srsr == NULL) {
      for (i = 0; i < N; i++) {
	if (!(srs->srs_reg + i)->srsr_ptr)
	  break;
      }
      if (i > N)
	return su_seterrno(ENOMEM);

      srsr = srs->srs_reg + i;
    }
    else 
      srsr = old_srsr;
  }

  if (srsr) {
    if (su_wait_create(wait, new_socket, SU_WAIT_IN | SU_WAIT_ERR) == -1) {
      srsr = NULL;
      what = "su_wait_create";
      error = su_errno();
    }

    if (srsr)
      index = su_root_register(srs->srs_root, wait, sres_sofia_poll, srsr, 0);

    if (index < 0) {
      srsr = NULL;
      what = "su_root_register";
      error = su_errno();
      su_wait_destroy(wait);
    }
  }

  if (old_srsr) {
    su_root_deregister(srs->srs_root, old_srsr->srsr_index);
    memset(old_srsr, 0, sizeof *old_srsr);
  }

  if (srsr) {
    srsr->srsr_ptr = srs;
    srsr->srsr_socket = new_socket;
    srsr->srsr_index = index;
  }

  if (!what)
    return 0;		/* success */

  SU_DEBUG_3(("sres: %s: %s\n", what, su_strerror(error)));

  return su_seterrno(error);			
}


/** Sofia timer wrapper. */
static 
void 
sres_sofia_timer(su_root_magic_t *magic, su_timer_t *t, sres_sofia_t *srs)
{
  sres_resolver_timer(srs->srs_resolver);
}


/** Sofia poll/select wrapper, called by su_root_t object */
static 
int 
sres_sofia_poll(su_root_magic_t *magic, 
		su_wait_t *w, 
		sres_sofia_register_t *srsr)
{
  sres_sofia_t *srs = srsr->srsr_ptr;
  int retval = 0;
  int socket = srsr->srsr_socket;
  int events = su_wait_events(w, socket);

  if (events & SU_WAIT_ERR)
    retval = sres_resolver_error(srs->srs_resolver, socket);
  if (events & SU_WAIT_IN)
    retval = sres_resolver_receive(srs->srs_resolver, socket);

  return retval;
}

sres_query_t *
sres_query(sres_resolver_t *res,
	   sres_answer_f *callback,
	   sres_context_t *context,
	   uint16_t type,
	   char const *domain)
{
  sres_sofia_t *srs;

  if (res == NULL)
    return su_seterrno(EFAULT), (void *)NULL;
  
  srs = sres_resolver_get_async(res, sres_sofia_update);

  if (srs)
    return sres_query_make(res, callback, context, type, domain);
  else
    return su_seterrno(EINVAL), (void *)NULL;
}

/** Make a reverse DNS query.
 *
 * The function sres_query_sockaddr() sends a query with specified @a type
 * and domain name formed from the socket address @a addr. The sres resolver
 * takes care of retransmitting the query, and generating an error record
 * with nonzero status if no response is received.
 *
 */
sres_query_t *
sres_query_sockaddr(sres_resolver_t *res,
		    sres_answer_f *callback,
		    sres_context_t *context,
		    uint16_t type,
		    struct sockaddr const *addr)
{
  sres_sofia_t *srs;

  if (res == NULL)
    return su_seterrno(EFAULT), (void *)NULL;
  
  srs = sres_resolver_get_async(res, sres_sofia_update);

  if (srs)
    return sres_query_make_sockaddr(res, callback, context, type, addr);
  else
    return su_seterrno(EINVAL), (void *)NULL;
}
