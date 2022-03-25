#include "dtls-support.h"
#include "lib/random.h"
#include "net/ipv6/uiplib.h"

/* Log configuration */
#define LOG_MODULE "dtls-support"
#define LOG_LEVEL  LOG_LEVEL_DTLS
#include "dtls-log.h"

//static dtls_context_t the_dtls_context;
//static dtls_cipher_context_t cipher_context;
//static uint8_t lock_context = 0;
/*---------------------------------------------------------------------------*/
dtls_context_t *
dtls_context_acquire(void)
{
 return NULL;
}
/*---------------------------------------------------------------------------*/
void
dtls_context_release(dtls_context_t *context)
{

}
/*---------------------------------------------------------------------------*/
/* In Contiki we know that there should be no threads accessing the
   functions at the same time which means there is no need for locking */
dtls_cipher_context_t *
dtls_cipher_context_acquire(void)
{
return NULL;
}
/*---------------------------------------------------------------------------*/
void
dtls_cipher_context_release(dtls_cipher_context_t *c)
{
}
/*---------------------------------------------------------------------------*/
void
dtls_session_init(session_t *sess)
{
}
/*---------------------------------------------------------------------------*/
int
dtls_session_equals(const session_t *a, const session_t *b)
{
return 0;
}
/*---------------------------------------------------------------------------*/
void *
dtls_session_get_address(const session_t *a)
{
return NULL;
}
/*---------------------------------------------------------------------------*/
int
dtls_session_get_address_size(const session_t *a)
{
return 0;
}
/*---------------------------------------------------------------------------*/
void
dtls_session_log(const session_t *s)
{

}
/*---------------------------------------------------------------------------*/
void
dtls_session_print(const session_t *s)
{

}
/*---------------------------------------------------------------------------*/
int
dtls_fill_random(uint8_t *buf, size_t len)
{
	return 0;
}

/*---------------------------------------------------------------------------*/
/* time support */
/*---------------------------------------------------------------------------*/
void
dtls_ticks(dtls_tick_t *t)
{
}


/*---------------------------------------------------------------------------*/
void
dtls_set_retransmit_timer(dtls_context_t *context, unsigned int time)
{

}
/*---------------------------------------------------------------------------*/
void
dtls_support_init(void)
{
}
/*---------------------------------------------------------------------------*/
