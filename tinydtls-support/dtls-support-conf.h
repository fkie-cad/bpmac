/*
 * Copyright (c) 2017, RISE SICS AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         DTLS support for CoAP
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

#ifndef DTLS_SUPPORT_CONF_H_
#define DTLS_SUPPORT_CONF_H_

//#define DTLS_LOG_CONF_PATH "coap-log.h"
#define DTLS_LOG_LEVEL LOG_LEVEL_DEBUG

#include <stdint.h>
//#include "uip.h"

typedef struct connection_t connection_t;

typedef struct {

} session_t;

#include "sys/ctimer.h"
#include <stdint.h>

typedef struct {
  struct ctimer retransmit_timer;
} dtls_support_context_state_t;

#define DTLS_SUPPORT_CONF_CONTEXT_STATE dtls_support_context_state_t

#define DTLS_TICKS_PER_SECOND CLOCK_SECOND

typedef clock_time_t dtls_tick_t;

#define HAVE_ASSERT_H 1

/* Hardware accelerated SHA on Zoul for dtls-hmac.h which includes it via tinydtls.h */
#ifdef USE_HW_ACCEL
/* Replace builtin SHA algorithm */

#if IS_ZOUL==1
/* Contiki OS hardware accelerated API */
#include "dev/sha256.h"
#endif

#ifndef WITH_SHA256
#define WITH_SHA256 1
#endif
/** Aaron D. Gifford's implementation of SHA256
 *  see http://www.aarongifford.com/ */
#include "sha2/sha2.h"

extern bool tinydtls_use_hwsha2;
#define set_tinydtls_use_hwsha2(uses)  tinydtls_use_hwsha2 = uses

/* Double context is waste of space but not important */
typedef struct {
  sha256_state_t hw;
  dtls_sha256_ctx sw;
} dtls_hash_ctx;

//typedef sha256_state_t dtls_hash_ctx;
typedef dtls_hash_ctx *dtls_hash_t;
#define DTLS_HASH_CTX_SIZE sizeof(dtls_hash_ctx)

/**
 * Must call crypto_init() first
 */
static inline void
dtls_hash_init(dtls_hash_t ctx) {
  if(tinydtls_use_hwsha2) {
    sha256_init(&ctx->hw);
  } else {
    dtls_sha256_init(&ctx->sw);
  }
}

static inline void
dtls_hash_update(dtls_hash_t ctx, const unsigned char *input, size_t len) {
  if(tinydtls_use_hwsha2) {
    sha256_process(&ctx->hw, input, len);
  } else {
    dtls_sha256_update(&ctx->sw, input, len);
  }
}

/**
 * Can call crypto_disable() when done with hashing
 */
static inline size_t
dtls_hash_finalize(unsigned char *buf, dtls_hash_t ctx) {
  if(tinydtls_use_hwsha2) {
    sha256_done(&ctx->hw, buf);
    return 32;
  } else {
    dtls_sha256_final(buf, &ctx->sw);
    return DTLS_SHA256_DIGEST_LENGTH;
  }
}
#else
#define set_tinydtls_use_hwsha2(use)
#endif /* USE_HW_ACCEL */


#endif /* DTLS_SUPPORT_CONF_H_ */
