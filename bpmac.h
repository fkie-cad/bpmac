#pragma once

#include "contiki.h"

#define INT_SIZE sizeof(int)

typedef struct pre_ctx_t{

  unsigned char mac_key[16];
  int default_msg[MAC_LEN/INT_SIZE];
  int res[MAC_LEN/INT_SIZE];
  int* bit_flips;//[30*8* (16/sizeof(int))];
  int max_len;

  uint8_t nonce_cache[16];
  uint8_t prev_nonce[16];
  uint8_t nonce_key[32];

} bpmac_ctx_t;

void bpmac_init(char* key, char* nonce_key, int max_size, bpmac_ctx_t* ctx);
void bpmac_sign( bpmac_ctx_t* ctx, char* msg, int size, char* output) __attribute__ ((optimize(3)));
void bpmac_pre(bpmac_ctx_t* ctx, uint8_t nonce[8]);
int bpmac_vrfy(char* msg, int size, char* sig, bpmac_ctx_t* ctx);
void bpmac_deinit(bpmac_ctx_t* ctx);

void xor_tags(void* tag, void* value) __attribute__ ((optimize(3)));

void bpmac_test();
