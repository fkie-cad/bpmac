#pragma once

#include "contiki.h"

void hmac_init(unsigned char* key);
void hmac_sign(unsigned char* msg, int size, int* nonce, unsigned char* output);
int hmac_vrfy(unsigned char* msg, int size, int nonce, unsigned char* sig);
void hmac_deinit();
