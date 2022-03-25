//#include "contiki-net.h"
#include "tinydtls.h"
#include "dtls-hmac.h"

#include <string.h>

#include "hmac.h"

bool tinydtls_use_hwsha2;

struct {

  dtls_hmac_context_t* ctx;
  unsigned char mac_key[32];

} hmac_ctx;


void hmac_init(unsigned char* key){

    memcpy( hmac_ctx.mac_key, key, 32 );

    hmac_ctx.ctx = dtls_hmac_new( key, 32 );
}

void hmac_sign(unsigned char* msg, int size, int* nonce, unsigned char* output){

    unsigned char input[size+sizeof(int)];

    memcpy(input, msg, size );
    memcpy(&(input[size]), nonce, sizeof(int));

    // Preparing the init in advance takes double the time
    dtls_hmac_init(hmac_ctx.ctx, hmac_ctx.mac_key, 32);
    dtls_hmac_update(hmac_ctx.ctx, input, size+sizeof(int));
    dtls_hmac_finalize(hmac_ctx.ctx, output);

}

int hmac_vrfy(unsigned char* msg, int size, int nonce, unsigned char* sig){

    unsigned char input[size+sizeof(int)];
    unsigned char output[32];

    memcpy(input, msg, size );
    memcpy(&(input[size]), &nonce, sizeof(int));

    dtls_hmac_update(hmac_ctx.ctx, input, size+sizeof(int));
    dtls_hmac_finalize(hmac_ctx.ctx, output);

    return memcmp( sig, output, 32 );
}

void hmac_deinit(){

    dtls_hmac_free(hmac_ctx.ctx);
}
