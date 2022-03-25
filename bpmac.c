
#include "umac.h"
#include "contiki.h"
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>

#include "contiki-net.h"
#include "tinydtls.h"
#include "dtls-hmac.h"
#include "os/lib/heapmem.h"

#include <string.h>
#include <stdio.h>

#include "rijndael.h"

#include "bpmac.h"

#if (IS_ZOUL==0) // Zoleratia z1
#define SIZEOF_INT 2
#elif (IS_ZOUL==1) // Zolertia borad
#define SIZEOF_INT 4
#endif

#define MAC_LEN_IN_INT (MAC_LEN/sizeof(int))

static void pbuf(void *buf, int n, char *s)
{
    int i;
    char *cp = (char *)buf;

    if (n <= 0 || n >= 30)
        n = 30;

    if (s)
        printf("%s: ", s);

    for (i = 0; i < n; i++)
        printf("%02X", (unsigned char)cp[i]);
    printf("\n");
}

void bpmac_init( char* key,  char* nonce_key, int max_size, bpmac_ctx_t* ctx){

    uint32_t i,j;

    //ctx->bit_flips = (int*) malloc( 8*max_size*MAC_LEN );
    //if (ctx->bit_flips == 0){
    //	printf("Failed to allocate memory for bitflit MACs\n");
    //}

    memset(ctx->res, 0, MAC_LEN);
    memset(ctx->default_msg, 0, MAC_LEN);

    memcpy( ctx->mac_key, key, 16 );
    memcpy( ctx->nonce_key, nonce_key, 16 );

    memset(ctx->prev_nonce, 0, 16);
    memset(ctx->nonce_cache, 0, 16);

    dtls_hmac_context_t* hmac_ctx = dtls_hmac_new( (unsigned char*) key, 16 );

    ctx->max_len = max_size*8+1;

    unsigned char output0[32];
    unsigned char output1[32];

    ctx->bit_flips = (int*)malloc((max_size*8+1)*MAC_LEN);
    if(! ctx->bit_flips){
        printf("Error: Could not allocate memory for bitflips MACs\n");
    }

    for(i=0; i<max_size*8 +1; i++){

        dtls_hmac_init(hmac_ctx, ctx->mac_key, 16);

    	uint32_t input = 2*i;

        dtls_hmac_update(hmac_ctx, (unsigned char*)&input, 4);
        dtls_hmac_finalize(hmac_ctx, output0);


        dtls_hmac_init(hmac_ctx, ctx->mac_key, 16);


        input += 1;

        dtls_hmac_update(hmac_ctx, (unsigned char*)&input, 4);
        dtls_hmac_finalize(hmac_ctx, output1);

    	for(j=0; j<MAC_LEN_IN_INT; j++){
    	    ctx->default_msg[j] ^= ((int*)output0)[j];

    	    ctx->bit_flips[  i*MAC_LEN_IN_INT + j] = ((int*)output0)[j] ^ ((int*)output1)[j];
    	}
    }


    dtls_hmac_free(hmac_ctx);


}

void inline xor_tags(void* tag, void* value) __attribute__ ((optimize(3)));
void inline xor_tags(void* tag, void* value) {

#if (MAC_LEN == 4)
    *((uint32_t *)tag) ^= *((uint32_t *)value);
#elif (MAC_LEN == 8)
    *((uint64_t *)tag) ^= *((uint64_t *)value);
#elif (MAC_LEN == 12)
    ((uint64_t *)tag)[0] ^= ((uint64_t *)value)[0];
    ((uint32_t *)tag)[2] ^= ((uint32_t *)value)[2];
#elif (MAC_LEN == 16)
    ((uint64_t *)tag)[0] ^= ((uint64_t *)value)[0];
    ((uint64_t *)tag)[1] ^= ((uint64_t *)value)[1];
#endif

}


void bpmac_sign(bpmac_ctx_t* ctx, char* msg, int len,  char* tag) {

    memcpy(tag, ctx->res, 16);

    register int index = 0;
    register int i,j;

    /* For each byte in the message*/
    for(i=0; i < len; ++i){
    	/* For each bit in that byte*/

        for(j=0; j < 8; ++j){

	        /* If that bit is set */
            if( msg[i] & (1<<(7-j)) ){

                /* Index of Bitflip MAC */
            	//int index = (i*8+j)*MAC_LEN_IN_INT; // Optimization: Other index computation, that is slower

                /* current MAC XOR bitflip MAC */
                xor_tags( tag, &ctx->bit_flips[index] );

            }

            index += MAC_LEN_IN_INT; // Optimization: Computing the index like this, and not more complicatly only when bit is set, is on average slightly faster and decreases variance


        }
    }

    /* Add 1 padding bit */
    xor_tags( tag, &(ctx->bit_flips[index]) );

}


void bpmac_pre(bpmac_ctx_t* ctx, uint8_t nonce[8])
{
    /* 'index' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the index-1st
     * element, then we may have the result in the cache already.
     */

#if (MAC_LEN == 4)
#define LOW_BIT_MASK 3
#elif (MAC_LEN == 8)
#define LOW_BIT_MASK 1
#elif (MAC_LEN > 8)
#define LOW_BIT_MASK 0
#endif

    uint8_t tmp_nonce_lo[4];

#if (MAC_LEN < 12)
    int index = nonce[7] & LOW_BIT_MASK;
#else
    int index = 0;
#endif
    *(uint32_t *)tmp_nonce_lo = ((uint32_t *)nonce)[1];
    tmp_nonce_lo[3] &= ~LOW_BIT_MASK; /* zero last bit */

    if ( (((uint32_t *)tmp_nonce_lo)[0] != ((uint32_t *)ctx->prev_nonce)[1]) ||
         (((uint32_t *)nonce)[0] != ((uint32_t *)ctx->prev_nonce)[0]) )
    {
        ((uint32_t *)ctx->prev_nonce)[0] = ((uint32_t *)nonce)[0];
        ((uint32_t *)ctx->prev_nonce)[1] = ((uint32_t *)tmp_nonce_lo)[0];

        rijndaelEncrypt( (const uint32_t*) ctx->nonce_key, 10, nonce, ctx->nonce_cache);

    }

    int k;
    for(k=0; k<MAC_LEN_IN_INT; k++){
        ((int*)ctx->default_msg)[k] ^= ((int*)ctx->nonce_cache)[k+index*MAC_LEN_IN_INT];
    }
}

int bpmac_vrfy( char* msg, int size, char* sig, bpmac_ctx_t* ctx){

    char output[32];

    bpmac_sign(ctx, msg, size, output);

    return memcmp( sig, output, 16 );
}

void bpmac_deinit(bpmac_ctx_t* ctx){

    free(ctx->bit_flips);

}


void bpmac_test(){


    bpmac_ctx_t ctx;

    char nonce[] = "abcdefgh";
    char tag[16] = {0};
    int lengths[] = {1,5,10};
    char* data_ptr = "abcdeaaaaa";
    char *results[] = {"C80C26AA72514B2EB9F17A97A3074321",
                       "4F69137E8BE9172038DD205101E5DB9D",
                       "3669434DB12F48435A181503B0269B27"};

    char key[] =  "abcdefghijklmnop";
    char key2[] = "ponmlkjihgfedcba";


    printf("Testing known vectors.\n\n");
    printf("Msg                 %-*s Is\n", MAC_LEN * 2, "Should be");
    printf("---                 %-*s --\n", MAC_LEN * 2, "---------");

    int i;
    for ( i = 0; i < sizeof(lengths)/sizeof(*lengths); i++) {

	bpmac_init(key, key2, lengths[i], &ctx);

    	bpmac_pre(&ctx, (uint8_t*)nonce);

    	bpmac_sign(&ctx, data_ptr, lengths[i], tag);

	    bpmac_deinit(&ctx);

    	printf("'%5s'[:%2d] : %.*s ", data_ptr, lengths[i], MAC_LEN * 2, results[i]);
    	pbuf(tag, MAC_LEN, NULL);
    }

    printf("Done.\n");

}
