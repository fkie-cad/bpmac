/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "tinydtls.h"

#ifdef RETROFIT_USE_HW_ACCEL
#include "crypto.h"
#endif

#include <string.h>
#include <stdio.h>


#include "random.h"

#include "hmac.h"
#include "bpmac.h"
#include "umac.h"


#if USE_HW_ACCEL
#include "dev/sha256.h"
#endif

PROCESS(udp_client_process, "bpmac");
AUTOSTART_PROCESSES(&udp_client_process);
PROCESS_THREAD(udp_client_process, ev, data1)
{

    PROCESS_BEGIN();

    rtimer_clock_t start, end, end_live;
    int i, j, n;

    #if USE_HW_ACCEL
    crypto_init();
    #endif

    int nb_of_repetitions = 30;

    int sizes[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    unsigned char msg[32];
    uint8_t nonce[8];
    memset(nonce, 0, 8);

    unsigned char output[32];
    unsigned char key[32];
    for(i = 0; i < 32; i++)
        key[i] = rand();

    unsigned char key2[32];
    for(i = 0; i < 32; i++)
        key2[i] = rand();


    /* for each message size */
    for(j=0; j<sizeof(sizes)/sizeof(int); j++){

        int size = sizes[j];


        /*************************/
        /*                       */
        /*         UMAC          */
        /*                       */
        /*************************/


        umac_ctx_t umac_ctx = umac_new((char*)key);

        for(n=0; n < nb_of_repetitions; n++){

            for(i = 0; i < size; i++)
	            msg[i] = rand();

	        start = RTIMER_NOW();

	        for(i = 0; i<100; ++i){
                umac_reset(umac_ctx);
	            umac_update(umac_ctx, (char*)msg, size);
                nonce[7] = (char)i;
                umac_final(umac_ctx, (char*)output, (char*)nonce);
	        }

            end = RTIMER_NOW();

            printf("UMAC *100 (len:%d) %d l: %ld p: 0 t: %ld\n", size, n, (long unsigned int)((end-start)), (long unsigned int)RTIMER_ARCH_SECOND);

        }

        umac_delete(umac_ctx);


#ifdef USE_HW_ACCEL

        /*************************/
        /*                       */
        /* HW-accl. HMAC-SHA256  */
        /*                       */
        /*************************/

        set_tinydtls_use_hwsha2(true);

        hmac_init(key);

        for(n=0; n < nb_of_repetitions; n++){

            for(i = 0; i < size; i++)
	            msg[i] = rand();

            start = RTIMER_NOW();

            for(i = 0; i< 100; ++i){

            	hmac_sign(msg, size, &i, output);

            }

            end = RTIMER_NOW();

            printf("HW-HMAC *100 (len:%d) %d l: %ld p: 0 t: %ld\n", size, n, (long unsigned int)(end-start), (long unsigned int)RTIMER_ARCH_SECOND);

        }

        hmac_deinit();

#endif


        /*************************/
        /*                       */
        /*     Our Proposal      */
        /*                       */
        /*************************/

	bpmac_ctx_t ctx;

        bpmac_init((char*)key, (char*)key2, size, &ctx);

        for(n=0; n < nb_of_repetitions; n++){


            for(i = 0; i < size; i++)
	            msg[i] = rand();

    		start = RTIMER_NOW();

    		for(i = 0; i< 100; ++i){

                nonce[7] = (char)i;
    		    bpmac_pre(&ctx, nonce);
    		    bpmac_sign(&ctx, (char*) msg, size, (char*)output);

    		}

            end_live = RTIMER_NOW();

            for(i = 0; i< 100; ++i){
                nonce[7] = (char)i;
	            bpmac_pre(&ctx, nonce);

	        }

            end = RTIMER_NOW();

            printf("Preprocessable *100 (len:%d) %d l: %ld p: %ld t: %ld\n", size, n, (long unsigned int)((end_live-start)-(end-end_live)), (long unsigned int)(end-end_live), (long unsigned int)RTIMER_ARCH_SECOND);

        }



        bpmac_deinit(&ctx);

    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
