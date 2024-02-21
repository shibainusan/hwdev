/* rand.c */
/*
 * Copyright (C) 1998-2002
 * Akira Iwata & Takuto Okuno
 * Akira Iwata Laboratory,
 * Nagoya Institute of Technology in Japan.
 *
 * All rights reserved.
 *
 * This software is written by Takuto Okuno(usapato@anet.ne.jp)
 * And if you want to contact us, send an email to Kimitake Wakayama
 * (wakayama@elcom.nitech.ac.jp)
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *    Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *     Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 *   THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT EXPRESS OR IMPLIED WARRANTY.
 *   AKIRA IWATA LABORATORY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 *   SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 *   IN NO EVENT SHALL AKIRA IWATA LABORATORY BE LIABLE FOR ANY SPECIAL,
 *   INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 *   FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 *   NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT OF OR IN CONNECTION
 *   WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_rand.h"

/*-----------------------------------------------
  RAND initialize
-----------------------------------------------*/
int RAND_init(){
	int err=-1;
	seed_t seed_p;

	if(!lutz_is_initialized())
		if(lutz_rand_init(PRNGD_STATE_SIZE, ENTROPY_NEEDED)) goto done;

	if(seed_internal(&seed_p)) goto done;

	if(seed_stat()) goto done;

	if(seed_internal(&seed_p)) goto done;

	if(seed_env()) goto done;

	if(seed_internal(&seed_p)) goto done;
	err=0;
done:
	memset(&seed_p,0,sizeof(seed_t));
	return err;
}

/*-----------------------------------------------
  get random bytes ("num" bytes)
-----------------------------------------------*/
int RAND_bytes(unsigned char *buf,int num){

	if(lutz_is_seeded()<0){
		if(RAND_init()) return -1;
	}

	return lutz_rand_bytes(buf,num);
}

/*-----------------------------------------------
  mixing RAND "pool" and increase entropy
-----------------------------------------------*/
int RAND_add(const void *buf,int num,double entropy){
	return lutz_rand_add(buf,num,entropy);
}

int RAND_seed(const void *buf,int num){
	return lutz_rand_add(buf,num,num);
}

/*-----------------------------------------------
  clean and free random "pool" 
-----------------------------------------------*/
void RAND_cleanup(void){
	lutz_rand_clean();
}
