/* dsa_gen.c */
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
#include "ok_sha1.h"
#include "ok_dsa.h"

#define PRIME_MAX 2000 /* this is defined large_prime.h */
extern const unsigned int prime[];

int dsapm_gen_q(DSAParam *pm, unsigned char *seed, LNm *n1, LNm *a, LNm *b);
int dsapm_gen_p(DSAParam *pm,int sz,unsigned char *seed, LNm *n1, LNm *a, LNm *b);

/*-----------------------------------
	DSA Param generator
------------------------------------*/
DSAParam *DSAPm_gen_parameter(int size /* bits */){
	int	i,err=-1;
	unsigned char seed[32];
	DSAParam *ret=NULL;
	LNm *n1=NULL,*a=NULL,*b=NULL;

	/* check size */
	if((size<512)||(1024<size)||(size % 64)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_DSA,ERR_PT_DSAGEN,NULL);
		goto done;
	}

	if((a =LN_alloc())==NULL) goto done;
	if((b =LN_alloc())==NULL) goto done;
	if((n1=LN_alloc())==NULL) goto done;
	if((ret=DSAPm_new())==NULL) goto done;

	do{
		/* phase 1 : get q */
		if((i=dsapm_gen_q(ret,seed,n1,a,b))<0) goto done;

		/* phase 2 : get p */
		if((i=dsapm_gen_p(ret,size,seed,n1,a,b))<0) goto done;

	}while(i);

	/* phase 3 : get g */
	LN_copy(ret->p,n1);
	LN_long_sub(n1,1);
	LN_div_mod(n1,ret->q,a,b); /* a = (p-1)/q */

	for(;;){
		if(RAND_bytes(seed,4)) goto done; /* get seed */
		if(LN_set_num_c(b,4,seed)) goto done;

		LN_exp_mod(b,a,ret->p,ret->g); /* b ^ a (mod p) */

		if(LN_now_bit(ret->g)>1) break;
	}

	ret->version = 1;
	if((ret->der = DSAPm_toDER(ret,NULL,&i,0))==NULL) goto done;

	err=0;
done:
	LN_free(a);
	LN_free(b);
	LN_free(n1);
	if(ret&&err){ DSAPm_free(ret); ret=NULL;}
	return ret;
}

int dsapm_gen_q(DSAParam *pm, unsigned char *seed, LNm *n1, LNm *a, LNm *b){
	unsigned char buf[32],buf2[32],tmp[32];
	ULONG md;
	int i,j=0;

	do{
		/* step 1 */
		if(RAND_bytes(seed,20)) goto error; /* get seed */
		OK_SHA1(20,seed,buf);

		/* step 2 */
		memcpy(tmp,seed,32);
		for(i=19; i>=0; i--)
			if((++(tmp[i])) != 0) break;
		OK_SHA1(20,tmp,buf2);

		for(i=0;i<20;i++) buf[i] ^=buf2[i];

		/* step 3 */
		buf[0]|=0x80; buf[19]|=0x01; /* odd prime ? */

		/* step 4 */
		if(LN_set_num_c(pm->q,20,buf)) goto error;

		{if(!(++j%5)){printf(".");fflush(stdout);}}

		/* find prime -- print out process */
		/* do easy test first */
		for(i=0;i<PRIME_MAX;i++){
			if(LN_long_mod(pm->q,prime[i],&md)) goto error;
			if(md==0) break;
		}
		/* miller rabin test */
		i = -1;
		if(md){
			if((i=(int)_LN_miller_rabin(pm->q,50,1,n1,a,b))<0) goto error;
		}
	
	}while(i);

	return 0;
error:
	return -1;
}

int dsapm_gen_p(DSAParam *pm,int sz,unsigned char *seed, LNm *n1, LNm *a, LNm *b){
	unsigned char cr,t,k,off;
	unsigned char buf[140],tmp[32];
	ULONG md;
	int i,n,bb,cnt;

	/* step 6 */
	n   = sz / 160;
	bb  = (sz - (160*n))>>3;
	off = 2;
	cnt = 0;

	memcpy(tmp,seed,32); /* <-- here is not FIPS compatible ? */

	while(cnt < 4096){
		/* step 7 */
		t=tmp[19];
		cr = (t > (tmp[19]+=off))?(1):(0);

		for(i=18; i>=0; i++)
			if((tmp[i]+=cr) != 0) break;

		for(k=0;k<=n;k++){
			t=tmp[19];
			cr = (t > (tmp[19]+=k))?(1):(0);

			for(i=18; i>=0; i++)
				if((tmp[i]+=cr) != 0) break;

			OK_SHA1(20,tmp,&buf[120-k*20]);
		}

		/* step 8 */
		k = 140-(n*20)-bb;
		buf[k] |= 0x80;

		if(LN_set_num_c(n1,(sz>>3),&buf[k])) goto error;

		/* step 9 */
		if(LN_lshift32(pm->q,1,pm->p)) goto error;
		if(LN_div_mod(n1,pm->p,a,b)) goto error;
		if(LN_minus(n1,b,pm->p)) goto error;
		if(LN_long_add(pm->p,1)) goto error;

		{if(!(cnt%5)){printf("+");fflush(stdout);}}

		/* step 10 */
		if(LN_now_bit(pm->p) == sz){
			/* step 11 */
			/* do easy test first */
			for(i=0;i<PRIME_MAX;i++){
				if(LN_long_mod(pm->p,prime[i],&md)) goto error;
				if(md==0) break;
			}
			/* miller rabin test */
			if(md){
				if((i=_LN_miller_rabin(pm->p,5440/sz,1,n1,a,b))<0) goto error;
				if(i==0) break;
			}
		}

		cnt++; off+=n+1;
	}

	return (cnt >= 4096);
error:
	return -1;
}
