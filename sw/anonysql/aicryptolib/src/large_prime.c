/* large_prime.c */
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
#include <math.h>

#include "ok_io.h"
#include "ok_rand.h"

#include "large_prime.h"
#include "large_num.h"

ULONG   n1s[LN_MAX],as[LN_MAX],bs[LN_MAX];
LNm     nn,aa,bb;

/* init local values */
void LN_init_prime_tv(){
        nn.num=n1s; aa.num=as; bb.num=bs;
        nn.size=aa.size=bb.size=LN_MAX;
}

/*-----------------------------------------------
  large number make random num (maybe prime)
-----------------------------------------------*/
int LN_set_probprime(LNm *a,int byte,unsigned short iv){
	unsigned short tmp,m;
	unsigned char *cp;
	ULONG mod[PRIME_MAX],l;
	int	 i,j;

	j = LN_MAX<<2;
	if((byte<=0)||(byte>j)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMPRIME,NULL);
		goto error;
	}

	/* set random bytes */
	a->neg = 0;

	cp = (unsigned char*)a->num;
	memset(cp,0,j);
	if(RAND_bytes(&cp[j-byte],byte)) goto error;

	/* top bit must be "1" */
	if(byte&0x3){
		cp[j-byte] |= 0xc0;
		i = LN_MAX -1 -(byte>>2);

		switch(byte&0x3){
		case 1: l=(ULONG)cp[j-byte]; break;
		case 2: l=(ULONG)(cp[j-byte]<<8)|(cp[j-byte+1]); break;
		case 3: l=(ULONG)(cp[j-byte]<<16)|(cp[j-byte+1]<<8)|(cp[j-byte+2]); break;
		}
		a->num[i] = l;
		a->top = LN_now_top(i,a);
	}else{
		i = LN_MAX - (byte>>2);
		a->num[i] |= 0xc0000000;
		a->top = LN_now_top(i,a);
	}
	/* last bit must be odd */
	a->num[LN_MAX-1] |= 0x1;

	/* calc gcd(a,primes[i]) */
	for(i=0;i<PRIME_MAX;i++)
		if(LN_long_mod(a,prime[i],&mod[i])) goto error;

	for(m=tmp=0;;){
		for(i=0;i<PRIME_MAX;i++)
			if(mod[i]==0){
				m+=2;
				for(i=0;i<PRIME_MAX;i++)
					mod[i] = (mod[i]+2)%prime[i];
				tmp++;
				break;
			}
		if(tmp)  tmp=0;
		else     break;
	}

	if(LN_long_add(a,m)) goto error;
	return 0;
error:
	return -1;
}

/*-----------------------------------------------
  large number make prime
-----------------------------------------------*/
int LN_prime(int byte,LNm *ret,int print){
	int iter,i,err=-1;
	LNm *n1=NULL,*a=NULL,*b=NULL;

	if((n1=LN_alloc())==NULL) goto done;
	if((a =LN_alloc())==NULL) goto done;
	if((b =LN_alloc())==NULL) goto done;

	/* find out appropriate iteration */
	/* error should be less than 2^(-100) for k-bit integer...
	 * see P1363 A.15.2 for determining iteration.
	 */
	if((byte<=0)||(byte>680)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_LNM,ERR_PT_LNMPRIME+1,NULL);
		goto done;
	}
	iter = 680 / byte;

	{
prime_loop:
	/* make random number */
	if(LN_set_probprime(ret, byte, (unsigned short)(rand()*3)))
		goto done;

	i=_LN_miller_rabin(ret,iter,print,n1,a,b);
	if(i==0){err=0; goto done;}
	if(i< 0) goto done;
	
	if(print){printf(".");fflush(stdout);}
	goto prime_loop;
	}
done:
	if(print) printf("\n");
	LN_free(n1);
	LN_free(a);
	LN_free(b);
	return err;
}

/*-------------------------------------------------
  large number Miller-Rabin Algorithm
  (ret=1 .. n is composit)
  * LN_init_prime_tv() should be executed before
-------------------------------------------------*/
int _LN_miller_rabin(LNm *n,int iter,int print, LNm *n1,LNm *a,LNm *b){
	int i,top;

	if(n1==NULL) n1=&nn;
	if(a ==NULL) a =&aa;
	if(b ==NULL) b =&bb;

	top=LN_MAX-1;

	/* n1 = n-1 */
	LN_copy(n,n1);
	n1->num[top]&=0xfffffffe;

	/* set random -> a */
	a->top = 1;
	i = LN_MAX-a->top;
	a->num[i]=(n->num[i]&0x7f)+1;

	/* simple version (just check fermat) */
	for(i=0;i<iter;i++){
		/* ? a^(n-1) == 1 */
  
		if(LN_exp_mod(a,n1,n,b)) /* b=a^(n-1) mod n */
			return -1; /* error */

		if((b->top!=1)||(b->num[top]!=1))
			return 1;		/* n is composit number */

		if(print&&(!(i%5))){
			printf("o");
			fflush(stdout);
		}
		/* set other a */
		a->num[top]++;
	}

#if 0
  /* check witness */
	LN_exp_mod(a,m,n,b);	/* b=a^m mod n */
	for(j=0;j<k;j++){
	if(((b->top==1)&&(b->num[top]==1))||(!LN_cmp(b,n1)))
	    break;	/* maybe prime */

	LN_multi(b,b,m);
	LN_div_mod(m,n,a,b); /* b = b*b mod n */
    }

    if(j==k)	return 1;	/* n is composit number */
#endif

  return 0;	/* maybe prime */
}


#if 0 /* hmm, no longer used */
int last_zero_bit(unsigned short num){
  static int bit[]={
      4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0};
  int	ret=0;

  if(num&0x0f)
    return bit[num&0x0f];

  if(num&0xf0)
    return(bit[((num&0xf0)>>4)]+4);

  if(num&0xf00)
    return(bit[((num&0xf00)>>8)]+8);

  if(num&0xf000)
    return(bit[((num&0xf000)>>12)]+12);
}
#endif
