/* rsa.c */
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

#include "ok_rsa.h"

/*-----------------------------------------------
  do RSA encrypt and decrypt
-----------------------------------------------*/
int rsa_do(int len,unsigned char *from,unsigned char *to, LNm *n, LNm *c){
	LNm *in,*out;
	int nlen,err=-1;

	nlen = LN_now_byte(n);
	if(len > nlen){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_RSA,ERR_PT_RSA,NULL);
		return -1;
	}

	if((in =LN_alloc_c(len,from))==NULL) goto done;
	if((out=LN_alloc())==NULL) goto done;

	if(LN_exp_mod(in,c,n,out)) goto done;

	nlen = LN_now_byte(out);
	if(nlen>len) len=nlen;
	LN_get_num_c(out,len,to);
	err=0;

done:
	LN_free(in);
	LN_free(out);
	return err;
}

/*-----------------------------------------------
  do RSA encrypt and decrypt
-----------------------------------------------*/
int RSApub_doCrypt(int len, unsigned char *from,
			  unsigned char *to, Pubkey_RSA *key){
	return rsa_do(len,from,to,key->n,key->e);
}

/*-----------------------------------------------
  do RSA encrypt and decrypt (private key)
-----------------------------------------------*/
int RSAprv_doCrypt(int len, unsigned char *from,
                          unsigned char *to, Prvkey_RSA *key){
	return rsa_do(len,from,to,key->n,key->d);
}

/*-----------------------------------------------
  set RSA public key
-----------------------------------------------*/
void OK_RSA_set_pubkey(Pubkey_RSA *key,LNm *n,LNm *e){
    key->n = n;
    key->e = e;
}

void OK_RSA_set_prvkey(Prvkey_RSA *key,LNm *n,LNm *d){
    key->n = n;
    key->d = d;
}

