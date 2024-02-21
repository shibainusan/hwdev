/* asn1_rsa.c */
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

#include "aiconfig.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ok_rsa.h"
#include "ok_asn1.h"
#include "key_type.h"

/*-----------------------------------------
  ASN.1 to struct Prvkey_RSA
-----------------------------------------*/
Prvkey_RSA *ASN1_read_rsaprv(unsigned char *in){
	Prvkey_RSA 	*ret;
	unsigned char	*cp;
	int	i,err=-1;

	if(in == NULL) return NULL;
	if(*in != 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		return NULL;}

	/* if this DER contains less 40 byte (512 bit) integer, 
	 * it must not be RSA private key!! 
	 */
	cp = ASN1_step(in,2);
	if((cp[0]!=0x02)||(cp[1]<0x40)){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		return NULL;}

	if((ret=RSAprvkey_new())==NULL) goto done;

	/* check PKCS#1 Private key version. it must be 0. */
	cp = ASN1_next(in);
	if((ret->version=ASN1_integer(cp,&i)) != 0){
		OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		goto done;
	}

	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->n,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->e,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->d,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->p,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->q,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->e1,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->e2,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->cof,&i)) goto done;

	ret->size    = LN_now_byte(ret->n);
	ret->der     = in;
	err=0;
done:
	if(err&&ret){RSAkey_free((Key*)ret);ret=NULL;}
	return(ret);
}

/*-----------------------------------------
  ASN.1 to struct large_number
-----------------------------------------*/
int ASN1_int2LNm(unsigned char *in,LNm *ret,int *mv){
	int len,ptm;

	*mv = 1;
	if(*in != ASN1_INTEGER){
		OK_set_error(ERR_ST_ASN_NOTINTEGER,ERR_LC_ASN1,ERR_PT_ASN1RSA+1,NULL);
		return -1;
	}
	len = ASN1_length((++in),&ptm);
	in += ptm;
	*mv += (ptm+len);

	if(LN_set_num_c(ret,len,in)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ASN1,ERR_PT_ASN1RSA+1,NULL);
		return -1;
	}
	return 0;
}

/*-----------------------------------------
  struct large_number to ASN.1
-----------------------------------------*/
int ASN1_LNm2int(LNm *n,unsigned char *ret,int *mv){
	unsigned char	*cp;
	int   i,j,len;

	*ret = ASN1_INTEGER;
	cp = ret+1;

	j   = (LN_now_bit(n) % 8)?(0):(1);
	len = LN_now_byte(n) + j;
	ASN1_set_length(len,cp,&i);
	cp+=i;
	if(LN_get_num_c(n,len,cp)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ASN1,ERR_PT_ASN1RSA+2,NULL);
		return -1;
	}
	if(j) *cp=0;

	*mv = len+i+1;
	return 0;
}
