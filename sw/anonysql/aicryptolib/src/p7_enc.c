/* p7_enc.c */
/* this is PKCS#7 functions */
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

#include "ok_asn1.h"
#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_pkcs.h"
#include "ok_tool.h"

/*-----------------------------------------------
  PKCS#7 get data.(encrypted data)
  *in is ContentInfo DER top.
-----------------------------------------------*/
unsigned char *ASN1_get_p7enc(unsigned char *in,int *ret_len){
	unsigned char *cp,*dmy,*ret=NULL;
	Dec_Info *dif=NULL;
	int i,len,err=-1;

	cp = ASN1_next(in);
	if(ASN1_object_2int(cp)!=OBJ_P7_ENCRYPTED){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_PKCS7,ERR_PT_P7ENC,NULL);
		goto done;
	}

	cp = ASN1_step(cp,3);
	if(ASN1_integer(cp,&i)){
		OK_set_error(ERR_ST_BADVER,ERR_LC_PKCS7,ERR_PT_P7ENC,NULL);
		goto done;
	}

	cp = ASN1_step(cp,2);
	if(ASN1_object_2int(cp)!=OBJ_P7_DATA){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_PKCS7,ERR_PT_P7ENC,NULL);
		goto done;
	}

	if((dif=DInfo_new())==NULL) goto done;

	/* set password */
	OK_get_password_p12(NULL,dif,0);

	cp = ASN1_next(cp);
	if(ASN1_pbe_algorithm(cp,&(dif->info),&(dif->salt),&(dif->slen),&(dif->iter))<0)
		goto done;

	if((cp = ASN1_skip(cp))==NULL) goto done;

	len = ASN1_length(&cp[1],&i);
	if(len){
		cp+=i+1;
		*ret_len = len;
		dif->cry = cp;
	}else{
		*cp=0x24;
		if(ASN1_octetstring(cp,&i,&dmy,ret_len)) goto done;
		len = *ret_len;
		dif->cry = dmy;
	}

	dif->clen = len;
	if((ret=(unsigned char*)MALLOC(len+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7ENC,NULL);
		goto done;
	}

	if(Pbe_get_decrypted(dif,ret)) goto done;

	err=0;
done:
	DInfo_free(dif);
	if(err&&ret){FREE(ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------
  Get PKCS#7 DER of Encrypted
-----------------------------------------*/
int P7_in_DER_encrypted(Dec_Info *dif,unsigned char *ret,int *ret_len){
	unsigned char *cp,*sq;
	int	i,j,k;

	ASN1_set_integer(0,ret,&i);
	sq = ret+i;
	ASN1_int_2object(OBJ_P7_DATA,sq,&j);
	cp = sq+j;

	if(Pbe_DER_algorithm(dif,cp,&k)) return -1;
	cp+= k; j+=k;

	if(Pbe_set_encrypted(dif)) return -1;

	/* set implicit[ 0 ] */
	ASN1_set_octetstring(dif->clen,dif->cry,cp,&k);
	*cp = 0x80;
	j+=k;
  
	ASN1_set_sequence(j,sq,&j);
	i+=j;
	ASN1_set_sequence(i,ret,ret_len);
	return 0;
}

unsigned char *P7_encrypted_toDER(int len,unsigned char *cry,int algo,
			  unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	Dec_Info *dif;
	int i,j,err=-1;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(len+64))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7ENC,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	cp=ret;
	ASN1_int_2object(OBJ_P7_ENCRYPTED,ret,&i);
	cp=ret+i;

	if((dif=DInfo_new())==NULL) goto done;

	/* set password */
	OK_get_password_p12(NULL,dif,0);

	dif->iter = 1000;
	dif->info = algo;
	if(dif_set_salt(dif)) goto done;

	dif->cry  = cry;
	dif->clen = len;

	if(P7_in_DER_encrypted(dif,cp,&j)) goto done;

	ASN1_set_explicit(j,0,cp,&j);

	ASN1_set_sequence(i+j,ret,ret_len);

	err=0;
done:
	DInfo_free(dif);
	if(err){
		if(buf!=ret) FREE(ret);
		ret=NULL;
	}
	return ret;
}

