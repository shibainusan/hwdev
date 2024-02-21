/* p12_mac.c */
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

#include "large_num.h"

#include "ok_asn1.h"
#include "ok_hmac.h"
#include "ok_pkcs.h"
#include "ok_tool.h"
#include "ok_rsa.h"

/*-----------------------------------------
  PKCS#12 general mac.
-----------------------------------------*/
int P12_gen_mac(Dec_Info *dif,unsigned char *safe,unsigned char *ret){
	unsigned char *key;
	int i,tlen,dmy;

	if((key=P12_gen_mackey(dif))==NULL) return -1;

	tlen = ASN1_length(&safe[1],&i);
	if(tlen==0) ASN1_indef_count(&safe[2],&tlen,&dmy);
	tlen += 1+i;

	HMAC_SHA1(tlen,safe,20,key,ret);

	FREE(key);
	return 0;
}

/*-----------------------------------------
  PKCS#12 make new mac.
-----------------------------------------*/
int P12_new_mac(unsigned char *safe,unsigned char *salt,unsigned char *mac){
	Dec_Info *dif;
	int err=-1;

	if((dif=DInfo_new())==NULL) return -1;

	/* set password */
	OK_get_password_p12(NULL,dif,0x0100);
	
	if(dif->salt==NULL){
		if((dif->salt=(unsigned char*)MALLOC(8))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12MAC+1,NULL);
			goto done;
	}}
	dif->slen = 8;
	memcpy(dif->salt,salt,8);

	dif->iter = 1;
	dif->klen = 20;
	if(P12_gen_mac(dif,safe,mac)) goto done;

	err=0;
done:
	DInfo_free(dif);
	return err;
}

/*-----------------------------------------
  PKCS#12 verify mac.
  output : if verify ok ... return 0
-----------------------------------------*/
int P12_verify_mac(char *prompt,unsigned char *in,unsigned char *safe){
	unsigned char *cp,*mac=NULL,get[20];
	Dec_Info *dif;
	int i,j,len,mlen,err=-1;

	if((dif=DInfo_new())==NULL) return -1;
	/* set password */
	OK_get_password_p12(prompt,dif,0);

	len= ASN1_length(&in[1],&i);
	in = ASN1_next(in);
	j  = ASN1_length(&in[1],&i);
	j += i+1; cp = in+j;
	if(ASN1_octetstring(cp,&i,&(dif->salt),&(dif->slen))) goto done;

	dif->iter = 1;
	dif->klen = 20;

	if(len!=(i+j)){ /* microsoft PKCS#12 have mac iteration */
		cp+=i;
		dif->iter = ASN1_integer(cp,&i);
	}

	cp = ASN1_next(in);
	if((cp = ASN1_skip(cp))==NULL) goto done;
	if(ASN1_octetstring(cp,&i,&mac,&mlen)) goto done;

	if(P12_gen_mac(dif,safe,get)) goto done;

	if(err = memcmp(mac,get,20)){
		OK_set_error(ERR_ST_P12_BADMAC,ERR_LC_PKCS12,ERR_PT_P12MAC+2,NULL);
	}

done:
	if(mac) FREE(mac);
	if(dif) DInfo_free(dif);
	return err;
}
