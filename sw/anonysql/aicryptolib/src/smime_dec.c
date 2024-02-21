/* smime_dec.c */
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
#include <stdlib.h>
#include <string.h>

#include "ok_mime.h"
#include "ok_pkcs.h"

PKCS7 *ASN1_read_p7s(unsigned char *der);
PKCS7 *ASN1_read_p7env(unsigned char *der);

/*---------------------------------------------------
  decode SMIME PKCS#7-Signed
  Input: app/pkcs7-signature (don't input multipart)
---------------------------------------------------*/
PKCS7 *SMIME_p7s_get_certs(char *msg){
	PKCS7 *p7=NULL;
	unsigned char *dec=NULL;
	char *cp,*body;
	int encode,size;

	cp = strstr(msg,"ncoding:");
	if((encode=get_encoding_type(cp))<0) goto done;

	if(encode!=MAIL_ENC_BS64){
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_SMIME,ERR_PT_SMIME_DEC,NULL);
		goto done;
	}

	if(body = strstr(cp,"\n\n")){
		body+=2;
	}else{
		body = strstr(cp,"\r\n\r\n");
		body+=4;}

	if((dec=Base64_decode(body,&size))==NULL) goto done;

	p7=ASN1_read_p7s(dec);

done:
	if(dec) FREE(dec);
	return p7;
}

/*----------------------------------------------------
  get message from SMIME PKCS#7-Signed
  Input: app/pkcs7-signature (don't input multipart)
----------------------------------------------------*/
PKCS7 *SMIME_p7s_get_msg(char *msg,char **ret){
	PKCS7 *p7=NULL;
	unsigned char *dec=NULL;
	char *cp,*body;
	int encode,size;

	*ret=NULL;
	cp = strstr(msg,"ncoding:");
	if((encode=get_encoding_type(cp))<0) goto done;

	if(encode!=MAIL_ENC_BS64){
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_SMIME,ERR_PT_SMIME_DEC+1,NULL);
		goto done;
	}
	if(body = strstr(cp,"\n\n")){
		body+=2;
	}else{
		body = strstr(cp,"\r\n\r\n");
		body+=4;}

	if((dec=Base64_decode(body,&size))==NULL) goto done;

/*	{FILE *fp;fp=fopen("p7s_get_msg.der","wb");fwrite(dec,1,size,fp);fclose(fp);}*/

	if(p7=ASN1_read_p7s(dec)){
		if(cp=((P7_Signed*)p7->cont)->content){
			size = ((P7_Signed*)p7->cont)->cnt_size;
			if((*ret=(unsigned char*)MALLOC(size+2))==NULL){
				OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SMIME,ERR_PT_SMIME_DEC+1,NULL);
				goto done;
			}
			memset(*ret,0,size+2);
			memcpy(*ret,cp,size);
		}
	}
done:
	if(dec) FREE(dec);
	if(*ret==NULL){P7_free(p7);p7=NULL;}
	return p7;
}

/*-------------------------------------------------
  decrypt SMIME PKCS#7-Enveloped
  Input: app/pkcs7-mime (don't input multipart)
-------------------------------------------------*/
unsigned char *SMIME_p7m_decrypt(char *msg, PKCS12 *p12){
	PKCS7 *p7=NULL;
	Cert *cert;
	Key *key;
	unsigned char *dec=NULL;
	char *cp,*body,*ret=NULL;
	int encode,size;

	cp = strstr(msg,"ncoding:");
	if((encode=get_encoding_type(cp))<0) goto done;

	if(encode!=MAIL_ENC_BS64){
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_SMIME,ERR_PT_SMIME_DEC+2,NULL);
		goto done;
	}

	if(body = strstr(cp,"\n\n")){
		body+=2;
	}else{
		body = strstr(cp,"\r\n\r\n");
		body+=4;}

	if((dec=Base64_decode(body,&size))==NULL) goto done;

	if((cert=P12_get_usercert(p12))==NULL) goto done;
	if((key=P12_get_privatekey(p12))==NULL) goto done;
	if((p7=ASN1_read_p7env(dec))==NULL) goto done;

	ret=P7m_decrypt_enveloped(p7,cert,key);
	P7_free(p7);

done:
	if(dec) FREE(dec);
	return ret;
}

/*---------------------------------------------------
  verify SMIME PKCS#7-Signed
  Input: app/pkcs7-signature, data, len
  Output: 0..no problem, 1..error
---------------------------------------------------*/
int SMIME_p7s_verify(PKCS7 *p7, unsigned char *data, int len){

    if((data==NULL)&&(((P7_Signed*)p7->cont)->content==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SMIME,ERR_PT_SMIME_DEC+3,NULL);
	    return -1;
	}
    return P7s_verify_signed(p7,data,len);
}
