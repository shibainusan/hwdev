/* smime_enc.c */
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

#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_mime.h"

const char MIME_P7M_HEAD[] = "MIME-Version: 1.0\nContent-Type: application/x-pkcs7-mime;\n\tsmime-type=enveloped-data;\n\tname=\"smime.p7m\"\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment;\n\tfilename=\"smime.p7m\"\n\n";

const char MIME_P7S_inP7M_HEAD[] = "Content-Type: application/x-pkcs7-mime; name=smime.p7m; smime-type=signed-data\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename=smime.p7m\n\n";

const char MIME_P7S_HEAD[] = "MIME-Version: 1.0\nContent-Type: application/x-pkcs7-mime;\n\tname=\"smime.p7m\"\n\tsmime-type=signed-data\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment;\n\tfilename=\"smime.p7m\"\n\n";

const char MIME_MULTI_SIGN[] = "MIME-Version: 1.0\nContent-Type: multipart/signed;\n\tprotocol=\"application/x-pkcs7-signature\";\n\t";

char *mime_get_boundary(void);
unsigned char *get_random_bytes(int size);
char *mime_multi_signed(char *msg, char *sig);

/* global value */
int default_p7s_digest_algo=OBJ_HASH_SHA1;

/*---------------------------------------------------
  make SMIME PKCS#7-Signed
  Output: app/pkcs7-signature (clear-sig or pkcs7)
---------------------------------------------------*/
char *SMIME_p7s_set_signature(char *msg, PKCS12 *p12, int clear_sig){
	PKCS7 *p7=NULL;
	P7_Signed *sig;
	unsigned char *der,*enc,*ret,*t;
	int i,j;

	der=enc=ret=NULL;

	i=strlen(msg);
	if((p7=P7s_get_signed(p12, msg, i, default_p7s_digest_algo))==NULL)
		return NULL;

	if(clear_sig){
		sig=(P7_Signed*)p7->cont;
		FREE(sig->content);
		sig->cnt_size=0;
		sig->content=NULL;
	}
	
	if((der=P7_signed_toDER(p7,NULL,&i))==NULL) goto done;

	if((enc=Base64_encode(i,der,16))==NULL) goto done;

	i=strlen(MIME_P7S_HEAD);
	j=strlen(enc);

	if((ret=(unsigned char*)MALLOC(i+j+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SMIME,ERR_PT_SMIME_ENC,NULL);
		goto done;
	}
	memcpy(ret,MIME_P7S_HEAD,i);
	memcpy(&ret[i],enc,j);
	ret[i+j]=0;

	if(clear_sig){
		t=ret;
		ret=(unsigned char*)mime_multi_signed(msg,t);
		FREE(t);
	}

done:
	/* if an error happens, ret must be NULL */
	if(der) FREE(der);
	if(enc) FREE(enc);
	P7_free(p7);
	return (char*)ret;
}


char *mime_multi_signed(char *msg, char *sig){
	char *ret=NULL,*boundary=NULL;
	int	i,j;

	i=strlen(msg);
    j=strlen(sig);

	if((ret=(char*)MALLOC(i+j+512))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SMIME,ERR_PT_SMIME_ENC+1,NULL);
		goto done;
	}
	memset(ret,0,i+j+512);
    
	strcat(ret,MIME_MULTI_SIGN);
	strcat(ret,"micalg=SHA1;\n");
	if((boundary=mime_get_boundary())==NULL) goto done;
	strcat(ret,"\tboundary=\"");
	strcat(ret,boundary);
	strcat(ret,"\"\n\nThis is a multi-part message in MIME format.\n\n--");

	strcat(ret,boundary);
	strcat(ret,"\n");
	strcat(ret,msg);
	strcat(ret,"\n\n--");
	strcat(ret,boundary);
	strcat(ret,"\n");
	strcat(ret,sig);
	strcat(ret,"\n\n--");
	strcat(ret,boundary);
	strcat(ret,"\n");
done:
	if(boundary) FREE(boundary);
	return ret;
}

char *mime_get_boundary(void){
	unsigned char *s=NULL;
	char *ret;

	if((ret=(char*)MALLOC(48))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SMIME,ERR_PT_SMIME_ENC+2,NULL);
		goto done;
	}
	if((s=(unsigned char*)get_random_bytes(6))==NULL) goto done;
	sprintf(ret,"----part--%.2x%.2x--part--%.2x%.2x--part--%.2x%.2x----",
		s[0],s[1],s[2],s[3],s[4],s[5]);
done:
	if(s) FREE(s);
	return ret;
}


/*---------------------------------------------------
  make SMIME PKCS#7-Signed (include message)
  Output: app/pkcs7-signature (don't input multipart)
---------------------------------------------------*/
char *SMIME_p7s_set_msg_sign(char *msg, PKCS12 *p12, int clear_sig){
	PKCS7 *p7;
	unsigned char *der,*ret,*enc;
	int i,j;

	der=ret=enc=NULL;

	i=strlen(msg);
	if((p7=P7s_get_signed(p12,msg,i,default_p7s_digest_algo))==NULL)
		return NULL;

	if((der=P7_signed_toDER(p7,NULL,&i))==NULL) goto done;

	if((enc=Base64_encode(i,der,16))==NULL) goto done;

	i=strlen(MIME_P7S_inP7M_HEAD);
	j=strlen(enc);

	if((ret=(unsigned char*)MALLOC(i+j+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SMIME,ERR_PT_SMIME_ENC+3,NULL);
		goto done;
	}
	memcpy(ret,MIME_P7S_inP7M_HEAD,i);
	memcpy(&ret[i],enc,j);
	ret[i+j]=0;

done:
	if(enc) FREE(enc);
	if(der) FREE(der);
	P7_free(p7);
	return (char*)ret;
}

/*-------------------------------------------------
  encrypt SMIME PKCS#7-Enveloped
  Output: app/pkcs7-mime (don't input multipart)
-------------------------------------------------*/
char *SMIME_p7m_encrypt(char *msg, PKCS7 *p7b){
	PKCS7 *p7;
	unsigned char *der,*ret,*enc;
	int i,j;

	der=ret=enc=NULL;

	i=strlen(msg);
	if((p7=P7m_encrypt_enveloped(p7b,msg,i))==NULL)
		return NULL;

	if((der=P7_envelope_toDER(p7,NULL,&i))==NULL) goto done;

	if((enc=Base64_encode(i,der,16))==NULL) goto done;

	i=strlen(MIME_P7M_HEAD);
	j=strlen(enc);

	if((ret=(unsigned char*)MALLOC(i+j+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SMIME,ERR_PT_SMIME_ENC+4,NULL);
		goto done;
	}
	memcpy(ret,MIME_P7M_HEAD,i);
	memcpy(&ret[i],enc,j);
	ret[i+j]=0;

done:
	if(enc) FREE(enc);
	if(der) FREE(der);
	P7_free(p7);
	return (char*)ret;
}

