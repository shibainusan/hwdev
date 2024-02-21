/* pem.c */
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

#include <sys/types.h>
#include <sys/stat.h>

#include "ok_base64.h"
#include "ok_x509.h"
#include "ok_des.h"
#include "ok_md5.h"

#include "ok_asn1.h"
#include "ok_pem.h"
#include "ok_tool.h"


/*-----------------------------------------
  PEM key crypto  (DES CBC)
-----------------------------------------*/
int pem_des_cbc(int len, unsigned char *in, unsigned char *ret,
			unsigned char *ivc, char *pass, int mode){
	unsigned char m[16];
	MD5_CTX	mdc;
	Key_DES	*dkey;

	MD5Init(&mdc);
	MD5Update(&mdc,pass,strlen(pass));
	MD5Update(&mdc,ivc,8);
	MD5Final(m,&mdc);

	if((dkey=DESkey_new(8,m))==NULL) return -1;
	DES_set_iv(dkey,ivc);

	if(mode) 	DES_cbc_encrypt(dkey,len,in,ret);
	else		DES_cbc_decrypt(dkey,len,in,ret);

	DESkey_free(dkey);
	return 0;
}

/*-----------------------------------------
  PEM key decrypt  (DES EDE3 CBC)
-----------------------------------------*/
int pem_des_ede3(int len, unsigned char *in, unsigned char *ret,
		 unsigned char *ivc, char *pass, int mode){
	unsigned char m[32];
	MD5_CTX	mdc;
	Key_3DES *dkey=NULL;
	int i;

	for(i=0;i<=16;i+=16){
		MD5Init(&mdc);
		if(i) MD5Update(&mdc,m,16);
		MD5Update(&mdc,pass,strlen(pass));
		MD5Update(&mdc,ivc,8);
		MD5Final(&m[i],&mdc);
	}

	if((dkey=DES3key_new_c(24,m))==NULL) return -1;
	DES3_set_iv(dkey,ivc);

	if(mode)	DES3_cbc_encrypt(dkey,len,in,ret);
	else 		DES3_cbc_decrypt(dkey,len,in,ret);

	DES3key_free(dkey);
	return 0;
}

/*-----------------------------------------
    PEM key decrypt
-----------------------------------------*/
unsigned char *PEM_msg_decrypt(unsigned char *cry, int clen,
			       unsigned char *ivc, int type){
	unsigned char pass[32],*ret=NULL;
	int err=-1;

	if((ret=(unsigned char*)MALLOC(clen+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_PEMCRY,NULL);
		return NULL;
	}

#ifdef __WINDOWS__
	OK_get_passwd("Open Private Key: ",pass,0);
#else
	OK_get_passwd("Input PASS Phrase: ",pass,0);
#endif

	switch(type){
	case OBJ_CRYALGO_DESCBC:	/* type is DES CBC mode */
		if(pem_des_cbc(clen,cry,ret,ivc,pass,0)) goto done;
		break;
	case OBJ_CRYALGO_3DESCBC:	/* type is DES EDE3 CBC mode */
		if(pem_des_ede3(clen,cry,ret,ivc,pass,0)) goto done;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PEM,ERR_PT_PEMCRY,NULL);
		goto done;
	}
	memset(pass,0,32);

	/* check padding */
	if(RFC1423_check_padding(clen,ret)){
		OK_set_error(ERR_ST_BADPADDING,ERR_LC_PEM,ERR_PT_PEMCRY,NULL);
		goto done;
	}

	ret[clen]=0;
	err=0;
done:
	if(err&&ret){ FREE(ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------
    PEM key encryption
-----------------------------------------*/
unsigned char *PEM_msg_encrypt(unsigned char *msg, int *ret_len,
			       unsigned char *ivc, int type){
	unsigned char pass[32],*ret=NULL,*in=NULL;
	int len,err=-1;

	len=*ret_len;

	if((in=(unsigned char*)MALLOC(len+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_PEMCRY+1,NULL);
		goto done;
	}
	if((ret=(unsigned char*)MALLOC(len+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_PEMCRY+1,NULL);
		goto done;
	}
	memcpy(in,msg,len);

#ifdef __WINDOWS__
	OK_get_passwd("Save Private Key: ",pass,1);
#else
	OK_get_passwd("Input PASS Phrase: ",pass,1);
#endif
	/* set padding */
	*ret_len=len = RFC1423_enc_padding(8,len,in);

	switch(type){
	case OBJ_CRYALGO_DESCBC:	/* type is DES CBC mode */
		if(pem_des_cbc(len,in,ret,ivc,pass,1)) goto done;
		break;
	case OBJ_CRYALGO_3DESCBC:	/* type is DES EDE3 CBC mode */
		if(pem_des_ede3(len,in,ret,ivc,pass,1)) goto done;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PEM,ERR_PT_PEMCRY+1,NULL);
		goto done;
	}
	memset(pass,0,32);
	err=0;

done:
	if(in) FREE(in);
	if(err&&ret){ FREE(ret);ret=NULL;}
	return ret;
}
