/* pbe_cry.c */
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

#include "ok_asn1.h"
#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_pkcs.h"

/*-----------------------------------------------
  PKCS#12 Pbe RC2Decrypt
-----------------------------------------------*/
int Pbe_RC2_decrypt(Dec_Info *dif,unsigned char *ret){
	Key_RC2 *rc2k;
	int err=-1;

	if((rc2k=(Key_RC2*)Pbe_gen_key(dif))==NULL) goto done;
	if(Pbe_gen_iv(dif)) goto done;

	RC2_set_iv(rc2k,dif->iv);

	RC2_cbc_decrypt(rc2k,dif->clen,dif->cry,ret);

	/* check padding */
	if(RFC1423_check_padding(dif->clen,ret)){
		OK_set_error(ERR_ST_BADPADDING,ERR_LC_PKCS,ERR_PT_PBECRY,NULL);
		goto done;
	}

	err=0;
done:
	RC2key_free(rc2k);
	return err;
}

/*-----------------------------------------------
  PKCS#12 Pbe RC2Encrypt
-----------------------------------------------*/
int Pbe_RC2_encrypt(Dec_Info *dif){
	unsigned char *cry=NULL;
	Key_RC2	*rc2k;
	int	len,err=-1;

	if((rc2k=(Key_RC2*)Pbe_gen_key(dif))==NULL) goto done;
	if(Pbe_gen_iv(dif)) goto done;

	RC2_set_iv(rc2k,dif->iv);

	/* do padding */
	len = RFC1423_enc_padding(8,dif->clen,dif->cry);

	if((cry=(unsigned char*)MALLOC(len))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PBECRY+1,NULL);
		goto done;
	}
	memcpy(cry,dif->cry,len);

	dif->clen = len;
	RC2_cbc_encrypt(rc2k,len,cry,dif->cry);

	err=0;
done:
	if(cry) FREE(cry);
	RC2key_free(rc2k);
	return err;
}

/*-----------------------------------------------
  PKCS#12 Pbe 3DESDecrypt
-----------------------------------------------*/
int Pbe_3DES_decrypt(Dec_Info *dif,unsigned char *ret){
	Key_3DES *des3;
	int err=-1;

	if((des3=(Key_3DES*)Pbe_gen_key(dif))==NULL) goto done;
	if(Pbe_gen_iv(dif)) goto done;

	DES3_set_iv(des3,dif->iv);

	DES3_cbc_decrypt(des3,dif->clen,dif->cry,ret);

	/* check padding */
	if(RFC1423_check_padding(dif->clen,ret)){
		OK_set_error(ERR_ST_BADPADDING,ERR_LC_PKCS,ERR_PT_PBECRY+2,NULL);
		goto done;
	}

	err=0;
done:
	DES3key_free(des3);
	return err;
}

/*-----------------------------------------------
  PKCS#12 Pbe 3DESEncrypt
-----------------------------------------------*/
int Pbe_3DES_encrypt(Dec_Info *dif){
	unsigned char *cry=NULL;
	Key_3DES *des3;
	int len,err=-1;

	if((des3=(Key_3DES*)Pbe_gen_key(dif))==NULL) goto done;
	if(Pbe_gen_iv(dif)) goto done;

	DES3_set_iv(des3,dif->iv);

	/* do padding */
	len = RFC1423_enc_padding(8,dif->clen,dif->cry);

	if((cry=(unsigned char*)MALLOC(len))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PBECRY+3,NULL);
		goto done;
	}
	memcpy(cry,dif->cry,len);

	dif->clen = len;
	DES3_cbc_encrypt(des3,len,cry,dif->cry);

	err=0;
done:
	if(cry) FREE(cry);
	DES3key_free(des3);
	return err;
}

/*-----------------------------------------------
  PKCS#8 Pbe DESDecrypt
-----------------------------------------------*/
int Pbe_DES_decrypt(Dec_Info *dif,unsigned char *ret){
	Key_DES *des;
	int err=-1;

	if((des=(Key_DES*)Pbe_gen_key(dif))==NULL) goto done;
	if(Pbe_gen_iv(dif)) goto done;

	DES_set_iv(des,dif->iv);

	DES_cbc_decrypt(des,dif->clen,dif->cry,ret);

	/* check padding */
	if(RFC1423_check_padding(dif->clen,ret)){
		OK_set_error(ERR_ST_BADPADDING,ERR_LC_PKCS,ERR_PT_PBECRY+4,NULL);
		goto done;
	}

	err=0;
done:
	DESkey_free(des);
	return err;
}

/*-----------------------------------------------
  PKCS#8 Pbe DESDecrypt
-----------------------------------------------*/
int Pbe_DES_encrypt(Dec_Info *dif){
	unsigned char *cry=NULL;
	Key_DES *des;
	int len,err=-1;

	if((des=(Key_DES*)Pbe_gen_key(dif))==NULL) goto done;
	if(Pbe_gen_iv(dif)) goto done;

	DES_set_iv(des,dif->iv);

	/* do padding */
	len = RFC1423_enc_padding(8,dif->clen,dif->cry);

	if((cry=(unsigned char*)MALLOC(len))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PBECRY+5,NULL);
		goto done;
	}
	memcpy(cry,dif->cry,len);

	dif->clen = len;
	DES_cbc_encrypt(des,len,cry,dif->cry);

	err=0;
done:
	if(cry) FREE(cry);
	DESkey_free(des);
	return err;
}

/*-----------------------------------------------
  encryption padding (RFC1423)
-----------------------------------------------*/
int RFC1423_enc_padding(int block,int len,unsigned char *buf){
	int i,j,k;

	j = block-(len%block);
	k = len+j;
	for(i=len;i<k;i++) buf[i]=j;
	return k;
}

/*-----------------------------------------------
  decryption -- check padding 
-----------------------------------------------*/
int RFC1423_check_padding(int len,unsigned char *buf){
	int i,j;

	for(i=j=buf[len-1];i>0;i--){
		if(j != buf[len-i]) return -1;
		buf[len-i] =0; /* clear padding */
	}
	return 0;
}



/*-----------not used ---------------*/
#ifdef DEBUG_PBE
	for(i=0;i<64;i++) printf("%.4x ",rc2k->S[i]);
	printf(" -- RC2 key %d\n",8);

	for(i=0;i<8;i++) printf("%.2x ",dif->iv[i]);
	printf(" -- IV char %d\n",8);

	for(i=0;i<len;i++) printf("%.2x ",ret[i]);
	printf(" -- ret char %d\n",len);
#endif
