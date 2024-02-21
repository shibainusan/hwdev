/* pbe_key.c */
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
#include "ok_md2.h"
#include "ok_md5.h"
#include "ok_sha1.h"
#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_pkcs.h"


Key_RC2 *P12_gen_RC2key(Dec_Info *dif);
Key_3DES *P12_gen_3DESkey(Dec_Info *dif);

Key_RC2 *P5_gen_RC2key(Dec_Info *dif);
Key_DES *P5_gen_DESkey(Dec_Info *dif);

/*-----------------------------------------------
  Pbe key generation for PKCS#12 and PKCS#8
-----------------------------------------------*/
Key *Pbe_gen_key(Dec_Info *dif){
	Key *ret;
	if((OBJ_P5_MD2DES<=dif->info)&&(dif->info<=OBJ_P5_SHA1RC2)){
		/* pbes1 key generation */
		switch(dif->info){
		case OBJ_P5_MD2RC2:
		case OBJ_P5_MD5RC2:
		case OBJ_P5_SHA1RC2:
			ret=(Key*)P5_gen_RC2key(dif);
			break;
		case OBJ_P5_MD2DES:
		case OBJ_P5_MD5DES:
		case OBJ_P5_SHA1DES:
			ret=(Key*)P5_gen_DESkey(dif);
			break;
		}
	}else if((OBJ_P12Pbe_128RC4<=dif->info)&&(dif->info<=OBJ_P12Pbe_40RC2)){
		/* pkcs12 key generation */
		switch(dif->info){
		case OBJ_P12Pbe_3K3DES:
		case OBJ_P12Pbe_2K3DES:
			ret=(Key*)P12_gen_3DESkey(dif);
			break;

		case OBJ_P12Pbe_128RC2:
		case OBJ_P12Pbe_40RC2:
			ret=(Key*)P12_gen_RC2key(dif);
			break;
		}
	}else{
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PBEKEY,NULL);
		return NULL;
	}
	return ret;
}

/*-----------------------------------------------
  Pbe key IV for PKCS#12 and PKCS#8
-----------------------------------------------*/
int Pbe_gen_iv(Dec_Info *dif){
	if((OBJ_P5_MD2DES<=dif->info)&&(dif->info<=OBJ_P5_SHA1RC2)){
		/* pbes1 IV generation */
		/* this IV must be created in Pbe_gen_key() */
		if(dif->iv==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS,ERR_PT_PBEKEY+1,NULL);
			return -1;
		}

	}else if((OBJ_P12Pbe_128RC4<=dif->info)&&(dif->info<=OBJ_P12Pbe_40RC2)){
		/* pkcs12 IV generation */
		dif->klen=8;
		dif->iv  =P12_gen_iv(dif);

	}else{
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PBEKEY+1,NULL);
		return -1;
	}
	return 0;
}


/*-----------------------------------------------
  PKCS#5 Pbes1 key generation
-----------------------------------------------*/
int PBKDF1(Dec_Info *dif,unsigned char *buf){
	int i;

	/* alloc IV memory */
	if((dif->iv=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_PBEKEY+2,NULL);
		return -1;
	}

	/* dif->salt must be set before */
	if(dif->salt==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS,ERR_PT_PBEKEY+2,NULL);
		return -1;
	}

	switch(dif->hash){
	case OBJ_HASH_MD2:
		{	
			MD2_CTX ctx;

			MD2Init(&ctx);
			MD2Update(&ctx,dif->pass,dif->plen);
			MD2Update(&ctx,dif->salt,dif->slen);
			MD2Final(buf,&ctx);

			for(i=1;i<dif->iter;i++) OK_MD2(16,buf,buf);
		}
		break;
	case OBJ_HASH_MD5:
		{	
			MD5_CTX ctx;

			MD5Init(&ctx);
			MD5Update(&ctx,dif->pass,dif->plen);
			MD5Update(&ctx,dif->salt,dif->slen);
			MD5Final(buf,&ctx);

			for(i=1;i<dif->iter;i++) OK_MD5(16,buf,buf);
		}
		break;
	case OBJ_HASH_SHA1:
		{	
			SHA1_CTX ctx;

			SHA1init(&ctx);
			SHA1update(&ctx,dif->pass,dif->plen);
			SHA1update(&ctx,dif->salt,dif->slen);
			SHA1final(buf,&ctx);

			for(i=1;i<dif->iter;i++) OK_SHA1(20,buf,buf);
		}
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PBEKEY+2,NULL);
		return -1;
	}

	memcpy(dif->iv,&buf[8],8);
	return 0;
}

Key_RC2 *P5_gen_RC2key(Dec_Info *dif){
	unsigned char buf[32];
	Key_RC2 *ret=NULL;

	if(PBKDF1(dif,buf)) return NULL;

	ret=RC2key_new(8,buf);
	memset(buf,0,32);

	/* iv will be set later */
	return ret;
}

Key_DES *P5_gen_DESkey(Dec_Info *dif){
	unsigned char buf[32];
	Key_DES *ret=NULL;

	if(PBKDF1(dif,buf)) return NULL;

	ret=DESkey_new(8,buf);
	memset(buf,0,32);

	/* iv will be set later */
	return ret;
}
