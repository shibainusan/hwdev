/* pbe.c */
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

#include <time.h>

#include "ok_asn1.h"
#include "ok_pkcs.h"

/*-----------------------------------------
  PKCS#5 Pbe get algorithm
-----------------------------------------*/
int ASN1_pbe_algorithm(unsigned char *cp,int *pbe,unsigned char **salt,int *slen,int *iter){
	int i,err=-1;

	/* get algorithm */
	cp = ASN1_next(cp);
	if((*pbe=ASN1_object_2int(cp))<0)
		goto done;

	cp = ASN1_step(cp,2);
	if(ASN1_octetstring(cp,&i,salt,slen))
		goto done;

	cp = ASN1_next(cp);
	if((*iter=ASN1_integer(cp,&i))<0)
		goto done;

	err=0;
done:
	return err;
}

/*-----------------------------------------
  PKCS#5 Pbe get DER algorithm
-----------------------------------------*/
int Pbe_DER_algorithm(Dec_Info *dif,unsigned char *der,int *ret_len){
	unsigned char *cp,*sq;
	int i,j,k,err=-1;

	cp = der;
	if(ASN1_int_2object(dif->info,cp,&i)<0) goto done;
	sq = (cp+=i);

	if(dif->salt==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS,ERR_PT_PBE+1,NULL);
		goto done;
	}
	ASN1_set_octetstring(8,dif->salt,cp,&j);
	cp+=j;

	if(dif->iter<=0){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_PKCS,ERR_PT_PBE+1,NULL);
		goto done;
	}
	ASN1_set_integer(dif->iter,cp,&k);
	j+=k;
	ASN1_set_sequence(j,sq,&j);
	i+=j;
	ASN1_set_sequence(i,der,ret_len);
	err=0;

done:
	return err;
}

/*-----------------------------------------
  Pbe get decrypted
-----------------------------------------*/
int Pbe_get_decrypted(Dec_Info *dif,unsigned char *ret){
	int err;

	switch(dif->info){
	case OBJ_P12Pbe_3K3DES:
		dif->klen = 192/8;
		err=Pbe_3DES_decrypt(dif,ret);
		break;
	case OBJ_P12Pbe_2K3DES:
		dif->klen = 128/8;
		err=Pbe_3DES_decrypt(dif,ret);
		break;
	case OBJ_P12Pbe_128RC2:
		dif->klen = 128/8;
		err=Pbe_RC2_decrypt(dif,ret);
		break;
	case OBJ_P12Pbe_40RC2:
		dif->klen = 40/8;
		err=Pbe_RC2_decrypt(dif,ret);
		break;
    case OBJ_P5_MD2DES:
	case OBJ_P5_MD5DES:
	case OBJ_P5_SHA1DES:
		switch(dif->info){
		case OBJ_P5_MD2DES: dif->hash=OBJ_HASH_MD2; break;
		case OBJ_P5_MD5DES: dif->hash=OBJ_HASH_MD5; break;
		case OBJ_P5_SHA1DES:dif->hash=OBJ_HASH_SHA1;break;
		}
		dif->klen = 64/8;
		err=Pbe_DES_decrypt(dif,ret);
		break;
	case OBJ_P5_MD2RC2:
	case OBJ_P5_MD5RC2:
	case OBJ_P5_SHA1RC2:
		switch(dif->info){
		case OBJ_P5_MD2RC2: dif->hash=OBJ_HASH_MD2; break;
		case OBJ_P5_MD5RC2: dif->hash=OBJ_HASH_MD5; break;
		case OBJ_P5_SHA1RC2:dif->hash=OBJ_HASH_SHA1;break;
		}
		dif->klen = 64/8;
		err=Pbe_RC2_decrypt(dif,ret);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PBE+2,NULL);
		err=-1;
	}
	return err;
}

/*-----------------------------------------
  Pbe get DER encrypted
-----------------------------------------*/
int Pbe_set_encrypted(Dec_Info *dif){
	int err;

	switch(dif->info){
	case OBJ_P12Pbe_3K3DES:
		dif->klen = 192/8;
		err=Pbe_3DES_encrypt(dif);
		break;
	case OBJ_P12Pbe_2K3DES:
		dif->klen = 128/8;
		err=Pbe_3DES_encrypt(dif);
		break;
	case OBJ_P12Pbe_128RC2:
		dif->klen = 128/8;
		err=Pbe_RC2_encrypt(dif);
		break;
	case OBJ_P12Pbe_40RC2:
		dif->klen = 40/8;
		err=Pbe_RC2_encrypt(dif);
		break;
    case OBJ_P5_MD2DES:
	case OBJ_P5_MD5DES:
	case OBJ_P5_SHA1DES:
		switch(dif->info){
		case OBJ_P5_MD2DES: dif->hash=OBJ_HASH_MD2; break;
		case OBJ_P5_MD5DES: dif->hash=OBJ_HASH_MD5; break;
		case OBJ_P5_SHA1DES:dif->hash=OBJ_HASH_SHA1;break;
		}
		dif->klen = 64/8;
		err=Pbe_DES_encrypt(dif);
		break;
	case OBJ_P5_MD2RC2:
	case OBJ_P5_MD5RC2:
	case OBJ_P5_SHA1RC2:
		switch(dif->info){
		case OBJ_P5_MD2RC2: dif->hash=OBJ_HASH_MD2; break;
		case OBJ_P5_MD5RC2: dif->hash=OBJ_HASH_MD5; break;
		case OBJ_P5_SHA1RC2:dif->hash=OBJ_HASH_SHA1;break;
		}
		dif->klen = 64/8;
		err=Pbe_RC2_encrypt(dif);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PKCS,ERR_PT_PBE+3,NULL);
		err=-1;
	}
	return err;
}
