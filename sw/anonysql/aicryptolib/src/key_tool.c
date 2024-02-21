/* key_tool.c */
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

#include "ok_x509.h"
#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_rsa.h"
#include "ok_asn1.h"

/*-----------------------------------------
  duplicate key structure...
-----------------------------------------*/
Key *Key_dup(Key *src){
	Key	*ret;

	if(src==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509KEY,ERR_PT_KEYTOOL,NULL);
		return NULL;
	}

	switch(src->key_type){
	case KEY_RSA_PUB:
		ret = (Key*)RSApubkey_dup((Pubkey_RSA*)src);
		break;
	case KEY_RSA_PRV:
		ret = (Key*)RSAprvkey_dup((Prvkey_RSA*)src);
		break;
	case KEY_DSA_PUB:
		ret = (Key*)DSApubkey_dup((Pubkey_DSA*)src);
		break;
	case KEY_DSA_PRV:
		ret = (Key*)DSAprvkey_dup((Prvkey_DSA*)src);
		break;
	case KEY_ECDSA_PUB:
		ret = (Key*)ECDSApubkey_dup((Pubkey_ECDSA*)src);
		break;
	case KEY_ECDSA_PRV:
		ret = (Key*)ECDSAprvkey_dup((Prvkey_ECDSA*)src);
		break;

	case KEY_DES:
		ret = (Key*)DESkey_dup((Key_DES*)src);
		break;
	case KEY_3DES:
		ret = (Key*)DES3key_dup((Key_3DES*)src);
		break;
	case KEY_RC2:
		ret = (Key*)RC2key_dup((Key_RC2*)src);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509KEY,ERR_PT_KEYTOOL,NULL);
		return NULL;
	}
	return ret;
}

/*-----------------------------------------
  compare two key structure 
-----------------------------------------*/
int Key_cmp(Key *k1, Key *k2){
	int ret;
	if(k1->key_type != k2->key_type) return -1;
	if(k1->size != k2->size) return -1;

	switch(k1->key_type){
	case KEY_RSA_PUB:
		ret = RSApubkey_cmp((Pubkey_RSA*)k1,(Pubkey_RSA*)k2);
		break;
	case KEY_RSA_PRV:
		ret = RSAprvkey_cmp((Prvkey_RSA*)k1,(Prvkey_RSA*)k2);
		break;
	case KEY_DSA_PUB:
		ret = DSApubkey_cmp((Pubkey_DSA*)k1,(Pubkey_DSA*)k2);
		break;
	case KEY_DSA_PRV:
		ret = DSAprvkey_cmp((Prvkey_DSA*)k1,(Prvkey_DSA*)k2);
		break;
	case KEY_ECDSA_PUB:
		ret = ECDSApubkey_cmp((Pubkey_ECDSA*)k1,(Pubkey_ECDSA*)k2);
		break;
	case KEY_ECDSA_PRV:
		ret = ECDSAprvkey_cmp((Prvkey_ECDSA*)k1,(Prvkey_ECDSA*)k2);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509KEY,ERR_PT_KEYTOOL+1,NULL);
		return -1;
	}
	return ret;
}

/*-----------------------------------------
  if key pair is valid return 0, else -1
-----------------------------------------*/
int Key_pair_cmp(Key *prv, Key *pub){
	int kt1,kt2,ret=-1;

	kt1 = prv->key_type;
	kt2 = pub->key_type;
	if(kt1 == KEY_RSA_PRV){
		if(kt2 != KEY_RSA_PUB) return -1;
		ret = RSA_pair_cmp((Prvkey_RSA*)prv,(Pubkey_RSA*)pub);

	}else if(kt1 == KEY_DSA_PRV){
		if(kt2 != KEY_DSA_PUB) return -1;
		ret = DSA_pair_cmp((Prvkey_DSA*)prv,(Pubkey_DSA*)pub);

	}else if(kt1 == KEY_ECDSA_PRV){
		if(kt2 != KEY_ECDSA_PUB) return -1;
		ret = ECDSA_pair_cmp((Prvkey_ECDSA*)prv,(Pubkey_ECDSA*)pub);
	}
	return ret;
}
