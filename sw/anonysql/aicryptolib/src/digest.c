/* digest.c */
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

/*-------------------------------------------------------
  get digest from data with digest_algo
-------------------------------------------------------*/
unsigned char *OK_do_digest(int digest_algo,unsigned char *data,int data_len,unsigned char *ret,int *ret_len){
	unsigned char *cp=ret;

	if(ret==NULL){
		if((cp=ret=(unsigned char*)MALLOC(20))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_TOOL,ERR_PT_DIGEST,NULL);
			return NULL;}
	}
	switch(digest_algo){
	case OBJ_HASH_MD2:
	case OBJ_SIG_MD2RSA:
	case OBJ_SIGOIW_MD2RSA:
		*ret_len = 16; /* byte */
		OK_MD2(data_len,data,cp);
		break;
	case OBJ_HASH_MD5:
	case OBJ_SIG_MD5RSA:
	case OBJ_SIGOIW_MD5RSA:
		*ret_len = 16; /* byte */
		OK_MD5(data_len,data,cp);
		break;
	case OBJ_HASH_SHA1:
	case OBJ_SIG_SHA1RSA:
	case OBJ_SIG_SHA1DSA:
	case OBJ_SIG_SHA1ECDSA:
	case OBJ_SIGOIW_SHA1RSA:
		*ret_len = 20; /* byte */
		OK_SHA1(data_len,data,cp);
		break;
	default:
		if(ret!=cp) FREE(cp);
		cp=NULL;
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_TOOL,ERR_PT_DIGEST,NULL);
		break;
	}
	return cp;
}
