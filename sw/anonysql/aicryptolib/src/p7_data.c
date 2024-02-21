/* p7_data.c */
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
#include <string.h>

#include "ok_asn1.h"
#include "ok_pkcs.h"

/*-----------------------------------------------
  PKCS#7 get data.
  *in is ContentInfo DER top.
-----------------------------------------------*/
unsigned char *ASN1_get_p7data(unsigned char *in,int *ret_len){
	unsigned char *cp,*ret;
	int i;

	cp = ASN1_next(in);
	if(ASN1_object_2int(cp)!=OBJ_P7_DATA){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_PKCS7,ERR_PT_P7DATA,NULL);
		return NULL;
	}
	cp = ASN1_step(cp,2);
	if(ASN1_octetstring(cp,&i,&ret,ret_len))
		return NULL;

	return ret;
}

/*-----------------------------------------
  Get PKCS#7 DER of Data
-----------------------------------------*/
unsigned char *P7_data_toDER(int len,unsigned char *in,int inf_type,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int i,j;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(len+32))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS7,ERR_PT_P7DATA+1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	cp=ret;

	if(inf_type){
		cp[0]=0x30;cp[1]=0x80; cp+=2;	/* SEQUENCE INFINITY */
		ASN1_int_2object(OBJ_P7_DATA,cp,&i);
		cp+=i;
	
		cp[0]=0xa0;cp[1]=0x80; cp+=2;	/* cont[0] INFINITY */
		ASN1_set_octetstring(len,in,cp,&j);
		cp+=j;

		ASN1_set_end(cp);
		cp+=2;
		ASN1_set_end(cp);

		*ret_len = 8+j+i;

	}else {
		ASN1_int_2object(OBJ_P7_DATA,cp,&i);
		cp+=i;
	
		ASN1_set_octetstring(len,in,cp,&j);
		ASN1_set_explicit(j,0,cp,&j);

		ASN1_set_sequence(i+j,ret,ret_len);
	}

	return ret;
}


