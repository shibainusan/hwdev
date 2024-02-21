/* p8_file.c */
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

#include "ok_io.h"
#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_base64.h"
#include "ok_pem.h"

int default_p5_cry_algo = OBJ_P5_MD5DES;

/*-----------------------------------------
  Read PKCS#8 File
-----------------------------------------*/
Key *P8_read_file(char *fname){
	unsigned char *buf=NULL,*tmp=NULL;
	Key *ret=NULL;
	int i;

	if((i=get_fformat(fname,&buf))<0) goto done;
	switch(i){
	case 1: /* binary (DER?) */
		ret = ASN1_p8_prvkey(buf);
		break;
	case 2: /* PEM */
		ret = PEM_read_p8(fname);
		break;
	case 3: /* text */
		if((tmp=Base64_decode(buf,&i))==NULL) goto done;
		ret = ASN1_p8_prvkey(tmp);
		break;
	}

done:	
	if(buf) FREE(buf);
	if(tmp) FREE(tmp);
	return ret;
}

/*-----------------------------------------
  Write PKCS#8 File
-----------------------------------------*/
int P8_write_file(Key *p8,char *fname){
	unsigned char *der;
	int i,err=-1;

	if((der=P8_toDER(p8,NULL,&i))==NULL)
		return -1;

	if(ASN1_write_der(der,fname))
		goto done;

	err=0;
done:
	FREE(der);
	return err;
}

/*-----------------------------------------
  Read Encrypted PKCS#8 File
-----------------------------------------*/
Key *P8enc_read_file(char *fname){
	unsigned char *buf=NULL,*tmp=NULL,*p8=NULL;
	Key *ret=NULL;
	int i;

	if((i=get_fformat(fname,&buf))<0) goto done;
	switch(i){
	case 3: /* text */
		if((tmp=Base64_decode(buf,&i))==NULL) goto done;
		FREE(buf); buf=tmp; tmp=NULL;

	case 1: /* binary (DER?) */
		if((p8=ASN1_p8_decrypted(buf,&i))==NULL) p8 = buf;
		ret = ASN1_p8_prvkey(p8);
		break;
	case 2: /* PEM */
		ret = PEM_read_p8enc(fname);
		break;
	}

done:	
	if(buf) FREE(buf);
	if((p8!=buf)&&p8) FREE(p8);
	return ret;
}

/*-----------------------------------------
  Write PKCS#8 File
-----------------------------------------*/
int P8enc_write_file(Key *p8,char *fname){
	unsigned char *der;
	int i,err=-1;

	if((der=P8_encrypted_toDER(p8,default_p5_cry_algo,NULL,&i))==NULL)
		return -1;

	if(ASN1_write_der(der,fname))
		goto done;

	err=0;
done:
	FREE(der);
	return err;
}
