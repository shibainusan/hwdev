/* pem_pkcs.c */
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

#include "ok_io.h"
#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_pkcs.h"
#include "ok_pem.h"

int write_bs64(FILE *fp,long len,unsigned char *der);
int pem_write(unsigned char *der,char *fname,char *begin,char *end);

/*-----------------------------------------
  Read PEM PKCS#8 file (return DER buf)
-----------------------------------------*/
unsigned char *PEM_read_p8_2der(char *fname){  
	return(pem_read2der("-----BEGIN PRIVATE KEY-----",
		"-----END PRIVATE KEY-----",
		fname));
}

/*-----------------------------------------
  Read PEM PKCS#8 file (return *Key)
-----------------------------------------*/
Key *PEM_read_p8(char *fname){
	unsigned char *cp;
	Key *ret=NULL;

	if((cp=PEM_read_p8_2der(fname))==NULL) return NULL;

	ret = ASN1_p8_prvkey(cp);

	FREE(cp);
	return ret;
}

/*-----------------------------------------
  Write PEM PKCS#8 file
-----------------------------------------*/
int PEM_write_p8(Key *key,char *fname){
	unsigned char *der;
	int i,err=-1;

	if((der=P8_toDER(key,NULL,&i))==NULL) return -1;

	err = pem_write(der,fname,
		"-----BEGIN PRIVATE KEY-----\n",
		"-----END PRIVATE KEY-----\n");

	FREE(der);
	return err;
}


/*-----------------------------------------
  Read PEM PKCS#8 file (return DER buf)
-----------------------------------------*/
unsigned char *PEM_read_p8enc_2der(char *fname){  
	return(pem_read2der("-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"-----END ENCRYPTED PRIVATE KEY-----",
		fname));
}

/*-----------------------------------------
  Read PEM PKCS#8 file (return *Key)
-----------------------------------------*/
Key *PEM_read_p8enc(char *fname){
	unsigned char *cp,*p8=NULL;
	Key *ret=NULL;
	int i;

	if((cp=PEM_read_p8enc_2der(fname))==NULL) goto done;

	if((p8=ASN1_p8_decrypted(cp,&i))==NULL) goto done;

	ret = ASN1_p8_prvkey(p8);
done:
	if(cp) FREE(cp);
	if(p8) FREE(p8);
	return ret;
}

/*-----------------------------------------
  Write PEM encrypted PKCS#8 file
-----------------------------------------*/
int PEM_write_p8enc(Key *key,char *fname){
	unsigned char *der;
	int i,err=-1;

	if((der=P8_encrypted_toDER(key,default_p5_cry_algo,NULL,&i))==NULL)
		return -1;

	err = pem_write(der,fname,
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
		"-----END ENCRYPTED PRIVATE KEY-----\n");
	FREE(der);
	return err;
}

/*-----------------------------------------
  Read PEM PKCS#7 file (return DER buf)
-----------------------------------------*/
unsigned char *PEM_read_p7_2der(char *fname){  
	return(pem_read2der("-----BEGIN PKCS7-----",
		"-----END PKCS7-----",
		fname));
}

/*-----------------------------------------
  Read PEM PKCS#7 file
-----------------------------------------*/
PKCS7 *PEM_read_p7(char *fname){
	unsigned char *der;
	PKCS7 *ret=NULL;

	if((der=PEM_read_p7_2der(fname))==NULL) return NULL;

	ret = ASN1_read_p7s(der);

	/* P7s might contain very big size of content.
	 * so, p7->der doesn't have any buffer.
	 */
	FREE(der);
	return ret;
}

/*-----------------------------------------
  Write PEM PKCS#7 Signed data file
-----------------------------------------*/
int PEM_write_p7(PKCS7 *p7,char *fname){
	unsigned char *der;
	FILE *fp;
	int i,err=-1;

	if((fp = fopen(fname,"wt"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PEM,ERR_PT_PEMPKCS+2,NULL);
		return -1;
	}

	if((der=P7_signed_toDER(p7,NULL,&i))==NULL) goto done;

	fputs("-----BEGIN PKCS7-----\n",fp);
	if(write_bs64(fp,i,der)) goto done;
	fputs("-----END PKCS7-----\n",fp);

	err=0;
done:
	fclose(fp);
	if(der) FREE(der);
	return err;
}
