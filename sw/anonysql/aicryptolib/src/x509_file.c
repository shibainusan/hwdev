/* x509_file.c */
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
#include "ok_base64.h"
#include "ok_pem.h"
#include "ok_rsa.h"
#include "ok_x509.h"


/*-----------------------------------------
  Read Certificate file
-----------------------------------------*/
void *read_x509_file(char *fname,int type){
	void *ret=NULL;
	switch(type){
	case 1: ret = _read_x509_file((fname),(void*)ASN1_read_cert,(void*)PEM_read_cert); break;
	case 2: ret = _read_x509_file((fname),(void*)ASN1_read_crl, (void*)PEM_read_crl); break;
	case 3: ret = _read_x509_file((fname),(void*)ASN1_read_req, (void*)PEM_read_req); break;
	case 4: ret = _read_x509_file((fname),(void*)ASN1_read_crtp,(void*)PEM_read_crtp); break;
	}
	return ret;
}

void *_read_x509_file(char *fname,void* (*der_cb)(unsigned char*),
					void* (*pem_cb)(char*)){
	unsigned char *buf=NULL,*tmp=NULL;
	void *ret=NULL;
	int i;

	if((i=get_fformat(fname,&buf))<0) goto done;
	switch(i){
	case 1: /* binary (DER?) */
		if(ret = der_cb(buf)) buf=NULL; /* remain buf */
		break;
	case 2: /* PEM */
		ret = pem_cb(fname);
		break;
	case 3: /* text */
		if((tmp=Base64_decode(buf,&i))==NULL) goto done;
		if(ret = der_cb(tmp)) tmp=NULL; /* remain tmp */
		break;
	}

done:	
	if(buf) FREE(buf);
	if(tmp) FREE(tmp);
	return ret;
}

/*-----------------------------------------
  return file format
  1...binary, 2...pem, 3...text(base64?)
  -1...error
-----------------------------------------*/
int get_fformat(char *fname,unsigned char **rbuf){
	int i,j,ret=-1;

	if((*rbuf=get_file2buf(fname,&i))==NULL) goto done;

	for(j=0;j<i;j++)
		if((*rbuf)[j] & 0x80){ ret=1; goto done;}

	if(strstr(*rbuf,"-----")){ret=2; goto done;}

	ret = 3;
done:
	return ret;
}
