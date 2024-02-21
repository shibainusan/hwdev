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

#include "ok_io.h"
#include "ok_base64.h"
#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_pem.h"


/*-----------------------------------------
     Read PEM cert file (return DER buf)
-----------------------------------------*/
unsigned char *PEM_read_cert_2der(char *fname){  
	return(pem_read2der("-----BEGIN CERTIFICATE-----",
		"-----END CERTIFICATE-----",
		fname));
}

/*-----------------------------------------
     Read PEM cert file (return *Cert)
-----------------------------------------*/
Cert *PEM_read_cert(char *fname){
	unsigned char *cp;
	Cert *ret;

	if((cp=PEM_read_cert_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_cert(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE certd.
	 */
	return ret;
}

/*---------------------------------------------
  Read PEM cross-cert file (return DER buf)
---------------------------------------------*/
unsigned char *PEM_read_crtp_2der(char *fname){  
	return(pem_read2der("-----BEGIN CROSS CERTIFICATE PAIR-----",
		"-----END CROSS CERTIFICATE PAIR-----",
		fname));
}

/*---------------------------------------------
  Read PEM cross-cert file (return *CertPair)
---------------------------------------------*/
CertPair *PEM_read_crtp(char *fname){
	unsigned char *cp;
	CertPair *ret;

	if((cp=PEM_read_crtp_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_crtp(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE certd.
	 */
	return ret;
}

/*-----------------------------------------
     Read PEM crl file (return DER buf)
-----------------------------------------*/
unsigned char *PEM_read_crl_2der(char *fname){
	return(pem_read2der("-----BEGIN X509 CRL-----",
		"-----END X509 CRL-----",
		fname));
}

/*-----------------------------------------
  Read PEM crl file (return *CRL)
-----------------------------------------*/
CRL *PEM_read_crl(char *fname){
	unsigned char *cp;
	CRL *ret;

	if((cp=PEM_read_crl_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_crl(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE crld.
	 */
	return ret;
}

/*-----------------------------------------
     Read PEM req file (return DER buf)
-----------------------------------------*/
unsigned char *PEM_read_req_2der(char *fname){
	unsigned char *ret;
	if(ret=pem_read2der(
		"-----BEGIN CERTIFICATE REQUEST-----",
		"-----END CERTIFICATE REQUEST-----",fname))
		return ret;

	return pem_read2der(
		"-----BEGIN NEW CERTIFICATE REQUEST-----",
		"-----END NEW CERTIFICATE REQUEST-----",fname);
}

/*-----------------------------------------
  Read PEM crl file (return *Req)
-----------------------------------------*/
Req *PEM_read_req(char *fname){
	unsigned char *cp;
	Req *ret;

	if((cp=PEM_read_req_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_req(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE reqd.
	 */
	return ret;
}


/*-----------------------------------------
  Read file to buffer (static function)
-----------------------------------------*/
char *pem_read2der(char *begin,char *end,char *fname){
	unsigned char *ret=NULL;
	char *buf=NULL,*bp,*ep;
	int i;

	if((buf=get_file2buf(fname,&i))==NULL)
		return NULL;

	if((bp=strstr(buf,begin))==NULL){
		OK_set_error(ERR_ST_PEM_BADHEADER,ERR_LC_PEM,ERR_PT_PEM+1,NULL);
		goto done;}

	bp += strlen(begin);
	if((ep=strstr(buf,end))==NULL){
		OK_set_error(ERR_ST_PEM_BADFOOTER,ERR_LC_PEM,ERR_PT_PEM+1,NULL);
		goto done;}
	*ep = 0;

	ret = Base64_decode(bp,&i);

done:
	if(buf) FREE(buf);
	return ret;
}

unsigned char *get_file2buf(char *fname,int *len){
	FILE *fp;
	unsigned char  *buf;
	int sz,err=-1;

	if((fp = fopen(fname,"rb"))==NULL){
		if(okerr) fprintf(okerr,"f2b read:fopen error:%s\n",fname);
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PEM,ERR_PT_PEM+2,NULL);
		return NULL;
	}

	*len = sz= ok_get_flen(fp);
	if((buf=(char*)MALLOC(sz+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_PEM+2,NULL);
		goto done;
	}
	memset(buf,0,sz+2);

	if(fread(buf,sizeof(char),sz,fp)<(unsigned)sz){
		OK_set_error(ERR_ST_FILEREAD,ERR_LC_PEM,ERR_PT_PEM+2,NULL);
		goto done;
	}
	err=0;

done:
	fclose(fp);
	if(err&&buf){ FREE(buf); buf=NULL;}
	return buf;
}

