/* p7_file.c */
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

PKCS7 *ASN1_read_p7s(unsigned char *der);
PKCS7 *ASN1_read_p7env(unsigned char *der);

/*-----------------------------------------
  Read PKCS#7 Signed-Data File
-----------------------------------------*/
PKCS7 *P7s_read_file(char *fname){
	unsigned char *buf=NULL,*tmp=NULL;
	PKCS7 *ret=NULL;
	int i;

	if((i=get_fformat(fname,&buf))<0) goto done;
	switch(i){
	case 1: /* binary (DER?) */
		ret = ASN1_read_p7s(buf);
		break;
	case 2: /* PEM */
		ret = PEM_read_p7(fname);
		break;
	case 3: /* text */
		if((tmp=Base64_decode(buf,&i))==NULL) goto done;
		ret = ASN1_read_p7s(tmp);
		break;
	}

	/* This operation breaks friendly name and local keyID... */
	/*  P12_check_chain((PKCS12*)ret,0); */

done:	
	/* P7s might contain very big size of content.
	 * so, p7->der doesn't have any buffer.
	 */
	if(buf) FREE(buf);
	if(tmp) FREE(tmp);
	return ret;
}

/*-----------------------------------------
  Write PKCS#7 Signed-Data File
-----------------------------------------*/
int P7s_write_file(PKCS7 *p7, char *fname){
	unsigned char *sig;
	FILE  *fp;
	int	len,err=-1;

	if((fp = fopen(fname,"wb"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PKCS7,ERR_PT_P7FILE+1,NULL);
		return -1;
	}

	if((sig=P7_signed_toDER(p7,NULL,&len))==NULL) goto done;

	/* ASN1_write_der doesn't work because of Indefinite length... */

	if(fwrite(sig,sizeof(char),len,fp)<(unsigned)len){
		OK_set_error(ERR_ST_FILEWRITE,ERR_LC_PKCS7,ERR_PT_P7FILE+1,NULL);
		goto done;
	}
	err=0;
done:
	fclose(fp);
	if(sig) FREE(sig);
	return err;
}

/*-----------------------------------------
  Read PKCS#7 Enveloped-Data File
-----------------------------------------*/
PKCS7 *P7m_read_file(char *fname){
	unsigned char *der;
	PKCS7 *ret;

	if((der = ASN1_read_der(fname))==NULL)
		return NULL;

	ret = ASN1_read_p7env(der);

	/* ret->der should be empty, because encrypted data
	   might be very big... */

	FREE(der);
	return ret;
}

/*-----------------------------------------
  Write PKCS#7 Enveloped-Data File
-----------------------------------------*/
int P7m_write_file(PKCS7 *p7, char *fname){
	unsigned char *env;
	FILE  *fp;
	int	len,err=-1;

	if((fp = fopen(fname,"wb"))==NULL){
		if(okerr) fprintf(okerr,"P7m write:fopen error:%s\n",fname);
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PKCS7,ERR_PT_P7FILE+3,NULL);
		return 1;
	}

	if((env=P7_envelope_toDER(p7,NULL,&len))==NULL) goto done;

	/* ASN1_write_der doesn't work because of Indefinite length... */

	if(fwrite(env,sizeof(char),len,fp)<(unsigned)len){
		OK_set_error(ERR_ST_FILEWRITE,ERR_LC_PKCS7,ERR_PT_P7FILE+3,NULL);
		goto done;
	}
	err=0;
done:
	fclose(fp);
	FREE(env);
	return err;
}

/*-----------------------------------------------
  PKCS#7 Signed-Data Print
-----------------------------------------------*/
void P7_print(PKCS7 *p7){
	P12_Baggage	*bg;

	for(bg=p7->bag;bg!=NULL;bg=bg->next){
		switch(bg->type){
		case OBJ_P12v1Bag_CERT:
			printf(" ---- PKCS#7 Signed-DATA Certificate ---- \n");
			Cert_print(((P12_CertBag*)bg)->cert);
			printf(" ---------- END of Certificate ---------- \n");
			break;
		case OBJ_P12v1Bag_CRL:
			printf(" ------- PKCS#7 Signed-DATA CRL --------- \n");
			CRL_print(((P12_CRLBag*)bg)->crl);
			printf(" -------------- END of CRL -------------- \n");
			break;
		}
	}
}
