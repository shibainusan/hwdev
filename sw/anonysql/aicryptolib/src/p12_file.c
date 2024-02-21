/* p12_file.c */
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

#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_tool.h"
#include "ok_uconv.h"

/*-----------------------------------------------
  PKCS#12 File Read.
-----------------------------------------------*/
PKCS12 *P12_read_file(char *fname){
	PKCS12 *ret;
	unsigned char *der,*cp;

	if((der=ASN1_read_der(fname))==NULL)
		return NULL;
  
#ifdef __WINDOWS__
	if(strchr(fname,'\\')){ /* set prompt for "ca.p12" */
		char prompt[64];

		cp = &fname[strlen(fname)-1];
		while(*cp!='\\'){cp--;}
		if(!strcmp(cp,"\\ca.p12")){
			cp--;
			if(*cp != '.')
				while(*cp != '\\'){ cp--; };
		}
		memset(prompt,0,64);
		strncpy(prompt, ++cp,60);
		strcat(prompt," :");
		OK_set_prompt(prompt);
	}
	ret = ASN1_read_p12(der);
	OK_set_prompt(NULL);
#else
	ret = ASN1_read_p12(der);
#endif

	FREE(der);
	return ret;
}

/*-----------------------------------------------
  PKCS#12 File Write. ret=0 .. success.
-----------------------------------------------*/
int P12_write_file(PKCS12 *p12,char *fname){
	unsigned char *der;
	int i,err=-1;

	if((der=P12_toDER(p12,NULL,&i))==NULL)
		return -1;

	if(ASN1_write_der(der,fname))
		goto done;

	err=0;
done:
	FREE(der);
	return err;
}

/*-----------------------------------------------
  PKCS#12 Print
-----------------------------------------------*/
void print_f_l(P12_Baggage *bg){
	char  buf[256];
	int i;

	if(bg->friendlyName){
		if(UC_conv(UC_CODE_UNICODE,UC_LOCAL_JCODE,(char*)bg->friendlyName,
			   bmp_len((char*)bg->friendlyName),buf,254) < 0)
		  return;
		printf("Friendly Name: %s\n",buf);
	}else{
		printf("Friendly Name: NULL\n");
	}
	printf("Local Key ID: ");
	for(i=0;i<4;i++) printf("%.2x ",bg->localKeyID[i]);
	printf("\n");
}

void P12_print(PKCS12 *p12){
	P12_Baggage *bg;

	printf("PKCS#12 file version : %d\n",p12->version);

	for(bg=p12->bag;bg!=NULL;bg=bg->next){
		switch(bg->type){
		case OBJ_P12v1Bag_PKCS8:
			printf(" ----- PKCS#12 v1 Private Key Bag ----- \n");
			print_f_l(bg);
			Key_print(((P12_KeyBag*)bg)->key);
			printf(" ------- END of Private Key Bag ------- \n");
			break;
		case OBJ_P12v1Bag_CERT:
			printf(" -------- PKCS#12 v1 Cert Bag --------- \n");
			print_f_l(bg);
			Cert_print(((P12_CertBag*)bg)->cert);
			printf(" ---------- END of Cert Bag ----------- \n");
			break;
		case OBJ_P12v1Bag_CRL:
			printf(" --------- PKCS#12 v1 CRL Bag --------- \n");
			CRL_print(((P12_CRLBag*)bg)->crl);
			printf(" ----------- END of CRL Bag ----------- \n");
			break;
		}
	}
}

