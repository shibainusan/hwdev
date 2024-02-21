/* crl_print.c */
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

#include "ok_x509.h"
#include "ok_asn1.h"


void print_sig_crl(CRL *crl);
void print_timecrl(CRL *crl);
void print_revoked(CRL *crl);

/* cert_print.c */
void print_v3_extensions(CertExt *top, int cf);
void print_sig_algo(int algo);
void print_signature(unsigned char *sig, int max, int algo);

/*-----------------------------------------
  print CRL struct
-----------------------------------------*/
void CRL_print(CRL *crl){
	if(crl==NULL) return;

	printf("CRL:\n");
	printf("  Data:\n");
	printf("    Version: %d (0x%x)\n",crl->version+1,crl->version);
	printf("    Signature Algorithm: ");
	print_sig_algo(crl->signature_algo);
	printf("    Issuer: %s\n",crl->issuer);
	print_timecrl(crl);
	print_revoked(crl);
	if(crl->ext) print_v3_extensions(crl->ext,2);
	print_signature(crl->signature,crl->siglen,0);
}

void print_timecrl(CRL *crl){
	char *cp;

	if((cp=stm2str(&crl->lastUpdate,0))==NULL) return;
	printf("    lastUpdate: %s\n",cp);
	if(crl->nextUpdate.tm_year>0){
		if((cp=stm2str(&crl->nextUpdate,0))==NULL) return;
		printf("    nextUpdate: %s\n",cp);
	}
}

void print_revoked(CRL *crl){
    Revoked *rv;
	char *cp;

    printf("    Revoked:\n");
    for(rv=crl->next;rv!=NULL;rv=rv->next){
		if((cp=stm2str(&rv->revocationDate,0))==NULL) continue;

		printf("      serialNumber:%d, revocationDate:%s\n",rv->serialNumber,cp);
		if(rv->entExt) print_v3_extensions(rv->entExt,3);
	}
}
