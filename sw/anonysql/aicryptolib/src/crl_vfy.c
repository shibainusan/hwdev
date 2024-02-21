/* crl_vfy.c */
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

#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"
#include "ok_tool.h"

/*-----------------------------------------
  CRL Verify.
-----------------------------------------*/
int CRL_verify(CertList *crtl,CRLList *crll,CRL *crl,int max_depth,int type){
	CertList *cl = NULL;
	Cert  *ca = NULL;
	int ret = 0;

	/* find CA certificate in the list */
	for(cl=crtl; cl ;cl=cl->next){
		if(CRL_is_path(cl->cert,crl)){
			ca = Certlist_get_cert(cl);
			break;
		}
	}
	if(cl == NULL){
		ret = X509_VFY_ERR_NOT_IN_CERTLIST;
		goto done;
	}
	if(ret=Cert_verify(crtl,crll,ca,max_depth,type)) goto done;

	/* verify CRL */
	if(ret=CRL_signature_verify(ca,crl)) goto done;
	else if(ret=CRL_time_verify(crl)) goto done;

done:
	return ret;
}
/*-----------------------------------------------
  CRL signature verify
  return 0  ... verify OK
  return err  ... verify Failed(err=number)
-----------------------------------------------*/
int CRL_signature_verify(Cert *ca,CRL *crl){
	int i,ret = 0;

	if(Cert_dncmp(&ca->subject_dn,&crl->issuer_dn))
		return X509_VFY_ERR_NOT_CACERT;

	i = ASN1_vfy_sig(ca->pubkey,ASN1_next(crl->der),crl->signature,crl->signature_algo);
	if(i > 0) ret = X509_VFY_ERR_SIGNATURE_CRL;
	if(i==-2) ret = X509_VFY_ERR_UNKOWN_SIG_ALGO;
	if(i < 0) ret = X509_VFY_ERR_SYSTEMERR;

	return ret;
}

/*-----------------------------------------------
  CRL validity verify
  return 0  ... verify OK
  return err  ... verify Failed(err=number)
-----------------------------------------------*/
int CRL_time_verify(CRL *crl){
	time_t t1,t2;

	time(&t1); /* get current utc time */

	t2 = timegm(&crl->lastUpdate); /* utc -> utc */
	if(t1<t2) return X509_VFY_ERR_LASTUPDATE;      /* last update Error */

	t2 = timegm(&crl->nextUpdate); /* utc -> utc */
	if(t1>t2) return X509_VFY_ERR_NEXTUPDATE;      /* next update Error */

	return 0;
}

/*-----------------------------------------------
  compare two CRL structures
-----------------------------------------------*/
int CRL_cmp(CRL *c1, CRL *c2){
	CertExt *e1,*e2;
	Revoked *r1,*r2;
	time_t t1,t2;

	/* compare version */
	if(c1->version != c2->version) return -1;
	/* compare DN */
	if(Cert_dncmp(&c1->issuer_dn,&c2->issuer_dn)) return -1;
	/* compare TIME */
	t1 = mktime(&c1->lastUpdate);
	t2 = mktime(&c2->lastUpdate);
	if(t1 != t2) return -1;
	t1 = mktime(&c1->nextUpdate);
	t2 = mktime(&c2->nextUpdate);
	if(t1 != t2) return -1;

	/* compare list -- should be same order (SEQUENCE) */
	r1=c1->next; r2=c2->next;
	while(r1&&r2){
		if(r1->serialNumber != r2->serialNumber) return -1;
		t1 = mktime(&r1->revocationDate);
		t2 = mktime(&r2->revocationDate);
		if(t1 != t2) return -1;

		r1=r1->next;
		r2=r2->next;
	}
	if(r1 || r2) return -1;

	/* compare extensions -- just compare list of extension */
	e1 = c1->ext; e2 = c2->ext;
	while(e1 && e2){
		if(e1->extnID != e2->extnID) return -1;
		if(e1->critical != e2->critical) return -1;
		e1=e1->next; e2=e2->next;
	}
	if(e1 || e2) return -1;

	return 0;
}

