/* wincry_cert.c */
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

#ifdef __WINDOWS__	/* these codes are required with WIN CRYPT API */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_err.h"
#include "ok_asn1.h"
#include "ok_tool.h"
#include "ok_wincry.h"

/*-----------------------------------------------
	Crypt32 API compatible functions
-----------------------------------------------*/
PCCRL_CONTEXT CRL_crl2pccrl(CRL *crl){
	PCCRL_CONTEXT ret;
	int i,j;

	/* get PCCRL_CONTEXT from CRL structure */
	if(crl==NULL){return NULL;}

	if(crl->der==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL,NULL);
		return NULL;
	}
	i=ASN1_length(&crl->der[1],&j);i+=j+1;

	if((ret=CertCreateCRLContext(X509_ASN_ENCODING,crl->der,i))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL,(int*)GetLastError());
	}
	return ret;
}

CRL *CRL_pccrl2crl(PCCRL_CONTEXT ccon){
	CRL *ret;
	if(ccon==NULL){return NULL;}

	if((ret=ASN1_read_crl(ccon->pbCrlEncoded))==NULL)
		return NULL;
	
	if((ret->der=ASN1_dup(ccon->pbCrlEncoded))==NULL){
		CRL_free(ret); ret=NULL;}

	return ret;
}

/*-----------------------------------------------
	Add CRL to the "pvPara" store.
-----------------------------------------------*/
int CRL_add_toStore(CRL *crl, char *pvPara){
	HCERTSTORE hcs=NULL;
	PCCRL_CONTEXT ccon=NULL;
	int err=-1;

	/* get PCCRL_CONTEXT from Cert structure */
	if((ccon=CRL_crl2pccrl(crl))==NULL)
		return -1;

	/* Open system store */
	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,pvPara))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL+2,(int*)GetLastError());
		goto done;
	}
	/* Add the CRL to "hcs" store. */
	if(!CertAddCRLContextToStore(hcs,ccon,CERT_STORE_ADD_USE_EXISTING,NULL)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL+2,(int*)GetLastError());
		goto done;
	}
	err=0;

done:
	if(ccon) CertFreeCRLContext(ccon);
	if(hcs)  CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG);
	return err;
}

/*-----------------------------------------------
	Delete CRL from the "pvPara" store.
-----------------------------------------------*/
int CRL_del_fromStore(CRL *crl, char *pvPara){
	HCERTSTORE hcs=NULL;
	PCCRL_CONTEXT ccon=NULL;
	int err=-1;

	/* get PCCRL_CONTEXT from Cert structure */
	if((ccon=CRL_crl2pccrl(crl))==NULL)
		return -1;

	/* Open system store */
	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,pvPara))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL+3,(int*)GetLastError());
		goto done;
	}

#if 0 /* current version doesn't support this API */
	PCCRL_CONTEXT *ctmp;

	/* get PCCRL_CONTEXT in the "hcs" store. */
	if((ctmp=CertFindCRLInStore(hcs,0,0,CRL_FIND_EXISTING,ccon,NULL))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL+3,(int*)GetLastError());
		goto done;
	}

	/* delete the CRL from "hcs" store. */
	if(!CertDeleteCRLFromStore(ctmp)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CRL+3,(int*)GetLastError());
		goto done;
	}
#endif
	err=0;

done:
	if(ccon) CertFreeCRLContext(ccon);
	if(hcs)  CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG);
	return err;
}

#endif /* __WINDOWS__ */
