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

void _s2c(unsigned short *st,char *cr,int max);

/*-----------------------------------------------
	Crypt32 API compatible functions
-----------------------------------------------*/
PCCERT_CONTEXT Cert_cert2pccert(Cert *ct){
	PCCERT_CONTEXT ret;
	int i,j;

	/* get PCCERT_CONTEXT from Cert structure */
	if(ct==NULL){return NULL;}

	if(ct->der==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT,NULL);
		return NULL;
	}
	i=ASN1_length(&ct->der[1],&j);i+=j+1;

	if((ret=CertCreateCertificateContext(X509_ASN_ENCODING,ct->der,i))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT,(int*)GetLastError());
	}
	return ret;
}

Cert *Cert_pccert2cert(PCCERT_CONTEXT ccon){
	Cert *ret;
	if(ccon==NULL){return NULL;}
	if((ret=ASN1_read_cert(ccon->pbCertEncoded))==NULL)
		return NULL;
	
	if((ret->der=ASN1_dup(ccon->pbCertEncoded))==NULL){
		Cert_free(ret); ret=NULL;}
	return ret;
}

/*-----------------------------------------------
	Add Certificate to the "pvPara" store.
-----------------------------------------------*/
int Cert_add_toStore(Cert *ct, char *pvPara){
	HCERTSTORE hcs=NULL;
	PCCERT_CONTEXT ccon=NULL;
	int err=-1;

	/* get PCCERT_CONTEXT from Cert structure */
	if((ccon=Cert_cert2pccert(ct))==NULL)
		return -1;

	/* open system store */
	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,pvPara))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+2,(int*)GetLastError());
		goto done;
	}
	/* Add the certificate to "hcs" store. */
	if(!CertAddCertificateContextToStore(hcs,ccon,CERT_STORE_ADD_USE_EXISTING,NULL)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+2,(int*)GetLastError());
		goto done;
	}
	err=0;

done:
	if(ccon) CertFreeCertificateContext(ccon);
	if(hcs)  CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG);
	return err;
}

/*-----------------------------------------------
	Delete Certificate from the "pvPara" store.
-----------------------------------------------*/
int Cert_del_fromStore(Cert *ct, char *pvPara){
	HCERTSTORE hcs=NULL;
	PCCERT_CONTEXT ccon=NULL,ctmp;
	int err=-1;

	/* get PCCERT_CONTEXT from Cert structure */
	if((ccon=Cert_cert2pccert(ct))==NULL)
		return -1;

	/* open system store */
	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,pvPara))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+3,(int*)GetLastError());
		goto done;
	}
	/* get PCCERT_CONTEXT in the "hcs" store. */
	if((ctmp=CertFindCertificateInStore(hcs,0,0,CERT_FIND_PUBLIC_KEY,
			&ccon->pCertInfo->SubjectPublicKeyInfo,NULL))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+3,(int*)GetLastError());
		goto done;
	}
	/* delete the certificate from "hcs" store. */
	if(!CertDeleteCertificateFromStore(ctmp)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+3,(int*)GetLastError());
		goto done;
	}
	err=0;

done:
	if(ccon) CertFreeCertificateContext(ccon);
	if(hcs)  CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG);
	return err;
}

/*---------------------------------------------------
 Import Certificate & Private key to the "MY" store.
---------------------------------------------------*/
int Cert_add_toMyStore(Cert *ct,Key *prv,int enhanced,int export){
	HCERTSTORE hcs=NULL;
	PCCERT_CONTEXT ccon=NULL,ctmp;
	CRYPT_KEY_PROV_INFO ckpInfo;
	int i,j,err=-1;
	char buf1[256],buf2[32];
	unsigned short bufs[256];

	if((ct==NULL)||(prv==NULL))
		return -1;

	/* get PCCERT_CONTEXT from Cert structure */
	if((ccon=Cert_cert2pccert(ct))==NULL)
		return -1;

	/* open system store */
	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,WIN_STORE_MY))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+4,(int*)GetLastError());
		goto done;
	}
	/* Add the certificate to "hcs" store. */
	if(!CertAddCertificateContextToStore(hcs,ccon,CERT_STORE_ADD_REPLACE_EXISTING,NULL)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+4,(int*)GetLastError());
		goto done;
	}
	/* get PPCERT_CONTEXT in the "hcs" store. */
	if((ctmp=CertFindCertificateInStore(hcs,0,0,CERT_FIND_PUBLIC_KEY,
			&ccon->pCertInfo->SubjectPublicKeyInfo,NULL))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+4,(int*)GetLastError());
		goto done;
	}

	/* get Container Name */
	strcpy(buf1,"{aicrypto-");
	strncat(buf1,ct->issuer,64);
	sprintf(buf2,"-%.6d}",ct->serialNumber);
	strcat(buf1,buf2);
	j = strlen(buf1);

	memset(bufs,0,sizeof(short)*256);
	for(i=0;i<j; i++) bufs[i] = (unsigned short)buf1[i];

	/* filfull CRYPT_KEY_PROV_INFO */
	ckpInfo.pwszContainerName = bufs;
	ckpInfo.pwszProvName = (enhanced)?(MS_ENHANCED_PROV_W):(MS_DEF_PROV_W);
	ckpInfo.dwProvType = PROV_RSA_FULL;
	ckpInfo.dwFlags = 0;
	ckpInfo.cProvParam = 0;
	ckpInfo.rgProvParam = NULL;
	ckpInfo.dwKeySpec = AT_KEYEXCHANGE;

	if(!CertSetCertificateContextProperty(ctmp,CERT_KEY_PROV_INFO_PROP_ID,
			CERT_STORE_NO_CRYPT_RELEASE_FLAG,&ckpInfo)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+4,(int*)GetLastError());
		goto done;
	}

	switch(prv->key_type){
	case KEY_RSA_PRV:
		if(RSAprv_add_toContainer((Prvkey_RSA*)prv, buf1,
			(enhanced)?(MS_ENHANCED_PROV):(MS_DEF_PROV),export))
			goto done;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+4,(int*)GetLastError());
		goto done;
	}

	err=0;
done:
	if(ccon) CertFreeCertificateContext(ccon);
	if(hcs)  CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG);
	return err;
}

/*---------------------------------------------------
 Export  Private key from the "MY" store.
---------------------------------------------------*/
Key *Cert_get_keyFromContainer(Cert *ct){
	char buf1[256],buf2[256];
	Key *ret=NULL;
	HCERTSTORE hcs=NULL;
	PCCERT_CONTEXT ccon=NULL,ctmp;
	PCRYPT_KEY_PROV_INFO ckpInfo=NULL;
	int i;

	if(ct==NULL) return NULL;

	/* get PCCERT_CONTEXT from Cert structure */
	if((ccon=Cert_cert2pccert(ct))==NULL) return NULL;

	/* open system store */
	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,WIN_STORE_MY))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+5,(int*)GetLastError());
		goto done;
	}
	/* get PPCERT_CONTEXT in the "hcs" store. */
	if((ctmp=CertFindCertificateInStore(hcs,0,0,CERT_FIND_PUBLIC_KEY,
			&ccon->pCertInfo->SubjectPublicKeyInfo,NULL))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+5,(int*)GetLastError());
		goto done;
	}

	/* get certificate property information */
	/* CRYPT_KEY_PROV_INFO is really problem -- this function returns
	 * variable length record...need to alloc memory first.
	 */
	if(!CertGetCertificateContextProperty(ctmp,CERT_KEY_PROV_INFO_PROP_ID,NULL,&i)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+5,(int*)GetLastError());
		goto done;
	}
	if((ckpInfo=(PCRYPT_KEY_PROV_INFO)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+5,(int*)GetLastError());
		goto done;
	}
	if(!CertGetCertificateContextProperty(ctmp,CERT_KEY_PROV_INFO_PROP_ID,ckpInfo,&i)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CERT+5,(int*)GetLastError());
		goto done;
	}

	memset(buf1,0,256);
	memset(buf2,0,256);
	_s2c(ckpInfo->pwszContainerName,buf1,250);
	_s2c(ckpInfo->pwszProvName,buf2,250);
	ret = (Key*)RSAprv_get_fromContainer(buf1,buf2);

done:
	if(ckpInfo) FREE(ckpInfo);
	if(ccon) CertFreeCertificateContext(ccon);
	if(hcs)  CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG);
	return ret;
}

void _s2c(unsigned short *st,char *cr,int max){
	int i=0;
	while((st[i])&&(i<max)){
		cr[i] = (char)st[i];
		i++;
	}
}


#endif /* __WINDOWS__ */
