/* wincry_clist.c */
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
#include "ok_pem.h"
#include "ok_tool.h"
#include "ok_wincry.h"

CertList *Certlist_get_from_system(char *pvPara){
	HCERTSTORE hcs;
	PCCERT_CONTEXT ccon;
	CertList *ret,*cl;
	Cert *ct;

	if((hcs=CertOpenStore(CERT_STORE_PROV_SYSTEM,0,(ULONG)NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,pvPara))==NULL){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CLIST,(int*)GetLastError());
		return NULL;
	}

	ccon=NULL; ret=cl=NULL;
	do{
		if((ccon=CertEnumCertificatesInStore(hcs,ccon))==NULL)
			break;

		if((ct=ASN1_read_cert(ccon->pbCertEncoded))==NULL)
			continue;

		if((ct->der = ASN1_dup(ccon->pbCertEncoded))==NULL)
			goto error;

		if(ret==NULL){
			if((cl=ret=Certlist_new())==NULL) goto error;

		}else{
			if((cl->next=Certlist_new())==NULL) goto error;
			cl->next->prev = cl;
			cl = cl->next;
		}

		cl->cert=ct;
		cl->serialNumber=ct->serialNumber;
		if((STRDUP(cl->issuer,ct->issuer))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_WINCRY,ERR_PT_WINCRY_CLIST,NULL);
			goto error;
		}
		if((STRDUP(cl->subject,ct->subject))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_WINCRY,ERR_PT_WINCRY_CLIST,NULL);
			goto error;
		}
	}while(1);

	if(!(CertCloseStore(hcs,CERT_CLOSE_STORE_FORCE_FLAG))){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_CLIST,(int*)GetLastError());
		goto error;
	}

 	return ret;
error:
	Certlist_free_all(ret);
	return NULL;
}

#endif /* __WINDOWS__ */
