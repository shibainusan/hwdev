/* cert.c */
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

#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_asn1.h"

/*-----------------------------------------
  make new struct cert
-----------------------------------------*/
Cert *Cert_new(void){
	Cert	*ret;

	if((ret=(Cert*)MALLOC(sizeof(Cert)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERT,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Cert));
	ret->signature_algo = OBJ_SIG_NULL;
	ret->pubkey_algo = KEY_NULL;
	return ret;
}

/*-----------------------------------------
  FREE struct cert
-----------------------------------------*/
void Cert_free(Cert *ct){
	if(ct==NULL) return;

	if(ct->long_sn)  FREE(ct->long_sn);
	if(ct->issuer)	 FREE(ct->issuer);
	if(ct->subject)	 FREE(ct->subject);
	cert_dn_free(&(ct->issuer_dn));
	cert_dn_free(&(ct->subject_dn));

	if(ct->pubkey)	 Key_free(ct->pubkey);

	CertExt_free_all(ct->ext);
	if(ct->signature)	 FREE(ct->signature);
	if(ct->der)		 FREE(ct->der);
	FREE(ct);
}

/*-----------------------------------------
  Duplicate struct Cert
-----------------------------------------*/
Cert *Cert_dup(Cert *src){
	Cert *ret=NULL;

	if(src==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CERT,ERR_PT_CERTTOOL+6,NULL);
		return NULL;
	}

	if((ret=Cert_new())==NULL) goto error;
	ret->version        = src->version;
	ret->serialNumber   = src->serialNumber;
	ret->pubkey_algo    = src->pubkey_algo;
	ret->siglen         = src->siglen;
	ret->signature_algo = src->signature_algo;
	memcpy(&ret->time,&src->time,sizeof(Validity));

	if(src->long_sn){
		if((ret->long_sn=ASN1_dup(src->long_sn))==NULL)
			goto error;
	}

	if(src->issuer){	/* for CSR */
		if((STRDUP(ret->issuer,src->issuer))==NULL)
			goto error;
	}
	if((STRDUP(ret->subject,src->subject))==NULL)
		goto error;

	if(Cert_dncopy(&src->issuer_dn,&ret->issuer_dn))
		goto error;
	if(Cert_dncopy(&src->subject_dn,&ret->subject_dn))
		goto error;

	if(src->ext){
		if((ret->ext=CertExt_dup_all(src->ext))==NULL)
			goto error;
	}
	if((ret->pubkey=Key_dup(src->pubkey))==NULL)
		goto error;

	if((ret->signature=(unsigned char*)MALLOC(src->siglen))==NULL)
		goto error;
	memcpy(ret->signature,src->signature,src->siglen);

	if(src->der){
		if((ret->der=ASN1_dup(src->der))==NULL)
			goto error;
	}

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERTTOOL+6,NULL);
	Cert_free(ret);
	return NULL;
}

/*-----------------------------------------
  CertDN init & FREE.
-----------------------------------------*/
void cert_dn_init(CertDN *dn){
	memset(dn,0,sizeof(CertDN));
}

void cert_dn_free(CertDN *dn){
	int	i;
	for(i=0;i<dn->num;i++)
		if(dn->rdn[i].tag){
			FREE(dn->rdn[i].tag);
			dn->rdn[i].tag=NULL;
		}
}

