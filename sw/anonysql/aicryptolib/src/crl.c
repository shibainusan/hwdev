/* crl.c */
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
#include "ok_x509.h"


/*-----------------------------------------
  make new struct crl
-----------------------------------------*/
CRL *CRL_new(void){
	CRL  *ret;

	if((ret=(CRL*)MALLOC(sizeof(CRL)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRL,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CRL));
	return ret;
}

Revoked *Revoked_new(void){
	Revoked *ret;

	if((ret=(Revoked*)MALLOC(sizeof(Revoked)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRL+1,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Revoked));
	return ret;
}

/*-----------------------------------------
  FREE struct crl
-----------------------------------------*/
void CRL_free(CRL *crl){
	if(crl==NULL) return;

	if(crl->issuer) FREE(crl->issuer);
	cert_dn_free(&(crl->issuer_dn));

	if(crl->signature) FREE(crl->signature);
	if(crl->der) FREE(crl->der);
	CertExt_free_all(crl->ext);

	Revoked_free_all(crl->next);
	FREE(crl);
}

void Revoked_free(Revoked *rv){
	if(rv==NULL) return;
	if(rv->long_sn) FREE(rv->long_sn);
	CertExt_free_all(rv->entExt);
	FREE(rv);
}

void Revoked_free_all(Revoked *top){
	Revoked	*next;

	while(top!=NULL){
		next = top->next;
		Revoked_free(top);
		top=next;
	}
}

/*-----------------------------------------
  duplicate struct crl
-----------------------------------------*/
CRL *CRL_dup(CRL *src){
	CRL *ret;

	if(src==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CRL,ERR_PT_CRL+2,NULL);
		return NULL;
	}

	if((ret=CRL_new())==NULL) return NULL;
	ret->version        = src->version;
	ret->siglen         = src->siglen;
	ret->signature_algo = src->signature_algo;
	memcpy(&ret->lastUpdate,&src->lastUpdate,sizeof(struct tm));
	memcpy(&ret->nextUpdate,&src->nextUpdate,sizeof(struct tm));

	if((STRDUP(ret->issuer,src->issuer))==NULL) 
		goto error;
	if(Cert_dncopy(&src->issuer_dn,&ret->issuer_dn))
		goto error;

	if(src->next){
		if((ret->next=Revoked_dup(src->next))==NULL)
			goto error;
	}
	if(src->ext){
		if((ret->ext=CertExt_dup_all(src->ext))==NULL)
			goto error;
	}

	if((ret->signature=(unsigned char*)MALLOC(src->siglen))==NULL)
		goto error;
	memcpy(ret->signature,src->signature,src->siglen);

	if(src->der){
		if((ret->der=ASN1_dup(src->der))==NULL)
			goto error;
	}

	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRL+2,NULL);
	CRL_free(ret);
	return NULL;
}

Revoked *Revoked_dup(Revoked *src){
	Revoked *ret,*now;

	ret=NULL;
	while(src){
		if((now=Revoked_new())==NULL) goto error;

		now->serialNumber = src->serialNumber;
		memcpy(&now->revocationDate,&src->revocationDate,sizeof(struct tm));
		if(src->long_sn){
			if((now->long_sn = ASN1_dup(src->long_sn))==NULL) goto error;
		}
		if(src->entExt){
			if((now->entExt=CertExt_dup_all(src->entExt))==NULL) goto error;
		}

		src=src->next;
		if(ret){
			now->next=ret->next;
			ret->next=now;
		}else{
			ret=now;
		}
	}
	return ret;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CRL,ERR_PT_CRL+3,NULL);
	Revoked_free_all(now);
	Revoked_free_all(ret);
	return NULL;
}
