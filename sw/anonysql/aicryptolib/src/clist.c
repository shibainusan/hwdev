/* clist.c */
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

#include "ok_pem.h"
#include "ok_x509.h"

/*-----------------------------------------
  alloc & FREE struct certlist
-----------------------------------------*/
CertList *Certlist_new(void){
	CertList *ret;

	if((ret=(CertList*)MALLOC(sizeof(CertList)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CLIST,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CertList));
	return ret;
}

void Certlist_free(CertList *cl){
	if(cl==NULL) return;

	if(cl->subject)	FREE(cl->subject);
	if(cl->issuer)	FREE(cl->issuer);

	Cert_free(cl->cert);
	FREE(cl);
}

void Certlist_free_all(CertList *top){
	CertList *cl,*next;

	for(cl=top; cl ;cl=next){
		next=cl->next;
		Certlist_free(cl);
	}
}

/*-----------------------------------------
  duplicate struct CertList
-----------------------------------------*/
CertList *Certlist_dup(CertList *org){
	CertList *ret=NULL;

	if((ret=Certlist_new())==NULL) goto  error;

	ret->state        = org->state;
	ret->serialNumber = org->serialNumber;

	if(org->cert){
		if((ret->cert=Cert_dup(org->cert))==NULL) goto error;
	}
	if(org->issuer){
		if((STRDUP(ret->issuer,org->issuer))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_X509CERT,ERR_PT_CLIST+1,NULL);
			goto error;
		}
	}
	if(org->subject){
		if((STRDUP(ret->subject,org->subject))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_X509CERT,ERR_PT_CLIST+1,NULL);
			goto error;
		}
	}

	return ret;
error:
	Certlist_free(ret);
	return NULL;
}

CertList *Certlist_dup_all(CertList *top){
	CertList *hd,*cl,*ret=NULL;

	for( ; top ;top=top->next){
		if((cl=Certlist_dup(top))==NULL) goto error;
		if(ret){
			hd->next = cl;
			cl->prev = hd;
			hd = cl;
		}else{
			ret=hd=cl;
		}
	}
	return ret;
error:
	Certlist_free_all(ret);
	return NULL;
}


/*-----------------------------------------
  alloc & FREE struct CRLList
-----------------------------------------*/
CRLList *CRLlist_new(void){
	CRLList *ret;

	if((ret=(CRLList*)MALLOC(sizeof(CRLList)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CLIST+2,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CRLList));
	return ret;
}

void CRLlist_free(CRLList *cl){
	if(cl==NULL) return;

	if(cl->issuer)	FREE(cl->issuer);
	CRL_free(cl->crl);
	FREE(cl);
}

void CRLlist_free_all(CRLList *top){
	CRLList *cl,*next;

	for(cl=top;cl!=NULL;cl=next){
		next=cl->next;
		CRLlist_free(cl);
	}
}

/*-----------------------------------------
  duplicate struct CRLList
-----------------------------------------*/
CRLList *CRLlist_dup(CRLList *org){
	CRLList *ret=NULL;

	if((ret=CRLlist_new())==NULL) goto  error;

	ret->state = org->state;

	if(org->crl){
		if((ret->crl=CRL_dup(org->crl))==NULL) goto error;
	}
	if(org->issuer){
		if((STRDUP(ret->issuer,org->issuer))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_X509CERT,ERR_PT_CLIST+2,NULL);
			goto error;
		}
	}

	return ret;
error:
	CRLlist_free(ret);
	return NULL;
}

CRLList *CRLlist_dup_all(CRLList *top){
	CRLList *hd,*cl,*ret=NULL;

	for( ; top ;top=top->next){
		if((cl=CRLlist_dup(top))==NULL) goto error;
		if(ret){
			hd->next = cl;
			cl->prev = hd;
			hd = cl;
		}else{
			ret=hd=cl;
		}
	}
	return ret;
error:
	CRLlist_free_all(ret);
	return NULL;
}

