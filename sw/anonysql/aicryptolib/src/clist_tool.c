/* clist_tool.c */
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
#include "ok_pem.h"
#include "ok_x509.h"

/* 
 * Cert list tools
 */
/*-----------------------------------------
  find clist from subject list
-----------------------------------------*/
CertList *Certlist_find_bySbj(CertList *top, char *subject){
	while(top){
		if(top->subject)
			if(!strcmp(top->subject,subject))
				return top;
		top = top->next;
	}
	return NULL;
}

CertList *Certlist_find_byIss(CertList *top, char *issuer){
	while(top){
		if(top->issuer)
			if(!strcmp(top->issuer,issuer))
				return top;
		top = top->next;
	}
	return NULL;
}

CertList *Certlist_find_bySNum(CertList *top, int serial){
	while(top){
		if(top->serialNumber == serial)
			return top;
		top = top->next;
	}
	return NULL;
}

/*-----------------------------------------
  Get a certificate
-----------------------------------------*/
CertList *Cert_2Certlist(Cert *ct){
	CertList *cl;

	if((cl=Certlist_new())==NULL) return NULL;

	if((cl->cert=Cert_dup(ct))==NULL) goto error;;
	if((STRDUP(cl->issuer,ct->issuer))==NULL) goto dup_error;
	if((STRDUP(cl->subject,ct->subject))==NULL) goto dup_error;
	cl->serialNumber = ct->serialNumber;
	return cl;
dup_error:
	OK_set_error(ERR_ST_STRDUP,ERR_LC_X509CERT,ERR_PT_CLTOOL+1,NULL);
error:
	Certlist_free(cl);
	return NULL;
}

/*-----------------------------------------
  list oparations
-----------------------------------------*/
/* incert "data" after "where" */
int Certlist_insert(CertList *where, CertList *data){
	CertList *cl;

	if((where==NULL)||(data==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CERT,ERR_PT_CLTOOL+2,NULL);
		return -1;
	}
	if(cl=where->next) /* it's not compare */
		cl->prev =data;
	where->next=data;
	data->next =cl;
	data->prev =where;
	return 0;
}

CertList *Certlist_join(CertList *top, CertList *join){
	CertList *hd=NULL;

	if(top==NULL) return join;
	if(join==NULL) return top;
	if(top&&join){
		for(hd=top; hd->next ; hd=hd->next);
		hd->next = join;
		join->prev = hd;
	}
	return top;
}

/* delete "list" from whole list */
int Certlist_delete(CertList *list){
	if(list->prev) list->prev->next=list->next;
	if(list->next) list->next->prev=list->prev;

	Certlist_free(list);
	return 0;
}

/* count list items */
int Certlist_count(CertList *top){
	int i=0;

	while(top){i++; top=top->next;}
	return i;
}

/* 
 * CRL list tools
 */
/*-----------------------------------------
  find clist from subject list
-----------------------------------------*/
CRLList *CRLlist_find_byIss(CRLList *top, char *issuer){
	while(top){
		if(!strcmp(top->issuer,issuer))
			return top;
		top = top->next;
	}
	return NULL;
}

/*-----------------------------------------
  Get a CRL list
-----------------------------------------*/
CRLList *CRL_2CRLlist(CRL *crl){
	CRLList *cl;

	if((cl=CRLlist_new())==NULL) return NULL;

	if((cl->crl=CRL_dup(crl))==NULL) goto error;
	if((STRDUP(cl->issuer,crl->issuer))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_X509CERT,ERR_PT_CLTOOL+4,NULL);
		goto error;
	}
	return cl;
error:
	CRLlist_free(cl);
	return NULL;
}

/*-----------------------------------------
  list oparations
-----------------------------------------*/
/* incert "data" after "where" */
int CRLlist_insert(CRLList *where, CRLList *data){
	CRLList *cl;

	if((where==NULL)||(data==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CERT,ERR_PT_CLTOOL+5,NULL);
		return -1;
	}
	if(cl=where->next) /* it's not compare */
		cl->prev =data;
	where->next=data;
	data->next =cl;
	data->prev =where;
	return 0;
}

CRLList *CRLlist_join(CRLList *top, CRLList *join){
	CRLList *hd=NULL;

	if(top==NULL) return join;
	if(join==NULL) return top;
	if(top&&join){
		for(hd=top; hd->next ; hd=hd->next);
		hd->next = join;
		join->prev = hd;
	}
	return top;
}

/* delete "list" from whole list */
int CRLlist_delete(CRLList *list){
	if(list->prev) list->prev->next=list->next;
	if(list->next) list->next->prev=list->prev;

	CRLlist_free(list);
	return 0;
}

/* count list items */
int CRLlist_count(CRLList *top){
	int i=0;

	while(top){i++; top=top->next;}
	return i;
}

