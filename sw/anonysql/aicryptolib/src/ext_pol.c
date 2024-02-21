/* ext_pol.c */
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
 *	this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *	this list of conditions and the following disclaimer in the documentation
 *	and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *	display the following acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *	acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	 Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
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

#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_x509ext.h"

#include "ok_uconv.h"

/*-----------------------------------------
    alloc & free ExtCertPol
-----------------------------------------*/
ExtCertPol *ExtCP_new(){
	ExtCertPol *ret;

	if((ret=(ExtCertPol*)MALLOC(sizeof(ExtCertPol)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTPOL,NULL);
		return NULL;
	}

	memset(ret,0,sizeof(ExtCertPol));
	return(ret);	
}

void ExtCP_free(ExtCertPol *ecp){
	if(ecp==NULL) return;
	if(ecp->policyID) FREE(ecp->policyID);
	ExtPI_free_all(ecp->info);
	FREE(ecp);
}

void ExtCP_free_all(ExtCertPol *top){
	ExtCertPol *next;
	while(top){
		next=top->next;
		ExtCP_free(top);
		top=next;
	}
}

ExtCertPol *ExtCP_dup(ExtCertPol *ecp){
	ExtCertPol *ret=NULL;

	if((ret=ExtCP_new())==NULL) goto error;

	if((STRDUP(ret->policyID,ecp->policyID))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTPOL,NULL);
		goto error;
	}
	if((ret->info=ExtPI_dup_all(ecp->info))==NULL) goto error;

	return ret;
error:
	ExtCP_free(ret);
	return NULL;
}

ExtCertPol *ExtCP_dup_all(ExtCertPol *top){
	ExtCertPol *hd,*now,*ret=NULL;
	while(top){
		if((now=ExtCP_dup(top))==NULL) goto error;
		if(ret){
			hd->next = now;
			hd = hd->next;
		}else{
			hd = ret = now;
		}
		top=top->next;
	}
	return ret;
error:
	ExtCP_free_all(ret);
	return NULL;
}

/*-----------------------------------------
    alloc & free ExtPolUN
-----------------------------------------*/
ExtPolUN *ExtPUN_new(){
	ExtPolUN *ret;
	int i;

	if((ret=(ExtPolUN*)MALLOC(sizeof(ExtPolUN)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTPOL+1,NULL);
		return NULL;
	}

	memset(ret,0,sizeof(ExtPolUN));
	for(i=0;i<4;i++)
		ret->noticeNumbers[i] = -1;
	return(ret);	
}

void ExtPUN_free(ExtPolUN *epu){
	if(epu->organization) FREE(epu->organization);
	if(epu->explicitText) FREE(epu->explicitText);
	FREE(epu);
}

ExtPolUN *ExtPUN_dup(ExtPolUN *src){
	ExtPolUN *ret=NULL;
	int i;

	if(src==NULL) return NULL;
	if((ret=ExtPUN_new())==NULL) goto error;

	for(i=0;i<4;i++)
		ret->noticeNumbers[i]=src->noticeNumbers[i];

	if(src->organization)
		if((STRDUP(ret->organization,src->organization))==NULL)
			goto error;
	if(src->explicitText)
		if((STRDUP(ret->explicitText,src->explicitText))==NULL)
			goto error;

	return ret;
error:
	ExtPUN_free(ret);
	OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTPOL+2,NULL);
	return NULL;
}

/*-----------------------------------------
    alloc & free ExtPolInfo
-----------------------------------------*/
ExtPolInfo *ExtPI_new(){
	ExtPolInfo *ret;

	if((ret=(ExtPolInfo*)MALLOC(sizeof(ExtPolInfo)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTPOL+3,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(ExtPolInfo));
	return ret;	
}

void ExtPI_free(ExtPolInfo *epi){
	if(epi==NULL) return;
	if(epi->qualifierID) FREE(epi->qualifierID);
	if(epi->qualifier){
		switch(epi->qid){
		case OBJ_PKIX_IDQT_UNOTICE:
			ExtPUN_free((ExtPolUN*)epi->qualifier); break;
		default:
			FREE(epi->qualifier); break;
		}
	}
	FREE(epi);
}

void ExtPI_free_all(ExtPolInfo *top){
	ExtPolInfo *next;
	while(top){
		next=top->next;
		ExtPI_free(top);
		top=next;
	}
}

ExtPolInfo *ExtPI_dup(ExtPolInfo *src){
	ExtPolInfo *ret=NULL;

	if(src==NULL) return NULL;
	if((ret=ExtPI_new())==NULL) goto error;
	ret->qid      = src->qid;
	ret->qual_len = src->qual_len;

	if(src->qualifierID)
		if((STRDUP(ret->qualifierID,src->qualifierID))==NULL)
			goto error;

	if(src->qualifier){
		switch(src->qid){
		case OBJ_PKIX_IDQT_UNOTICE:
			if((ret->qualifier=(unsigned char*)ExtPUN_dup((ExtPolUN*)src->qualifier))==NULL)
				goto error;
			break;
		default:
			if((STRDUP(ret->qualifier,src->qualifier))==NULL)
				goto error;
			break;
		}
	}

	return ret;
error:
	ExtPI_free(ret);
	OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTPOL+4,NULL);
	return NULL;
}

ExtPolInfo *ExtPI_dup_all(ExtPolInfo *top){
	ExtPolInfo *hd,*now,*ret=NULL;
	while(top){
		if((now=ExtPI_dup(top))==NULL) goto error;
		if(ret){
			hd->next = now;
			hd = hd->next;
		}else{
			hd = ret = now;
		}
		top=top->next;
	}
	return ret;
error:
	ExtPI_free_all(ret);
	return NULL;
}

/*-----------------------------------------
    get new ExtPolInfo
-----------------------------------------*/
ExtPolInfo *ExtPI_get_unotice(char *id, char *org, int num, char *expText){
	unsigned char tmp[32];
	ExtPolInfo *ret;
	ExtPolUN *epu;
	int i,j=0;

	if((id==NULL)||((org==NULL)&&(expText==NULL))){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTPOL+5,NULL);
		return NULL;
	}
	if((ret=ExtPI_new())==NULL) goto error;
	/* set string OID type, ex. "1.2.33.444" */
	if((STRDUP(ret->qualifierID,id))==NULL) goto error;

	/* set unotice */
	if((epu=ExtPUN_new())==NULL) goto error;
	ret->qualifier=(unsigned char*)epu;

	if(org != NULL){
		if((STRDUP(epu->organization,org))==NULL) goto error;
		epu->noticeNumbers[0] = num;
		j+=strlen(org);
	}
	if(expText != NULL){
		if((STRDUP(epu->explicitText,expText))==NULL) goto error;
		j+=strlen(expText);
	}

	if((i=str2objid(id,tmp,32))<0) goto error;
	ret->qid      = ASN1_object_2int(tmp);
	ret->qual_len = (j>>1)*3+16;

	return ret;
error:
	OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTPOL+5,NULL);
	ExtPI_free(ret);
	return NULL;
}

ExtPolInfo *ExtPI_get_cps(char *id, char *qual){
	unsigned char tmp[32];
	ExtPolInfo *ret;
	int i;

	if((id==NULL)||(qual==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTPOL+6,NULL);
		return NULL;
	}

	if((ret=ExtPI_new())==NULL) goto error;
	/* set string OID type, ex. "1.2.33.444" */
	if((STRDUP(ret->qualifierID,id))==NULL) goto error;

	if((STRDUP(ret->qualifier,qual))==NULL) goto error;

	if((i=str2objid(id,tmp,32))<0) goto error;
	ret->qid      = ASN1_object_2int(tmp);
	ret->qual_len = strlen(qual);

	return ret;
error:
	OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTPOL+6,NULL);
	ExtPI_free(ret);
	return NULL;
}

/*-----------------------------------------
    ExtCertPol to DER
-----------------------------------------*/
unsigned char *ExtCP_toDER(ExtCertPol *pol,unsigned char *buf,int *ret_len){
	unsigned char *ret,*cp,*tp,*t;
	ExtPolInfo *epi;
	int i,j,k,l;

	if(buf==NULL){
		if((i=ExtCP_estimate_der_size(pol))<=0)
			return NULL;
		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTPOL+7,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	for(i=0,tp=ret; pol ; pol=pol->next){
		/* set policyID */
		if((j=str2objid(pol->policyID,tp,32))<0) goto error;
		t=cp=tp+j;

		/* policy qualifiers OPTIONAL */
		k = 0;
		if(pol->info){
			for(epi=pol->info; epi; epi=epi->next){
				if(ExtPI_toDER(epi,t,&l)==NULL) goto error;
				k+=l; t+=l;
			}
			ASN1_set_sequence(k,cp,&k);
		}
		ASN1_set_sequence(j+k,tp,&j);
		i+=j; tp+=j;
	}
	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
    ExtPolInfo to DER
-----------------------------------------*/
int ExtPUN_DER_un(ExtPolUN *epu,unsigned char *ret,int *ret_len){
	unsigned char *cp,*ct,tmp[256]; /* <-- 256 is ok. see RFC2459 */
	int i=0,j,k,l;

	cp = ret;
	/* noticeRef NoticeReference OPTIONAL */
	if(epu->organization){
		if((i=UC_conv(UC_LOCAL_JCODE,UC_CODE_UTF8,epu->organization,strlen(epu->organization),tmp,256))<0)
			goto error;
		if(ASN1_set_utf8(tmp,ret,&i)) goto error;
		ct=cp=ret+i;

		for(j=k=0;k<4;k++){
			if(epu->noticeNumbers[k] != -1){
				ASN1_set_integer(epu->noticeNumbers[k],ct,&l);
				ct+=l; j+=l;
			}
		}
		ASN1_set_sequence(j,cp,&j);
		ASN1_set_sequence(i+j,ret,&i);
		cp = ret+i;
	}
	/* explicitText DisplayText OPTIONAL */
	if(epu->explicitText){
		if((k=UC_conv(UC_LOCAL_JCODE,UC_CODE_UTF8,epu->explicitText,strlen(epu->explicitText),tmp,256))<0)
			goto error;
		if(ASN1_set_utf8(tmp,cp,&j)) goto error;
		i+=j;
	}
	ASN1_set_sequence(i,ret,ret_len);
	return 0;
error:
	return -1;
}

unsigned char *ExtPI_toDER(ExtPolInfo *epi,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int i,j;

	if(buf==NULL){
		i = (strlen(epi->qualifierID)/2) + 2;
		i+= epi->qual_len + 4;
		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTPOL+9,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	/* set qualifierID */
	if((i=str2objid(epi->qualifierID,ret,32))<0) goto error;
	cp=ret+i;

	/* set qualifier OPTIONAL */
	if(epi->qualifier){
		switch(epi->qid){
		case OBJ_PKIX_IDQT_UNOTICE:
			if(ExtPUN_DER_un((ExtPolUN*)epi->qualifier,cp,&j)) goto error;
			break;
		case OBJ_PKIX_IDQT_CPS:
			if(ASN1_set_ia5(epi->qualifier,cp,&j)) goto error;
			break;
		default:
			memcpy(cp,epi->qualifier,epi->qual_len);
			j = epi->qual_len;
			break;
		}
		i+=j;
	}
	ASN1_set_sequence(i,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  estimate ExtGN DER size from Cert
-----------------------------------------*/
int ExtCP_estimate_der_size(ExtCertPol *ecp){
	ExtPolInfo *epi;
	int ret=8;

	if(ecp==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTPOL+10,NULL);
		return -1;
	}

	while(ecp){
		ret+=(strlen(ecp->policyID)/2) + 8;

		for(epi=ecp->info;epi;epi=epi->next){
			ret+=(strlen(epi->qualifierID)/2) + 2;
			ret+= epi->qual_len + 4;
		}
		ecp=ecp->next;
	}
	return ret;
}
