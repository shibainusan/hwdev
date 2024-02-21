/* ext_gn.c */
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

/*-----------------------------------------
    alloc & free General Name
-----------------------------------------*/
ExtGenNames *ExtGN_new(){
	ExtGenNames	*ret;

	if((ret=(ExtGenNames*)MALLOC(sizeof(ExtGenNames)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(ExtGenNames));
	return(ret);
}

void ExtGN_free(ExtGenNames *top){
	ExtGenNames *gn,*next;

	for(gn=top;gn!=NULL;gn=next){
		next=gn->next;
		if(gn->name){
			switch(gn->type){
			case 4:
				cert_dn_free((CertDN*)gn->name);
				FREE(gn->name);
				break;
			case 0:
				ExtGN_on_free((OtherName*)gn->name);
				break;
			default:
				FREE(gn->name);
				break;
		}}
		FREE(gn);
	}
}

ExtGenNames *ExtGN_dup(ExtGenNames *src){
	ExtGenNames	*ret;

	if(src==NULL) goto error;

	switch(src->type){
	case 1:	/* rfc822Name (IA5String) */
	case 2:	/* dNSName (IA5String) */
	case 6:	/* uniformResourceIdentifier (IA5String) */
	case 8:	/* registeredID (OBJECT IDENTIFIER) */
		if((ret=ExtGN_set_str(src->name,src->type))==NULL) goto error;
		break;
	case 4:	/* directoryName */
		if((ret=ExtGN_set_dn((CertDN*)src->name))==NULL) goto error;
		break;
	case 7:	/* iPAddress (OCTET STRING) */
		if((ret=ExtGN_set_bin(src->name,src->name_len,src->type))==NULL)
			goto error;
		break;
	case 0: /* otherName */
		if((ret=ExtGN_set_oth((OtherName*)src->name,src->name_len))==NULL)
			goto error;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_X509EXT,ERR_PT_EXTGN+1,NULL);
		goto error;
	}
	return ret;
error:
	return NULL;
}

ExtGenNames *ExtGN_dup_all(ExtGenNames *top){
	ExtGenNames *hd,*now,*ret=NULL;

	while(top){
		if((now=ExtGN_dup(top))==NULL) goto error;
		if(ret){
			hd->next=now;
			hd = hd->next;
		}else{
			ret=hd=now;
		}
		top=top->next;
	}
	return ret;
error:
	ExtGN_free(ret);
	return NULL;
}

/*-----------------------------------------
    get new Other Names
-----------------------------------------*/
OtherName *ExtGN_on_new(){
	OtherName	*ret;

	if((ret=(OtherName*)MALLOC(sizeof(OtherName)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+2,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(OtherName));
	return(ret);
}

void ExtGN_on_free(OtherName *on){
	if(on==NULL) return;
	if(on->name) FREE(on->name);
	if(on->oidc) FREE(on->oidc);
	FREE(on);
}

OtherName *ExtGN_on_dup(OtherName *src){
	OtherName	*ret;

	if(src==NULL) return NULL;
	if((ret=ExtGN_on_new())==NULL) goto error;

	if((ret->name=(unsigned char*)MALLOC(src->nlen))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+3,NULL);
		goto error;
	}
	if((STRDUP(ret->oidc,src->oidc))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTGN+3,NULL);
		goto error;
	}
	memcpy(ret->name,src->name,src->nlen);
	ret->nlen = src->nlen;
	ret->oid  = src->oid;

	return ret;
error:
	ExtGN_on_free(ret);
	return NULL;
}

/*-----------------------------------------
    get new General Names
-----------------------------------------*/
ExtGenNames *ExtGN_set_str(char *str,int type){
	ExtGenNames	*ret;

	if((ret=ExtGN_new())==NULL) goto error;
	if((STRDUP(ret->name,str))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTGN+4,NULL);
		goto error;
	}
	ret->name_len = strlen(str);
	ret->type = type;
	return ret;
error:
	ExtGN_free(ret);
	return NULL;
}

ExtGenNames *ExtGN_set_dn(CertDN *dn){
	ExtGenNames	*ret;
	int i,j,k;

	if((ret=ExtGN_new())==NULL) goto error;
	if((ret->name=(char*)MALLOC(sizeof(CertDN)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+5,NULL);
		goto error;
	}

	if(Cert_dncopy(dn,(CertDN*)ret->name)) goto error;
	for(i=j=0;i<dn->num;i++)
		if(dn->rdn[i].tag){
			k=strlen(dn->rdn[i].tag);
			if(dn->rdn[i].derform==ASN1_UTF8STRING){
				k=(k>>1)*3;
			}
			j+=k;
		}

	ret->name_len = j;
	ret->type = 4;
	return ret;
error:
	ExtGN_free(ret);
	return NULL;
}

ExtGenNames *ExtGN_set_bin(unsigned char *buf, int len, int type){
	ExtGenNames	*ret;

	if((ret=ExtGN_new())==NULL) goto error;
	if((ret->name=(char*)MALLOC(len))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+6,NULL);
		goto error;
	}
	ret->name_len = len;
	ret->type     = type;
	memcpy(ret->name,buf,len);
	return ret;
error:
	ExtGN_free(ret);
	return NULL;
}

ExtGenNames *ExtGN_set_oth(OtherName *son, int len){
	ExtGenNames	*ret;
	OtherName *on;

	if((ret=ExtGN_new())==NULL) goto error;
	if((on=ExtGN_on_new())==NULL) goto error;

	if(son->name)
		if((on->name=ASN1_dup(son->name))==NULL)
			goto error;
	if(son->oidc)
		if((STRDUP(on->oidc,son->oidc))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTGN+7,NULL);
			goto error;
		}
	on->nlen  = son->nlen;
	on->oid   = son->oid;

	ret->name     = (char*)on;
	ret->name_len = len;
	ret->type     = 0;	/* otherName */

	return ret;
error:
	ExtGN_free(ret);
	return NULL;
}

/*-----------------------------------------
    General Names to DER
-----------------------------------------*/
int ExtGN_DER_gname(ExtGenNames *now,unsigned char *ret,int *ret_len){
	int i;
	switch(now->type){
	case 1:	/* rfc822Name (IA5String) */
	case 2:	/* dNSName (IA5String) */
	case 6:	/* uniformResourceIdentifier (IA5String) */
		if(ASN1_set_ia5(now->name,ret,ret_len)) goto error;
		ASN1_set_implicit(now->type,ret);
		break;
	case 4:	/* directoryName */
		if(Cert_DER_subject((CertDN*)now->name,ret,&i)) goto error;
		ASN1_set_explicit(i,4,ret,ret_len);
		break;
	case 7:	/* iPAddress (OCTET STRING) */
		ASN1_set_octetstring(now->name_len,now->name,ret,ret_len);
		*ret = 0x87; /* implicit */
		break;
	case 8:	/* registeredID (OBJECT IDENTIFIER) */
		if((str2objid(now->name,ret,32))<0) goto error;
		*ret = 0x88; /* implicit */
		break;
	case 0: /* otherName */
		if(ExtGN_DER_othname((OtherName*)now->name,ret,ret_len)) goto error;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_X509EXT,ERR_PT_EXTGN+8,NULL);
		goto error;
	}
	return 0;
error:
	return -1;
}

int ExtGN_DER_othname(OtherName *on,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j;

	if(on->oid){
		if(ASN1_int_2object(on->oid,ret,&i)) goto error;
		cp = ret+i;
	}else{
		if((i=str2objid(on->oidc,ret,32))<0) goto error;
		cp = ret+i;
	}
	memcpy(cp,on->name,on->nlen);
	ASN1_set_explicit(on->nlen,0,cp,&j);
	i+=j;

	ASN1_set_explicit(i,0,ret,ret_len);
	return 0;
error:
	return -1;
}

unsigned char *ExtGN_toDER(ExtGenNames *top,unsigned char *buf,int *ret_len){
	ExtGenNames	*now;
	unsigned char *cp,*ret;
	int i,j=0;

	if(buf==NULL){
		if((i=ExtGN_estimate_der_size(top))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+9,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	*ret_len=0; cp=ret;
	for(now=top;now!=NULL;now=now->next){
		if(ExtGN_DER_gname(now,cp,&i)) goto error;
		cp+=i; j +=i;
	}
	ASN1_set_sequence(j,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  estimate ExtGN DER size from Cert
-----------------------------------------*/
int ExtGN_estimate_der_size(ExtGenNames *top){
	ExtGenNames *gn;
	int ret;

	if(top==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTGN+10,NULL);
		return -1;
	}
	for(ret=0,gn=top;gn;gn=gn->next){
		ret+= gn->name_len;
		switch(gn->type){
		case 4: ret += ((CertDN*)gn->name)->num*20; break;
		case 0: ret += 24; break; /* oid + explicit */
		default: ret += 10;
		}
	}
	return ret;
}


/*-----------------------------------------
  ExtSubTrees new & Free
-----------------------------------------*/
ExtSubTrees *ExtSubT_new(){
	ExtSubTrees *ret;

	if((ret=(ExtSubTrees *)MALLOC(sizeof(ExtSubTrees)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+11,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(ExtSubTrees));
	ret->maximum = -1; /* optional */
	return(ret);
}

void ExtSubT_free(ExtSubTrees *ext){
	if(ext==NULL) return;
	ExtGN_free(ext->base);
	FREE(ext);
}

void ExtSubT_free_all(ExtSubTrees *top){
	ExtSubTrees *tmp;
	while(top){
		tmp = top->next;
		ExtSubT_free(top);
		top = tmp;
	}
}

ExtSubTrees *ExtSubT_dup(ExtSubTrees *src){
	ExtSubTrees *ret=NULL;

	if(src==NULL) return NULL;

	if((ret=ExtSubT_new())==NULL) goto error;
	if(src->base)
		if((ret->base=ExtGN_dup(src->base))==NULL) goto error;

	ret->minimum = src->minimum;
	ret->maximum = src->maximum;
	return ret;
error:
	return NULL;
}

ExtSubTrees *ExtSubT_dup_all(ExtSubTrees *top){
	ExtSubTrees *hd,*now,*ret=NULL;

	while(top){
		if((now=ExtSubT_dup(top))==NULL) goto error;
		if(ret){
			hd->next=now;
			hd = hd->next;
		}else{
			ret=hd=now;
		}
		top=top->next;
	}
	return ret;
error:
	ExtSubT_free_all(ret);
	return NULL;
}

/*-----------------------------------------
    Sub Trees to DER
-----------------------------------------*/
unsigned char *ExtSubT_toDER(ExtSubTrees *top,unsigned char *buf,int *ret_len){
	ExtSubTrees	*now;
	unsigned char *cp,*t,*ret;
	int i,j,k;

	if(buf==NULL){
		if((i=ExtSubT_estimate_der_size(top))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTGN+12,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	*ret_len=0;
	cp=t=ret; j=k=0;
	for(now=top;now;now=now->next){
		if(ExtGN_DER_gname(now->base,cp,&j)) goto error;
		cp+=j;

		ASN1_set_integer(now->minimum,cp,&i); *cp = 0x80; /* implicit */
		cp+=i; j+=i;

		if(now->maximum>=0){
			ASN1_set_integer(now->maximum,cp,&i); *cp = 0x81; /* implicit */
			cp+=i; j+=i;
		}
		ASN1_set_sequence(j,t,&j);
		t+=j; k+=j; cp=t;
	}
	ASN1_set_sequence(k,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  estimate ExtSubT DER size from Cert
-----------------------------------------*/
int ExtSubT_estimate_der_size(ExtSubTrees *top){
	ExtSubTrees *st;
	int i,ret;

	if(top==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTGN+13,NULL);
		return -1;
	}
	for(ret=0,st=top;st;st=st->next){
		if((i = ExtGN_estimate_der_size(st->base)) < 0) return -1;
		ret+= i + 6; /* name & minimum */
		ret+= (st->maximum >=0)?(6):(0);
	}
	return ret;
}

/*-----------------------------------------
    get SubTrees
-----------------------------------------*/
ExtSubTrees *ExtSubT_get_tree(ExtGenNames *base, int min, int max){
	ExtSubTrees *ret;

	if((ret=ExtSubT_new())==NULL) return NULL;
	ret->base = base;
	ret->minimum = min;
	ret->maximum = max;

	return ret;
}
