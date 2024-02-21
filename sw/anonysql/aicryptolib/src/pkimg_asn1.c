/* pkimg_asn1.c */
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

#include "ok_asn1.h"
#include "ok_cmp.h"

/*-----------------------------------------
  ASN.1 read PKI message.
-----------------------------------------*/
PKIMessage *ASN1_read_pkimsg(unsigned char *der){
	PKIMessage *ret=NULL;
	unsigned char *cp;
	int i;

	if(der==NULL) goto error;

	if(*der!=0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_CMP,ERR_PT_PKIMG_ASN,NULL);
		goto error;
	}

	if((ret=PKImsg_new())==NULL) goto error;

	/* PKIHeader */
	cp = ASN1_next(der);
	if((ret->header=ASN1_read_pkihead(cp))==NULL) goto error;

	/* PKIBody */
	cp = ASN1_skip(cp);
	if((ret->body=ASN1_read_pkibody(cp))==NULL) goto error;

	/* PKIProtection (BITSTRING) OPTIONAL */
	cp = ASN1_skip(cp);
	if(*cp==0xa0){
		cp = ASN1_next(cp); /* skip explicit */
		if(ASN1_bitstring(cp,&i,&ret->protection,&ret->plen,&i)) 
			goto error;
		cp = ASN1_next(cp);
	}

	/* SEQ SIZE (1..) OF Certificate OPTIONAL */
	if(*cp==0xa1){
		cp = ASN1_next(cp); /* skip explicit */
		if((ret->extraCerts=asn1_seq_certlist(cp))==NULL)
			goto error;
	}
	return ret;
error:
	PKImsg_free(ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 read certlist.
-----------------------------------------*/
CertList *asn1_seq_certlist(unsigned char *in){
	CertList *ret=NULL,*cl;
	unsigned char *cp;
	int i,j,len;

	len = ASN1_length(&in[1],&j);
	cp = ASN1_next(in);
	for(i=0;i<len;){
		i+= ASN1_length(&cp[1],&j);
		i+= 1+j;

		if((cl=Certlist_new())==NULL) goto error;
		if(ret==NULL){
			ret = cl;
		}else{
			cl->next = ret;
			ret = cl;
		}
		if((ret->cert=ASN1_read_cert(cp))==NULL) goto error;
		if((ret->cert->der=ASN1_dup(cp))==NULL) goto error;
		cp = ASN1_skip(cp);
	}
	return ret;
error:
	Certlist_free_all(ret);
	return NULL;
}

/*-----------------------------------------
  Get pki message DER.
-----------------------------------------*/
unsigned char *PKImsg_toDER(PKIMessage *pki,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=PKImsg_estimate_der_size(pki))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_CMP,ERR_PT_PKIMG_ASN+2,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if(PKIhead_toDER(pki->header,ret,&j)==NULL) goto error;
	cp=ret+j;

	if(PKIbody_toDER(pki->body,cp,&i)==NULL) goto error;
	cp+=i; j+=i;

	if(pki->protection){ /* explicit [0] OPTIONAL */
		ASN1_set_bitstring(0,pki->plen,pki->protection,cp,&i);
		ASN1_set_explicit (i,0,cp,&i);
		cp+=i; j+=i;
	}
	if(pki->extraCerts){ /* explicit [1] OPTIONAL */
		if(Certlist_DER_data(pki->extraCerts,cp,&i)) goto error;
		ASN1_set_explicit (i,1,cp,&i);
		j+=i;
	}

	ASN1_set_sequence(j,ret,ret_len);
	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  Get certlist DER.
-----------------------------------------*/
int Certlist_DER_data(CertList *cl,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,k;

	i=j=*ret_len=0;
	cp = ret;
	while(cl){
		if(cl->cert){
			if(cl->cert->der==NULL){
				OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIMG_ASN+4,NULL);
				return -1;
			}

			k = ASN1_length(&cl->cert->der[1],&j);
			k+= 1+j; i+= k;

			memcpy(cp,cl->cert->der,k);
			cp+=k;
		}
		cl=cl->next;
	}

	if(i){
		ASN1_set_sequence(i,ret,ret_len);
	}
	return 0;
}

/*-----------------------------------------
  estimate PKIMessage DER size.
-----------------------------------------*/
int PKImsg_estimate_der_size(PKIMessage *pki){
	CertList *cl;
	int sz,i;

	if((sz=i=PKIhead_estimate_der_size(pki->header))<=0) goto error;

	if((i=PKIbody_estimate_der_size(pki->body))<=0) goto error;
	sz+=i;

	if(pki->protection){ sz+=pki->plen + 4;}

	if(pki->extraCerts){
		cl=pki->extraCerts;
		while(cl){
			if(cl->cert){
				if(cl->cert->der==NULL){
					OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_CMP,ERR_PT_PKIMG_ASN+5,NULL);
					goto error;
				}
				sz+=ASN1_length(&cl->cert->der[1],&i);
				sz+=1+i;
			}
			cl=cl->next;
		}
		sz+=4;
	}

	return sz;
error:
	return -1;
}

