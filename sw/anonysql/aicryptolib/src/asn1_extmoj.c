/* asn1_extmoj.c */
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
#include "ok_x509ext.h"
#include "ok_tool.h"

#include "ok_uconv.h"

/*-----------------------------------------
  CertExt MOJ-corpinfo
-----------------------------------------*/
CertExt *ASN1_ext_mojcorpinfo(unsigned char *in){
	CE_MOJCoInfo *ret;
	unsigned char *cp,ct,c,fg = OK_get_ext_flag(AC_EXTF_LC_ASN1);
	int i,j,len;

	if((ret=(CE_MOJCoInfo*)CertExt_new(OBJ_MOJ_RegCoInfo))==NULL) return NULL;

	if((ret->der = ASN1_dup(in))==NULL) goto error;

	len= ASN1_tlen(in);
	in = ASN1_next(in);
	ct=0xa0;
	for(i=0,c=0;(c<7)&&(i<len);c++){
		if(*in==(ct+c)){ /* explicit i */
			cp = ASN1_next(in);
			if(fg & AC_EXTF_ST_MOJCO){
				/* oops, UTF8STRING contains S-JIS string !!
				 * this operation breaks DER binary string, but I don't care of it.
				 * because this mode is used by PKIX CMP decoding and DER binary will be
				 * deleted.
				 */
				*cp = ASN1_T61STRING;
			}
			if((ret->corpInfo[c]=asn1_get_str(cp,&j))==NULL) goto error;
			if((in=ASN1_skip_(in,&j))==NULL) goto error;
			i+=j;
		}
	}

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  CertExt (MOJ Attribute)
-----------------------------------------*/
/* moj attribute (not cert extension) */
AttrTAV *ASN1_ext_timelimit(unsigned char *in){
	CE_Com *ret;
	int i,j;

	if((ret=(CE_Com*)CertExt_new(OBJ_MOJ_TimeLimit))==NULL) return NULL;
	if((ret->der = ASN1_dup(in))==NULL) goto error;

	if(ASN1_octetstring(in,&i,&ret->comment,&j)) goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* moj attribute (not cert extension) */
AttrTAV *ASN1_ext_suspcode(unsigned char *in){
	CE_MOJSuspCode *ret;
	unsigned char *tmp;
	int i;

	if((ret=(CE_MOJSuspCode*)CertExt_new(OBJ_MOJ_SuspCode))==NULL) return NULL;
	if((ret->der = ASN1_dup(in))==NULL) goto error;

	/* read DER */
	in = ASN1_next(in);
	ret->hash_algo = ASN1_object_2int(ASN1_next(in));

	in = ASN1_skip(in);
	if(ASN1_octetstring(in,&i,&tmp,&ret->hlen)) goto error;
	memcpy(ret->hash,tmp,ret->hlen);
	FREE(tmp);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* moj attribute (not cert extension) */
int asn1_get_negokey(unsigned char *in, NegoKey *ret){
	in = ASN1_next(in);
	if((ret->symm_algo = ASN1_object_2int(ASN1_next(in)))<0) goto error;
	in = ASN1_skip(in);

	if((ret->pub_algo = ASN1_object_2int(ASN1_next(in)))<0) goto error;
	in = ASN1_skip(in);

	if((ret->hash_algo = ASN1_object_2int(ASN1_next(in)))<0) goto error;
	return 0;
error:
	return -1;
}

AttrTAV *ASN1_ext_mojgenmreq(unsigned char *in){
	CE_MOJGenmReq *ret;
	int i,j,k,len;

	if((ret=(CE_MOJGenmReq*)CertExt_new(OBJ_MOJ_GenmReq))==NULL) return NULL;
	if((ret->der = ASN1_dup(in))==NULL) goto error;

	/* read DER */
	len= ASN1_tlen(in);
	in = ASN1_next(in);

	for(i=j=0;(i<len)&&(j<4);j++){
		if(asn1_get_negokey(in,&ret->nego[j])) goto error;
		ret->nego_num = j+1;
		
		if((in = ASN1_skip_(in,&k))==NULL) break;
		i+=k;
	}
	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* moj attribute (not cert extension) */
AttrTAV *ASN1_ext_mojgenpres(unsigned char *in){
	CE_MOJGenpRes *ret;
	unsigned char *cp;
	int i,j,k,len;

	if((ret=(CE_MOJGenpRes*)CertExt_new(OBJ_MOJ_GenpRes))==NULL) return NULL;
	if((ret->der = ASN1_dup(in))==NULL) goto error;

	/* read DER */
	in = ASN1_next(in);

	cp = ASN1_next(in);
	if((ret->pki_status=ASN1_integer(cp,&i))<0) goto error;
	in = ASN1_skip(in);

	/* SEQENCE OF NEGOKEY OPTIONAL */
	if((*in==0x30)&&(in[1])){
		len= ASN1_tlen(in);
		in = ASN1_next(in);

		for(i=j=0;(i<len)&&(j<4);j++){
			if(asn1_get_negokey(in,&ret->nego[j])) goto error;
			ret->nego_num = j+1;
		
			if((in = ASN1_skip_(in,&k))==NULL) break;
			i+=k;
		}
	}
	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* moj attribute (not cert extension) */
AttrTAV *ASN1_ext_mojgenspreq(unsigned char *in){
	CE_MOJGenSpReq *ret;
	unsigned char *cp,*tmp;
	int i,j,k;

	if((ret=(CE_MOJGenSpReq*)CertExt_new(OBJ_MOJ_GenSpReq))==NULL) return NULL;
	if((ret->der = ASN1_dup(in))==NULL) goto error;

	/* read DER */
	in = ASN1_next(in);
	/* CertTemplate */
	cp = ASN1_next(in);
	if(*cp==0x81){
		if((ret->snum_der=ASN1_dup(cp))==NULL) goto error;
		cp = ASN1_next(cp); ret->snum_der[0] = ASN1_INTEGER;
	}
	if(*cp==0xa3){
		cp = ASN1_next(cp);
		if((tmp=ASN1_get_subject(cp,&(ret->issuer_dn)))==NULL) goto error;
		FREE(tmp);
	}
	in = ASN1_skip(in);

	/* reason flag */
	if(ASN1_bitstring(in,&i,&tmp,&j,&k)) goto error;
	in = ASN1_next(in);
	ret->revReason[0] = tmp[0];
	FREE(tmp);
	/* suspentionReasonCode */
	if((ret->suspReason=ASN1_integer(in,&i))<0) goto error;
	in = ASN1_next(in);

	/* suspensionDetail */
	in = ASN1_next(in);

	if(*in != 0xa3) goto error;
	if((ret->keyAlg = ASN1_object_2int(ASN1_next(in)))<0) goto error;
	in = ASN1_skip(in);

	if(ASN1_bitstring(in,&i,&ret->encValue,&ret->enc_len,&k)) goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* moj attribute (not cert extension) */
AttrTAV *ASN1_ext_mojgenspres(unsigned char *in){
	CE_MOJGenSpRes *ret;
	unsigned char *cp;
	char *tmp;
	int i;

	if((ret=(CE_MOJGenSpRes*)CertExt_new(OBJ_MOJ_GenSpRes))==NULL) return NULL;
	if((ret->der = ASN1_dup(in))==NULL) goto error;

	/* read DER */
	in = ASN1_next(in);
	/* PKIStatus */
	cp = ASN1_next(in);
	if((ret->status=ASN1_integer(cp,&i))<0) goto error;
	in = ASN1_skip(in);
	/* CertID */
	in = ASN1_next(in);
	if(*in==0xa4){
		cp = ASN1_next(in);
		if((tmp=ASN1_get_subject(cp,&(ret->issuer_dn)))==NULL) goto error;
		FREE(tmp);
	}
	in = ASN1_skip(in);

	if((ret->snum_der=ASN1_dup(in))==NULL) goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

