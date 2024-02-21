/* asn1_p7sign.c */
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
#include "ok_hmac.h"
#include "ok_pkcs.h"
#include "ok_tool.h"

Cert *ASN1_read_cert(unsigned char *in);
CRL *ASN1_read_crl(unsigned char *in);

/*-----------------------------------------------
  getPKCS#7 Signed-DATA from DER buffer.
-----------------------------------------------*/
PKCS7 *ASN1_read_p7env(unsigned char *der){
	unsigned char *cp;
	P7_Envelope *p7env;
	PKCS7	*ret=NULL;
	int	i,j,err=-1;

	if(der == NULL){return NULL;}
	if(*der!= 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7E,NULL);
		goto done;
	}

	cp=ASN1_next(der);
	if(ASN1_object_2int(cp)!=OBJ_P7_ENVELP){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7E,NULL);
		goto done;
	}

	if((ret=P7_new(OBJ_P7_ENVELP))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1P7E,NULL);
		goto done;
	}
	p7env = (P7_Envelope*)ret->cont;

	/* get Enveloped Data version */
	cp = ASN1_step(cp,3);
	p7env->version=j=ASN1_integer(cp,&i);
	if((j<0)||(j>2)){
		OK_set_error(ERR_ST_BADVER,ERR_LC_ASN1,ERR_PT_ASN1P7E,NULL);
		goto done;
	}

	/* get set of RecipientInfos */
	cp = ASN1_next(cp);
	if(ASN1_get_recipi(cp,p7env->recipi)) goto done;

	if((cp = ASN1_skip(cp))==NULL) goto done;
	if(ASN1_get_encCnt(cp,p7env->encCnt)) goto done;

	err=0;
done:
	if(err&&ret){ P7_free(ret); ret=NULL;}
	return ret;
}

int ASN1_get_recipi(unsigned char *in, RecipInfo *ret){
	RecipInfo *rcp;
	unsigned char *cp,*tp,*sp;
	int	clen,len,i,j,err=-1;

	len =ASN1_length((in+1),&i);
	sp = in+1+i; /* ASN1_next */

	j=0; rcp=ret;
	do{
		cp=sp;
		clen =ASN1_length((cp+1),&i);
		clen+=1+i;

		/* set version */
		cp = ASN1_next(cp);
		rcp->version = ASN1_integer(cp,&i);
		cp = ASN1_next(cp);
		
		/* get issuerAndSerialNumber */
		tp = ASN1_next(cp);
		if((cp = ASN1_skip(cp))==NULL) goto done;

		if((rcp->iss_str=ASN1_get_subject(tp,&rcp->iss_dn))==NULL) goto done;

		if((tp = ASN1_skip(tp))==NULL) goto done;
		rcp->serialNum = ASN1_integer(tp,&i);

		/* get KeyEncryptionAlgorithm */
		tp = ASN1_next(cp);
		if((cp = ASN1_skip(cp))==NULL) goto done;
		if((rcp->enc_algo=ASN1_object_2int(tp))<=0){
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1P7E+1,NULL);
			goto done;
		}

		/* get encryptedKey */
		if(ASN1_octetstring(cp,&i,&(rcp->key),&(rcp->size))) goto done;

		sp+=clen;
		j +=clen;

		if(j>=len) break;

		if((rcp=P7_recip_new())==NULL) goto done;
		rcp->next=ret->next;
		ret->next=rcp;
	}while(1);
	err=0;
done:
	if(err){P7_recip_free(ret->next); ret->next=NULL;}
	return err;
}

int ASN1_get_encCnt(unsigned char *in, EncCntInfo *ret){
	unsigned char *cp,*tp;
	int	i,err=-1;

	cp = ASN1_next(in);
	if((i=ASN1_object_2int(cp))!=OBJ_P7_DATA){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7E+2,NULL);
		return -1;
	}

	/* get data type */
	ret->type = i;
	cp = ASN1_next(cp);

	/* get contentEncryptionAlgorithmIdentifer */
	tp = ASN1_next(cp);
	if((cp = ASN1_skip(cp))==NULL) goto done;
	
	ret->enc_algo = i = ASN1_object_2int(tp);
	switch(i){
	case OBJ_CRYALGO_RC2CBC:
		tp = ASN1_step(tp,2);
		if((ret->iter=ASN1_integer(tp,&i))<0){
			if(i==0){
				OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7E+2,NULL);
				goto done;
			}
		}
		tp = ASN1_next(tp);
		if(ASN1_octetstring(tp,&i,&(ret->iv),&(ret->iv_size)))
			goto done;
		break;
	case OBJ_CRYALGO_3DESCBC:
	case OBJ_CRYALGO_DESCBC:
		tp = ASN1_next(tp);
		if(ASN1_octetstring(tp,&i,&(ret->iv),&(ret->iv_size)))
			goto done;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1P7E+2,NULL);
		goto done;
	}

	/* get encryptedContent */
	*cp |= ASN1_OCTETSTRING;
	if(ASN1_octetstring(cp,&i,&(ret->data),&(ret->size)))
		goto done;
	err=0;
done:
	return err;
}



