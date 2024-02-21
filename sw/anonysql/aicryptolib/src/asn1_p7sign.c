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
PKCS7 *ASN1_read_p7s(unsigned char *der){
	unsigned char *ct,*cp,*t;
	Cert	*cert;
	CRL		*crl;
	PKCS7	*ret;
	P7_Signed *p7sig;
	int	i,j,len,clen,err=-1;

	if(der == NULL){return NULL;}
	if(*der!= 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
		return NULL;
	}

	cp=ASN1_next(der);
	if(ASN1_object_2int(cp)!=OBJ_P7_SIGNED){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
		return NULL;
	}

	if((ret=P7_new(OBJ_P7_SIGNED))==NULL) goto done;

	/* ret->der = der; -- content might be big. so it's not used */
	p7sig = (P7_Signed*)ret->cont;

	/* get Signed Data version */
	cp = ASN1_step(cp,3);
	p7sig->version = ASN1_integer(cp,&i);
	if(p7sig->version!=1){
		OK_set_error(ERR_ST_BADVER,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
		goto done;
	}

	/* get Digest Algorithm */
	cp = ASN1_next(cp);
	if(cp[1]){ /* digest Algorithm isn't blank */
		cp = ASN1_step(cp,2);
		if((p7sig->digest_algo=ASN1_object_2int(cp))<=0){
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
			goto done;
		}
		cp = ASN1_next(cp);
	}
	cp = ASN1_next(cp);

	/* content Info */
	ct = ASN1_next(cp);
	if(ASN1_object_2int(ct)!=OBJ_P7_DATA){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
		goto done;
	}

	ct = ASN1_next(ct);
	t  = ASN1_next(ct);
	if((cp = ASN1_skip(cp))==NULL) goto done;
	/* microsoft P7b-output doesn't have NULL tag after object-identifier.
	 * moreover, next tag is usually cont[0]. so I need to check 2 tag points.
	 */
	if((*ct==0xa0)&&(*t!=0x30)){
		ct = ASN1_next(ct);
		/* in many case, this octetstring have Infinity length
		 * and it might be structure.
		 */
		if(ASN1_octetstring(ct,&i,&(p7sig->content),&(p7sig->cnt_size)))
			goto done;
	}

	/* [0] Read Certificates OPTIONAL */
	if(*cp==0xa0){
		if(cp[1]==0x80) /* Infinity */
			len =0x7fff;
		else
			len =ASN1_length(&cp[1],&i);

		ct = ASN1_next(cp);
		if((cp = ASN1_skip(cp))==NULL) goto done;

		for(j=0;j<len;j+=clen){
			if((cert=ASN1_read_cert(ct))==NULL) break;

			clen =ASN1_length((ct+1),&i);
			clen+=i+1;

			if((cert->der=(unsigned char*)MALLOC(clen+4))==NULL){
				OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
				goto done;
			}
			memcpy(cert->der,ct,clen);

			if(P12_add_cert((PKCS12*)ret,cert,NULL,0xff)) goto done;
			ct  +=clen;
		}
	}

	/* [1] Read CRL OPTIONAL */
	if(*cp==0xa1){
		len =ASN1_length((++cp),&i);
		ct = cp+i;
		cp+= len+i;

		for(j=0;j<len;j+=clen){
			if((crl =ASN1_read_crl(ct))==NULL) break;

			clen =ASN1_length((ct+1),&i);
			clen+=i+1;

			if((crl->der=(unsigned char*)MALLOC(clen+4))==NULL){
				OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1P7S,NULL);
				goto done;
			}
			memcpy(crl->der,ct,clen);

			if(P12_add_crl((PKCS12*)ret,crl,NULL,0xff)) goto done;
			ct  +=clen;
		}  
	}

	/* Get set of signerInfo */
	if(cp[1]){/* signerInfos isn't blank */
		if(ASN1_get_signerInfo(cp,p7sig->signer))
			goto done;
	}
	err=0;
done:
	if(err&&ret){P7_free(ret); ret=NULL;}
	return ret;
}

int ASN1_get_signerInfo(unsigned char *in, SignerInfo *ret){
	SignerInfo *sig;
	unsigned char *cp,*tp,*sp;
	int	clen,len,i,j,k,err=-1;

	len =ASN1_length((in+1),&i);
	sp = in+1+i; /* ASN1_next */

	j=0; sig=ret;
	do{
		clen =ASN1_length((sp+1),&i);
		clen+=1+i;

		/* get version */
		cp = ASN1_next(sp);
		if((sig->version=ASN1_integer(cp,&i)) != 1){
			OK_set_error(ERR_ST_BADVER,ERR_LC_ASN1,ERR_PT_ASN1P7S+1,NULL);
			goto done;
		}
		cp = ASN1_next(cp);

		/* get issuerAndSerialNumber */
		tp = ASN1_next(cp);
		if((cp = ASN1_skip(cp))==NULL) goto done;

		if((sig->iss_str=ASN1_get_subject(tp,&sig->iss_dn))==NULL) goto done;

		if((tp = ASN1_skip(tp))==NULL) goto done;
		sig->serialNum = ASN1_integer(tp,&i);

		/* get Digest Algorithm */
		tp = ASN1_next(cp);
		if((cp = ASN1_skip(cp))==NULL) goto done;
		if((sig->digest_algo=ASN1_object_2int(tp))<=0){
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1P7S+1,NULL);
			goto done;
		}
		/* get authenticatedAttribute (optional) */
		if(*cp==0xa0){
			if((sig->auth=ASN1_get_authatt(cp))==NULL) goto done;
			if((cp = ASN1_skip(cp))==NULL) goto done;
		}

		/* get digestEncryptionAlgorithmIdentifer */
		tp = ASN1_next(cp);
		if((cp = ASN1_skip(cp))==NULL) goto done;
		if((sig->enc_algo=ASN1_object_2int(tp))<=0){
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1P7S+1,NULL);
			goto done;
		}

		/* get encryptedDigest */
		if(ASN1_octetstring(cp,&k,&(sig->signature),&(sig->sig_size)))
			goto done;
		cp = ASN1_next(cp);

		/* get unauthenticatedAttribute (optional) */
		if(*cp==0xa1){
			if((sig->unauth=ASN1_get_authatt(cp))==NULL)
				goto done;
		}

		sp+=clen;
		j +=clen;

		if(j>=len)	break;

		if((sig=P7_signer_new())==NULL) goto done;
		sig->next=ret->next;
		ret->next=sig;
		memset(sig,0,sizeof(SignerInfo));

	}while(1);
	err=0;
done:
	if(err){P7_signer_free(ret->next); ret->next=NULL;}
	return err;
}

AuthAtt *ASN1_get_authatt(unsigned char *in){
	AuthAtt *ret,*att;
	unsigned char *sp;
	int	clen,len,i,j,err=-1;

	len =ASN1_length((in+1),&i);
	sp = in+1+i; /* ASN1_next */

	/* be careful!! -- these AuthenticatedAttributes might be
	 * digested later. therefore, order must be same as file order.
	 */
	j=0; ret=att=NULL;
	do{
		clen =ASN1_length((sp+1),&i);
		clen+=1+i;
		if(ret){
			if((att->next=P7_authatt_new())==NULL) goto done;
			att = att->next;
		}else{
			if((att=ret=P7_authatt_new())==NULL) goto done;
		}

		/* copy data */
		att->der_size = clen;
		if((att->der=(unsigned char*)MALLOC(clen))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1P7S+2,NULL);
			goto done;
		}
		memcpy(att->der,sp,clen);

		sp+=clen;
		j +=clen;
	}while(j<len);

	err=0;
done:
	if(err&&ret){P7_authatt_free(ret); ret=NULL;}
	return ret;
}
