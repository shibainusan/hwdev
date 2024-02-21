/* asn1_p12.c */
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
#include "ok_pkcs.h"
#include "ok_tool.h"

/*-----------------------------------------------
  Read PKCS#12 DER
-----------------------------------------------*/
PKCS12 *ASN1_read_p12(unsigned char *in){
	unsigned char *safe=NULL,*mac=NULL,*cp;
	PKCS12 *ret;
	int i,err=-1;

	if((ret=P12_new())==NULL)
		return NULL;

	/* PKCS#12 version check */
	cp = ASN1_next(in);
	if((ret->version=ASN1_integer(cp,&i))!=3){
		OK_set_error(ERR_ST_BADVER,ERR_LC_ASN1,ERR_PT_ASN1P12,NULL);
		goto done;
	}

	cp = ASN1_next(cp);
	if((safe=ASN1_get_p7data(cp,&i))==NULL) goto done;

	if((mac = ASN1_skip(cp))==NULL) goto done;

	/* check password */
	if(P12_verify_mac("Input PKCS#12 Password: ",mac,safe)){
		printf("MAC Verify Error -- password missing.\n");
		goto done;
	}

	if(ASN1_authsafe(ret,safe)) goto done;

	err=0;
done:
	if(safe) FREE(safe);
	if(err&&ret){P12_free(ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------------
  PKCS#12 File Read (AuthSafes)
-----------------------------------------------*/
int ASN1_authsafe(PKCS12 *p12,unsigned char *safe){
	unsigned char *cp,*t,*p7c[8];
	P12_Baggage *bag;
	int i,j,k,l,len,bgk[8],err=-1;

	/* microsoft PKCS#12 is KeyBag first and CertBag last.
	 * but netscape old type is CertBag first and KeyBag last
	 */
	len= ASN1_tlen(safe);
	cp = ASN1_next(safe);

	/* netscape has infinity length !! X( */
	if(len==0){
		if(ASN1_skip_(safe,&i)==NULL) goto done;
		len = i - 4;
	}

	/* SafeBag ::= SEQUENCE { */
	memset(p7c,0,sizeof(char*)*8);
	for(k=j=0;(k<len)&&(j<8);j++){
		t  = ASN1_next(cp);

		switch(bgk[j]=ASN1_object_2int(t)){
		case OBJ_P7_ENCRYPTED: /* pkcs7 encrypted certificate */
			if((p7c[j]=ASN1_get_p7enc(cp,&i))==NULL) goto done;
			break;
		case OBJ_P7_DATA: /* pkcs8 encrypted */
			if((p7c[j]=ASN1_get_p7data(cp,&i))==NULL) goto done;
			break;
		default:
			OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+1,NULL);
			goto done;
		}

		if((cp=ASN1_skip_(cp,&i))==NULL) goto done;
		k+=i;
	}

	for(i=0;i<j;i++){
		switch(bgk[i]){
		case OBJ_P7_ENCRYPTED: /* get certificate */
			len= ASN1_tlen(p7c[i]);
			cp = ASN1_next(p7c[i]);

			for(k=0;k<len;){
				t = ASN1_next(cp);
				switch(ASN1_object_2int(t)){
				case OBJ_P12v1Bag_CERT:
					if((bag=(P12_Baggage*)ASN1_get_certbag(cp))==NULL) goto done;
					break;
				case OBJ_P12v1Bag_CRL:
					if((bag=(P12_Baggage*)ASN1_get_crlbag(cp))==NULL) goto done;
					break;
				case OBJ_P12v1Bag_KEY:
					if((bag=(P12_Baggage*)ASN1_get_keybag(cp))==NULL) goto done;
					break;
				case OBJ_P12v1Bag_PKCS8:
					if((bag=(P12_Baggage*)ASN1_get_p8bag(cp))==NULL) goto done;
					break;
				default: /* not cert bag & crl bag */
					OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+1,NULL);
					goto done;
				}
				P12_add_bag(p12,bag);
				if((cp=ASN1_skip_(cp,&l))==NULL) goto done;
				k+=l;
			}
			break;
		case OBJ_P7_DATA:	/* get private key */
			if((bag=(P12_Baggage*)ASN1_get_p8bag(ASN1_next(p7c[i])))==NULL)
				goto done;
			P12_add_bag(p12,bag);
			break;
		}
	}

	err=0;
done:
	for(i=0;i<j;i++) FREE(p7c[i]);
	return err;
}

/*-----------------------------------------
  PKCS#12 get x509 certificate
  in ... DER top of pkcs12_CertBag
-----------------------------------------*/
P12_CertBag *ASN1_get_certbag(unsigned char *in){
	unsigned char *cp,*buf=NULL;
	P12_CertBag	*ret=NULL;
	int i,j;

	cp = ASN1_next(in);
	if(ASN1_object_2int(cp)!=OBJ_P12v1Bag_CERT){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+2,NULL);
		goto error;
	}

	cp = ASN1_step(cp,3);
	if(ASN1_object_2int(cp)!=OBJ_P9_X509CERT){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+2,NULL);
		goto error;
	}

	if((ret=P12_Cert_new())==NULL) goto error;
 
	cp = ASN1_step(cp,2);
	if(ASN1_octetstring(cp,&i,&buf,&j)) goto error;

	if((ret->cert=ASN1_read_cert(buf))==NULL) goto error;

	cp = ASN1_next(cp);
	if(ASN1_get_fri_loc(cp,&(ret->friendlyName),ret->localKeyID))
		goto error;

	/* buf is used by ret->der
	 * so cannot FREE it.
	 */
	return ret;
error:
	if(ret){
		if((!ret->cert)&&buf) FREE(buf);
		P12Bag_free((P12_Baggage*)ret);
	}
	return NULL;
}

/*-----------------------------------------
  PKCS#12 get x509 CRL
  in ... DER top of pkcs12_CRLBag
-----------------------------------------*/
P12_CRLBag *ASN1_get_crlbag(unsigned char *in){
	unsigned char *cp,*buf=NULL;
	P12_CRLBag	*ret=NULL;
	int i,j;

	cp = ASN1_next(in);
	if(ASN1_object_2int(cp)!=OBJ_P12v1Bag_CRL){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+3,NULL);
		goto error;
	}

	cp = ASN1_step(cp,3);
	if(ASN1_object_2int(cp)!=OBJ_P9_X509CRL){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+3,NULL);
		goto error;
	}

	if((ret=P12_CRL_new())==NULL) goto error;
 
	cp = ASN1_step(cp,2);
	if(ASN1_octetstring(cp,&i,&buf,&j)) goto error;

	if((ret->crl=ASN1_read_crl(buf))==NULL) goto error;

	cp = ASN1_next(cp);
	if(ASN1_get_fri_loc(cp,&(ret->friendlyName),ret->localKeyID))
		goto error;

	/* buf is used by ret->der
	 * so cannot FREE it.
	 */
	return ret;
error:
	if(ret){
		if((!ret->crl)&&buf) FREE(buf);
		P12Bag_free((P12_Baggage*)ret);
	}
	return NULL;
}

/*-----------------------------------------
  PKCS#12 get private key.
  in ... DER top of pkcs12_keyBag
-----------------------------------------*/
P12_KeyBag *ASN1_get_keybag(unsigned char *in){
	unsigned char *cp,*buf=NULL;
	P12_KeyBag	*ret=NULL;
	int i,j,k;

	cp = ASN1_next(in);
	if(ASN1_object_2int(cp)!=OBJ_P12v1Bag_KEY){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+4,NULL);
		goto error;
	}

	if((ret=P12_Key_new())==NULL) goto error;
	cp = ASN1_step(cp,3);

	/* get integer -- ? */
	/* i = ASN1_integer(cp); */
	cp = ASN1_step(cp,2);

	/* algorithm identifier */
	k=ASN1_object_2int(cp);

	cp = ASN1_step(cp,2);
	if(ASN1_octetstring(cp,&i,&buf,&j)) goto error;

	switch(k){
	case OBJ_CRYPT_RSA:
		if((ret->key=(Key*)ASN1_read_rsaprv(buf))==NULL)
			goto error;
		break;
	case OBJ_CRYPT_DSA:
		/* not supported now */
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1P12+4,NULL);
		goto error;
	}

	cp = ASN1_next(cp);
	if(ASN1_get_fri_loc(cp,&(ret->friendlyName),ret->localKeyID))
		goto error;

	/* buf is used by ret->der
	 * so cannot FREE it.
	 */
	return ret;
error:
	if(ret){
		if((!ret->key)&&buf) FREE(buf);
		P12Bag_free((P12_Baggage*)ret);
	}
	return NULL;
}

/*-----------------------------------------
  PKCS#12 get private key.
  in ... DER top of pkcs12_keyBag
-----------------------------------------*/
P12_KeyBag *ASN1_get_p8bag(unsigned char *in){
	unsigned char *cp,*buf=NULL;
	P12_KeyBag	*ret=NULL;
	int j,err=-1;

	cp = ASN1_next(in);
	if(ASN1_object_2int(cp)!=OBJ_P12v1Bag_PKCS8){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+5,NULL);
		goto done;
	}

	cp=ASN1_step(cp,2);
	if((buf=ASN1_p8_decrypted(cp,&j))==NULL){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+5,NULL);
		goto done;
	}

	if((ret=P12_Key_new())==NULL) goto done;
	if((ret->key=ASN1_p8_prvkey(buf))==NULL) goto done;

	if((cp = ASN1_skip(cp))==NULL) goto done;
	if(ASN1_get_fri_loc(cp,&(ret->friendlyName),ret->localKeyID))
		goto done;

	err=0;
done:
	if(buf) FREE(buf);
	if(err&&ret){P12Bag_free((P12_Baggage*)ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------
  PKCS#12 get friendlyName & localIDkey
-----------------------------------------*/
int ASN1_get_fri_loc(unsigned char *in,char **frname,unsigned char *id){
	unsigned char *cp,*sq;
	int	i,k,len;

	/* bagAttributes SET OF PKCS12Attribute OPTIONAL */
	if(*in != 0x31){
		/* there is not any attribute value */
		return 0;
	}

	len=ASN1_tlen(in);
	sq =ASN1_next(in);

	for(i=0;i<len;){
		cp = ASN1_next(sq);

		switch(ASN1_object_2int(cp)){
		case OBJ_P9_Friendly:
			cp = ASN1_step(cp,2);
			*frname = ASN1_bmp(cp,&k);
			break;
		case OBJ_P9_LocalKEY:
			cp = ASN1_step(cp,2);
			cp +=2;
			memcpy(id,cp,4);
			break;
		case 0: /* unknown attribute ... */
			/* actually, there would be some attributes exist
			 * other than Friendly Name and LocalKey ID.
			 *
			 * but here, they are just ignored...
			 */
			OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_ASN1,ERR_PT_ASN1P12+6,NULL);
			break;
		default:
			OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1P12+6,NULL);
			return -1;
		}

		if((sq=ASN1_skip_(sq,&k))==NULL) return -1;
		i+=k;
	}
	return 0;
}
