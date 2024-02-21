/* asn1_cert.c */
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
#include <string.h>
#include <stdlib.h>
#if defined(__WINDOWS__) && defined(_DEBUG)
#include <crtdbg.h>
#endif

#include "ok_asn1.h"
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_x509.h"
#include "ok_tool.h"
#include "ok_uconv.h"


/*-----------------------------------------
  Encode digest (asn1 is Certificate top)
-----------------------------------------*/
int ASN1_do_digest(int type,unsigned char *der,unsigned char *ret,int *ret_len){
	int len;

	if(ASN1_skip_(der,&len)==NULL) return -1;
	if(OK_do_digest(type,der,len,ret,ret_len)==NULL) return -1;

	return 0;
}

/*-----------------------------------------
  verify signature with DER data
-----------------------------------------*/
int ASN1_vfy_sig(Key *pub, unsigned char *der, unsigned char *sig, int sig_algo){
	unsigned char digest[32];
	int   dlen;

	if(ASN1_do_digest(sig_algo,der,digest,&dlen)) return -1;

	return OK_do_verify(pub,digest,sig,sig_algo);
}

/*-----------------------------------------
  Get public key from cert DER
-----------------------------------------*/
int asn1_get_algoid(unsigned char *in, void **param){
	int ret=-1;

	in = ASN1_next(in);
	ret = ASN1_object_2int(in);

	switch(ret){
	case OBJ_CRYPT_DSA:
		in = ASN1_next(in);
		if((*param = (void*)ASN1_read_dsaparam(in,0))==NULL) goto error;
		if((((DSAParam*)*param)->der=ASN1_dup(in))==NULL) goto error;
		break;
	case OBJ_CRYPT_ECDSA:
		in = ASN1_next(in);
		if((*param = (void*)ASN1_read_ecparam(in))==NULL) goto error;
		if((((ECParam*)*param)->der=ASN1_dup(in))==NULL) goto error;
		break;
	default:
		*param = NULL;
		break;
	}
	return ret;
error:
	if((*param)&&(ret==OBJ_CRYPT_DSA)) DSAPm_free((DSAParam*)*param);
	if((*param)&&(ret==OBJ_CRYPT_ECDSA)) ECPm_free((ECParam*)*param);
	return -1;
}

Key *ASN1_get_pubkey(unsigned char *in){
	unsigned char *cp;
	int	i,len,err=-1;
	Pubkey_ECDSA *ek=NULL;	
	Key	*ret=NULL;
	void *pm=NULL;

	/*  TOP sequence tag pointer is in */
	cp = ASN1_next(in);

	i  = asn1_get_algoid(cp,(void**)&pm);
	cp = ASN1_skip(cp);

	if((*cp&0x1f)!=ASN1_BITSTRING){
		OK_set_error(ERR_ST_ASN_NOTBITSTR,ERR_LC_ASN1,ERR_PT_ASN1CERT+1,NULL);
		goto done;
	}

	switch(i){
	case OBJ_CRYPT_RSA:
		/* if key type is RSA PUBLIC KEY */
		if((ret=(Key*)RSApubkey_new())==NULL) goto done;

		len = ASN1_length((++cp),&i);

		/* set public module -- n */
		cp+=(i+1);/* because bitstring */
		cp = ASN1_next(cp);

		if(ASN1_int2LNm(cp,((Pubkey_RSA*)ret)->n,&i)) goto done;

		/* set public key -- e */
		cp = ASN1_next(cp);
		if(ASN1_int2LNm(cp,((Pubkey_RSA*)ret)->e,&i)) goto done;

		ret->size = LN_now_byte(((Pubkey_RSA*)ret)->n);
		err=0;
		break;

	case OBJ_CRYPT_DSA:
		/* if key type is DSA PUBLIC KEY */
		len = ASN1_length((++cp),&i);

		/* set public module -- w */
		cp+=(i+1);/* because bitstring */

		if((ret=(Key*)DSApubkey_new())==NULL) goto done;

		if((((Pubkey_DSA*)ret)->pm=(DSAParam*)pm)==NULL) goto done;
		if(ASN1_int2LNm(cp,((Pubkey_DSA*)ret)->w,&i)) goto done;

		ret->size = LN_now_byte(((Pubkey_DSA*)ret)->w);
		err=0;
		break;

	case OBJ_CRYPT_ECDSA:
		/* if key type is ECDSA PUBLIC KEY */
		len = ASN1_length((++cp),&i);

		/* set public module -- w */
		cp+=(i+1);/* because bitstring */

		if((ek=ECDSApubkey_new())==NULL) goto done;
		ret=(Key*)ek;

		if((ek->E=(ECParam*)pm)==NULL) goto done;
		if( ek->W) ECp_free(ek->W);
		if((ek->W=ECp_OS2P(ek->E,cp,len-1))==NULL) goto done;

		ek->size = ek->E->psize >> 3;
		err=0;
		break;

	case -1: /* it's not object identifier!! */
		break;
	default: /* it's not supported algorithm!! */
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1CERT+1,NULL);
		break;
	}

#ifdef DEBUG_ASN1_X509
	printf("getpubkey - ");
	for(i=0;i<len;i++) printf("%.2x",dk[i]); printf("\n");
#endif
done:
	if(err&&ret){
		/* pm will be free in Key_free func */
		Key_free(ret); ret=NULL;
	}
	return ret;
}

/*-----------------------------------------
  Get subject from cert DER
-----------------------------------------*/
char *asn1_get_str(unsigned char *cp,int *i){
	char tmp[512],*ret=NULL;

	switch(*cp){
	case ASN1_UTF8STRING:
		if((ret = ASN1_utf8(cp,i))==NULL) goto error;
		strncpy(tmp,ret,512);
		if(UC_conv(UC_CODE_UTF8,UC_LOCAL_JCODE,tmp,strlen(tmp),ret,*i-1)<0)
			goto error;
		break;
	case ASN1_BMPSTRING:
		if((ret = ASN1_bmp(cp,i))==NULL) goto error;
		strncpy(tmp,ret,512);
		if(UC_conv(UC_CODE_UNICODE,UC_LOCAL_JCODE,tmp,bmp_len(tmp),ret,*i-1)<0)
			goto error;
		break;
	case ASN1_IA5STRING:
		ret = ASN1_ia5(cp,i);
		break;
	case ASN1_PRINTABLE_STRING:
		ret = ASN1_printable(cp,i);
		break;
	case ASN1_T61STRING:
		ret = ASN1_t61(cp,i);
		break;
	case ASN1_ISO64_STRING:
/*	case ASN1_VISIBLESTRING: */
		ret = ASN1_iso64(cp,i);
		break;
	default:
		STRDUP(ret,"!not string!"); /* might be NULL */
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_ASN1,ERR_PT_ASN1CERT+2,NULL);
		break;
	}
	return ret;
error:
	if(ret) FREE(ret);
	return NULL;
}

char *ASN1_get_subject(unsigned char *in,CertDN *dn){
	unsigned char *cp,*pr,*nx;
	char *ret=NULL,str[512],sb[256],*s1;
	int i,j,err=-1;

	if(!(*in & ASN1_T_STRUCTURED)){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1CERT+3,NULL);
		return NULL;
	}

	cp=ASN1_next(in);
	dn->num = 0;

	for(*str=*sb=0;(*cp&0x1f)==ASN1_SET;cp=nx){
		if((nx = ASN1_skip(cp))==NULL) goto done;
		cp = ASN1_step(cp,2);
		pr = ASN1_next(cp);

		s1=asn1_get_str(pr,&i);

		if((j=ASN1_object_2int(cp))<0) goto done; /* it's not object identifier!! */

		if((OBJ_DIR_C<=j)&&(j<=OBJ_DIR_CN)){
			SNPRINTF (sb,256,"%s=%s, ",dir_t[j-OBJ_DIR_C],s1);
		}else if(j==OBJ_DIR_EMAIL){
			SNPRINTF (sb,256,"/Email=%s",s1);
		}else{
			SNPRINTF (sb,256,"\?\?=%s, ",s1);
		}

		i = dn->num;
		dn->rdn[i].tagoid  = j;
		dn->rdn[i].derform = *pr;
		dn->rdn[i].tag     = s1;
		dn->num++;

		strcat(str,sb);
	}

#ifdef DEBUG_ASN1_X509
	printf("getsubject - %s\n",str);
#endif

	if((STRDUP(ret,str))==NULL) goto done;
	err=0;
done:
	if(err) cert_dn_free(dn);
	return ret;
}

/*-----------------------------------------------
  Get X.509v3.0 Certificate Extension (OPTIONAL)
  return 1...not Extension 
  return 0...no error.
  return -1..error!!
  set "Extensions" DER top -- not explicit tag.
------------------------------------------------*/
CertExt *asn1_get_exts(unsigned char *cp,int *ret_len){
	CertExt *ret=NULL,*hd,*ext;
	unsigned char *oid,*t,*ecp=NULL;
	int i,j,k,cr,id,len,err=-1;

	if((len=ASN1_tlen(cp))<=0){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1CERT+4,NULL);
		goto done;
	}
	t = ASN1_next(cp);
	for(i=0;i<len;){
		cr  = 0; 
		oid = ASN1_next(t);

		if((id = ASN1_object_2int(oid))<0) goto done;

		/* get critical OPTIONAL */
		cp = ASN1_next(oid);
		if((*cp&0x1f)== ASN1_BOOLEAN){
			cr = ASN1_boolean(cp,&j);
			cp = ASN1_next(cp);
		}

		/* get octetstring */
		if(ASN1_octetstring(cp,&j,&ecp,&k)) goto done;
	
		if((ext=ASN1_get_ext(id,ecp))==NULL) goto done;
		FREE(ecp); ecp=NULL;

		/* set other information */
		if(cr) ext->critical = cr;
		if((ext->objid=ASN1_dup(oid))==NULL) goto done;

		/* set extension list -- don't swap the order */
		if(ret==NULL){
			ret= hd = ext;
		}else{
			hd->next= ext;
			hd = ext;
		}

		if((t=ASN1_skip_(t,&j))==NULL) goto done;
		i+=j;
	}
	err=0;
done:
	if(err){
		if(ecp) FREE(ecp);
		OK_set_errorlocation(ERR_LC_ASN1,ERR_PT_ASN1CERT+4);
		CertExt_free_all(ret); ret=NULL;
	}
	return ret;
}
 
int ASN1_get_certext(unsigned char *in, Cert *ct){
	unsigned char *cp;
	int i;
	CertExt *ext;

	if(*in != 0xa3){return 1;} /* no extension */
	if(ct->version<2){ /* invalid version */
		OK_set_error(ERR_ST_BADVER,ERR_LC_ASN1,ERR_PT_ASN1CERT+5,NULL);
		return -1;
	}

	if((ct->ext=CertExt_new(OBJ_DUMMY))==NULL) return -1;
	ext=ct->ext;
	
	/* Extensions is SEQUENCE OF Extension */
	if(in[1]==0){
		/* no extension, but there is explicit tag >:| */
		return 1;
	}

	cp = ASN1_next(in); /* skip Explicit tag */
	if((ext->next = asn1_get_exts(cp,&i))==NULL) return -1;

	return 0;
}

/*-----------------------------------------
  ASN.1 to struct cert 
-----------------------------------------*/
Cert *ASN1_read_cert(unsigned char *in){
	unsigned char *cp,*d2;
	int	i;
	Cert *ret;

	if(in == NULL){return NULL;}

	cp = ASN1_next(in);
	if((*in!=0x30)||(*cp!=0x30)){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1CERT+6,NULL);
		return NULL;
	}

	cp = ASN1_step(in,2);

	/* get certificate */
	if((ret=Cert_new())==NULL) goto error;

	/* read certificate version & serial number */
	/* check x509 v3 certificate or not */
	if((cp[0]==0xa0)||(cp[1]==0x03)){
		cp = ASN1_next(cp);
		ret->version=ASN1_integer(cp,&i);
		if((ret->version<0)||(ret->version>2)){
			OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1,ERR_PT_ASN1CERT+6,NULL);
			goto error;
		}
		cp = ASN1_next(cp);
		if((ret->serialNumber=ASN1_integer(cp,&i))<0)
			if(i==0) goto error;

	}else if((*cp&0x1f)==ASN1_INTEGER){
		if((ret->serialNumber=ASN1_integer(cp,&i))<0)
			if(i==0) goto error;
	}else{
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1CERT+6,NULL);
		goto error;
	}
	/* check if long serial number or not */
	if(ASN1_tlen(cp)>4){
		if((ret->long_sn=ASN1_dup(cp))==NULL) goto error;
	}

	/* check signature algolithm */
	cp = ASN1_next(cp);
	d2 = ASN1_next(cp);
	if((ret->signature_algo=ASN1_object_2int(d2))<0) goto error;

	/* read issuer subject */
	if((cp = ASN1_skip(cp))==NULL) goto error;
	if((ret->issuer=ASN1_get_subject(cp,&(ret->issuer_dn)))==NULL) goto error;

	/* read validity time */
	if((cp = ASN1_skip(cp))==NULL) goto error;

	cp = ASN1_next(cp);
	if(UTC2stm(cp,&ret->time.notBefore)) goto error;

	cp = ASN1_next(cp);
	if(UTC2stm(cp,&ret->time.notAfter)) goto error;


	/* read certificate subject */
	cp = ASN1_next(cp);
	if((ret->subject=ASN1_get_subject(cp,&(ret->subject_dn)))==NULL) goto error;

	/* read public key */
	if((cp = ASN1_skip(cp))==NULL) goto error;
	if((ret->pubkey=(Key*)ASN1_get_pubkey(cp))==NULL) goto error;

	ret->pubkey_algo = ret->pubkey->key_type;

	/* read certificate extent (ver.3) */
	if((cp = ASN1_skip(cp))==NULL) goto error;
	if(ASN1_get_certext(cp,ret)<0) goto error;

	/* read signature */
	if(ret->ext!=NULL) 
		if((cp = ASN1_skip(cp))==NULL) goto error;

	if((d2 = ASN1_skip(cp))==NULL) goto error;
	cp = ASN1_next(cp);
	if((i=ASN1_object_2int(cp))<0) goto error;

	if(ret->signature_algo!=i){
		OK_set_error(ERR_ST_UNMATCHEDPARAM,ERR_LC_ASN1,ERR_PT_ASN1CERT+6,NULL);
		goto error;
	}

	if(ASN1_bitstring(d2,&i,&(ret->signature),&(ret->siglen),NULL)<0)
		goto error;

	ret->der = in;
	return(ret);
error:
	Cert_free(ret);
	return NULL;
}
