/* cert_vfy.c */
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

#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"
#include "ok_tool.h"

Cert *read_cert(char *fname);
CRL *read_crl(char *fname);


/*-----------------------------------------
  Certificate Verify.
-----------------------------------------*/
int Cert_verify(CertList *crtl,CRLList *crll,Cert *cert,int max_depth,int type){
	static int depth=0;
	int	ret,last=0;
	CertList *cl;
	CRLList *rl;
	Cert  *ca;
	CRL   *crl;

	if(type & DONT_VERIFY)
		return 0;

	if(depth>max_depth)
		return 0;

	if(cert == NULL)
		return (X509_VFY_ERR|depth);

	if(Cert_is_root(cert)){
		if(!depth)
			if(!(type & ALLOW_SELF_SIGN))
				return X509_VFY_ERR_SELF_SIGN;
			last=1;
	}

	ret=0; ca=NULL; crl=NULL;
	for(cl=crtl; cl ;cl=cl->next){
		if(Cert_is_path(cl->cert,cert)){
			ca = Certlist_get_cert(cl);

			if(Cert_is_root(cert)){
				crl = NULL; type |= DONT_CHECK_REVOKED;
			}else{
				if(rl = CRLlist_find_byIss(crll,cert->issuer))
					crl = CRLlist_get_crl(rl);
			}
			break;
		}
	}

	if(cl == NULL){
		ret = (X509_VFY_ERR_NOT_IN_CERTLIST|depth);
		goto done;
	}
	if(Cert_is_CA(ca)<0){
		ret = (X509_VFY_ERR_NOT_CACERT|depth);
		goto done;
	}
	if(!(last||(type & DONT_CHECK_REVOKED)))
		if((crl == NULL)&&(!(type & IF_NO_CRL_DONT_CHECK_REVOKED))){
			ret = (X509_VFY_ERR_ISSUER_CRL|depth);
			goto done;
		}

	/* CA chain check */
	if(!last){
		depth++;
		ret = Cert_verify(crtl,crll,ca,max_depth,type);
		depth--;
		if(ret) goto done;
	}

	/* verify CRL */
	if(!(last||(type & DONT_CHECK_REVOKED)||(crl==NULL)))
		if(!(type & DONT_VERIFY_CRL)){
			if(ret=CRL_signature_verify(ca,crl)){
				ret|=depth; goto done; 
			}else if(ret=CRL_time_verify(crl)){
				ret|=depth; goto done; 
			}
		}


	/* printf("CRL Verify OK ... %s\n",crlbuf); */
	if(ret=Cert_signature_verify(ca,cert)){
		ret|=depth; goto done; 
	}else if(ret=Cert_validity_verify(cert)){
		ret|=depth; goto done; 
	}else{
		if(!(last||(type & DONT_CHECK_REVOKED)||(crl==NULL)))
			if(!(depth&&(type & ONLY_FIRST_DEPTH_CHECK_REVOKED))){
				ret=Cert_revoked_check(cert,crl);
				if(ret){ ret|=depth; goto done; }
			}
	}

	/*  printf("Verify OK\n");*/
done:
	return ret;
}

/*-----------------------------------------------
  Certificate signature verify
  return 0  ... verify OK
  return err  ... verify Failed(err=number)
-----------------------------------------------*/
int obj_sig2hash(int sig_oid){
	int ret;
	switch(sig_oid){
	case OBJ_SIG_MD2RSA:
	case OBJ_SIGOIW_MD2RSA:
	case OBJ_HASH_MD2:
		ret = OBJ_HASH_MD2; break;
	case OBJ_SIG_MD5RSA:
	case OBJ_SIGOIW_MD5RSA:
	case OBJ_HASH_MD5:
		ret = OBJ_HASH_MD5; break;
	case OBJ_SIG_SHA1RSA:
	case OBJ_SIG_SHA1DSA:
	case OBJ_SIG_SHA1ECDSA:
	case OBJ_SIGOIW_SHA1RSA:
	case OBJ_HASH_SHA1:
		ret = OBJ_HASH_SHA1; break;
	default:
		ret = -1;
	}
	return ret;
}

int hash_size(int hash_algo){
	int ret;
	switch(hash_algo){
	case OBJ_SIG_MD2RSA:
	case OBJ_SIGOIW_MD2RSA:
	case OBJ_HASH_MD2: ret = 16;  break;
	case OBJ_SIG_MD5RSA:
	case OBJ_SIGOIW_MD5RSA:
	case OBJ_HASH_MD5: ret = 16;  break;
	case OBJ_SIG_SHA1RSA:
	case OBJ_SIG_SHA1DSA:
	case OBJ_SIG_SHA1ECDSA:
	case OBJ_SIGOIW_SHA1RSA:
	case OBJ_HASH_SHA1: ret = 20; break;
	default: ret = -1; break;
	}
	return ret;
}

int Cert_signature_verify(Cert *ca,Cert *user){
	int i,ret = 0;

	if(ca != user){ /* CSR should not do this comparison */
		if(Cert_dncmp(&ca->subject_dn,&user->issuer_dn))
			return X509_VFY_ERR_NOT_CACERT;
	}

	i = ASN1_vfy_sig(ca->pubkey,ASN1_next(user->der),user->signature,user->signature_algo);
	if(i > 0) ret = X509_VFY_ERR_SIGNATURE;
	if(i==-2) ret = X509_VFY_ERR_UNKOWN_SIG_ALGO;
	if(i < 0) ret = X509_VFY_ERR_SYSTEMERR;

	return ret;
}

/*-----------------------------------------------
  Certificate validity verify
  return 0  ... verify OK
  return err  ... verify Failed(err=number)
-----------------------------------------------*/
int Cert_validity_verify(Cert *ct){
	time_t t1,t2;

	/*  tzset();*/
	time(&t1); /* get current utc time */

	t2 = timegm(&ct->time.notBefore); /* utc -> utc */
	if(t1<t2) return X509_VFY_ERR_NOTBEFORE;	/* NOT Before Error */

        t2 = timegm(&ct->time.notAfter); /* utc -> utc */
	if(t1>t2) return X509_VFY_ERR_NOTAFTER;	/* NOT After Error */

	return 0;
}

/*-----------------------------------------------
  Certificate Revoked check
  return 0  ... verify OK
  return err  ... verify Failed(err=number)
-----------------------------------------------*/
int Cert_revoked_check(Cert *ct,CRL *crl){
	Revoked *rv;

	if(Cert_dncmp(&ct->issuer_dn,&crl->issuer_dn))
		return X509_VFY_ERR_ISSUER_CRL;

	for(rv=crl->next;rv!=NULL;rv=rv->next)
		if(ct->serialNumber == rv->serialNumber)
			return X509_VFY_ERR_REVOKED;

	return 0;
}

/*-----------------------------------------------
  Get Verification Error string.
-----------------------------------------------*/
char *Cert_get_vfyerrstr(int err){
	static char buf[64];

	switch((err&0xff00)){
	case X509_VFY_ERR:
		sprintf(buf,"CERT Verify Failed (?) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_NOT_IN_CERTLIST:
		sprintf(buf,"CERT Verify Failed (unknown CA) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_NOT_CACERT:
		sprintf(buf,"CERT Verify Failed (CA cert not found) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_ISSUER_CRL:
		sprintf(buf,"CERT Verify Failed (CRL not found) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_SIGNATURE_CRL:
		sprintf(buf,"CRL Verify Failed (signature error) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_LASTUPDATE:
	case X509_VFY_ERR_NEXTUPDATE:
		sprintf(buf,"CRL Verify Failed (CRL expired) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_SIGNATURE:
		sprintf(buf,"CERT Verify Failed (signature error) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_NOTBEFORE:
	case X509_VFY_ERR_NOTAFTER:
		sprintf(buf,"CERT Verify Failed (certificate expired) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_REVOKED:
		sprintf(buf,"CERT Verify Failed (certificate revoked) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_SYSTEMERR:
		sprintf(buf,"Cannot continue verification process : system error : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_UNKOWN_SIG_ALGO:
		sprintf(buf,"CERT Verify Failed (unknown signature algorithm) : %d",err&0x00ff);
		break;
	case X509_VFY_ERR_SELF_SIGN:
		sprintf(buf,"CERT Verify Failed (certificate self signed) : %d",err&0x00ff);
		break;
	case 0:
		sprintf(buf,"CERT Verify OK");
		break;
	default:
		sprintf(buf,"CERT Verify (Unknown error) : %d",err&0x00ff);
		break;
	}
	return buf;
}
