/* cert_tool.c */
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
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_tool.h"
#include "ok_uconv.h"

int igcase_strcmp(char *c1, char *c2);

/*-----------------------------------------
  Compare two certificates
  return same content ... 0, differ ... -1
-----------------------------------------*/
int Cert_cmp(Cert *c1, Cert *c2){
	CertExt *e1,*e2;
	time_t t1,t2;

	/* compare version */
	if(c1->version != c2->version) return -1;
	/* compare serial number */
	if(c1->serialNumber != c2->serialNumber) return -1;
	/* compare DN */
	if(Cert_dncmp(&c1->issuer_dn,&c2->issuer_dn)) return -1;
	if(Cert_dncmp(&c1->subject_dn,&c2->subject_dn)) return -1;
	/* compare TIME */
	t1 = mktime(&c1->time.notBefore);
	t2 = mktime(&c2->time.notBefore);
	if(t1 != t2) return -1;
	t1 = mktime(&c1->time.notAfter);
	t2 = mktime(&c2->time.notAfter);
	if(t1 != t2) return -1;

	/* compare keys */
	if(Key_cmp(c1->pubkey,c2->pubkey)) return -1;

	/* compare extensions -- just compare list of extension */
	e1 = c1->ext; e2 = c2->ext;
	while(e1 && e2){
		if(e1->extnID != e2->extnID) return -1;
		if(e1->critical != e2->critical) return -1;
		e1=e1->next; e2=e2->next;
	}
	if(e1 || e2) return -1;

	return 0;
}

/*-----------------------------------------
  CertDN tools
-----------------------------------------*/
int Cert_dncopy(CertDN *from,CertDN *to){
	int	i;
	for(i=0;i<from->num;i++){
		if(from->rdn[i].tag){
			if((STRDUP(to->rdn[i].tag,from->rdn[i].tag))==NULL){
				OK_set_error(ERR_ST_STRDUP,ERR_LC_X509CERT,ERR_PT_CERTTOOL,NULL);
				return -1;
			}
		}
		to->rdn[i].derform =from->rdn[i].derform;
		to->rdn[i].tagoid  =from->rdn[i].tagoid;
	}
	to->num=from->num;
	return 0;
}
/*
 * compare two distinguished names
 * different number of RDN : 
 *    d1 < d2 ... -1; d1==d2 ... 0; d1 > d2 ... 1
 * same namber of RDN :
 *    compare each RDN strings ...
 */
int Cert_dncmp(CertDN *d1,CertDN *d2){
	int	i,j,s1,s2;
	if(d1->num<d2->num) return -1;
	if(d1->num>d2->num) return 1;

	for(i=0; i<d1->num; i++){
		s1 = d1->rdn[i].derform;
		s2 = d2->rdn[i].derform;
		if((s1==ASN1_UTF8STRING)||(s2==ASN1_UTF8STRING)){
			/* utf8 string is case sensitive */
			if(j=strcmp(d1->rdn[i].tag,d2->rdn[i].tag)) return j;
		}else if((s1==ASN1_BMPSTRING)||(s2==ASN1_BMPSTRING)){
			/* bmp string is case sensitive */
			if(j=bmp_strcmp(d1->rdn[i].tag,d2->rdn[i].tag)) return j;
			i++;
		}else{
			/* this case is case insensitive */
			if(j=igcase_strcmp(d1->rdn[i].tag,d2->rdn[i].tag)) return j;
		}
	}
	return 0;
}

int igcase_strcmp(char *c1, char *c2){
	int i,j;
	while(*c1||*c2){
		i=*c1; j=*c2;
		if(('A'<=i)&&(i<='Z')) i=(i-'A')+'a';
		if(('A'<=j)&&(j<='Z')) j=(j-'A')+'a';
		if(i < j) return -1;
		if(i > j) return 1;
		c1++; c2++;
	}
	return 0;
}

char *Cert_find_dn(CertDN *dn, int tkind, int *cr_num){
	char *ret=NULL;
	int	i;

	for(i=0;i<dn->num;i++){
		if(dn->rdn[i].tagoid==tkind){
			ret = dn->rdn[i].tag;
			*cr_num = i;
			break;
		}
	}
	return ret;
}

char *Cert_subject_str(CertDN *dn){
	char sb[128],*ret=NULL;
	int	 i,j;

	for(i=j=0;i<dn->num;i++){
		if(dn->rdn[i].tag) j+=strlen(dn->rdn[i].tag)+10;
	}

	if((ret=(char*)MALLOC(j))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERTTOOL+1,NULL);
		goto error;
	}
	memset(ret,0,j);

	for(i=0;i<dn->num;i++){
		j = dn->rdn[i].tagoid;
		if((OBJ_DIR_C<=j)&&(j<=OBJ_DIR_CN)){
			SNPRINTF (sb,126,"%s=%s, ",dir_t[j-OBJ_DIR_C],dn->rdn[i].tag);
		}else if(j==OBJ_DIR_EMAIL){
			SNPRINTF (sb,126,"/Email=%s",dn->rdn[i].tag);
		}else{
			SNPRINTF (sb,126,"\?\?=%s, ",dn->rdn[i].tag);
		}
		strcat(ret,sb);
	}
	return ret;
error:
	if(ret) FREE(ret);
	return NULL;
}

/*-----------------------------------------
  Set Cert digest from cert data
-----------------------------------------*/
int set_digalgo_from_sigalgo(int algo){
	int kt;
	switch(algo){
	case OBJ_SIG_MD2RSA:
	case OBJ_SIGOIW_MD2RSA:
		sign_digest_algo = OBJ_HASH_MD2;
		kt = KEY_RSA_PRV;
		break;
	case OBJ_SIG_MD5RSA:
	case OBJ_SIGOIW_MD5RSA:
		sign_digest_algo = OBJ_HASH_MD5;
		kt = KEY_RSA_PRV;
		break;
	case OBJ_SIG_SHA1RSA:
	case OBJ_SIGOIW_SHA1RSA:
		sign_digest_algo = OBJ_HASH_SHA1;
		kt = KEY_RSA_PRV;
		break;
	case OBJ_SIG_SHA1DSA:
		sign_digest_algo = OBJ_HASH_SHA1;
		kt = KEY_DSA_PRV;
		break;
	case OBJ_SIG_SHA1ECDSA:
		sign_digest_algo = OBJ_HASH_SHA1;
		kt = KEY_ECDSA_PRV;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509CERT,ERR_PT_CERTTOOL+2,NULL);
		kt = -1;
	}
	return kt;
}

int Cert_set_sigalgo(Cert *ct,Key *prv){
	int kt;

	if((kt=set_digalgo_from_sigalgo(default_cert_sig_algo))<0)
		return -1;

	if(kt!=prv->key_type){
		OK_set_error(ERR_ST_UNMATCHEDPARAM,ERR_LC_X509CERT,ERR_PT_CERTTOOL+3,NULL);
		return -1;
	}
	ct->signature_algo = default_cert_sig_algo;
	return 0;
}

int x509_set_signature(unsigned char *data,Key *prv,unsigned char **signature,int *sig_len){
	unsigned char	digest[20];
	int i;
	
	switch(prv->key_type){
	case KEY_RSA_PRV:
		if((*signature=P1_do_sign(prv,data,sig_len))==NULL)
			return -1;
		break;
	case KEY_DSA_PRV:
		if(ASN1_do_digest(sign_digest_algo,data,digest,&i))
			return -1;

		if((*signature=DSA_get_signature((Prvkey_DSA*)prv,digest,i,sig_len))==NULL)
			return -1;
		break;
	case KEY_ECDSA_PRV:
		if(ASN1_do_digest(sign_digest_algo,data,digest,&i))
			return -1;

		if((*signature=ECDSA_get_signature((Prvkey_ECDSA*)prv,digest,i,sig_len))==NULL)
			return -1;
		break;

	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509CERT,ERR_PT_CERTTOOL+4,NULL);
		return -1;
	}

	return 0;
}

/*-----------------------------------------
  Cert path check routines
-----------------------------------------*/
/* 1..only CA, 0..both, -1..only EE */
int Cert_is_CA(Cert *ct){
	CertExt *bc,*ku;
	int i;

	if(ct->version == 0) return 0;

	bc = CertExt_find(ct->ext,OBJ_X509v3_BASIC);
	ku = CertExt_find(ct->ext,OBJ_X509v3_KEY_Usage);

	if((bc==NULL)&&(ku==NULL)) return 0; /* both */
	if(ku){
		i = ((CE_KUsage*)ku)->flag << 8;
		if(!((i&EXT_KU_keyCertSign)&&(i&EXT_KU_cRLSign))) return -1;
	}
	if(bc){
		if(((CE_BasicCons*)bc)->ca == 0)  return -1; 
	}
	return 1;
}

/* 1..root Cert, 0..not root */
int Cert_is_root(Cert *ct){
	CertExt *sk,*ak;
	unsigned char *ba,*bs;
	int i,j;

	/* check DN */
	if(Cert_dncmp(&ct->issuer_dn,&ct->subject_dn)) return 0;

	/* check key ID */
	ak = CertExt_find(ct->ext,OBJ_X509v3_AuthKeyIdt);
	sk = CertExt_find(ct->ext,OBJ_X509v3_SbjKeyIdt);
	if(ak && sk){
		i = ((CE_AuthKID*)ak)->klen;
		j = ((CE_SbjKID*)sk)->klen;
		if(i != j) return 0;
		ba = ((CE_AuthKID*)ak)->keyid;
		bs = ((CE_SbjKID*)sk)->keyid;
		if(memcmp(ba,bs,i)) return 0; /* this is link certificate */
	}else if(ak){
		return 0;
	}
	return 1;
}

/* 1..path ok, 0..cannot get path */
int Cert_is_path(Cert *upper, Cert *lower){
	CertExt *sk,*ak;
	unsigned char *ba,*bs;
	int i,j;

	/* check DN */
	if(Cert_dncmp(&lower->issuer_dn,&upper->subject_dn)) return 0;

	/* check key ID */
	sk = CertExt_find(upper->ext,OBJ_X509v3_SbjKeyIdt);
	ak = CertExt_find(lower->ext,OBJ_X509v3_AuthKeyIdt);
	if(ak && sk){
		j = ((CE_SbjKID*)sk)->klen;
		i = ((CE_AuthKID*)ak)->klen;
		if(i != j) return 0;
		bs = ((CE_SbjKID*)sk)->keyid;
		ba = ((CE_AuthKID*)ak)->keyid;
		if(memcmp(bs,ba,i)) return 0; /* path is invalid */
	}else if(ak){
		return 0;
	}
	return 1;
}

/* 1..path ok, 0..cannot get path */
int CRL_is_path(Cert *ca, CRL *crl){
	CertExt *sk,*ak;
	unsigned char *ba,*bs;
	int i,j;

	/* check DN */
	if(Cert_dncmp(&crl->issuer_dn,&ca->subject_dn)) return 0;

	/* check key ID */
	sk = CertExt_find(ca->ext,OBJ_X509v3_SbjKeyIdt);
	ak = CertExt_find(crl->ext,OBJ_X509v3_AuthKeyIdt);
	if(ak && sk){
		j = ((CE_SbjKID*)sk)->klen;
		i = ((CE_AuthKID*)ak)->klen;
		if(i != j) return 0;
		bs = ((CE_SbjKID*)sk)->keyid;
		ba = ((CE_AuthKID*)ak)->keyid;
		if(memcmp(bs,ba,i)) return 0; /* path is invalid */
	}else if(ak){
		return 0;
	}
	return 1;
}
