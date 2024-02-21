/* ext_cert.c */
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
#include "ok_x509ext.h"
#include "ok_sha1.h"
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_asn1.h"
#include "ok_uconv.h"

/*-----------------------------------------
  CertExt Key & Key Identifier
-----------------------------------------*/
/* support */
CertExt *Extnew_authkey_id(Cert *auth,int option){
	CE_AuthKID *ret=NULL;
	CE_SbjKID  *sk =NULL;
	unsigned char *cp,*pub=NULL,*buf=NULL,*kb,tmp[32];
	int i,j,len,err=-1;

	if(auth==NULL) return NULL;
	if(auth->der==NULL){
		if(auth->pubkey==NULL){
			OK_set_error(ERR_ST_NULLKEY,ERR_LC_X509EXT,ERR_PT_EXTCERT,NULL);
			goto done;
		}else{
			switch(auth->pubkey->key_type){
			case KEY_RSA_PUB:
				if((pub=RSApub_toDER((Pubkey_RSA*)auth->pubkey,NULL,&j))==NULL)
					goto done;
				break;
			case KEY_DSA_PUB:
				if((pub=DSApub_toDER((Pubkey_DSA*)auth->pubkey,NULL,&j))==NULL)
					goto done;
				break;
			case KEY_ECDSA_PUB:
				if((pub=ECDSApub_toDER((Pubkey_ECDSA*)auth->pubkey,NULL,&j))==NULL)
					goto done;
				break;
			}
			OK_SHA1(j,pub,tmp); /* get hash */
		}
	}else{
		cp = ASN1_find_tag(auth->der,ASN1_BITSTRING);
		len = ASN1_length((++cp),&i);

		cp+=(i+1);/* because bitstring */
		OK_SHA1(len-1,cp,tmp); /* get hash */
	}

	/* set Authority Key ID */
	if((ret=(CE_AuthKID*)CertExt_new(OBJ_X509v3_AuthKeyIdt))==NULL) goto done;

	/* check subject size */
	for(i=j=0;i<RDN_MAX;i++){
		if(auth->subject_dn.rdn[i].tag)
			j+=strlen(auth->subject_dn.rdn[i].tag)+20;
	}
	if((buf=(unsigned char*)MALLOC(j+128))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT,NULL);
		goto done;
	}

	i=0; cp=buf;
	/* set Identifier... */
	if(option&0x4){
		if(sk=(CE_SbjKID*)CertExt_find(auth->ext,OBJ_X509v3_SbjKeyIdt)){
			ret->klen = sk->klen;
			kb        = sk->keyid;
		}else{
			ret->klen = 20;
			kb        = tmp;
		}
	
		if((ret->keyid=(unsigned char*)MALLOC(ret->klen))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT,NULL);
			goto done;
		}
		memcpy(ret->keyid,kb,ret->klen);

		/* get DER */
		ASN1_set_octetstring(ret->klen,ret->keyid,cp,&i);
		ASN1_set_implicit(0,cp); /* implicit OCTET STRING */
		cp+=i;
	}
	/* set Directory... */
	if(option&0x2){
		if((ret->authorityCertIssuer=ExtGN_set_dn(&auth->subject_dn))==NULL)
			goto done;

		/* get DER */
		Cert_DER_subject(&(auth->subject_dn),cp,&j);
		ASN1_set_explicit(j,4,cp,&j);
		ASN1_set_explicit(j,1,cp,&j); /* implicit GeneralNames */
		cp+=j; i+=j;
	}
	/* set Serial Number... */
	if(option&0x1){
		if(auth->long_sn){
			/* set long integer */
			if((ret->long_sn=ASN1_dup(auth->long_sn))==NULL) goto done;

			/* get DER */
			ret->slen= j= ASN1_tlen(auth->long_sn);
			memcpy(cp,auth->long_sn,j+2);
			ASN1_set_implicit(2,cp); /* implicit INTEGER */
		}else{
			ret->slen     =4;
			ret->serialNum=auth->serialNumber;

			/* get DER */
			ASN1_set_integer(auth->serialNumber,cp,&j);
			*cp = 0x82; /* implicit INTEGER */
		}
		i+=j;
	}
	ASN1_set_sequence(i,buf,&i);

	ret->dlen = i;
	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT,NULL);
		goto done;
	}
	memcpy(ret->der,buf,i);
	err=0;

done:
	if(pub) FREE(pub);
	if(buf) FREE(buf);
	if(err&&ret){CertExt_free((CertExt*)ret);ret=NULL;}
	return (CertExt*)ret;
}

/* support */
CertExt *Extnew_sbjkey_id(Cert *ct){
	CE_SbjKID *ret=NULL;
	unsigned char buf[32],*cp,*pub=NULL;
	int i,len,err=-1;

	if(ct==NULL) return NULL;
	if(ct->der==NULL){
		if(ct->pubkey==NULL){
			OK_set_error(ERR_ST_NULLKEY,ERR_LC_X509EXT,ERR_PT_EXTCERT+1,NULL);
			goto done;
		}else{
			switch(ct->pubkey->key_type){
			case KEY_RSA_PUB:
				if((pub=RSApub_toDER((Pubkey_RSA*)ct->pubkey,NULL,&i))==NULL)
					goto done;
				break;
			case KEY_DSA_PUB:
				if((pub=DSApub_toDER((Pubkey_DSA*)ct->pubkey,NULL,&i))==NULL)
					goto done;
				break;
			case KEY_ECDSA_PUB:
				if((pub=ECDSApub_toDER((Pubkey_ECDSA*)ct->pubkey,NULL,&i))==NULL)
					goto done;
				break;
			}
			OK_SHA1(i,pub,buf); /* get hash */
		}
	}else{
		cp = ASN1_find_tag(ct->der,ASN1_BITSTRING);
		len = ASN1_length((++cp),&i);

		cp+=(i+1);/* because bitstring */
		OK_SHA1(len-1,cp,buf); /* get hash */
	}

	if((ret=(CE_SbjKID*)CertExt_new(OBJ_X509v3_SbjKeyIdt))==NULL) goto done;

	if((ret->der=(unsigned char*)MALLOC(32))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+1,NULL);
		goto done;
	}
	/* set data */
	ret->klen = 20;
	if((ret->keyid=(unsigned char*)MALLOC(ret->klen))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+1,NULL);
		goto done;
	}
	memcpy(ret->keyid,buf,20);

	/* get DER */
	ASN1_set_octetstring(20,buf,ret->der,&ret->dlen);
	err=0;

done:
	if(pub) FREE(pub);
	if(err&&ret){CertExt_free((CertExt*)ret);ret=NULL;}
	return (CertExt*)ret;
}

/* support */
CertExt *Extnew_keyusage(unsigned char flag){
	/* is it necessary to support encipherOnly and decipherOnly !?
	 * it's not supported here, so just 0-6 bits are used.
	 */
	CE_KUsage *ret;
	int i,msk;

	if((ret=(CE_KUsage*)CertExt_new(OBJ_X509v3_KEY_Usage))==NULL) return NULL;

	if((ret->der=(unsigned char*)MALLOC(4))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+2,NULL);
		CertExt_free((CertExt*)ret);
		return NULL;
	}
	/* set data */
	ret->flag = flag;

	/* Get DER */
	for(i=0,msk=0x01; i<8; i++,msk<<=1) if(flag&msk) break;
	ASN1_set_bitstring(i,1,&flag,ret->der,&ret->dlen);
	return (CertExt*)ret;
}

/* option */
CertExt *Extnew_extkeyusage(char **obj_ids){
	int i,j,k;
	unsigned char *cp;
	CE_ExtKUsage *ret=NULL;

	if(obj_ids==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTCERT+3,NULL);
		goto error;
	}
	if((ret=(CE_ExtKUsage*)CertExt_new(OBJ_X509v3_ExtKeyUsage))==NULL) goto error;

	/* set data */
	for(i=j=0;i<16;i++){
		if((obj_ids[i]==NULL)||(*obj_ids[i]==0)) break;
	
		if((STRDUP(ret->keyPurposeId[i],obj_ids[i]))==NULL) goto error;
		j+=strlen(obj_ids[i])+2;
	}
	/* get DER */
	if((ret->der=MALLOC(j+3))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+3,NULL);
		goto error;
	}
	cp = ret->der;
	for(i=j=0;i<16;i++){
		if(ret->keyPurposeId[i]==NULL) break;

		if((k=str2objid(ret->keyPurposeId[i],cp,32))<0) goto error;
		cp+=k; j+=k;
	}
	ASN1_set_sequence(j,ret->der,&ret->dlen);

    return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* option */
CertExt *Extnew_prvkeyusage_period(){
	CE_PKUsagePrd *ret=NULL;
    return (CertExt*)ret;
}

/*-----------------------------------------
  CertExt Policies
-----------------------------------------*/
/* support */
CertExt *Extnew_cert_policy(int type,ExtCertPol *ecp){
	CE_CertPol *ret;

	if((ret=(CE_CertPol*)CertExt_new(type))==NULL) goto error;

	if((ret->der=ExtCP_toDER(ecp,NULL,&ret->dlen))==NULL) goto error;
	ret->ecp = ecp;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* support */
CertExt *Extnew_policy_map(char *issdp,char *sbjdp){
	unsigned char *cp,obj1[32],obj2[32];
	CE_PolMap *ret=NULL;
	int i,j;

	/* this function supports only one Policy Mapping */
	if((issdp==NULL)||(sbjdp==NULL)) return NULL;
	if((i=str2objid(issdp,obj1,32))<0) goto error;
	if((j=str2objid(sbjdp,obj2,32))<0) goto error;

	if((ret=(CE_PolMap*)CertExt_new(OBJ_X509v3_CertPolMap))==NULL) goto error;

	if((ret->der=(unsigned char*)MALLOC(i+j+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+5,NULL);
		goto error;
	}

	/* set data */
	if((STRDUP(ret->issuerDomainPolicy[0],issdp))==NULL) goto error;
	if((STRDUP(ret->subjectDomainPolicy[0],sbjdp))==NULL) goto error;
	ret->pnum = 1;

	/* get DER */
	cp = ret->der;
	memcpy(cp,obj1,i); cp +=i;
	memcpy(cp,obj2,j);

	ASN1_set_sequence(i+j,ret->der,&i); /* only one map... */

	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  CertExt *AltName
-----------------------------------------*/
/* option */
CertExt *Extnew_altname(int id, ExtGenNames *top){
	CE_SbjAltName *ret;

	if((ret=(CE_SbjAltName*)CertExt_new(id))==NULL) 
		goto error;

	/* set information */
	ret->egn = top;

	/* get DER */
	if((ret->der=ExtGN_toDER(top,NULL,&ret->dlen))==NULL)
		goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}


/*-----------------------------------------
  CertExt *Constraints
-----------------------------------------*/
/* support */
CertExt *Extnew_basic_cons(int ca,int path){
	CE_BasicCons *ret;
	unsigned char *cp;
	int i,j;

	if((ret=(CE_BasicCons*)CertExt_new(OBJ_X509v3_BASIC))==NULL) goto error;

	/* estimate size & malloc DER */
	if((ret->der=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+6,NULL);
		goto error;
	}

	/* set data */
	ret->ca      = ca;
	ret->pathLen = path;

	/* get DER */
	cp = ret->der;
	i  = 0;

	if(ca){ /* set CA X509v3 BASIC Constraints */
		ASN1_set_boolean(ca,cp,&i);
		cp += i;
		if(path >= 0){
			ASN1_set_integer(path,cp,&j);
			i+=j;
		}
	}

	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* support */
CertExt *Extnew_name_cons(ExtSubTrees *permit,ExtSubTrees *exclude){
	CE_NameCons *ret;
	unsigned char *cp;
	int i,k=0;

	if((ret=(CE_NameCons*)CertExt_new(OBJ_X509v3_NameConst))==NULL) return NULL;

	/* estimate size & malloc DER */
	if(permit){
		if((i=ExtSubT_estimate_der_size(permit))<0) goto error;
		k+=i;
	}
	if(exclude){
		if((i=ExtSubT_estimate_der_size(exclude))<0) goto error;
		k+=i;
	}
	if((ret->der=(unsigned char*)MALLOC(k+4))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+7,NULL);
		goto error;
	}
	/* set data */
	ret->permittedSubtrees = permit;
	ret->excludedSubtrees  = exclude;

	/* get DER */
	cp=ret->der; k=0;
	if(permit){
		if(ExtSubT_toDER(permit,cp,&i)==NULL) goto error;
		*cp=0xa0; /* permittedSubtrees [0] GeneralSubtrees OPTIONAL */
		cp+=i; k+=i;
	}
	if(exclude){
		if(ExtSubT_toDER(exclude,cp,&i)==NULL) goto error;
		*cp=0xa1; /* excludedSubtrees [1] GeneralSubtrees OPTIONAL */
		cp+=i; k+=i;
	}
	ASN1_set_sequence(k,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/* support */
CertExt *Extnew_policy_cons(int req, int inhibit){
	CE_PolCons *ret;
	unsigned char *cp;
	int i=0,j=0;

	if((ret=(CE_PolCons*)CertExt_new(OBJ_X509v3_PolicyConst))==NULL) return NULL;

	/* estimate size & malloc DER */
	if((ret->der=(unsigned char*)MALLOC(8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+8,NULL);
		goto error;
	}

	/* set data */
	ret->requireExplicitPolicy = req;
	ret->inhibitPolicyMapping  = inhibit;

	/* get DER */
	cp = ret->der;
	if(req >= 0){ /* requireExplicitPolicy [0] OPTIONAL */
		ASN1_set_integer(req,cp,&j); *cp = 0x80;
		cp+=j; i+=j;
	}
	if(inhibit >= 0){ /* inhibitPolicyMapping [1] OPTIONAL */
		ASN1_set_integer(inhibit,cp,&j); *cp = 0x81;
		i+=j;
	}
	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  CertExt CRL Distribution Point
-----------------------------------------*/
/* support */
CertExt *Extnew_crl_distpoint(ExtGenNames *distp,unsigned char *flg,ExtGenNames *issuer){
	CE_CRLDistPt *ret;
	unsigned char *cp;
	int i,j,k=16,l;

	/* estimate size & malloc DER */
	if(distp){
		if((i=ExtGN_estimate_der_size(distp))<0) goto error;
		k+=i;
	}
	if(issuer){
		if((i=ExtGN_estimate_der_size(issuer))<0) goto error;
		k+=i;
	}
	k+=(flg)?(16):(0);

	if((ret=(CE_CRLDistPt*)CertExt_new(OBJ_X509v3_CRL_Point))==NULL) goto error;

	if((ret->der=(unsigned char*)MALLOC(k))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+9,NULL);
		goto error;
	}

	i=0; cp=ret->der;
	if(distp){
		/* set data */
		ret->distp[0].distp.fullName = distp;
		ret->distp[0].distp.FullorRDN= 1;
		/* get DER */
		if(ExtGN_toDER(distp,cp,&j)==NULL) goto error;	
		*cp = 0xa0; /* implicit */
		ASN1_set_explicit(j,0,cp,&j);
		cp+=j; i+=j;
	}
	if(flg){
		/* set data */
		memcpy(ret->distp[0].flag,flg,2);
		/* get DER */
		asn1_check_derbit(2,flg,&k,&l);
		ASN1_set_bitstring(k,l,flg,cp,&j);
		*cp = 0x81; /* implicit */
		cp+=j; i+=j;
	}
	if(issuer){
		/* set data */
		ret->distp[0].cRLIssuer = issuer;
		/* get DER */
		if(ExtGN_toDER(issuer,cp,&j)==NULL) goto error;
		*cp = 0xa2; /* implicit */
		i+=j;
	}

	ASN1_set_sequence(i,ret->der,&i);
	ASN1_set_sequence(i,ret->der,&ret->dlen);
	ret->pnum = 1;
	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  CertExt others
-----------------------------------------*/
/* option */
CertExt *Extnew_sbjdir_attr(){
    return NULL;
}

/*-----------------------------------------
  PKIX Authority Information Access
-----------------------------------------*/
/* support */
CertExt *Extnew_pkix_aia(char *oid,ExtGenNames *aloc){
	CE_AIA *ret=NULL;
	unsigned char *cp;
	int i,j;

	if((oid==NULL)||(aloc==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509EXT,ERR_PT_EXTCERT+10,NULL);
		goto error;
	}
	if((i=ExtGN_estimate_der_size(aloc))<0) goto error;
	i+=16;

	if((ret=(CE_AIA*)CertExt_new(OBJ_PKIX_IDPE_AIA))==NULL) goto error;

	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+10,NULL);
		goto error;
	}

	/* set information */
	ret->pnum = 1;
	if((STRDUP(ret->adesc[0].oidc,oid))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTCERT+10,NULL);
		goto error;
	}
	cp = ret->der;
	if((i=str2objid(oid,cp,32))<0) goto error;

	ret->adesc[0].oid = ASN1_object_2int(cp);
	ret->adesc[0].accessLocation = aloc;

	/* get DER */
	cp+=i;

	if(ExtGN_DER_gname(aloc,cp,&j)) goto error;

	ASN1_set_sequence(i+j,ret->der,&i);
	ASN1_set_sequence(i,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  OCSP Cert Extensions
-----------------------------------------*/
CertExt *Extnew_ocsp_nocheck(){
	CertExt *ret=NULL;
	int i = 4;

	if((ret=(CertExt*)CertExt_new(OBJ_PKIX_OCSP_NOCHECK))==NULL) goto error;

	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+11,NULL);
		goto error;
	}

	/* get DER */
	ASN1_set_null(ret->der);
	ret->dlen = 2;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Netscape Cert Extensions
-----------------------------------------*/
CertExt *Extnew_comment(int type,char *comment){
	unsigned char *tmp=NULL;
	CE_Com *ret;
	int i;
	
	if((ret=(CE_Com*)CertExt_new(type))==NULL) return NULL;
	
	/* set data */
	if((STRDUP(ret->comment,comment))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_X509EXT,ERR_PT_EXTCERT+12,NULL);
		goto error;
	}
	i = (strlen(comment)>>1)*3+4;
	if((tmp=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+12,NULL);
		goto error;
	}
	/* get DER */
	switch(type){
	case OBJ_NS_CERT_CRLURL:
	case OBJ_NS_CERT_COMMENT:
	case OBJ_P9_UNST_NAME:
		ret->der = tmp;
		if(ASN1_set_ia5(comment,ret->der,&ret->dlen)) goto error;
		break;
	case OBJ_P9_CHALL_PWD:
		ret->der = tmp;
		if(ASN1_set_printable(comment,ret->der,&ret->dlen)) goto error;
		break;
	case OBJ_MOJ_Registrar:
		if((ret->der=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+12,NULL);
			goto error;
		}
		if(UC_conv(UC_LOCAL_JCODE,UC_CODE_UTF8,comment,strlen(comment),tmp,i)<0)
			goto error;
		if(ASN1_set_utf8(tmp,ret->der,&ret->dlen)) goto error;
		break;
	}

	if(tmp != ret->der) FREE(tmp);
	return (CertExt*)ret;
error:
	if(tmp != ret->der) FREE(tmp);
	CertExt_free((CertExt*)ret);
	return NULL;
}

CertExt *Extnew_ns_flag(unsigned char flag){
	CE_NSType *ret;
	int i,msk;

	if((ret=(CE_NSType*)CertExt_new(OBJ_NS_CERT_TYPE))==NULL) return NULL;

	if((ret->der=(unsigned char*)MALLOC(4))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+13,NULL);
		goto error;
	}
	
	/* set data */
	ret->type = flag;
	/* get DER */
	for(i=0,msk=0x01; i<8; i++,msk<<=1) if(flag&msk) break;
	ASN1_set_bitstring(i,1,&flag,ret->der,&ret->dlen);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extreq (PKCS#9) Cert Extensions
-----------------------------------------*/
CertExt *Extnew_extreq(CertExt *ext){
	CE_ExtReq *ret;
	CertExt *et;
	int i;

	if((ret=(CE_ExtReq*)CertExt_new(OBJ_P9_EXT_REQ))==NULL) goto error;

	/* count der */
	for(i=8,et=ext; et; et=et->next)
		if(et->der) i += et->dlen + 24;
	
	if((ret->der=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509EXT,ERR_PT_EXTCERT+14,NULL);
		goto error;
	}

	/* set data */
	ret->ext = ext;

	/* get der */
	if(x509_DER_exts(ext,ret->der,&ret->dlen))
		goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}



