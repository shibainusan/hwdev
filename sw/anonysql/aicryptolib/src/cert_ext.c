/* cert_ext.c */
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
#include "ok_asn1.h"
#include "ok_sha1.h"

/*-----------------------------------------
  CertExt alloc & FREE.
-----------------------------------------*/
CertExt *CertExt_new(int obj_id){
	CertExt *ret;
	int size;

	switch(obj_id){
	/* certificate extensions */
	case OBJ_X509v3_SbjKeyIdt: size = sizeof(CE_SbjKID); break;
	case OBJ_X509v3_KEY_Usage: size = sizeof(CE_KUsage); break;
	case OBJ_X509v3_ExtKeyUsage: size = sizeof(CE_ExtKUsage); break;
	case OBJ_X509v3_PrvKeyUsgPrd: size = sizeof(CE_PKUsagePrd); break;
	case OBJ_X509v3_SbjAltName: size = sizeof(CE_SbjAltName); break;
	case OBJ_X509v3_IssAltName: size = sizeof(CE_IssAltName); break;
	case OBJ_X509v3_BASIC: size = sizeof(CE_BasicCons); break;
	case OBJ_X509v3_NameConst: size = sizeof(CE_NameCons); break;
	case OBJ_X509v3_PolicyConst: size = sizeof(CE_PolCons); break;
	case OBJ_X509v3_CRL_Point: size = sizeof(CE_CRLDistPt); break;
	case OBJ_X509v3_CERT_Pol: size = sizeof(CE_CertPol); break;
	case OBJ_X509v3_CertPolMap: size = sizeof(CE_PolMap); break;
	case OBJ_X509v3_AuthKeyIdt: size = sizeof(CE_AuthKID); break;
	case OBJ_PKIX_IDPE_AIA: size = sizeof(CE_AIA); break;
	case OBJ_NS_CERT_TYPE: size = sizeof(CE_NSType); break;
	case OBJ_NS_CERT_CRLURL:
	case OBJ_NS_CERT_COMMENT:
	case OBJ_P9_UNST_NAME:
	case OBJ_P9_CHALL_PWD:
	case OBJ_MOJ_Registrar: size = sizeof(CE_Com); break;
	case OBJ_MOJ_JCertPol: size = sizeof(CE_CertPol); break;
	case OBJ_MOJ_RegCoInfo: size = sizeof(CE_MOJCoInfo); break;
	case OBJ_MOJ_TimeLimit: size = sizeof(CE_Com); break;
	case OBJ_MOJ_SuspCode: size = sizeof(CE_MOJSuspCode); break;
	case OBJ_MOJ_GenmReq: size = sizeof(CE_MOJGenmReq); break;
	case OBJ_MOJ_GenpRes: size = sizeof(CE_MOJGenpRes); break;
	case OBJ_MOJ_GenSpReq: size = sizeof(CE_MOJGenSpReq); break;
	case OBJ_MOJ_GenSpRes: size = sizeof(CE_MOJGenSpRes); break;
	case OBJ_P9_EXT_REQ: size = sizeof(CE_ExtReq); break;
	/* CRL extensions */
	case OBJ_X509v3_CRLNumber: size = sizeof(CE_CRLNum); break;
	case OBJ_X509v3_CRLReason: size = sizeof(CE_Reason); break;
	case OBJ_X509v3_IssDistPoint: size = sizeof(CE_IssDistPt); break;
	/* not supported */
	case OBJ_X509v3_SubDirAtt: 
	case OBJ_X509v3_HoldInsCode:
	case OBJ_X509v3_InvalData:
	case OBJ_X509v3_DeltaCRLInd:
	case OBJ_X509v3_CertIssuer:
	case OBJ_PKIX_OCSP_NOCHECK:
	default: size = sizeof(CertExt); break;
	}

	if((ret=(CertExt*)MALLOC(size))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERTEXT,NULL);
		return NULL;
	}
	memset(ret,0,size);
	ret->extnID = obj_id;

	/* initialize in the structure */
	switch(obj_id){
	case OBJ_X509v3_PolicyConst:
		((CE_PolCons*)ret)->requireExplicitPolicy = -1;
		((CE_PolCons*)ret)->inhibitPolicyMapping = -1;
		break;
	case OBJ_X509v3_BASIC:
		((CE_BasicCons*)ret)->pathLen = -1;  /* means NULL */
		break;
	default:
		break;
	}
	return ret;
}

void CertExt_free(CertExt *ext){
	int i;

	if(ext==NULL) return;
	switch(ext->extnID){
	case OBJ_X509v3_AuthKeyIdt:
		ExtGN_free(((CE_AuthKID*)ext)->authorityCertIssuer);
		if(((CE_AuthKID*)ext)->long_sn) FREE(((CE_AuthKID*)ext)->long_sn);
		if(((CE_AuthKID*)ext)->keyid) FREE(((CE_AuthKID*)ext)->keyid);
		break;
	case OBJ_X509v3_SbjKeyIdt:
		if(((CE_SbjKID*)ext)->keyid) FREE(((CE_SbjKID*)ext)->keyid);
		break;
	case OBJ_X509v3_ExtKeyUsage:
		for(i=0;i<16;i++){
			if(((CE_ExtKUsage*)ext)->keyPurposeId[i])
				FREE(((CE_ExtKUsage*)ext)->keyPurposeId[i]);
		}
		break;
	case OBJ_X509v3_SbjAltName:
	case OBJ_X509v3_IssAltName:
		ExtGN_free(((CE_SbjAltName*)ext)->egn);
		break;
	case OBJ_X509v3_NameConst:
		ExtSubT_free_all(((CE_NameCons*)ext)->permittedSubtrees);
		ExtSubT_free_all(((CE_NameCons*)ext)->excludedSubtrees);
		break;
	case OBJ_X509v3_CRL_Point:
		for(i=0;i<8;i++){
			ExtGN_free(((CE_CRLDistPt*)ext)->distp[i].distp.fullName);
			if(((CE_CRLDistPt*)ext)->distp[i].distp.nameRelativeToCRLIssuer)
				FREE(((CE_CRLDistPt*)ext)->distp[i].distp.nameRelativeToCRLIssuer);
			ExtGN_free(((CE_CRLDistPt*)ext)->distp[i].cRLIssuer);
		}
		break;
	case OBJ_MOJ_JCertPol:
	case OBJ_X509v3_CERT_Pol:
		ExtCP_free_all(((CE_CertPol*)ext)->ecp);
		break;
	case OBJ_X509v3_CertPolMap:
		for(i=0;i<16;i++){
			if(((CE_PolMap*)ext)->issuerDomainPolicy[i])
				FREE(((CE_PolMap*)ext)->issuerDomainPolicy[i]);
			if(((CE_PolMap*)ext)->subjectDomainPolicy[i])
				FREE(((CE_PolMap*)ext)->subjectDomainPolicy[i]);
		}
		break;
	case OBJ_P9_EXT_REQ:
		CertExt_free_all(((CE_ExtReq*)ext)->ext);
		break;
	case OBJ_P9_UNST_NAME:
	case OBJ_P9_CHALL_PWD:
	case OBJ_MOJ_TimeLimit:
	case OBJ_MOJ_Registrar:
	case OBJ_NS_CERT_CRLURL:
	case OBJ_NS_CERT_COMMENT:
		if(((CE_Com*)ext)->comment)
			FREE(((CE_Com*)ext)->comment);
		break;
	case OBJ_PKIX_IDPE_AIA:
		for(i=0;i<((CE_AIA*)ext)->pnum;i++){
			if(((CE_AIA*)ext)->adesc[i].oidc)
				FREE(((CE_AIA*)ext)->adesc[i].oidc);
			ExtGN_free(((CE_AIA*)ext)->adesc[i].accessLocation);
		}
		break;
	case OBJ_MOJ_RegCoInfo:
		for(i=0;i<7;i++){
			if(((CE_MOJCoInfo*)ext)->corpInfo[i])
				FREE(((CE_MOJCoInfo*)ext)->corpInfo[i]);
		}
		break;
	case OBJ_MOJ_GenSpReq:
		cert_dn_free(&((CE_MOJGenSpReq*)ext)->issuer_dn);
		if(((CE_MOJGenSpReq*)ext)->encValue)
			FREE(((CE_MOJGenSpReq*)ext)->encValue);
		if(((CE_MOJGenSpReq*)ext)->snum_der)
			FREE(((CE_MOJGenSpReq*)ext)->snum_der);
		break;
	case OBJ_MOJ_GenSpRes:
		cert_dn_free(&((CE_MOJGenSpRes*)ext)->issuer_dn);
		if(((CE_MOJGenSpRes*)ext)->snum_der)
			FREE(((CE_MOJGenSpRes*)ext)->snum_der);
		break;
	case OBJ_X509v3_IssDistPoint:
		ExtGN_free(((CE_IssDistPt*)ext)->distp.fullName);
		if(((CE_IssDistPt*)ext)->distp.nameRelativeToCRLIssuer)
			FREE(((CE_IssDistPt*)ext)->distp.nameRelativeToCRLIssuer);
		break;
	case OBJ_X509v3_KEY_Usage: 
	case OBJ_X509v3_PrvKeyUsgPrd:
	case OBJ_X509v3_BASIC:
	case OBJ_X509v3_PolicyConst:
	case OBJ_X509v3_CRLNumber:
	case OBJ_X509v3_CRLReason:
	case OBJ_NS_CERT_TYPE:
	case OBJ_MOJ_SuspCode:
	case OBJ_MOJ_GenmReq:
	case OBJ_MOJ_GenpRes:
	case OBJ_PKIX_OCSP_NOCHECK:
		break;

	/* not supported */
	case OBJ_X509v3_SubDirAtt: 
	case OBJ_X509v3_HoldInsCode:
	case OBJ_X509v3_InvalData:
	case OBJ_X509v3_DeltaCRLInd:
	case OBJ_X509v3_CertIssuer:
	default:
		break;
	}
	if(ext->der)	FREE(ext->der);
	if(ext->objid)	FREE(ext->objid);
	FREE(ext);
}

void CertExt_free_all(CertExt *top){
	CertExt *ext,*next;
	for(ext=top;ext!=NULL;ext=next){
		next=ext->next;
		CertExt_free(ext);
	}
}

/*-----------------------------------------
  Duplicate struct CertExt
-----------------------------------------*/
CertExt *CertExt_dup(CertExt *src){
	CertExt *ret;
	
	if((ret=ASN1_get_ext(src->extnID,src->der))==NULL) goto error;
	ret->critical = src->critical;
	ret->dlen     = src->dlen;
	ret->next     = NULL;

	if(src->objid){
		if((ret->objid=ASN1_dup(src->objid))==NULL) goto error;
	}
	return ret;
error:
	CertExt_free(ret);
	return NULL;
}

CertExt *CertExt_dup_all(CertExt *top){
	CertExt *ret,*tp,*now;

	ret=tp=NULL;
	while(top){
		if((now=CertExt_dup(top))==NULL) goto error;

		top=top->next;
		if(ret){
			ret->next=now;
			ret=ret->next;
		}else{
			ret=tp=now;
		}
	}
	return tp;
error:
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509CERT,ERR_PT_CERTEXT+1,NULL);
	CertExt_free_all(tp);
	return NULL;
}

/*-----------------------------------------
  Find Extention from CertExt *head 
-----------------------------------------*/
CertExt *CertExt_find(CertExt* head,int id){
	CertExt *ret;
	for(ret=head;ret;ret=ret->next){
		if(ret->extnID==id)
			return ret;
	}
	return NULL;
}

