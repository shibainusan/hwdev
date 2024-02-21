/* asn1_ext.c */
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

#include "ok_asn1.h"

char *ret_string(char *in,int *mv);

/*-----------------------------------------
  ASN.1 to CertExt structure
-----------------------------------------*/
CertExt *ASN1_get_ext(int id, unsigned char *in){
	CertExt *ret;

	switch(id){
	case OBJ_X509v3_AuthKeyIdt: ret = ASN1_ext_authkey(in); break;
	case OBJ_X509v3_SbjKeyIdt: ret = ASN1_ext_sbjkey(in); break;
	case OBJ_X509v3_KEY_Usage: ret = ASN1_ext_keyusage(in); break;
	case OBJ_X509v3_ExtKeyUsage: ret = ASN1_ext_extkeyusage(in); break;
	case OBJ_X509v3_PrvKeyUsgPrd: ret = ASN1_ext_prvkey_period(in); break;
	case OBJ_X509v3_CERT_Pol: ret = ASN1_ext_certpol(id,in); break;
	case OBJ_X509v3_CertPolMap: ret = ASN1_ext_certpolmap(in); break;

	case OBJ_X509v3_SbjAltName: ret = ASN1_ext_altname(id,in); break;
	case OBJ_X509v3_IssAltName: ret = ASN1_ext_altname(id,in); break;

	case OBJ_X509v3_BASIC: ret = ASN1_ext_basiccons(in); break;
	case OBJ_X509v3_NameConst: ret = ASN1_ext_namecons(in); break;
	case OBJ_X509v3_PolicyConst: ret = ASN1_ext_policons(in); break;

	case OBJ_X509v3_CRL_Point: ret = ASN1_ext_crlpoint(in); break;

	case OBJ_X509v3_CRLNumber: ret = ASN1_ext_crlnumber(in); break;
	case OBJ_X509v3_IssDistPoint: ret = ASN1_ext_issdistpt(in); break;
	case OBJ_X509v3_CRLReason: ret = ASN1_ext_reasoncode(in); break;

	case OBJ_PKIX_IDPE_AIA: ret = ASN1_ext_pkixaia(in); break;
	case OBJ_NS_CERT_CRLURL: ret = ASN1_ext_nscrlurl(in); break;
	case OBJ_NS_CERT_COMMENT: ret = ASN1_ext_nscomment(in); break;
	case OBJ_NS_CERT_TYPE: ret = ASN1_ext_nscerttype(in); break;

	case OBJ_MOJ_JCertPol: ret = ASN1_ext_certpol(id,in); break;
	case OBJ_MOJ_Registrar: ret = ASN1_ext_mojregist(in); break;
	case OBJ_MOJ_RegCoInfo: ret = ASN1_ext_mojcorpinfo(in); break;
	case OBJ_MOJ_TimeLimit: ret = ASN1_ext_timelimit(in); break;
	case OBJ_MOJ_SuspCode: ret = ASN1_ext_suspcode(in); break;
	case OBJ_MOJ_GenmReq: ret = ASN1_ext_mojgenmreq(in); break;
	case OBJ_MOJ_GenpRes: ret = ASN1_ext_mojgenpres(in); break;
	case OBJ_MOJ_GenSpReq: ret = ASN1_ext_mojgenspreq(in); break;
	case OBJ_MOJ_GenSpRes: ret = ASN1_ext_mojgenspres(in); break;
	case OBJ_PKIX_OCSP_NOCHECK: ret = ASN1_ext_ocspnochk(in); break;

	case OBJ_P9_EXT_REQ: ret = ASN1_ext_extreq(in); break;
	case OBJ_P9_UNST_NAME: ret = ASN1_ext_p9unstname(in); break;
	case OBJ_P9_CHALL_PWD: ret = ASN1_ext_p9chapass(in); break;

	case OBJ_X509v3_SubDirAtt: 
	case OBJ_X509v3_HoldInsCode:
	case OBJ_X509v3_InvalData:
	case OBJ_X509v3_DeltaCRLInd:
	case OBJ_X509v3_CertIssuer:
	default:
		if((ret = CertExt_new(id))==NULL) goto error;
		if(in){
			if((ret->der = ASN1_dup(in))==NULL) goto error;
		}
		break;
	}
	if(ret==NULL) goto error;

	if(in) ASN1_skip_(in,&ret->dlen);
	return ret;
error:
	CertExt_free(ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 to struct general Names
-----------------------------------------*/
ExtGenNames *asn1_get_genname(unsigned char *in){
	ExtGenNames *ret=NULL;
	CertDN dn;
	char *str=NULL;
	int i,err=-1;

	cert_dn_init(&dn);
	switch(*in&0x1f){
	case 1:	/* rfc822Name (IA5String) */
	case 2:	/* dNSName (IA5String) */
	case 6:	/* uniformResourceIdentifier (IA5String) */
		if((*in&0xe0)==0x80){
			if((str=ret_string(in,&i))==NULL) goto done;
			if((ret=ExtGN_set_str(str,(*in&0x1f)))==NULL) goto done;
		}
		break;
	case 4:	/* directoryName */
		in = ASN1_next(in);
		if((str= ASN1_get_subject(in,&dn))==NULL) goto done;
		if((ret= ExtGN_set_dn(&dn))==NULL) goto done;
		break;
	case 7:	/* iPAddress (OCTET STRING) */
		if((ret=ExtGN_new())==NULL) goto done;
		ret->type = (*in&0x1f);
		if(ASN1_octetstring_(in,&i,(unsigned char**)&ret->name,&ret->name_len,1)) goto done;
		break;
	case 8:	/* registeredID (OBJECT IDENTIFIER) */
		i = ASN1_tlen(in)*4+8;
		if((ret=ExtGN_new())==NULL) goto done;
		if((ret->name=MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1EXT+1,NULL);
			goto done;
		}
		if(objid2str(in,ret->name,i)<0) goto done;
		ret->name_len = strlen(ret->name);
		ret->type     = (*in&0x1f);
		break;

	case 0:	/* otherName */
		if((ret=ExtGN_new())==NULL) goto done;
		if((ret->name=(char*)asn1_get_othname(in,&ret->name_len))==NULL) goto done;
		ret->type     = (*in&0x1f);
		break;
	case 3:	/* x400Address */
	case 5:	/* ediPartyName */
		if((ret=ExtGN_new())==NULL) goto done;
		ret->type = (*in&0x1f);
		break;
	default:
		/* not supported */
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1EXT+1,NULL);
		goto done;
	}

	err=0;
done:
	cert_dn_free(&dn);
	if(str) FREE(str);
	if(err){ExtGN_free(ret); ret=NULL;}
	return ret;
}

ExtGenNames *ASN1_get_gennames(unsigned char *in){
	ExtGenNames *gn,*hd,*ret=NULL;
	int i,j,len;

	if(in==NULL) return NULL;

	len= ASN1_tlen(in);
	in = ASN1_next(in);

	for(i=0;i<len;){
		if((gn=asn1_get_genname(in))==NULL) goto error;
		if(ret){
			hd->next = gn;
			hd = hd->next;
		}else{
			hd = ret = gn;
		}

		if((in=ASN1_skip_(in,&j))==NULL) goto error;
		i+=j;
	}
	return ret;
error:
	ExtGN_free(ret);
	return NULL;
}

OtherName *asn1_get_othname(unsigned char *in,int *ret_len){
	OtherName *ret;
	char tmp[64];

	if(*in != 0xa0) goto error;

	if((ret=ExtGN_on_new())==NULL) goto error;

	/* get OID */
	in = ASN1_next(in);
	if((ret->oid = ASN1_object_2int(in))<0) goto error;
	if(objid2str(in,tmp,62)<0) goto error;
	if((STRDUP(ret->oidc,tmp))==NULL) goto error;

	/* get name */
	in = ASN1_step(in,2);
	switch(ret->oid){
	default:
		if((ret->name=ASN1_dup(in))==NULL) goto error;
		ASN1_skip_(in,&ret->nlen);
	}

	return ret;
error:
	ExtGN_on_free(ret);
	return NULL;
}

/*-----------------------------------------
  ASN.1 to struct ExtCertPol
-----------------------------------------*/
ExtPolUN *asn1_get_unotice(unsigned char *in,int *ret_len){
	unsigned char *cp;
	ExtPolUN *ret;
	int i,j,k,len;

	*ret_len = 0;
	if((ret=ExtPUN_new())==NULL) goto error;

	in = ASN1_next(in);
	/* noticeRef NoticeReference OPTIONAL */
	if(*in == 0x30){ /* sequence */
		cp = ASN1_next(in);
		if((ret->organization= asn1_get_str(cp,&i))==NULL) goto error;

		cp = ASN1_next(cp);
		len= ASN1_tlen(cp);
		cp = ASN1_next(cp);
		for(i=k=0;(i<len)&&(k<4);i+=j,k++){
			if((ret->noticeNumbers[k]=ASN1_integer(cp,&j))<0) goto error;
			cp = ASN1_next(cp);
		}
		*ret_len += strlen(ret->organization) + 16;

		if((in=ASN1_skip(in))==NULL) goto error;
	}
	/* explicitText DisplayText OPTIONAL */
	if((*in==ASN1_UTF8STRING)||(*in==ASN1_ISO64_STRING)||(*in==ASN1_BMPSTRING)){
		if((ret->explicitText= asn1_get_str(in,&i))==NULL) goto error;
		*ret_len += strlen(ret->explicitText);
	}

	return ret;
error:
	ExtPUN_free(ret);
	return NULL;
}

ExtPolInfo *asn1_get_polqualinfo(unsigned char *in){
	ExtPolInfo *epi,*hd,*ret=NULL;
	unsigned char *cp,*dp;
	int  i,j,k,l,len;

	len= ASN1_tlen(in);
	dp = ASN1_next(in);

	for(i=0;i<len;i+=j,dp+=j){
		l=j=ASN1_length(&dp[1],&k);
		j+=k+1;

		cp = ASN1_next(dp);
		k  = ASN1_tlen(cp)+2;
		if(*cp!=ASN1_OBJECT_IDENTIFIER)
			continue;

		if((epi=ExtPI_new())==NULL) goto error;

		if((epi->qualifierID = (char*)MALLOC(k*4+4))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1EXT+2,NULL);
			goto error;
		}

		if((epi->qid=ASN1_object_2int(cp))<0) goto error;
		if(objid2str(cp,epi->qualifierID,k*4+4)<0) goto error;
		if(ret){
			hd->next = epi;
			hd = hd->next;
		}else{
			ret = hd = epi;
		}

		/* careful! qualifier is OPTIONAL */
		if(l<=k) continue;

		cp = ASN1_next(cp);
		switch(epi->qid){
		case OBJ_PKIX_IDQT_CPS:
			if((epi->qualifier= asn1_get_str(cp,&epi->qual_len))==NULL)
				goto error;
			break;

		case OBJ_PKIX_IDQT_UNOTICE:
			if((epi->qualifier= (unsigned char*)asn1_get_unotice(cp,&epi->qual_len))==NULL)
				goto error;
			break;

		default:
			if((epi->qualifier= ASN1_dup(cp))==NULL){
				OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1EXT+2,NULL);
				goto error;
			}
			epi->qual_len = ASN1_tlen(cp)+2;
			break;
		}
	}
	return ret;
error:
	ExtPI_free_all(ret);
	return NULL;
}

ExtCertPol *ASN1_get_certpol(unsigned char *in){
	ExtCertPol *ecp,*hd,*ret=NULL;
	ExtPolInfo *epi;
	unsigned char *cp;
	int i,j,k,len;

	if(in==NULL) return NULL;

	len= ASN1_tlen(in);
	in = ASN1_next(in);

	for(i=0;i<len;){
		cp = ASN1_next(in);
		k  = ASN1_tlen(in);

		if((in=ASN1_skip_(in,&j))==NULL) goto error;
		i+=j;

		if(*cp!=ASN1_OBJECT_IDENTIFIER)
			continue;

		if((ecp=ExtCP_new())==NULL) goto error;

		if((ecp->policyID = (char*)MALLOC(k*4+4))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1EXT+3,NULL);
			goto error;
		}
		if(objid2str(cp,ecp->policyID,k*4+4)<0) goto error;
		if(ret){
			hd->next = ecp;
			hd = hd->next;
		}else{
			ret = hd = ecp;
		}

		/* policyQualifiers is OPTIONAL */
		j  = ASN1_tlen(cp)+2;
		if(k<=j) continue;

		cp = ASN1_next(cp);
		if(epi=asn1_get_polqualinfo(cp))
			ecp->info = epi;
	}
	return ret;
error:
	ExtCP_free_all(ret);
	return NULL;
}

/*-----------------------------------------
  Ext GeneralSubTrees
-----------------------------------------*/
ExtSubTrees *asn1_ext_gensubtrees(unsigned char *in){
	unsigned char *cp;
	int  i,j,len;
	ExtSubTrees *hd,*ret=NULL;

	len= ASN1_tlen(in);
	in = ASN1_next(in);

	for(i=0;i<len;){
		/* base */
		if(ret){
			if((hd->next=ExtSubT_new())==NULL) goto error;
			hd = hd->next;
		}else{
			if((ret=hd=ExtSubT_new())==NULL) goto error;
		}

		cp = ASN1_next(in);
		if((hd->base=asn1_get_genname(cp))==NULL) goto error;

		/* minimum [0] DEFAULT 0 */
		if((cp=ASN1_skip(cp))==NULL) goto error;
		if(*cp ==0x80){ /* format error */
			if((hd->minimum = ASN1_integer_(cp,&j,1))<0) goto error;
			if((cp=ASN1_skip(cp))==NULL) goto error;
		}

		/* maximum [1] OPTIONAL */
		if(*cp ==0x81){ /* context | 1 */
			if((hd->maximum = ASN1_integer_(cp,&j,1))<0) goto error;
		}

		if((in=ASN1_skip_(in,&j))==NULL) goto error;
		i+=j;
	}
	return ret;
error:
	ExtSubT_free_all(ret);
	return NULL;
}

int asn1_ext_distpoint(unsigned char *in,DistPointName *dpn){
	int i;

	in = ASN1_next(in);
	i = dpn->FullorRDN = (*in&0x1f) + 1;

	switch(i){
	case 1:	/* fullName */
		if((dpn->fullName=ASN1_get_gennames(in))==NULL) return -1;
		break;
	case 2:	/* nameRelativeToCRLIssuer */
		/* not supported */
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ASN1,ERR_PT_ASN1EXT+5,NULL);
		return -1;
	}
	return 0;
}

/*-----------------------------------------
  Get AttributeTypeAndValues
-----------------------------------------*/
AttrTAV *asn1_get_attrs(unsigned char *in, int *ret_len){
	AttrTAV *ret=NULL,*hd,*att;
	unsigned char *t,*cp;
	int i,j,id,len,err=-1;

	len = ASN1_length(in+1,&i);
	*ret_len = len+i+1;

	t=cp=ASN1_next(in);

	for(i=0;i<len;){
		/* get object ID */
		cp = ASN1_next(t);
		if((id = ASN1_object_2int(cp))<0) goto done;

		/* get attribute value */
		cp = ASN1_next(cp);
		if((att = ASN1_get_ext(id, cp))==NULL)
		if(id == 0){
			/* unknown object id */
			if((att->objid=ASN1_dup(cp))==NULL) goto done;
		}

		if(ret==NULL){
			ret= hd = att;
		}else{
			hd->next= att;
			hd = att;
		}

		if((t=ASN1_skip_(t,&j))==NULL) goto done;
		i+=j;
	}
	err = 0;
done:
	if(err){ CertExt_free_all(ret); ret=NULL; }
	return ret;
}

