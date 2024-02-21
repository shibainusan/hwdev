/* asn1_extdef.c */
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
#include "ok_x509.h"
#include "ok_x509ext.h"
#include "ok_rsa.h"


/*-----------------------------------------
  Extension Authority Key Identifier
-----------------------------------------*/
CertExt *ASN1_ext_authkey(unsigned char* in){
	CE_AuthKID *ret=NULL;
	unsigned char *cp;
	int i;

	if((ret=(CE_AuthKID*)CertExt_new(OBJ_X509v3_AuthKeyIdt))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	cp = ASN1_next(in);
	if(*cp==0x80){
		/* keyIdentifier  [0] KeyIdentifier OPTIONAL */
		if(ASN1_octetstring_(cp,&i,&ret->keyid,&ret->klen,1)) goto error;
		cp = ASN1_next(cp);
	}

	if(*cp==0xa1){
		/* authorityCertIssuer  [1] GeneralNames OPTIONAL */
		if((ret->authorityCertIssuer=ASN1_get_gennames(cp))==NULL) goto error;

		if((cp=ASN1_skip(cp))==NULL) goto error;
	}
	if(*cp==0x82){
		/* authorityCertSerialNumber  [2] CertficateSerialNumber OPTIONAL */
		ret->serialNum=ASN1_integer_(cp,&ret->slen,1);

		if(ASN1_tlen(cp)>4){
			if((ret->long_sn=ASN1_dup(cp))==NULL) goto error;
		}

	}
	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Subject Key Identifier
-----------------------------------------*/
CertExt *ASN1_ext_sbjkey(unsigned char* in){
	CE_SbjKID *ret=NULL;
	int i;

	if((ret=(CE_SbjKID*)CertExt_new(OBJ_X509v3_SbjKeyIdt))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if(ASN1_octetstring(in,&i,&ret->keyid,&ret->klen))
		goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Key Usage string
-----------------------------------------*/
CertExt *ASN1_ext_keyusage(unsigned char *in){
	CE_KUsage *ret=NULL;

	if((ret=(CE_KUsage*)CertExt_new(OBJ_X509v3_KEY_Usage))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	/* get BMPString */
	ret->flag = in[3];

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Extended Key Usage string
-----------------------------------------*/
CertExt *ASN1_ext_extkeyusage(unsigned char *in){
	int i,j,k,len;
	unsigned char *cp,tmp[64];
	CE_ExtKUsage *ret=NULL;

	if((ret=(CE_ExtKUsage*)CertExt_new(OBJ_X509v3_ExtKeyUsage))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	len = ASN1_tlen(in);
	cp  = ASN1_next(in);
	for(i=j=0;(i<len)&&(j<16);j++){
		if(objid2str(cp,tmp,62)<0) goto error;
		if((STRDUP(ret->keyPurposeId[j],tmp))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_ASN1_,ERR_PT_ASN1EXTDEF+3,NULL);
			goto error;
		}
		if((cp=ASN1_skip_(cp,&k))==NULL) goto error;
		i+=k;
	}

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Private Key Usage Period
-----------------------------------------*/
CertExt *ASN1_ext_prvkey_period(unsigned char *in){
	CE_PKUsagePrd *ret=NULL;
	unsigned char t=0;
	
	if((ret=(CE_PKUsagePrd*)CertExt_new(OBJ_X509v3_PrvKeyUsgPrd))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	in = ASN1_next(in);
	if(*in==0x80){ /* context | 0 OPTIONAL */
		t=*in; *in=ASN1_GENERALIZEDTIME;
		if(UTC2stm(in,&ret->notBefore)) goto error;
		*in=t; t=0;
		in = ASN1_next(in);
	}
	if(*in==0x81){ /* context | 1 OPTIONAL */
		t=*in; *in=ASN1_GENERALIZEDTIME;
		if(UTC2stm(in,&ret->notAfter)) goto error;
		*in=t; t=0;
	}

	return (CertExt*)ret;
error:
	if(t) *in=t;
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Certificate Policies
-----------------------------------------*/
CertExt *ASN1_ext_certpol(int id,unsigned char *in){
	CE_CertPol *ret=NULL;
	unsigned char t=0;
	
	if((ret=(CE_CertPol*)CertExt_new(id))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if((ret->ecp=ASN1_get_certpol(in))==NULL)
		goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Policy Mapping
-----------------------------------------*/
CertExt *ASN1_ext_certpolmap(unsigned char *in){
	CE_PolMap *ret=NULL;
	unsigned char *cp;
    char tmp[64];
	int i,j,k,len;

	if((ret=(CE_PolMap*)CertExt_new(OBJ_X509v3_CertPolMap))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

    len= ASN1_tlen(in);
	in = ASN1_next(in);

    for(i=k=0;(i<len)&&(k<16);k++){
		cp = ASN1_next(in);
		if(objid2str(cp,tmp,62)<0) goto error;

		if((STRDUP(ret->issuerDomainPolicy[k],tmp))==NULL) goto error;

		cp = ASN1_next(cp);
		if(objid2str(cp,tmp,62)<0) goto error;

		if((STRDUP(ret->subjectDomainPolicy[k],tmp))==NULL) goto error;

		if((in=ASN1_skip_(in,&j))==NULL) goto error;
		i+=j;
	}
	ret->pnum = k;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Sbject or Issuer AltName
-----------------------------------------*/
CertExt *ASN1_ext_altname(int id,unsigned char *in){
	CE_SbjAltName *ret;

	if((ret=(CE_SbjAltName*)CertExt_new(id))==NULL) 
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if((ret->egn=ASN1_get_gennames(in))==NULL)
		goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Basic Constraints
-----------------------------------------*/
CertExt *ASN1_ext_basiccons(unsigned char *in){
	CE_BasicCons *ret=NULL;
	int i;

	if((ret=(CE_BasicCons*)CertExt_new(OBJ_X509v3_BASIC))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if(in[1]){
		in=ASN1_next(in);
		ret->ca = in[2];	/* Boolean */

		in=ASN1_next(in);
		if(*in == ASN1_INTEGER){
			if((ret->pathLen=ASN1_integer(in,&i))<0) goto error;
		}
	}

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Name Constraints
-----------------------------------------*/
CertExt *ASN1_ext_namecons(unsigned char *in){
	CE_NameCons *ret=NULL;
	unsigned char *cp;

	if((ret=(CE_NameCons*)CertExt_new(OBJ_X509v3_NameConst))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	cp = ASN1_next(in);
	if(*cp==0xa0){ /* permittedSubtrees [0] OPTIONAL */
		if((ret->permittedSubtrees=asn1_ext_gensubtrees(cp))==NULL)
			goto error;

		if((cp=ASN1_skip(cp))==NULL) goto error;
	}
	if(*cp==0xa1){ /* excludedSubtrees [1] OPTIONAL */
		if((ret->excludedSubtrees=asn1_ext_gensubtrees(cp))==NULL)
			goto error;
	}

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension Policy Constraints
-----------------------------------------*/
CertExt *ASN1_ext_policons(unsigned char *in){
	CE_PolCons *ret=NULL;
	unsigned char *cp;
	int i;

	if((ret=(CE_PolCons*)CertExt_new(OBJ_X509v3_PolicyConst))==NULL)
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	cp = ASN1_next(in);
    
	if(*cp==0x80){ /* requireExplicitPolicy [0] OPTIONAL */
		if((ret->requireExplicitPolicy=ASN1_integer_(cp,&i,1))<0)
			goto error;
		cp = ASN1_next(cp);
	}
	if(*cp==0x81){ /* inhibitPolicyMapping [1] OPTIONAL */
		if((ret->inhibitPolicyMapping=ASN1_integer_(cp,&i,1))<0)
			goto error;
	}

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension CRL Distribution Point
-----------------------------------------*/
CertExt *ASN1_ext_crlpoint(unsigned char *in){
	CE_CRLDistPt *ret;
	unsigned char *cp;
	int  i,j,k,len;

	if((ret=(CE_CRLDistPt*)CertExt_new(OBJ_X509v3_CRL_Point))==NULL) 
		goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	len= ASN1_tlen(in);
	in = ASN1_next(in);

	for(i=k=0;i<len;k++){
		cp = ASN1_next(in);

		if(*cp==0xa0){
			/* distributionPoint */
			if(asn1_ext_distpoint(cp,&ret->distp[k].distp)) goto error;
			if((cp=ASN1_skip_(cp,&j))==NULL) goto error;
		}
		if(*cp==0x81){
			/* reasons BITSTRING */
			memcpy(ret->distp[k].flag,&cp[3],2);
			if((cp=ASN1_skip_(cp,&j))==NULL) goto error;
		}
		if(*cp==0xa2){
			/* cRLIssuer */
			if((ret->distp[k].cRLIssuer=ASN1_get_gennames(cp))==NULL)
				goto error;
		}

		if((in=ASN1_skip_(in,&j))==NULL) goto error;
		i += j;
	}
	ret->pnum = k;
	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension PKIX AIA
-----------------------------------------*/
CertExt *ASN1_ext_pkixaia(unsigned char *in){
	unsigned char *cp;
	CE_AIA *ret;
	int len,i,j,k;
	char tmp[64];

	if((ret=(CE_AIA*)CertExt_new(OBJ_PKIX_IDPE_AIA))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	len= ASN1_tlen(in);
	in = ASN1_next(in);
	for(i=k=0;(i<len)&&(k<4);k++){
		cp = ASN1_next(in);

		if(objid2str(cp,tmp,62)<0) goto error;
		if((STRDUP(ret->adesc[k].oidc,tmp))==NULL) goto error;
		ret->adesc[k].oid = ASN1_object_2int(cp);

		cp = ASN1_next(cp);
		if((ret->adesc[k].accessLocation=asn1_get_genname(cp))==NULL)
			goto error;

		if((in=ASN1_skip_(in,&j))==NULL) goto error;
		i+=j;
	}
	ret->pnum = k;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension OCSP nocheck
-----------------------------------------*/
CertExt *ASN1_ext_ocspnochk(unsigned char *in){
	CertExt *ret;

	if((ret=(CertExt*)CertExt_new(OBJ_PKIX_OCSP_NOCHECK))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if((in[0]!=0x05)||(in[1])){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_ASN1_,ERR_PT_ASN1EXTDEF+10,NULL);
		goto error;
	}

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension NS Cert Type
-----------------------------------------*/
CertExt *ASN1_ext_comment(int id,unsigned char *in){
	CE_Com *ret;
	int i;
	
	if((ret=(CE_Com*)CertExt_new(id))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if((ret->comment=asn1_get_str(in,&i))==NULL) goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

CertExt *ASN1_ext_nscerttype(unsigned char *in){
	CE_NSType *ret;

	if((ret=(CE_NSType*)CertExt_new(OBJ_NS_CERT_TYPE))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	/* CertificateType BITSTRING */
	ret->type = in[3];

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension CRL Entry reason
-----------------------------------------*/
CertExt *ASN1_ext_reasoncode(unsigned char *in){
	CE_Reason *ret;
	int i;
	
	if((ret=(CE_Reason*)CertExt_new(OBJ_X509v3_CRLReason))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if((ret->code=ASN1_enumerated(in,&i))<0) goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension CRL Number
-----------------------------------------*/
CertExt *ASN1_ext_crlnumber(unsigned char *in){
	CE_CRLNum *ret;
	int i;
	
	if((ret=(CE_CRLNum*)CertExt_new(OBJ_X509v3_CRLNumber))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	ret->num=ASN1_integer(in,&i);

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension CRL Issuing Dist Point
-----------------------------------------*/
CertExt *ASN1_ext_issdistpt(unsigned char *in){
	CE_IssDistPt *ret;

	if((ret=(CE_IssDistPt*)CertExt_new(OBJ_X509v3_IssDistPoint))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	in = ASN1_next(in);
	if(*in==0xa0){ /* context | structed | 0 */
		/* distributionPoint */
		if(asn1_ext_distpoint(in,&ret->distp)) goto error;
		if((in=ASN1_skip(in))==NULL) goto error;
	}
	if(*in==0x81){ /* context | 1 implicit */
		ret->onlyContainsUserCerts = in[2];
		in = ASN1_next(in);
	}
	if(*in==0x82){ /* context | 2 implicit */
		ret->onlyContainsCACerts = in[2];
		in = ASN1_next(in);
	}
	if(*in==0x83){
		/* reasons BITSTRING */
		memcpy(ret->rflag,&in[3],2);
		in = ASN1_next(in);
	}
	if(*in==0x84){ /* implicit */
		ret->indirectCRL = in[2];
	}
	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

/*-----------------------------------------
  Extension PKCS#9 ExtensionRequest
-----------------------------------------*/
CertExt *ASN1_ext_extreq(unsigned char *in){
	CE_ExtReq *ret;
	int i;
	
	if((ret=(CE_ExtReq*)CertExt_new(OBJ_P9_EXT_REQ))==NULL) goto error;

	if((ret->der=ASN1_dup(in))==NULL) goto error;

	if((ret->ext=asn1_get_exts(in,&i))==NULL) goto error;

	return (CertExt*)ret;
error:
	CertExt_free((CertExt*)ret);
	return NULL;
}

