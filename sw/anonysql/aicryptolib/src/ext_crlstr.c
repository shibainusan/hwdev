/* ext_crlstr.c */
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
 *	this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *	this list of conditions and the following disclaimer in the documentation
 *	and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *	display the following acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *	acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	 Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
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

char *ret_string(char *in,int *mv);

#define M_check_length_and_copy()	\
		if(max<=(ret+i)) goto max_end; \
		strncat(buf,tmp,i+1); ret+=i;

/*-----------------------------------------
  Extension reasonCode
-----------------------------------------*/
/* support */
int Ext_reasoncode_str(CE_Reason *ce,char *buf,int max){
	char tmp[32],tmp2[32];
	int ret;

	switch(ce->code){
	case 0:	strcpy(tmp,"unspecified ");break;
	case 1:	strcpy(tmp,"keyCompromise ");break;
	case 2:	strcpy(tmp,"cACompromise ");break;
	case 3:	strcpy(tmp,"affiliationChanged ");break;
	case 4:	strcpy(tmp,"superseded ");break;
	case 5:	strcpy(tmp,"cessationOfOperation ");break;
	case 6:	strcpy(tmp,"certificateHold ");break;
	case 8:	strcpy(tmp,"removeFromCRL ");break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_X509CRL,ERR_PT_CRLEXTSTR,NULL);
		return -1;
	}
	sprintf(tmp2,"(0x%.2x)%s",ce->code,RTN);
	strcat(tmp,tmp2);

	ret = strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}


/* option */
int Ext_holdinstcode_str(CertExt *ce, char *buf,int max){
	int ret=0;
	return ret;
}

/* option */
int Ext_invdate_str(CertExt *ce, char *buf,int max){
	int ret=0;
	return ret;
}


/*-----------------------------------------
  Extension CRL Number
-----------------------------------------*/
/* support */
int Ext_crlnum_str(CE_CRLNum *ce,char *buf,int max){
	char tmp[64];
	int ret;
	
	sprintf(tmp,"        num=%d%s",ce->num,RTN);
	ret = strlen(tmp);

	if(max <= ret) ret=max-1;
	strncpy(buf,tmp,ret+1);

	return ret;
}

/*-----------------------------------------
  Extension issuingDistributionPoint
-----------------------------------------*/
/* support */
int Ext_issdistpt_str(CE_IssDistPt *ce, char *buf,int max){
	char tmp[512],tmp2[482];
	int  i,ret=0;

	*buf=0;
	if(ce->distp.FullorRDN){
		/* distributionPoint [0] DistributionPointName OPTIONAL */
		sprintf(tmp,"        [0] dist-point :%s",RTN);

		if((i=get_distpoint_str(&ce->distp,tmp2,480))<0) 
			return -1;
		strcat(tmp,tmp2);
		i = strlen(tmp);
	
		M_check_length_and_copy();
	}

	/* onlyContainsUserCerts [1] BOOLEAN */
	if(ce->onlyContainsUserCerts){
		strcpy(tmp,"        [1] onlyUserCerts: TRUE");
		strcat(tmp,RTN);
		i = strlen(tmp);
	
		M_check_length_and_copy();
	}
	/* onlyContainsCACerts [2] BOOLEAN */
	if(ce->onlyContainsCACerts){
		strcpy(tmp,"        [2] onlyCACerts: TRUE");
		strcat(tmp,RTN);
		i = strlen(tmp);
	
		M_check_length_and_copy();
	}
	if((ce->rflag[0])||(ce->rflag[1])){
		/*onlySomeReasons [3] ReasonFlags OPTIONAL */
		strcpy(tmp,"        [3] reasons :");

		if((i=get_reason_str(ce->rflag,tmp2,480))<0)
			return -1;
		strcat(tmp,tmp2);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	/* indirectCRL [4] BOOLEAN */
	if(ce->indirectCRL){
		strcpy(tmp,"        [4] indirectCRL: TRUE");
		strcat(tmp,RTN);
		i = strlen(tmp);
	
		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  (Cert) Extension CRL Distribution Point
-----------------------------------------*/
int get_genname_str(ExtGenNames *egn, char *buf,int max){
	unsigned char *cp;
	char *tmp=NULL,str[128],t2[64];
	int i,ret=0;

	*buf = 0;
	sprintf(t2,"          [%d] ",egn->type);
	i=strlen(t2);

	if(max <= i) goto max_end;
	strncpy(buf,t2,i+1);
	ret+=i;

	switch(egn->type){
	case 1:	/* rfc822Name (IA5String) */
	case 2:	/* dNSName (IA5String) */
	case 6:	/* uniformResourceIdentifier (IA5String) */
	case 8:	/* registeredID (OBJECT IDENTIFIER) */
		if((tmp=egn->name)==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CRL,ERR_PT_CRLEXTSTR+4,NULL);
			return -1;
		}
		break;

	case 4:	/* directoryName */
		if((tmp=Cert_subject_str((CertDN*)egn->name))==NULL)
			return -1;
		break;

	case 7:	/* iPAddress (OCTET STRING) */
		if((cp=(unsigned char*)egn->name)==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_X509CRL,ERR_PT_CRLEXTSTR+4,NULL);
			return -1;
		}
		for(*str=i=0;i<egn->name_len;i++){
			sprintf(t2,"%d.",cp[i]);
			strcat(str,t2);
		}
		tmp = str;
		break;

	case 0:	/* otherName */
		if((tmp=asn1_get_str(((OtherName*)egn->name)->name,&i))==NULL)
			return -1;

		if(((OtherName*)egn->name)->oid)
			switch_str(((OtherName*)egn->name)->oid,str);
		else
			strncpy(str,((OtherName*)egn->name)->oidc,32);
		strcat(str," : ");
		strncat(str,tmp,90);
		FREE(tmp); tmp = str;
		break;

	case 3:	/* x400Address */
	case 5:	/* ediPartyName */
		tmp = "..not supported..";
		break;
		/* not supported, but this one is necessary for certificate viewer.
		 OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_X509CRL,ERR_PT_CRLEXTSTR+4,NULL);
		 return -1;
		 */
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_X509CRL,ERR_PT_CRLEXTSTR+4,NULL);
		return -1;
	}	

	i = strlen(tmp);

	M_check_length_and_copy();

	strcpy(t2,RTN);
	i = strlen(RTN);
	if(max<=(ret+i)) goto max_end;
	strncat(buf,t2,i+1); ret+=i;

	if(egn->type==4) FREE(tmp);
	return ret;

max_end:
	strncat(buf,(tmp)?(tmp):(str),max-ret);
	if(egn->type==4) FREE(tmp);
	return max;
}

int get_gennames_str(ExtGenNames *egn,char *buf,int max){
	int j,ret=0;
	char tmp[256];

	*buf = 0;
	while(egn){
		if((j=get_genname_str(egn,tmp,254))<0) return -1;

		if(max <= ret+j) goto max_end;
		strncat(buf,tmp,j+1);
		ret+=j;

		egn=egn->next;
	}

	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

int get_reason_str(unsigned char *cp, char *buf, int max){
	char tmp[256],tmp2[32];
	int ret;

	*tmp=0;
	if(cp[0]&0x80)	strcat(tmp,"unused, ");
	if(cp[0]&0x40)	strcat(tmp,"keyCompromize, ");
	if(cp[0]&0x20)	strcat(tmp,"caCompromize, ");
	if(cp[0]&0x10)	strcat(tmp,"affiliationChanged, ");
	if(cp[0]&0x08)	strcat(tmp,"superseded, ");
	if(cp[0]&0x04)	strcat(tmp,"cessationOfOperation, ");
	if(cp[0]&0x02)	strcat(tmp,"certificateHold ");
	if(cp[0]&0x01)	strcat(tmp,"privilegeWithdrawn");
	if(cp[1]&0x80)	strcat(tmp,"aACompromise");

	sprintf(tmp2,"(0x%.2x%.2x)%s",cp[0],(0x80&cp[1]),RTN);
	strcat(tmp,tmp2);

	ret = strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}

int get_distpoint_str(DistPointName *dpn, char *buf, int max){
	char tmp[512],tmp2[482];
	int ret;

	*tmp=0;
	switch(dpn->FullorRDN){
	case 1:	/* fullName */
		sprintf(tmp,"          [0] fullName :%s",RTN);
		if(get_gennames_str(dpn->fullName,tmp2,480)<0) return -1;
		strcat(tmp,tmp2);
		break;
	case 2:	/* nameRelativeToCRLIssuer */
		sprintf(tmp,"          [1] nameRelativeToCRLIssuer :%s",RTN);
		break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_X509CRL,ERR_PT_CRLEXTSTR+5,NULL);
		return -1;
	}
	ret = strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}
