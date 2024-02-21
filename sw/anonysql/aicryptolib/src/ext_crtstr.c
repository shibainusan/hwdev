/* ext_crtstr.c */
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

char *ret_string(char *in,int *mv);

#define M_check_length_and_copy()	\
		if(max<=(ret+i)) goto max_end; \
		strncat(buf,tmp,i+1); ret+=i;


/*-----------------------------------------
  Extension Authority Key Identifier
-----------------------------------------*/
int Ext_authkey_str(CE_AuthKID *ce, char *buf, int max){
	char tmp[512],tmp2[64];
	int  i,ret=0;

	*buf = 0;
	/* keyIdentifier  [0] KeyIdentifier OPTIONAL */
	if(ce->keyid){
		strcpy(tmp,"        ");
		for(i=0;i<ce->klen;i++){
			sprintf(tmp2,"%.2x:",ce->keyid[i]);
			strcat(tmp,tmp2);
		}
		strcat(tmp,RTN);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	/* authorityCertIssuer  [1] GeneralNames OPTIONAL */
	if(ce->authorityCertIssuer){
		sprintf(tmp,"        GeneralNames :%s",RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

        if((i=get_gennames_str(ce->authorityCertIssuer,tmp,510))<0)
			return -1;

		M_check_length_and_copy();
	}
	/* authorityCertSerialNumber  [2] CertficateSerialNumber OPTIONAL */
	if(ce->slen){
		if(ce->long_sn){
			strcpy(tmp,"        SerialNum : ");
			for(i=0;i<ce->long_sn[1];i++){
				sprintf(tmp2,"%.2x:",ce->long_sn[i+2]);
				strcat(tmp,tmp2);
			}
			strcat(tmp,RTN);
		}else{
			sprintf(tmp,"        SerialNum : %.2d%s",ce->serialNum,RTN);
		}
		i = strlen(tmp);

		M_check_length_and_copy();
	}

	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

int Ext_sbjkey_str(CE_SbjKID *ce, char *buf, int max){
	char tmp[512],tmp2[64];
	int  i,ret=0;

	*buf = 0;
	if(ce->keyid==NULL) return -1;

	strcpy(tmp,"        ");
	for(i=0;i<ce->klen;i++){
		sprintf(tmp2,"%.2x:",ce->keyid[i]);
		strcat(tmp,tmp2);
	}
	strcat(tmp,RTN);

	ret = strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}

/*-----------------------------------------
  Extension Key Usage string
-----------------------------------------*/
int Ext_keyusage_str(CE_KUsage *ce, char *buf, int max){
	char tmp[256],tmp2[32],cp;
	int ret;

	*tmp = 0;
	cp = (char)ce->flag;

	if(cp&0x80)	strcat(tmp,"digitalSignature, ");
	if(cp&0x40)	strcat(tmp,"nonRepudiation, ");
	if(cp&0x20)	strcat(tmp,"keyEncipherment, ");
	if(cp&0x10)	strcat(tmp,"dataEncipherment, ");
	if(cp&0x08)	strcat(tmp,"keyAgreement, ");
	if(cp&0x04)	strcat(tmp,"keyCertSign, ");
	if(cp&0x02)	strcat(tmp,"cRLSign ");
	sprintf(tmp2,"(0x%.2x)%s",cp&0xfe,RTN);
	strcat(tmp,tmp2);

	ret=strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}

/*-----------------------------------------
  Extension Key Usage string
-----------------------------------------*/
int Ext_extkeyusage_str(CE_ExtKUsage *ce, char *buf, int max){
	int ret=0,i,j,id;
	char tmp[128],t2[64];

	*buf=0;
	for(j=0;j<16;j++){
		if(ce->keyPurposeId[j]){
			if(str2objid(ce->keyPurposeId[j],t2,32)<0) return -1;
			if((id=ASN1_object_2int(t2))<0) return -1;

			strcpy (tmp,"        ");
			strncat(tmp,ce->keyPurposeId[j],64);
			if(id){
				strcat(tmp," = ");
				switch_str(id,t2);
				strcat(tmp,t2);
			}
			strcat(tmp,RTN);
			i = strlen(tmp);

			M_check_length_and_copy();
		}
	}

	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  Extension Private Key Usage Period
-----------------------------------------*/
int Ext_prvkey_period_str(CE_PKUsagePrd *ce, char *buf, int max){
	char tmp[128];
	int ret=0,i;

	*buf=0;
	if(ce->notBefore.tm_year){ /* OPTIONAL */
		SNPRINTF (tmp,126,"        notBefore: %s%s",stm2str(&ce->notBefore,0),RTN);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	if(ce->notAfter.tm_year){ /* OPTIONAL */
		SNPRINTF (tmp,126,"        notAfter: %s%s",stm2str(&ce->notAfter,0),RTN);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  Extension Certificate Policies
-----------------------------------------*/
int get_polunotice_str(ExtPolUN *epu, char *buf){
	char tmp[32];
	int i;

	*buf=0;
	if(epu->organization){
		strcat (buf,"            organization : ");
		strncat(buf,epu->organization,200);
		strcat (buf,RTN);
		strcat (buf,"            noticeNumbers : ");
		for(i=0;i<4;i++){
			if(epu->noticeNumbers[i] != -1){
				sprintf(tmp,"%d, ",epu->noticeNumbers[i]); 
				strcat(buf,tmp);
			}
		}
		strcat (buf,RTN);
	}
	if(epu->explicitText){
		strcat (buf,"            explicitText : ");
		strncat(buf,epu->explicitText,200);
		strcat (buf,RTN);
	}
	return 0;
}

int get_polqualinfo_str(ExtPolInfo *epi, char *buf, int max){
	char tmp[512],tmp2[512],*str=NULL;
	int  i,ret=0;

	*buf=0;
	while(epi){
		strcpy(tmp,"          qualifierID = ");
		if(epi->qid){
			switch_str(epi->qid,tmp2);
			strcat(tmp,tmp2);
		}else{
			strncat(tmp,epi->qualifierID,128);
		}
		strcat(tmp,RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

		/* careful! qualifier is OPTIONAL */
		if(epi->qualifier){
			switch(epi->qid){
			default:
			case OBJ_PKIX_IDQT_CPS:
				SNPRINTF (tmp,510,"          qualifier = %s%s",epi->qualifier,RTN);
				break;
			case OBJ_PKIX_IDQT_UNOTICE:
				if(get_polunotice_str((ExtPolUN*)epi->qualifier,tmp2))
					return -1;
				SNPRINTF (tmp,510,"          qualifier :%s%s",RTN,tmp2);
				break;
			}
			i = strlen(tmp);

			M_check_length_and_copy();
		}

		epi=epi->next;
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

int Ext_certpol_str(CE_CertPol *ce, char *buf, int max){
	ExtCertPol *ecp;
	char tmp[512];
	int i,ret=0;

	*buf=0;
	for(ecp=ce->ecp;ecp;ecp=ecp->next){
		SNPRINTF (tmp,510,"        policyID = %s%s",ecp->policyID,RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

		/* careful! policyQualifiers is OPTIONAL. */
		if((i=get_polqualinfo_str(ecp->info,tmp,510))<0)
			return -1;
		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  Extension Policy Mapping
-----------------------------------------*/
int Ext_certpolmap_str(CE_PolMap *ce, char *buf, int max){
    char tmp[256];
    int  i,k,ret=0;

    *buf=0;
    for(k=0;k<ce->pnum;k++){
		/* issuer policy */
		SNPRINTF (tmp,254,"        issuerDomainPolicy : %s%s",
			ce->issuerDomainPolicy[k],RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

		/* subject domain policy */
		SNPRINTF (tmp,254,"        subjectDomainPolicy : %s%s",
			ce->subjectDomainPolicy[k],RTN);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  Extension Sbject or Issuer AltName
-----------------------------------------*/
int Ext_altname_str(CE_SbjAltName *ce, char *buf, int max){
	*buf=0;
	return get_gennames_str(ce->egn,buf,max);
}

/*-----------------------------------------
  Extension Basic Constraints
-----------------------------------------*/
int Ext_basiccons_str(CE_BasicCons *ce,char *buf, int max){
	char tmp[64],tmp2[32];
	int ret=0;

	sprintf(tmp,"CA:%s%s",(ce->ca)?("TRUE"):("FALSE"),RTN);

	strcat(tmp,"        PathLenConstraint:");
	if(ce->pathLen >= 0){
		sprintf(tmp2,"%.2x%s",ce->pathLen,RTN);
	}else{
		sprintf(tmp2,"NULL%s",RTN);
	}
	strcat(tmp,tmp2);

	ret=strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}

/*-----------------------------------------
  Extension Name Constraints
-----------------------------------------*/
int get_gensubtrees_str(ExtSubTrees *est, char *buf, int max){
	char tmp[256];
	int  i,ret=0;

	*buf=0;
	while(est){
		/* base */
		if(est->base){
			if((i=get_genname_str(est->base,tmp,254))<0) return -1;

			M_check_length_and_copy();
		}
		/* minimum [0] DEFAULT 0 */
		if(est->minimum >= 0){
			sprintf(tmp,"          min = %d%s",est->minimum,RTN);
			i = strlen(tmp);

			M_check_length_and_copy();
		}
		/* maximum [1] OPTIONAL */
		if(est->maximum >= 0){
			sprintf(tmp,"          max = %d%s",est->maximum,RTN);
			i = strlen(tmp);

			M_check_length_and_copy();
		}
		est=est->next;
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

int Ext_namecons_str(CE_NameCons *ce,char *buf,int max){
	char tmp[512];
	int i,ret=0;

    *buf=0;
	/* permittedSubtrees [0] OPTIONAL */
	if(ce->permittedSubtrees){ 
		sprintf(tmp,"        [0] permittedSubtrees:%s",RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

		if((i=get_gensubtrees_str(ce->permittedSubtrees,tmp,480))<0)
			return -1;

		M_check_length_and_copy();
	}
	/* excludedSubtrees [1] OPTIONAL */
	if(ce->excludedSubtrees){
		sprintf(tmp,"        [1] excludedSubtrees :%s",RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

		if((i=get_gensubtrees_str(ce->excludedSubtrees,tmp,480))<0)
			return -1;

		M_check_length_and_copy();
	}

	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  Extension Policy Constraints
-----------------------------------------*/
int Ext_polcons_str(CE_PolCons *ce, char *buf, int max){
	char tmp[128];
	int i,ret=0;

	*buf=0;
	/* requireExplicitPolicy [0] OPTIONAL */
	if(ce->requireExplicitPolicy >=0){ 
		sprintf(tmp,"        [0] requireExplicitPolicy : %d%s",ce->requireExplicitPolicy,RTN);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	/* inhibitPolicyMapping [1] OPTIONAL */
	if(ce->inhibitPolicyMapping >=0){
		sprintf(tmp,"        [1] inhibitPolicyMapping : %d%s",ce->inhibitPolicyMapping,RTN);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  Extension CRL Distribution Point
-----------------------------------------*/
/* support */
int Ext_crlpoint_str(CE_CRLDistPt *ce, char *buf, int max){
	char tmp[512],tmp2[482];
	int  i,k,ret=0;

	*buf=0;
	for(k=0;k<ce->pnum;k++){
		if(ce->distp[k].distp.FullorRDN){
			sprintf(tmp,"        [0] dist-point :%s",RTN);

			if((i=get_distpoint_str(&ce->distp[k].distp,tmp2,480))<0) 
				return -1;
			strcat(tmp,tmp2);
			i = strlen(tmp);
	
			M_check_length_and_copy();
		}
		if((ce->distp[k].flag[0])||(ce->distp[k].flag[1])){
			strcpy(tmp,"        [1] reasons :");

			if((i=get_reason_str(ce->distp[k].flag,tmp2,480))<0)
				return -1;
			strcat(tmp,tmp2);
			i = strlen(tmp);

			M_check_length_and_copy();
		}
		if(ce->distp[k].cRLIssuer){
			sprintf(tmp,"        [2] cRLIssuer :%s",RTN);

			if((i=get_gennames_str(ce->distp[k].cRLIssuer,tmp2,480))<0)
				return -1;
			strcat(tmp,tmp2);
			i = strlen(tmp);

			M_check_length_and_copy();
		}
	}

	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  PKIX Authoriay Information Access
-----------------------------------------*/
/* support */
int Ext_pkixaia_str(CE_AIA *aia, char *buf, int max){
	char tmp[256],tmp2[256];
	int  i,j,ret=0;

	*buf=0;
	for(j=0;j<aia->pnum;j++){
		sprintf(tmp,"        AccessDescription :%s",RTN);
		strcat (tmp,"          accessMethod : ");
		if(aia->adesc[j].oid)
			switch_str(aia->adesc[j].oid,tmp2);
		else
			strncpy(tmp2,aia->adesc[j].oidc,32);
		strncat(tmp,tmp2,32);
		strcat (tmp,RTN);
		i = strlen(tmp);

		M_check_length_and_copy();

		sprintf(tmp,"          accessLocation : %s",RTN);
		if(get_genname_str(aia->adesc[j].accessLocation,tmp2,230)<0)
			return -1;
		strcat(tmp,tmp2);
		i = strlen(tmp);

		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/*-----------------------------------------
  OCSP no check
-----------------------------------------*/
int Ext_ocspnochk_str(CertExt *onk, char *buf, int max){
	char tmp[256];
	int  i,ret=0;

	*buf=0;
	strcpy (tmp,"        NoCheck [ON]");
	strcat (tmp,RTN);
	i = strlen(tmp);

	M_check_length_and_copy();

	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

/* comment extension for NS, MOJ,... */
int Ext_comment_str(CE_Com *ce, char *buf, int max){
	strncpy(buf,ce->comment,max-4);
	strncat(buf,RTN,3);
	return strlen(buf);
}


/*-----------------------------------------
  Netscape Extensions
-----------------------------------------*/
int Ext_nscerttype_str(CE_NSType *ce, char *buf, int max){
	char tmp[128],tmp2[32],cp;
	int ret;

	cp = (char)ce->type;
	*tmp=0;
	if(cp&0x80)	strcat(tmp,"SSL client, ");
	if(cp&0x40)	strcat(tmp,"SSL server, ");
	if(cp&0x20)	strcat(tmp,"S/MIME, ");
	if(cp&0x10)	strcat(tmp,"Obj-Sign, ");
	if(cp&0x04)	strcat(tmp,"SSL CA, ");
	if(cp&0x02)	strcat(tmp,"S/MIME CA, ");
	if(cp&0x01)	strcat(tmp,"Obj-Sign CA ");
	sprintf(tmp2,"(0x%.2x)%s",(unsigned char)cp,RTN);
	strcat(tmp,tmp2);

	ret=strlen(tmp);
	if(max <= ret) ret=max-1;

	strncpy(buf,tmp,ret+1);

	return ret;
}

/*-----------------------------------------
  snprintf...
-----------------------------------------*/
#ifndef HAVE_SNPRINTF
int my_snprintf( char *buffer, size_t count, const char *format, ...){
	FILE *fp;
	va_list args;
	char *buf=NULL;
	int len,ret=-1;

	va_start(args, format);
	if ((fp = fopen("/dev/null","w")) == NULL) return -1;
	if ((len= fprintf(fp,buffer,args)) == -1) goto done;

	if ((buf= MALLOC(len+2))==NULL) goto done;
	if ((len= sprintf(buf,args))== -1) goto done;

	if(count>(unsigned)len){
		strncpy(buffer,buf,count);
	}else{
		memcpy (buffer,buf,count);
	}
done:
	va_end(args);
	if(buf) FREE(buf);
	fclose(fp);
	return ret;
}
#endif
