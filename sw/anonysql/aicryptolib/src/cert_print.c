/* cert_print.c */
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

#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_x509ext.h"
#include "ok_rsa.h"

char *dir_t[10]={
    "C","ST","L","O","OU","CN","","","","EMAIL"};

void print_dn(CertDN *dn);
void print_sig_algo(int algo);
void print_serialnum(Cert *ct);
void print_validity(Cert *ct);
void print_pubkey(Cert *ct);
void print_pubkey_algo(Cert *ct);
void print_v3_extensions(CertExt *top,int cf);
void print_signature(unsigned char *sig, int max, int algo);

/*-----------------------------------------
  print Cert struct
-----------------------------------------*/
void Cert_print(Cert *ct){
	if(ct==NULL) return;

	if(ct->issuer){
		printf("issuer: ");
		print_dn(&(ct->issuer_dn));
		printf("subject: ");
		print_dn(&(ct->subject_dn));
		printf("serial: %d\n",ct->serialNumber);

		printf("Certificate:\n");
	}else
		printf("Certificate Request:\n");

	printf("  Data:\n");
	printf("    Version: %d (0x%x)\n",ct->version+1,ct->version);

	if(ct->issuer){
		print_serialnum(ct);

		printf("    Signature Algorithm: ");
		print_sig_algo(ct->signature_algo);

		printf("    Issuer: %s\n",ct->issuer);
		print_validity(ct);
	}
	printf("    Subject: %s\n",ct->subject);
	print_pubkey(ct);

	if(ct->ext) print_v3_extensions(ct->ext,(ct->issuer)?(0):(1));
	print_signature(ct->signature,ct->siglen,ct->signature_algo);
}

void print_serialnum(Cert *ct){
	int i;
	if(ct->long_sn){
		printf("    Serial Number: ");
		for(i=0;i<ct->long_sn[1];i++) printf("%.2x:",ct->long_sn[i+2]);
		printf("\n");
	}else{
		printf("    Serial Number: %d (0x%x)\n",ct->serialNumber,ct->serialNumber);	
	}
}

void print_dn(CertDN *dn){
	int i,j;
	for(i=0;i<dn->num;i++){
		j = dn->rdn[i].tagoid;
		if((OBJ_DIR_C<=j)&&(j<=OBJ_DIR_CN)){
			printf("/");
			printf(dir_t[j-OBJ_DIR_C]);
			printf("=");
			printf(dn->rdn[i].tag);
		}else if(j==OBJ_DIR_EMAIL){
			printf("/EMAIL=");
			printf(dn->rdn[i].tag);
		}else{
			printf("/\?\?=");
			printf(dn->rdn[i].tag);
		}
	}
	printf("\n");
}

void print_sig_algo(int algo){
	switch(algo){
	case OBJ_SIG_MD2RSA:
	case OBJ_SIGOIW_MD2RSA:
		printf("md2WithRSAEncryption\n");
		break;
	case OBJ_SIG_MD5RSA:
	case OBJ_SIGOIW_MD5RSA:
		printf("md5WithRSAEncryption\n");
		break;
	case OBJ_SIG_SHA1RSA:
	case OBJ_SIGOIW_SHA1RSA:
		printf("SHA1WithRSAEncryption\n");
		break;
	case OBJ_SIG_SHA1DSA:
		printf("SHA1WithDSAEncryption\n");
		break;
	case OBJ_SIG_SHA1ECDSA:
		printf("SHA1WithECDSAEncryption\n");
		break;
	default:
		printf("\n");
		break;
	}
}

void print_validity(Cert *ct){
	char *cp;

	printf("    Validity\n");
	if((cp=stm2str(&ct->time.notBefore,0))==NULL) return;
	printf("      Not Before: %s\n",cp);
	if((cp=stm2str(&ct->time.notAfter,0))==NULL) return;
	printf("      Not After : %s\n",cp);
}

void print_pubkey(Cert *ct){
	Pubkey_ECDSA *ek;
	char num[32];
	int bit = ct->pubkey->size*8;

	printf("    Subject Public Key Info:\n");
	print_pubkey_algo(ct);
	switch(ct->pubkey_algo){
	case KEY_RSA_PUB:
		printf("      RSA Public Key: (%d bit)\n",bit);
		printf("        Modulus (%d bit):\n",bit);
		LN_print2(((Pubkey_RSA*)ct->pubkey)->n,10);
		printf("        Exponent:\n");
		LN_print2(((Pubkey_RSA*)ct->pubkey)->e,10);
		break;
	case KEY_DSA_PUB:
		printf("      DSA Public Key: \n");
		printf("        Parameters (%d bit):\n",bit);
		printf("        P :\n");
		LN_print2(((Pubkey_DSA*)ct->pubkey)->pm->p,10);
		printf("        Q :\n");
		LN_print2(((Pubkey_DSA*)ct->pubkey)->pm->q,10);
		printf("        G :\n");
		LN_print2(((Pubkey_DSA*)ct->pubkey)->pm->g,10);
		printf("        Public key w:\n");
		LN_print2(((Pubkey_DSA*)ct->pubkey)->w,10);
		break;
	case KEY_ECDSA_PUB:
		ek =(Pubkey_ECDSA*)ct->pubkey;
		printf("        Elliptic Curve Parameters: \n");

		if((ek->E->curve_type != ECP_ORG_primeParam) &&
		   (ek->E->curve_type != ECP_ORG_char2Param)){
			switch_str(ek->E->curve_type,num);
			printf("        prime-field (Prime-p):\n");
			printf("          %s\n",num);
		}else{
			printf("        FieldID : ");
			switch(ek->E->type){
			case OBJ_X962_FT_PRIME: 
			  printf(" prime-field (Prime-p):\n");
			  LN_print2(ek->E->p,10);
			  break;
			case OBJ_X962_FT_CHR2:
			  printf(" characteristic-two-field\n");
			  break;
			}
			/* curve */
			printf("        Curve :\n");
			printf("        a :\n");
			LN_print2(ek->E->a,10);
			printf("        b :\n");
			LN_print2(ek->E->b,10);

			/* base */
			printf("        Base point G :\n");
			printf("        G.x :\n");
			LN_print2(ek->E->G->x,10);
			printf("        G.y :\n");
			LN_print2(ek->E->G->y,10);

			/* order */
			printf("        order of base point (n):\n");
			LN_print2(ek->E->n,10);

			/* cofactor */
			if(ek->E->h->top){
			  printf("        cofactor ( h = #E(F)/n ) :\n");
			  LN_print2(ek->E->h,10);
			}
		}
		/* curve */
		printf("        ECDSA Public Key W:\n");
		printf("        W.x :\n");
		LN_print2(ek->W->x,10);
		printf("        W.y :\n");
		LN_print2(ek->W->y,10);
		break;
	}
}

void print_pubkey_algo(Cert *ct){
	printf("      Public Key Algorithm: ");
	switch(ct->pubkey_algo){
	case KEY_RSA_PUB: printf("rsaEncryption\n"); break;
	case KEY_DSA_PUB: printf("dsaEncryption\n"); break;
	case KEY_ECDSA_PUB: printf("ecdsaEncryption\n"); break;
	}
}

void print_v3_extensions(CertExt *top, int cf){
	unsigned char *cp;
	CertExt *ext,*e2;
	char  *cs,*str,buf[512];
	int	i;

	switch(cf){
	case 1:  printf("    PKCS#10 Attributes:\n");break;
	case 2:  printf("    X509 CRL extensions:\n");break;
	case 3:  printf("        crlEntryExtensions:\n");break;
	case 4:  break;
	default: printf("    X509v3 extensions:\n");break;
	}

	for(ext=top;ext!=NULL;ext=ext->next){
		cp = ext->der;
		cs = (ext->critical)?("[critical]"):("");
		switch(ext->extnID){
		case OBJ_X509v3_BASIC:
			Ext_basiccons_str((CE_BasicCons*)ext,buf,510);
			printf("      x509 Basic Constraints:%s\n        %s",cs,buf);
			break;
		case OBJ_X509v3_NameConst:
			Ext_namecons_str((CE_NameCons*)ext,buf,510);
			printf("      x509 Name Constraints:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_PolicyConst:
			Ext_polcons_str((CE_PolCons*)ext,buf,510);
			printf("      x509 Policy Constraints:%s\n%s",cs,buf);
			break;

		case OBJ_X509v3_SbjKeyIdt:
			printf("      x509 Subject Key Identifier:%s\n        ",cs);
			for(i=2;i<cp[1]+2;i++)
				printf("%.2x:",cp[i]);
			printf("\n");
			break;
		case OBJ_X509v3_AuthKeyIdt:
			Ext_authkey_str((CE_AuthKID*)ext,buf,510);
			printf("      x509 Authority Key Identifier:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_KEY_Usage:
			Ext_keyusage_str((CE_KUsage*)ext,buf,510);
			printf("      x509 Key Usage:%s\n        %s",cs,buf);
			break;
		case OBJ_X509v3_ExtKeyUsage:
			Ext_extkeyusage_str((CE_ExtKUsage*)ext,buf,510);
			printf("      x509 Ext Key Usage:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_PrvKeyUsgPrd:
			Ext_prvkey_period_str((CE_PKUsagePrd*)ext,buf,510);
			printf("      x509 PrivateKey Usage Period:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_CERT_Pol:
			Ext_certpol_str((CE_CertPol*)ext,buf,510);
			printf("      x509 Certificate Policies:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_CertPolMap:
			Ext_certpolmap_str((CE_PolMap*)ext,buf,510);
			printf("      x509 Policy Mappings:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_SbjAltName:
			Ext_altname_str((CE_SbjAltName*)ext,buf,510);
			printf("      x509 Subject Alt Name:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_IssAltName:
			Ext_altname_str((CE_IssAltName*)ext,buf,510);
			printf("      x509 Issuer Alt Name:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_CRL_Point:
			Ext_crlpoint_str((CE_CRLDistPt*)ext,buf,510);
			printf("      x509 CRL Distribution Points:%s\n%s",cs,buf);
			break;

		/***** CRL Extensions *****/
		case OBJ_X509v3_CRLNumber:
			Ext_crlnum_str((CE_CRLNum*)ext,buf,510);
			printf("      x509 CRL Number:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_IssDistPoint:
			Ext_issdistpt_str((CE_IssDistPt*)ext,buf,510);
			printf("      x509 Issuer Distribution Points:%s\n%s",cs,buf);
			break;
		case OBJ_X509v3_CRLReason: /* CRL entryExtension */
			Ext_reasoncode_str((CE_Reason*)ext,buf,510);
			printf("        reasonCode: %s",buf);
			break;

		/***** pkix aia *****/
		case OBJ_PKIX_IDPE_AIA: /* CRL entryExtension */
			Ext_pkixaia_str((CE_AIA*)ext,buf,510);
			printf("       pkix-idpe-AuthInfoAccess: %s\n%s",cs,buf);
			break;

		/***** pkix ocsp *****/
		case OBJ_PKIX_OCSP_NOCHECK:
			Ext_ocspnochk_str(ext,buf,510);
			printf("      pkix-ocsp-nocheck: %s\n%s",cs,buf);
			break;

		/***** moj extensions *****/
		case OBJ_MOJ_JCertPol:
			Ext_certpol_str((CE_JCertPol*)ext,buf,510);
			printf("      MOJ JCertificate Policies:%s\n%s",cs,buf);
			break;
		case OBJ_MOJ_Registrar:
			Ext_comment_str((CE_Com*)ext,buf,510);
			printf("      MOJ Registrar:%s\n        %s\n",cs,buf);
			break;
		case OBJ_MOJ_RegCoInfo:
			Ext_mojcorpinfo_str((CE_MOJCoInfo*)ext,buf,510);
			printf("      MOJ RegistCorpInfo:%s\n%s\n",cs,buf);
			break;

		/***** Netscape Extensions *****/
		case OBJ_NS_CERT_CRLURL:
			Ext_comment_str((CE_Com*)ext,buf,510);
			printf("      Netscape CA Revocation Url:%s\n        %s",cs,buf);
			break;
		case OBJ_NS_CERT_COMMENT:
			Ext_comment_str((CE_Com*)ext,buf,510);
			printf("      Netscape Comment:%s\n        %s",cs,buf);
			break;
		case OBJ_NS_CERT_TYPE:
			Ext_nscerttype_str((CE_NSType*)ext,buf,510);
			printf("      Netscape Cert Type:%s\n        %s",cs,buf);
			break;

		/***** CSR (PKCS#10) Attribute *****/
		case OBJ_P9_CHALL_PWD:
			str=asn1_get_str(cp,&i);
			printf("      PKCS#9 Challenge Password:\n        %s\n",str);
			FREE(str);
			break;
		case OBJ_P9_UNST_NAME:
			str=asn1_get_str(cp,&i);
			printf("      PKCS#9 Unstructured Name:\n        %s\n",str);
			FREE(str);
			break;

		case OBJ_P9_EXT_REQ:
			printf("      PKCS#9 X.509v3 Extension request {\n");
			if((e2=asn1_get_exts(cp,&i))==NULL){
				printf("        decode error!\n");
			}else{
				print_v3_extensions(e2, 4);
			}
			printf("      }\n");
			break;

		/***** Unknown or Unsupported Extensions *****/
		case 0:
		default:
			{
				char buf[64];

				if(ext->extnID==0)
					objid2str(ext->objid,buf,62);
				else if((ext->extnID>3000)&&(ext->extnID<10000))
					switch_str(ext->extnID,buf);
				else
					break;
				printf("      %s:%s\n        ",buf,cs);

				for(i=0;i<ext->dlen;i++){
					printf("%.2x:",cp[i]);
					if((i%16)==15)printf("\n        ");
				}
				printf("\n");
				break;
			}
	    }
	}
}

void print_signature(unsigned char *sig, int max, int algo){
	int	i,j;

	if(algo){
		printf("  Signature Algorithm: ");
		print_sig_algo(algo);
	}else{
		printf("  Signature:\n");
	}

	for(i=0;i<max;i++){
		if(!(j=i%18)) printf("    ");
		printf("%.2x:",sig[i]);
		if(j==17) printf("\n");
	}
	printf("\n");
}

