/* asn1_print.c */
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

/*-----------------------------------------------
  print ASN.1 length binary
-----------------------------------------------*/
int ASN1_print_length_bin(unsigned char *in,int *mv){
	int i,len,octet;

	len = ASN1_length(in,mv);
	if(0x80 & *in){
	  octet = (unsigned char)(0x7f & *in);
	  for(i=0;i<=octet;i++)
	    printf(" %.2x",in[i]);
	}else{
	  printf(" %.2x",*in);
	}
	return(len);
}

/*-----------------------------------------------
   print ASN.1 INTEGER (long)
-----------------------------------------------*/
void ASN1_print_integer(unsigned char *in,int *mv){
	int	i,len,ptm;
	long	integer;

	if(*in == ASN1_INTEGER){
	  printf("INTEGER [%.2x",*in);
	}else if(*in == ASN1_ENUMERATED){
	  printf("ENUMERATED [%.2x",*in);
	}

	integer=ASN1_integer(in,mv);
  
	len = ASN1_print_length_bin((++in),&ptm);
	in += ptm;
	for(i=0;i<len;i++)
	  printf(" %.2x",in[i]);

	printf("] int=%d\n",integer);
}

/*-----------------------------------------------
   print ASN.1 OBJECT IDENTIFIER
-----------------------------------------------*/
void switch_str(int obj,char *sb){
  switch(obj){
    case OBJ_DIR_C:		strcpy(sb,"C"); break;
    case OBJ_DIR_ST:	strcpy(sb,"ST"); break;
    case OBJ_DIR_L:		strcpy(sb,"L"); break;
    case OBJ_DIR_O:		strcpy(sb,"O"); break;
    case OBJ_DIR_OU:	strcpy(sb,"OU"); break;
    case OBJ_DIR_CN:	strcpy(sb,"CN"); break;
    case OBJ_DIR_EMAIL:	strcpy(sb,"EMAIL"); break; /* = OBJ_P9_EMAIL */

  /* X.509 v3 Extention */
    case OBJ_X509v3_SubDirAtt:
      strcpy(sb,"x509v3SubjectDirectoryAttributes"); break;
    case OBJ_X509v3_SbjKeyIdt:
      strcpy(sb,"x509v3SubjectKeyIdentifier"); break;
    case OBJ_X509v3_KEY_Usage:
      strcpy(sb,"x509v3KeyUsage"); break;
    case OBJ_X509v3_PrvKeyUsgPrd:
      strcpy(sb,"x509v3PrivateKeyUsagePeriod"); break;
    case OBJ_X509v3_SbjAltName:
      strcpy(sb,"x509v3SubjectAlternativeName"); break;
    case OBJ_X509v3_IssAltName:
      strcpy(sb,"x509v3IssuerAlternativeNames"); break;
    case OBJ_X509v3_BASIC:
      strcpy(sb,"x509v3BasicConstraints"); break;
    case OBJ_X509v3_CRLNumber:
      strcpy(sb,"x509v3CRLNumber"); break;
    case OBJ_X509v3_CRLReason:
      strcpy(sb,"x509v3ReasonCode"); break;
    case OBJ_X509v3_HoldInsCode:
      strcpy(sb,"x509v3HoldInstructionCode"); break;
    case OBJ_X509v3_InvalData:
      strcpy(sb,"x509v3InvalidityDate"); break;
    case OBJ_X509v3_DeltaCRLInd:
      strcpy(sb,"x509v3DeltaCRLIndicator"); break;
    case OBJ_X509v3_IssDistPoint:
      strcpy(sb,"x509v3IssuingDistributionPoint"); break;
    case OBJ_X509v3_CertIssuer:
      strcpy(sb,"x509v3CertificateIssuer"); break;
    case OBJ_X509v3_NameConst:
      strcpy(sb,"x509v3NameConstraints"); break;
    case OBJ_X509v3_CRL_Point:
      strcpy(sb,"x509v3CRLDistributionPoints"); break;
    case OBJ_X509v3_CERT_Pol:
      strcpy(sb,"x509v3CertPolicies"); break;
    case OBJ_X509v3_CertPolMap:
      strcpy(sb,"x509v3PolicyMappings"); break;
    case OBJ_X509v3_AuthKeyIdt:
      strcpy(sb,"x509v3AuthorityKeyIdentifier"); break;
    case OBJ_X509v3_PolicyConst:
      strcpy(sb,"x509v3PolicyConstraints"); break;
    case OBJ_X509v3_ExtKeyUsage:
      strcpy(sb,"x509v3ExtendedKeyUsageField"); break;

    case OBJ_CRYPT_RSA:
      strcpy(sb,"rsaEncryption"); break;
    case OBJ_CRYPT_DSA:
      strcpy(sb,"dsaEncryption"); break;
	case OBJ_CRYPT_ECDSA:
      strcpy(sb,"ecdsaEncryption"); break;
    case OBJ_SIG_MD2RSA:
    case OBJ_SIGOIW_MD2RSA:
      strcpy(sb,"md2WithRSAEncryption"); break;
    case OBJ_SIG_MD5RSA:
    case OBJ_SIGOIW_MD5RSA:
      strcpy(sb,"md5WithRSAEncryption"); break;
    case OBJ_SIG_SHA1RSA:
    case OBJ_SIGOIW_SHA1RSA:
      strcpy(sb,"sha1WithRSAEncryption"); break;
    case OBJ_SIG_SHA1DSA:
      strcpy(sb,"sha1WithDSAEncryption"); break;
    case OBJ_SIG_SHA1ECDSA:
      strcpy(sb,"sha1WithECDSAEncryption"); break;

    case OBJ_HASH_MD2:
      strcpy(sb,"Thumbprint-MD2"); break;
    case OBJ_HASH_MD5:
      strcpy(sb,"Thumbprint-MD5"); break;
    case OBJ_HASH_SHA1:
      strcpy(sb,"Thumbprint-SHA1"); break;

    case OBJ_CRYALGO_DESECB:
      strcpy(sb,"DES-ECB"); break;
    case OBJ_CRYALGO_DESCBC:
      strcpy(sb,"DES-CBC"); break;

    case OBJ_CRYALGO_RC2CBC:
      strcpy(sb,"RC2-CBC"); break;
    case OBJ_CRYALGO_RC4CBC:
      strcpy(sb,"RC4-CBC"); break;
    case OBJ_CRYALGO_3DESCBC:
      strcpy(sb,"DES-EDE3-CBC"); break;
    case OBJ_CRYALGO_RC5CBC:
      strcpy(sb,"RC5-CBC"); break;
    case OBJ_CRYALGO_DESCDMF:
      strcpy(sb,"DES-CDMF"); break;

    case OBJ_P7_DATA:
      strcpy(sb,"PKCS7-Data"); break;
    case OBJ_P7_SIGNED:
      strcpy(sb,"PKCS7-Signed"); break;
    case OBJ_P7_ENVELP:
      strcpy(sb,"PKCS7-Envelope"); break;
    case OBJ_P7_SIGandENV:
      strcpy(sb,"PKCS7-SIGandEnv"); break;
    case OBJ_P7_DIGESTED:
      strcpy(sb,"PKCS7-Digested"); break;
    case OBJ_P7_ENCRYPTED:
      strcpy(sb,"PKCS7-Encrypted"); break;

/*	case OBJ_P9_EMAIL: 
		strcpy(sb,"PKCS9-EMAIL"); break;*/
	case OBJ_P9_UNST_NAME:
		strcpy(sb,"PKCS9-unstructuredName"); break;
	case OBJ_P9_CONTENT_TYPE:
		strcpy(sb,"PKCS9-contentType"); break;
	case OBJ_P9_MESS_DGST:
		strcpy(sb,"PKCS9-messageDigest"); break;
	case OBJ_P9_SIGN_TIME:
		strcpy(sb,"PKCS9-signingTime"); break;
	case OBJ_P9_COUNT_SIG:
		strcpy(sb,"PKCS9-counterSignature"); break;
	case OBJ_P9_CHALL_PWD:
		strcpy(sb,"PKCS9-challengePassword"); break;
	case OBJ_P9_UNST_ADRS:
		strcpy(sb,"PKCS9-unstructuredAddress"); break;
	case OBJ_P9_EXT_CERT_ATT:
		strcpy(sb,"PKCS9-extendedCertificateAttributes"); break;
	case OBJ_P9_ISS_SN:
		strcpy(sb,"PKCS9-at-issuerAndSerialNumber"); break;
	case OBJ_P9_PASSCHECK:
		strcpy(sb,"PKCS9-at-passwordCheck"); break;
	case OBJ_P9_PUBKEY:
		strcpy(sb,"PKCS9-at-publicKey"); break;
	case OBJ_P9_SIG_DESCR:
		strcpy(sb,"PKCS9-at-signingDescription"); break;
	case OBJ_P9_EXT_REQ:
		strcpy(sb,"PKCS9-at-extensionRequest"); break;
	case OBJ_P9_SMIME_CAP:
		strcpy(sb,"PKCS9-at-smimeCapabilities"); break;

	case OBJ_P9_SMIME:
		strcpy(sb,"PKCS9-smime"); break;
	case OBJ_P9_CERT_TYPES:
		strcpy(sb,"PKCS9-certTypes"); break;
	case OBJ_P9_CRL_TYPES:
		strcpy(sb,"PKCS9-crlTypes"); break;

    case OBJ_P9_Friendly:
      strcpy(sb,"PKCS9-FriendlyName"); break;
    case OBJ_P9_LocalKEY:
      strcpy(sb,"PKCS9-LocalKeyID"); break;

    case OBJ_P9_X509CERT:
      strcpy(sb,"PKCS9-x509Cert"); break;
    case OBJ_P9_sdsiCERT:
      strcpy(sb,"PKCS9-sdsiCert"); break;
    case OBJ_P9_X509CRL:
      strcpy(sb,"PKCS9-x509CRL"); break;

    case OBJ_P5_MD2DES:
      strcpy(sb,"PKCS5-Pbe-MD2DES"); break;
    case OBJ_P5_MD2RC2:
      strcpy(sb,"PKCS5-Pbe-MD2RC2"); break;
    case OBJ_P5_MD5DES:
      strcpy(sb,"PKCS5-Pbe-MD5DES"); break;
    case OBJ_P5_MD5RC2:
      strcpy(sb,"PKCS5-Pbe-MD5RC2"); break;
    case OBJ_P5_SHA1DES:
      strcpy(sb,"PKCS5-Pbe-SHA1DES"); break;
    case OBJ_P5_SHA1RC2:
      strcpy(sb,"PKCS5-Pbe-SHA1RC2"); break;

    case OBJ_P12Pbe_128RC4:
      strcpy(sb,"PKCS12-Pbe-128RC4"); break;
    case OBJ_P12Pbe_40RC4:
      strcpy(sb,"PKCS12-Pbe-40RC4"); break;
    case OBJ_P12Pbe_3K3DES:
      strcpy(sb,"PKCS12-Pbe-3Key3DES"); break;
    case OBJ_P12Pbe_2K3DES:
      strcpy(sb,"PKCS12-Pbe-2Key3DES"); break;
    case OBJ_P12Pbe_128RC2:
      strcpy(sb,"PKCS12-Pbe-128RC2"); break;
    case OBJ_P12Pbe_40RC2:
      strcpy(sb,"PKCS12-Pbe-40RC2"); break;

    case OBJ_P12v1Bag_KEY:
      strcpy(sb,"PKCS12v1-BagID-Key"); break;
    case OBJ_P12v1Bag_PKCS8:
      strcpy(sb,"PKCS12v1-BagID-PKCS8"); break;      
    case OBJ_P12v1Bag_CERT:
      strcpy(sb,"PKCS12v1-BagID-CERT"); break;
    case OBJ_P12v1Bag_CRL:
      strcpy(sb,"PKCS12v1-BagID-CRL"); break;
    case OBJ_P12v1Bag_SECRET:
      strcpy(sb,"PKCS12v1-BagID-SECLET"); break;
    case OBJ_P12v1Bag_SAFE:
      strcpy(sb,"PKCS12v1-BagID-SAFE"); break;

    case OBJ_NS_CERT_TYPE:
      strcpy(sb,"Netscape-CertType"); break;
    case OBJ_NS_CERT_BASE:
      strcpy(sb,"Netscape-Base"); break;
    case OBJ_NS_CERT_POLICY:
      strcpy(sb,"Netscape-POLICY"); break;
    case OBJ_NS_CERT_CRLURL:
      strcpy(sb,"Netscape-CRL-URL"); break;
    case OBJ_NS_CERT_COMMENT:
      strcpy(sb,"Netscape-Comment"); break;

	case OBJ_MOJ_JCertPol:
	  strcpy(sb,"MOJ-JCertificatePolicy"); break;
	case OBJ_MOJ_Registrar:
	  strcpy(sb,"MOJ-Registrar"); break;
	case OBJ_MOJ_RegCoInfo:
	  strcpy(sb,"MOJ-RegistCorpInformation"); break;

	case OBJ_PKIX_IDPE_AIA:
	  strcpy(sb,"pkix-id-pe AuthInfoAccess"); break;
	case OBJ_PKIX_IDAD_OCSP:
	  strcpy(sb,"id-ad ocsp"); break;
	case OBJ_PKIX_IDAD_CAISS:
	  strcpy(sb,"id-ad caIssuers"); break;
	case OBJ_PKIX_IDAD_TMSTAMP:
	  strcpy(sb,"id-ad timeStamp"); break;
	case OBJ_PKIX_IDAD_DVCS:
	  strcpy(sb,"id-ad dvcs"); break;
	case OBJ_PKIX_IDAD_CAREPS:
	  strcpy(sb,"id-ad caRepository"); break;

	case OBJ_PKIX_IDQT_CPS:
	  strcpy(sb,"pkix-id-qt CPSurl"); break;
	case OBJ_PKIX_IDQT_UNOTICE:
	  strcpy(sb,"pkix-id-qt UserNotice"); break;

	case OBJ_PKIX_IDKP_SVAUTH: /* extended key usage */
	  strcpy(sb,"PKIX-IDKP-ServerAuth"); break;
	case OBJ_PKIX_IDKP_CLAUTH:
	  strcpy(sb,"PKIX-IDKP-ClientAuth"); break;
	case OBJ_PKIX_IDKP_CDSIGN:
	  strcpy(sb,"PKIX-IDKP-CodeSigning"); break;
	case OBJ_PKIX_IDKP_EMAIL:
	  strcpy(sb,"PKIX-IDKP-EmailProtection"); break;
	case OBJ_PKIX_IDKP_IPSEC_ES:
	  strcpy(sb,"PKIX-IDKP-IPSec-EndSystem"); break;
	case OBJ_PKIX_IDKP_IPSEC_TN:
	  strcpy(sb,"PKIX-IDKP-IPSec-Tunnel"); break;
	case OBJ_PKIX_IDKP_IPSEC_US:
	  strcpy(sb,"PKIX-IDKP-IPSec-User"); break;
	case OBJ_PKIX_IDKP_TMSTAMP:
	  strcpy(sb,"PKIX-IDKP-TimeStamp"); break;
	case OBJ_PKIX_IDKP_OCSPSIGN:
	  strcpy(sb,"PKIX-IDKP-OCSPSigning"); break;

	case OBJ_PKIX_OCSP_BASIC:
	  strcpy(sb,"id-pkix-ocsp-basic"); break;
	case OBJ_PKIX_OCSP_NONCE:
	  strcpy(sb,"id-pkix-ocsp-nonce"); break;
	case OBJ_PKIX_OCSP_CRL:
	  strcpy(sb,"id-pkix-ocsp-crl"); break;
	case OBJ_PKIX_OCSP_RESPONSE:
	  strcpy(sb,"id-pkix-ocsp-response"); break;
	case OBJ_PKIX_OCSP_NOCHECK:
	  strcpy(sb,"id-pkix-ocsp-nocheck"); break;
	case OBJ_PKIX_OCSP_ARCHIVE:
	  strcpy(sb,"id-pkix-ocsp-archive-cutoff"); break;
	case OBJ_PKIX_OCSP_SERVICE:
	  strcpy(sb,"id-pkix-ocsp-service-locator"); break;

	case OBJ_PKIX_IDIT_CAPROT: /* CMP */
	  strcpy(sb,"PKIX-IDIT-CAProtEncCert"); break;
	case OBJ_PKIX_IDIT_SIGNKEY:
	  strcpy(sb,"PKIX-IDIT-SignKeyPairTypes"); break;
	case OBJ_PKIX_IDIT_ENCKEY:
	  strcpy(sb,"PKIX-IDIT-EncKeyPairTypes"); break;
	case OBJ_PKIX_IDIT_PREFSYM:
	  strcpy(sb,"PKIX-IDIT-PreferredSymmAlg"); break;
	case OBJ_PKIX_IDIT_CAKEYUPD:
	  strcpy(sb,"PKIX-IDIT-CAKeyUpdateInfo"); break;
	case OBJ_PKIX_IDIT_CURCRL:
	  strcpy(sb,"PKIX-IDIT-CurrentCRL"); break;
	case OBJ_PKIX_IDIT_UNSPOID:
	  strcpy(sb,"PKIX-IDIT-unsupportedOIDs"); break;
	case OBJ_PKIX_IDIT_KEYPREQ:
	  strcpy(sb,"PKIX-IDIT-keyPairParamReq"); break;
	case OBJ_PKIX_IDIT_KEYPREP:
	  strcpy(sb,"PKIX-IDIT-keyPairParamRep"); break;
	case OBJ_PKIX_IDIT_REVPASS:
	  strcpy(sb,"PKIX-IDIT-revPassphrase"); break;
	case OBJ_PKIX_IDIT_IMPCONF:
	  strcpy(sb,"PKIX-IDIT-implicitConfirm"); break;
	case OBJ_PKIX_IDIT_CWAITTIME:
	  strcpy(sb,"PKIX-IDIT-confirmWaitTime"); break;
	case OBJ_PKIX_IDIT_PKIMESS:
	  strcpy(sb,"PKIX-IDIT-origPKIMessage"); break;

	case OBJ_MS_EU_LSTSIG: /* Microsoft extended key usage */
	  strcpy(sb,"Microsoft-CertTrustListSigning"); break;
	case OBJ_MS_EU_SGC:
	  strcpy(sb,"Microsoft-ServerGatedCrypto"); break;
	case OBJ_MS_EU_ENCFSYS:
	  strcpy(sb,"Microsoft-EncFileSystem"); break;
	case OBJ_MS_EU_ICLOGON:
	  strcpy(sb,"Microsoft-SmartCardLogon"); break;
	case OBJ_MS_GN_UPN:
	  strcpy(sb,"UPN"); break;

	case OBJ_X962_FT_PRIME:
	  strcpy(sb,"X9.62 fieldType prime"); break;
	case OBJ_X962_FT_CHR2:
	  strcpy(sb,"X9.62 fieldType char-2"); break;

	case OBJ_X962_prime192v1:
	  strcpy(sb,"X9.62 curve prime192v1"); break;
	case OBJ_X962_prime192v2:
	  strcpy(sb,"X9.62 curve prime192v2"); break;
	case OBJ_X962_prime192v3:
	  strcpy(sb,"X9.62 curve prime192v3"); break;
	case OBJ_X962_prime239v1:
	  strcpy(sb,"X9.62 curve prime239v1"); break;
	case OBJ_X962_prime239v2:
	  strcpy(sb,"X9.62 curve prime239v2"); break;
	case OBJ_X962_prime239v3:
	  strcpy(sb,"X9.62 curve prime239v3"); break;
	case OBJ_X962_prime256v1:
	  strcpy(sb,"X9.62 curve prime256v1"); break;

	default:
	  strcpy(sb,"unknown");
	}
}

/*-----------------------------------------------
   print ASN.1 OBJECT IDENTIFIER (text string)
-----------------------------------------------*/
void ASN1_print_object_id(unsigned char *in,int *mv){
	unsigned char *str,sb[64];
	int i,j,ptm,slen,len;

	printf("OBJECT [%.2x",*in);
	ASN1_object_id(in,mv,&str,&slen);
	j = ASN1_object_2int(in);

	len = ASN1_print_length_bin(&in[1],&ptm);
	for(i=0;i<slen;i++)
		printf(" %.2x",str[i]);

	if(j==0){
		objid2str(in,sb,62);
	}else{
		switch_str(j,sb);
	}
	printf("] : %s\n",sb);
	FREE(str);
}

/*-----------------------------------------------
   print ASN.1 STRINGS
-----------------------------------------------*/
void ASN1_print_strings(unsigned char *in,int *mv,char *kind,
			int type,char* (*cb)()){
	int len;
	unsigned char *str;
	int   ptm,slen;

	printf("%s [%.2x",kind,*in);
	if(type&0x10) str = (unsigned char*)cb(in,mv);
	if(type&0x20) cb(in,mv,&str,&slen,1);
	if(type&0x40) cb(in,mv,&str,&slen,NULL,1);

	len = ASN1_print_length_bin((++in),&ptm);
	if(type&0x1) printf(" ...] str=%s\n",str);
	if(type&0x2){
	  if(len) printf(" ...] length=%d\n",len);
	  else    (*mv)=0;
	}
	if(type&0x4) printf(" ...] time=%s\n",str);

	FREE((unsigned char*)str);
}

void ASN1_print_tag(unsigned char *in,int *mv){
	*mv = 0;

	if(*in & ASN1_C_APPLICATION){
	  ASN1_print_strings(in,mv,"appl",0x22,(char *(*)())ASN1_octetstring_);
	  return;
	}else if(*in & ASN1_C_CTXSPECIFIC){
	  ASN1_print_strings(in,mv,"cont",0x22,(char *(*)())ASN1_octetstring_);
	  return;
	}else if(*in & ASN1_C_PRIVATE){
	  ASN1_print_strings(in,mv,"priv",0x22,(char *(*)())ASN1_octetstring_);
	  return;
	}

	switch(0x1f&*in){
	case ASN1_END:
	  printf("END [%.2x %.2x]\n",in[0],in[1]);
	  *mv += 2;
	  break;
	  
	case ASN1_BOOLEAN:
	  printf("BOOLEAN [%.2x %.2x %.2x]\n",in[0],in[1],in[2]);
	  *mv += 3;
	  break;

	case ASN1_INTEGER:
	case ASN1_ENUMERATED:
	  ASN1_print_integer(in,mv);
	  break;

	case ASN1_BITSTRING:
#ifdef __WINDOWS__
	  ASN1_print_strings(in,mv,"BIT STRING",0x42,(char *(__cdecl *)())ASN1_bitstring_);
#else
	  ASN1_print_strings(in,mv,"BIT STRING",0x42,(char *(*)())ASN1_bitstring_);
#endif
	  break;

	case ASN1_OCTETSTRING:
#ifdef __WINDOWS__
	  ASN1_print_strings(in,mv,"OCTET STRING",0x22,(char *(__cdecl *)())ASN1_octetstring_);
#else
	  ASN1_print_strings(in,mv,"OCTET STRING",0x22,(char *(*)())ASN1_octetstring_);
#endif
	  break;
    
	case ASN1_NULL:
	  printf("NULL [%.2x %.2x]\n",in[0],in[1]);
	  *mv += 2;
	  break;

	case ASN1_OBJECT_IDENTIFIER:
	  ASN1_print_object_id(in,mv);
	  break;

	case ASN1_OBJECT_DESCRIPTOR:
	case ASN1_EXTERNAL:
	case ASN1_REAL:
	  /* SYNTAX ERROR ! */
	  printf("ENCODE ERROR\n");
	  break;

	case ASN1_SEQUENCE:
	case ASN1_SET:
	  ASN1_print(in,mv);
	  break;
	case ASN1_PRINTABLE_STRING:
	  ASN1_print_strings(in,mv,"PRINTABLE",0x11,ASN1_printable);
	  break;
	  
	case ASN1_T61STRING:
	  ASN1_print_strings(in,mv,"T61STRING",0x11,ASN1_t61);
	  break;
    
	case ASN1_IA5STRING:
	  ASN1_print_strings(in,mv,"IA5STRING",0x11,ASN1_ia5);
	  break;

	case ASN1_UTF8STRING:
	  ASN1_print_strings(in,mv,"UTF8STRING",0x11,ASN1_utf8);
	  break;

	case ASN1_BMPSTRING:
	  ASN1_print_strings(in,mv,"BMP STRING",0x12,ASN1_bmp);
	  break;

	case ASN1_UTCTIME:
	  ASN1_print_strings(in,mv,"UTCTIME",0x14,ASN1_utctime);
	  break;

	case ASN1_GENERALIZEDTIME:
	  ASN1_print_strings(in,mv,"GENTIME",0x14,ASN1_gtime);
	  break;

	default:
	  /* SYNTAX ERROR ! */
	  break;
	}
}

/*-----------------------------------------------
   print ASN.1 all.
-----------------------------------------------*/
void ASN1_print(unsigned char *in,int *mv){
	int i,j,ptm,len;
	static int depth=0;
	char buf[256];

	*mv = 1;
	if(!(*in & ASN1_T_STRUCTURED)) return;

	if(*in & ASN1_C_APPLICATION){
		printf("appl [%.2x",*in);
	}else if(*in & ASN1_C_CTXSPECIFIC){
		printf("cont [%.2x",*in);
	}else if(*in & ASN1_C_PRIVATE){
		printf("priv [%.2x",*in);
	}else {
		if((0x1f & *in) == ASN1_SET)
			printf("SET [%.2x",*in);
		else if((0x1f & *in) == ASN1_SEQUENCE)
			printf("SEQUENCE [%.2x",*in);
		else
			printf("construct [%.2x",*in);
	}

	len = ASN1_print_length_bin(&in[1],&ptm);

	if(in[1] == 0x80){
		printf("] len=Indefinite\n");
		len = 0x0fffffff;
		*mv += ptm;
	}else{
		printf("] len=%d\n",len);
		*mv += (ptm+len);
	}
	in += ptm + 1;
	depth++;


	for(i=0; i<len;){
		*buf = 0;
		for(j=0;j<depth;j++) printf("  ");

		if(in[i] & ASN1_T_STRUCTURED){
			ASN1_print(&in[i],&ptm);
		}else{
			if((!in[i])&&(!in[i+1])){ /* 00 00 means END */
				ASN1_print_tag(&in[i],&ptm);

				if(len==0x0fffffff){
					*mv += i+ptm;
					ptm=0;
				}
			}else{
				ASN1_print_tag(&in[i],&ptm);
			}
		}
		if(!ptm) { depth--; return; }
		i += ptm;
	}

	depth--;
}

/*-----------------------------------------------
   print ASN.1 print
-----------------------------------------------*/
void OK_ASN1_print(unsigned char *in){
  int   size;

  if(in==NULL) return;

  ASN1_print(in,&size);
  printf("end of ASN.1\n");
}

/*-----------------------------------------------
   duplicate ASN.1 binary
-----------------------------------------------*/
unsigned char *ASN1_dup(unsigned char *in){
	unsigned char *ret;
	int	len;
	
	if(in==NULL) return NULL;

	if(ASN1_skip_(in,&len)==NULL) return NULL;

	if((ret=(unsigned char*)MALLOC(len+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1PRT,NULL);
		return NULL;
	}
	memcpy(ret,in,len);
	memset(&ret[len],0,2);
	return ret;
}

