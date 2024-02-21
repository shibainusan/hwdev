/* asn1_obj.c */
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

typedef unsigned char Uchar[];

/* Netscape certificate */
static Uchar NSx509v3	 = {0x60,0x86,0x48,0x01,0x86,0xf8,0x42,0x01};

/* PKCS object identifier */
static Uchar P7OBJ	 = {0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0x7};
static Uchar P9OBJ	 = {0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0x9};

static Uchar PKCS5Pbe    = {0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0x5};
static Uchar PKCS12Pbe   = {0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0xc,0x1};
static Uchar PKCS12BagID = {0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0xc,0x3};
static Uchar PKCS12v1Bag = {0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0xc,0xa,0x1};

/* X.502 directory subject type */
/*   DIR 0x6 -- "C", DIR 0x8 -- "ST"
 *   DIR 0x7 -- "L", DIR 0xa -- "O" 
 *   DIR 0xb -- "OU",DIR 0x3 -- "CN"
 */
static Uchar DIR  = {0x55,0x4};

/*see pkcs9 -- static Uchar EMAIL  = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01};*/


/* X.509 certificate extension */
static Uchar V3ID_CE = {0x55,0x1d};
/*static Uchar V3BC = {0x55,0x1d,0x13};*/

/* hash type */
/*   RSAHASH 0x02 -- MD2, RSAHASH 0x05 -- MD5
 *   OIW 0x1a -- SHA1
 */
static Uchar RSAHASH = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02}; /* rsa -- hash*/
static Uchar OIW     = {0x2b,0x0e,0x03,0x02}; /* oiw -- sha 0x1a */


/* encryption type */
/*   RSACRYALG 0x04 -- RC2-CBC, RSACRYALG 0x07 -- 3DES-CBC
 *   OIW 0x7 -- DES-CBC
 */
static Uchar RSACRYALG = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03}; /* rsa -- encryption */

/* signature type */
/* md5WithRSAEncryption */
static Uchar CRYPT_RSA = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01}; /* rsa pkcs#1 */
static Uchar SIG_DSA   = {0x2a,0x86,0x48,0xce,0x38,0x04,0x03};
/*static Uchar MD5RSA  = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x04};*/

/* PKIX */
static Uchar PKIX_IDPE = {0x2b,0x06,0x01,0x05,0x05,0x07,0x01}; /* { pkix 1 } */
static Uchar PKIX_IDQT = {0x2b,0x06,0x01,0x05,0x05,0x07,0x02};
static Uchar PKIX_IDKP = {0x2b,0x06,0x01,0x05,0x05,0x07,0x03};
static Uchar PKIX_IDIT = {0x2b,0x06,0x01,0x05,0x05,0x07,0x04};
static Uchar PKIX_IDAD = {0x2b,0x06,0x01,0x05,0x05,0x07,0x30};

/* Microsoft */
static Uchar MS_EU = {0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x0a,0x03};
static Uchar MS_GN = {0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x14,0x02};

/* X9.62 -- elliptic curve */
static Uchar X9_62_FT  = {0x2a,0x86,0x48,0xce,0x3d,0x01};
static Uchar X9_62_KY  = {0x2a,0x86,0x48,0xce,0x3d,0x02};
static Uchar X9_62_CV  = {0x2a,0x86,0x48,0xce,0x3d,0x03};
static Uchar X9_62_SIG = {0x2a,0x86,0x48,0xce,0x3d,0x04};

/* MOJ -- houmusyou */
static Uchar MOJ_EXT  = {0x2a,0x83,0x08,0x86,0x8f,0x4c,0x01,0x01};
static Uchar MOJ_ATT  = {0x2a,0x83,0x08,0x86,0x8f,0x4c,0x01,0x02};

/*-----------------------------------------
  get int value from OBJECT IDENTIFIER
  return -1..not object id.
  return 0...unknown object.
-----------------------------------------*/
int ASN1_object_2int(unsigned char *cp){
	int	i,len;

	if(*cp != ASN1_OBJECT_IDENTIFIER){
		OK_set_error(ERR_ST_ASN_NOTOID,ERR_LC_ASN1,ERR_PT_ASN1OBJ,NULL);
		return -1;
	}

	len = ASN1_length((++cp),&i);
	cp+=i;

	switch(len){
	case 3:
		if(!memcmp(cp,DIR,2)){ /* dir object */
			cp+=2;
			switch(*cp){
			case 0x06:	return OBJ_DIR_C;
			case 0x08:	return OBJ_DIR_ST;
			case 0x07:	return OBJ_DIR_L;
			case 0x0a:	return OBJ_DIR_O;
			case 0x0b:	return OBJ_DIR_OU;
			case 0x03:	return OBJ_DIR_CN;
		}}
		if(!memcmp(cp,V3ID_CE,2)){
			cp+=2;
			switch(*cp){
			case 0x09:	return OBJ_X509v3_SubDirAtt;
	/* (?)   case 0x0d:	return OBJ_X509v3_SbjKeyIdt; */
			case 0x0e:	return OBJ_X509v3_SbjKeyIdt;
			case 0x0f:	return OBJ_X509v3_KEY_Usage;
			case 0x10:	return OBJ_X509v3_PrvKeyUsgPrd;
			case 0x11:	return OBJ_X509v3_SbjAltName;
			case 0x12:	return OBJ_X509v3_IssAltName;
			case 0x13:	return OBJ_X509v3_BASIC;
			case 0x14:	return OBJ_X509v3_CRLNumber;
			case 0x15:	return OBJ_X509v3_CRLReason;
			case 0x17:	return OBJ_X509v3_HoldInsCode;
			case 0x18:	return OBJ_X509v3_InvalData;
			case 0x1b:	return OBJ_X509v3_DeltaCRLInd;
			case 0x1c:	return OBJ_X509v3_IssDistPoint;
			case 0x1d:	return OBJ_X509v3_CertIssuer;
			case 0x1e:	return OBJ_X509v3_NameConst;
			case 0x1f:	return OBJ_X509v3_CRL_Point;
			case 0x20:	return OBJ_X509v3_CERT_Pol;
			case 0x21:	return OBJ_X509v3_CertPolMap;
			case 0x23:	return OBJ_X509v3_AuthKeyIdt;
			case 0x24:	return OBJ_X509v3_PolicyConst;
			case 0x25:	return OBJ_X509v3_ExtKeyUsage;
		}}
		return 0;

	case 5:
		if(!memcmp(cp,OIW,4)){
			cp+=4;
			switch(*cp){
			case 0x06:	return OBJ_CRYALGO_DESECB;
			case 0x07:	return OBJ_CRYALGO_DESCBC;
			case 0x18:	return OBJ_SIGOIW_MD2RSA;
			case 0x19:	return OBJ_SIGOIW_MD5RSA;
			case 0x1a:	return OBJ_HASH_SHA1;
			case 0x1d:	return OBJ_SIGOIW_SHA1RSA;
		}}
		return 0;

	case 7:
		if(!memcmp(cp,SIG_DSA,6)){
			cp+=6;
			switch(*cp){
			case 0x01:	return OBJ_CRYPT_DSA;
			case 0x03:	return OBJ_SIG_SHA1DSA;
		}}
		if(!memcmp(cp,X9_62_FT,6)){
			cp+=6;
			switch(*cp){
			case 0x01:	return OBJ_X962_FT_PRIME;
			case 0x02:	return OBJ_X962_FT_CHR2;
		}}
		if(!memcmp(cp,X9_62_KY,6)){
			cp+=6;
			switch(*cp){
			case 0x01:	return OBJ_CRYPT_ECDSA;
		}}
		if(!memcmp(cp,X9_62_SIG,6)){
			cp+=6;
			switch(*cp){
			case 0x01:	return OBJ_SIG_SHA1ECDSA;
		}}
		return 0;

	case 8:
		if(!memcmp(cp,RSAHASH,7)){ /* RSA HASH TYPE */
			cp+=7;
			switch(*cp){
			case 0x02:	return OBJ_HASH_MD2;
			case 0x05:	return OBJ_HASH_MD5;
		}}
		if(!memcmp(cp,RSACRYALG,7)){ /* RSA ENCRYPTION TYPE */
			cp+=7;
			switch(*cp){
			case 0x02:	return OBJ_CRYALGO_RC2CBC;
			case 0x04:	return OBJ_CRYALGO_RC4CBC;
			case 0x07:	return OBJ_CRYALGO_3DESCBC;
			case 0x08:	return OBJ_CRYALGO_RC5CBC;
			case 0x0a:	return OBJ_CRYALGO_DESCDMF;
		}}
		if(!memcmp(cp,PKIX_IDPE,6)){ /* PKIX OIDs */
			cp+=6;
			switch(*cp){
			case 1:
				cp++;
				switch(*cp){
				case 0x01:	return OBJ_PKIX_IDPE_AIA;
				}
				break;
	
			case 2:
				cp++;
				switch(*cp){
				case 0x01:	return OBJ_PKIX_IDQT_CPS;
				case 0x02:	return OBJ_PKIX_IDQT_UNOTICE;
				}
				break;

			case 3:
				cp++;
				switch(*cp){
				case 0x01:	return OBJ_PKIX_IDKP_SVAUTH;
				case 0x02:	return OBJ_PKIX_IDKP_CLAUTH;
				case 0x03:	return OBJ_PKIX_IDKP_CDSIGN;
				case 0x04:	return OBJ_PKIX_IDKP_EMAIL;
				case 0x05:	return OBJ_PKIX_IDKP_IPSEC_ES;
				case 0x06:	return OBJ_PKIX_IDKP_IPSEC_TN;
				case 0x07:	return OBJ_PKIX_IDKP_IPSEC_US;
				case 0x08:	return OBJ_PKIX_IDKP_TMSTAMP;
				case 0x09:	return OBJ_PKIX_IDKP_OCSPSIGN;
				}
				break;

			case 4:
				cp++;
				switch(*cp){
				case 0x01:	return OBJ_PKIX_IDIT_CAPROT;
				case 0x02:	return OBJ_PKIX_IDIT_SIGNKEY;
				case 0x03:	return OBJ_PKIX_IDIT_ENCKEY;
				case 0x04:	return OBJ_PKIX_IDIT_PREFSYM;
				case 0x05:	return OBJ_PKIX_IDIT_CAKEYUPD;
				case 0x06:	return OBJ_PKIX_IDIT_CURCRL;
				case 0x07:	return OBJ_PKIX_IDIT_UNSPOID;
				case 0x0a:	return OBJ_PKIX_IDIT_KEYPREQ;
				case 0x0b:	return OBJ_PKIX_IDIT_KEYPREP;
				case 0x0c:	return OBJ_PKIX_IDIT_REVPASS;
				case 0x0d:	return OBJ_PKIX_IDIT_IMPCONF;
				case 0x0e:	return OBJ_PKIX_IDIT_CWAITTIME;
				case 0x0f:	return OBJ_PKIX_IDIT_PKIMESS;
				}
				break;

			case 48:
				cp++;
				switch(*cp){
				case 0x01:	return OBJ_PKIX_IDAD_OCSP;
				case 0x02:	return OBJ_PKIX_IDAD_CAISS;
				case 0x03:	return OBJ_PKIX_IDAD_TMSTAMP;
				case 0x04:	return OBJ_PKIX_IDAD_DVCS;
				case 0x05:	return OBJ_PKIX_IDAD_CAREPS;
				}
				break;
			}
		}
		if(!memcmp(cp,X9_62_CV,6)){
			cp+=6;
			switch(*cp){
			case 0x01:
				cp++;
				switch(*cp){
				case 0x01:	return OBJ_X962_prime192v1;
				case 0x02:	return OBJ_X962_prime192v2;
				case 0x03:	return OBJ_X962_prime192v3;
				case 0x04:	return OBJ_X962_prime239v1;
				case 0x05:	return OBJ_X962_prime239v2;
				case 0x06:	return OBJ_X962_prime239v3;
				case 0x07:	return OBJ_X962_prime256v1;
				}
				break;
			}
		}
	case 9:
		if(!memcmp(cp,CRYPT_RSA,8)){ /* Signature */
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_CRYPT_RSA;
			case 0x02:	return OBJ_SIG_MD2RSA;
			case 0x04:	return OBJ_SIG_MD5RSA;
			case 0x05:	return OBJ_SIG_SHA1RSA;
		}}
		if(!memcmp(cp,PKCS5Pbe,8)){
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_P5_MD2DES;
			case 0x04:	return OBJ_P5_MD2RC2;
			case 0x03:	return OBJ_P5_MD5DES;
			case 0x06:	return OBJ_P5_MD5RC2;
			case 0x0a:	return OBJ_P5_SHA1DES;
			case 0x0b:	return OBJ_P5_SHA1RC2;
		}}
		if(!memcmp(cp,P7OBJ,8)){	/* This is PKCS#7 object */
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_P7_DATA;
			case 0x02:	return OBJ_P7_SIGNED;
			case 0x03:	return OBJ_P7_ENVELP;
			case 0x04:	return OBJ_P7_SIGandENV;
			case 0x05:	return OBJ_P7_DIGESTED;
			case 0x06:	return OBJ_P7_ENCRYPTED;
		}}
		if(!memcmp(cp,P9OBJ,8)){
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_P9_EMAIL;
			case 0x02:	return OBJ_P9_UNST_NAME;
			case 0x03:	return OBJ_P9_CONTENT_TYPE;
			case 0x04:	return OBJ_P9_MESS_DGST;
			case 0x05:	return OBJ_P9_SIGN_TIME;
			case 0x06:	return OBJ_P9_COUNT_SIG;
			case 0x07:	return OBJ_P9_CHALL_PWD;
			case 0x08:	return OBJ_P9_UNST_ADRS;
			case 0x09:	return OBJ_P9_EXT_CERT_ATT;
			case 0x0a:	return OBJ_P9_ISS_SN;
			case 0x0b:	return OBJ_P9_PASSCHECK;
			case 0x0c:	return OBJ_P9_PUBKEY;
			case 0x0d:	return OBJ_P9_SIG_DESCR;
			case 0x0e:	return OBJ_P9_EXT_REQ;
			case 0x0f:	return OBJ_P9_SMIME_CAP;
			case 0x10:	return OBJ_P9_SMIME;
			case 0x16:	return OBJ_P9_CERT_TYPES;
			case 0x17:	return OBJ_P9_CRL_TYPES;
			case 0x14:	return OBJ_P9_Friendly;
			case 0x15:	return OBJ_P9_LocalKEY;
		}}
		if(!memcmp(cp,NSx509v3,8)){
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_NS_CERT_TYPE;
			case 0x02:	return OBJ_NS_CERT_BASE;
			case 0x04:	return OBJ_NS_CERT_CRLURL;
			case 0x08:	return OBJ_NS_CERT_POLICY;
			case 0x0d:	return OBJ_NS_CERT_COMMENT;
		}}
		if(!memcmp(cp,MOJ_EXT,8)){
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_MOJ_JCertPol;
			case 0x02:	return OBJ_MOJ_Registrar;
			case 0x03:	return OBJ_MOJ_RegCoInfo;
		}}
		if(!memcmp(cp,MOJ_ATT,8)){
			cp+=8;
			switch(*cp){
			case 0x01:	return OBJ_MOJ_GenSpReq;
			case 0x02:	return OBJ_MOJ_GenSpRes;
			case 0x15:	return OBJ_MOJ_GenmReq;
			case 0x16:	return OBJ_MOJ_GenpRes;
			case 0x68:	return OBJ_MOJ_TimeLimit;
			case 0x69:	return OBJ_MOJ_SuspCode;
		}}
		if(!memcmp(cp,PKIX_IDPE,6)){ /* PKIX OIDs */
			cp+=6;
			if((cp[0]==48)||(cp[1]==1)){
				cp+=2;
				switch(*cp){
				case 1:	return OBJ_PKIX_OCSP_BASIC;
				case 2: return OBJ_PKIX_OCSP_NONCE;
				case 3: return OBJ_PKIX_OCSP_CRL;
				case 4: return OBJ_PKIX_OCSP_RESPONSE;
				case 5: return OBJ_PKIX_OCSP_NOCHECK;
				case 6: return OBJ_PKIX_OCSP_ARCHIVE;
				case 7: return OBJ_PKIX_OCSP_SERVICE;
				}
			}
		}
		return 0;

	case 10:
		if(!memcmp(cp,P9OBJ,8)){
			cp+=8;
			if(*cp==22){
				cp++;
				if(*cp==1) return OBJ_P9_X509CERT;
				if(*cp==2) return OBJ_P9_sdsiCERT;
			}else if(*cp==23){
				cp++;
				if(*cp==1) return OBJ_P9_X509CRL;
			}
		}
		if(!memcmp(cp,PKCS12Pbe,9)){
			cp+=9;
			switch(*cp){
			case 0x01:	return OBJ_P12Pbe_128RC4;
			case 0x02:	return OBJ_P12Pbe_40RC4;
			case 0x03:	return OBJ_P12Pbe_3K3DES;
			case 0x04:	return OBJ_P12Pbe_2K3DES;
			case 0x05:	return OBJ_P12Pbe_128RC2;
			case 0x06:	return OBJ_P12Pbe_40RC2;
		}}
		if(!memcmp(cp,MS_EU,9)){
			cp+=9;
			switch(*cp){
			case 0x01: return OBJ_MS_EU_LSTSIG;
			case 0x03: return OBJ_MS_EU_SGC;
			case 0x04: return OBJ_MS_EU_ENCFSYS;
		}}
		if(!memcmp(cp,MS_GN,9)){
			cp+=9;
			switch(*cp){
			case 0x02: return OBJ_MS_EU_ICLOGON;
			case 0x03: return OBJ_MS_GN_UPN;
		}}
		return 0;

	case 11:
		if(!memcmp(cp,PKCS12v1Bag,10)){
			cp+=10;
			switch(*cp){
			case 0x01:	return OBJ_P12v1Bag_KEY;
			case 0x02:	return OBJ_P12v1Bag_PKCS8;
			case 0x03:	return OBJ_P12v1Bag_CERT;
			case 0x04:	return OBJ_P12v1Bag_CRL;
			case 0x05:	return OBJ_P12v1Bag_SECRET;
			case 0x06:	return OBJ_P12v1Bag_SAFE;
		}}
		return 0;

	default:
		return 0;
	}
	return 0;
}


int ASN1_int_2object(int obj, unsigned char *ret, int *ret_len){
    int len = obj/1000;

    *ret = 0x06; ret++;
    *ret = len;  ret++;
    *ret_len = 2+len;

    switch(len){
	case 3:
	if(obj<3010){
	    memcpy(ret,DIR,2); ret+=2;
	    switch(obj){
	      case OBJ_DIR_C:  *ret = 0x06; break;
	      case OBJ_DIR_ST: *ret = 0x08; break;
	      case OBJ_DIR_L:  *ret = 0x07; break;
	      case OBJ_DIR_O:  *ret = 0x0a; break;
	      case OBJ_DIR_OU: *ret = 0x0b; break;
	      case OBJ_DIR_CN: *ret = 0x03; break;
	      default:	goto error;
	    }
	}else{
	    memcpy(ret,V3ID_CE,2); ret+=2;
	    switch(obj){
	      case OBJ_X509v3_SubDirAtt: *ret = 0x09; break;
	      case OBJ_X509v3_SbjKeyIdt: *ret = 0x0e; break;
	      case OBJ_X509v3_KEY_Usage: *ret = 0x0f; break;
	      case OBJ_X509v3_PrvKeyUsgPrd:*ret = 0x10; break;
	      case OBJ_X509v3_SbjAltName:  *ret = 0x11; break;
	      case OBJ_X509v3_IssAltName:  *ret = 0x12; break;
	      case OBJ_X509v3_BASIC:       *ret = 0x13; break;
	
	      case OBJ_X509v3_CRLNumber:   *ret = 0x14; break;
	      case OBJ_X509v3_CRLReason:   *ret = 0x15; break;
	      case OBJ_X509v3_HoldInsCode: *ret = 0x17; break;
	      case OBJ_X509v3_InvalData:   *ret = 0x18; break;
	      case OBJ_X509v3_DeltaCRLInd: *ret = 0x1b; break;
	      case OBJ_X509v3_IssDistPoint:*ret = 0x1c; break;
	      case OBJ_X509v3_CertIssuer:  *ret = 0x1d; break;
	      case OBJ_X509v3_NameConst:   *ret = 0x1e; break;
	      case OBJ_X509v3_CRL_Point:   *ret = 0x1f; break;
	      case OBJ_X509v3_CERT_Pol:    *ret = 0x20; break;
	      case OBJ_X509v3_CertPolMap:  *ret = 0x21; break;
	      case OBJ_X509v3_AuthKeyIdt:  *ret = 0x23; break;
	      case OBJ_X509v3_PolicyConst: *ret = 0x24; break;
	      case OBJ_X509v3_ExtKeyUsage: *ret = 0x25; break;
	      default:	goto error;
	    }
	}
	break;

	case 5:
		memcpy(ret,OIW,4); ret+=4;
		switch(obj){
		case OBJ_CRYALGO_DESECB:	*ret = 0x06; break;
		case OBJ_CRYALGO_DESCBC:	*ret = 0x07; break;
		case OBJ_SIGOIW_MD2RSA:		*ret = 0x18; break;
		case OBJ_SIGOIW_MD5RSA:		*ret = 0x19; break;
		case OBJ_HASH_SHA1:			*ret = 0x1a; break;
		case OBJ_SIGOIW_SHA1RSA:	*ret = 0x1d; break;
		default:	goto error;
		}
	break;

	case 7:
		if(obj<7010){
			memcpy(ret,SIG_DSA,6); ret+=6;
			switch(obj){
			case OBJ_CRYPT_DSA:	*ret = 0x01; break;
			case OBJ_SIG_SHA1DSA:	*ret = 0x03; break;
			default:	goto error;
			}
		}else if(obj<7050){
			memcpy(ret,X9_62_SIG,6); ret+=6;
			switch(obj){
			case OBJ_SIG_SHA1ECDSA:	*ret = 0x01; break;
			default:	goto error;
			}
		}else if(obj<7055){
			memcpy(ret,X9_62_FT,6); ret+=6;
			switch(obj){
			case OBJ_X962_FT_PRIME: *ret = 0x01; break;
			case OBJ_X962_FT_CHR2:	*ret = 0x02; break;
			default:	goto error;
			}
		}else if(obj<7060){
			memcpy(ret,X9_62_KY,6); ret+=6;
			switch(obj){
			case OBJ_CRYPT_ECDSA: *ret = 0x01; break;
			default:	goto error;
			}
		}
		break;

	case 8:
	if(obj<8020){
	    memcpy(ret,RSAHASH,7); ret+=7;
	    switch(obj){
	      case OBJ_HASH_MD2:	*ret = 0x02; break;
	      case OBJ_HASH_MD5:	*ret = 0x05; break;
	      default:	goto error;
	    }
	}else if(obj<8060){
	    memcpy(ret,RSACRYALG,7); ret+=7;
	    switch(obj){
	      case OBJ_CRYALGO_RC2CBC:	*ret =  0x02; break;
	      case OBJ_CRYALGO_RC4CBC:	*ret =  0x04; break;
	      case OBJ_CRYALGO_3DESCBC:	*ret =  0x07; break;
	      case OBJ_CRYALGO_RC5CBC:	*ret =  0x08; break;
	      case OBJ_CRYALGO_DESCDMF:	*ret =  0x0a; break;
	      default:	goto error;
	    }
	}else if(obj<8090){
		memcpy(ret,X9_62_CV,6); ret+=6;
		*ret=0; ret++;
		switch(obj){
		default:	goto error;
	    }
	}else if(obj<8100){
		memcpy(ret,X9_62_CV,6); ret+=6;
		*ret=1; ret++;
		switch(obj){
		case OBJ_X962_prime192v1: *ret=1; break;
		case OBJ_X962_prime192v2: *ret=2; break;
		case OBJ_X962_prime192v3: *ret=3; break;
		case OBJ_X962_prime239v1: *ret=4; break;
		case OBJ_X962_prime239v2: *ret=5; break;
		case OBJ_X962_prime239v3: *ret=6; break;
		case OBJ_X962_prime256v1: *ret=7; break;
		default:	goto error;
		}
	}else if(obj<8112){
	    memcpy(ret,PKIX_IDPE,7); ret+=7;
	    switch(obj){
		case OBJ_PKIX_IDPE_AIA:		*ret = 0x01; break;
		default:  goto error;
		}
	}else if(obj<8120){
	    memcpy(ret,PKIX_IDAD,7); ret+=7;
	    switch(obj){
		case OBJ_PKIX_IDAD_OCSP:	*ret = 0x01; break;
		case OBJ_PKIX_IDAD_CAISS:	*ret = 0x02; break;
		case OBJ_PKIX_IDAD_TMSTAMP:	*ret = 0x03; break;
		case OBJ_PKIX_IDAD_DVCS:	*ret = 0x04; break;
		case OBJ_PKIX_IDAD_CAREPS:	*ret = 0x05; break;
		default:  goto error;
		}
	}else if(obj<8130){
	    memcpy(ret,PKIX_IDQT,7); ret+=7;
	    switch(obj){
		case OBJ_PKIX_IDQT_CPS:		*ret = 0x01; break;
		case OBJ_PKIX_IDQT_UNOTICE:	*ret = 0x02; break;
		default:  goto error;
		}
	}else if(obj<8140){
	    memcpy(ret,PKIX_IDKP,7); ret+=7;
	    switch(obj){
		case OBJ_PKIX_IDKP_SVAUTH:	*ret = 0x01; break;
		case OBJ_PKIX_IDKP_CLAUTH:	*ret = 0x02; break;
		case OBJ_PKIX_IDKP_CDSIGN:	*ret = 0x03; break;
		case OBJ_PKIX_IDKP_EMAIL:	*ret = 0x04; break;
		case OBJ_PKIX_IDKP_IPSEC_ES:*ret = 0x05; break;
		case OBJ_PKIX_IDKP_IPSEC_TN:*ret = 0x06; break;
		case OBJ_PKIX_IDKP_IPSEC_US:*ret = 0x07; break;
		case OBJ_PKIX_IDKP_TMSTAMP:	*ret = 0x08; break;
		case OBJ_PKIX_IDKP_OCSPSIGN:*ret = 0x09; break;
		default:  goto error;
		}
	}else{
	    memcpy(ret,PKIX_IDIT,7); ret+=7;
	    switch(obj){
		case OBJ_PKIX_IDIT_CAPROT:	*ret = 0x01; break;
		case OBJ_PKIX_IDIT_SIGNKEY:	*ret = 0x02; break;
		case OBJ_PKIX_IDIT_ENCKEY:	*ret = 0x03; break;
		case OBJ_PKIX_IDIT_PREFSYM:	*ret = 0x04; break;
		case OBJ_PKIX_IDIT_CAKEYUPD:	*ret = 0x05; break;
		case OBJ_PKIX_IDIT_CURCRL:	*ret = 0x06; break;
		case OBJ_PKIX_IDIT_UNSPOID:	*ret = 0x07; break;
		case OBJ_PKIX_IDIT_KEYPREQ:	*ret = 0x0a; break;
		case OBJ_PKIX_IDIT_KEYPREP:	*ret = 0x0b; break;
		case OBJ_PKIX_IDIT_REVPASS:	*ret = 0x0c; break;
		case OBJ_PKIX_IDIT_IMPCONF:	*ret = 0x0d; break;
		case OBJ_PKIX_IDIT_CWAITTIME:	*ret = 0x0e; break;
		case OBJ_PKIX_IDIT_PKIMESS:	*ret = 0x0f; break;
		default:  goto error;
		}
	}
	break;

	case 9:
	if(obj<9010){
	    memcpy(ret,CRYPT_RSA,8); ret+=8;
	    switch(obj){
	      case OBJ_CRYPT_RSA:	*ret = 0x01; break;
	      case OBJ_SIG_MD2RSA:	*ret = 0x02; break;
	      case OBJ_SIG_MD5RSA:	*ret = 0x04; break;
	      case OBJ_SIG_SHA1RSA:	*ret = 0x05; break;
	      default:	goto error;
	    }
	}else if(obj<9020){
	    memcpy(ret,P7OBJ,8); ret+=8;
	    switch(obj){
	      case OBJ_P7_DATA:  *ret = 0x01; break;
	      case OBJ_P7_SIGNED:  *ret = 0x02; break;
	      case OBJ_P7_ENVELP:  *ret = 0x03; break;
	      case OBJ_P7_SIGandENV:  *ret = 0x04; break;
	      case OBJ_P7_DIGESTED:  *ret = 0x05; break;
	      case OBJ_P7_ENCRYPTED:  *ret = 0x06; break;
	      default:	goto error;
	    }
	}else if(obj<9050){
	    memcpy(ret,P9OBJ,8); ret+=8;
	    switch(obj){
	      case OBJ_P9_EMAIL:  *ret = 0x01; break;
	      case OBJ_P9_UNST_NAME:  *ret = 0x02; break;
	      case OBJ_P9_CONTENT_TYPE:  *ret = 0x03; break;
	      case OBJ_P9_MESS_DGST:  *ret = 0x04; break;
	      case OBJ_P9_SIGN_TIME:  *ret = 0x05; break;
	      case OBJ_P9_COUNT_SIG:  *ret = 0x06; break;
	      case OBJ_P9_CHALL_PWD:  *ret = 0x07; break;
	      case OBJ_P9_UNST_ADRS:  *ret = 0x08; break;
	      case OBJ_P9_EXT_CERT_ATT:  *ret = 0x09; break;

	      case OBJ_P9_ISS_SN:		*ret = 0x0a; break;
	      case OBJ_P9_PASSCHECK:	*ret = 0x0b; break;
	      case OBJ_P9_PUBKEY:	*ret = 0x0c; break;
	      case OBJ_P9_SIG_DESCR:	*ret = 0x0d; break;
	      case OBJ_P9_EXT_REQ:	*ret = 0x0e; break;
	      case OBJ_P9_SMIME_CAP:	*ret = 0x0f; break;

	      case OBJ_P9_SMIME:		*ret = 0x10; break;
	      case OBJ_P9_CERT_TYPES:	*ret = 0x16; break;
	      case OBJ_P9_CRL_TYPES:	*ret = 0x17; break;

	      case OBJ_P9_Friendly:  *ret = 0x14; break;
	      case OBJ_P9_LocalKEY:  *ret = 0x15; break;
	      default:	goto error;
	    }
	}else if(obj<9060){
	    memcpy(ret,NSx509v3,8); ret+=8;
	    switch(obj){
	      case OBJ_NS_CERT_TYPE:	*ret = 0x01; break;
	      case OBJ_NS_CERT_BASE:	*ret = 0x02; break;
	      case OBJ_NS_CERT_RVKURL:	*ret = 0x03; break;
	      case OBJ_NS_CERT_CRLURL:	*ret = 0x04; break;
	      case OBJ_NS_CERT_RENEW:	*ret = 0x07; break;
	      case OBJ_NS_CERT_POLICY:	*ret = 0x08; break;
	      case OBJ_NS_CERT_SSL_SV:	*ret = 0x0c; break;
	      case OBJ_NS_CERT_COMMENT:	*ret = 0x0d; break;
	      default:	goto error;
	    }
	}else if(obj<9070){
	    memcpy(ret,PKCS5Pbe,8); ret+=8;
		switch(obj){
		case OBJ_P5_MD2DES:			*ret = 0x01; break;
		case OBJ_P5_MD2RC2:			*ret = 0x04; break;
		case OBJ_P5_MD5DES:			*ret = 0x03; break;
		case OBJ_P5_MD5RC2:			*ret = 0x06; break;
		case OBJ_P5_SHA1DES:		*ret = 0x0a; break;
		case OBJ_P5_SHA1RC2:		*ret = 0x0b; break;
		default: goto error;
		}
	}else if(obj<9080){
	    memcpy(ret,MOJ_EXT,8); ret+=8;
		switch(obj){
		case OBJ_MOJ_JCertPol:		*ret = 0x01; break;
		case OBJ_MOJ_Registrar:		*ret = 0x02; break;
		case OBJ_MOJ_RegCoInfo:		*ret = 0x03; break;
		default: goto error;
		}
	}else if(obj<9100){
	    memcpy(ret,MOJ_ATT,8); ret+=8;
		switch(obj){
		case OBJ_MOJ_GenSpReq:		*ret = 0x01; break;
		case OBJ_MOJ_GenSpRes:		*ret = 0x02; break;
		case OBJ_MOJ_GenmReq:		*ret = 0x15; break;
		case OBJ_MOJ_GenpRes:		*ret = 0x16; break;
		case OBJ_MOJ_TimeLimit:		*ret = 0x68; break;
		case OBJ_MOJ_SuspCode:		*ret = 0x69; break;
		default: goto error;
		}
	}else{
	    memcpy(ret,PKIX_IDAD,7); ret+=7;
		*ret = 1; ret++;
		switch(obj){
		case OBJ_PKIX_OCSP_BASIC:	*ret = 0x01; break;
		case OBJ_PKIX_OCSP_NONCE:	*ret = 0x02; break;
		case OBJ_PKIX_OCSP_CRL:		*ret = 0x03; break;
		case OBJ_PKIX_OCSP_RESPONSE:*ret = 0x04; break;
		case OBJ_PKIX_OCSP_NOCHECK:	*ret = 0x05; break;
		case OBJ_PKIX_OCSP_ARCHIVE: *ret = 0x06; break;
		case OBJ_PKIX_OCSP_SERVICE: *ret = 0x07; break;
		default: goto error;
		}
	}
	break;

	case 10:
	if(obj<10010){
	    memcpy(ret,P9OBJ,8); ret+=8;
	    switch(obj){
	      case OBJ_P9_X509CERT:	*ret=22; ret[1]=1; break;
	      case OBJ_P9_sdsiCERT:	*ret=22; ret[1]=2; break;
	      case OBJ_P9_X509CRL:	*ret=23; ret[1]=1; break;
	      default: goto error;
	    }
	}else if(obj<10100){
	    memcpy(ret,PKCS12Pbe,9); ret+=9;
	    switch(obj){
	      case OBJ_P12Pbe_128RC4:	*ret=0x01; break;
	      case OBJ_P12Pbe_40RC4:	*ret=0x02; break;
	      case OBJ_P12Pbe_3K3DES:	*ret=0x03; break;
	      case OBJ_P12Pbe_2K3DES:	*ret=0x04; break;
	      case OBJ_P12Pbe_128RC2:	*ret=0x05; break;
	      case OBJ_P12Pbe_40RC2:	*ret=0x06; break;
	      default: goto error;
	    }
	}else if(obj<10110){
	    memcpy(ret,MS_EU,9); ret+=9;
	    switch(obj){
		  case OBJ_MS_EU_LSTSIG:	*ret=0x01; break;
		  case OBJ_MS_EU_SGC:		*ret=0x03; break;
		  case OBJ_MS_EU_ENCFSYS:	*ret=0x04; break;
	      default: goto error;
	    }
	}else{
	    memcpy(ret,MS_GN,9); ret+=9;
	    switch(obj){
		case OBJ_MS_EU_ICLOGON:		*ret=0x02; break;
		case OBJ_MS_GN_UPN:			*ret=0x03; break;
		default: goto error;
	    }
	}
	break;

	case 11:
	memcpy(ret,PKCS12v1Bag,10); ret+=10;
	switch(obj){
	  case OBJ_P12v1Bag_KEY:	*ret=0x01; break;
	  case OBJ_P12v1Bag_PKCS8:	*ret=0x02; break;
	  case OBJ_P12v1Bag_CERT:	*ret=0x03; break;
	  case OBJ_P12v1Bag_CRL:	*ret=0x04; break;
	  case OBJ_P12v1Bag_SECRET:	*ret=0x05; break;
	  case OBJ_P12v1Bag_SAFE:	*ret=0x06; break;
	  default: goto error;
	}
	break;

	default:
		goto error;
    }
    return 0;
error:
    OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_ASN1,ERR_PT_ASN1OBJ+1,NULL);
	return -1;
}

/*--------------------------------------------------
   get OBJECT IDENTIFIER (text oid to byte string)
--------------------------------------------------*/
int str2objid(char *txt,unsigned char *ret,int max){
	unsigned char buf[8],*rt;
	int	i,j,rlen,err=-1;
	char *cp,*tbuf;

	if((STRDUP(tbuf,txt))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_ASN1,ERR_PT_ASN1OBJ+2,NULL);
		return -1;
	}

	rt=ret; ret+=2;

	/* two top numbers */
	txt = tbuf;
	if((cp=strchr(txt,'.'))==NULL) goto done;
	*cp=0; i=atoi(txt); txt=cp+1;

	if((cp=strchr(txt,'.'))==NULL) goto done;
	*cp=0; j=atoi(txt); txt=cp+1;

	if((i<0)||(i>2)||(j<0)||(j>39)) goto done;
	if(max < (rlen = 3)) goto done;
	*ret =i*40+j; ret++;

	while(txt){
		if((cp=strchr(txt,'.'))==NULL){
			i=atoi(txt); txt=NULL;
		}else{
			*cp=0; i=atoi(txt); txt=cp+1;
		}
		j=7;
		do{
			buf[j]=i&0x7f;
			i>>=7;
			if(j!=7) buf[j]|=0x80;
			j--;
		}while(i);

		if(max < (rlen+=7-j)) goto done;
		memcpy(ret,&buf[j+1],7-j);
		ret +=7-j;
	}

	rt[0] = ASN1_OBJECT_IDENTIFIER;
	rt[1] = (unsigned char)rlen-2;
	err   = rlen;
done:
	if(err<0) OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1OBJ+2,NULL);
	FREE(tbuf);
	return err;
}

/*--------------------------------------------------
   get OBJECT IDENTIFIER (byte string to text oid)
--------------------------------------------------*/
int objid2str(unsigned char *id,char *sb,int max){
	unsigned char *cp,tmp[32];
	ULONG l;
	int i,j,k,ret=0,len;

	if(*id!=ASN1_OBJECT_IDENTIFIER){
		OK_set_error(ERR_ST_ASN_NOTOID,ERR_LC_ASN1,ERR_PT_ASN1OBJ+3,NULL);
        strcpy(sb,"notOID");
		return -1;
	}

    len=ASN1_length(id+1,&j);
    cp =id+1+j;

    /* encoding first string */
    i=(*cp)/40; j=(*cp)%40;
    sprintf(tmp,"%d.%d",i,j);
    cp++;

	if(max <= (i=strlen(tmp))) goto max_end;
	strncpy(sb,tmp,i+1); ret+=i;

    /* encoding other string */
    for(i=1;i<len;i+=j,cp++){
        l=*cp&0x7f; j=1;
        while(*cp&0x80){
            j++; cp++;
            l=(l*128)+(*cp&0x7f);
        }
        sprintf(tmp,".%d",l);

		if(max <= (k=strlen(tmp))) goto max_end;
		strncat(sb,tmp,k+1); ret+=k;
    }
	return ret;
max_end:
	strncat(sb,tmp,max-ret);
	return max;
}


