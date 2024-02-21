/* ok_asn1.h */
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
#ifndef __OK_ASN1_H__
#define __OK_ASN1_H__

#include "ok_err.h"
#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecc.h"
#include "ok_ecdsa.h"
#include "ok_x509.h"
#include "ok_x509ext.h"
#include "ok_pkcs.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* ASN.1 TAGS */
#define ASN1_END		0x00
#define	ASN1_BOOLEAN		0x01
#define	ASN1_INTEGER		0x02
#define ASN1_BITSTRING		0x03
#define ASN1_OCTETSTRING	0x04
#define ASN1_NULL		0x05
#define	ASN1_OBJECT_IDENTIFIER	0x06
#define ASN1_OBJECT_DESCRIPTOR	0x07
#define ASN1_EXTERNAL		0x08
#define ASN1_REAL		0x09
#define ASN1_ENUMERATED		0x0a
#define ASN1_UTF8STRING		0x0c
#define ASN1_SEQUENCE		0x10	/* struct, original=0x10 */
#define ASN1_SEQUENCE_OF	0x10    /* struct, original=0x10 */
#define ASN1_SET		0x11    /* struct, original=0x11 */
#define ASN1_SET_OF		0x11    /* struct, original=0x11 */
#define ASN1_PRINTABLE_STRING	0x13
#define ASN1_T61STRING		0x14
#define ASN1_TELETEXSTRING	0x14	/* alias */
#define ASN1_IA5STRING		0x16
#define ASN1_UTCTIME		0x17
#define ASN1_GENERALIZEDTIME	0x18
#define ASN1_GRAPHIC_STRING	0x19
#define ASN1_ISO64_STRING	0x1a
#define ASN1_VISIBLESTRING	0x1a	/* alias */
#define ASN1_GENERAL_STRING	0x1b
#define ASN1_UNIVERSAL_STRING	0x1c
#define ASN1_BMPSTRING		0x1e

#define ASN1_T_STRUCTURED	0x20
#define ASN1_C_UNIVERSAL	0x00
#define ASN1_C_APPLICATION	0x40
#define ASN1_C_CTXSPECIFIC	0x80
#define ASN1_C_PRIVATE		0xc0

/* ASN.1 OBJECT IDENTIFIER : define int size */
#define OBJ_DUMMY		-1
#define OBJ_NULL		0
#define OBJ_UNKNOWN		0
#define OBJ_DIR_C		3000
#define OBJ_DIR_ST		3001
#define OBJ_DIR_L		3002
#define OBJ_DIR_O		3003
#define OBJ_DIR_OU		3004
#define OBJ_DIR_CN		3005
#define OBJ_DIR_EMAIL	9021		/* = OBJ_P9_EMAIL */

#define OBJ_X509v3_SubDirAtt	3009
#define OBJ_X509v3_SbjKeyIdt	3014
#define OBJ_X509v3_KEY_Usage	3015
#define OBJ_X509v3_PrvKeyUsgPrd	3016
#define OBJ_X509v3_SbjAltName	3017
#define OBJ_X509v3_IssAltName	3018
#define OBJ_X509v3_BASIC		3019
#define OBJ_X509v3_CRLNumber	3020
#define OBJ_X509v3_CRLReason	3021
#define OBJ_X509v3_HoldInsCode	3023
#define OBJ_X509v3_InvalData	3024
#define OBJ_X509v3_DeltaCRLInd	3027
#define OBJ_X509v3_IssDistPoint	3028
#define OBJ_X509v3_CertIssuer	3029
#define OBJ_X509v3_NameConst	3030
#define OBJ_X509v3_CRL_Point	3031
#define OBJ_X509v3_CERT_Pol		3032
#define OBJ_X509v3_CertPolMap	3033
#define OBJ_X509v3_AuthKeyIdt	3035
#define OBJ_X509v3_PolicyConst	3036
#define OBJ_X509v3_ExtKeyUsage	3037

#define OBJ_HASH_SHA1		5000
#define OBJ_HASH_MD2		8000
#define OBJ_HASH_MD5		8001
/*#define OBJ_CRYPT_DH		998*/
#define OBJ_CRYPT_RSA		9000
#define OBJ_CRYPT_DSA		7000
#define OBJ_CRYPT_ECDSA		7055

#define OBJ_CRYALGO_DESECB	5006
#define OBJ_CRYALGO_DESCBC	5007
#define OBJ_CRYALGO_DESOFB	5008
#define OBJ_CRYALGO_DESCFB	5009

#define OBJ_CRYALGO_RC2CBC	8022
#define OBJ_CRYALGO_RC4CBC	8024
#define OBJ_CRYALGO_3DESCBC	8027
#define OBJ_CRYALGO_RC5CBC	8028
#define OBJ_CRYALGO_DESCDMF	8030

#define OBJ_X962_FT_PRIME	7050
#define OBJ_X962_FT_CHR2	7051

#define OBJ_X962_c2pnb163v1	8060
#define OBJ_X962_c2pnb163v2	8061
#define OBJ_X962_c2pnb163v3	8062
#define OBJ_X962_c2pnb176w1	8063
#define OBJ_X962_c2tnb191v1	8064
#define OBJ_X962_c2tnb191v2	8065
#define OBJ_X962_c2tnb191v3	8066
#define OBJ_X962_c2onb191v4	8067
#define OBJ_X962_c2onb191v5	8068
#define OBJ_X962_c2pnb208w1	8069
#define OBJ_X962_c2tnb239v1	8070
#define OBJ_X962_c2tnb239v2	8071
#define OBJ_X962_c2tnb239v3	8072
#define OBJ_X962_c2onb239v4	8073
#define OBJ_X962_c2onb239v5	8074
#define OBJ_X962_c2pnb272w1	8075
#define OBJ_X962_c2pnb304w1	8076
#define OBJ_X962_c2tnb359v1	8077
#define OBJ_X962_c2pnb368w1	8078
#define OBJ_X962_c2tnb431r1	8079

#define OBJ_X962_prime192v1	8090
#define OBJ_X962_prime192v2	8091
#define OBJ_X962_prime192v3	8092
#define OBJ_X962_prime239v1	8093
#define OBJ_X962_prime239v2	8094
#define OBJ_X962_prime239v3	8095
#define OBJ_X962_prime256v1	8096

#define OBJ_PKIX_IDPE_AIA		8111
/* id-ad -- used in AuthorityInfoAccess */
#define OBJ_PKIX_IDAD_OCSP		8112
#define OBJ_PKIX_IDAD_CAISS		8113
#define OBJ_PKIX_IDAD_TMSTAMP	8114
#define OBJ_PKIX_IDAD_DVCS		8115
#define OBJ_PKIX_IDAD_CAREPS	8116

#define OBJ_PKIX_IDQT_CPS		8121
#define OBJ_PKIX_IDQT_UNOTICE	8122

#define OBJ_PKIX_IDKP_SVAUTH	8131
#define OBJ_PKIX_IDKP_CLAUTH	8132
#define OBJ_PKIX_IDKP_CDSIGN	8133
#define OBJ_PKIX_IDKP_EMAIL		8134
#define OBJ_PKIX_IDKP_IPSEC_ES	8135
#define OBJ_PKIX_IDKP_IPSEC_TN	8136
#define OBJ_PKIX_IDKP_IPSEC_US	8137
#define OBJ_PKIX_IDKP_TMSTAMP	8138
#define OBJ_PKIX_IDKP_OCSPSIGN	8139

#define OBJ_PKIX_IDIT_CAPROT	8141
#define OBJ_PKIX_IDIT_SIGNKEY	8142
#define OBJ_PKIX_IDIT_ENCKEY	8143
#define OBJ_PKIX_IDIT_PREFSYM	8144
#define OBJ_PKIX_IDIT_CAKEYUPD	8145
#define OBJ_PKIX_IDIT_CURCRL	8146
#define OBJ_PKIX_IDIT_UNSPOID	8147
#define OBJ_PKIX_IDIT_KEYPREQ	8150
#define OBJ_PKIX_IDIT_KEYPREP	8151
#define OBJ_PKIX_IDIT_REVPASS	8152
#define OBJ_PKIX_IDIT_IMPCONF	8153
#define OBJ_PKIX_IDIT_CWAITTIME	8154
#define OBJ_PKIX_IDIT_PKIMESS	8155

#define OBJ_PKIX_OCSP_BASIC		9101
#define OBJ_PKIX_OCSP_NONCE		9102
#define OBJ_PKIX_OCSP_CRL		9103
#define OBJ_PKIX_OCSP_RESPONSE	9104
#define OBJ_PKIX_OCSP_NOCHECK	9105
#define OBJ_PKIX_OCSP_ARCHIVE	9106
#define OBJ_PKIX_OCSP_SERVICE	9107

#define OBJ_SIGOIW_MD2RSA	5001
#define OBJ_SIGOIW_MD5RSA	5002
#define OBJ_SIGOIW_SHA1RSA	5003

#define OBJ_SIG_NULL		9001
#define	OBJ_SIG_MD2RSA		9002
#define OBJ_SIG_MD5RSA		9003
#define OBJ_SIG_SHA1RSA		9004
#define OBJ_SIG_SHA1DSA		7001
#define OBJ_SIG_SHA1ECDSA	7010

#define OBJ_NS_CERT_TYPE	9051
#define OBJ_NS_CERT_BASE	9052
#define OBJ_NS_CERT_RVKURL	9053
#define OBJ_NS_CERT_CRLURL	9054
#define OBJ_NS_CERT_RENEW	9055
#define OBJ_NS_CERT_POLICY	9056
#define OBJ_NS_CERT_SSL_SV	9057
#define OBJ_NS_CERT_COMMENT	9058

#define OBJ_P5_MD2DES		9061
#define OBJ_P5_MD2RC2		9062
#define OBJ_P5_MD5DES		9063
#define OBJ_P5_MD5RC2		9064
#define OBJ_P5_SHA1DES		9065
#define OBJ_P5_SHA1RC2		9066
#define OBJ_P7_DATA    		9011
#define OBJ_P7_SIGNED		9012
#define OBJ_P7_ENVELP		9013
#define OBJ_P7_SIGandENV	9014
#define OBJ_P7_DIGESTED		9015
#define OBJ_P7_ENCRYPTED	9016
#define OBJ_P9_EMAIL		9021
#define OBJ_P9_UNST_NAME	9022
#define OBJ_P9_CONTENT_TYPE	9023
#define OBJ_P9_MESS_DGST	9024
#define OBJ_P9_SIGN_TIME	9025
#define OBJ_P9_COUNT_SIG	9026
#define OBJ_P9_CHALL_PWD	9027
#define OBJ_P9_UNST_ADRS	9028
#define OBJ_P9_EXT_CERT_ATT	9029
#define OBJ_P9_ISS_SN		9030
#define OBJ_P9_PASSCHECK	9031
#define OBJ_P9_PUBKEY		9032
#define OBJ_P9_SIG_DESCR	9033
#define OBJ_P9_EXT_REQ		9034
#define OBJ_P9_SMIME_CAP	9035
#define OBJ_P9_SMIME		9036
#define OBJ_P9_CERT_TYPES	9042
#define OBJ_P9_CRL_TYPES	9043
#define OBJ_P9_Friendly		9040
#define OBJ_P9_LocalKEY		9041

#define OBJ_MOJ_JCertPol	9071
#define OBJ_MOJ_Registrar	9072
#define OBJ_MOJ_RegCoInfo	9073
#define OBJ_MOJ_SuspCode	9081
#define OBJ_MOJ_TimeLimit	9082
#define OBJ_MOJ_GenmReq		9083
#define OBJ_MOJ_GenpRes		9084
#define OBJ_MOJ_GenSpReq	9085
#define OBJ_MOJ_GenSpRes	9086

#define OBJ_MS_EU_LSTSIG	10101
#define OBJ_MS_EU_SGC		10103
#define OBJ_MS_EU_ENCFSYS	10104

#define OBJ_MS_EU_ICLOGON	10112
#define OBJ_MS_GN_UPN		10113

#define OBJ_P9_X509CERT		10000
#define OBJ_P9_sdsiCERT		10001
#define OBJ_P9_X509CRL		10002

#define OBJ_P12Pbe_128RC4	10011
#define OBJ_P12Pbe_40RC4	10012
#define OBJ_P12Pbe_3K3DES	10013
#define OBJ_P12Pbe_2K3DES	10014
#define OBJ_P12Pbe_128RC2	10015
#define OBJ_P12Pbe_40RC2	10016
#define OBJ_P12v1Bag_KEY	11001
#define OBJ_P12v1Bag_PKCS8	11002
#define OBJ_P12v1Bag_CERT    	11003
#define OBJ_P12v1Bag_CRL      	11004
#define OBJ_P12v1Bag_SECRET    	11005
#define OBJ_P12v1Bag_SAFE    	11006

/* mv is moved pointer size at *in */
/* asn1_print.c */
void switch_str(int obj,char *sb);
void OK_ASN1_print(unsigned char *in);
void ASN1_print(unsigned char *in,int *mv);
unsigned char *ASN1_dup(unsigned char *in);

/* asn1.c */
int ASN1_length(unsigned char *in,int *mv);
void ASN1_indef_count(unsigned char *in,int *mv,int *size);

int ASN1_boolean(unsigned char *in,int *mv);
int ASN1_integer_(unsigned char *in,int *mv,int no_check_tag);
int ASN1_enumerated(unsigned char *in,int *mv);
#define ASN1_integer(in,mv)	ASN1_integer_((in),(mv),0)
/* if error occured, return -1 */
int ASN1_bitstring_(unsigned char *in,int *mv,unsigned char **ret,int *ret_size,int *no_use_bit,int no_check_tag);
int ASN1_octetstring_(unsigned char *in,int *mv,unsigned char **ret,int *ret_size,int no_check_tag);
int ASN1_object_id_(unsigned char *in,int *mv,unsigned char **ret,int *ret_size,int no_check_tag);
#define ASN1_bitstring(in,mv,ret,rsz,nbit)	ASN1_bitstring_((in),(mv),(ret),(rsz),(nbit),0)
#define ASN1_octetstring(in,mv,ret,rsz)		ASN1_octetstring_((in),(mv),(ret),(rsz),0)
#define ASN1_object_id(in,mv,ret,rsz)		ASN1_object_id_((in),(mv),(ret),(rsz),0)
/* if error occured, return NULL */
char *ASN1_printable(char *in,int *mv);
char *ASN1_utf8(char *in,int *mv);
char *ASN1_iso64(char *in,int *mv);
char *ASN1_t61(char *in,int *mv);
char *ASN1_ia5(char *in,int *mv);
char *ASN1_bmp(char *in,int *mv);
char *ASN1_utctime(char *in,int *mv);
char *ASN1_gtime(char *in,int *mv);
#define ASN1_time(a,b)	ASN1_utctime((a),(b))
int ASN1_tlen(unsigned char *in);
unsigned char *ASN1_next_(unsigned char *in,int *mv);
unsigned char *ASN1_step_(unsigned char *in,int n,int *mv);
unsigned char *ASN1_skip_(unsigned char *in,int *mv);
unsigned char *ASN1_find_tag(unsigned char *asn1,char tag);
#define ASN1_next(in)	ASN1_next_((in),NULL)
#define ASN1_step(in,n)	ASN1_step_((in),(n),NULL)
#define ASN1_skip(in)	ASN1_skip_((in),NULL)

/* asn1_set.c */
void ASN1_set_length(int len,unsigned char *ret,int *ret_len);
void ASN1_set_sequence(int len,unsigned char *der,int *ret_len);
void ASN1_set_set(int len,unsigned char *der,int *ret_len);
void ASN1_set_explicit(int len,char num,unsigned char *der,int *ret_len);

#define ASN1_set_implicit(num,der)	(*der)=((num)|ASN1_C_CTXSPECIFIC|(ASN1_T_STRUCTURED&(*der)))

void ASN1_set_boolean(int flag,unsigned char *der, int *ret_len);
void ASN1_set_integer(int num,unsigned char *der,int *ret_len);
void ASN1_set_enumerated(int num,unsigned char *der,int *ret_len);
void ASN1_set_bitstring(int nobit,int len,unsigned char *in,
			unsigned char *ret,int *ret_len);
void ASN1_set_octetstring(int len,unsigned char *in,
			  unsigned char *ret,int *ret_len);
int ASN1_set_printable(char *str,unsigned char *ret,int *ret_len);
int ASN1_set_ia5(char *str,unsigned char *ret,int *ret_len);
int ASN1_set_t61(char *str,unsigned char *ret,int *ret_len);
int ASN1_set_utc(char *str,unsigned char *ret,int *ret_len);
int ASN1_set_bmp(char *str,unsigned char *ret,int *ret_len);
int ASN1_set_utf8(char *str,unsigned char *ret,int *ret_len);/* not ready to use */
void ASN1_set_binary(int tag,int len,unsigned char *in,
			  unsigned char *ret,int *ret_len);
void ASN1_set_null(unsigned char *der);
void ASN1_set_end(unsigned char *der);
void asn1_set_str(int type,char *str,unsigned char *ret,int *ret_len);
int asn1_str_type(char *str);
int bmp_len(char *str);
int bmp_strcmp(char *c1,char *c2);
void asn1_check_derbit(int len, unsigned char *cp, int *nobit, int *ret_len);

/* asn1_file.c */
unsigned char *ASN1_read_der(char *fname);
int ASN1_write_der(unsigned char *der,char *fname);

/* asn1_obj.c */
int ASN1_object_2int(unsigned char *cp);
int ASN1_int_2object(int obj, unsigned char *ret, int *ret_len);
int str2objid(char *txt,unsigned char *ret,int max);
int objid2str(unsigned char *id,char *sb,int max);

/* asn1_cert.c */
int ASN1_do_digest(int type,unsigned char *der,unsigned char *ret,int *ret_len);
int ASN1_vfy_sig(Key *pub, unsigned char *der, unsigned char *sig, int sig_algo);
int asn1_get_algoid(unsigned char *in, void **param);
Key *ASN1_get_pubkey(unsigned char *in);
char *ASN1_get_subject(unsigned char *in,CertDN *dn);
int ASN1_get_certext(unsigned char *in, Cert *ct);
Cert *ASN1_read_cert(unsigned char *in);
char *asn1_get_str(unsigned char *cp,int *i);
CertExt *asn1_get_exts(unsigned char *cp,int *ret_len);

/* asn1_req.c */
Cert *ASN1_read_req(unsigned char *in);

/* asn1_crtp.c */
CertPair *ASN1_read_crtp(unsigned char *in);

/* asn1_crl.c */
CRL *ASN1_read_crl(unsigned char *in);

/* asn1_rsa.c */
Prvkey_RSA *ASN1_read_rsaprv(unsigned char *in);
int ASN1_int2LNm(unsigned char *in,LNm *ret,int *mv);
int ASN1_LNm2int(LNm *n,unsigned char *ret,int *mv);

/* asn1_dsa.c */
DSAParam *ASN1_read_dsaparam(unsigned char *der,int no_seq);
Prvkey_DSA *ASN1_read_dsaprv(unsigned char *der);

/* asn1_ecc.c */
ECParam *ASN1_read_ecparam(unsigned char *in);
int ASN1_get_ecfieldID(unsigned char *in,ECParam *ret);
int ASN1_get_eccurve(unsigned char *in,ECParam *ret);
ECp *ASN1_get_ecpoint(unsigned char *in,ECParam *ecp);

/* asn1_ecdsa.c */
Prvkey_ECDSA *ASN1_read_ecdsaprv(unsigned char *der);
Pubkey_ECDSA *ASN1_read_ecdsapub(unsigned char *der);

/* asn1_p12.c */
PKCS12 *ASN1_read_p12(unsigned char *in);
int ASN1_authsafe(PKCS12 *p12,unsigned char *safe);
P12_CertBag *ASN1_get_certbag(unsigned char *in);
P12_CRLBag *ASN1_get_crlbag(unsigned char *in);
P12_KeyBag *ASN1_get_keybag(unsigned char *in);
P12_KeyBag *ASN1_get_p8bag(unsigned char *in);
int ASN1_get_fri_loc(unsigned char *in,char **frname,unsigned char *id);

/* asn1_p7sign.c */
PKCS7 *ASN1_read_p7s(unsigned char *der);
int ASN1_get_signerInfo(unsigned char *in, SignerInfo *ret);
AuthAtt *ASN1_get_authatt(unsigned char *in);

/* asn1_p7env.c */
PKCS7 *ASN1_read_p7env(unsigned char *der);
int ASN1_get_recipi(unsigned char *in, RecipInfo *ret);
int ASN1_get_encCnt(unsigned char *in, EncCntInfo *ret);

/* asn1_ext.c */
CertExt *ASN1_get_ext(int id, unsigned char *in);
ExtGenNames *asn1_get_genname(unsigned char *in);
ExtGenNames *ASN1_get_gennames(unsigned char *in);
OtherName *asn1_get_othname(unsigned char *in,int *ret_len);

ExtPolUN *asn1_get_unotice(unsigned char *in,int *ret_len);
ExtPolInfo *asn1_get_polqualinfo(unsigned char *in);
ExtCertPol *ASN1_get_certpol(unsigned char *in);

ExtSubTrees *asn1_ext_gensubtrees(unsigned char *in);
int asn1_ext_distpoint(unsigned char *in,DistPointName *dpn);

AttrTAV *asn1_get_attrs(unsigned char *in, int *ret_len);


/* asn1_extdef.c */
CertExt *ASN1_ext_authkey(unsigned char* in);
CertExt *ASN1_ext_sbjkey(unsigned char* in);
CertExt *ASN1_ext_keyusage(unsigned char *in);
CertExt *ASN1_ext_extkeyusage(unsigned char *in);
CertExt *ASN1_ext_prvkey_period(unsigned char *in);
CertExt *ASN1_ext_certpol(int id,unsigned char *in);
CertExt *ASN1_ext_certpolmap(unsigned char *in);
CertExt *ASN1_ext_altname(int id,unsigned char *in);
CertExt *ASN1_ext_basiccons(unsigned char *in);
CertExt *ASN1_ext_namecons(unsigned char *in);
CertExt *ASN1_ext_policons(unsigned char *in);
CertExt *ASN1_ext_crlpoint(unsigned char *in);

CertExt *ASN1_ext_pkixaia(unsigned char *in);
CertExt *ASN1_ext_ocspnochk(unsigned char *in);

CertExt *ASN1_ext_extreq(unsigned char *in);

CertExt *ASN1_ext_reasoncode(unsigned char *in);
CertExt *ASN1_ext_crlnumber(unsigned char *in);
CertExt *ASN1_ext_issdistpt(unsigned char *in);

CertExt *ASN1_ext_comment(int id,unsigned char *in);
CertExt *ASN1_ext_nscerttype(unsigned char *in);

#define ASN1_ext_nscrlurl(in)	ASN1_ext_comment(OBJ_NS_CERT_CRLURL,(in))
#define ASN1_ext_nscomment(in)	ASN1_ext_comment(OBJ_NS_CERT_COMMENT,(in))
#define ASN1_ext_mojregist(in)	ASN1_ext_comment(OBJ_MOJ_Registrar,(in))
#define ASN1_ext_p9unstname(in)	ASN1_ext_comment(OBJ_P9_UNST_NAME,(in))
#define ASN1_ext_p9chapass(in)	ASN1_ext_comment(OBJ_P9_CHALL_PWD,(in))


/* AttrTAV == CertExt */
CertExt *ASN1_ext_mojcorpinfo(unsigned char *in);
AttrTAV *ASN1_ext_timelimit(unsigned char *in); 
AttrTAV *ASN1_ext_suspcode(unsigned char *in);
AttrTAV *ASN1_ext_mojgenmreq(unsigned char *in);
AttrTAV *ASN1_ext_mojgenpres(unsigned char *in);
AttrTAV *ASN1_ext_mojgenspreq(unsigned char *in);
AttrTAV *ASN1_ext_mojgenspres(unsigned char *in);


#ifdef  __cplusplus
}
#endif
#endif  /* __OK_ASN1_H__ */
