/* ok_pkcs7.h */
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
/*
 * This file is included in ok_pkcs.h
 */

#ifndef __OK_PKCS7_H__
#define __OK_PKCS7_H__

#ifdef  __cplusplus
extern "C" {
#endif

/*---- PKCS7 Structures ----*/
typedef struct PKCS7ContentInfo P7_Content;
struct PKCS7ContentInfo{ /* nomal data type */
	int		p7type;		/* use ASN.1 object id */

	int		size;
	unsigned char	*data;
};

/*--------------------------*/
typedef struct authenticatedAttribute AuthAtt;
struct authenticatedAttribute{
	AuthAtt	*next;

	int	der_size;
	unsigned char	*der;
};

typedef struct setOfSignerInfo SignerInfo;
struct setOfSignerInfo{
	SignerInfo	*next;

	int		version;
	int		serialNum;
	CertDN	iss_dn;
	char	*iss_str;
	int		digest_algo;

	AuthAtt	*auth;

	int		enc_algo;	/* digest and encryption algorithm */
	int		sig_size;
	unsigned char	*signature;

	AuthAtt	*unauth;
};

typedef struct P7_SignedDataType{
	int		p7type;		/* use ASN.1 object id */

	int		version;
	int		digest_algo;
	/*  Certificates and CRLs are top of PKCS7 */

	int	cnt_size;
	unsigned char *content; /* get data from ContentInfo (option?) */

	SignerInfo	*signer;
}P7_Signed;

/*--------------------------*/
typedef struct RecipientInfo RecipInfo;
struct RecipientInfo{
	RecipInfo	*next;

	int		version;
	int		serialNum;
	CertDN	iss_dn;
	char	*iss_str;

	int		enc_algo;
	int		size;
	unsigned char *key;
};

typedef struct EncryptedContentInfo{
	int		type;

	int		enc_algo;
	int		iter;
	int		iv_size;
	unsigned char *iv;

	int		size;
	unsigned char *data;
}EncCntInfo;

typedef struct P7_EnvelopedDataType{
	int		p7type;		/* use ASN.1 object id */

	int			version;
	RecipInfo	*recipi;
	EncCntInfo	*encCnt;
}P7_Envelope;

/*--------------------------*/

typedef struct P7_SignedAndEnvelopedDataType{
	int		p7type;		/* use ASN.1 object id */

	int			version;
	RecipInfo	*recipi;
	int			digest_algo;
	EncCntInfo	*encCnt;
	/*  Certificates and CRLs are top of PKCS7 */
	SignerInfo	*signer;

}P7_SignEnv;

/*--------------------------*/

typedef struct P7_DigestedDataType{
	int		p7type;		/* use ASN.1 object id */

	int		version;
	int		digest_algo;

	int		size;
	unsigned char *digest;
}P7_Digest;

/*--------------------------*/

typedef struct P7_EncryptedDataType{
	int		p7type;		/* use ASN.1 object id */

	int		version;
	EncCntInfo	*encCnt;
}P7_Encrypted;

/*--------------------------*/

typedef struct pkcs7{
  int		version;	/* it's not used in pkcs7 */
  P12_Baggage	*bag;	/* Certificates and CRLs */

  P7_Content	*cont;
  unsigned char	*der;
}PKCS7;

/* pkcs7.c */
PKCS7 *P7_new(int type);
P7_Content *P7_cont_new(int type);
SignerInfo *P7_signer_new();
AuthAtt *P7_authatt_new();
RecipInfo *P7_recip_new();
EncCntInfo *P7_enccont_new();

void P7_free(PKCS7 *p7);
void P7_cont_free(P7_Content *cont);
void P7_authatt_free(AuthAtt *att);
void P7_signer_free(SignerInfo *sig);
void P7_recip_free(RecipInfo *rci);
void P7_enccont_free(EncCntInfo *eci);

PKCS7 *P7_dup(PKCS7 *org);
P7_Content *P7_cont_dup(P7_Content *org);
SignerInfo *P7_signer_dup(SignerInfo *org);
AuthAtt *P7_authatt_dup(AuthAtt *org);
RecipInfo *P7_recip_dup(RecipInfo *org);
EncCntInfo *P7_enccont_dup(EncCntInfo *org);

/* p7_data.c */
unsigned char *ASN1_get_p7data(unsigned char *in,int *ret_len);
unsigned char *P7_data_toDER(int len,unsigned char *in,int inf_type,unsigned char *buf,int *ret_len);

/* p7_enc.c */
unsigned char *ASN1_get_p7enc(unsigned char *in,int *ret_len);
unsigned char *P7_encrypted_toDER(int len,unsigned char *cry,int algo,unsigned char *buf,int *ret_len);

/* p7_sign.c */
/* use user certs and private key */
PKCS7 *P7s_get_signed(PKCS12 *p12, unsigned char *data, int len, int digest_algo);
int P7s_get_signerInfo(PKCS7 *p7, unsigned char *data, int len);
int P7s_get_authatt(SignerInfo *sig,unsigned char *data,int len);
int P7s_get_signature(SignerInfo *sig,Key *key,unsigned char *data,int len);
int P7s_verify_signed(PKCS7 *p7, unsigned char *data, int len);
unsigned char *P7s_get_attdigest(SignerInfo *sig, unsigned char *data, int len, int *ret_len);
unsigned char *P7s_get_messagedigest_attr(SignerInfo *sig);

/* p7_env.c */
 /* make new encrypted envelope data */
PKCS7 *P7m_encrypt_enveloped(PKCS7 *p7b,unsigned char *data,int data_len);
unsigned char *P7m_recip_get_key(Key *pubkey,unsigned char *pass, int ps_size);
int P7m_get_recipInfo(RecipInfo *recipi,PKCS7 *p7b,unsigned char *pass, int ps_size);
int P7m_get_encCnt(EncCntInfo *ei,unsigned char *pass, int ps_size);
 /* decrypt enveloped data */
unsigned char *P7m_decrypt_enveloped(PKCS7 *p7, Cert *ct, Key *key);
unsigned char *P7m_decrypt_encCnt(EncCntInfo *ei, unsigned char *pass,int ps_size);



/* p7s_asn1.c */
unsigned char *P7_signed_toDER(PKCS7 *p7,unsigned char *buf,int *ret_len);
int P7_DER_signed_cert(PKCS7 *p7,unsigned char *cn0,int *ret_len);
int P7_DER_signed_crl(PKCS7 *p7,unsigned char *cn1,int *ret_len);
int P7_DER_sigCont(P7_Signed *sig,unsigned char *cp,int *ret_len);
int P7_DER_algoId(int algo_id,unsigned char *ret,int *ret_len);
int P7_DER_signerInfo(SignerInfo *signer,unsigned char *ret,int *ret_len);
int P7_DER_authatt(AuthAtt *att,unsigned char *ret,int *ret_len);
int P7s_estimate_der_size(PKCS7 *p7);

/* p7s_attr.c */
AuthAtt *P7s_attr_smimecap(int cry_algo,int size);
AuthAtt *P7s_attr_signtime();
AuthAtt *P7s_attr_cntType(int type);
AuthAtt *P7s_attr_digest(SignerInfo *si,unsigned char *data,int len);


/* p7m_asn1.c */
unsigned char *P7_envelope_toDER(PKCS7 *p7,unsigned char *buf,int *ret_len);
int P7_DER_recipi(RecipInfo *rci,unsigned char *ret,int *ret_len);
int P7_DER_encCnt(EncCntInfo *enc,unsigned char *ret,int *ret_len);
int P7_DER_contentEncAlgo(EncCntInfo *enc,unsigned char *ret,int *ret_len);
int P7m_estimate_der_size(PKCS7 *p7);

/* p7_file.c */
PKCS7 *P7s_read_file(char *fname);
int P7s_write_file(PKCS7 *p7, char *fname);
PKCS7 *P7m_read_file(char *fname);
int P7m_write_file(PKCS7 *p7, char *fname);
void P7_print(PKCS7 *p12);


#define P7b_read_file(fn)	P7s_read_file(fn)
#define P7b_write_file(pk,fn)	P7s_write_file(pk,fn)

/* PKCS#7 Signed -- digest algorithm.
 * this one should use OBJ_HASH_*
 */
extern int default_p7s_digest_algo;


#ifdef  __cplusplus
}
#endif

#endif /* __OK_PKCS_H__ */
