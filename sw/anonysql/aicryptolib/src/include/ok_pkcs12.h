/* ok_pkcs12.h */
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
	 
#ifndef __OK_PKCS12_H__
#define __OK_PKCS12_H__

#ifdef  __cplusplus
extern "C" {
#endif

/*---- PKCS12 Structures ----*/
typedef struct pkcs12_Bag_list P12_Baggage;
struct pkcs12_Bag_list{
	int		type;
	P12_Baggage	*next;

	unsigned char	*friendlyName;
	unsigned char	localKeyID[4];
};

typedef struct pkcs12{
	int		version;
	P12_Baggage	*bag;
	long		reserve;	/* (= NULL) this is just dummy for PKCS7 */
}PKCS12;


typedef struct pkcs12_BagID_key{
	int		type;
	P12_Baggage	*next;

	char	*friendlyName;
	char	localKeyID[4];

	Key	*key;

}P12_KeyBag;

typedef struct pkcs12_BagID_CERT{
	int		type;
	P12_Baggage	*next;

	char	*friendlyName;
	char	localKeyID[4];

	Cert	*cert;

}P12_CertBag;

typedef struct pkcs12_BagID_CRL{
	int		type;
	P12_Baggage	*next;

	char	*friendlyName;
	char	localKeyID[4];

	CRL	*crl;

}P12_CRLBag;

typedef struct decrypt_info{
	int		plen;	/* password length */
	unsigned char	*pass;	/* password */
	int		slen;	/* salt length */
	unsigned char *salt;	/* salt */

	unsigned char	*iv;	/* initialize vector */

	int		klen;	/* keylength (byte) */
	int		iter;	/* iteration */
	int		hash;	/* hash algo for key generation */
	int		info;	/* etc information */

	unsigned char	*cry;	/* encrypted data top */
	long		clen;	/* encrypted data length */
}Dec_Info;


#define P12_ID_GENKEY	1
#define P12_ID_GENIV	2
#define P12_ID_GENMAC	3

/* just for P12_estimate_der_size */
#define P12_ALLBAGS		0xffff



/* pkcs12.c */
PKCS12 *P12_new(void);
P12_KeyBag *P12_Key_new(void);
P12_CertBag *P12_Cert_new(void);
P12_CRLBag *P12_CRL_new(void);
void P12_free(PKCS12 *p12);
void P12Bag_free(P12_Baggage *bg);
void P12Bag_free_all(P12_Baggage *bg);
void P12_add_bag(PKCS12 *p12,P12_Baggage *bg);


/* p12_key.c */
unsigned char *P12_gen_key(Dec_Info *dif,int id);

#define P12_gen_iv(dif)		P12_gen_key(dif,P12_ID_GENIV)
#define P12_gen_mackey(dif)	P12_gen_key(dif,P12_ID_GENMAC)

/* Key_RC2 *P12_gen_RC2key(Dec_Info *dif);   */
/* Key_3DES *P12_gen_3DESkey(Dec_Info *dif); */

/* p12_file.c */
PKCS12 *P12_read_file(char *fname);
int P12_write_file(PKCS12 *p12,char *fname);

void print_f_l(P12_Baggage *bg);
void P12_print(PKCS12 *p12);

/* p12_asn1.c */
unsigned char *P12_toDER(PKCS12 *p12,unsigned char *buf,int *ret_len);
int P12_DER_mac(unsigned char *safe,unsigned char *der,int *ret_len);
int P12_DER_authsafe(PKCS12 *p12,unsigned char *safe,int *ret_len);
int P12_DER_keybag(PKCS12 *p12,unsigned char *der,int *ret_len);
int P12_DER_certbags(PKCS12 *p12,unsigned char *der,int *ret_len);
int P12_get_DER_f_l(P12_Baggage *bg,unsigned char *der,int *ret_len);
int P12_get_DER_keybag(P12_KeyBag *kb,unsigned char *der,int *ret_len);
int P12_get_DER_certbag(P12_CertBag *cb,unsigned char *der,int *ret_len);
int P12_estimate_der_size(PKCS12 *p12,int bag_type);

/* p12_mac.c */
int P12_gen_mac(Dec_Info *dif,unsigned char *safe,unsigned char *ret);
int P12_new_mac(unsigned char *safe,unsigned char *salt,unsigned char *mac);
int P12_verify_mac(char *prompt,unsigned char *in,unsigned char *safe);

/* p12_tool.c */
P12_Baggage *P12_find_bag(PKCS12 *p12,int type,unsigned char keyID);
int P12_max_depth(PKCS12 *p12,int type);

int P12_set_KeyBag(P12_KeyBag *kb,Key *key,char *fname,unsigned char id);
int P12_set_CertBag(P12_CertBag *cb,Cert *cert,char *fname,unsigned char id);
int P12_set_CRLBag(P12_CRLBag *cb,CRL *crl,char *fname,unsigned char id);

int P12_add_key(PKCS12 *p12,Key *key,char *fname,unsigned char id);
int P12_add_cert(PKCS12 *p12,Cert *ct,char *fname,unsigned char id);
int P12_add_crl(PKCS12 *p12,CRL *crl,char *fname,unsigned char id);
int P12_copy_p12bags(PKCS12 *to,PKCS12 *from);
void P12_mov_p12bags(PKCS12 *p12,PKCS12 *mov);
PKCS12 *P12_dup(PKCS12 *org);

Cert *P12_get_usercert(PKCS12 *p12);
Key *P12_get_privatekey(PKCS12 *p12);
int P12_check_chain(PKCS12 *p12,int print);
int get_dn_for_friendlyname(CertDN *dn,char *ret);
unsigned char *get_frname_from_dn(Cert *ct);

#ifdef  __cplusplus
}
#endif

#endif /* __OK_PKCS12_H__ */


