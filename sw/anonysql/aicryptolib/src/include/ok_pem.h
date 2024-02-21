/* ok_pem.h */
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

#ifndef __OK_PEM_H__
#define __OK_PEM_H__

#include "ok_rsa.h"
#include "ok_dsa.h"
#include "ok_ecdsa.h"
#include "ok_x509.h"
#include "ok_pkcs.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* pem.c */
Cert *PEM_read_cert(char *fname);
Req *PEM_read_req(char *fname);
CRL *PEM_read_crl(char *fname);
CertPair *PEM_read_crtp(char *fname);

unsigned char *PEM_read_cert_2der(char *fname);
unsigned char *PEM_read_crl_2der(char *fname);
unsigned char *PEM_read_req_2der(char *fname);
unsigned char *PEM_read_crtp_2der(char *fname);

char *pem_read2der(char *begin,char *end,char *fname);
unsigned char *get_file2buf(char *fname,int *len);

/* pem_key.c */
Prvkey_RSA *PEM_read_rsaprv(char *fname);
Prvkey_DSA *PEM_read_dsaprv(char *fname);
DSAParam *PEM_read_dsaparam(char *fname);
Prvkey_ECDSA *PEM_read_ecdsaprv(char *fname);
ECParam *PEM_read_ecparam(char *fname);

unsigned char *PEM_read_rsaprv_2der(char *fname);
unsigned char *PEM_read_dsaprv_2der(char *fname);
unsigned char *PEM_read_ecdsaprv_2der(char *fname);

unsigned char *pem_read_prvkey_2der(char *begin,char *end,char *fname);

/* pem_w.c */
int PEM_write_cert(Cert *cert,char *fname);
int PEM_write_req(Req *req,char *fname);
int PEM_write_crl(CRL *crl,char *fname);
int PEM_write_crtp(CertPair *crtp,char *fname);

int PEM_write_rsaprv(Prvkey_RSA *rsa,char *fname);
int PEM_write_dsaprv(Prvkey_DSA *dsa,char *fname);
int PEM_write_dsaparam(DSAParam *dpm,char *fname);
int PEM_write_ecdsaprv(Prvkey_ECDSA *dsa,char *fname);
int PEM_write_ecparam(ECParam *dpm,char *fname);

int pem_write_prvkey(unsigned char *der,char *fname,char *begin,char *end);
int pem_write(unsigned char *der,char *fname,char *begin,char *end);


/* pem_cry.c */
unsigned char *PEM_msg_decrypt(unsigned char *cry, int clen,
			       unsigned char *iv, int type);
unsigned char *PEM_msg_encrypt(unsigned char *in, int *ret_len,
			       unsigned char *ivc, int type);

/* pem_msg.c */
unsigned char *PEM_read_message(char *fname,int *len);
unsigned char *PEM_decode_message(char *buf,int *len,char *begin,char *end);
int PEM_write_message(unsigned char *buf,int len ,char *fname);
unsigned char *PEM_encode_message(char *buf,int len,char *begin,char *end);

#define PEM_decode_msg(x,i) \
    PEM_decode_message((x),(i),"-----BEGIN PRIVACY-ENHANCED MESSAGE-----",\
			   "-----END PRIVACY-ENHANCED MESSAGE-----")

#define PEM_encode_msg(x,i) \
    PEM_encode_message((x),(i),"-----BEGIN PRIVACY-ENHANCED MESSAGE-----",\
		           "-----END PRIVACY-ENHANCED MESSAGE-----")

/* pem_pkcs.c */
PKCS7 *PEM_read_p7(char *fname);
Key *PEM_read_p8(char *fname);
Key *PEM_read_p8enc(char *fname);

int PEM_write_p7(PKCS7 *p7,char *fname);
int PEM_write_p8(Key *key,char *fname);
int PEM_write_p8enc(Key *key,char *fname);

unsigned char *PEM_read_p7_2der(char *fname);
unsigned char *PEM_read_p8_2der(char *fname);
unsigned char *PEM_read_p8enc_2der(char *fname);

/***** global values *****/
/* just use OBJ_CRYALGO_* */
extern int default_pem_cry_algo;


#ifdef  __cplusplus
}
#endif

#endif /* __OK_PEM_H__ */
