/* ok_pkcs.h */
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

#ifndef __OK_PKCS_H__
#define __OK_PKCS_H__

#include "ok_err.h"
#include "ok_des.h"
#include "ok_rc2.h"
#include "ok_x509.h"

#include "ok_pkcs12.h"
#include "ok_pkcs7.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* dec_info.c */
Dec_Info *DInfo_new(void);
void DInfo_free(Dec_Info *dif);
int dif_set_salt(Dec_Info *dif);


/* pbe.c */
int ASN1_pbe_algorithm(unsigned char *cp,int *pbe,
		       unsigned char **salt,int *slen,int *iter);
int Pbe_DER_algorithm(Dec_Info *dif,unsigned char *der,int *ret_len);

int Pbe_get_decrypted(Dec_Info *dif,unsigned char *ret);
int Pbe_set_encrypted(Dec_Info *dif);

/* pbe_cry.c */
int Pbe_RC2_decrypt(Dec_Info *dif,unsigned char *ret);
int Pbe_DES_decrypt(Dec_Info *dif,unsigned char *ret);
int Pbe_3DES_decrypt(Dec_Info *dif,unsigned char *ret);
int Pbe_RC2_encrypt(Dec_Info *dif);
int Pbe_DES_encrypt(Dec_Info *dif);
int Pbe_3DES_encrypt(Dec_Info *dif);

int RFC1423_enc_padding(int block,int len,unsigned char *buf);
int RFC1423_check_padding(int len,unsigned char *buf);

/* pbe_key.c */
Key *Pbe_gen_key(Dec_Info *dif);
int Pbe_gen_iv(Dec_Info *dif);

int PBKDF1(Dec_Info *dif,unsigned char *buf);
Key_RC2 *P5_gen_RC2key(Dec_Info *dif);
Key_DES *P5_gen_DESkey(Dec_Info *dif);

/* pkcs8.c */
Key *ASN1_p8_prvkey(unsigned char *in);
unsigned char *ASN1_p8_decrypted(unsigned char *in,int *ret_len);

unsigned char *P8_toDER(Key *key,unsigned char *buf,int *ret_len);
unsigned char *P8_encrypted_toDER(Key *key,int algo,unsigned char *buf,int *ret_len);
int P8_encrypted_toDER_in(unsigned char *in,int algo,unsigned char *ret,int *ret_len);
int P8_estimate_der_size(Key *key);

/* p8_file.c */
Key *P8_read_file(char *fname);
int P8_write_file(Key *p8,char *fname);
Key *P8enc_read_file(char *fname);
int P8enc_write_file(Key *p8,char *fname);

/**** global values ****/
/* just use OBJ_CRYALGO_*, because of object identifier */
extern int default_p7env_cry_algo;
extern int default_p7env_passwd_len; /* bit length of password */

/* just use OBJ_P12Pbe_*, because of object identifier */
extern int default_p12_cb_cry_algo;
extern int default_p12_kb_cry_algo;

/* just use OBJ_P5Pbe_* for encryption PKCS#8 file */
extern int default_p5_cry_algo;

#ifdef  __cplusplus
}
#endif

#endif /* __OK_PKCS_H__ */
