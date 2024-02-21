/* ok_tool.h */
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

#ifndef __OK_TOOL_H__
#define __OK_TOOL_H__


#include "ok_pkcs.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* pass.c */
void OK_set_prompt(char *prom);
void OK_set_passwd(char *pwd);
void OK_clear_passwd();

void OK_get_localpass(char *ret);
void OK_get_passwd(char *prompt,unsigned char *ret,int mode);
void OK_get_password_p12(char *prompt,Dec_Info *dif,int mode);

#ifdef __WINDOWS__
void OK_set_pwd_dosmode(int flag);
#endif

void as2uni(char *in,unsigned char *ret);
void uni2as(unsigned char *in,char *ret);

/* digest.c */
unsigned char *OK_do_digest(int digest_algo,unsigned char *data,int data_len,
							unsigned char *ret,int *ret_len);

/* signature.c */
int OK_do_signature(Key *prv, unsigned char *data, int data_len, unsigned char **signature,int *sig_len, int sig_algo);
int OK_do_verify(Key *pub, unsigned char *digest, unsigned char *sig, int sig_algo);
unsigned char *OK_do_sign(Key *key,unsigned char *data,int data_len,unsigned char *ret);
unsigned char *P1_do_sign(Key *prv,unsigned char *data,int *ret_len);
unsigned char *P1_sign_digest(Key *key,unsigned char *digest,int dig_size,int dig_type);
unsigned char *P1_pad2digest(unsigned char *dec,int *dig_algo);

/* defalgo.c */
void OK_set_p12_cb_cry_algo(int algo);
void OK_set_p12_kb_cry_algo(int algo);
void OK_set_p7s_digest_algo(int algo);
void OK_set_p7env_cry_algo(int algo);
void OK_set_p7env_passwd_len(int bit_len);
void OK_set_p5_cry_algo(int algo);
void OK_set_pem_cry_algo(int algo);
void OK_set_sign_digest_algo(int algo);
void OK_set_cert_sig_algo(int algo);
void OK_set_crl_sig_algo(int algo);
void OK_set_ext_flag(int locate, unsigned char flag);
void OK_add_ext_flag(int locate, unsigned char flag);
void OK_del_ext_flag(int locate, unsigned char flag);

int OK_get_p12_cb_cry_algo();
int OK_get_p12_kb_cry_algo();
int OK_get_p7s_digest_algo();
int OK_get_p7env_cry_algo();
int OK_get_p7env_passwd_len();
int OK_get_p5_cry_algo();
int OK_get_pem_cry_algo();
int OK_get_sign_digest_algo();
int OK_get_cert_sig_algo();
int OK_get_crl_sig_algo();
unsigned char OK_get_ext_flag(int locate);

/* aicrypto extention flags */
#define AC_EXTF_LC_LNM		0
#define AC_EXTF_LC_ASN1		1
#define AC_EXTF_LC_X509		2
#define AC_EXTF_LC_KEY		3

#define AC_EXTF_ST_MOJCO	0x1

#ifdef  __cplusplus
}
#endif

#endif /* __OK_TOOL_H__ */
