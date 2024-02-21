/* ok_uconv.h */
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

#ifndef __OK_UCONV_H__
#define __OK_UCONV_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "aiconfig.h"
#include "ok_err.h"


#define UC_M_JIS_ASCII		100
#define UC_M_JIS_JISX208	101
#define UC_M_JIS_KATAKANA	102

#define UC_CODE_JIS			1
#define UC_CODE_SJIS		2
#define UC_CODE_EUC			3
#define UC_CODE_UNICODE		4
#define UC_CODE_UTF8		5

#define UC_ESC	0x1b
#define UC_SO	0x0e
#define UC_SI	0x0f


/* unicode11.h */
#ifndef UC_JIS2UNI_MAX
# define UC_JIS2UNI_MAX	7976
#endif

extern unsigned short jis2uni[UC_JIS2UNI_MAX];

/* uconv.c */
int UC_conv(int inform, int outform, char *in, int ilen, char *out, int max);

/* uc_jis.c */
int UC_jis2any(char *in, int ilen, char *out, int max,int (*transf)());
int jis2sjis_in(char *in,char *out,int max,int mode,int *i,int *ret);
int jis2euc_in(char *in,char *out,int max,int mode,int *i,int *ret);
int jis2uni_in(char *in,char *out,int max,int mode,int *i,int *ret);
int jis2utf_in(char *in,char *out,int max,int mode,int *i,int *ret);

int jis2sjis_c(char *in,unsigned char *out);
int jis2uni_c(char *in,unsigned char *out);

#define UC_jis2sjis(in,ilen,out,max)	UC_jis2any((in),(ilen),(out),(max),jis2sjis_in)
#define UC_jis2euc(in,ilen,out,max) 	UC_jis2any((in),(ilen),(out),(max),jis2euc_in)
#define UC_jis2uni(in,ilen,out,max) 	UC_jis2any((in),(ilen),(out),(max),jis2uni_in)
#define UC_jis2utf(in,ilen,out,max) 	UC_jis2any((in),(ilen),(out),(max),jis2utf_in)

/* uc_sjis.c */
int UC_sjeu2any(char *in, int ilen, char *out, int max, int (*transf)());
int sjis2jis_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int sjis2euc_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int sjis2uni_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int sjis2utf_in(char *in,char *out,int max,int *mode,int *i,int *ret);

int sjis2jis_c(char *in,unsigned char *out);

#define UC_sjis2jis(in,ilen,out,max)	UC_sjeu2any((in),(ilen),(out),(max),sjis2jis_in)
#define UC_sjis2euc(in,ilen,out,max) 	UC_sjeu2any((in),(ilen),(out),(max),sjis2euc_in)
#define UC_sjis2uni(in,ilen,out,max) 	UC_sjeu2any((in),(ilen),(out),(max),sjis2uni_in)
#define UC_sjis2utf(in,ilen,out,max) 	UC_sjeu2any((in),(ilen),(out),(max),sjis2utf_in)

/* uc_euc.c */
int euc2jis_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int euc2sjis_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int euc2uni_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int euc2utf_in(char *in,char *out,int max,int *mode,int *i,int *ret);

#define UC_euc2jis(in,ilen,out,max) 	UC_sjeu2any((in),(ilen),(out),(max),euc2jis_in)
#define UC_euc2sjis(in,ilen,out,max)	UC_sjeu2any((in),(ilen),(out),(max),euc2sjis_in)
#define UC_euc2uni(in,ilen,out,max) 	UC_sjeu2any((in),(ilen),(out),(max),euc2uni_in)
#define UC_euc2utf(in,ilen,out,max) 	UC_sjeu2any((in),(ilen),(out),(max),euc2utf_in)

/* uc_uni.c */
int UC_uni2any(char *in, int ilen, char *out, int max, int (*transf)());
int uni2jis_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int uni2sjis_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int uni2euc_in(char *in,char *out,int max,int *mode,int *i,int *ret);
int uni2utf_in(char *in,char *out,int max,int *mode,int *i,int *ret);

int uni2jis_c(unsigned short in,unsigned char *out);
int init_u2j_table();
void free_u2j_table();

#define UC_uni2jis(in,ilen,out,max) 	UC_uni2any((in),(ilen),(out),(max),uni2jis_in)
#define UC_uni2sjis(in,ilen,out,max) 	UC_uni2any((in),(ilen),(out),(max),uni2sjis_in)
#define UC_uni2euc(in,ilen,out,max) 	UC_uni2any((in),(ilen),(out),(max),uni2euc_in)
#define UC_uni2utf(in,ilen,out,max) 	UC_uni2any((in),(ilen),(out),(max),uni2utf_in)

/* uc_utf8.c */
int UC_utf2any(char *in, int ilen, char *out, int max, int (*transf)());
int utf2uni_in(char *in,char *out,int max,int *mode,int *i,int *ret);

int ucs22utf_c(unsigned char *in, unsigned char *out);
int utf2ucs2_c(unsigned char *in, unsigned char *out);

#define UC_utf2jis(in,ilen,out,max) 	UC_utf2any((in),(ilen),(out),(max),uni2jis_in)
#define UC_utf2sjis(in,ilen,out,max) 	UC_utf2any((in),(ilen),(out),(max),uni2sjis_in)
#define UC_utf2euc(in,ilen,out,max) 	UC_utf2any((in),(ilen),(out),(max),uni2euc_in)
#define UC_utf2uni(in,ilen,out,max) 	UC_utf2any((in),(ilen),(out),(max),utf2uni_in)


#ifdef  __cplusplus
}
#endif

#endif /* __OK_UCONV_H__ */
