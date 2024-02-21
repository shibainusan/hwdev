/* ok_ecc.h */
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

#ifndef __OK_ECC_H__
#define __OK_ECC_H__

#include "aiconfig.h"
#include "ok_err.h"
#include "large_num.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct EC_Point{
	LNm	*x;
	LNm	*y;
	LNm *z;
	int	infinity;
}ECp;

/* temporary buffer's number for culculation used in ECParam */
#define E_LNm_BUF 12
#define ECP_BUF	  12

typedef struct Elliptic_Curve_Param{
	int	version;
	int curve_type;

	/* Curve */
	LNm *a;
	LNm *b;		/* y^2 = x^3 + a*x + b mod p */
	/* ... seed */

	/* FieldID */
	int	type;
	/* prime-field { */
	LNm *p;		/* field modulo p */
	int	psize;	/* bit length of p */
	/* } */
	/* characteristic-two-field */
	/* ...int m */
	/* ...parameters */

	/* order */
	LNm *n;		/* the order of G on E */
	int	nsize;	/* bit length of n */

	/* cofactor */
	LNm *h;		/* h = #E / n (so, #E is nearly prime) */

	ECp *G;		/* base Point */

/* temporary buffers for culculation */
	LNm *buf[E_LNm_BUF];
	ECp *pbf[ECP_BUF];

	/* DER */
	unsigned char *der;
}ECParam;

/* Elliptic curve parameter type */
#define ECP_ORG_char2Param	100
#define ECP_ORG_primeParam	101
#define ECP_ORG_prime160	120
#define ECP_ORG_prime192	121
#define ECP_ORG_prime256	123
#define ECP_ORG_prime320	125

#define ECP_X962_c2pnb163v1	8060
#define ECP_X962_c2pnb163v2	8061
#define ECP_X962_c2pnb163v3	8062

#define ECP_X962_prime192v1	8090
#define ECP_X962_prime192v2	8091
#define ECP_X962_prime192v3	8092
#define ECP_X962_prime239v1	8093
#define ECP_X962_prime239v2	8094
#define ECP_X962_prime239v3	8095
#define ECP_X962_prime256v1	8096

/* ecc.c */
ECp *ECp_new();
ECp *ECp_dup(ECp *ecp);
void ECp_free(ECp *ecp);
ECParam *ECPm_new();
ECParam *ECPm_dup(ECParam *E);
void ECPm_free(ECParam *E);

/* ecc_std.c */
/* get standard elliptic curve parameters */
ECParam *ECPm_get_std_parameter(int type);
int ECPm_set_std_parameter(ECParam *E,int type);

/* ecc_asn1.c */
unsigned char *ECPm_toDER(ECParam *ecp,unsigned char *buf,int *ret_len);
int ECPm_DER_ecfieldID(ECParam *ecp,unsigned char *ret,int *ret_len);
int ECPm_DER_eccurve(ECParam *ecp,unsigned char *ret,int *ret_len);
int ECPm_DER_ecpoint(ECp *ecp,unsigned char *ret,int *ret_len);
int ECPm_estimate_der_size(ECParam *ecp);


/* ecp_addsub.c */
/* A + B = ret */
int ECp_add(ECParam *E, ECp *A, ECp *B, ECp *ret);
/* A - B = ret */
int ECp_sub(ECParam *E, ECp *A, ECp *B, ECp *ret);


/* ecp_multi.c */
/* k * A = ret */
/* binary with window method (default) */
int ECp_multi(ECParam *E, ECp *A, LNm *k, ECp *ret);
/* binary (a little bit slower) */
int ECp_multi_bin(ECParam *E, ECp *A, LNm *k, ECp *ret);


/* ecp_paddsub.c */
/* Projective Elliptic Doubling -- see IEEE P1363, Annex A, pp129 */
/* 2 * A = ret */
int ECp_pdouble(ECParam *E, ECp *A, ECp *ret);
/* A + B = ret */
int ECp_padd(ECParam *E, ECp *A, ECp *B, ECp *ret);
int ECp_padd_diffs(ECParam *E, ECp *A, ECp *B, ECp *ret);
/* A - B = ret */
int ECp_psub(ECParam *E, ECp *A, ECp *B, ECp *ret);

/* ecp_pmulti.c */
/* Projective Elliptic multi */
/* binary with NAF window method (default) */
int ECp_pmulti(ECParam *E, ECp *A, LNm *k, ECp *ret);
/* calculate A * 2^k */
int ECp_ppow2(ECParam *E, ECp *A, int k, ECp *ret);


/* ecp_conv.c */
int ECp_x2y(ECParam *E, LNm *x, LNm *y, int odd_y);
ECp *ECp_OS2P(ECParam *E,unsigned char *os,int len);
unsigned char *ECp_P2OS(ECp *p,int type,int *ret_len);


/* ecp_tool.c */
void ECp_copy(ECp *from, ECp *to);
/* return 0, if no differ */
int ECp_cmp(ECp *a, ECp *b);
/* point conversion */
int ECp_proj2af(ECParam *E, ECp *a);
/* print EC point */
void ECp_print(ECp *a);

/* ecp_gen.c */
ECParam *ECPm_gen_parameter(int size /* bits */);

/* ecp_vfy.c */
/* output 0    ...no error
 *        else ...error code.
 */
int ECPm_verify_parameter(ECParam *E);


#ifdef  __cplusplus
}
#endif

#endif /* __OK_ECC_H__ */
