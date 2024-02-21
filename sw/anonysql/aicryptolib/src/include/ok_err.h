/* ok_err.h */
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

#ifndef __OK_ERR_H__
#define __OK_ERR_H__

#include "aiconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*-----------------------------------------------
 * Define error location
 *---------------------------------------------*/
#define	ERR_LC_NON		0x0
#define	ERR_LC_LNM		0x1
#define	ERR_LC_ECC		0x2
#define	ERR_LC_RAND		0x3

#define	ERR_LC_DES		0x10
#define	ERR_LC_RC2		0x11
#define	ERR_LC_RC4		0x12

#define	ERR_LC_MD2		0x30
#define	ERR_LC_MD5		0x31
#define	ERR_LC_SHA1		0x32
#define	ERR_LC_HMAC		0x33

#define	ERR_LC_RSA		0x40
#define	ERR_LC_DSA		0x41
#define	ERR_LC_ECDSA	0x42
#define	ERR_LC_DH		0x43
	
#define	ERR_LC_ASN1		0x50
#define	ERR_LC_X509		0x51
#define	ERR_LC_X509CERT	0x52
#define	ERR_LC_X509CRL	0x53
#define	ERR_LC_X509KEY	0x54
#define	ERR_LC_X509EXT	0x55
#define	ERR_LC_X509REQ	0x56
#define	ERR_LC_ASN1_	0x57

#define	ERR_LC_PKCS		0x5a
#define	ERR_LC_PKCS7	0x5b
#define	ERR_LC_PKCS12	0x5c

#define	ERR_LC_PEM		0x60
#define	ERR_LC_SMIME	0x61
#define	ERR_LC_SSL		0x62
#define	ERR_LC_SSLHS	0x63
#define	ERR_LC_SSLREC	0x64
#define	ERR_LC_SSLALERT	0x65

#define	ERR_LC_TOOL		0x70
#define	ERR_LC_WINCRY	0x71
#define	ERR_LC_UCONV	0x72
#define	ERR_LC_STORE	0x73
#define	ERR_LC_STOREDEV	0x74

#define	ERR_LC_CMP		0x90
#define ERR_LC_ASN1CMP	0x91

/*-----------------------------------------------
 * define error point
 *---------------------------------------------*/
/* --- */
#define ERR_PT_NON		0x0
/* des */
#define ERR_PT_DES		0x10
#define ERR_PT_3DES		0x20
#define ERR_PT_DESKEY	0x30
#define ERR_PT_DESMODE	0x40
/* rc2 */
#define ERR_PT_RC2		0x10
#define ERR_PT_RC2KEY	0x20
#define ERR_PT_RC2MODE	0x30
/* rc4 */
#define ERR_PT_RC4		0x10
#define ERR_PT_RC4KEY	0x20
/* lnm */
#define ERR_PT_LNMADD	0x10
#define ERR_PT_LNMSUB	0x20
#define ERR_PT_LNMMUL	0x30
#define ERR_PT_LNMDIV	0x40
#define ERR_PT_LNMSQR	0x50
#define ERR_PT_LNMSHF	0x60
#define ERR_PT_LNMSET	0x70
#define ERR_PT_LNMLONG	0x80
#define ERR_PT_LNMSYS	0x90
#define ERR_PT_LNMRAND	0xa0
#define ERR_PT_LNMPRIME	0xb0
#define ERR_PT_LNMSQRT	0xc0
/* ecc */
#define ERR_PT_ECC		0x10
#define ERR_PT_ECCADD	0x20
#define ERR_PT_ECCMUL	0x30
#define ERR_PT_ECCPADD	0x40
#define ERR_PT_ECCPMUL	0x50
#define ERR_PT_ECCTOOL	0x60
#define ERR_PT_ECCCONV	0x70
#define ERR_PT_ECCSTD	0x80
#define ERR_PT_ECCGEN	0x90
#define ERR_PT_ECCVFY	0xa0
#define ERR_PT_ECCASN1	0xb0
/* rand */
#define	ERR_PT_RAND		0x10
#define	ERR_PT_LUTZRAND	0x20
#define	ERR_PT_LUTZSEED	0x30
/* ecdsa */
#define ERR_PT_ECDSA	0x10
#define ERR_PT_ECDSAKEY	0x20
#define ERR_PT_ECDSAASN	0x30
/* rsa */
#define ERR_PT_RSA		0x10
#define ERR_PT_RSAKEY	0x20
#define ERR_PT_RSAASN	0x30
/* dsa */
#define ERR_PT_DSA		0x10
#define ERR_PT_DSAKEY	0x20
#define ERR_PT_DSAGEN	0x30
#define ERR_PT_DSAASN	0x40
#define ERR_PT_DSASIG	0x50
/* dh */
#define ERR_PT_DH		0x10
#define ERR_PT_DHKEY	0x20
#define ERR_PT_DHASN	0x30

/* asn1 */
#define ERR_PT_ASN1		0x10
#define ERR_PT_ASN1CERT	0x20
#define ERR_PT_ASN1CRL	0x30
#define ERR_PT_ASN1FILE	0x40
#define ERR_PT_ASN1OBJ	0x50
#define ERR_PT_ASN1P7E	0x60
#define ERR_PT_ASN1P7S	0x70
#define ERR_PT_ASN1REQ	0x80
#define ERR_PT_ASN1RSA	0x90
#define ERR_PT_ASN1SET	0xa0
#define ERR_PT_ASN1PRT	0xb0
#define ERR_PT_ASN1P12	0xc0
#define ERR_PT_ASN1EXT	0xd0
#define ERR_PT_ASN1ECC	0xe0
#define ERR_PT_ASN1DSA	0xf0
/* asn1_ */
#define ERR_PT_ASN1DH	0x10
#define ERR_PT_ASN1EXTDEF	0x20
#define ERR_PT_ASN1EXTMOJ	0x30
#define ERR_PT_ASN1CRTP		0x40
#define ERR_PT_ASN1ECDSA	0x50

/* x509 */
#define ERR_PT_X509FILE		0x10
#define ERR_PT_X509TIME		0x20
/* x509-cert */
#define ERR_PT_CERT		0x10
#define ERR_PT_CERTASN1	0x20
#define ERR_PT_CERTEXT	0x30
#define ERR_PT_CERTEXTNS	0x40
#define ERR_PT_CERTEXTSTR	0x50
#define ERR_PT_CERTPRINT	0x60
#define ERR_PT_CERTTOOL	0x70
#define ERR_PT_CERTVFY	0x80

#define ERR_PT_CLIST	0x90
#define ERR_PT_CLFILE	0xa0
#define ERR_PT_CLTOOL	0xb0

#define ERR_PT_CRTP		0xc0
#define ERR_PT_CRTPASN1	0xd0

/* x509-crl */
#define ERR_PT_CRL		0x10
#define ERR_PT_CRLASN1	0x20
#define ERR_PT_CRLEXT	0x30
#define ERR_PT_CRLEXTSTR	0x40
#define ERR_PT_CRLPRINT		0x50
#define ERR_PT_CRLVFY		0x60
/* x509-key */
#define ERR_PT_KEY		0x10
#define ERR_PT_KEYTOOL	0x20
/* x509-ext */
#define ERR_PT_EXTGN	0x10
#define ERR_PT_EXTPOL	0x20
#define ERR_PT_EXTCERT	0x30
#define ERR_PT_EXTCRL	0x40
#define ERR_PT_EXTMS	0x50
#define ERR_PT_EXTMOJ	0x60
/* x509-req */
#define ERR_PT_REQASN1	0x10
#define ERR_PT_REQVFY	0x20

/* pkcs */
#define ERR_PT_PKCS12	0x10
#define ERR_PT_P12ASN1	0x20
#define ERR_PT_P12FILE	0x30
#define ERR_PT_P12KEY	0x40
#define ERR_PT_P12MAC	0x50
#define ERR_PT_P12TOOL	0x60

#define ERR_PT_PKCS7	0x10
#define ERR_PT_P7DATA	0x20
#define ERR_PT_P7ENC	0x30
#define ERR_PT_P7ENV	0x40
#define ERR_PT_P7FILE	0x50
#define ERR_PT_P7SIGN	0x60
#define ERR_PT_P7MASN1	0x70
#define ERR_PT_P7SASN1	0x80
#define ERR_PT_P7SATTR	0x90

#define ERR_PT_PKCS8	0x10
#define ERR_PT_P8FILE	0x20
#define ERR_PT_PBE		0x30
#define ERR_PT_PBECRY	0x40
#define ERR_PT_PBEKEY	0x50
#define ERR_PT_DECINFO	0x60

/* pem */
#define ERR_PT_BASE64	0x10
#define	ERR_PT_PEM		0x20
#define ERR_PT_PEMCRY	0x30
#define ERR_PT_PEMMSG	0x40
#define ERR_PT_PEMWRITE	0x50
#define ERR_PT_PEMPKCS	0x60
/* tool */
#define ERR_PT_DIGEST	0x10
#define ERR_PT_SIG		0x20
#define ERR_PT_PASS		0x30
/* wincry */
#define ERR_PT_WINCRY_CERT	0x10
#define ERR_PT_WINCRY_CLIST	0x20
#define ERR_PT_WINCRY_CRL	0x30
#define ERR_PT_WINCRY_KEY	0x40
/* uconv */
#define ERR_PT_UCONV	0x10
#define ERR_PT_UC_JIS	0x20
#define ERR_PT_UC_SJIS	0x30
#define ERR_PT_UC_EUC	0x40
#define ERR_PT_UC_UNI	0x50
#define ERR_PT_UC_UTF8	0x60
/* store */
#define ERR_PT_STORE	0x10
#define ERR_PT_STADD	0x20
#define ERR_PT_STDEL	0x30
#define ERR_PT_STSEARCH	0x40
#define ERR_PT_STTOOL	0x50
#define ERR_PT_MANAGER		0xf0
#define ERR_PT_MANADD		0xe0
#define ERR_PT_MANDEL		0xd0
#define ERR_PT_MANSEARCH	0xc0
#define ERR_PT_MANASN1		0xb0
#define ERR_PT_MANTOOL		0xa0

/* store device */
#define ERR_PT_STFILE	0x10
#define ERR_PT_STFILEMETH	0x20
/* smime */
#define ERR_PT_SMIME_DEC	0x10
#define ERR_PT_SMIME_ENC	0x20
#define ERR_PT_MIME_HEAD	0x30
/* ssl */
#define ERR_PT_SSL			0x10
#define ERR_PT_SSL_BIND		0x20
#define ERR_PT_SSL_CB		0x30
#define ERR_PT_SSL_CS		0x40
#define ERR_PT_SSL_HELLO	0x50
#define ERR_PT_SSL_LIST		0x60
#define ERR_PT_SSL_NAME		0x70
#define ERR_PT_SSL_RAND		0x80
#define ERR_PT_SSL_READ		0x90
#define ERR_PT_SSL_SOCK		0xa0
#define ERR_PT_SSL_TOOL		0xb0
#define ERR_PT_SSL_VFY		0xc0
#define ERR_PT_SSL_WRITE	0xd0

#define ERR_PT_SSLALERT		0x10

#define ERR_PT_SSLHS		0x10
#define ERR_PT_SSLHS_CLNT	0x20
#define ERR_PT_SSLHS_KEY	0x30
#define ERR_PT_SSLHS_SERV	0x40

#define ERR_PT_SSLREC		0x10
#define ERR_PT_SSLREC_PROC	0x20

/* cmp */
#define ERR_PT_PKIMSG		0x10
#define ERR_PT_PKIHEAD		0x20
#define ERR_PT_PKIBODY		0x30
#define ERR_PT_CMP			0x40
#define ERR_PT_PKIBD_ASN	0x50
#define ERR_PT_PKIHD_ASN	0x60
#define ERR_PT_PKIMG_ASN	0x70
#define ERR_PT_CMP_ASN		0x80
#define ERR_PT_PKIBD_ASNSZ	0x90
#define ERR_PT_CMP_ASNSZ	0xa0

/* asn_cmp */
#define ERR_PT_ASN_PKIBD	0x10
#define ERR_PT_ASN_PKIHD	0x20
#define ERR_PT_ASN_CMP		0x30

/*-----------------------------------------------
 * define error state
 *---------------------------------------------*/
/* general errors */
#define ERR_ST_NON				0x0
#define ERR_ST_MEMALLOC			0x1
#define ERR_ST_NULLPOINTER		0x2
#define ERR_ST_BADPARAM			0x3
#define ERR_ST_BADFORMAT		0x4
#define ERR_ST_BADVER			0x5
#define ERR_ST_BADPADDING		0x6
#define ERR_ST_UNMATCHEDPARAM	0x7
#define ERR_ST_STRDUP			0x8
#define ERR_ST_BADSTATE			0x9
#define ERR_ST_UNSUPPORTED_ALGO		0x10
#define ERR_ST_UNSUPPORTED_VER		0x11
#define ERR_ST_UNSUPPORTED_PARAM	0x12
#define ERR_ST_UNSUPPORTED_CODE		0x13
#define ERR_ST_BADNAME			0x14
#define ERR_ST_NULLKEY			0x20
#define ERR_ST_BADKEY			0x21
#define ERR_ST_FILEOPEN			0x30
#define ERR_ST_FILEREAD			0x31
#define ERR_ST_FILEWRITE		0x32

/* lnm */
#define ERR_ST_LNM_BUFOVERFLOW	0x80
#define ERR_ST_LNM_DIVBYZERO	0x81
#define ERR_ST_LNM_NOSQRT		0x82
/* asn1 */
#define ERR_ST_ASN_NOTINTEGER		0x101
#define ERR_ST_ASN_NOTENUMERATED	0x102
#define ERR_ST_ASN_NOTBITSTR		0x103
#define ERR_ST_ASN_NOTOCTETSTR		0x104
#define ERR_ST_ASN_NOTOID			0x105
#define ERR_ST_ASN_NOTPRINTABLESTR	0x106
#define ERR_ST_ASN_NOTUTF8STR		0x107
#define ERR_ST_ASN_NOTT61STR		0x108
#define ERR_ST_ASN_NOTIA5STR		0x109
#define ERR_ST_ASN_NOTBMPSTR		0x10a
#define ERR_ST_ASN_NOTUTCTIME		0x10b
#define ERR_ST_ASN_NOTGENTIME		0x10c
#define ERR_ST_ASN_NOTISO64STR		0x10d
#define ERR_ST_ASN_UNKNOWNOID		0x120
#define ERR_ST_ASN_BADOID			0x121
#define ERR_ST_ASN_NOTASN1			0x122
#define ERR_ST_ASN_NOTBOOLEAN		0x123
/* pkcs */
#define ERR_ST_P12_BADDEPTH		0x201
#define ERR_ST_P12_NOBAG		0x202
#define ERR_ST_P12_NOCERT		0x203
#define ERR_ST_P12_NOCRL		0x204
#define ERR_ST_P12_NOKEY		0x205
#define ERR_ST_P12_BADMAC		0x206
/* rand */
#define ERR_ST_RAND_NOPOOL		0x301
#define ERR_ST_RAND_NOTSEEDED	0x302
/* pem */
#define ERR_ST_PEM_BADHEADER	0x6e02
#define ERR_ST_PEM_BADFOOTER	0x6e03
#define ERR_ST_PEM_BADPASSWD	0x6e04
/* tool */
#define ERR_ST_P1_BADPADDING	0x6f00
/* wincry */
#define ERR_ST_WINAPI	0x7000
/* uconv */
#define ERR_ST_UC_BADJISCODE	0x7010
#define ERR_ST_UC_BADUTF8CODE	0x7011
#define ERR_ST_UC_UNKNOWNCODE	0x7012
/* store */
#define ERR_ST_STO_MANAGNOTFOUND	0x7300
#define ERR_ST_STO_STORENOTFOUND	0x7301
#define ERR_ST_STO_BAGNOTFOUND		0x7302
#define ERR_ST_STO_BADMANAG		0x7303
#define ERR_ST_STO_BADSTORE		0x7304
#define ERR_ST_STO_BADBAG		0x7305
#define ERR_ST_STO_BADID		0x7306

/* smime */
#define ERR_ST_MIME_BADHEADER	0x7101
#define ERR_ST_MIME_BADFOOTER	0x7102
/* ssl */
#define ERR_ST_SSL_CLOSE_NOTIFY			0x7201
#define ERR_ST_SSL_UNEXPECTED_MESSAGE	0x7202
#define ERR_ST_SSL_BAD_RECORD_MAC		0x7203
#define ERR_ST_SSL_DECOMPRESSION_FAILURE	0x7204
#define ERR_ST_SSL_HAND_SHAKE_FAILURE	0x7205
#define ERR_ST_SSL_NO_CERT			0x7206
#define ERR_ST_SSL_BAD_CERT			0x7207
#define ERR_ST_SSL_UNSUPPORTED_CERT	0x7208
#define ERR_ST_SSL_CERT_REVOKED		0x7209
#define ERR_ST_SSL_CERT_EXPIRED		0x720a
#define ERR_ST_SSL_CERT_UNKNOWN		0x720b
#define ERR_ST_SSL_ILLEGAL_PARAMETER	0x720c
#define ERR_ST_SSL_WRITE			0x720d
#define ERR_ST_SSL_READ				0x720e
#define ERR_ST_SSL_BADHEADER		0x720f
#define ERR_ST_SSL_BADSIGNATURE		0x7210
#define ERR_ST_SSL_BADFINISHED		0x7211

#define ERR_ST_ACCEPT			0x7221
#define ERR_ST_CONNECT			0x7222
#define ERR_ST_SOCKOPEN			0x7223
#define ERR_ST_SOCKWRITE		0x7224
#define ERR_ST_SOCKREAD			0x7225
#define ERR_ST_SOCKBIND			0x7226
#define ERR_ST_SOCKLISTEN		0x7227


/*
 * functions
 */

void OK_set_error(int error,int location,int point,int *info);
void OK_set_errorlocation(int location,int point);
void OK_clear_error();
ULONG OK_get_error();
int  *OK_get_errorinfo();
char *OK_get_errstr();

char *get_err_location(int err);
char *get_err_type(int err);

/* print error with "okerr" */
void OK_print_error();

#ifdef  __cplusplus
}
#endif

#endif /* __OK_ERR_H__ */
