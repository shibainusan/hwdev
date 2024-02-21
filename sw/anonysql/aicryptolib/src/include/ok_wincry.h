/* ok_wincry.h */
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

#ifndef __OK_WINCRY_H__
#define __OK_WINCRY_H__

#include "aiconfig.h"
/* windef.h has ULONG definition */
#undef ULONG

/* just dummy for including "wincrypt.h" */
#define _WIN32_WINNT 0x0500
#ifndef STRICT
# define STRICT
#endif

#include <windows.h>
#include <wincrypt.h>

#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* pvPara parameters */
#define WIN_STORE_MY	(char*)L"MY"
#define WIN_STORE_ROOT	(char*)L"root"
#define WIN_STORE_TRUST	(char*)L"trust"
#define WIN_STORE_CA	(char*)L"CA"
#define WIN_STORE_OTHERS	(char*)L"AddressBook"

#define WIN_STORE_ETOKEN	(char*)L"eToken Base Cryptographic Provider"

/* wincry_cert.c */
PCCERT_CONTEXT Cert_cert2pccert(Cert *ct);
Cert *Cert_pccert2cert(PCCERT_CONTEXT ccon);

int Cert_add_toStore(Cert *ct, char *pvPara);
int Cert_del_fromStore(Cert *ct, char *pvPara);
int Cert_add_toMyStore(Cert *ct,Key *prv,int enhanced,int export);

Key *Cert_get_keyFromContainer(Cert *ct);


/* wincry_crl.c */
PCCRL_CONTEXT CRL_crl2pccrl(CRL *crl);
CRL *CRL_pccrl2crl(PCCRL_CONTEXT ccon);

int CRL_add_toStore(CRL *ct, char *pvPara);
int CRL_del_fromStore(CRL *ct, char *pvPara);


/* wincry_key.c */
BYTE *RSAprv_prv2keyblob(Prvkey_RSA *prv, int *ret_len);
Prvkey_RSA *RSAprv_keyblob2prv(BYTE *prv);

int RSAprv_add_toContainer(Prvkey_RSA *prv,LPCTSTR con, LPCTSTR prov, int export);

Prvkey_RSA *RSAprv_get_fromContainer(LPCTSTR con, LPCTSTR prov);


/* wincry_clist.c */
CertList *Certlist_get_from_system(char *pvPara);


#ifdef  __cplusplus
}
#endif

#endif /* __OK_WINCRY_H__ */
