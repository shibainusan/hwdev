/* wincry_key.c */
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

#ifdef __WINDOWS__	/* these codes are required with WIN CRYPT API */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_err.h"
#include "ok_pem.h"
#include "ok_tool.h"
#include "ok_wincry.h"

/* change byte endian */
void _cbe(unsigned char *in,unsigned char *out,int len);

/*-----------------------------------------------
	Crypt32 API compatible functions
-----------------------------------------------*/
BYTE *RSAprv_prv2keyblob(Prvkey_RSA *prv, int *ret_len){
	unsigned char *ret,*tp,buf[LN_MAX*2];
	BLOBHEADER	*bh;
	RSAPUBKEY	*pub;
	int sz,sz2;

	if(prv==NULL){return NULL;}
	sz  = prv->size;
	sz2 = sz>>1;

	if((ret=(unsigned char*)MALLOC(sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+sz*5))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY,NULL);
		return NULL;
	}

	bh = (BLOBHEADER*)ret;
	bh->bType    = PRIVATEKEYBLOB;     /* 0x07 */
	bh->bVersion = CUR_BLOB_VERSION;   /* 0x02 */
	bh->reserved = 0;                  /* 0x0000 */
	bh->aiKeyAlg = CALG_RSA_KEYX|CALG_RSA_SIGN; //|CALG_TLS1_MASTER|CALG_TLS1_MASTER;

	pub = (RSAPUBKEY*)(ret+sizeof(BLOBHEADER));
	pub->magic     = 0x32415352;         /* "RSA2" */
	pub->bitlen    = sz*8;
	if(prv->e->top!=1){
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY,NULL);
		goto error;
	}
	pub->pubexp= prv->e->num[LN_MAX-1];

	tp = ret+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY);
	LN_get_num_c(prv->n,  sz, buf); _cbe(buf,tp,sz);  tp+=sz;
	LN_get_num_c(prv->p,  sz2,buf); _cbe(buf,tp,sz2); tp+=sz2;
	LN_get_num_c(prv->q,  sz2,buf); _cbe(buf,tp,sz2); tp+=sz2;
	LN_get_num_c(prv->e1, sz2,buf); _cbe(buf,tp,sz2); tp+=sz2;
	LN_get_num_c(prv->e2, sz2,buf); _cbe(buf,tp,sz2); tp+=sz2;
	LN_get_num_c(prv->cof,sz2,buf); _cbe(buf,tp,sz2); tp+=sz2;
	LN_get_num_c(prv->d,  sz, buf); _cbe(buf,tp,sz);

	*ret_len = sizeof(BLOBHEADER)+sizeof(RSAPUBKEY) + (sz2*9);
	return (BYTE*)ret;
error:
	FREE(ret);
	return NULL;
}

Prvkey_RSA *RSAprv_keyblob2prv(BYTE *prv){
	Prvkey_RSA *ret=NULL;
	BLOBHEADER	*bh;
	RSAPUBKEY	*pub;
	unsigned char *tp,buf[LN_MAX*2];
	int sz,sz2;

	if(prv==NULL){return NULL;}

	bh = (BLOBHEADER*)prv;
	if((bh->bType!=PRIVATEKEYBLOB)||(bh->bVersion!=2)||(bh->aiKeyAlg!=CALG_RSA_KEYX)){
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+1,NULL);
		goto error;
	}

	pub = (RSAPUBKEY*)(prv+sizeof(BLOBHEADER));
	if(pub->magic!=0x32415352){
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+1,NULL);
		goto error;
	}

	if((ret=RSAprvkey_new())==NULL) goto error;
	ret->size	= sz = pub->bitlen >> 3;
	sz2 = sz >> 1;

	LN_long_set(ret->e, pub->pubexp);

	tp = prv+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY);
	_cbe(tp,buf,sz);  LN_set_num_c(ret->n,  sz, buf); tp+=sz;
	_cbe(tp,buf,sz2); LN_set_num_c(ret->p,  sz2,buf); tp+=sz2;
	_cbe(tp,buf,sz2); LN_set_num_c(ret->q,  sz2,buf); tp+=sz2;
	_cbe(tp,buf,sz2); LN_set_num_c(ret->e1, sz2,buf); tp+=sz2;
	_cbe(tp,buf,sz2); LN_set_num_c(ret->e2, sz2,buf); tp+=sz2;
	_cbe(tp,buf,sz2); LN_set_num_c(ret->cof,sz2,buf); tp+=sz2;
	_cbe(tp,buf,sz);  LN_set_num_c(ret->d,  sz, buf);

	if((ret->der=RSAprv_toDER(ret,NULL,&sz))==NULL)
		goto error;

	return ret;
error:
	if(ret) Key_free((Key*)ret);
	return NULL;
}

/*-----------------------------------------------
	Add Private Key into the CSP.
-----------------------------------------------*/
int RSAprv_add_toContainer(Prvkey_RSA *prv, LPCTSTR con, LPCTSTR prov, int export){
	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	BYTE *blob=NULL;
	int i,err=-1;

	if(prv==NULL){return -1;}

	if(!CryptAcquireContext(&hProv, con, prov, PROV_RSA_FULL, 0)){
		if(GetLastError() == NTE_BAD_KEYSET){
			if(!CryptAcquireContext(&hProv, con, prov, PROV_RSA_FULL, CRYPT_NEWKEYSET)){
				OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+2,(int*)GetLastError());
				goto done;
			}
		}else{
			OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+2,(int*)GetLastError());
			goto done;
		}
	}

	if((blob=RSAprv_prv2keyblob(prv,&i))==NULL) goto done;

	/* Import the key blob into the CSP. */
	if(!CryptImportKey(hProv,blob,i,0,(export)?(CRYPT_EXPORTABLE):(0),&hKey)) {
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+2,(int*)GetLastError());
		goto done;
	}
	err=0;

done:
	if(blob) FREE(blob);
	if(hKey) CryptDestroyKey(hKey);
	if(hProv) CryptReleaseContext(hProv,0);
	return err;
}

/*-----------------------------------------------
	Get Private Key from the CSP.
-----------------------------------------------*/
Prvkey_RSA *RSAprv_get_fromContainer(LPCTSTR con, LPCTSTR prov){
	HCRYPTPROV hProv = 0;
	HCRYPTKEY  hKey = 0;
	BYTE *blob = NULL;
	Prvkey_RSA *prv = NULL;
	int i;

	if(!CryptAcquireContext(&hProv, con, prov, PROV_RSA_FULL, 0)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+3,(int*)GetLastError());
		goto done;
	}
	/* need to Export private key !! */
	if(!CryptGetUserKey(hProv,AT_KEYEXCHANGE,&hKey)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+3,(int*)GetLastError());
		goto done;
	}
	if(!CryptExportKey(hKey,0,PRIVATEKEYBLOB,0,NULL,&i)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+3,(int*)GetLastError());
		goto done;
	}
	if((blob=(BYTE*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+3,NULL);
		goto done;
	}

	if(!CryptExportKey(hKey,0,PRIVATEKEYBLOB,0,blob,&i)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+3,(int*)GetLastError());
		goto done;
	}

	//{FILE *fp;fp=fopen("kblob.bin","w");fwrite(blob,1,i,fp);fclose(fp);}

	/* convert Private key blob to Prvkey_RSA */
	prv = RSAprv_keyblob2prv(blob);

done:
	if(blob) FREE(blob);
	if(hKey) CryptDestroyKey(hKey);
	if(hProv) CryptReleaseContext(hProv,0);
	return prv;
}

/* change byte endian */
/* little endian <--> big endian */
void _cbe(unsigned char *in,unsigned char *out,int len){
	int i;
	for(i=0;i<len;i++)
		out[len-1-i]=in[i];
}


/*-------------------------------------------------------*/
#if 0
int wincry_key(){
	HCRYPTPROV hProv = 0;
	BYTE pbData[1000];
	DWORD cbData;
	int	i;

	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)){
		OK_set_error(ERR_ST_WINAPI,ERR_LC_WINCRY,ERR_PT_WINCRY_KEY+4,(int*)GetLastError());
		return -1;}

	/* Read the name of the default CSP. */
	cbData = 1000;
	if(!CryptGetProvParam(hProv, PP_NAME, pbData, &cbData, 0)) {
		printf("Error %x reading CSP name!\n", GetLastError());
		return -1;
	}
	printf("Provider name: %s\n", pbData);

	/* Read the name of the default key container. */
	cbData = 1000;
	if(!CryptGetProvParam(hProv, PP_CONTAINER, pbData, &cbData, 0)) {
		printf("Error %x reading key container name!\n", GetLastError());
		return -1;
	}
	printf("Key Container name: %s\n", pbData);

	if(!CryptReleaseContext(hProv, 0)) {
		printf("Error %x during CryptReleaseContext!\n", GetLastError());
		return -1;
	}
	return 0;
}
#endif

#endif /* __WINDOWS__ */
