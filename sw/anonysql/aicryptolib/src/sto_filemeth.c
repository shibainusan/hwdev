/* sto_meth.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_err.h"
#include "ok_asn1.h"
#include "ok_store.h"

int seek_and_read(FILE *fp,unsigned char *buf,int len, fpos_t *pos);
int asn1_check_tag(unsigned char uc);

/*-----------------------------------------
  alloc & FREE device info
-----------------------------------------*/
CSDevStrage* CSDevStrage_new(char *path){
	CSDevStrage *ret=NULL;

	if((ret=(CSDevStrage*)MALLOC(sizeof(CSDevStrage)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STOREDEV,ERR_PT_STFILEMETH,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(CSDevStrage));

	if(path){
		if((STRDUP(ret->path,path))==NULL){
			OK_set_error(ERR_ST_STRDUP,ERR_LC_STOREDEV,ERR_PT_STFILEMETH,NULL);
			goto error;
		}
	}
	return ret;
error:
	CSDevStrage_free(ret);
	return NULL;
}

void CSDevStrage_free(CSDevStrage *dev){
	if(dev==NULL) return;
	if(dev->path) FREE(dev->path);
	FREE(dev);
}

/*-----------------------------------------
  static method : get_data 
-----------------------------------------*/
unsigned char *get_der_on_strage(CSBag *bag){
	unsigned char *der=NULL;
	FILE *fp;
	fpos_t pos;

	/* get from strage */
	if(bag->der){
		if((der=ASN1_dup(bag->der))==NULL) goto error;
	}else{
		if(bag->dev_info==NULL) goto error;
		fp = ((CSDevStrage*)bag->dev_info)->fp;
		pos= ((CSDevStrage*)bag->dev_info)->pos;
		if((der=get_der_from_fposition(fp,pos))==NULL) goto error;
	}
	return der;
error:
	return NULL;
}

Cert *CS_bag2cert_on_strage(CSBag *bag){
	unsigned char *der=NULL;
	Cert *ret;

	/* check on cache or not */
	if(bag->cache) return Cert_dup((Cert*)bag->cache);
	
	if((der=get_der_on_strage(bag))==NULL) goto error;
	if((ret=ASN1_read_cert(der))==NULL) goto error;
	return ret;
error:
	if(der) FREE(der);
	return NULL;
}

CRL *CS_bag2crl_on_strage(CSBag *bag){
	unsigned char *der=NULL;
	CRL *ret;

	/* check on cache or not */
	if(bag->cache) return CRL_dup((CRL*)bag->cache);
	
	if((der=get_der_on_strage(bag))==NULL) goto error;
	if((ret=ASN1_read_crl(der))==NULL) goto error;
	return ret;
error:
	if(der) FREE(der);
	return NULL;
}

Req *CS_bag2req_on_strage(CSBag *bag){
	unsigned char *der=NULL;
	Req *ret;

	/* check on cache or not */
	if(bag->cache) return Cert_dup((Req*)bag->cache);
	
	if((der=get_der_on_strage(bag))==NULL) goto error;
	if((ret=ASN1_read_req(der))==NULL) goto error;
	return ret;
error:
	if(der) FREE(der);
	return NULL;
}

Key *CS_bag2key_on_strage(CSBag *bag){
	unsigned char *der=NULL,*dec=NULL;
	Key *ret;
	int i;

	/* check on cache or not */
	if(bag->cache) return Key_dup((Key*)bag->cache);
	
	if((der=get_der_on_strage(bag))==NULL) goto error;
	if((dec=ASN1_p8_decrypted(der,&i))==NULL) goto error;
	if((ret=ASN1_p8_prvkey(dec))==NULL) goto error;
	FREE(der); FREE(dec);
	return ret;
error:
	if(dec) FREE(dec);
	if(der) FREE(der);
	return NULL;
}

/* always non cache */
unsigned char *CS_bag2der_on_strage(CSBag *bag){
	return get_der_on_strage(bag);
}

/* always non cache */
unsigned char *CS_bag2encder_on_strage(CSBag *bag){
	unsigned char *der=NULL,*dec=NULL;
	int i;

	if((der=get_der_on_strage(bag))==NULL) goto done;
	dec = ASN1_p8_decrypted(der,&i);
	FREE(der);
done:
	return dec;
}

/* get DER binary data */
unsigned char *get_der_from_fposition(FILE *fp, fpos_t pos){
	unsigned char tmp[32],*ret=NULL;
	fpos_t tpos;
	int i,j,len,ptm,dep;

	fsetpos(fp,&pos);
	fgetpos(fp,&tpos);
	if((i=fread(tmp,sizeof(char),32,fp))<=1){
		OK_set_error(ERR_ST_FILEREAD,ERR_LC_STOREDEV,ERR_PT_STFILEMETH+2,NULL);
		goto error;
	}

	i=ASN1_length(&tmp[1],&j);		
	j+=i+1;

	// *tmp is indifinit length !!
	if(tmp[1]==0x80){
		if(seek_and_read(fp,tmp,j,&tpos)) goto error;
		i=dep=0;
		while(*tmp||dep){
			if(*tmp==0){
				/* END [00 00] tag */
				if(seek_and_read(fp,tmp,2,&tpos)) goto error;
				dep--; i+=2;
			}else{
				/* other tags */
				if(asn1_check_tag(*tmp)) goto error;
				len = ASN1_length(&tmp[1],&ptm);
				len+= ptm+1;

				if(tmp[1]==0x80) dep++;
				if(seek_and_read(fp,tmp,len,&tpos)) goto error;
				i += len;
			}
		}
		j += i+2;
    }

	if((ret=(unsigned char*)MALLOC(j+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_STOREDEV,ERR_PT_STFILEMETH+2,NULL);
		goto error;
	}
	memset(ret,0,j+2);

	fsetpos(fp,&pos);
	if((i=fread(ret,sizeof(char),j,fp))<=1){
		OK_set_error(ERR_ST_FILEREAD,ERR_LC_STOREDEV,ERR_PT_STFILEMETH+2,NULL);
		goto error;
	}

	return ret;
error:
	if(ret) FREE(ret);
	return NULL;
}

/* buf should be more than 64 byte */
int seek_and_read(FILE *fp,unsigned char *buf,int len, fpos_t *pos){
	fsetpos(fp,pos);
	if(fseek(fp,len,SEEK_CUR)){
		OK_set_error(ERR_ST_FILEREAD,ERR_LC_STOREDEV,ERR_PT_STFILEMETH+3,NULL);
		goto error;
	}
	fgetpos(fp,pos);
	if(fread(buf,sizeof(char),32,fp)<=1){
		OK_set_error(ERR_ST_FILEREAD,ERR_LC_STOREDEV,ERR_PT_STFILEMETH+3,NULL);
		goto error;
	}
	return 0;
error:
	return -1;
}
