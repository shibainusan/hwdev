/* p12_key.c */
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

#include "ok_asn1.h"
#include "ok_md5.h"
#include "ok_sha1.h"
#include "ok_rc2.h"
#include "ok_des.h"
#include "ok_rsa.h"
#include "ok_x509.h"
#include "ok_pkcs.h"

/*-----------------------------------------
  PKCS12 Key General.
-----------------------------------------*/
unsigned char *P12_gen_key(Dec_Info *dif,int id){
	unsigned char	*I,*cp,*DI,*ret,*A,*B;
	int ilen,smax,pmax,dilen,err=-1,em;
	int i,j,u,v,c,klen,slen,plen,iter;
	LNm *Ij,*Bl,*tmp;

	klen=dif->klen; slen=dif->slen; plen=dif->plen;
	iter=dif->iter;

	u = 160/8;	/* now SHA.1 only */
	v = 512/8;

	c = (klen-1)/u +1;
	smax = v*((slen+v-1)/v);
	pmax = v*((plen+v-1)/v);
	ilen = smax+pmax;
	dilen = v+ilen;

	ret=DI=A=B=I=NULL;
	Ij=Bl=tmp=NULL;

	em = -1;
	if((ret=(unsigned char*)MALLOC(klen))==NULL) goto done;
	if((DI=(unsigned char*)MALLOC(dilen))==NULL) goto done;
	if((A=(unsigned char*)MALLOC(u*c))==NULL) goto done;
	if((B=(unsigned char*)MALLOC(v))==NULL) goto done;
	if((I=(unsigned char*)MALLOC(ilen))==NULL) goto done;
	em = 0;

	if((Ij = LN_alloc())==NULL) goto done;
	if((Bl = LN_alloc())==NULL) goto done;
	if((tmp= LN_alloc())==NULL) goto done;

	for(cp=I,i=0;i<smax;i++) *cp++ = dif->salt[i % slen];
	for(i=0;i<pmax;i++) *cp++ = dif->pass[i % plen];

	memset(DI,id,v);

	for(i=0;i<c;i++){
		cp=&A[i*u];
		memcpy(&DI[v],I,ilen);
		OK_SHA1(dilen,DI,cp);

		for(j=1;j<iter;j++) OK_SHA1(u,cp,cp);

		klen-=u;
		if(klen>0){
			for(j=0;j<v;j++) B[j]=cp[j%u];

			err = LN_set_num_c(Bl,v,B);
			err|= LN_long_add(Bl,1);
			if(err) goto done;

			for(j=0;j<ilen;j+=v){
				err = LN_set_num_c(Ij,v,&I[j]);
				err|= LN_plus(Ij,Bl,tmp);
				/* get Ij->num 64 byte */
				err|= LN_get_num_c(tmp,64,&I[j]);
				if(err) goto done;
			}
		}
	}

	memcpy(ret,A,dif->klen);
	err=0;
done:
	memset(A,0,dif->klen);
	FREE(DI); FREE(A); FREE(B); FREE(I);
	LN_free(Ij); LN_free(Bl); LN_free(tmp);
	if(err&&ret){FREE(ret);ret=NULL;}
	if(em) OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12KEY,NULL);
	return ret;
}

/*-----------------------------------------------
  PKCS#12 make RC2 key
-----------------------------------------------*/
Key_RC2 *P12_gen_RC2key(Dec_Info *dif){
	unsigned char *buf;
	Key_RC2 *ret;
	int err=-1;

	if((buf=P12_gen_key(dif,P12_ID_GENKEY))==NULL) return NULL;
	if((ret=RC2key_new(dif->klen,buf))==NULL) goto done;
	err=0;
done:
	memset(buf,0,dif->klen);
	FREE(buf);
	if(err&&ret){RC2key_free(ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------------
  PKCS#12 make triple DES key
-----------------------------------------------*/
Key_3DES *P12_gen_3DESkey(Dec_Info *dif){
	unsigned char *buf;
	Key_3DES *ret;
	int err=-1;

	if((buf=P12_gen_key(dif,P12_ID_GENKEY))==NULL) return NULL;
	if((ret=DES3key_new_c(dif->klen,buf))==NULL) goto done;
	err=0;
done:
	memset(buf,0,dif->klen);
	FREE(buf);
	if(err&&ret){DES3key_free(ret);ret=NULL;}
	return ret;
}




