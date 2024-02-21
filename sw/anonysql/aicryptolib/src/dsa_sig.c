/* dsa_sig.c */
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

#include "large_num.h"
#include "ok_dsa.h"
#include "ok_asn1.h"

/*-----------------------------------------------------
  get DSA signature and return Dss-Sig-Value (DER)
-----------------------------------------------------*/
unsigned char *DSA_get_signature(Prvkey_DSA *prv, unsigned char *data, int data_len, int *ret_len){
	unsigned char *ret=NULL,*cp;
	LNm *f=NULL,*c=NULL,*d=NULL;
	int	i,j,err=-1;

	if(data_len>prv->size){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_DSA,ERR_PT_DSASIG,NULL);
		goto done;
	}

	/* generate signature of DSA */
	if((c=LN_alloc())==NULL) goto done;
	if((d=LN_alloc())==NULL) goto done;
	if((f=LN_alloc_c(data_len,data))==NULL) goto done;

	if(DSA_sig_in(prv,f,c,d)) goto done;

	/* get DER binary form of DSA signature */
	i  = LN_now_byte(c);
	i += LN_now_byte(d);
	if((ret=(unsigned char*)MALLOC(i+12))==NULL){	/* length of c & d */
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSASIG,NULL);
		goto done;
	}

	/* integer r */
	if(ASN1_LNm2int(c,ret,&i)) goto done;
	cp = ret+i;

	/* integer s */
	if(ASN1_LNm2int(d,cp,&j)) goto done;

	ASN1_set_sequence(i+j,ret,ret_len);

	err=0;
done:
	LN_free(f);
	LN_free(d);
	LN_free(c);
	if(err&&ret){FREE(ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------------------
  generate DSA signature
  output : integers c and d.
-----------------------------------------------------*/
int DSA_sig_in(Prvkey_DSA *prv, LNm *f, LNm *c, LNm *d){
	LNm *u=NULL,*v=NULL,*tmp1=NULL,*tmp2=NULL;
	DSAParam *pm;
	int err=-1;

	if((u=LN_alloc())==NULL) goto done;
	if((v=LN_alloc())==NULL) goto done;
	if((tmp1=LN_alloc())==NULL) goto done;
	if((tmp2=LN_alloc())==NULL) goto done;
	pm = prv->pm;

	LN_init_lexp_tv();

	do{
		do{ /* create one time password */
		    err  = LN_set_rand(tmp2, 7 /* byte */, (unsigned short)(rand()*3));
			err  = LN_div_mod(tmp2,pm->q,tmp1,u);
			err |= LN_exp_mod(pm->g,u,pm->p,v);
			if(err) goto done;
		}while(v->top == 0);

		/* c = v mod q */
		if(err=LN_div_mod(v,pm->q,tmp1,c))	goto done;
		if(c->top==0)	continue;

		/* d = u^(-1)*(f+sc) mod q */
		err  = LN_mod_inverse(u,pm->q,tmp1);	/* u^(-1) */
		err |= LN_multi(prv->k,c,d);
		err |= LN_plus(d,f,tmp2);					/* f + sc */
		err |= LN_mul_mod(tmp1,tmp2,pm->q,d);
		if(err) goto done;
		if(d->top==0)	continue;
		break;
	}while(1);

	err=0;
done:
	LN_free(u); LN_free(v);
	LN_free(tmp1); LN_free(tmp2);
	return err;
}

/*-----------------------------------------------------
  verify DSA signature
  output : ok...0, verify error...1, error...-1;
-----------------------------------------------------*/
int DSA_vfy_signature(Pubkey_DSA *pub, unsigned char *data, int data_len, unsigned char *sig){
	LNm *f=NULL,*c=NULL,*d=NULL;
	unsigned char *cp;
	int	i,vfy=-1;

	if(data_len>pub->size){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DSA,ERR_PT_DSASIG+2,NULL);
		goto done;
	}

	/* encode DSA signature */
	if(*sig != 0x30){
		OK_set_error(ERR_ST_ASN_NOTASN1,ERR_LC_DSA,ERR_PT_DSASIG+2,NULL);
		goto done;
	}

	/* get signature */
	if((c=LN_alloc())==NULL) goto done;
	if((d=LN_alloc())==NULL) goto done;
	if((f=LN_alloc_c(data_len,data))==NULL) goto done;

	/* Dss-Sig-Value  ::=  SEQUENCE  { */
	cp = ASN1_next(sig);

	/* r INTEGER */
	if(ASN1_int2LNm(cp,c,&i)) goto done;
	cp = ASN1_next(cp);

	/* s INTEGER  } */
	if(ASN1_int2LNm(cp,d,&i)) goto done;

	vfy= DSA_vfy_in(pub,f,c,d);

done:
	LN_free(f);
	LN_free(d);
	LN_free(c);
	return vfy;
}

/*-----------------------------------------------------
  verify DSA signature
  output : ok...0, verify error...1, error...-1;
-----------------------------------------------------*/
int	DSA_vfy_in(Pubkey_DSA *pub, LNm *f, LNm *c, LNm *d){
	LNm *h1=NULL,*h2=NULL;
	LNm *gh=NULL,*wh=NULL;
	DSAParam *pm;
	int	err=-1;

	pm = pub->pm;
	if((c->top==0)||(d->top==0)) return 1;
	if(LN_cmp(pm->q,c)<=0) return 1;
	if(LN_cmp(pm->q,d)<=0) return 1;

	if((h1 =LN_alloc())==NULL) goto done;
	if((h2 =LN_alloc())==NULL) goto done;
	if((gh =LN_alloc())==NULL) goto done;
	if((wh =LN_alloc())==NULL) goto done;

	LN_init_lexp_tv();

	/* tmp = d^(-1) mod q */
	err = LN_mod_inverse(d,pm->q,gh);
	/* h1  = f * tmp mod q */
	err|= LN_mul_mod(f,gh,pm->q,h1);
	/* h2  = c * tmp mod q */
	err|= LN_mul_mod(c,gh,pm->q,h2);
	if(err) goto done;

	/* c' = ((g^h1 * w^h2) mod p) mod q */
	if(LN_exp_mod(pm->g ,h1,pm->p,gh)) goto done;
	if(LN_exp_mod(pub->w,h2,pm->p,wh)) goto done;
	if(LN_mul_mod(gh,wh,pm->p,h1)) goto done;

	if(LN_div_mod(h1,pm->q,gh,wh)) goto done;

	if(LN_cmp(wh,c)){err=1;goto done;}

	err=0;
done:
	LN_free(h1); LN_free(h2);
	LN_free(gh); LN_free(wh);
	return err;
}

