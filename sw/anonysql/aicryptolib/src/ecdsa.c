/* ecdsa.c */
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
#include <math.h>

#include "ok_asn1.h"
#include "ok_x509.h"
#include "ok_ecdsa.h"


/*-----------------------------------------------------
  get ECDSA signature and return c||d octet strings
-----------------------------------------------------*/
unsigned char *ECDSA_get_signature(Prvkey_ECDSA *prv, unsigned char *data, int data_len, int *ret_len){
	unsigned char *ret=NULL,*cp;
	LNm *f=NULL,*c=NULL,*d=NULL;
	ECParam *E=NULL;
	int	i,j,err=-1;

	if(data_len>prv->size){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ECDSA,ERR_PT_ECDSA,NULL);
		goto done;
	}
	if((E=prv->E)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECDSA,ERR_PT_ECDSA,NULL);
		goto done;
	}

	if((c=LN_alloc())==NULL) goto done;
	if((d=LN_alloc())==NULL) goto done;
	if((f=LN_alloc_c(data_len,data))==NULL) goto done;

	if(ECDSA_sig_in(E,prv,f,c,d)) goto done;

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
  generate ECDSA signature
  output : integers c and d.
-----------------------------------------------------*/
int ECDSA_sig_in(ECParam *E, Prvkey_ECDSA *prv, LNm *f, LNm *c, LNm *d){
	LNm *tmp1,*tmp2;
	Prvkey_ECDSA *otp;	/* one time password */
	int err=-1;

	tmp1= E->buf[10];
	tmp2= E->buf[11];
	if((otp=ECDSAprvkey_new())==NULL) goto done;

	do{
		do{ /* create one time password */
			LN_long_set(E->G->z,1);
		    err  = LN_set_rand(otp->k, 7 /* byte */, (unsigned short)(rand()*3));
		    err |= ECp_pmulti(E,E->G,otp->k,otp->W);
		    err |= ECp_proj2af(E,otp->W);
			if(err) goto done;
		}while((otp->W->x->top==0)&&(otp->W->y->top==0));

		/* get c */
		if(err=LN_div_mod(otp->W->x,E->n,tmp1,c))	goto done;
		if(c->top==0)	continue;

		err  = LN_mod_inverse(otp->k,E->n,tmp1);	/* u^(-1) */
		err |= LN_multi(prv->k,c,d);
		err |= LN_plus(d,f,tmp2);					/* f + sc */
		err |= LN_mul_mod(tmp1,tmp2,E->n,d);
		if(err) goto done;
		if(d->top==0)	continue;
		break;
	}while(1);

done:
	if(otp) ECDSAkey_free((Key*)otp);
	return err;
}

/*-----------------------------------------------------
  verify ECDSA signature
  output : ok...0, verify error...1, error...-1;
-----------------------------------------------------*/
int ECDSA_vfy_signature(Pubkey_ECDSA *pub, unsigned char *data, int data_len, unsigned char *sig){
	LNm *f=NULL,*c=NULL,*d=NULL;
	ECParam *E=NULL;
	unsigned char *cp;
	int	i,vfy=-1;

	if(data_len>pub->size){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ECDSA,ERR_PT_ECDSA+1,NULL);
		goto done;
	}

	if((E=pub->E)==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECDSA,ERR_PT_ECDSA+1,NULL);
		goto done;
	}

	/* encode ECDSA signature */
	if(*sig != 0x30){
		OK_set_error(ERR_ST_ASN_NOTASN1,ERR_LC_ECDSA,ERR_PT_ECDSA+1,NULL);
		goto done;
	}

	i  = LN_now_byte(E->n);
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

	vfy= ECDSA_vfy_in(E,pub,f,c,d);

done:
	LN_free(f);
	LN_free(d);
	LN_free(c);
	return vfy;
}

/*-----------------------------------------------------
  verify ECDSA signature
  output : ok...0, verify error...1, error...-1;
-----------------------------------------------------*/
int	ECDSA_vfy_in(ECParam *E, Pubkey_ECDSA *pub, LNm *f, LNm *c, LNm *d){
	LNm *tmp=NULL,*h1=NULL,*h2=NULL;
	ECp *gh=NULL,*wh=NULL,*P=NULL;
	int	err=-1;

	if((c->top==0)||(d->top==0)) return 1;
	if(LN_cmp(E->n,c)<=0) return 1;
	if(LN_cmp(E->n,d)<=0) return 1;

	LN_init_lexp_tv();

	if((h1 =LN_alloc())==NULL) goto done;
	if((h2 =LN_alloc())==NULL) goto done;
	if((tmp=LN_alloc())==NULL) goto done;
	if((gh =ECp_new())==NULL) goto done;
	if((wh =ECp_new())==NULL) goto done;
	if((P  =ECp_new())==NULL) goto done;

	err = LN_mod_inverse(d,E->n,tmp);
	err|= LN_mul_mod(f,tmp,E->n,h1);
	err|= LN_mul_mod(c,tmp,E->n,h2);
	if(err) goto done;

	LN_long_set(E->G->z,1);
	LN_long_set(pub->W->z,1);

	err = ECp_pmulti(E,E->G,h1,gh);
	err|= ECp_pmulti(E,pub->W,h2,wh);
	err|= ECp_padd(E,gh,wh,P);
	err|= ECp_proj2af(E,P);
	if(err) goto done;

	if(err=P->infinity) goto done;
	if(err=LN_div_mod(P->x,E->n,tmp,h1)) goto done;
	if(LN_cmp(h1,c)){err=1;goto done;}

	err=0;
done:
	LN_free(tmp); LN_free(h1); LN_free(h2);
	ECp_free(gh); ECp_free(wh); ECp_free(P);
	return err;
}

