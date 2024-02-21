/* ecc_asn1.c */
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

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>

#include "ok_asn1.h"
#include "ok_ecc.h"
#include "ok_x509.h"


/*-----------------------------------------------
  ECDSA Parameter to DER
-----------------------------------------------*/
unsigned char *ECPm_toDER(ECParam *ecp,unsigned char *buf,int *ret_len){
	unsigned char *cp,*ret;
	int	i,j;

	if(buf==NULL){
		if((i=ECPm_estimate_der_size(ecp))<=0)
			return NULL;

		if((ret=(unsigned char*)MALLOC(i))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ECC,ERR_PT_ECCASN1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if((ecp->curve_type != ECP_ORG_primeParam) &&
		(ecp->curve_type != ECP_ORG_char2Param)){
		/* this is known curve. set OID and return :-) */
		if(ASN1_int_2object(ecp->curve_type,ret,ret_len)) goto error;
		return ret;
	}

	/* version ECVersion */
	ASN1_set_integer(ecp->version,ret,&i);
	cp = ret+i;
	
	/* fieldID FieldID */
	if(ECPm_DER_ecfieldID(ecp,cp,&j)) goto error;
	cp+=j; i+=j;

	/* curve Curve */
	if(ECPm_DER_eccurve(ecp,cp,&j)) goto error;
	cp+=j; i+=j;

	/* base ECPoint */
	if(ECPm_DER_ecpoint(ecp->G,cp,&j)) goto error;
	cp+=j; i+=j;

	/* order INTEGER */
	if(ASN1_LNm2int(ecp->n,cp,&j)) goto error;
	cp+=j; i+=j;

	/* cofactor INTEGER OPTIONAL */
	if(ecp->h->top){
		if(ASN1_LNm2int(ecp->h,cp,&j)) goto error;
		i+=j;
	}

	ASN1_set_sequence(i,ret,ret_len);

	return ret;
error:
	if(ret!=buf) FREE(ret);
	return NULL;
}


int ECPm_DER_ecfieldID(ECParam *ecp,unsigned char *ret,int *ret_len){
	unsigned char *cp;
	int i,j,err=-1;

	/* fieldType OBJECT Identifier */
	if(ASN1_int_2object(ecp->type,ret,&i)) goto done;
	cp = ret+i;

	/* parameters ANY DEFINED BY fieldType */
	switch(ecp->type){
	case OBJ_X962_FT_PRIME:
		if(ASN1_LNm2int(ecp->p,cp,&j)) goto done;
		i+=j;
		break;
	case OBJ_X962_FT_CHR2:
		/* not supported */
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_ECC,ERR_PT_ECCASN1+1,NULL);
		goto done;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ECC,ERR_PT_ECCASN1+1,NULL);
		goto done;
	}

	ASN1_set_sequence(i,ret,ret_len);
	err=0;
done:
	return err;
}

int ECPm_DER_eccurve(ECParam *ecp,unsigned char *ret,int *ret_len){
	unsigned char *cp,buf[LN_MAX*sizeof(ULONG)];
	int i,j,k,err=-1;

	/* a FieldElement */
	k=LN_now_byte(ecp->a);
	if(LN_get_num_c(ecp->a,k,buf)) goto done;
	ASN1_set_octetstring(k,buf,ret,&i);
	cp = ret + i;

	/* b FieldElement */
	k=LN_now_byte(ecp->b);
	if(LN_get_num_c(ecp->b,k,buf)) goto done;
	ASN1_set_octetstring(k,buf,cp,&j);
	i+=j;

	/* seed BIT STRING */
	/* not supported */

	ASN1_set_sequence(i,ret,ret_len);
	err=0;
done:
	return err;
}

int ECPm_DER_ecpoint(ECp *ecp,unsigned char *ret,int *ret_len){
	unsigned char *buf;
	int i;

	/* ECPoint OCTET STRING */
	if((buf=ECp_P2OS(ecp,4,&i))==NULL) return -1;
	ASN1_set_octetstring(i,buf,ret,ret_len);

	FREE(buf);
	return 0;
}


/*-----------------------------------------------
  estimate DER size of ECDSA Parameter 
-----------------------------------------------*/
int ECPm_estimate_der_size(ECParam *ecp){
	int i;

	if(ecp==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_ECC,ERR_PT_ECCASN1+1,NULL);
		return -1;
	}

	if((ecp->curve_type != ECP_ORG_primeParam) &&
		(ecp->curve_type != ECP_ORG_char2Param)){
		/* known curve */
		return 16;
	}

	/* version & ... */
	i=16;

	/* fieldID */
	switch(ecp->type){
	case OBJ_X962_FT_PRIME: i+=16+(ecp->psize>>3); break;
	case OBJ_X962_FT_CHR2:  i+=24; break;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ECC,ERR_PT_ECCASN1+1,NULL);
		return -1;
	}
	/* curve */
	i+=10 + (ecp->a->top<<2) + (ecp->b->top<<2);
	/* base */
	i+= 4 + (ecp->G->x->top<<2) + (ecp->G->y->top<<2);
	/* order */
	i+= 4 + (ecp->nsize>>3);
	/* cofactor */
	i+= 4 + (ecp->h->top<<2);

	return i;
}

