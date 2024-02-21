/* asn1_ecc.c */
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
#include <string.h>
#include <stdlib.h>

#include "key_type.h"

#include "ok_ecc.h"
#include "ok_asn1.h"

/*-----------------------------------------
  ASN.1 to struct ECParam
-----------------------------------------*/
ECParam *ASN1_read_ecparam(unsigned char *in){
	unsigned char *top;
	ECParam *ret=NULL;
	int i;

	if(in == NULL) goto error;

	if(*in == ASN1_OBJECT_IDENTIFIER){
		if((i=ASN1_object_2int(in))<0) goto error;
		if((ret = ECPm_get_std_parameter(i))==NULL) goto error;
		return ret;

	}else if(*in == ASN1_NULL){
		/* CA certificate has this parameter */
		goto error;
	}

	if(*in != 0x30) goto error;
	top= in;
	in = ASN1_next(in);

	if((ret=ECPm_new())==NULL) goto error;

	/* version ECVer */
	if((ret->version=ASN1_integer(in,&i)) != 1) goto error;
	in = ASN1_next(in);

	/* fieldID FieldID */
	if(ASN1_get_ecfieldID(in,ret)) goto error;
	if((in = ASN1_skip(in))==NULL) goto error;

	/* curve Curve */
	if(ASN1_get_eccurve(in,ret)) goto error;
	if((in = ASN1_skip(in))==NULL) goto error;

	/* base ECPoint */
	if(ret->G) ECp_free(ret->G);
	if((ret->G=ASN1_get_ecpoint(in,ret))==NULL) goto error;
	in = ASN1_next(in);

	/* order INTEGER */
	if(ASN1_int2LNm(in,ret->n,&i)) goto error;
	ret->nsize=LN_now_bit(ret->n);
	in = ASN1_next(in);
	
	/* cofactor INTEGER OPTIONAL */
	if(*in == ASN1_INTEGER){
		if(ASN1_int2LNm(in,ret->h,&i)) goto error;
	}

	ret->der=top;
	return ret;
error:
	ECPm_free(ret);
	return NULL;
}

int ASN1_get_ecfieldID(unsigned char *in,ECParam *ret){
	int i;

	in = ASN1_next(in);

	/* fieldType OBJECT IDENTIFIER */
	if((ret->type=ASN1_object_2int(in))<0) goto error;
	in = ASN1_next(in);

	/* parameters ANY DEFINED BY fieldType */
	switch(ret->type){
	case OBJ_X962_FT_PRIME:
		if(ASN1_int2LNm(in,ret->p,&i)) goto error;
		ret->psize      = LN_now_bit(ret->p);
		ret->curve_type = ECP_ORG_primeParam;
		break;
	case OBJ_X962_FT_CHR2:
		/* not supported */
		ret->curve_type = ECP_ORG_char2Param;
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_ASN1,ERR_PT_ASN1ECC+1,NULL);
		goto error;
	default:
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_ASN1,ERR_PT_ASN1ECC+1,NULL);
		goto error;
	}

	return 0;
error:
	return -1;
}

int ASN1_get_eccurve(unsigned char *in,ECParam *ret){
	unsigned char *buf;
	int i,j;
	
	in = ASN1_next(in);

	/* a FieldElement */
	if(ASN1_octetstring(in,&i,&buf,&j)) goto error;
	i = LN_set_num_c(ret->a,j,buf);
	FREE(buf);
	if(i) goto error;
	in = ASN1_next(in);

	/* b FieldElement */
	if(ASN1_octetstring(in,&i,&buf,&j)) goto error;
	i = LN_set_num_c(ret->b,j,buf);
	FREE(buf);
	if(i) goto error;
	in = ASN1_next(in);

	/* seed BIT STRING OPTIONAL */
	if(*in == ASN1_BITSTRING){
		/* not supported */
	}
	return 0;
error:
	return -1;
}

ECp *ASN1_get_ecpoint(unsigned char *in,ECParam *ecp){
	unsigned char *buf=NULL;
	int i,j;
	ECp *ret;
	
	/* ECPoint OCTET STRING */
	if(ASN1_octetstring(in,&i,&buf,&j)) goto done;
	ret = ECp_OS2P(ecp,buf,j); /* might be NULL */

done:
	if(buf) FREE(buf);
	return ret;
}

