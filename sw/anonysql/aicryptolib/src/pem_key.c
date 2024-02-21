/* pem_key.c */
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
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "ok_io.h"
#include "ok_base64.h"
#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_pem.h"

/*-----------------------------------------
     Read PEM key file (return DER buf)
-----------------------------------------*/
void get_iv(char *in,unsigned char *ret){
	char	c[8]={"0x  "},*c2;
	int i;

	c2 = &c[2];
	for(i=0;i<8;i++,ret++){
		strncpy(c2,in,2); in+=2;
		*ret = (unsigned char)strtol(c,(char**)NULL,16);
	}
}

unsigned char *pem_read_prvkey_2der(char *begin,char *end,char *fname){
	unsigned char  *ret=NULL,*buf;
	int	i,err=-1;

	if((buf=get_file2buf(fname,&i))==NULL)
		return NULL;

	ret=PEM_decode_message(buf,&i,begin,end);

	if((ret==NULL)||(ret[0] != 0x30)){
		if(okerr) fprintf(okerr,"PEM Verify Error -- password missing.\n");
		OK_set_error(ERR_ST_PEM_BADPASSWD,ERR_LC_PEM,ERR_PT_PEM,NULL);
		goto done;
	}
	err=0;

done:
	if(buf) FREE(buf);
	if(err&&ret){ FREE(ret);ret=NULL;}
	return ret;
}

/*-----------------------------------------
  Read PEM RSA private file
    (return *Prvkey_RSA)
-----------------------------------------*/
unsigned char *PEM_read_rsaprv_2der(char *fname){
	return(pem_read_prvkey_2der("-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
		fname));
}

Prvkey_RSA *PEM_read_rsaprv(char *fname){
	unsigned char *cp;
	Prvkey_RSA	*ret;

	if((cp=PEM_read_rsaprv_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_rsaprv(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE rsad.
	 */
	return ret;
}

/*-----------------------------------------
  Read PEM DSA private file
    (return *Prvkey_DSA)
-----------------------------------------*/
unsigned char *PEM_read_dsaprv_2der(char *fname){
	return(pem_read_prvkey_2der("-----BEGIN DSA PRIVATE KEY-----",
		"-----END DSA PRIVATE KEY-----",
		fname));
}

Prvkey_DSA *PEM_read_dsaprv(char *fname){
	unsigned char *cp;
	Prvkey_DSA	*ret;

	if((cp=PEM_read_dsaprv_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_dsaprv(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE rsad.
	 */
	return ret;
}

/*-----------------------------------------
  Read PEM dsaparam file (return *DSAParam)
-----------------------------------------*/
DSAParam *PEM_read_dsaparam(char *fname){
	unsigned char *cp;
	DSAParam *ret;

	if((cp=pem_read2der(
			"-----BEGIN DSA PARAMETERS-----",
			"-----END DSA PARAMETERS-----",
			fname))==NULL)
		return NULL;

	ret = ASN1_read_dsaparam(cp,0);

	/* cp pointer is used by ret->der.
	 * so cannot FREE reqd.
	 */
	return ret;
}

/*-----------------------------------------
  Read PEM ECDSA private file
    (return *Prvkey_ECDSA)
-----------------------------------------*/
unsigned char *PEM_read_ecdsaprv_2der(char *fname){
	return(pem_read_prvkey_2der("-----BEGIN ECDSA PRIVATE KEY-----",
		"-----END ECDSA PRIVATE KEY-----",
		fname));
}

Prvkey_ECDSA *PEM_read_ecdsaprv(char *fname){
	unsigned char *cp;
	Prvkey_ECDSA	*ret;

	if((cp=PEM_read_ecdsaprv_2der(fname))==NULL)
		return NULL;

	ret = ASN1_read_ecdsaprv(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE rsad.
	 */
	return ret;
}

/*-----------------------------------------
  Read PEM dsaparam file (return *ECParam)
-----------------------------------------*/
ECParam *PEM_read_ecparam(char *fname){
	unsigned char *cp;
	ECParam *ret;

	if((cp=pem_read2der(
			"-----BEGIN ECDSA PARAMETERS-----",
			"-----END ECDSA PARAMETERS-----",
			fname))==NULL)
		return NULL;

	ret = ASN1_read_ecparam(cp);

	/* cp pointer is used by ret->der.
	 * so cannot FREE reqd.
	 */
	return ret;
}

