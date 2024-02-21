/* pem_w.c */
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
#include <time.h>

#include "ok_io.h"
#include "ok_x509.h"
#include "ok_asn1.h"
#include "ok_rsa.h"
#include "ok_base64.h"
#include "ok_pem.h"

/* just use OBJ_CRYALGO_* */
int default_pem_cry_algo=OBJ_CRYALGO_3DESCBC;

int write_bs64(FILE *fp,long len,unsigned char *der);

/*-----------------------------------------
  Write PEM cert file
-----------------------------------------*/
int PEM_write_cert(Cert *cert,char *fname){
	return pem_write(cert->der,fname,
		"-----BEGIN CERTIFICATE-----\n",
		"-----END CERTIFICATE-----\n");
}

/*--------------------------------------------
  Write PEM cross-cert file 
--------------------------------------------*/
int PEM_write_crtp(CertPair *crtp,char *fname){
	return pem_write(crtp->der,fname,
		"-----BEGIN CROSS CERTIFICATE PAIR-----\n",
		"-----END CROSS CERTIFICATE PAIR-----\n");
}

/*-----------------------------------------
  Write PEM CRL file.
-----------------------------------------*/
int PEM_write_crl(CRL *crl,char *fname){
	return pem_write(crl->der,fname,
		"-----BEGIN X509 CRL-----\n",
		"-----END X509 CRL-----\n");
}

/*-----------------------------------------
  Write PEM cert file (return DER buf)
-----------------------------------------*/
int PEM_write_req(Cert *req,char *fname){
  return pem_write(req->der,fname,
	    "-----BEGIN CERTIFICATE REQUEST-----\n",
	    "-----END CERTIFICATE REQUEST-----\n");
}

/*-----------------------------------------
  Write PEM Private Key file.
-----------------------------------------*/
int pem_write_prvkey(unsigned char *der,char *fname,char *begin,char *end){
	unsigned char *cry=NULL,ivc[8];
	time_t t;
	int i,len,err=-1;
	FILE *fp;
  
	if(der==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PEM,ERR_PT_PEMWRITE,NULL);
		return -1;
	}
	if((fp = fopen(fname,"wt"))==NULL){
		if(okerr) fprintf(okerr,"PEM write:fopen error:%s\n",fname);
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PEM,ERR_PT_PEMWRITE,NULL);
		return -1;
	}

	time(&t);
	for(i=0;i<8;i++) ivc[i]=(unsigned char)(rand()+t);

	fputs(begin,fp);
	if(default_pem_cry_algo){
		fputs("Proc-Type: 4,ENCRYPTED\n",fp);

		switch(default_pem_cry_algo){
		case OBJ_CRYALGO_RC2CBC:
			fputs("DEK-Info: RC2-CBC,",fp);
			break;
		case OBJ_CRYALGO_DESCBC:
			fputs("DEK-Info: DES-CBC,",fp);
			break;
		case OBJ_CRYALGO_3DESCBC:
			fputs("DEK-Info: DES-EDE3-CBC,",fp);
			break;
		default:
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PEM,ERR_PT_PEMWRITE,NULL);
			goto done;
		}

		for(i=0;i<8;i++) fprintf(fp,"%.2X",ivc[i]);
		fputs("\n\n",fp);
	}

	
	/* set length and get encrypted length */
	if(ASN1_skip_(der,&len)==NULL) goto done;

	if(default_pem_cry_algo){
		if((cry=PEM_msg_encrypt(der,&len,ivc,default_pem_cry_algo))==NULL)
			goto done;
	}else{
		cry = der;
	}

	if(write_bs64(fp,len,cry)) goto done;

	fputs(end,fp);
	err=0;

done:
	if((cry)&&(cry!=der)) FREE(cry);
	fclose(fp);
	return err;
}

/* RSA private key */
int PEM_write_rsaprv(Prvkey_RSA *rsa,char *fname){
	if(rsa==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PEM,ERR_PT_PEMWRITE+1,NULL);
		return -1;
	}
	if(pem_write_prvkey(rsa->der,fname,
			"-----BEGIN RSA PRIVATE KEY-----\n",
			"-----END RSA PRIVATE KEY-----\n"))
		return -1;
	return 0;
}

/* DSA private key */
int PEM_write_dsaprv(Prvkey_DSA *dsa,char *fname){
	if(dsa==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PEM,ERR_PT_PEMWRITE+2,NULL);
		return -1;
	}
	if(pem_write_prvkey(dsa->der,fname,
			"-----BEGIN DSA PRIVATE KEY-----\n",
			"-----END DSA PRIVATE KEY-----\n"))
		return -1;
	return 0;
}

/* DSA parameter */
int PEM_write_dsaparam(DSAParam *dpm,char *fname){
  return pem_write(dpm->der,fname,
			"-----BEGIN DSA PARAMETERS-----\n",
			"-----END DSA PARAMETERS-----\n");
}

/* ECDSA private key */
int PEM_write_ecdsaprv(Prvkey_ECDSA *dsa,char *fname){
	if(dsa==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PEM,ERR_PT_PEMWRITE+3,NULL);
		return -1;
	}
	if(pem_write_prvkey(dsa->der,fname,
			"-----BEGIN ECDSA PRIVATE KEY-----\n",
			"-----END ECDSA PRIVATE KEY-----\n"))
		return -1;
	return 0;
}

/* ECDSA parameter */
int PEM_write_ecparam(ECParam *dpm,char *fname){
  return pem_write(dpm->der,fname,
			"-----BEGIN ECDSA PARAMETERS-----\n",
			"-----END ECDSA PARAMETERS-----\n");
}


/*-----------------------------------------
  PEM write from der.
-----------------------------------------*/
int pem_write(unsigned char *der,char *fname,char *begin,char *end){
	FILE *fp;
	int err=-1;

	if(der==NULL) return -1;

	if((fp = fopen(fname,"wt"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PEM,ERR_PT_PEMWRITE+4,NULL);
		return -1;
	}

	fputs(begin,fp);
	if(write_bs64(fp,0,der)) goto done;
	fputs(end,fp);

	err=0;
done:
	fclose(fp);
	return err;
}

/*-----------------------------------------
  PEM write base64 code from der.
-----------------------------------------*/
int write_bs64(FILE *fp,long len,unsigned char *der){
	unsigned char *buf;
	int	i;

	if(!len){
		len = ASN1_length((der+1),&i);
		len+= i+1;
	}
	if((buf=Base64_encode(len,der,16))==NULL)
		return -1;

	fputs(buf,fp);
	fputs("\n",fp);

	FREE(buf);
	return 0;
}




