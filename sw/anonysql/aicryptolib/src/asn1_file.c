/* asn1_file.c */
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

#include <sys/types.h>
#include <sys/stat.h>

#include "ok_io.h"
#include "ok_asn1.h"

/*-----------------------------------------
  Read DER file (return DER buf)
-----------------------------------------*/
unsigned char *ASN1_read_der(char *fname){
	char  *buf;
	FILE  *fp;
	int sz,err=-1;

	if((fp = fopen(fname,"rb"))==NULL){
		if(okerr) fprintf(okerr,"DER read:fopen error:%s\n",fname);
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_ASN1,ERR_PT_ASN1FILE,NULL);
		return(NULL);
	}

	sz = ok_get_flen(fp);

	if((buf=(char*)MALLOC(sz+1))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1FILE,NULL);
		goto done;
	}
	if(fread(buf,sizeof(char),sz,fp)<(unsigned)sz){
		OK_set_error(ERR_ST_FILEREAD,ERR_LC_ASN1,ERR_PT_ASN1FILE,NULL);
		goto done;
	}
	buf[sz]=0;

	if(buf[0] != (ASN1_SEQUENCE|0x20)){
		OK_set_error(ERR_ST_ASN_NOTASN1,ERR_LC_ASN1,ERR_PT_ASN1FILE,NULL);
		goto done;
	}
	err=0;
done:
	if(err&&buf){ FREE(buf); buf=NULL;}
	fclose(fp);
	return(buf);
}

/*-----------------------------------------
  Write DER file.
  error -- return -1
-----------------------------------------*/
int ASN1_write_der(unsigned char *der,char *fname){
	int   i,len,err=-1;
	FILE  *fp;

	if(der==NULL){return -1;}
	if((fp = fopen(fname,"wb"))==NULL){
		if(okerr) fprintf(okerr,"DER write:fopen error:%s\n",fname);
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_ASN1,ERR_PT_ASN1FILE+1,NULL);
		return -1;
	}

	len =ASN1_length((der+1),&i);
	len+=i+1;

	if(fwrite(der,sizeof(char),len,fp)<(unsigned)len){
		OK_set_error(ERR_ST_FILEWRITE,ERR_LC_ASN1,ERR_PT_ASN1FILE+1,NULL);
		goto done;
	}
	err=0;
done:
	fclose(fp);
	return err;
}
