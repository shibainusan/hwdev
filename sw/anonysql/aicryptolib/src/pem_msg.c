/* pem_msg.c */
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
#include <time.h>

#include "ok_io.h"
#include "ok_asn1.h"
#include "ok_base64.h"
#include "ok_pem.h"

void get_iv(char *in,unsigned char *ret);


/*----------------------------------------------------
     Read PEM message file (return message buf)
----------------------------------------------------*/
unsigned char *PEM_read_message(char *fname, int *len){
	unsigned char *ret,*buf;

	if((buf=get_file2buf(fname,len))==NULL)
		return NULL;

	ret=PEM_decode_message(buf,len,
		"-----BEGIN PRIVACY-ENHANCED MESSAGE-----",
		"-----END PRIVACY-ENHANCED MESSAGE-----");

	FREE(buf);
	return ret;
}

/*-----------------------------------------
	Write PEM message file
-----------------------------------------*/
int PEM_write_message(unsigned char *buf,int len, char *fname){
	unsigned char *ret;
	FILE	*fp;
	int err=-1;
  
	if(buf==NULL) return -1;
	if((fp = fopen(fname,"wt"))==NULL){
		if(okerr) fprintf(okerr,"PEM write:fopen error:%s\n",fname);
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_PEM,ERR_PT_PEMMSG,NULL);
		return -1;
	}

	ret=PEM_encode_message(buf,len,
		"-----BEGIN PRIVACY-ENHANCED MESSAGE-----\n",
		"-----END PRIVACY-ENHANCED MESSAGE-----\n");

	if(ret==NULL) goto done;

	fputs(ret,fp);
	err=0;

done:
	fclose(fp);
	if(ret) FREE(ret);
	return err;
}


/*----------------------------------------------------
     Decrypt PEM message file (return message buf)
----------------------------------------------------*/
unsigned char *PEM_decode_message(char *buf,int *len,char *begin,char *end){
	unsigned char *cry,*ret,iv[8];
	char  *bp,*ep,*c,*s;
	int   cnt,i;

	if((bp=strstr(buf,begin))==NULL){
		OK_set_error(ERR_ST_PEM_BADHEADER,ERR_LC_PEM,ERR_PT_PEMMSG+1,NULL);
		return NULL;
	}
	bp += strlen(begin);
	if((ep=strstr(buf,end))==NULL){
		OK_set_error(ERR_ST_PEM_BADFOOTER,ERR_LC_PEM,ERR_PT_PEMMSG+1,NULL);
		return NULL;
	}
	*ep = 0;

	if((c=strchr(bp,':'))!=NULL){
		for(s=bp; c!=NULL;){
			s=c;
			c=strchr((++c),':');
		}
		bp = strchr(s,'\n');
	}

	if((cry=Base64_decode(bp,&cnt))==NULL)
		return NULL;

	if((c=strstr(buf,"DEK-Info:"))==NULL){ /* not encrypted */      
		return cry;
	}else if((bp=strstr(c,"DES-CBC"))!=NULL){ /* des cbc encrypted */
		i=OBJ_CRYALGO_DESCBC;
	}else if((bp=strstr(c,"DES-EDE3-CBC"))!=NULL){ /* des ede3 cbc encrypted */
		i=OBJ_CRYALGO_3DESCBC;
	}else{
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PEM,ERR_PT_PEMMSG+1,NULL);
		goto done;
	}

	*len = cnt;
	if((bp=strchr(c,','))==NULL){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_PEM,ERR_PT_PEMMSG+1,NULL);
		goto done;
	}
	bp++; get_iv(bp,iv);

	ret = PEM_msg_decrypt(cry,cnt,iv,i);

done:
	FREE(cry);
	return ret;
}


/*----------------------------------------------------
     Encrypt PEM message file (return message buf)
     if len==0 then buf is counted by strlen();
----------------------------------------------------*/
unsigned char *PEM_encode_message(char *buf,int len,char *begin,char *end){
	unsigned char *cry=NULL,*ret=NULL,*bs=NULL,ivc[8];
	time_t t;
	int	i,err=-1;

	/* first get contents */
	if(len==0) len=strlen(buf);

	time(&t);
	for(i=0;i<8;i++) ivc[i]=(unsigned char)(rand()+t);

	if(default_pem_cry_algo){
		if((cry=PEM_msg_encrypt(buf,&len,ivc,default_pem_cry_algo))==NULL) goto done;
		if((bs =Base64_encode(len,cry,16))==NULL) goto done;
	}else{
		if((bs =Base64_encode(len,buf,16))==NULL) goto done;
	}

	/* output text */
	/* alloc memory (len/3)*4...encode, (len/64)...number of '\n'  */
	/*              196...header,footer                            */
	len = (len/3)<<2;
	if((ret=(char*)MALLOC(len+(len>>6)+196))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_PEMMSG+2,NULL);
		goto done;
	}

	*ret= 0;
	strcat(ret,begin);
	if(default_pem_cry_algo){
		strcat(ret,"Proc-Type: 4,ENCRYPTED\n");

		switch(default_pem_cry_algo){
		case OBJ_CRYALGO_RC2CBC:
			strcat(ret,"DEK-Info: RC2-CBC,");
			break;
		case OBJ_CRYALGO_DESCBC:
			strcat(ret,"DEK-Info: DES-CBC,");
			break;
		case OBJ_CRYALGO_3DESCBC:
			strcat(ret,"DEK-Info: DES-EDE3-CBC,");
			break;
		default:
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_PEM,ERR_PT_PEMMSG+2,NULL);
			goto done;
		}

		for(i=0;i<8;i++){ 
		    char cb[16];
			sprintf(cb,"%.2X",ivc[i]);
			strcat(ret,cb);
		}

		strcat(ret,"\n\n");
	}else{
		strcat(ret,"\n");
	}
	strcat(ret,bs);

	strcat(ret,"\n");
	strcat(ret,end);
	strcat(ret,"\n");
	err=0;

done:
	if(cry) FREE(cry);
	if(bs)  FREE(bs);
	if(err&&ret){FREE(ret);ret=NULL;}
	return ret;
}

