/* uc_uni.c */
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

#include "unicode11.h"
#include "ok_uconv.h"

static unsigned short *u2j_1=NULL;
static unsigned short *u2j_2=NULL;
static unsigned short *u2j_3=NULL;

/*-----------------------------------------
	UNICODE1.1 to Any Kanji code
-----------------------------------------*/
int UC_uni2any(char *in, int ilen, char *out, int max, int (*transf)()){
	int i,ret=0,mode=UC_M_JIS_ASCII;

	/* mode : 0..ASCII, 1..JIS X 208, 2..JIS X 201 (KATAKANA) */
	if((in==NULL)||(out==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_UCONV,ERR_PT_UC_UNI,NULL);
		return -1;
	}

	if(init_u2j_table()) return -1;

	i=ret=0;
	/* do conversion */
	while(i < ilen){
		/* "mode" can be ommited. but if this function uses static
		 * value, it won't be thread-safe...
		 */
		if(transf(&in[i],&out[ret],max,&mode,&i,&ret)) goto done;
	}
done:
	return ret;
}

/*-----------------------------------------
	UNICODE to JIS
-----------------------------------------*/
int uni2jis_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned short l;
	int r = *ret;

	l  = (*in)<<8;
	l |= (unsigned char)in[1];

	if( l<0x80 ){
		/* ASCII or something else */
		if(*mode != UC_M_JIS_ASCII){
			/* shift to ASCII mode */
			if(max<=(r+2)) goto max_end;

			out[0]=UC_ESC; out[1]='('; out[2]='B';
			*mode = UC_M_JIS_ASCII;
			r+=3; (*ret)+=3; out+=3;
		}

		if(max <= r) goto max_end;

		*out = (unsigned char)l;
		(*i)+=2; (*ret)++;

	}else if( (0xff61<=l)&&(l<=0xff9f) ){
		/* Katakana characters */
		if(*mode != UC_M_JIS_KATAKANA){
			/* shift to JIS7 katakana mode */
			if(max<=(r+2)) goto max_end;

			out[0]=UC_ESC; out[1]='('; out[2]='I';
			*mode = UC_M_JIS_KATAKANA;
			r+=3; (*ret)+=3; out+=3;
		}

		if(max <= r) goto max_end;

		*out =(unsigned char)(l-0xff40);
		(*i)+=2; (*ret)++;

	}else{
		/* UNICODE Kanji characters or else */
		if(*mode != UC_M_JIS_JISX208){
			/* shift to JIS X 208 mode */
			if(max<=(r+2)) goto max_end;

			out[0]=UC_ESC; out[1]='$'; out[2]='B';
			*mode = UC_M_JIS_JISX208;
			r+=3; (*ret)+=3; out+=3;
		}

		if(max<=(r+1)) goto max_end;

		if(uni2jis_c(l,out)){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

int uni2jis_c(unsigned short in,unsigned char *out){
	int r;

	if((0x80<=in)&&(in<=0x451)){
		r = u2j_1[in-0x80];
	}else if((0x2000<=in)&&(in<=0x9FA0)){
		r = u2j_2[in-0x2000];
	}else if((0xFF01<=in)&&(in<=0xFFE5)){
		r = u2j_3[in-0xFF00];
	}else{
		/* unable to convert to jis */
		OK_set_error(ERR_ST_UC_UNKNOWNCODE,ERR_LC_UCONV,ERR_PT_UC_UNI+2,NULL);
		return -1;
	}
	out[0] = (unsigned char)(r>>8);
	out[1] = (unsigned char) r;

	return 0;
}

/*-----------------------------------------
	UNICODE to S-JIS
-----------------------------------------*/
int uni2sjis_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned short l;
	unsigned char buf[16];
	int r = *ret;

	l  = (*in)<<8;
	l |= (unsigned char)in[1];

	if( l<0x80 ){
		/* ASCII or something else */
		if(max <= r) goto max_end;

		*out = (unsigned char)l;
		(*i)+=2; (*ret)++;

	}else if( (0xff61<=l)&&(l<=0xff9f) ){
		/* Katakana characters */
		if(max <= r) goto max_end;

		*out =(unsigned char)(l-0xff00+0x40);
		(*i)+=2; (*ret)++;

	}else{
		/* UNICODE Kanji characters or else */
		if(max<=(r+1)) goto max_end;

		if(uni2jis_c(l,buf)){
			*ret=-1; return -1;
		}
		if(jis2sjis_c(buf,out)){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	UNICODE to EUC
-----------------------------------------*/
int uni2euc_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned short l;
	int r = *ret;

	l  = (*in)<<8;
	l |= (unsigned char)in[1];

	if( l<0x80 ){
		/* ASCII or something else */
		if(max <= r) goto max_end;

		*out = (unsigned char)l;
		(*i)+=2; (*ret)++;

	}else if( (0xff61<=l)&&(l<=0xff9f) ){
		/* Katakana characters */
		if(max <= r) goto max_end;

		out[0] =(unsigned char) 0x8e;
		out[1] =(unsigned char)(l-0xff00+0x40);
		(*i)+=2; (*ret)+=2;

	}else{
		/* UNICODE Kanji characters or else */
		if(max<=(r+1)) goto max_end;

		if(uni2jis_c(l,out)){
			*ret=-1; return -1;
		}
		out[0] |= 0x80;
		out[1] |= 0x80;
		(*i)+=2; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	UNICODE to UTF8
-----------------------------------------*/
int uni2utf_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	int j,r=*ret;

	if(max<=(r+2)) goto max_end;

	if((j=ucs22utf_c(in,out))<0){
		*ret=-1; return -1;
	}
	(*i)+=2; (*ret)+=j;

	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
  initialize convert table for uni2jis
-----------------------------------------*/
int init_u2j_table(){
	int i,j;

	if(u2j_1) return 0; /* table has been created already */

	if(u2j_1==NULL){
		if((u2j_1=MALLOC(sizeof(short)*0x400))==NULL) goto error;
		memset(u2j_1,0,sizeof(short)*0x400);
	}
	if(u2j_2==NULL){
		if((u2j_2=MALLOC(sizeof(short)*0x8000))==NULL) goto error;
		memset(u2j_2,0,sizeof(short)*0x8000);
	}
	if(u2j_3==NULL){
		if((u2j_3=MALLOC(sizeof(short)*0xFF))==NULL) goto error;
		memset(u2j_3,0,sizeof(short)*0xFF);
	}

	for(i=0;i<UC_JIS2UNI_MAX;i++){
		if((j = jis2uni[i])<0) continue;

		if((0x80<=j)&&(j<=0x451)){
			u2j_1[j-0x80] = ((0x21+i/96)<<8)|(0x21+i%96);
		}else if((0x2000<=j)&&(j<=0x9FA0)){
			u2j_2[j-0x2000] = ((0x21+i/96)<<8)|(0x21+i%96);
		}else if((0xFF01<=j)&&(j<=0xFFE5)){
			u2j_3[j-0xFF00] = ((0x21+i/96)<<8)|(0x21+i%96);
		}
	}

	return 0;
error:
	free_u2j_table();
	OK_set_error(ERR_ST_MEMALLOC,ERR_LC_UCONV,ERR_PT_UC_UNI+5,NULL);
	return -1;
}

void free_u2j_table(){
	if(u2j_1){ FREE(u2j_1); u2j_1=NULL; }
	if(u2j_2){ FREE(u2j_2); u2j_2=NULL; }
	if(u2j_3){ FREE(u2j_3); u2j_3=NULL; }
}

