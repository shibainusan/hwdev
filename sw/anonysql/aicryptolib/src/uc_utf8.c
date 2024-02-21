/* uc_utf8.c */
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

#include "ok_uconv.h"

/*-----------------------------------------
	UTF8 to Any Kanji code
-----------------------------------------*/
int UC_utf2any(char *in, int ilen, char *out, int max, int (*transf)()){
	int i,j,d,ret=0,mode=UC_M_JIS_ASCII;
	unsigned char buf[16];

	/* mode : 0..ASCII, 1..JIS X 208, 2..JIS X 201 (KATAKANA) */
	if((in==NULL)||(out==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_UCONV,ERR_PT_UC_UTF8,NULL);
		return -1;
	}

	if(init_u2j_table()) return -1;

	i=ret=0;
	/* do conversion */
	while(i < ilen){
		/* "mode" can be ommited. but if this function uses static
		 * value, it won't be thread-safe...
		 */
		if((j=utf2ucs2_c(&in[i],buf))<0) return -1;
		i+=j;

		if(transf(buf,&out[ret],max,&mode,&d,&ret)) goto done;
	}
done:
	return ret;
}

/*-----------------------------------------
	UNICODE to UTF8
-----------------------------------------*/
int utf2uni_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	if(max<=((*ret)+1)) return 1;

	out[0] = in[0];
	out[1] = in[1];
	(*i)+=2; (*ret)+=2;
	return 0;
}

/*-----------------------------------------
	UCS-2 to UTF8
-----------------------------------------*/
int ucs22utf_c(unsigned char *in, unsigned char *out){
	unsigned char c1=in[0],c2=in[1];
	int cd,ret=1;

	cd = ((int)c1<<8) | c2;
	if(cd<0x80){
		out[0]= c2;
	}else if(cd<0x0800){
		out[0] = 0xc0 |(c1<<2)|(c2>>6);
		c2    &= 0x3f;
		out[1] = 0x80 | c2;
		ret++;
	}else{
		out[0] = 0xe0 |(c1>>4);
		c1    &= 0x0f;
		out[1] = 0x80 |(c1<<2)|(c2>>6);
		c2    &= 0x3f;
		out[2] = 0x80 | c2;
		ret+=2;
	}
	return ret;
}

/*-----------------------------------------
	UTF8 to UCS-2
-----------------------------------------*/
int utf2ucs2_c(unsigned char *in, unsigned char *out){
	unsigned char c1=in[0],c2,c3;
	int ret=1;

	if(c1<0x80){
		out[0]= 0;
		out[1]= c1;
	}else if((c1&0xe0)==0xc0){
		c2 = in[1];
		if((c2&0xc0)!=0x80) goto error;

		out[0] = (c1&0x1f)>>2;
		out[1] = (c1<<6)|(c2&0x3f);
		ret++;
	}else if((c1&0xf0)==0xe0){
		c2=in[1]; c3=in[2];
		if((c2&0xc0)!=0x80) goto error;
		if((c3&0xc0)!=0x80) goto error;

		out[0] = (c1<<4)|((c2&0x3f)>>2);
		out[1] = (c2<<6)| (c3&0x3f);
		ret+=2;
	}else
		goto error;

	return ret;
error:
	/* bad utf8 encoding */
	OK_set_error(ERR_ST_UC_BADUTF8CODE,ERR_LC_UCONV,ERR_PT_UC_UTF8+2,NULL);
	return -1;
}
