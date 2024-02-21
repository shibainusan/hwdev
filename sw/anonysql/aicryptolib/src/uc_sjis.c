/* uc_sjis.c */
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
	Shift-JIS to Any Kanji code
-----------------------------------------*/
int UC_sjeu2any(char *in, int ilen, char *out, int max, int (*transf)()){
	int i,ret=0,mode=UC_M_JIS_ASCII;

	/* mode : 0..ASCII, 1..JIS X 208, 2..JIS X 201 (KATAKANA) */
	if((in==NULL)||(out==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_UCONV,ERR_PT_UC_SJIS,NULL);
		return -1;
	}

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
	Shift-JIS to JIS
-----------------------------------------*/
int sjis2jis_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch;
	int r = *ret;

	ch = *in;
	if( (ch<=0x80)||(ch==0xA0)||(ch>=0xFD) ){
		/* ASCII or something else */
		if(*mode != UC_M_JIS_ASCII){
			/* shift to ASCII mode */
			if(max<=(r+2)) goto max_end;

			out[0]=UC_ESC; out[1]='('; out[2]='B';
			*mode = UC_M_JIS_ASCII;
			r+=3; (*ret)+=3; out+=3;
		}

		if(max <= r) goto max_end;

		*out = ch; (*i)++; (*ret)++;

	}else if( (0xA1<=ch)&&(ch<=0xDF) ){
		/* JIS8 Katakana characters */
		if(*mode != UC_M_JIS_KATAKANA){
			/* shift to JIS7 katakana mode */
			if(max<=(r+2)) goto max_end;

			out[0]=UC_ESC; out[1]='('; out[2]='I';
			*mode = UC_M_JIS_KATAKANA;
			r+=3; (*ret)+=3; out+=3;
		}

		if(max <= r) goto max_end;

		*out = 0x7f&ch; (*i)++; (*ret)++;

	}else{
		/* S-JIS Kanji characters */
		if(*mode != UC_M_JIS_JISX208){
			/* shift to JIS X 208 mode */
			if(max<=(r+2)) goto max_end;

			out[0]=UC_ESC; out[1]='$'; out[2]='B';
			*mode = UC_M_JIS_JISX208;
			r+=3; (*ret)+=3; out+=3;
		}

		if(max<=(r+1)) goto max_end;

		if(sjis2jis_c(in,out)){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

int sjis2jis_c(char *in,unsigned char *out){
	unsigned char c1=in[0],c2=in[1];

	c1 -= (c1<=0x9f)?(0x70):(0xb0);
	c1 <<= 1;

	if(c2<0x9f){
		c2 -= (c2<0x7f)?(0x1f):(0x20);
		c1--;
    }else{
		c2 -= 0x7e;
	}

	out[0]=c1; out[1]=c2;
	return 0;
}

/*-----------------------------------------
	Shift-JIS to EUC
-----------------------------------------*/
int sjis2euc_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch,buf[16];
	int r = *ret;

	ch = *in;
	if( (ch<=0x80)||(ch==0xA0)||(ch>=0xFD) ){
		/* ASCII or something else */
		if(max <= r) goto max_end;

		*out = ch; (*i)++; (*ret)++;

	}else if( (0xA1<=ch)&&(ch<=0xDF) ){
		/* JIS8 Katakana characters */
		if(max <=(r+1)) goto max_end;

		out[0] = (unsigned char)0x8E;
		out[1] = ch;
		(*i)++; (*ret)+=2;

	}else{
		/* S-JIS Kanji characters */
		if(max<=(r+1)) goto max_end;

		if(sjis2jis_c(in,buf)){
			*ret=-1; return -1;
		}
		out[0] = 0x80|buf[0];
		out[1] = 0x80|buf[1];
		(*i)+=2; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	Shift-JIS to UNICODE1.1
-----------------------------------------*/
int sjis2uni_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch,buf[16];
	int r = *ret;

	ch = *in;
	if( (ch<=0x80)||(ch==0xA0)||(ch>=0xFD) ){
		/* ASCII or something else */
		if(max <= (r+1)) goto max_end;

		out[0] = 0;
		out[1] = ch;
		(*i)++; (*ret)+=2;

	}else if( (0xA1<=ch)&&(ch<=0xDF) ){
		/* JIS8 Katakana characters */
		if(max <=(r+1)) goto max_end;

		out[0] = (unsigned char)0xFF;
		out[1] = ch-0x40;
		(*i)++; (*ret)+=2;

	}else{
		/* S-JIS Kanji characters */
		if(max<=(r+1)) goto max_end;

		if(sjis2jis_c(in,buf)){
			*ret=-1; return -1;
		}
		if(jis2uni_c(buf,out)){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	Shift-JIS to UTF8
-----------------------------------------*/
int sjis2utf_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch,buf[16],buf2[16];
	int j,r = *ret;

	ch = *in;
	if( (ch<=0x80)||(ch==0xA0)||(ch>=0xFD) ){
		if( ch&0x80 ){
			/* something else */
			if(max <= (r+1)) goto max_end;

			out[0] = 0xc0 |(ch>>6);
			ch    &= 0x3f;
			out[1] = 0x80 | ch;
			(*i)++; (*ret)+=2;
		}else{
			/* ASCII data -- just copy it */
			if(max <= r) goto max_end;

			*out = ch;
			(*i)++; (*ret)++;
		}
	}else if( (0xA1<=ch)&&(ch<=0xDF) ){
		/* JIS8 Katakana characters */
		if(max <=(r+1)) goto max_end;

		buf[0] = 0xFF;
		buf[1] = ch-0x40;
		if((j=ucs22utf_c(buf,out))<0){
			*ret=-1; return -1;
		}
		(*i)++; (*ret)+=j;

	}else{
		/* S-JIS Kanji characters */
		if(max<=(r+2)) goto max_end;

		if(sjis2jis_c(in,buf)){
			*ret=-1; return -1;
		}
		if(jis2uni_c(buf,buf2)){
			*ret=-1; return -1;
		}
		if((j=ucs22utf_c(buf2,out))<0){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=j;
	}
	return 0;
max_end:
	return 1;
}

