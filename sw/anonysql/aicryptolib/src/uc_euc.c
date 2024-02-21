/* uc_euc.c */
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
	EUC to JIS
-----------------------------------------*/
int euc2jis_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch;
	int r = *ret;

	ch = *in;
	if( ch & 0x80 ){
		if( (0xA1<=ch)&&(ch<=0xFE) ){
			/* EUC Kanji */
			if(*mode != UC_M_JIS_JISX208){
				/* shift to JIS X 208 mode */
				if(max<=(r+2)) goto max_end;

				out[0]=UC_ESC; out[1]='$'; out[2]='B';
				*mode = UC_M_JIS_JISX208;
				r+=3; (*ret)+=3; out+=3;
			}

			if(max<=(r+1)) goto max_end;

			out[0] = 0x7f & ch;
			out[1] = 0x7f & in[1];
			(*i)+=2; (*ret)+=2;

		}else if( ch == 0x8E ){
			/* JIS8 Katakana characters */
			if(*mode != UC_M_JIS_KATAKANA){
				/* shift to JIS7 katakana mode */
				if(max<=(r+2)) goto max_end;

				out[0]=UC_ESC; out[1]='('; out[2]='I';
				*mode = UC_M_JIS_KATAKANA;
				r+=3; (*ret)+=3; out+=3;
			}

			if(max <= r) goto max_end;

			*out = 0x7f & in[1];
			(*i)+=2; (*ret)++;
		}else{
			/* hojo kanji or something else...
			 * unsupported data.
			 */
			OK_set_error(ERR_ST_UNSUPPORTED_CODE,ERR_LC_UCONV,ERR_PT_UC_EUC,NULL);
			*ret = -1;
			return -1;
		}
	}else{
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
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	EUC to S-JIS
-----------------------------------------*/
int euc2sjis_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch,buf[16];
	int r = *ret;

	ch = *in;
	if( ch & 0x80 ){
		if( (0xA1<=ch)&&(ch<=0xFE) ){
			/* EUC Kanji */
			if(max<=(r+1)) goto max_end;

			buf[0] = 0x7f & ch;
			buf[1] = 0x7f & in[1];
			if(jis2sjis_c(buf,out)){
				*ret=-1; return -1;
			}
			(*i)+=2; (*ret)+=2;

		}else if( ch == 0x8E ){
			/* JIS8 Katakana characters */
			if(max <= r) goto max_end;

			*out = in[1];
			(*i)+=2; (*ret)++;
		}else{
			/* hojo kanji or something else...
			 * unsupported data.
			 */
			OK_set_error(ERR_ST_UNSUPPORTED_CODE,ERR_LC_UCONV,ERR_PT_UC_EUC+1,NULL);
			*ret = -1;
			return -1;
		}
	}else{
		/* ASCII or something else */
		if(max <= r) goto max_end;

		out[0]=ch; (*i)++; (*ret)++;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	EUC to UNICODE1.1
-----------------------------------------*/
int euc2uni_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch,buf[16];
	int r = *ret;

	ch = *in;
	if( ch & 0x80 ){
		if( (0xA1<=ch)&&(ch<=0xFE) ){
			/* EUC Kanji */
			if(max<=(r+1)) goto max_end;

			buf[0] = 0x7f & ch;
			buf[1] = 0x7f & in[1];
			if(jis2uni_c(buf,out)){
				*ret=-1; return -1;
			}
			(*i)+=2; (*ret)+=2;

		}else if( ch == 0x8E ){
			/* JIS8 Katakana characters */
			if(max <=(r+1)) goto max_end;

			out[0] = (unsigned char)0xFF;
			out[1] = in[1]-0x40;
			(*i)+=2; (*ret)+=2;

		}else{
			/* hojo kanji or something else...
			 * unsupported data.
			 */
			OK_set_error(ERR_ST_UNSUPPORTED_CODE,ERR_LC_UCONV,ERR_PT_UC_EUC+2,NULL);
			*ret = -1;
			return -1;
		}
	}else{
		/* ASCII or something else */
		if(max <= (r+1)) goto max_end;

		out[0] = 0;
		out[1] = ch;
		(*i)++; (*ret)+=2;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	EUC to UTF8
-----------------------------------------*/
int euc2utf_in(char *in,char *out,int max,int *mode,int *i,int *ret){
	unsigned char ch,buf[16],buf2[16];
	int j,r = *ret;

	ch = *in;
	if( ch & 0x80 ){
		if( (0xA1<=ch)&&(ch<=0xFE) ){
			/* EUC Kanji */
			if(max<=(r+2)) goto max_end;

			buf[0] = 0x7f & ch;
			buf[1] = 0x7f & in[1];
			if(jis2uni_c(buf,buf2)){
				*ret=-1; return -1;
			}
			if((j=ucs22utf_c(buf2,out))<0){
				*ret=-1; return -1;
			}
			(*i)+=2; (*ret)+=j;

		}else if( ch == 0x8E ){
			/* JIS8 Katakana characters */
			if(max <=(r+2)) goto max_end;

			buf[0] = 0xFF;
			buf[1] = in[1]-0x40;
			if((j=ucs22utf_c(buf,out))<0){
				*ret=-1; return -1;
			}
			(*i)+=2; (*ret)+=j;

		}else{
			/* hojo kanji or something else...
			 * unsupported data.
			 */
			OK_set_error(ERR_ST_UNSUPPORTED_CODE,ERR_LC_UCONV,ERR_PT_UC_EUC+3,NULL);
			*ret = -1;
			return -1;
		}
	}else{
		/* ASCII or something else */
		if(max <= r) goto max_end;

		*out = ch;
		(*i)++; (*ret)++;
	}
	return 0;
max_end:
	return 1;
}

