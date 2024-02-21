/* uc_jis.c */
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
	JIS to Any Kanji code
-----------------------------------------*/
int UC_jis2any(char *in, int ilen, char *out, int max,int (*transf)()){
	int i,ret,mode=UC_M_JIS_ASCII;
	char ch;

	/* mode : 0..ASCII, 1..JIS X 208, 2..JIS X 201 (KATAKANA) */
	if((in==NULL)||(out==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_UCONV,ERR_PT_UC_JIS,NULL);
		return -1;
	}

	i=ret=0;
	/* do conversion */
	while(i < ilen){
		/* check mode change -- ignore normal chars */
		switch(in[i]){
		case UC_ESC: /* get escape sequence !! */
			ch = in[i+1];
			switch(ch){
			case '$':
				ch = in[i+2];
				if((ch=='B')||(ch=='@')){
					mode = UC_M_JIS_JISX208; i+=3;
				}
				break;
			case '(':
				ch = in[i+2];
				if((ch=='B')||(ch=='J')||(ch=='H')){
					mode = UC_M_JIS_ASCII; i+=3;
				}else if(ch=='I'){
					mode = UC_M_JIS_KATAKANA; i+=3;
				}
				break;
			case 'K': /* NEC escape sequence -- to jis-x-208 */
				mode = UC_M_JIS_JISX208; i+=2; break;
			case 'H': /* NEC escape sequence -- to ascii */
				mode = UC_M_JIS_ASCII; i+=2; break;
			}
			break;
		case UC_SO:
			mode = UC_M_JIS_KATAKANA; i++; break;
		case UC_SI:
			mode = UC_M_JIS_ASCII; i++; break;
		}

		if(transf(&in[i],&out[ret],max,mode,&i,&ret)) goto done;
	}
done:
	return ret;
}

/*-----------------------------------------
	JIS to Shift-JIS
-----------------------------------------*/
int jis2sjis_in(char *in,char *out,int max,int mode,int *i,int *ret){
	int r = *ret;

	switch(mode){
	case UC_M_JIS_ASCII:
		/* just copy a char */
		if(max <= r) goto max_end;

		*out = *in;
		(*i)++; (*ret)++;
		break;
	case UC_M_JIS_JISX208:  /* JIS to S-JIS kanji */
		if(max <=(r+1)) goto max_end;

		if(jis2sjis_c(in,out)){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=2;
		break;
	case UC_M_JIS_KATAKANA: /* JIS7katakana to JIS8katakana */
		if(max <= r) goto max_end;

		*out = 0x80|*in;
		(*i)++; (*ret)++;
		break;
	}
	return 0;
max_end:
	return 1;
}

int jis2sjis_c(char *in,unsigned char *out){
	unsigned char c1=in[0],c2=in[1];

	if(c1 & 0x1){
		c1 = (c1>>1) + 0x71;
		c2+= 0x1f;
		if(c2>=0x7f) c2++;
	}else{
		c1 = (c1>>1) + 0x70;
		c2+= 0x7e;
	}

    if(c1 > 0x9f) c1+=0x40;

	out[0]=c1; out[1]=c2;
	return 0;
}

/*-----------------------------------------
	JIS to EUC
-----------------------------------------*/
int jis2euc_in(char *in,char *out,int max,int mode,int *i,int *ret){
	int r = *ret;

	switch(mode){
	case UC_M_JIS_ASCII:
		/* just copy a char */
		if(max <= r) goto max_end;

		*out = *in;
		(*i)++; (*ret)++;
		break;
	case UC_M_JIS_JISX208:  /* JIS to EUC kanji */
		if(max <=(r+1)) goto max_end;

		out[0] = 0x80|*in;
		out[1] = 0x80|in[1];
		(*i)+=2; (*ret)+=2;
		break;
	case UC_M_JIS_KATAKANA: /* JIS7katakana to JIS8katakana */
		if(max <=(r+1)) goto max_end;

		out[0] = (unsigned char)0x8E;
		out[1] = 0x80|*in;
		(*i)++; (*ret)+=2;
		break;
	}
	return 0;
max_end:
	return 1;
}

/*-----------------------------------------
	JIS to UNICODE1.1
-----------------------------------------*/
int jis2uni_in(char *in,char *out,int max,int mode,int *i,int *ret){
	int r = *ret;

	switch(mode){
	case UC_M_JIS_ASCII:
		/* just copy a char */
		if(max <= (r+1)) goto max_end;

		out[0] = 0;
		out[1] = *in;
		(*i)++; (*ret)+=2;
		break;
	case UC_M_JIS_JISX208:  /* JIS to UNICODE1.1 kanji */
		if(max <=(r+1)) goto max_end;

		if(jis2uni_c(in,out)){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=2;
		break;
	case UC_M_JIS_KATAKANA: /* JIS7katakana to UNICODE katakana */
		if(max <=(r+1)) goto max_end;

		out[0] = (unsigned char)0xFF;
		out[1] = *in+0x40;
		(*i)++; (*ret)+=2;
		break;
	}
	return 0;
max_end:
	return 1;
}

int jis2uni_c(char *in,unsigned char *out){
	unsigned short ret;
	int k;

	if((in[0]&0x80)||(in[1]&0x80)) goto error;

	if((k=(in[0]-0x21)*96 + (in[1]-0x21))<0) goto error;

	if(k >=UC_JIS2UNI_MAX){
		/* buffer overflow, put "dot" moji here. */
		out[0] = 0x30; out[1] = 0xfb;
	}

	if((ret = jis2uni[k])>0){
		/* table conversion succeeded */
		out[0]=(unsigned char)(ret>>8);
		out[1]=(unsigned char) ret;
	}else{
		/* oops, there isn't a appropriate code in table
		 * in this case, just put "dot" moji here.
         */
		out[0] = 0x30; out[1] = 0xfb;
	}
	return 0;
error:
	OK_set_error(ERR_ST_UC_BADJISCODE,ERR_LC_UCONV,ERR_PT_UC_JIS+4,NULL);
	return -1;
}

/*-----------------------------------------
	JIS to UTF8
-----------------------------------------*/
int jis2utf_in(char *in,char *out,int max,int mode,int *i,int *ret){
	unsigned char buf[16];
	int j,r = *ret;

	switch(mode){
	case UC_M_JIS_ASCII:
		/* just copy a char */
		if(max <= r) goto max_end;

		if(*in&0x80){ /* invalid code ! */
			OK_set_error(ERR_ST_UC_BADJISCODE,ERR_LC_UCONV,ERR_PT_UC_JIS+5,NULL);
			*ret=-1; return -1;
		}

		*out = *in;
		(*i)++; (*ret)++;
		break;
	case UC_M_JIS_JISX208:  /* JIS to UTF8 kanji */
		if(max <=(r+2)) goto max_end;

		if(jis2uni_c(in,buf)){
			*ret=-1; return -1;
		}
		if((j=ucs22utf_c(buf,out))<0){
			*ret=-1; return -1;
		}
		(*i)+=2; (*ret)+=j;
		break;
	case UC_M_JIS_KATAKANA: /* JIS7katakana to UTF8 katakana */
		if(max <=(r+2)) goto max_end;

		buf[0] = 0xFF;
		buf[1] = *in+0x40;
		if((j=ucs22utf_c(buf,out))<0){
			*ret=-1; return -1;
		}
		(*i)++; (*ret)+=j;
		break;
	}
	return 0;
max_end:
	return 1;
}



/*-------------------------------------*/
#if 0
int jis2sjis_in(UC_CTX *c){
	switch(c->mode){
	case UC_M_JIS_ASCII:
		/* just copy a char */
		if(c->max <= c->ret) goto done;

		c->out[c->ret]=c->in[c->i];
		(c->i)++; (c->ret)++;
		break;
	case UC_M_JIS_JISX208:  /* JIS to S-JIS kanji */
		if(c->max <=(c->ret+1)) goto done;

		if(jis2sjis_c(&c->in[c->i],&c->out[c->ret])){
			c->ret=-1; return -1;
		}
		(c->i)+=2; (c->ret)+=2;
		break;
	case UC_M_JIS_KATAKANA: /* JIS7katakana to JIS8katakana */
		if(c->max <=(c->ret)) goto done;

		c->out[c->ret]=0x80|c->in[c->i];
		(c->i)++; (c->ret)++;
		break;
	}
done:
	return 0;
}
#endif
