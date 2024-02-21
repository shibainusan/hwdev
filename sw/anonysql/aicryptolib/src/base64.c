/* base64.c */
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

#include "ok_err.h"
#include "ok_base64.h"

static unsigned char enT[]={
    'A','B','C','D','E','F','G','H',
    'I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X',
    'Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3',
    '4','5','6','7','8','9','+','/'};


static unsigned char deT[]={
    62, 00, 00, 00, 63, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 00, 00, 00,000, 00,
     0, 00,  0,  1,  2,  3,  4,  5,  6,  7,
    8 ,  9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 00, 00,
    00, 00, 00, 00, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
    42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};


/*-----------------------------------------------
  base64 encode len = in's size
  set '\n' every (block*4) byte
-----------------------------------------------*/
char *Base64_encode(int len,unsigned char *in,int block){
	unsigned char *ret,*top;
	int m,i,j;

	if((block<0)||(block>128)) block=16;

	m   = len/3;
	i	= m/block;
	if((ret=(unsigned char*)MALLOC((m<<2)+i+8))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_BASE64,NULL);
		return NULL;
	}
	top = ret;

	i=0;j=0;
	while(i<m){
		ret[0]=enT[(in[0]>>2)&0x3f];
		ret[1]=enT[(0x30&(in[0]<<4))|(0x0f&(in[1]>>4))];
		ret[2]=enT[(0x3c&(in[1]<<2))|(0x03&(in[2]>>6))];
		ret[3]=enT[0x3f&in[2]];
		i++;
		j++;
		in+=3;
		ret+=4;
		if(j==block){ j=0; *ret='\n'; ret++; }
	}

	m=len%3;
	if(m==1){
		ret[0]=enT[(in[0]>>2)&0x3f];
		ret[1]=enT[(0x30&(in[0]<<4))];
		ret[2]=ret[3]= '=';
	}else if(m==2){
		ret[0]=enT[(in[0]>>2)&0x3f];
		ret[1]=enT[(0x30&(in[0]<<4))|(0x0f&(in[1]>>4))];
		ret[2]=enT[(0x3c&(in[1]<<2))];
		ret[3]= '=';
	}else{
		if(j==0) ret--;
		ret[0]=0;
	}

	ret[4]=0;
	return(top);
}


/*-----------------------------------------------
  base64 input code normalize(step '\n',' ')
-----------------------------------------------*/
char *base64_normalize(char *in){
	char *ret,*cp;
	int size,i;

	size = strlen(in);
	if((ret=(char*)MALLOC(size+4))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_BASE64+1,NULL);
		return NULL;
	}
	cp = ret;

	for(i=0;i<size;i++){
		if((0x2b<=in[i])&&(in[i]<=0x7a)){
			*cp = in[i];
			cp++;}
	}
	*cp=0;
	return(ret);
}

/*-----------------------------------------------
  base64 decode ret size is *size
-----------------------------------------------*/
unsigned char *Base64_decode(char *in,int *ret_size){
	unsigned char *ret,*cp;
	char *buf,*tbuf=NULL;
	ULONG l;
	int i,sz;


	if((tbuf=base64_normalize(in))==NULL) return NULL;
	buf=tbuf;
	sz =strlen(buf);

	i = (sz>>2)*3;
	if((ret=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PEM,ERR_PT_BASE64+2,NULL);
		goto done;
	}
	cp = ret;

	*ret_size = 0;
	i=0;
	do{
		l =0;
		l |=((ULONG)deT[buf[0]-'+'])<<18;
		l |=((ULONG)deT[buf[1]-'+'])<<12;
		l |=((ULONG)deT[buf[2]-'+'])<<6;
		l |=((ULONG)deT[buf[3]-'+']);

		cp[0] = (unsigned char)(l>>16);
		if(buf[2]=='=')
			*ret_size +=1;
		else{
			cp[1] = (unsigned char)(l>>8);
			if(buf[3]=='=')
				*ret_size +=2;
			else{
				cp[2] = (unsigned char) l;
				*ret_size +=3;
			}
		}
		i+=4;
		cp+=3;
		buf+=4;
	}while(i<sz);

done:
	if(tbuf) FREE(tbuf);
	return ret;
}
