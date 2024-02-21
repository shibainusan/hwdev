/* asn1.c */
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

#include "ok_asn1.h"


/*-----------------------------------------------
   return ASN.1 length (long)
   (*in is ASN.1 length top pointer)
   (this function use last 4 octet,if length>4)
-----------------------------------------------*/
int ASN1_length(unsigned char *in,int *mv){
	int ret,len,i;

	ret=0;
	*mv=1;
	if(0x80 & *in){
		len = 0x7f & *in;
		for(i=0,++in;i<len;i++,(*mv)++){
			ret <<= 8;
			ret  |= (unsigned char)in[i];
		}
		return(ret);
	}else{
		ret = 0x7f & *in;
		return(ret);
	}
}


/*-----------------------------------------------
   return ASN.1 BOOLEAN
-----------------------------------------------*/
int ASN1_boolean(unsigned char *in,int *mv){
	int len,ptm,ret=0;

	*mv = 1;
	if(*in != ASN1_BOOLEAN){
		OK_set_error(ERR_ST_ASN_NOTBOOLEAN,ERR_LC_ASN1,ERR_PT_ASN1,NULL);
		*mv=0; return -1;
	}

	len = ASN1_length((++in),&ptm);
	in += ptm;
	*mv += (ptm+len);

	return (*in)?(1):(0);
}

/*-----------------------------------------------
   return ASN.1 INTEGER (long)
-----------------------------------------------*/
int ASN1_integer_(unsigned char *in,int *mv,int no_check_tag){
	int len,i,ptm,ret=0;

	*mv = 1;
	if((!no_check_tag)&&(*in != ASN1_INTEGER)){
		OK_set_error(ERR_ST_ASN_NOTINTEGER,ERR_LC_ASN1,ERR_PT_ASN1,NULL);
		*mv=0; return -1;
	}

	len = ASN1_length((++in),&ptm);
	in += ptm;
	*mv += (ptm+len);

	for(i=0;i<len;i++){
		ret <<= 8;
		ret  |= in[i];
	}
	return(ret);
}

int ASN1_enumerated(unsigned char *in,int *mv){
	int ret;
	if(*in != ASN1_ENUMERATED){
		OK_set_error(ERR_ST_ASN_NOTENUMERATED,ERR_LC_ASN1,ERR_PT_ASN1+1,NULL);
		*mv=0; return -1;
	}

	*in = ASN1_INTEGER;
	ret = ASN1_integer(in,mv);
	*in = ASN1_ENUMERATED;
	return ret;
}

/*-----------------------------------------------
   return ASN.1 BIT STRING (*char)
-----------------------------------------------*/
int ASN1_bitstring_(unsigned char *in,int *mv,unsigned char **ret,int *ret_size,int *no_use_bit,int no_check_tag){
	int ptm,len=0;
	unsigned char *top;

	*mv = 1;
	if((!no_check_tag)&&(*in != ASN1_BITSTRING)){
		OK_set_error(ERR_ST_ASN_NOTBITSTR,ERR_LC_ASN1,ERR_PT_ASN1+2,NULL);
		return -1;}

	len = ASN1_length((++in),&ptm);
	in += ptm;
	*mv += (ptm+len);

	*ret_size = len-1;
	if((*ret=(unsigned char*)MALLOC(*ret_size+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1+2,NULL);
		return -1;
	}
	memset(*ret,0,*ret_size+2);

	top = *ret;
	memcpy(top,&in[1],*ret_size);
	top[len-2] &= 0xff << in[0];

	if(no_use_bit) *no_use_bit = in[0];
	return 0;
}

/*-----------------------------------------------
   return ASN.1 OCTET STRING (*char)
-----------------------------------------------*/
void ASN1_indef_count(unsigned char *in,int *mv,int *size){
	int len,ptm,dmy,st=0xffffff;

	if(*mv) st=*mv;
	for(*mv=*size=0;(*in)&&(*mv<st);in+=len+ptm+1){
		len = ASN1_length(&in[1],&ptm);
		if(len==0) ASN1_indef_count(&in[2],(int*)&len,&dmy);
		*size += len;
		*mv += len+ptm+1;
	}
	if(st!=0xffffff) *mv=st;
	else    *mv+=2; /* end [00 00] */
}

int ASN1_octetstring_(unsigned char *in,int *mv,unsigned char **ret,int *ret_size,int no_check_tag){
	int len=0,ptm,tmp=0;
	unsigned char *top;

	*mv = 1;
	if((!no_check_tag)&&((*in&0x1f)!=ASN1_OCTETSTRING)){
		OK_set_error(ERR_ST_ASN_NOTOCTETSTR,ERR_LC_ASN1,ERR_PT_ASN1+3,NULL);
		return -1;}

	if(*in & ASN1_T_STRUCTURED){ /* cont,appl,priv[] */
		/* !!sometimes length=Indefinite!! */
		tmp = ASN1_length((++in),&ptm);
		in += ptm;
		ASN1_indef_count(in,&tmp,(int*)&len);
		*mv += (ptm+tmp);


	}else{ /* normal */
		len = ASN1_length((++in),&ptm);
		in += ptm;
		*mv += (ptm+len);
	}

	if((top=(unsigned char*)MALLOC(len+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1+3,NULL);
		return -1;
	}
	memset(top,0,len+2);
	if(tmp){
		int cnt=0,tmv,t;
		unsigned char *ttop;

		for(;(*in)&&(cnt<len);in+=tmv,cnt+=t){
			if(ASN1_octetstring(in,&tmv,&ttop,&t))
				return -1;
			memcpy(&top[cnt],ttop,t);
			FREE(ttop);
		}
	}else
		memcpy(top,in,len);

	*ret_size = len;
	*ret = top;
	return 0;
}

/*-----------------------------------------------
   return ASN.1 OBJECT IDENTIFIER (*char)
-----------------------------------------------*/
int ASN1_object_id_(unsigned char *in,int *mv,unsigned char **ret,int *ret_size,int no_check_tag){
	int len=0,ptm;

	*mv = 1;
	if((!no_check_tag)&&(*in != ASN1_OBJECT_IDENTIFIER)){
		OK_set_error(ERR_ST_ASN_NOTOID,ERR_LC_ASN1,ERR_PT_ASN1+4,NULL);
		return -1;
	}

	len = ASN1_length((++in),&ptm);
	in += ptm;
	*mv+= (ptm+len);

/*  printf("%d=%d+%d\n",*mv,ptm,len); */
	if((*ret=(unsigned char*)MALLOC(len+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1+4,NULL);
		return -1;
	}
	*ret_size = len;
	memcpy(*ret,in,len);
	return 0;
}

/*-----------------------------------------------
   return ASN.1 PRINTABLE STRING (*char)
-----------------------------------------------*/
char *ret_string(char *in,int *mv){
	int ptm,len=0;
	unsigned char *ret;

	*mv = 1;
	len = ASN1_length((++in),&ptm);
	in += ptm;
	*mv += (ptm+len);

	if((ret=(unsigned char*)MALLOC(len+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_ASN1,ERR_PT_ASN1+5,NULL);
		return NULL;
	}
	memcpy(ret,in,len);
	ret[len]=ret[len+1]=0x00;
	return(ret);
}

char *ASN1_printable(char *in,int *mv){
	if(*in != ASN1_PRINTABLE_STRING){
		OK_set_error(ERR_ST_ASN_NOTPRINTABLESTR,ERR_LC_ASN1,ERR_PT_ASN1+6,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return ASN.1 UTF8 STRING (*char)
-----------------------------------------------*/
char *ASN1_utf8(char *in,int *mv){
	char *ret;

	if(*in != ASN1_UTF8STRING){
		OK_set_error(ERR_ST_ASN_NOTUTF8STR,ERR_LC_ASN1,ERR_PT_ASN1+7,NULL);
		return NULL;
	}
	if((ret = ret_string(in,mv))==NULL) return NULL;

	/* convert character to local code */


	return ret;
}

/*-----------------------------------------------
   return ASN.1 T61(8bit) STRING (*char)
-----------------------------------------------*/
char *ASN1_t61(char *in,int *mv){
	if(*in != ASN1_T61STRING){
		OK_set_error(ERR_ST_ASN_NOTT61STR,ERR_LC_ASN1,ERR_PT_ASN1+8,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return ASN.1 IA5 (ascii) STRING (*char)
-----------------------------------------------*/
char *ASN1_ia5(char *in,int *mv){
	if(*in != ASN1_IA5STRING){
		OK_set_error(ERR_ST_ASN_NOTIA5STR,ERR_LC_ASN1,ERR_PT_ASN1+9,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return ASN.1 Visible (ascii) STRING (*char)
-----------------------------------------------*/
char *ASN1_iso64(char *in,int *mv){
	if(*in != ASN1_ISO64_STRING){
		OK_set_error(ERR_ST_ASN_NOTISO64STR,ERR_LC_ASN1,ERR_PT_ASN1+10,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return ASN.1 BMP STRING (*char)
-----------------------------------------------*/
char *ASN1_bmp(char *in,int *mv){
	if(*in != ASN1_BMPSTRING){
		OK_set_error(ERR_ST_ASN_NOTBMPSTR,ERR_LC_ASN1,ERR_PT_ASN1+11,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return ASN.1 UTCTIME
-----------------------------------------------*/
char *ASN1_utctime(char *in,int *mv){
	if(*in != ASN1_UTCTIME){
		OK_set_error(ERR_ST_ASN_NOTUTCTIME,ERR_LC_ASN1,ERR_PT_ASN1+12,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return ASN.1 UTCTIME
-----------------------------------------------*/
char *ASN1_gtime(char *in,int *mv){
	if(*in != ASN1_GENERALIZEDTIME){
		OK_set_error(ERR_ST_ASN_NOTGENTIME,ERR_LC_ASN1,ERR_PT_ASN1+13,NULL);
		return NULL;
	}
	return ret_string(in,mv);
}

/*-----------------------------------------------
   return next TAG pointer
-----------------------------------------------*/
unsigned char *ASN1_next_(unsigned char *in,int *mv){
	unsigned char *top;
	int len,ptm;

	top = in;
	len = ASN1_length((++in),&ptm);
	in += ptm;


	if(0x20 & *top){
		if(mv) *mv = ptm+1;
		return(in);
	}else{
		if(mv) *mv = len+ptm+1;
		return((in+=len));
	}
}

/*-----------------------------------------------
   return TAG pointer of step n.
-----------------------------------------------*/
unsigned char *ASN1_step_(unsigned char *in,int n,int *mv){
	unsigned char *cp;
	int i,j,k;

	cp=in;
	for(i=j=0;i<n;i++){
		cp = ASN1_next_(cp,&k);
		j += k;
	}
	if(mv) *mv = j;
	return(cp);
}

/*-----------------------------------------------
   return TAG pointer : skip depth.
-----------------------------------------------*/
int asn1_check_tag(unsigned char uc){
	int i;

	i = uc & 0x1f;

	switch(uc&0xc0){
	case 0x80:
		/* content-specific : implicit or explicit */
		/*
		 * Tagging number should not be so big ...
		 * In RFC2510 (CMP), there is 23 numbers for explicit tagging,
		 * and it was the biggest number I've ever seen ...
		 */
		if(i>23) goto error; /* bad tagging number */
		break;
	case 0x0:  /* universal */
		if(uc&0x20){
			/* constructed type */
			/* this constructed flag is usually used with SEQUENCE,
			 * SEQUENCE OF, SET, SET OF, and explicit tagging.
			 * But netscape pkcs12 file uses this flag with OCTETSTRING.
			 * it is kind of rare case.
			 */
			if((i!=0x10)&&(i!=0x11)&&(i!=0x04)) goto error;
		}
		break;
	case 0x40: /* application */
	case 0xc0: /* private */
		OK_set_error(ERR_ST_UNSUPPORTED_PARAM,ERR_LC_ASN1,ERR_PT_ASN1+14,NULL);
		return -1;
	}

	return 0;
error:
	OK_set_error(ERR_ST_ASN_NOTASN1,ERR_LC_ASN1,ERR_PT_ASN1+14,NULL);
	return -1;
}


unsigned char *ASN1_skip_(unsigned char *in, int *mv){
	int len,ptm,dep,tl,i;

	if(asn1_check_tag(*in)) return NULL;
	len = ASN1_length((++in),&ptm);
	tl  = *in;
	in += ptm+len;
	if(mv) *mv = len+ptm+1;

	if(tl==0x80){
		dep=i=0;
		while(*in||dep){
			if(*in==0){
				/* END [00 00] tag */
				in+=2; dep--; i+=2;
			}else{
				/* other tags */
				if(asn1_check_tag(*in)) return NULL;
				len = ASN1_length((++in),&ptm);

				if(*in==0x80) dep++;
				in += ptm+len;
				i  += ptm+len+1;
			}
		}
		in +=2; i+=2;
		if(mv) *mv+= i;
    }
    return(in);
}

/*-----------------------------------------------
   return TAG's length.
-----------------------------------------------*/
int ASN1_tlen(unsigned char *in){
	int ptm;
	return ASN1_length((++in),&ptm);
}

/*-----------------------------------------------
   find and return TAG pointer
   !caution! if cannot find TAG,loop forever!
-----------------------------------------------*/
unsigned char *ASN1_find_tag(unsigned char *asn1,char tag){
	unsigned char *ret;

	if((0x1f&*asn1) == tag)
		if(!(0x80&*asn1))
			return asn1;

	for(ret=asn1;;){
		ret = ASN1_next(ret);
		if((0x1f&*ret) == tag)
			if(!(0x80&*ret))
				return ret;
	}
	return NULL;
}
