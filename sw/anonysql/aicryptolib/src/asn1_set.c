/* asn1_set.c */
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
#include <string.h>

#include "ok_asn1.h"

/*-----------------------------------------
  set ASN1_length
-----------------------------------------*/
void ASN1_set_length(int len,unsigned char *ret,int *ret_len){
	if(len < 0){
		*ret = 0x80;
		*ret_len = 1;
	}else if(len<=0x7f){
		*ret = (unsigned char)len;
		*ret_len = 1;
	}else if(len<=0xff){
		ret[0] = 0x81;
		ret[1] = (unsigned char)len;
		*ret_len = 2;
	}else if(len<=0xffff){
		ret[0] = 0x82;
		ret[1] = (unsigned char)(len>>8);
		ret[2] = (unsigned char) len;
		*ret_len = 3;
	}else if(len<=0xffffff){
		ret[0] = 0x83;
		ret[1] = (unsigned char)(len>>16);
	    ret[2] = (unsigned char)(len>>8);
	    ret[3] = (unsigned char) len;
		*ret_len = 4;
	}
}

/*-----------------------------------------
  used by SEQUENCE & SET
-----------------------------------------*/
static void set_depth(int len,unsigned char *der,int *ret_len){
	unsigned char	buf[32],*cp;
	int i,j;

	ASN1_set_length(len,&buf[1],&i);
	cp = &(der[len+i]);

	for(j=len-1;j>=0;j--){
		*cp = der[j]; cp--;
	}
	memcpy(der,buf,i+1);
	*ret_len = len+i+1;
}

/*-----------------------------------------
  set ASN1_sequence
-----------------------------------------*/
void ASN1_set_sequence(int len,unsigned char *der,int *ret_len){
	set_depth(len,der,ret_len);
	*der = ASN1_SEQUENCE|0x20;
}

/*-----------------------------------------
  set ASN1_set
-----------------------------------------*/
void ASN1_set_set(int len,unsigned char *der,int *ret_len){
	set_depth(len,der,ret_len);
	*der = ASN1_SET|0x20;
}

/*-----------------------------------------
  set ASN1 explicit
-----------------------------------------*/
void ASN1_set_explicit(int len,char num,unsigned char *der,int *ret_len){
	set_depth(len,der,ret_len);
	*der = 0xa0|num;
}


/*-----------------------------------------
  set ASN1 boolean
-----------------------------------------*/
void ASN1_set_boolean(int flag,unsigned char *der, int *ret_len){
	der[0] = ASN1_BOOLEAN;
	der[1] = 1;
	der[2] = (flag)?(0xff):(0);
	*ret_len = 3;
}

/*-----------------------------------------
  set ASN1 integer
-----------------------------------------*/
void ASN1_set_integer(int num,unsigned char *der,int *ret_len){
	int	i=2,j;

	*der = ASN1_INTEGER;
	if(num>0xffffff){ der[i]=(unsigned char)(num>>24); i++; }
	if(num>0xffff){ der[i]=(unsigned char)(num>>16); i++; }
	if(num>0xff){ der[i]=(unsigned char)(num>>8); i++; }
	der[i]=(unsigned char)num;

	if(der[2]&0x80){
		i++;
		for(j=i;j>2;j--) der[j]=der[j-1];
		der[2]=0;
	}
	der[1]=i-1;
	*ret_len = 1+i;
}

/*-----------------------------------------
  set ASN1 enumerated
-----------------------------------------*/
void ASN1_set_enumerated(int num,unsigned char *der,int *ret_len){
	ASN1_set_integer(num,der,ret_len);
	*der = ASN1_ENUMERATED;
}

/*-----------------------------------------
  set ASN1 bit string
-----------------------------------------*/
void asn1_check_derbit(int len, unsigned char *cp, int *nobit, int *ret_len){
	int k,l,msk;

	for(l=len-1; l>=0; l--)
		for(k=0,msk=0x01; k<8; k++,msk<<=1)
			if(cp[l]&msk) goto done;
	k=0;
done:
	*nobit=k; *ret_len=l+1;
}

void ASN1_set_bitstring(int nobit,int len,unsigned char *in,
			unsigned char *ret,int *ret_len){
	int	i;

	*ret = ASN1_BITSTRING;
	ASN1_set_length(len+1,&ret[1],&i);
	ret[1+i]=nobit;
	memcpy(&ret[2+i],in,len);
	*ret_len = 2+i+len;
}

/*-----------------------------------------
  set ASN1 octet string
-----------------------------------------*/
void ASN1_set_octetstring(int len,unsigned char *in,
			  unsigned char *ret,int *ret_len){
	int	i;
	*ret = ASN1_OCTETSTRING;
	ASN1_set_length(len,&ret[1],&i);
	memcpy(&ret[1+i],in,len);
	*ret_len = 1+i+len;
}

/*-----------------------------------------
  set ASN1 strings
-----------------------------------------*/
void asn1_set_str(int type,char *str,unsigned char *ret,int *ret_len){
	int	i,slen = strlen(str);

	*ret = (unsigned char)type;
	ret++;

	ASN1_set_length(slen,ret,&i);
	ret += i;
	memcpy(ret,str,slen);
	*ret_len = 1+i+slen;
}

/*-----------------------------------------
  set ASN1 strings
-----------------------------------------*/
/* be careful! this function doesn't return "real" string type.
 * this function is just used to determine appropriate string type
 * for DN. (used in EasyCert functions)
 */
int asn1_str_type(char *str){
	int i,ret,len = strlen(str);
	char c;

	ret = ASN1_PRINTABLE_STRING;
	for(i=0;i<len;i++){
		c = str[i];

		if(('0'<= c)&&(c <='9')) continue;
		if(('a'<= c)&&(c <='z')) continue;
		if(('A'<= c)&&(c <='Z')) continue;
		if( (c == '+')||(c == '-')||(c == '/')||(c == '=')||
			(c == ' ')||(c =='\'')||(c == '.')||(c == ',')||
			(c == '(')||(c == ')')||(c == ':')||(c == '?'))
			continue;

		/* ret = ASN1_IA5STRING; */
		ret = ASN1_TELETEXSTRING;
		if(c & 0x80) return ASN1_UTF8STRING;
	}
	return ret;
}

/*-----------------------------------------
  set ASN1_printable
-----------------------------------------*/
int ASN1_set_printable(char *str,unsigned char *ret,int *ret_len){
	if(asn1_str_type(str) != ASN1_PRINTABLE_STRING){
		OK_set_error(ERR_ST_ASN_NOTPRINTABLESTR,ERR_LC_ASN1,ERR_PT_ASN1SET+4,NULL);
		return -1;
	}
	asn1_set_str(ASN1_PRINTABLE_STRING,str,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  set ASN1_set_ia5 string
-----------------------------------------*/
int ASN1_set_ia5(char *str,unsigned char *ret,int *ret_len){
	if(asn1_str_type(str) == ASN1_UTF8STRING){ /* printable, ia5 is ok */
		OK_set_error(ERR_ST_ASN_NOTIA5STR,ERR_LC_ASN1,ERR_PT_ASN1SET+5,NULL);
		return -1;
	}
	asn1_set_str(ASN1_IA5STRING,str,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  set ASN1_set_t61 string
-----------------------------------------*/
int ASN1_set_t61(char *str,unsigned char *ret,int *ret_len){
	asn1_set_str(ASN1_T61STRING,str,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  set ASN1_utctime string;
-----------------------------------------*/
int ASN1_set_utc(char *str,unsigned char *ret,int *ret_len){
	int i,len = strlen(str);
	char c;

	for(i=0;i<len;i++){
		c = str[i];
		if(('0'<= c)&&(c <='9')) continue;
		if((c == '+')||(c == '-')||(c == '.')||(c == 'Z')) continue;

		OK_set_error(ERR_ST_ASN_NOTUTCTIME,ERR_LC_ASN1,ERR_PT_ASN1SET+6,NULL);
		return -1;
	}
	asn1_set_str(ASN1_UTCTIME,str,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  set ASN1_bmp string;
-----------------------------------------*/
int bmp_len(char *str){
	int	i;
	for(i=0;str[i]||str[i+1];i+=2);
	return i;
}

int bmp_strcmp(char *c1,char *c2){
	int i,j;
	do{
		i = c1[0]<<8|c1[1];
		j = c2[0]<<8|c2[1];

		if(i < j) return -1;
		if(i > j) return 1;
		c1+=2; c2+=2;
	}while(i || j);
	return 0;
}

int ASN1_set_bmp(char *str,unsigned char *ret,int *ret_len){
	int	i,len;
	*ret = ASN1_BMPSTRING;
	len = bmp_len(str);

	ASN1_set_length(len,&ret[1],&i);
	memcpy(&ret[1+i],str,len);
	*ret_len = 1+i+len;
	return 0;
}

/*-----------------------------------------
  set ASN1_utf8
-----------------------------------------*/
int ASN1_set_utf8(char *str,unsigned char *ret,int *ret_len){
	asn1_set_str(ASN1_UTF8STRING,str,ret,ret_len);
	return 0;
}

/*-----------------------------------------
  set ASN1_set_binary
-----------------------------------------*/
void ASN1_set_binary(int tag,int len,unsigned char *in,
			  unsigned char *ret,int *ret_len){
	int	i;
	*ret = (unsigned char)tag;
	ASN1_set_length(len,&ret[1],&i);
	memcpy(&ret[1+i],in,len);
	*ret_len = 1+i+len;
}

/*-----------------------------------------
  set ASN1_set_NULL
-----------------------------------------*/
void ASN1_set_null(unsigned char *der){
	der[0] = ASN1_NULL;
	der[1] = 0;
}

/*-----------------------------------------
  set ASN1_set_END
-----------------------------------------*/
void ASN1_set_end(unsigned char *der){
	der[0]=der[1] = 0;
}
