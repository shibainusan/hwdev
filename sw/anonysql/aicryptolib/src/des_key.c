/* des_key.c */
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

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_des.h"


void MakeKeys(ULLONG orgKeyL,ULLONG *keyL);
ULLONG BitChange(ULLONG block,char *change,int loop);

#ifdef __WINDOWS__
static ULLONG bits[]={	0x0,
    0x8000000000000000,0x4000000000000000,0x2000000000000000,0x1000000000000000,
    0x0800000000000000,0x0400000000000000,0x0200000000000000,0x0100000000000000,
    0x0080000000000000,0x0040000000000000,0x0020000000000000,0x0010000000000000,
    0x0008000000000000,0x0004000000000000,0x0002000000000000,0x0001000000000000,
    0x0000800000000000,0x0000400000000000,0x0000200000000000,0x0000100000000000,
    0x0000080000000000,0x0000040000000000,0x0000020000000000,0x0000010000000000,
    0x0000008000000000,0x0000004000000000,0x0000002000000000,0x0000001000000000,
    0x0000000800000000,0x0000000400000000,0x0000000200000000,0x0000000100000000,
    0x0000000080000000,0x0000000040000000,0x0000000020000000,0x0000000010000000,
    0x0000000008000000,0x0000000004000000,0x0000000002000000,0x0000000001000000,
    0x0000000000800000,0x0000000000400000,0x0000000000200000,0x0000000000100000,
    0x0000000000080000,0x0000000000040000,0x0000000000020000,0x0000000000010000,
    0x0000000000008000,0x0000000000004000,0x0000000000002000,0x0000000000001000,
    0x0000000000000800,0x0000000000000400,0x0000000000000200,0x0000000000000100,
    0x0000000000000080,0x0000000000000040,0x0000000000000020,0x0000000000000010,
    0x0000000000000008,0x0000000000000004,0x0000000000000002,0x0000000000000001,
};
#else
static ULLONG bits[]={	0x0LL,
    0x8000000000000000LL,0x4000000000000000LL,0x2000000000000000LL,0x1000000000000000LL,
    0x0800000000000000LL,0x0400000000000000LL,0x0200000000000000LL,0x0100000000000000LL,
    0x0080000000000000LL,0x0040000000000000LL,0x0020000000000000LL,0x0010000000000000LL,
    0x0008000000000000LL,0x0004000000000000LL,0x0002000000000000LL,0x0001000000000000LL,
    0x0000800000000000LL,0x0000400000000000LL,0x0000200000000000LL,0x0000100000000000LL,
    0x0000080000000000LL,0x0000040000000000LL,0x0000020000000000LL,0x0000010000000000LL,
    0x0000008000000000LL,0x0000004000000000LL,0x0000002000000000LL,0x0000001000000000LL,
    0x0000000800000000LL,0x0000000400000000LL,0x0000000200000000LL,0x0000000100000000LL,
    0x0000000080000000LL,0x0000000040000000LL,0x0000000020000000LL,0x0000000010000000LL,
    0x0000000008000000LL,0x0000000004000000LL,0x0000000002000000LL,0x0000000001000000LL,
    0x0000000000800000LL,0x0000000000400000LL,0x0000000000200000LL,0x0000000000100000LL,
    0x0000000000080000LL,0x0000000000040000LL,0x0000000000020000LL,0x0000000000010000LL,
    0x0000000000008000LL,0x0000000000004000LL,0x0000000000002000LL,0x0000000000001000LL,
    0x0000000000000800LL,0x0000000000000400LL,0x0000000000000200LL,0x0000000000000100LL,
    0x0000000000000080LL,0x0000000000000040LL,0x0000000000000020LL,0x0000000000000010LL,
    0x0000000000000008LL,0x0000000000000004LL,0x0000000000000002LL,0x0000000000000001LL,
};
#endif

static char PC1c[]={
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4};

static char PC2c[]={
    14,17,11,24,1,5,3,28,
    15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32};


/*---------------------------------
  DES key struct new.
---------------------------------*/
Key_DES *DESkey_new_(){
	Key_DES *ret;
	if((ret=(Key_DES*)MALLOC(sizeof(Key_DES)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DES,ERR_PT_DESKEY,NULL);
		return NULL;
	}
	ret->key_type = KEY_DES;
	return ret;
}

int DESkey_set(Key_DES *dk,int len,unsigned char *key){
	ULLONG orgkey;
	int	i,j;

	orgkey=0;
	if((len<0)||(len>8)) len=8;
	for(i=0,j=56;i<len;i++,j-=8)
		orgkey |= (ULLONG)key[i]<<j;

	dk->size = len;
	MakeKeys(orgkey,dk->list);
	return 0;
}

Key_DES *DESkey_new(int len,unsigned char *key){
	Key_DES *ret=NULL;

	if((ret=DESkey_new_())==NULL) goto error;
	if(DESkey_set(ret,len,key)) goto error;
	return ret;
error:
	DESkey_free(ret);
	return NULL;
}

/*---------------------------------
  DES key struct duplicate
---------------------------------*/
Key_DES *DESkey_dup(Key_DES *org){
	Key_DES *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DES,ERR_PT_DESKEY+1,NULL);
		return NULL;
	}
	if((ret=(Key_DES*)MALLOC(sizeof(Key_DES)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DES,ERR_PT_DESKEY+1,NULL);
		return NULL;
	}
	memcpy(ret,org,sizeof(Key_DES));
	return ret;
}

/*---------------------------------
  DES key struct FREE.
---------------------------------*/
void DESkey_free(Key_DES *key){
	if(key==NULL) return;
	memset(key,0,sizeof(Key_DES));
	FREE(key);
}

void DES_set_iv(Key_DES *key,unsigned char *ivc){
	c2ll(8,ivc,&(key->iv));
	c2ll(8,ivc,&(key->oiv));
}

/*---------------------------------
  DES key struct new.
---------------------------------*/
Key_3DES *DES3key_new_(){
	Key_3DES *ret;
	if((ret=(Key_3DES*)MALLOC(sizeof(Key_3DES)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DES,ERR_PT_DESKEY+2,NULL);
		return NULL;
	}
	ret->key_type = KEY_3DES;
	return ret;
}

int DES3key_set(Key_3DES *dk,Key_DES *key1,Key_DES *key2,Key_DES *key3){

	if((key1==NULL)||(key2==NULL)){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DES,ERR_PT_DESKEY+3,NULL);
		return -1;
	}
	memcpy(dk->list1,key1->list,sizeof(ULLONG)*16);
	memcpy(dk->list2,key2->list,sizeof(ULLONG)*16);

	if(key3==NULL)
		memcpy(dk->list3,key1->list,sizeof(ULLONG)*16);
	else
		memcpy(dk->list3,key3->list,sizeof(ULLONG)*16);
	return 0;
}

int DES3key_set_c(Key_3DES *dk,int len,unsigned char *key){
	Key_DES *k1=NULL,*k2=NULL,*k3=NULL;
	int	err=-1;

	if((len<8)||(len>24)){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_DES,ERR_PT_DESKEY+4,NULL);
		goto done;
	}
	if((k1=DESkey_new(8,key))        ==NULL) goto done;
	if((k2=DESkey_new(len-8,&key[8]))==NULL) goto done;
	if((len-16)>0){
		if((k3=DESkey_new(len-16,&key[16]))==NULL) goto done;
	}
	if(DES3key_set(dk,k1,k2,k3)) goto done;

	err=0;
done:
	if(k1) DESkey_free(k1);
	if(k2) DESkey_free(k2);
	if(k3) DESkey_free(k3);
	return err;
}

Key_3DES *DES3key_new(Key_DES *key1,Key_DES *key2,Key_DES *key3){
	Key_3DES *ret=NULL;

	if((ret=DES3key_new_())==NULL) goto error;
	if(DES3key_set(ret,key1,key2,key3)) goto error;
	return ret;
error:
	DES3key_free(ret);
	return NULL;
}

Key_3DES *DES3key_new_c(int len,unsigned char *key){
	Key_3DES *ret=NULL;

	if((ret=DES3key_new_())==NULL) goto error;
	if(DES3key_set_c(ret,len,key)) goto error;
	return ret;
error:
	DES3key_free(ret);
	return NULL;
}

/*---------------------------------
  3DES key struct duplicate
---------------------------------*/
Key_3DES *DES3key_dup(Key_3DES *org){
	Key_3DES *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_DES,ERR_PT_DESKEY+5,NULL);
		return NULL;
	}
	if((ret=(Key_3DES*)MALLOC(sizeof(Key_3DES)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_DES,ERR_PT_DESKEY+5,NULL);
		return NULL;
	}
	memcpy(ret,org,sizeof(Key_3DES));
	return ret;
}

/*---------------------------------
  3DES key struct FREE.
---------------------------------*/
void DES3key_free(Key_3DES *key){
	if(key==NULL) return;
	memset(key,0,sizeof(Key_3DES));
	FREE(key);
}

void DES3_set_iv(Key_3DES *key,unsigned char *ivc){
	c2ll(8,ivc,&(key->iv));
	c2ll(8,ivc,&(key->oiv));
}


/*---------------------------------
    Generate Key schedule
---------------------------------*/
void MakeKeys(ULLONG orgKeyL,ULLONG *keyL){
	ULLONG cL,dL,tmp;
	int  i,j;
	char shift[]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

	tmp = BitChange(orgKeyL,PC1c,56); /* PC1 */
	cL = tmp >> 36;
	dL = (tmp >> 8) & 0x0fffffff;

	for(i=0;i<16;i++){
		j = shift[i];
		cL = ((cL << j) & 0x0fffffff) | (cL >> (28-j));  /* 右詰め28ビット */
		dL = ((dL << j) & 0x0fffffff) | (dL >> (28-j));  /* 右詰め28ビット */

		tmp = cL << 36;
		tmp |= dL << 8;

		keyL[i] = BitChange(tmp,PC2c,48) >> 16; /* PC2 */
    }
}

/*-----------------------------------------
    DES ULLONG TOOLs
-----------------------------------------*/
void c2ll(int len,unsigned char *in,ULLONG *ret){
	ULONG r,l;
	int i,j;

	for(i=j=0;j<len;i++,j+=8){
		l=((long)in[j  ]<<24)|((long)in[j+1]<<16)|((long)in[j+2]<<8)|((long)in[j+3]);
		r=((long)in[j+4]<<24)|((long)in[j+5]<<16)|((long)in[j+6]<<8)|((long)in[j+7]);
		ret[i]=((ULLONG)l<<32)|(ULLONG)r;
	}
}

void ll2c(int len,ULLONG *in,unsigned char *ret){
	unsigned char	*ot;
	ULLONG	tmp;
	int	i;

	for(i=0,ot=ret;i<len;i++){
		tmp = in[i];
		*ot = (unsigned char)(tmp>>56); ot++;
		*ot = (unsigned char)(tmp>>48); ot++;
		*ot = (unsigned char)(tmp>>40); ot++;
		*ot = (unsigned char)(tmp>>32); ot++;
		*ot = (unsigned char)(tmp>>24); ot++;
		*ot = (unsigned char)(tmp>>16); ot++;
		*ot = (unsigned char)(tmp>>8 ); ot++;
		*ot = (unsigned char) tmp; ot++;
  }
}

/*---------------------------------
    ULLONG bit change
---------------------------------*/
ULLONG BitChange(ULLONG block,char *change,int loop){
	ULLONG ret;
	int i;
		
	ret = 0L;

#ifdef DEBUG_DES
if(loop==64)
    printf("bc-- %x%x - %d\n",(long)(block>>32),(long)block,loop);
#endif 

	for(i=0;i<loop;){
		if(bits[change[i]] & block){
			i++;
			ret |= bits[i];
		}else i++;
	}
	return ret;
}

