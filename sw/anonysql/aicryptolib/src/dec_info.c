/* dec_info.c */
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

#include "ok_pkcs.h"

Dec_Info *DInfo_new(void){
	Dec_Info *ret;

	if((ret=(Dec_Info*)MALLOC(sizeof(Dec_Info)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_DECINFO,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(Dec_Info));
	return ret;
}

void DInfo_free(Dec_Info *dif){
	if(dif==NULL) return;
	memset(dif->pass,0,dif->plen);
	if(dif->pass) FREE(dif->pass);
	memset(dif->salt,0,dif->slen);
	if(dif->salt) FREE(dif->salt);
	if(dif->iv){
		memset(dif->iv,0,8);
		FREE(dif->iv);
	}
	memset(dif,0,sizeof(Dec_Info));
	FREE(dif);
}

int dif_set_salt(Dec_Info *dif){
	time_t t;
	int i;

	if(dif->salt==NULL){
		if((dif->salt=(unsigned char*)MALLOC(8))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS,ERR_PT_DECINFO+2,NULL);
			return -1;
		}
	}
	dif->slen = 8;

	time(&t);
	for(i=0;i<8;i++) dif->salt[i]=(unsigned char)(rand()+t);
	return 0;
}

