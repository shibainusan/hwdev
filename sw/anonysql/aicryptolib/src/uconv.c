/* uconv.c */
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

typedef int (*tfunc)();

tfunc uct1[5]={       NULL,jis2sjis_in, jis2euc_in, jis2uni_in, jis2utf_in};
tfunc uct2[5]={sjis2jis_in,       NULL,sjis2euc_in,sjis2uni_in,sjis2utf_in};
tfunc uct3[5]={ euc2jis_in,euc2sjis_in,       NULL, euc2uni_in, euc2utf_in};
tfunc uct4[5]={ uni2jis_in,uni2sjis_in, uni2euc_in, utf2uni_in, uni2utf_in};

/*-----------------------------------------
	Kanji converter
-----------------------------------------*/
int UC_conv(int inform, int outform, char *in, int ilen, char *out, int max){
	int ret=ilen;

	if((inform<1)||(UC_CODE_UTF8<inform)) goto error;

	memset(out,0,max);
	if(inform == outform){
		if(ret>max) ret=max;
		memcpy(out,in,ret);
	}else{
		switch(inform){
		case UC_CODE_JIS:    ret=UC_jis2any(in,ilen,out,max,uct1[outform-1]); break;
		case UC_CODE_SJIS:   ret=UC_sjeu2any(in,ilen,out,max,uct2[outform-1]); break;
		case UC_CODE_EUC:    ret=UC_sjeu2any(in,ilen,out,max,uct3[outform-1]); break;
		case UC_CODE_UNICODE:ret=UC_uni2any(in,ilen,out,max,uct4[outform-1]); break;
		case UC_CODE_UTF8:   ret=UC_utf2any(in,ilen,out,max,uct4[outform-1]); break;
		};
	}
	return ret;
error:
	OK_set_error(ERR_ST_BADPARAM,ERR_LC_UCONV,ERR_PT_UCONV,NULL);
	return -1;
}

