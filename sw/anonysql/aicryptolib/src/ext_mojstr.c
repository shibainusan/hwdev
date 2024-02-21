/* ext_mojstr.c */
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

#include "ok_x509.h"
#include "ok_x509ext.h"

#include "ok_uconv.h"

#define M_check_length_and_copy()	\
		if(max<=(ret+i)) goto max_end; \
		strncat(buf,tmp,i+1); ret+=i;

 
 /*-----------------------------------------
  Extension MOJ Registrated Corp Info
-----------------------------------------*/
int Ext_mojcorpinfo_str(CE_MOJCoInfo *ce, char *buf, int max){
	char tmp[128];
	int ret=0,i;

	*buf=0;
	if(ce->corpInfo[0]){
		SNPRINTF (tmp,126,"        [0]corporateName: %s%s",ce->corpInfo[0],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	if(ce->corpInfo[1]){
		SNPRINTF (tmp,126,"        [1]registeredNumber: %s%s",ce->corpInfo[1],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	if(ce->corpInfo[2]){
		SNPRINTF (tmp,126,"        [2]corporateAddress: %s%s",ce->corpInfo[2],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	if(ce->corpInfo[3]){
		SNPRINTF (tmp,126,"        [3]DirectorName: %s%s",ce->corpInfo[3],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	if(ce->corpInfo[4]){
		SNPRINTF (tmp,126,"        [4]DirectorTitle: %s%s",ce->corpInfo[4],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	if(ce->corpInfo[5]){
		SNPRINTF (tmp,126,"        [5]??: %s%s",ce->corpInfo[5],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	if(ce->corpInfo[6]){
		SNPRINTF (tmp,126,"        [6]registryOffice: %s%s",ce->corpInfo[6],RTN);
		i = strlen(tmp);
		M_check_length_and_copy();
	}
	return ret;
max_end:
	strncat(buf,tmp,max-ret);
	return max;
}

