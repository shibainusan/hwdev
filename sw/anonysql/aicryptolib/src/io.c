/* io.c */
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

#include <sys/types.h>
#include <sys/stat.h>

FILE *okin  = NULL;
FILE *okout = NULL;
FILE *okerr = NULL;

void OK_set_stdin(FILE *in){
	okin = in;
}

void OK_set_stdout(FILE *out){
	okout = out;
}

void OK_set_errout(FILE *err){
	okerr = err;
}

void *ai_malloc(int sz){
	return malloc(sz);
}

void ai_free(void *pt){
	free(pt);
}

#ifdef __WINDOWS__
char *strdup_debug(char *b){
	char *ret;
	int i = strlen(b);

	if((ret=(char*)MALLOC(i+2))==NULL) return NULL;
	strncpy(ret,b,i+2);
	return ret;
}
#endif /* defined(__WINDOWS__) */

/*----------------------------------------
	get file length
----------------------------------------*/
int ok_get_flen(FILE *fp){
	struct stat sbuf;

	fstat(fileno(fp),&sbuf);
	return sbuf.st_size;
}
