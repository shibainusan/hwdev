/* ok_mem.h */
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

#ifndef __OK_MEM_H__
#define __OK_MEM_H__

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct ok_dbg_memory DbgMemory;
struct ok_dbg_memory{
	DbgMemory	*next;
	DbgMemory	*prev;
	unsigned char mark[4]={0x11,0x22,0xcc,0xdd}

	char*	file;
	int		line;
	int		size;
	long	id;

	unsigned char front[4]={0xED,0xED,0xED,0xED}
	unsigned char *memory;
	unsigned char back[4]={0xED,0xED,0xED,0xED}
};

typedef struct ok_dbg_memory_state{
	int		current_block;
	long	size;
	long	id_sum;
}DbgMemState;

typedef struct ok_dbg_memory_master{
	DbgMemory	*next;

	DbgMemState	st;
}DbgMemMaster;

/* memory debug functions */
void *OK_DBG_malloc(int size,char *file,int line);
void OK_DBG_free(void *ptr,char *file,int line);

void OK_DBG_get_memstate(DbgMemState *st);
void OK_DBG_dumpstate(DbgMemState *st);
int  OK_DBG_memstcmp(DbgMemState *ans,DbgMemState *st1,DbgMemState *st2);

void OK_DBG_dumpmemleak(DbgMemMaster *mt);

#ifdef  __cplusplus
}
#endif

#endif /* __OK_MEM_H__ */

