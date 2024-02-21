/* sto_del.c */
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
#include "ok_sha1.h"
#include "ok_asn1.h"
#include "ok_store.h"


/*-----------------------------------------
  remove all bags from the store
-----------------------------------------*/
void CStore_remove_all(CStore *cs){
	CSBag_free_all(cs,cs->bags);
	cs->bags=NULL;
}

/*-----------------------------------------
  delete bags from the store
-----------------------------------------*/
int CStore_del_bag(CStore *cs, CSBag *del){
	CSBag *bg;

	for(bg=cs->bags; bg ; bg=bg->next)
		if(bg == del) break;

	if(bg == NULL){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STDEL,NULL);
		return -1;
	}
	if(bg->next) bg->next->prev = bg->prev;
	if(bg->prev) bg->prev->next = bg->next;
	else         cs->bags = bg->next;

	cs->csf_stat.st_mtime = -1; /* set update flag */
	CSBag_free(cs, bg);
	return 0;
}

int CStore_del_byID(CStore *cs, char *unique_id){
	CSBag *bg;

	if((bg=CStore_find_byID(CStore_get_firstBag(cs),unique_id))==NULL){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STDEL+1,NULL);
		return -1;
	}
	return CStore_del_bag(cs,bg);
}

int CStore_del_byKeyHash(CStore *cs, unsigned char hash[20]){
	CSBag *bg;
	int i=0, ret=0;

	bg = CStore_get_firstBag(cs);
	while(bg=CStore_find_byKeyHash(bg,hash)){
		ret |= CStore_del_bag(cs,bg);
		bg   = CSBag_next(bg);
		i++;
	}
	if(i==0){
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_STORE,ERR_PT_STDEL+2,NULL);
		return -1;
	}
	return ret;
}

