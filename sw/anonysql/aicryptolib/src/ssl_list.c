/* ssl_list.c */
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
 *	this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *	this list of conditions and the following disclaimer in the documentation
 *	and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *	display the following acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *	acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	 Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
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
#include <time.h>

#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_ssl.h"

/*-----------------------------------------
  set SSLCTX to reconnection list
-----------------------------------------*/
int SSL_add_connect_list(SSL *listen_ssl,SSL *ssl){
	SSLCTX *top;

	if((listen_ssl==NULL)||(ssl==NULL)) return -1;

	if(listen_ssl->ctx==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_LIST,NULL);
		return -1;
	}
	if(!(ssl->opt&SSL_SYS_RECONNECTION)){
		top=listen_ssl->ctx;
		ssl->ctx->top=top;	/* it's already set in SSL_accept */

		/* if list_max == 0, don't add any SSLCTX */
		if(top->list_max==0) return 0;

		ssl->opt|=SSL_SYS_CTXLISTED;
		add_to_top(top,ssl->ctx);
		top->list_num++;
		if(top->list_max < top->list_num){
			if(delete_one_ctx(top)) return -1;
			top->list_num--;
		}
	}
	return 0;
}

/*-----------------------------------------
  SSLCTX list modification
-----------------------------------------*/
void add_to_top(SSLCTX *top,SSLCTX *add){
	if(top->prev==NULL)	/* first time to add */
		top->prev = add;	/* the oldest connection */
	if(top->next)
		top->next->prev = add;
	add->next = top->next;
	top->next = add;
	add->prev = top;
}

void move_to_top(SSLCTX *top,SSLCTX *mv){
	if(mv->next)
		mv->next->prev = mv->prev;
	if(mv->prev)
		mv->prev->next = mv->next;
	if(top->prev==mv)	/* oldest one will be latest one */
		top->prev = mv->prev;
	add_to_top(top,mv);
}

int delete_one_ctx(SSLCTX *top){
	SSLCTX *prev;

	if(top->prev==NULL){ /* this one should not occur !! */
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL_LIST+1,NULL);
		return -1;
	}
	prev = top->prev;
	top->prev = prev->prev;
	if(top->prev==top)
		top->prev=NULL;

	if(prev->ssl)
		prev->ssl->opt&=~SSL_SYS_CTXLISTED;	/* clear listed flag */
	
	/* if(prev->ssl) ... people might forget to FREE SSL before X(
	 * so this SSLCTX, "prev," would not be FREEd, if this one is put here.
	 */
	SSLCTX_free(prev);
	return 0;
}


/*-----------------------------------------
  reconnection support functions
-----------------------------------------*/
SSLCTX *find_old_ctx(SSLCTX *ctx, unsigned char *id, int len){
	SSLCTX *ret,*top;

	top=(ctx->top)?(ctx->top):(ctx);

	for(ret=top;ret!=NULL;ret=ret->next){
		if(!memcmp(ret->shello->session_id,id,len)){
			/* find same session_id SSLCTX !! */
			/* set time stamp */
			time(&ret->contime);
			/* move to top of list */
			move_to_top(top,ret);
			break;}
	}
	return ret;
}

int copy_part_of_ctx(SSLCTX *to,SSLCTX *from){
	if(from->exkey)
		if((to->exkey=Key_dup(from->exkey))==NULL) return -1;
	if(from->cp12)
		if((to->cp12=P12_dup(from->cp12))==NULL) return -1;
	to->sp12	= from->sp12;

	memcpy(to->shello->session_id,from->shello->session_id,32);
	memcpy(to->premaster,from->premaster,48);
	memcpy(to->master_secret,from->master_secret,48);
	to->contime	= from->contime;
	to->list_max= from->list_max;
	to->list_num= from->list_num;
	to->top		= from->top;
	to->next	= NULL;
	to->prev	= NULL;
	to->stm		= from->stm;
	return 0;
}

void SSL_set_list_max(SSL *ssl,int num){
	if(ssl->ctx)
		ssl->ctx->list_max = num;
}
