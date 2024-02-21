/* ssl.c */
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

#include "ok_ssl.h"

/*-----------------------------------------
  make new struct SSL
-----------------------------------------*/
SSL *SSL_new(void){
	SSL *ret;

	if((ret = (SSL*)MALLOC(sizeof(SSL)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL,NULL);
		return NULL;
	}

	memset(ret,0,sizeof(SSL));
	return ret;
}

/*-----------------------------------------
  FREE struct SSLCTX
-----------------------------------------*/
void SSL_free(SSL *ssl){
	if(ssl==NULL) return;

	if(ssl->ctx){
		SSLCTX *ctx,*next;

		if(ssl->ctx->top==NULL){
			/* single SSL connection or SSL listening socket(server) */
			for(ctx=ssl->ctx;ctx!=NULL;ctx=next){
				next = ctx->next;
				SSLCTX_free(ctx);
			}
		}else if(ssl->opt&SSL_SYS_RECONNECTION){
			/* reconnection SSL */
			SSLCTX_free(ssl->ctx);
		}else{
			/* other case ... listed SSLCTX won't be FREEd */
			ssl->ctx->ssl=NULL;
			if(!(ssl->opt&SSL_SYS_CTXLISTED))
				SSLCTX_free(ssl->ctx);	/* this one is not listed */
		}
	}
	memset(ssl,0,sizeof(SSL));
	FREE(ssl);
}

/*-----------------------------------------
  duplicate struct SSLCTX
-----------------------------------------*/
SSL *SSL_dup(SSL *org){
	SSL *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL+1,NULL);
		return NULL;
	}

	if((ret=SSL_new())==NULL) goto error;

	memcpy(ret,org,sizeof(SSL));
	if(org->ctx){
		if((ret->ctx=SSLCTX_dup(org->ctx))==NULL) goto error;
		ret->ctx->ssl = ret;
	}

	return ret;
error:
	SSL_free(ret);
	return NULL;
}

/*-----------------------------------------
  make new struct SSLCTX
-----------------------------------------*/
SSLCTX *SSLCTX_new(void){
	SSLCTX  *ret;

	if((ret=(SSLCTX*)MALLOC(sizeof(SSLCTX)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+2,NULL);
		return NULL;
	}
	memset(ret,0,sizeof(SSLCTX));

	if((ret->cspec = SSL_CipherSpec_new())==NULL) goto error;

	ret->version.major = 3;
	ret->version.minor = 0;
	ret->list_max	   = SSL_CONNECT_LIST_MAX;
	ret->vfy_depth	   = 8;
	return ret;
error:
	SSLCTX_free(ret);
	return NULL;
}

/*-----------------------------------------
  FREE struct SSLCTX
-----------------------------------------*/
void SSLCTX_free(SSLCTX *sl){
	if(sl==NULL) return;

	if(sl->ptxt)  SSL_Plaintext_free(sl->ptxt);
	if(sl->comp)  SSL_Compressed_free(sl->comp);
	if(sl->ctxt)  SSL_Ciphertext_free(sl->ctxt);

	if(sl->cspec) SSL_CipherSpec_free(sl->cspec);

	if(sl->chello) SSL_ClientHello_free(sl->chello);
	if(sl->shello) SSL_ServerHello_free(sl->shello);

	if(sl->exkey)	Key_free(sl->exkey);
	if(sl->cp12)	P12_free(sl->cp12);
	if(sl->top==NULL){	/* it's master SSLCTX */
		if(sl->sp12)	P12_free(sl->sp12);
		if(sl->stm)		STM_close(sl->stm);
	}

	if(sl->wbuf)   FREE(sl->wbuf);
	if(sl->rbuf)   FREE(sl->rbuf);

	if(sl->hsmsg_md5)	FREE(sl->hsmsg_md5);
	if(sl->hsmsg_sha1)	FREE(sl->hsmsg_sha1);

	if(sl->ckey)	Key_free(sl->ckey);
	if(sl->skey)	Key_free(sl->skey);

	if(sl->cb)	SSLCB_free(sl->cb);

	memset(sl,0,sizeof(SSLCTX));
	FREE(sl);
}

/*-----------------------------------------
  duplicate struct SSLCTX
-----------------------------------------*/
SSLCTX *SSLCTX_dup(SSLCTX *org){
	SSLCTX *ret;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSL,ERR_PT_SSL+3,NULL);
		return NULL;
	}

	if((ret=SSLCTX_new())==NULL) goto error;

	memcpy(ret,org,sizeof(SSLCTX));
	if(org->ptxt)
		if((ret->ptxt=SSL_Plaintext_dup(org->ptxt))==NULL) goto error;
	if(org->comp)
		if((ret->comp=SSL_Compressed_dup(org->comp))==NULL) goto error;
	if(org->ctxt)
		if((ret->ctxt=SSL_Ciphertext_dup(org->ctxt))==NULL) goto error;

	if(org->cspec)
		if((ret->cspec=SSL_CipherSpec_dup(org->cspec))==NULL) goto error;
	if(org->chello)
		if((ret->chello=SSL_ClientHello_dup(org->chello))==NULL) goto error;
	if(org->shello)
		if((ret->shello=SSL_ServerHello_dup(org->shello))==NULL) goto error;

	if(org->exkey)
		if((ret->exkey=Key_dup(org->exkey))==NULL) goto error;
	if(org->cp12)
		if((ret->cp12 =P12_dup(org->cp12))==NULL) goto error;

	/* sp12 & clist pointer is just copied */

	if(org->top==NULL){
		/* org is master SSLCTX */
		ret->next	= NULL;
		ret->prev	= NULL;
	}

	if(org->ckey)
		if((ret->ckey=Key_dup(org->ckey))==NULL) goto error;
	if(org->skey)
		if((ret->skey=Key_dup(org->skey))==NULL) goto error;

	if(org->cb)
		if((ret->cb=SSLCB_dup(org->cb))==NULL) goto error;

	if(org->wbuf){
		/* alloc new buffer */
		if((ret->wbuf=(unsigned char*)MALLOC(SSLMAXBUF+3072))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+3,NULL);
			goto error;
		}
		memcpy(ret->wbuf,org->wbuf,SSLMAXBUF+3072);
	}
	if(org->rbuf){
		/* alloc new buffer */
		if((ret->rbuf=(unsigned char*)MALLOC(SSLMAXBUF+3072))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+3,NULL);
			goto error;
		}
		memcpy(ret->rbuf,org->rbuf,SSLMAXBUF+3072);
	}

	if(org->hsmsg_md5){
		if((ret->hsmsg_md5=(MD5_CTX*)MALLOC(sizeof(MD5_CTX)))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+3,NULL);
			goto error;
		}
		memcpy(ret->hsmsg_md5,org->hsmsg_md5,sizeof(MD5_CTX));
	}
	if(org->hsmsg_sha1){
		if((ret->hsmsg_sha1=(SHA1_CTX*)MALLOC(sizeof(SHA1_CTX)))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+3,NULL);
			goto error;
		}
		memcpy(ret->hsmsg_sha1,org->hsmsg_sha1,sizeof(SHA1_CTX));
	}

	return ret;
error:
	SSLCTX_free(ret);
	return NULL;
}

/*-----------------------------------------
   new & FREE & dup struct SSLCB
-----------------------------------------*/
SSLCB *SSLCB_new(void){
	SSLCB  *ret;

	if((ret = (SSLCB*)MALLOC(sizeof(SSLCB)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+4,NULL);
	    return NULL;
	}
	memset(ret,0,sizeof(SSLCB));
	return ret;
}

void SSLCB_free(SSLCB *scb){
	if(scb==NULL) return;
	FREE(scb);
}

SSLCB *SSLCB_dup(SSLCB *scb){
	SSLCB  *ret;

	if(scb==NULL) return NULL;

	if((ret = SSLCB_new())==NULL) return NULL;

	memcpy(ret,scb,sizeof(SSLCB));
	return ret;
}

/*-----------------------------------------
  alloc & FREE & dup CipherSpec
-----------------------------------------*/
SSLCipherSpec *SSL_CipherSpec_new(void){
	SSLCipherSpec *ret;
	
	if((ret=(SSLCipherSpec*)MALLOC(sizeof(SSLCipherSpec)))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSL,ERR_PT_SSL+5,NULL);
	    return NULL;
	}

	memset(ret,0,sizeof(SSLCipherSpec));
	return ret;
}

void SSL_CipherSpec_free(SSLCipherSpec *cs){
	if(cs==NULL) return;

	memset(cs,0,sizeof(SSLCipherSpec));
	FREE(cs);
}

SSLCipherSpec *SSL_CipherSpec_dup(SSLCipherSpec *org){
	SSLCipherSpec *ret;
	
	if(org==NULL) return NULL;

	if((ret=SSL_CipherSpec_new())==NULL) return NULL;

	memcpy(ret,org,sizeof(SSLCipherSpec));
	return ret;
}

