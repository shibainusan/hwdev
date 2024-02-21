/* ssl_hsserv.c */
/* Handshake procedures */
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

#define CIMAX 4
unsigned char possible_cipher[CIMAX]=
	{0x0a,0x09,0x08,0x06};

extern unsigned char pad_1[48];
extern unsigned char pad_2[48];

void get_final_hashes(SSLCTX *ctx,unsigned char *md5,unsigned char *sha1,int i,int final);
void get_keyexcg_hashes(SSLCTX *ctx,unsigned char *sp,int splen,unsigned char *md5,unsigned char *sha1);
void init_before_hello(SSL *ssl);

/*-----------------------------------------
  SSL Handshake (Hello Request)
-----------------------------------------*/
int SSL_send_helloreq(SSL *ssl){
	unsigned char buf[64];

	memset(buf,0,4);
	if(SSL_write(ssl,buf,4)<0) return -1;

	return 0;
}

/*-----------------------------------------
  SSL Handshake (Client Hello)
-----------------------------------------*/
int SSL_recv_client_hello(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,err=-1;
	SSLCTX *ctx;
	
	ctx = ssl->ctx;
	init_before_hello(ssl);

	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	/* now server get client_hello */
	if(SSL_set_clienthello(ctx,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashinit(ctx);
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

/* set ssl->chello from message */
int SSL_set_clienthello(SSLCTX *ctx, unsigned char *buf, int len){
	int	i,j,clen,slen,chlen;

	if(buf[0] != SSL_HT_CLIENT_HELLO){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_SERV,NULL);
		goto error;
	}

	if((buf[1]==0x3)&&(buf[3]==0)){
		/* SSLv3 v2_client_hello */
		ctx->chello->version.major = buf[1];
		ctx->chello->version.major = buf[2];

		/* if client has SSLv3, this should be first session.
		 * therefore, no session-id should be sent by client.
		 */
		clen = buf[3]<<8; clen |= buf[4];
		slen = buf[5]<<8; slen |= buf[6];
		chlen= buf[7]<<8; chlen|= buf[8];

		memset(ctx->chello->cipher_suites,0,64);
		for(i=1,j=2;j<clen;i+=2,j+=3)
			ctx->chello->cipher_suites[i] = buf[9+j];

		memset(ctx->chello->random,0,16);
		memcpy(&(ctx->chello->random[16]),&(buf[9+clen]),chlen);

	}else if((buf[4]==0x3)&&(buf[5]==0)){
		/* SSLv3 v3_client_hello */
		ctx->chello->version.major = buf[4];
		ctx->chello->version.major = buf[5];

		/* clen=buf[1]<<16; clen|=buf[2]<<8; clen|=buf[3]; */
		memcpy(ctx->chello->random,&(buf[6]),32);	/* gmt_unix_time & random_byte[28] */

		if((slen=buf[38])!=0){	/* session id is not 0 */
			SSLCTX *old;

			if(old=find_old_ctx(ctx,&(buf[39]),slen)){
				if(copy_part_of_ctx(ctx,old)) goto error;
				ctx->ssl->opt|=SSL_SYS_RECONNECTION;
			}
		}
		slen += 39;

		clen = buf[slen]<<8; clen |= buf[slen+1];
		slen+= 2;
		memset(ctx->chello->cipher_suites,0,64);
		for(i=1;i<clen;i+=2)
			ctx->chello->cipher_suites[i] = buf[slen+i];

		/* no compression method is supported.
		 */
		slen+=i-1;
		if((buf[slen]!=1)||(buf[slen+1]!=0)){
			OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_SERV,NULL);
			goto error;
		}
	}else{
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_SERV,NULL);
		goto error;
	}
	return 0;
error:
	ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

/*-----------------------------------------
  SSL Handshake (Server Hello)
-----------------------------------------*/
int SSL_send_serv_hello(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,err=-1;
	SSLCTX *ctx;
	
	if(!(ssl->opt & SSL_OPT_HS_SEPARATE))
		SSL_setopt(ssl,SSL_OPT_KEEPWBUF|SSL_getopt(ssl));

	ctx = ssl->ctx;
	ctx->serv = 1;
	if((len=SSL_get_serverhello(ctx,buf))<0) goto done;

	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

int SSL_send_serv_cert(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;
	
	ctx = ssl->ctx;
	ctx->serv = 1;
	if((len=SSL_get_certificate(ctx,buf))<0) goto done;

	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

int SSL_send_serv_keyexchange(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;

	ctx = ssl->ctx;
	if((len=SSL_get_keyexchange(ctx,buf))<0) goto done;

	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

int SSL_send_certreq(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;

	ctx = ssl->ctx;
	if((len=SSL_get_certreq(ctx,buf))<0) goto done;

	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

int SSL_send_serv_hellodone(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;

	ctx = ssl->ctx;
	if((len=SSL_get_serverhellodone(ctx,buf))<0) goto done;

	if(SSL_write(ssl,buf,len)<0) goto done;

	/* flush SSL write buffer */
	if(SSL_wflush(ssl)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

/* ------------------------------------------------------------*/
/* return is buf-length. if return is -1, it's error.
 * buf-length must be smaller than SSLMAXBUF.
 */
int SSL_get_serverhello(SSLCTX *ctx, unsigned char *buf){
	unsigned char *c;
	ULONG t;
	int i,j,k;

	time((time_t*)&t);

	/* first, set server hello */
	ctx->shello->version.major = 3;
	ctx->shello->version.minor = 0;

#define UCH	unsigned char
	c = ctx->shello->random;
	c[0]=(UCH)(0xff&(t>>24)); c[1]=(UCH)(0xff&(t>>16));	/* gmt_unix_time */
	c[2]=(UCH)(0xff&(t>>8));  c[3]=(UCH)(0xff&t);
#undef UCH
	if(SSL_set_rand(&(c[4]),28)) goto error;

	if(!(ctx->ssl->opt&SSL_SYS_RECONNECTION))
		if(SSL_set_rand(ctx->shello->session_id,32)) goto error;

	/* set appropriate cipher suite from client hello */
	memset(ctx->shello->cipher_suites,0,2);
	for(i=1;(k=ctx->chello->cipher_suites[i]);i+=2){
		for(j=0;j<CIMAX;j++)
			if(k == possible_cipher[j]){
				ctx->shello->cipher_suites[1] = possible_cipher[j];
				break;
			}
		if(ctx->shello->cipher_suites[1]) break;
	}

	if(ctx->shello->cipher_suites[1] == 0){
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_SERV+1,NULL);
		goto error;
	}

	/* second, set buffer */
	buf[0] =SSL_HT_SERVER_HELLO;	/* server_hello */
	buf[1] =buf[2]=0; buf[3] = 70;	/* length */

	/* SSL version */
	buf[4] = ctx->version.major;
	buf[5] = ctx->version.minor;

	memcpy(&(buf[6]),ctx->shello->random,32);	/* server random */
	buf[38] = 32;	/* session ID len */
	memcpy(&(buf[39]),ctx->shello->session_id,32);		/* session_id */
	memcpy(&(buf[71]),ctx->shello->cipher_suites,2);	/* cipher suite */
	buf[73] = 0;	/* compression method (=0) */
	
	return 74; /* Oops :-) */
error:
	ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_get_certificate(SSLCTX *ctx, unsigned char *buf){
	PKCS12 *sp12;
	P12_Baggage *bg;
	int	rlen,clen,i,j,k;

	sp12 = (ctx->serv)?(ctx->sp12):(ctx->cp12);
	if(sp12==NULL) goto error;

	buf[0] = SSL_HT_CERTIFICATE;	/* certificate */

	i=P12_max_depth(sp12,OBJ_P12v1Bag_CERT);

	for(rlen=7,clen=0;i>=0;i--){
		if((bg=P12_find_bag(sp12,OBJ_P12v1Bag_CERT,(char)i))==NULL)
			goto error;

		j = ASN1_length(&((P12_CertBag*)bg)->cert->der[1],&k);
		j+= k+1;

		buf[rlen]=j>>16; buf[rlen+1]=0xff&(j>>8); buf[rlen+2]=0xff&j;

		memcpy(&(buf[rlen+3]),((P12_CertBag*)bg)->cert->der,j);
		clen+= j+3;
		rlen+= j+3;
	}

	rlen-=4;
	buf[1]=rlen>>16; buf[2]=0xff&(rlen>>8); buf[3]=0xff&rlen;
	buf[4]=clen>>16; buf[5]=0xff&(clen>>8); buf[6]=0xff&clen;

	return(rlen+4);
error:
	ctx->errnum = SSL_AD_NO_CERTIFICATE | (SSL_AL_WARNING<<8);
	OK_set_error(ERR_ST_SSL_NO_CERT,ERR_LC_SSLHS,ERR_PT_SSLHS_SERV+2,NULL);
	return -1;
}

int SSL_get_keyexchange(SSLCTX *ctx, unsigned char *buf){
	unsigned char *cp,in[128];	/* for 512bit key */
	int len,i,j;

	/* key exchange algorithm is selected in cipher spec. (it's RSA) */
	if((ctx->exkey=(Key*)RSAprvkey_new())==NULL) goto error;

	/* 512 bit key */
	if(RSAprv_generate((Prvkey_RSA*)ctx->exkey,32)) goto error;
	
	cp=&(buf[4]);
	if(ASN1_LNm2int(((Prvkey_RSA*)ctx->exkey)->n,cp,&i)) goto error;
	*cp=0; cp+= i;	/* actually, it's not ASN.1 format */
	if(ASN1_LNm2int(((Prvkey_RSA*)ctx->exkey)->e,cp,&j)) goto error;
	*cp=0; cp+= j; i+=j;

	/* set padding -- PKCS#1 type1 padding */
	for(j=1;j<28/*64-36*/;j++) in[j]=0xff;
	in[0]=0; in[1]=1; in[27]=0;

	/* get hashes */
	get_keyexcg_hashes(ctx,&buf[4],i,&in[28],&in[44]);

	/* set length & do sign */
	buf[4+i]=0; buf[5+i]=64;
	if(RSAprv_doCrypt(64,in,&buf[6+i],(Prvkey_RSA*)ctx->exkey)) goto error;
	len=2+i+64;

	buf[0] = SSL_HT_SERVER_KEY_EXCHANGE;	/* key exchange */
	buf[1]=0; buf[2]=(len>>8); buf[3]=(len);	/* length */
	return(len+4);
error:
	ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_get_certreq(SSLCTX *ctx, unsigned char *buf){
	CStore *cs;
	CertList *cl2,*cl1=NULL,*cl=NULL;
	unsigned char *cp;
	int i,j,k,l,len=-5;

	buf[4] = SSL_CERT_ALGOMAX;
	for(i=0;i<SSL_CERT_ALGOMAX;i++)
		buf[5+i]=i+1;	/* just SSL_HT_RSA_SIGN */
	i+=5;

	/* get appropriate certlist from store */
	if(ctx->stm){
		if((cs=STM_find_byName(ctx->stm,STORE_ROOT,CSTORE_ON_STORAGE,CSTORE_CTX_CERT))==NULL) goto done;
		cl1 = CStore_2certlist(cs); /* might be NULL */
		if((cs=STM_find_byName(ctx->stm,STORE_MIDCA,CSTORE_ON_STORAGE,CSTORE_CTX_CERT))==NULL) goto done;
		cl2 = CStore_2certlist(cs); /* might be NULL */
		cl1 = cl = Certlist_join(cl1,cl2);
	}
	l=i+2;
	for(len=0; cl ;cl=cl->next){
		if(cl->cert){
			/* set CA subject list */
			cp = ASN1_step(cl->cert->der,2);
			if(*cp == 0xa0) cp = ASN1_skip(cp); /* version 3 */
			cp = ASN1_skip(cp); /* serial number */
			cp = ASN1_skip(cp); /* signature algo */
			cp = ASN1_skip(cp); /* issuer DN */
			cp = ASN1_skip(cp); /* validate */

			/* this cp should have a pointer of ASN.1 cert subject */
			if(*cp == 0x30){
			    j =ASN1_length(cp+1,&k);
			    j+=k+1;

				buf[l]=(j>>8); buf[l+1]=(j);
				memcpy(&buf[l+2],cp,j);
				len+=j+2;
				l  +=j+2;
			}
		}
	}
	buf[i]=(len>>8); buf[i+1]=(len);
	len+=i-2;	/* +2-4 */

	buf[0] = SSL_HT_CERTIFICATE_REQUEST;	/* cert request */
	buf[1]=0; buf[2]=(len>>8); buf[3]=(len);	/* length */
done:
	Certlist_free(cl1);
	return(len+4);
}

int SSL_get_serverhellodone(SSLCTX *ctx, unsigned char *buf){
	buf[0] = 14;	/* server hello done */
	buf[1]=buf[2]=buf[3]=0;
	return 4;
}

/*-----------------------------------------
  SSL Handshake (Client Answers)
-----------------------------------------*/
int SSL_recv_client_cert(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,i,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if(*buf==SSL_HT_CERTIFICATE){
		/* handshake_messages */
		if((i=SSL_set_certificate(ctx,buf,len))<0) goto done;

		i+=4;
		if(i<len){	/* netscape type handshake message */
			ctx->rpklen += len-i;
			ctx->ptxt->fragment -= len-i;
		}
		SSL_hs_hashupdate(ctx,buf,i);

	}else{
		/* set back the message */
		ctx->rpklen += len;
		ctx->ptxt->fragment -= len;
		
		/* anonymous server cannot send certificate request */
		if((ssl->opt&SSL_OPT_CERTREQ)&&(ctx->sp12))
			err=SSL_AD_NO_CERTIFICATE | (SSL_AL_FATAL<<8);
	}
	err=0;
done:
	return err;
}

int SSL_recv_clikeyexchange(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,i,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if(*buf!=SSL_HT_CLIENT_KEY_EXCHANGE){
		ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_SSL_NO_CERT,ERR_LC_SSLHS,ERR_PT_SSLHS_SERV+5,NULL);
		goto done;
	}

	/* handshake_messages */
	if((i=SSL_set_clikeyexchange(ctx,buf,len))<0) goto done;

	i+=4;
	if(i<len){	/* netscape type handshake message */
		ctx->rpklen += len-i;
		ctx->ptxt->fragment -= len-i;
	}

	SSL_hs_hashupdate(ctx,buf,i);

	SSL_gen_mastersecret(ctx);
	err=0;
done:
	return err;
}

int SSL_recv_client_certvfy(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,i,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if(*buf==SSL_HT_CERTIFICATE_VERIFY){
		/* handshake_messages */
		if((i=SSL_set_certvfy(ctx,buf,len))<0) goto done;

		i+=4;
		if(i<len){	/* netscape type handshake message */
			ctx->rpklen += len-i;
			ctx->ptxt->fragment -= len-i;
		}
		SSL_hs_hashupdate(ctx,buf,i);

	}else{
		/* set back the message */
		ctx->rpklen += len;
		ctx->ptxt->fragment -= len;
	}
	err=0;
done:
	return err;
}

/*---------------------------------------------------------------*/
int SSL_set_clikeyexchange(SSLCTX *ctx, unsigned char *buf, int len){
	unsigned char out[260];	/* smaller than 2048bit RSA */
	int	i,err=0;
	Key *key;

	/* get server private key */
	if(ctx->sp12){
		if((key=P12_get_privatekey(ctx->sp12))==NULL)
			goto error;

	}else{
		/* key exchange handshake was used */
		key=ctx->exkey;
	}

	switch(key->key_type){
	case KEY_RSA_PRV:
		if(RSAprv_doCrypt(key->size,&buf[4],out,(Prvkey_RSA*)key))
			goto error;

		/* check PKCS#1 padding */
		if(out[0]||(out[1]!=2)){ /* decryption error */
			OK_set_error(ERR_ST_P1_BADPADDING,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+4,NULL);
			goto error;
		}

		for(i=1;out[i];i++);	/* go through padding */
		i++;
		memcpy(ctx->premaster,&(out[i]),48);
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+4,NULL);
		goto error;
	}

	return (buf[1]<<16)|(buf[2]<<8)|(buf[3]);
error:
	if(!ctx->errnum)
		ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_set_certvfy(SSLCTX *ctx, unsigned char *buf, int len){
	unsigned char vfy[64],out[260]; /* smaller than 2048bit RSA */
	int	i,err=-1;
	Cert *ct;
	Key *key;

	/* If this function is called, 
	 * usually server must recieve client certificate.
	 */
	if(ctx->cp12==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	get_final_hashes(ctx,vfy,&vfy[16],0,0);

	/* get server certificate & public key */
	if((ct=P12_get_usercert(ctx->cp12))==NULL) goto error;
	if((key=ct->pubkey)==NULL){
		OK_set_error(ERR_ST_NULLKEY,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	/* get server private key */
	switch(key->key_type){
	case KEY_RSA_PUB:
		if(RSApub_doCrypt(key->size,&buf[6],out,(Pubkey_RSA*)key))
			goto error;

		/* check PKCS#1 padding */
		if(out[0]||(out[1]!=1)){ /* decryption error */
			OK_set_error(ERR_ST_P1_BADPADDING,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
			goto error;
		}

		for(i=1;out[i];i++);	/* go through padding */
		i++;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	if(memcmp(vfy,&(out[i]),36)){
		OK_set_error(ERR_ST_SSL_BADSIGNATURE,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	return (buf[1]<<16)|(buf[2]<<8)|(buf[3]);
error:
	if(!ctx->errnum)
		ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

/*-----------------------------------------
  SSL Handshake (Finished)
-----------------------------------------*/
int SSL_recv_finished(SSL *ssl){
	unsigned char buf[SSLMAXBUF],md5[16],sha1[20];
	int	len;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	/* receive finished */
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) return -1;

	/* calculate and verify hash */
	get_final_hashes(ctx,md5,sha1,ctx->serv^1,1);

	SSL_hs_hashupdate(ctx,buf,len);

	if(memcmp(&(buf[4]),md5,16)) goto error;

	if(memcmp(&(buf[20]),sha1,20)) goto error;

	return 0;
error:
	OK_set_error(ERR_ST_SSL_BADFINISHED,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+6,NULL);
	ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_send_finished(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	/* calculate hash */
	get_final_hashes(ctx,&(buf[4]),&(buf[20]),ctx->serv,1);
	buf[0]=SSL_HT_FINISHED;
	buf[1]=0; buf[2]=0; buf[3]=36;
	len = 40;

	SSL_hs_hashupdate(ctx,buf,len);

	/* send finished */
	if(SSL_write(ssl,buf,len)<0) goto done;

	/* flush data and clear flag */
	if(SSL_wflush(ssl)<0) goto done;

	SSL_setopt(ssl,(~SSL_OPT_KEEPWBUF)&SSL_getopt(ssl));
	err=0;
done:
	return err;
}

void get_final_hashes(SSLCTX *ctx,unsigned char *md5,unsigned char *sha1,int i,int final){
	unsigned char sender[2][4]={/* client, server */
		{0x43,0x4c,0x4e,0x54},{0x53,0x52,0x56,0x52}};
	MD5_CTX mctx;
	SHA1_CTX sctx;

	memcpy(&mctx,ctx->hsmsg_md5,sizeof(MD5_CTX));
	memcpy(&sctx,ctx->hsmsg_sha1,sizeof(SHA1_CTX));

	if(final) MD5Update(&mctx,sender[i],4);
	MD5Update(&mctx,ctx->master_secret,48);
	MD5Update(&mctx,pad_1,48);
	MD5Final(md5,&mctx);
	if(final) SHA1update(&sctx,sender[i],4);
	SHA1update(&sctx,ctx->master_secret,48);
	SHA1update(&sctx,pad_1,40);
	SHA1final(sha1,&sctx);

	MD5Init(&mctx);
	MD5Update(&mctx,ctx->master_secret,48);
	MD5Update(&mctx,pad_2,48);
	MD5Update(&mctx,md5,16);
	MD5Final(md5,&mctx);
	SHA1init(&sctx);
	SHA1update(&sctx,ctx->master_secret,48);
	SHA1update(&sctx,pad_2,40);
	SHA1update(&sctx,sha1,20);
	SHA1final(sha1,&sctx);
}

void get_keyexcg_hashes(SSLCTX *ctx,unsigned char *sp,int splen,unsigned char *md5,unsigned char *sha1){
	MD5_CTX mctx;
	SHA1_CTX sctx;

	MD5Init(&mctx);
	MD5Update(&mctx,ctx->chello->random,32);
	MD5Update(&mctx,ctx->shello->random,32);
	MD5Update(&mctx,sp,splen);
	MD5Final(md5,&mctx);
	SHA1init(&sctx);
	SHA1update(&sctx,ctx->chello->random,32);
	SHA1update(&sctx,ctx->shello->random,32);
	SHA1update(&sctx,sp,splen);
	SHA1final(sha1,&sctx);
}

