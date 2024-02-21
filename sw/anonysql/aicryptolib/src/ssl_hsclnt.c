/* ssl_hsclnt.c */
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
#include "ok_x509.h"
#include "ok_pkcs.h"
#include "ok_ssl.h"

/* ssl_hsserv.c */
#define CIMAX 4
extern unsigned char possible_cipher[CIMAX];
/* ssl_cs.c */
int set_cipher_spec(SSLCTX *ctx,int set);


void get_final_hashes(SSLCTX *ctx,unsigned char *md5,unsigned char *sha1,int i,int final);
void get_keyexcg_hashes(SSLCTX *ctx,unsigned char *sp,int splen,unsigned char *md5,unsigned char *sha1);
void init_before_hello(SSL *ssl);


/*-----------------------------------------
  SSL Handshake (Client Hello)
-----------------------------------------*/
int SSL_send_client_hello(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	init_before_hello(ssl);

	if(ctx->state==SSL_HT_NULL){
		ssl->mode = SSL_HANDSHAKE;		/* send v3 client hello */
	}else
		ssl->mode = SSL_HANDSHAKEv2;	/* send v2 client hello */

	if(!(ssl->opt & SSL_OPT_HS_SEPARATE))
		SSL_setopt(ssl,SSL_OPT_KEEPWBUF|SSL_getopt(ssl));

	if((len=SSL_get_clienthello(ctx,buf))<0) goto done;

	/* send client_hello */
	if(SSL_write(ssl,buf,len)<len) goto done;

	/* flush SSL write buffer */
	if(SSL_wflush(ssl)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashinit(ctx);
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;

done:
	ssl->mode = SSL_HANDSHAKE;	/* for v2 client mode */
	return err;
}

/* return is buf_length. if return is -1, it's error.
 * buf_length must be smaller than SSLMAXBUF.
 */
int SSL_get_clienthello(SSLCTX *ctx, unsigned char *buf){
	/* client hello must be SSL version 2 */
	unsigned char *c;
	ULONG t;
	int i,j,k=0;

	if(ctx->chello==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT,NULL);
		goto error;
	}

	if(ctx->state==SSL_HT_NULL){
		/* this one is not new connection. so, use SSLv3 client_hello.
		 * id, cipher, and certificates are already set.
		 * so just set buffer.
		 */
		/* clear cipher spec */
		set_cipher_spec(ctx,0);

		/* set client random */
		time((time_t*)&t);
#define UCH	unsigned char
		c = ctx->chello->random;
		c[0]=(UCH)(0xff&(t>>24)); c[1]=(UCH)(0xff&(t>>16));	/* gmt_unix_time */
		c[2]=(UCH)(0xff&(t>>8));  c[3]=(UCH)(0xff&t);
#undef UCH
		if(SSL_set_rand(&(c[4]),28)) goto error;

		/* set buffer */
		memset(buf,0,256);

		/* set client random */
		memcpy(&(buf[6]),ctx->chello->random,32);
		/* set session id */
		buf[38] = 32;	/* session ID len */
		memcpy(&(buf[39]),ctx->shello->session_id,32);		/* session_id */

		/* set cipher_spec list */
		k = CIMAX * 2;
		buf[71] = (k>>8); buf[72] = (k);	/* cipher_spec_length */
		for(i=1,j=0;j<CIMAX;i+=2,j++)
			buf[73+i] = possible_cipher[j];	/* set cipher_suites */

		/* set compression method list */
		k+=73;
		buf[k  ] = 1;	/* no compression method is supported */
		buf[k+1] = 0;
		

		k+=2; i =k-4;
		/* set header info */
		buf[0] = SSL_HT_CLIENT_HELLO;
		buf[1] = 0; buf[2]=(i>>8); buf[3]=(i);	/* length */

		buf[4] = ctx->chello->version.major;	/* set version */
		buf[5] = ctx->chello->version.minor;
	}else{
		/* new connection. use SSLv2 client_hello */
		ctx->chello->version.major = 3;
		ctx->chello->version.minor = 0;

		/* set cipher_suite */
		c = ctx->chello->cipher_suites;
		memset(c,0,64);
		for(i=1,j=0;j<CIMAX;i+=2,j++)
			c[i] = possible_cipher[j];

		/* set challenge */
		c = ctx->chello->random;
		memset(c,0,16);
		if(SSL_set_rand(&(c[16]),16)) goto error;

		/* set buffer */
		memset(buf,0,128);
		buf[0] = SSL_HT_CLIENT_HELLO;
		buf[1] = ctx->chello->version.major;	/* set version */
		buf[2] = ctx->chello->version.minor;

		k = CIMAX * 3;
		buf[3] = (k>>8); buf[4] = (k);	/* cipher_spec_length */
		buf[5] = 0; buf[6] = 0;			/* session_id length  */
		buf[7] = 0; buf[8] = 16;		/* challenge length	  */

		for(i=2,j=0;j<CIMAX;i+=3,j++)
			buf[9+i] = possible_cipher[j];	/* set cipher_suites */

		memcpy(&buf[9+k],&c[16],16);
		k+=25;
	}
	return k;
error:
	ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

/*-----------------------------------------
  SSL Handshake (Server Hello)
-----------------------------------------*/
int SSL_recv_serv_hello(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,i,err=-1;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	/* now client get server_hello */
	if((i=SSL_set_serverhello(ctx,buf,len))<0) goto done;

	i+=4;
	if(i<len){	/* netscape type handshake message */
		ctx->rpklen += len-i;
		ctx->ptxt->fragment -= len-i;
	}
	SSL_hs_hashupdate(ctx,buf,i);
	err=0;
done:
	return err;
}

int SSL_recv_serv_certificate(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,i,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if(*buf==SSL_HT_CERTIFICATE){
		/* now client get server_certificate */
		ctx->serv = 0;
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
	}
	err=0;
done:
	return err;
}

int SSL_recv_serv_keyexchange(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,i,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if(*buf==SSL_HT_SERVER_KEY_EXCHANGE){
		/* now client get server_hello */
		ctx->serv = 0;
		if((i=SSL_set_skeyexchange(ctx,buf,len))<0) goto done;

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

int SSL_recv_serv_certreq(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,i,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if(*buf==SSL_HT_CERTIFICATE_REQUEST){
		/* now client get server_hello */
		ssl->opt |= SSL_SYS_GOT_CERTREQ;

		if((i=SSL_set_certreq(ctx,buf,len))<0) goto done;

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

int SSL_recv_serv_hellodone(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	int	len,err=-1;
	SSLCTX *ctx;

	ctx = ssl->ctx;
	if((len=SSL_read(ssl,buf,SSLMAXBUF))<0) goto done;

	if((*buf!=SSL_HT_SERVER_HELLO_DONE)||(buf[3])){
		/* it's not server hello done!! */
		ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+1,NULL);
		goto done;
	}

	SSL_hs_hashupdate(ssl->ctx,buf,len);
	err=0;
done:
	return err;
}

/* ------------------------------------------------------------*/
/* set ssl->shello from message */
int SSL_set_serverhello(SSLCTX *ctx, unsigned char *buf, int len){
	int	slen;

	if(buf[0] != SSL_HT_SERVER_HELLO){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+2,NULL);
		goto error;
	}

	if((buf[4]!=3)||(buf[5]!=0)){
		OK_set_error(ERR_ST_BADVER,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+2,NULL);
		goto error;
	}

	if(ctx->shello==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT,NULL);
		goto error;
	}
	/* set version ... assumed SSLv3 */
	ctx->shello->version.major = buf[4];
	ctx->shello->version.minor = buf[5];

	memcpy(ctx->shello->random,&(buf[6]),32);	/* gmt_unix_time & random_byte[28] */

	slen=buf[38];		/* session id length */
	if(memcmp(ctx->shello->session_id,&(buf[39]),slen))
		memcpy(ctx->shello->session_id,&(buf[39]),slen);
	else
		/* returned session id is same one ! re-connect. */
		ctx->ssl->opt|=SSL_SYS_RECONNECTION;

	slen+=39;
	memcpy(ctx->shello->cipher_suites,&(buf[slen]),2);

	/* any compression method is not supported.
	 * so, receiving non-zero value means fatal error.
	 */
	if(buf[slen+2]){
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+2,NULL);
		goto error;
	}

	return (buf[1]<<16)|(buf[2]<<8)|(buf[3]);
error:
	ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_set_certificate(SSLCTX *ctx, unsigned char *buf, int len){
	Cert *ct;
	PKCS12 *p12;
	int	rlen,clen,i,j,k;
	unsigned char *der;

	if(buf[0] != SSL_HT_CERTIFICATE){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+3,NULL);
		goto error;
	}

	if(ctx->serv){
		p12 = ctx->cp12 = P12_new();
	}else{
		p12 = ctx->sp12 = P12_new();
	}
	if(p12==NULL) goto error;

	rlen = (buf[4]<<16)|(buf[5]<<8)|(buf[6]);
	for(i=7,j=0;j<rlen;i+=clen,j+=clen){
		clen = (buf[i]<<16)|(buf[i+1]<<8)|(buf[i+2]);
		clen+= 3;

		/* ct->der has buf pointer, so memory must be duplicated */
		if((der=(unsigned char*)MALLOC(clen))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+3,NULL);
			goto error;
		}

		memcpy(der,&(buf[i+3]),clen-3);

		/* read certificate */
		if((ct = ASN1_read_cert(der))==NULL){
			ctx->errnum = SSL_AD_UNSUPPORTED_CERTIFICATE | (SSL_AL_FATAL<<8);
			goto error;
		}

		/* add a cert into pkcs12 */
		P12_add_cert(p12,ct,NULL,0xff);
	}

	/* verify user certificate */
	if((ct=P12_get_usercert(p12))==NULL) goto error;

	k = SSL_cert_verify(ctx->ssl,ct);

	switch(k&0xff00){
	case 0:
		/* verification -- o.k. */
	    break;

	case X509_VFY_ERR_REVOKED:
		ctx->errnum = SSL_AD_CERTIFICATE_REVOKED | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_SSL_CERT_REVOKED,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+3,NULL);
		goto error;

	case X509_VFY_ERR_LASTUPDATE:
	case X509_VFY_ERR_NEXTUPDATE:
		ctx->errnum = SSL_AD_CERTIFICATE_EXPIRED | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_SSL_CERT_EXPIRED,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+3,NULL);
		goto error;

	default:
	    ctx->errnum = SSL_AD_CERTIFICATE_UNKNOWN | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_SSL_CERT_UNKNOWN,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+3,NULL);
		goto error;
	}

	return (buf[1]<<16)|(buf[2]<<8)|(buf[3]);
error:
	if(!ctx->errnum)
		ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_set_skeyexchange(SSLCTX *ctx, unsigned char *buf, int len){
	unsigned char *cp,hash[64],out[260];
	int	i,j;

	/* In SSL3.0 draft 5.6.3, it is described that a certificate with
	 * RSA key, which is larger than 512 bit, may not be used for
	 * key exchange because of US export law. Therefore, both server cert
	 * and key exchange messages may be received.
	 * but in this imprementation, only one handshake, server cert or
	 * key exchange, will be accepted, because that case is pretty rare.
	 */
	/* only RSA key exchange is accepted. and it should be selected by
	 * the server in the server hello handshake.
	 */

	if(buf[0] != SSL_HT_SERVER_KEY_EXCHANGE){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+4,NULL);
		goto error;
	}

	/* set public key */
	if((ctx->exkey=(Key*)RSApubkey_new())==NULL) goto error;

	cp=&(buf[4]);
	i = (cp[0]<<8)|(cp[1]);
	if(LN_set_num_c(((Pubkey_RSA*)ctx->exkey)->n,i,&cp[2])) goto error;

	cp+=i+2;
	j  =(cp[0]<<8)|(cp[1]);
	i +=4+j;
	if(LN_set_num_c(((Pubkey_RSA*)ctx->exkey)->e,j,&cp[2])) goto error;

	/* get key size */
	ctx->exkey->size = LN_now_byte(((Pubkey_RSA*)ctx->exkey)->n);

	get_keyexcg_hashes(ctx,&buf[4],i,hash,&hash[16]);

	cp+=j+2; j=(cp[0]<<8)|(cp[1]);
	if((j<=0)||(j>256)){	/* key length must be less than 2048 bit */
		ctx->errnum = SSL_AD_ILLEGAL_PARAMETER | (SSL_AL_FATAL<<8);
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+4,NULL);
		goto error;
	}

	if(RSApub_doCrypt(j,&cp[2],out,(Pubkey_RSA*)ctx->exkey)) goto error;

	/* check PKCS#1 padding */
	if((out[0]!=0)||(out[1]!=1)){ /* decryption error */
		OK_set_error(ERR_ST_P1_BADPADDING,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+4,NULL);
		goto error;
	}

	for(i=1;out[i];i++);	/* go through padding */
	i++;

	if(memcmp(hash,&(out[i]),36)){
		/* signature error !! */
		OK_set_error(ERR_ST_SSL_BADSIGNATURE,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+4,NULL);
		goto error;
	}

	return (buf[1]<<16)|(buf[2]<<8)|(buf[3]);
error:
	if(!ctx->errnum)
		ctx->errnum = SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_set_certreq(SSLCTX *ctx, unsigned char *buf, int len){
	Cert *ct;
	CertDN sbj_dn;
	char *sbj;
	int	ret,i,j,k,l,flg;

	if(buf[0] != SSL_HT_CERTIFICATE_REQUEST){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	ret = (buf[1]<<16)|(buf[2]<<8)|(buf[3]);

	if(ctx->cp12==NULL){
		/* later, no certificate alert will be sent */
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	/* check received subjects and user certificate */
	if((ct=P12_get_usercert(ctx->cp12))==NULL) goto error;

	i=buf[4];	/* get length of certificate type */
	for(j=k=0;j<i;j++){
		/* now only RSA_SIGN certificate is available. */
		if(buf[5+j]==SSL_HT_RSA_SIGN){
			k=SSL_HT_RSA_SIGN;
			break;
		}
	}

	if(!k){
		/* certificate type is not matched - clean p12 file */
		OK_set_error(ERR_ST_UNMATCHEDPARAM,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	j=(buf[5+i]<<8)|(buf[6+i]);	/* get length of subject list */

	if(j==0) return ret;	/* any certificate is ok to send. */

	for(i+=7,flg=k=0;k<j;k+=l,i+=l){
		l = ((buf[i]<<8)|(buf[i+1])) + 2;
		cert_dn_init(&sbj_dn);

		if(sbj=ASN1_get_subject(&buf[i+2],&sbj_dn)){
			if(!strcmp(ct->issuer,sbj))
				flg = 1;	/* matched !! */
			FREE(sbj);
		}
		cert_dn_free(&sbj_dn);
		if(flg) break;
	}

	if(!flg){
		/* user certificate doesn't have requested issuer */
		OK_set_error(ERR_ST_SSL_NO_CERT,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+5,NULL);
		goto error;
	}

	return ret;
error:
	P12_free(ctx->cp12);
	ctx->cp12 = NULL;
	ctx->errnum = SSL_AD_NO_CERTIFICATE | (SSL_AL_FATAL<<8);
	return -1;
}

/*-----------------------------------------
  SSL Handshake (Client Answers)
-----------------------------------------*/
int SSL_send_client_cert(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;

	ctx = ssl->ctx;
	ctx->serv=0;
	if((len=SSL_get_certificate(ctx,buf))<0) goto done;

	/* send client_certificate */
	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

int SSL_send_client_keyexchange(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;

	ctx = ssl->ctx;
	if((len=SSL_get_clikeyexchange(ctx,buf))<0) goto done;

	/* send client_hello */
	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

int SSL_send_client_certvfy(SSL *ssl){
	unsigned char buf[SSLMAXBUF];
	SSLCTX *ctx;
	int	len,err=-1;

	ctx = ssl->ctx;
	if((len=SSL_get_client_certvfy(ctx,buf))<0) goto done;

	/* send client_hello */
	if(SSL_write(ssl,buf,len)<0) goto done;

	/* handshake_messages */
	SSL_hs_hashupdate(ctx,buf,len);
	err=0;
done:
	return err;
}

/*----------------------------------------------------------*/
int SSL_get_clikeyexchange(SSLCTX *ctx,unsigned char *buf){
	unsigned char in[260];	/* smaller than 2048bit RSA */
	Cert *ct;
	Key *key;
	int	i,j;
	
	if(ctx->sp12){
		/* get server certificate & public key */
		if((ct =P12_get_usercert(ctx->sp12))==NULL) goto error;
		if((key=ct->pubkey)==NULL){
			OK_set_error(ERR_ST_NULLKEY,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+6,NULL);
			goto error;
		}
	}else{
		/* key exchange handshake was used */
		key=ctx->exkey;
	}

	/* set PKCS#1 padding */
	if(SSL_set_rand(in,key->size)) goto error;
	j=key->size-49;
	for(i=1;i<j;i++) in[i]|=0x10;
	in[0]=0; in[1]=2; in[j]=0;

	/* set premaster */
	if(SSL_set_rand(ctx->premaster,48)) goto error;
	ctx->premaster[0] = ctx->version.major;
	ctx->premaster[1] = ctx->version.minor;
	memcpy(&(in[j+1]),ctx->premaster,48);
	i = key->size;	/* length */

	switch(key->key_type){
	case KEY_RSA_PUB:
		if(RSApub_doCrypt(key->size,in,&buf[4],(Pubkey_RSA*)key)) goto error;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+6,NULL);
		goto error;
	}

	/* set client key exchange handshake */
	buf[0] = SSL_HT_CLIENT_KEY_EXCHANGE;
	buf[1]=i>>16; buf[2]=i>>8; buf[3]=i;

	SSL_gen_mastersecret(ctx);

	return i+4;
error:
	ctx->errnum=SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

int SSL_get_client_certvfy(SSLCTX *ctx,unsigned char *buf){
	unsigned char in[260];
	Key *key;
	int	len=0,err=0;

	/* if NO_CERTIFICATE is sent before, this function is never called.
	 * so, ctx->cp12 must exist here.
	 */
	if(ctx->cp12==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+7,NULL);
		goto error;
	}

	/* get client private key */
	if((key=P12_get_privatekey(ctx->cp12))==NULL) goto error;

	memset(in,0xff,260);
	in[0]=0; in[1]=1;	/* PKCS#1 type 1 padding */

	len=key->size;
	in[len-37]=0;

	/* calculate hash */
	get_final_hashes(ctx,&in[len-36],&in[len-20],0,0);

	buf[4]=(len>>8); buf[5]=(len);
	len+=2;

	switch(key->key_type){
	case KEY_RSA_PRV:
		if(RSAprv_doCrypt(key->size,in,&buf[6],(Prvkey_RSA*)key)) goto error;
		break;
	default:
		OK_set_error(ERR_ST_UNSUPPORTED_ALGO,ERR_LC_SSLHS,ERR_PT_SSLHS_CLNT+7,NULL);
		goto error;
	}

	buf[0]=SSL_HT_CERTIFICATE_VERIFY;
	buf[1]=0; buf[2]=(len>>8); buf[3]=(len);

	return len+4;
error:
	ctx->errnum=SSL_AD_HAND_SHAKE_FAILURE | (SSL_AL_FATAL<<8);
	return -1;
}

/*-----------------------------------------
  Initialize SSL before Handshake Hello.
-----------------------------------------*/
void init_before_hello(SSL *ssl){
	SSLCTX *ctx;

	ctx = ssl->ctx;
	ssl->opt &=~SSL_OPT_KEEPWBUF;		/* clear keeping buffer flag */
	ssl->opt &=~SSL_SYS_RECONNECTION;	/* clear re-connection flag */
	ctx->recv_cspec = 0;	/* clear recv_cspec flag */
	
	if(ctx->ckey){Key_free(ctx->ckey);ctx->ckey=NULL;}
	if(ctx->skey){Key_free(ctx->skey);ctx->skey=NULL;}
	memset(ctx->wseq,0,8);
	memset(ctx->rseq,0,8);

	/* clear read & write buffer */
	SSL_clear_rwbuf(ctx);
}
