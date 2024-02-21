/* ssl_alert.c */
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

#include "ok_io.h"
#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_ssl.h"

/* ssl_read.c */
int check_mac(SSLCTX *ctx, int ml);

/*-----------------------------------------
  Recieve SSL Alert
-----------------------------------------*/
int SSL_recv_alert(SSLCTX *ctx,unsigned char *buf,int *len){
	unsigned char alt[16];
	char str[64];
	int	plen,err=-1,sv=0;

	if(buf[1]!=0x3){
		OK_set_error(ERR_ST_BADVER,ERR_LC_SSLALERT,ERR_PT_SSLALERT,NULL);
		ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
		goto done; /* version check error : fatal */
	}
	*len = plen = (buf[3]<<8)|buf[4];

	/* set content */
	ctx->ctxt->type   = buf[0];
	ctx->ctxt->length = plen;
	memcpy(ctx->ctxt->fragment,&(buf[5]),plen);

	if(SSL_decode_packet(ctx)) goto done;

	if(check_mac(ctx,plen)) goto done;

	/* read SSL Alert packet */
	if(SSL_packet_read(ctx,alt,16)!=2) goto done; /* it's not alert packet! */

	ctx->errnum = alt[1] | (alt[0]<<8);
	err = 1 - alt[0];	/* warning..1, fatal..2 */

	/* handling alert. it's case by case */
	switch(alt[1]){
	case SSL_AD_CLOSE_NOTIFY:
		/* probably it's coming with warning level.
		 * but this one uses fatal process
		 */
		OK_set_error(ERR_ST_SSL_CLOSE_NOTIFY,ERR_LC_SSLALERT,ERR_PT_SSLALERT,NULL);
		err = -1;	/* fatal error */
		break;
	case SSL_AD_NO_CERTIFICATE:
		/* the SSL server send certificate request, then
		 * the server might receive NO_CERTIRICATE with WARNING level.
		 * but it's actually fatal process.
		 */
		OK_set_error(ERR_ST_SSL_NO_CERT,ERR_LC_SSLALERT,ERR_PT_SSLALERT,NULL);
		err = -1;
		break;

	case SSL_AD_UNEXPECTED_MESSAGE:
	case SSL_AD_BAD_RECORD_MAC:
	case SSL_AD_DECOMPRESSION_FAILURE:
	case SSL_AD_HAND_SHAKE_FAILURE:
	case SSL_AD_BAD_CERTIFICATE:
	case SSL_AD_UNSUPPORTED_CERTIFICATE:
	case SSL_AD_CERTIFICATE_REVOKED:
	case SSL_AD_CERTIFICATE_EXPIRED:
	case SSL_AD_CERTIFICATE_UNKNOWN:
	case SSL_AD_ILLEGAL_PARAMETER:
		break;
	default:
		/* this one is illegal parameter */
		OK_set_error(ERR_ST_BADPARAM,ERR_LC_SSLALERT,ERR_PT_SSLALERT,NULL);
		ctx->errnum = SSL_AD_UNEXPECTED_MESSAGE | (SSL_AL_FATAL<<8);
		err = -1;
		break;
	};

	SSL_alert_str(alt[0],alt[1],str);
	/* okerr -- shold be changed */
	fprintf(stderr,"SSL Received Aleart:%s\n",str);

done:
	return err;
}

int SSL_send_alert(SSL *ssl,int level,int description){
	unsigned char buf[64];
	int	sv;

	SSL_alert_str(level,description,buf);
	/* okerr -- shold be changed */
	fprintf(stderr,"SSL Send Aleart:%s\n",buf);

	sv = ssl->mode;
	ssl->mode = SSL_ALERT;

	/* set alert content */
	buf[0] = (level==SSL_AL_FATAL)?(SSL_AL_FATAL):(SSL_AL_WARNING);
	buf[1] = (unsigned char)description;

	if(SSL_write(ssl,buf,2)<0) return -1;

	/* if SSL_OPT_KEEPWBUF option is used, data is still in
	 * the write buffer. So, It needs to be flushed.
	 */
	if(SSL_wflush(ssl)<0) return -1;

	ssl->mode = sv;
	return 0;
}

void SSL_alert_str(int level,int description,char *buf){
	switch(level){
	case SSL_AL_WARNING:
		strcpy(buf,"[warning alert] ");
		break;
	case SSL_AL_FATAL:
		strcpy(buf,"[fatal alert] ");
		break;
	default:
		sprintf(buf,"[unknown alert(%d)] ",level);
		break;
	}
	switch(description){
	case SSL_AD_CLOSE_NOTIFY:
		strcat(buf,"CLOSE_NOTIFY");
		break;
	case SSL_AD_NO_CERTIFICATE:
		strcat(buf,"NO_CERTIFICATE");
		break;
	case SSL_AD_UNEXPECTED_MESSAGE:
		strcat(buf,"UNEXPECTED_MESSAGE");
		break;
	case SSL_AD_BAD_RECORD_MAC:
		strcat(buf,"BAD_RECORD_MAC");
		break;
	case SSL_AD_DECOMPRESSION_FAILURE:
		strcat(buf,"DECOMPRESSION_FAILURE");
		break;
	case SSL_AD_HAND_SHAKE_FAILURE:
		strcat(buf,"HAND_SHAKE_FAILURE");
		break;
	case SSL_AD_BAD_CERTIFICATE:
		strcat(buf,"BAD_CERTIFICATE");
		break;
	case SSL_AD_UNSUPPORTED_CERTIFICATE:
		strcat(buf,"UNSUPPORTED_CERTIFICATE");
		break;
	case SSL_AD_CERTIFICATE_REVOKED:
		strcat(buf,"CERTIFICATE_REVOKED");
		break;
	case SSL_AD_CERTIFICATE_EXPIRED:
		strcat(buf,"CERTIFICATE_EXPIRED");
		break;
	case SSL_AD_CERTIFICATE_UNKNOWN:
		strcat(buf,"CERTIFICATE_UNKNOWN");
		break;
	case SSL_AD_ILLEGAL_PARAMETER:
		strcat(buf,"ILLEGAL_PARAMETER");
		break;
	default:
		strcat(buf,"UNKNOWN");
		break;
	}
}
