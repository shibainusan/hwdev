/* mime_head.c */
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

#include "ok_mime.h"

/*-----------------------------------------
  get tipical header info (from,to...)
-----------------------------------------*/
int Mail_get_stdheader(char *buf, Mail *ret){
	char	*tp,*cp,*cp2;

	if(cp = strstr(buf,"\n\n")){
	  *cp = 0;
	  if((STRDUP(ret->header,buf))==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SMIME,ERR_PT_MIME_HEAD,NULL);
		goto error;
	  }
	  *cp='\n';
	}else{
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SMIME,ERR_PT_MIME_HEAD,NULL);
		goto error;
	}
	fprintf(stderr,"abcde\n");
	tp = ret->header;
	if(cp = strstr(tp,"From:")){
		cp2= strchr(cp,'\n');
		cp+=6; *cp2=0;
		ret->from = strdup(cp); *cp2='\n';}

	if(cp = strstr(tp,"To:")){
		cp2= strchr(cp,'\n');
		cp+=4; *cp2=0;
		ret->to = strdup(cp); *cp2='\n';}

	if(cp = strstr(tp,"Subject:")){
		cp2= strchr(cp,'\n');
		cp+=9; *cp2=0;
		ret->subject = strdup(cp); *cp2='\n';}

	if(cp = strstr(tp,"Date:")){
		cp2= strchr(cp,'\n');
		cp+=6; *cp2=0;
		ret->date = strdup(cp); *cp2='\n';}

	if(cp = strstr(tp,"Sender:")){
		cp2= strchr(cp,'\n');
		cp+=8; *cp2=0;
		ret->sender = strdup(cp); *cp2='\n';}
	return 0;
error:
	return -1;
}

/*------------------------------------------------------
  Get content type (number)
  == cp must be top of the "Content-Type:" line. ==
------------------------------------------------------*/
int get_ctype_pkcs(char *cp){
	cp+=4;
	if(*cp=='7'){
		cp+=2;
		if(*cp=='m') return MAIL_BDT_APP_P7MM;
		else		 return MAIL_BDT_APP_P7SIG;
	}else if(*cp=='1'){
		cp++;
		if(*cp=='2') return MAIL_BDT_APP_P12;
		if(*cp=='0') return MAIL_BDT_APP_P10;
	}
	return MAIL_BDT_APP;
}

int get_content_type(char *cp){
	if(cp==NULL) return MAIL_BDT_TXT;
	cp = strstr(cp,"ype:");

	if(cp==NULL) return MAIL_BDT_TXT;
	cp+=5;

	switch(*cp){
	case 'a': /* application or audio */
		if(cp[1]=='p'){ /* application */
			cp+=12;
			switch(*cp){
			case 'o': return MAIL_BDT_APP_OCT;
			case 'p': /* pkcs* */
				return get_ctype_pkcs(cp);
			case 'x': /* x-* */
				cp+=2;
				if(*cp=='p') /* pkcs* */
					return get_ctype_pkcs(cp);
			}
		}else{ /* audio */
			cp+=6;
			switch(*cp){
			case 'b': return MAIL_BDT_AUD_BC; 
			default : return MAIL_BDT_AUD_EXTKN; 
			}
		}
	case 'i': /* image */
		cp+=6;
		switch(*cp){
		case 'g': return MAIL_BDT_IMG_GIF; 
		case 'j': return MAIL_BDT_IMG_JPEG; 
		default : return MAIL_BDT_IMG_EXTKN; 
		}
	case 't': /* text */
		cp+=5;
		switch(*cp){
		case 'p': return MAIL_BDT_TXT_PL; 
		case 'r': return MAIL_BDT_TXT_RITCH; 
		case 'h': return MAIL_BDT_TXT_HTML; 
		default : return MAIL_BDT_TXT_XW; 
		}
	case 'v': /* video */
		cp+=6;
		switch(*cp){
		case 'm': return MAIL_BDT_VID_MPEG; 
		default : return MAIL_BDT_VID_EXTKN; 
		}
		
	case 'm': /* multipart or message */
		if(cp[1]=='u'){ /* multipart */
			cp+=10;
			switch(*cp){
			case 'm': return MAIL_BDT_MP_MIXED; 
			case 'a': return MAIL_BDT_MP_ALT; 
			case 'd': return MAIL_BDT_MP_DIGST; 
			case 'p': return MAIL_BDT_MP_PARALL; 
			default : return MAIL_BDT_MP_SIGNED; 
			}
		}else{ /* message */
			cp+=8;
			switch(*cp){
			case 'r': return MAIL_BDT_MSG_RFC822; 
			case 'p': return MAIL_BDT_MSG_PRTI; 
			case 'e': return MAIL_BDT_MSG_EXTB; 
			default	: return MAIL_BDT_MSG_EXTKN; 
			}
		}
	}
	return 0;
}

/*------------------------------------------------------
  Get encoding type (number)
== cp must be top of the "Content-Transfer-Encoding:" line. ==
------------------------------------------------------*/
int get_encoding_type(char *cp){
	int ret;
	if(cp==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_SMIME,ERR_PT_MIME_HEAD+3,NULL);
		return -1;
	}
	cp = strstr(cp,"ncoding:");

	if(cp==NULL){
		OK_set_error(ERR_ST_MIME_BADHEADER,ERR_LC_SMIME,ERR_PT_MIME_HEAD+3,NULL);
		return -1;
	}
	cp+= 9;

	switch(*cp){
	case '7':	ret = MAIL_ENC_7BIT; break;	/* 7bit */
	case '8':	ret = MAIL_ENC_8BIT; break;	/* 8bit */
	case 'q':	ret = MAIL_ENC_QUOTE; break;	/* quoted-printable */
	case 'b':
		if(cp[1]=='a')	ret = MAIL_ENC_BS64;	/* base64 */
		else			ret = MAIL_ENC_BIN;		/* binary */
		break; 
	case 'x':	ret = MAIL_ENC_XTOKEN; break;	/* x-token */
	default:
		OK_set_error(ERR_ST_MIME_BADHEADER,ERR_LC_SMIME,ERR_PT_MIME_HEAD,NULL);
		ret = -1;
	}
	return ret;
}

/*------------------------------------------------------
  Get attachment file name
== cp must be top of the "Content-Disposition:" line. ==
------------------------------------------------------*/
char *get_attach_fname(char *cp){
	char *last,*ret;
	if(cp==NULL) return NULL;

	cp = strstr(cp,"filename=");
	if(cp==NULL) return NULL;

	cp+= 9;
	if(*cp=='"'){
		cp++;
		last=strchr(cp,'"'); *last=0;
		ret=strdup(cp); *last='"';
	}else{
		char c='\r';
		last=strchr(cp,'\r');
		if(!last){ last=strchr(cp,'\n'); c='\n';}
		*last=0;
		ret=strdup(cp); *last=c;
	}
	return ret;
}

/*------------------------------------------------------
  Get charset type
== cp must be top of the "Content-Type:" line. ==
------------------------------------------------------*/
int get_charset_type(char *cp){
	if(cp==NULL) return 0;
	cp = strstr(cp,"charset=");

	if(cp==NULL) return 0;
	cp+= 9;

	switch(*cp){
	case 'u': return MAIL_CHSET_USASCII;	/* us-ascii */
	case 'i':
		if(cp[4]=='2')
			return MAIL_CHSET_ISO2022JP;	/* iso-2022-jp */
	}
	return 0;
}

