/* mime_body.c */
/*
 * Copyright (C) 1998-2002
 *  Akira Iwata Laboratory. 
 *  Nagoya Institute of Technology in Japan.
 *
 * All rights reserved.
 *
 * This software is written by Takuto Okuno(usagi@mars.elcom.nitech.ac.jp)
 * And if you want to contact us, e-mail to Kimitake Wakayama
 * (wakayama@elcom.nitech.ac.jp)
 *
 * This library is FREE for commercial and non-commercial use as long as
 * the following conditions are aheared to.
 * If you want to use aicrypto library and CA applications code in product,
 * should be e-mail to Akira Iwata Laboratory (wakayama@elcom...).
 * 
 * Please note that MD2 and MD5 includes RSA Data Security, Inc. LICENSE.
 * Those are besed on RFC1319 and RFC1321 document. And copyright distribution
 * is following in ok_md2.h ok_md5.h .
 *
 */

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "ok_mime.h"


/*-----------------------------------------
  Get mail body by content_type
  == tp can be top of mail ==
-----------------------------------------*/
void Mail_get_body(char *tp,Mail *ml){
	MBody *ret;
	char *cp;
	long type;

	cp = strstr(tp,"Content-Type");
	if(!cp) cp = strstr(tp,"Content-type");

	if(cp){
		type = get_content_type(cp);
		ret = MBody_new(type);
		switch(type&0xffff0000){
		case MAIL_BDT_MP:
			MBody_multi_get_body((MBody_Multi*)ret,tp);
			break;
		case MAIL_BDT_MSG:
			MBody_msg_get_body((MBody_Msg*)ret,tp);
			break;
		case MAIL_BDT_APP:
			if((type&0xfffff000)==MAIL_BDT_APP_SMIME){
				MBody_free(ret); ret=NULL;
				MBody_smime_get_body(ml,&ret,tp);
				break;
			}
		case MAIL_BDT_IMG:
		case MAIL_BDT_AUD:
		case MAIL_BDT_VID:
		case MAIL_BDT_EXT_EXTKN:
			MBody_bin_get_body((MBody_Bin*)ret,tp);
			break;
		case MAIL_BDT_TXT:
			MBody_txt_get_body((MBody*)ret,tp);
			break;
		}
	}else{
		char *body;
		body = strstr(tp,"\n\n"); body+=2;

		ret = MBody_new(MAIL_BDT_TXT);
		STRDUP(ret->message,body);
	}

	ml->body=ret;
}

/*-----------------------------------------
  Get mail body type letter
-----------------------------------------*/
void MBody_get_body_str(MBody *bd, char *buf){
	long type =bd->body_type;

	switch(type&0xffff0000){
	case MAIL_BDT_TXT:	/* text */
		strcat(buf,"text/");
		switch(type){
		case MAIL_BDT_TXT_PL:	/* text/plain */
			strcat(buf,"plain"); return;
		case MAIL_BDT_TXT_RITCH:/* text/richtext */
			strcat(buf,"richtext"); return;
		case MAIL_BDT_TXT_HTML:	/* text/html */
			strcat(buf,"html"); return;
		case MAIL_BDT_TXT_XW:	/* text/x-whatever */
			strcat(buf,"x-?"); return;
		}
		break;
	case MAIL_BDT_MP:	/* multipart */
		strcat(buf,"multipart/");
		switch(type){
		case MAIL_BDT_MP_MIXED:	/* multipart/mixed */
			strcat(buf,"mixed"); return;
		case MAIL_BDT_MP_ALT:	/* multipart/alternative */
			strcat(buf,"alternative"); return;
		case MAIL_BDT_MP_DIGST:	/* multipart/digest */
			strcat(buf,"digest"); return;
		case MAIL_BDT_MP_PARALL:/* multipart/parallel */
			strcat(buf,"parallel"); return;
		case MAIL_BDT_MP_SIGNED:/* multipart/signed */
			strcat(buf,"signed"); return;
		}
		break;
	case MAIL_BDT_MSG:	/* message */
		strcat(buf,"message/");
		switch(type){
		case MAIL_BDT_MSG_RFC822:	/* message/rfc822 */
			strcat(buf,"rfc822"); return;
		case MAIL_BDT_MSG_PRTI:		/* message/partial */
			strcat(buf,"partial"); return;
		case MAIL_BDT_MSG_EXTB:		/* message/external-body */
			strcat(buf,"external-body"); return;
		case MAIL_BDT_MSG_EXTKN:	/* message/extention-token */
			strcat(buf,"extention-token"); return;
		}
		break;
	case MAIL_BDT_IMG:	/* image */
		strcat(buf,"image/");
		switch(type){
		case MAIL_BDT_IMG_GIF:	/* image/gif */
			strcat(buf,"gif"); return;
		case MAIL_BDT_IMG_JPEG:	/* image/jpeg */
			strcat(buf,"jpeg"); return;
		case MAIL_BDT_IMG_EXTKN:/* image/extension-token */
			strcat(buf,"extention-token"); return;
		}
		break;
	case MAIL_BDT_AUD:	/* audio */
		strcat(buf,"audio/");
		switch(type){
		case MAIL_BDT_AUD_BC:	/* audio/basic */
			strcat(buf,"basic"); return;
		case MAIL_BDT_AUD_EXTKN:/* audio/extension-token */
			strcat(buf,"extention-token"); return;
		}
		break;
	case MAIL_BDT_VID:	/* video */
		strcat(buf,"video/");
		switch(type){
		case MAIL_BDT_VID_MPEG:	/* video/mpeg */
			strcat(buf,"mpeg"); return;
		case MAIL_BDT_VID_EXTKN:/* video/extension-token */
			strcat(buf,"extention-token"); return;
		}
		break;
	case MAIL_BDT_APP:	/* application */
		strcat(buf,"application/");
		switch(type){
		case MAIL_BDT_APP_OCT:	/* application/octet-stream */
			strcat(buf,"octet-stream"); return;
		case MAIL_BDT_APP_P7SIG:/* application/pkcs7-signature */
			strcat(buf,"pkcs7-signature"); return;
		case MAIL_BDT_APP_P7MM:	/* application/pkcs7-mime */
			strcat(buf,"pkcs7-mime"); return;
		case MAIL_BDT_APP_P10:	/* application/pkcs10 */
			strcat(buf,"pkcs10"); return;
		case MAIL_BDT_APP_P12:	/* application/pkcs12 */
			strcat(buf,"pkcs12"); return;
		}
		break;
	case MAIL_BDT_EXT_EXTKN:	/*  */
		strcat(buf,"extension-token");
		break;
	}
}

/*-----------------------------------------
  decode file from mail body
-----------------------------------------*/
void MBody_decode_file(MBody *bd){
	FILE  *fp;
	long  type=bd->body_type;

	switch(type&0xffff0000){
	case MAIL_BDT_MP:
		{
			int i=0, max;
			max= ((MBody_Multi*)bd)->bodynum;
			do{
				MBody_decode_file(((MBody_Multi*)bd)->body[i]);
				i++;
			}while(i<max);
		}
		break;
	case MAIL_BDT_MSG:
		break;
	case MAIL_BDT_IMG:
	case MAIL_BDT_AUD:
	case MAIL_BDT_VID:
	case MAIL_BDT_APP:
	case MAIL_BDT_EXT_EXTKN:
		if((fp=fopen(((MBody_Bin*)bd)->fname,"wb"))==NULL)
			return;
		fwrite(((MBody_Bin*)bd)->message,sizeof(char),((MBody_Bin*)bd)->size,fp);
		fclose(fp);
		break;
	case MAIL_BDT_TXT:
	default:
		break;
	}
}
