/* mime.c */
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

#include "ok_mime.h"

/*-----------------------------------------
  make new struct Mail
-----------------------------------------*/
Mail *Mail_new(void){
	Mail	*ret;

	if((ret = (Mail*)MALLOC(sizeof(Mail)))==NULL){
	  return NULL;
	}
	memset(ret,0,sizeof(Mail));
	return(ret);
}

/*-----------------------------------------
  FREE struct Mail
-----------------------------------------*/
void Mail_free(Mail *ml){
	if(ml==NULL) return;

	if(ml->from)	FREE(ml->from);
	if(ml->to)		FREE(ml->to);
	if(ml->subject)	FREE(ml->subject);
	if(ml->date)	FREE(ml->date);
	if(ml->sender)	FREE(ml->sender);

	if(ml->header)	FREE(ml->header);

	if(ml->body)	MBody_free(ml->body);
	FREE(ml);
}

/*-----------------------------------------
  MBody alloc & FREE.
-----------------------------------------*/
MBody *MBody_new(long type){
	switch(type&0xffff0000){
	case MAIL_BDT_MP:
		return((MBody*)MBody_multi_new(type));
	case MAIL_BDT_MSG:
		return((MBody*)MBody_msg_new(type));
	case MAIL_BDT_IMG:
	case MAIL_BDT_AUD:
	case MAIL_BDT_VID:
	case MAIL_BDT_APP:
	case MAIL_BDT_EXT_EXTKN:
		return((MBody*)MBody_bin_new(type));
	case MAIL_BDT_TXT:
	default:
		return(MBody_txt_new(type));
	}
}

void MBody_free(MBody *mb){
	switch(mb->body_type&0xffff0000){
	case MAIL_BDT_MP:
		MBody_multi_free((MBody_Multi*)mb);
		break;
	case MAIL_BDT_MSG:
		MBody_msg_free((MBody_Msg*)mb);
		break;
	case MAIL_BDT_IMG:
	case MAIL_BDT_AUD:
	case MAIL_BDT_VID:
	case MAIL_BDT_APP:
	case MAIL_BDT_EXT_EXTKN:
		MBody_bin_free((MBody_Bin*)mb);
		break;
	case MAIL_BDT_TXT:
	default:
		MBody_txt_free(mb);
		break;
	}
}

/*-----------------------------------------
  analizing buf and get Mail structure
-----------------------------------------*/
Mail *Mail_read_str(char *buf,Cert *cert,Key *key){
	Mail	*ret;

	if(buf==NULL)	return(NULL);

	ret= Mail_new();
	ret->cert = cert;
	ret->key  = key;

fprintf(stderr,"get header\n");
	Mail_get_stdheader(buf,ret);
fprintf(stderr,"get body\n");
	Mail_get_body(buf,ret);
fprintf(stderr,"get end\n");

	return(ret);
}


/*-----------------------------------------
  Mail struct to string buffer
-----------------------------------------*/
char *Mail_get_str(Mail *ml){
	char *ret;

	return ret;
}

