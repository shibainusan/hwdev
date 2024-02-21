/* mimebd_msg.c */
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
  make new struct MBody (default)
-----------------------------------------*/
MBody_Msg *MBody_msg_new(long type){
	MBody_Msg	*ret;

	ret = (MBody_Msg*)MALLOC(sizeof(MBody_Msg));
	memset(ret,0,sizeof(MBody_Msg));
	ret->body_type=type;
	return(ret);
}

/*-----------------------------------------
  FREE struct MBody (default);
-----------------------------------------*/
void MBody_msg_free(MBody_Msg *mb){
	if(mb==NULL) return;

	if(mb->id)	FREE(mb->id);
	if(mb->message)	FREE(mb->message);
	FREE(mb);
}

/*-----------------------------------------
  Get mail body
-----------------------------------------*/
void MBody_msg_get_body(MBody_Msg *ret, char *top){
	char *cp,*num,*last;
	int	ren;

	cp = strstr(top,"essage/");

	if(ret->body_type==MAIL_BDT_MSG_PRTI){
		num = strstr(cp,"id="); num+=4;
		last= strchr(cp,'"'); *last =0;
		ret->id =strdup(num); *last='"';

		num = strstr(cp,"number="); num+=7;
		num[1]=0; ret->number =atoi(num); num[1]=';';

		num = strstr(cp,"total="); num+=6;
		num[1]=0; ret->total =atoi(num); num[1]=';';
	}

	/* now I don't check any encoding type... */
	if(num = strstr(cp,"\n\n")){
		num+=2;
	}else{
		num = strstr(cp,"\r\n\r\n");
		num+=4;}

	ret->message=Base64_decode(num,&ren);
	ret->size=ren;
}
