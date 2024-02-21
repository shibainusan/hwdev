/* mimebd_bin.c */
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
MBody_Bin *MBody_bin_new(long type){
	MBody_Bin	*ret;

	ret = (MBody_Bin*)MALLOC(sizeof(MBody_Bin));
	memset(ret,0,sizeof(MBody_Bin));
	ret->body_type=type;
	return(ret);
}

/*-----------------------------------------
  FREE struct MBody (default);
-----------------------------------------*/
void MBody_bin_free(MBody_Bin *mb){
	if(mb==NULL) return;

	if(mb->message)	FREE(mb->message);
	FREE(mb);
}

/*-----------------------------------------
  Get mail body
-----------------------------------------*/
void MBody_bin_get_body(MBody_Bin *ret, char *top){
	char *cp;
	long type;

	cp = strstr(top,"ncoding:");
	ret->encode = type= get_encoding_type(cp);
	cp = strstr(top,"isposition:");
	ret->fname  = get_attach_fname(cp);

	if(type==MAIL_ENC_BS64){
		char *body;
		int	 ren;

		if(body = strstr(cp,"\n\n")){
			body+=2;
		}else{
			body = strstr(cp,"\r\n\r\n");
			body+=4;}

		ret->message=Base64_decode(body,&ren);
		ret->size=ren;
	}
}
