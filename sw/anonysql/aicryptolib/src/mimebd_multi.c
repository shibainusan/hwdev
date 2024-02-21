/* mimebd_txt.c */
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
MBody_Multi *MBody_multi_new(long type){
	MBody_Multi	*ret;
	int	i=0;

	ret = (MBody_Multi*)MALLOC(sizeof(MBody_Multi));
	memset(ret,0,sizeof(MBody_Multi));
	ret->body_type=type;
	ret->body = (MBody**)MALLOC(sizeof(long)*MMULTI_MAX);
	return(ret);
}

/*-----------------------------------------
  FREE struct MBody (default);
-----------------------------------------*/
void MBody_multi_free(MBody_Multi *mb){
	int	i=0,max;

	if(mb==NULL) return;

	if(mb->boundary)	FREE(mb->boundary);
	max = mb->bodynum;
	do{
		MBody_free(mb->body[i]);
		i++;
	}while(i<max);
	FREE(mb);
}

/*-----------------------------------------
  Get mail body
-----------------------------------------*/
void MBody_multi_get_body(MBody_Multi *ret, char *top){
        Mail *dmy=NULL;
	char *cp,*tmp,*bd;
	int  i,len;

	cp = strstr(top,"multipart/");

	cp = strstr(cp,"boundary=");
	cp+= 9;
	if(*cp=='"'){
		tmp = strchr(&cp[2],'"'); *tmp=0;
		ret->boundary =strdup(&cp[1]); *tmp='"';
	}else{
		char c='\r';

		tmp=strchr(cp,'\r');
		if(!tmp){ tmp=strchr(cp,'\n'); c='\n';}
		*tmp=0;
		ret->boundary =strdup(cp); *tmp=c;
	}

fprintf(stderr,ret->boundary);

	bd = ret->boundary;
	len= strlen(bd);
	cp+= len;

	dmy= Mail_new();
	if((cp = strstr(cp,bd))==NULL) goto done;
	cp+= len;

	i  = 0;
	do{
		if((tmp= strstr(cp,bd))==NULL) goto done;
		tmp-=3; *tmp=0;

		Mail_get_body(cp,dmy);
		ret->body[i]= dmy->body;
		dmy->body=NULL;
		*tmp= '\n';

		i++;
		tmp+=len+2;
		if((tmp[0]=='-')&&(tmp[1]=='-'))
			break;
		cp = tmp;
	}while(i<MMULTI_MAX);
done:
	Mail_free(dmy);
	ret->bodynum=i;
}



