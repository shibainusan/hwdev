/* mime_tool.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_mime.h"


void Mail_print(Mail *ml){
	char buf[128]="";
	long type=ml->body->body_type;

	MBody_get_body_str(ml->body, buf);
	printf("Context-Type: %s\n",buf);

	if((type&0xffff0000)==MAIL_BDT_TXT){
		printf("%s\n",ml->body->message);

	}else if((type&0xffff0000)==MAIL_BDT_MP){
		MBody_Multi *mm;
		int i=0, max;

		mm = (MBody_Multi*)ml->body;
		max= mm->bodynum;
		do{
			*buf=0;
			MBody_get_body_str(mm->body[i], buf);
			printf("[%d] Context-Type: %s\n",i,buf);
			if((mm->body[i]->body_type&0xffff0000)==MAIL_BDT_TXT)
				printf("%s\n",mm->body[i]->message);
			else
				printf("... message is binary ...\n\n");
			i++;
		}while(i<max);
	}
}

