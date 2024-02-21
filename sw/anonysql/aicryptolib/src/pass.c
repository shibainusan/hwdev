/* pass.c */
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

#include <aiconfig.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_TERMIO_H
#  include <termio.h>
#  define TTY_STRUCT          struct termio
#  define TTY_GET(tty,data)   ioctl(tty,TCGETA,data)
#  define TTY_SET(tty,data)   ioctl(tty,TCSETA,data)

#elif HAVE_TERMIOS_H
#  include <termios.h>
#  define TTY_STRUCT          struct termios
#  define TTY_GET(tty,data)   tcgetattr(tty,data)
#  define TTY_SET(tty,data)   tcsetattr(tty,TCSANOW,data)
#endif

#include "ok_tool.h"

static char pass[32]="";
static char *pprompt=NULL;

/*-----------------------------------------------
  Password Input function.
-----------------------------------------------*/
void OK_get_passwd(char *prompt,unsigned char *ret,int mode){
#if 0
	TTY_STRUCT tio,save;
	FILE	*tty;
	char	buf[34],buf2[34];
	int	max,len;

	if(*pass){strncpy(ret,pass,32); return;}
	if(pprompt) prompt=pprompt;

	if((tty=fopen("/dev/tty","rt"))==NULL){
		fprintf(stderr,"tty is stdin\n");
		tty=stdin;
	}

	TTY_GET(fileno(tty),&save);
	memcpy(&tio,&save,sizeof(TTY_STRUCT));
	tio.c_lflag &= ~ECHO;
	TTY_SET(fileno(tty),&tio);

	for(max=3;max;--max){
		fprintf(stderr,"%s",prompt);
		fgets(buf,32,tty);
		if((len=strlen(buf)-1)>3){
			if(mode&0x01){
				fprintf(stderr,"\nVerifying - %s",prompt);
				fgets(buf2,32,tty);

				if(strcmp(buf,buf2)){
					fprintf(stderr,"\npassword mismatch.\n");
					continue;
				}
			}

			buf[len]=0;
			break;
		}else
			fprintf(stderr,"\nInput must be larger than 4 char.\n");
	}

	fprintf(stderr,"\n");
	strncpy(ret,buf,32);
  
	TTY_SET(fileno(tty),&save);

	if(stdin!=tty) fclose(tty);
#endif
}

void OK_get_localpass(char *ret){
	strncpy(ret,pass,32);
}

void OK_set_passwd(char *pwd){
    strncpy(pass,pwd,32);
}

void OK_clear_passwd(){
    memset(pass,0,32);
}

void OK_set_prompt(char *prom){
	pprompt=prom;
}

void OK_get_password_p12(char *prompt,Dec_Info *dif,int mode){

	if(prompt&&(*pass==0))
		OK_get_passwd(prompt,(unsigned char*)pass,mode&0x00ff);

	dif->plen = 2*strlen(pass)+2;
	if((dif->pass = (unsigned char*)MALLOC(dif->plen))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_TOOL,ERR_PT_PASS+1,NULL);
		return;
	}
	as2uni(pass,dif->pass);

	if(mode&0x0100) memset(pass,0,32);
}

/*-----------------------------------------------
  ASCII to UNICODE
-----------------------------------------------*/
void as2uni(char *in,unsigned char *ret){
	int i,j,len = strlen(in);

	memset(ret,0,2*len+2);
	for(i=0,j=1;i<len;i++,j+=2)
		ret[j]=in[i];
}

/*-----------------------------------------------
  UNICODE to ASCII
-----------------------------------------------*/
void uni2as(unsigned char *in,char *ret){
	int i,j;

	for(i=0,j=1;in[j-1]||in[j];i++,j+=2)
		ret[i]=in[j];
	ret[i]=0;
}
